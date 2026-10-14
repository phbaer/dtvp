"""Isolated real PostgreSQL playground; never reads the production .env."""

import argparse
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_stack(compose, skip_build):
    command = compose + ["up", "-d", "--wait"]
    if not skip_build:
        command.append("--build")
    subprocess.run(command, check=True, cwd=ROOT)
    if not (ROOT / "frontend/node_modules").exists():
        subprocess.run(["npm", "ci", "--include=optional"], cwd=ROOT / "frontend", check=True)
    name = f"dtvp-automatic-tests-{os.getpid()}"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            "--label",
            "dtvp.purpose=automatic-tests",
            "-e",
            "POSTGRES_PASSWORD=synthetic-tests-only",
            "-e",
            "POSTGRES_DB=dtvp_test",
            "-p",
            "127.0.0.1::5432",
            "-d",
            "postgres:18",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", "dtvp_test"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Disposable test database did not become ready")
        address = subprocess.check_output(["docker", "port", name, "5432"], text=True).strip()
        env = {
            **os.environ,
            "DTVP_TEST_DATABASE_URL": f"postgresql+psycopg://postgres:synthetic-tests-only@{address}/dtvp_test",
        }
        subprocess.run(["uv", "run", "pytest"], check=True, cwd=ROOT, env=env)
        for command in [
            ["npm", "run", "build"],
            ["npm", "run", "test:unit"],
            ["npx", "playwright", "install", "chromium"],
            ["npm", "run", "test:ui"],
        ]:
            subprocess.run(command, check=True, cwd=ROOT / "frontend")
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["up", "down", "reset", "logs", "test"])
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    compose = [
        "docker",
        "compose",
        "--env-file",
        "/dev/null",
        "-f",
        str(ROOT / "playground/compose.yml"),
    ]
    if args.command == "up":
        command = compose + ["up", "-d", "--wait"]
        if not args.skip_build:
            command.append("--build")
    elif args.command == "reset":
        subprocess.run(compose + ["down", "--volumes"], check=True, cwd=ROOT)
        command = compose + ["up", "-d", "--wait"]
    elif args.command == "down":
        command = compose + ["down"]
    elif args.command == "test":
        test_stack(compose, args.skip_build)
        return
    else:
        command = compose + ["logs", "--tail", "100"]
    subprocess.run(command, check=True, cwd=ROOT)
    if args.command in {"up", "reset"}:
        print(
            f"Playground ready on this Docker host: http://127.0.0.1:{os.getenv('DTVP_PLAYGROUND_PORT', '8800')} — synthetic data, no external accounts"
        )


if __name__ == "__main__":
    main()
