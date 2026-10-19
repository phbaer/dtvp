"""Isolated real PostgreSQL playground; never reads the production .env."""

import argparse
import os
import socket
import ssl
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build_environment(ca_cert=None):
    """Forward host trust to BuildKit and host-side npm/Playwright downloads."""
    env = dict(os.environ)
    selected = ca_cert or next(
        (env[name] for name in (
            "DTVP_BUILD_CA", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        ) if env.get(name)),
        None,
    ) or ssl.get_default_verify_paths().cafile
    if selected:
        bundle = Path(selected).expanduser().resolve()
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cafile=str(bundle))
        except (OSError, ssl.SSLError) as error:
            raise ValueError(f"Cannot load CA bundle {bundle}: {error}") from None
        env["DTVP_BUILD_CA"] = str(bundle)
        env["NODE_EXTRA_CA_CERTS"] = str(bundle)
    return env


def test_stack(compose, skip_build, env=None):
    # Browser fixtures reset data: always use a separate project and volumes.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    test_env = {
        **(env if env is not None else os.environ),
        "DTVP_PLAYGROUND_PORT": str(port),
        "DTVP_UI_URL": f"http://127.0.0.1:{port}",
    }
    test_compose = compose + ["--project-name", f"dtvp-ui-tests-{os.getpid()}"]
    try:
        run_test_stack(test_compose, skip_build, test_env)
    finally:
        subprocess.run(
            test_compose + ["down", "--volumes", "--remove-orphans"],
            cwd=ROOT,
            env=test_env,
            check=False,
        )


def run_test_stack(compose, skip_build, test_env):
    command = compose + ["up", "-d", "--wait"]
    if not skip_build:
        command.append("--build")
    subprocess.run(command, check=True, cwd=ROOT, env=test_env)
    if not (ROOT / "frontend/node_modules").exists():
        subprocess.run(
            ["npm", "ci", "--include=optional"], cwd=ROOT / "frontend", check=True, env=test_env
        )
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
            **test_env,
            "DTVP_TEST_DATABASE_URL": f"postgresql+psycopg://postgres:synthetic-tests-only@{address}/dtvp_test",
        }
        subprocess.run(["uv", "run", "pytest"], check=True, cwd=ROOT, env=env)
        for command in [
            ["npm", "run", "build"],
            ["npm", "run", "test:unit"],
            ["npx", "playwright", "install", "chromium"],
            ["npm", "run", "test:ui"],
            ["npm", "run", "test:integration"],
        ]:
            subprocess.run(
                command,
                check=True,
                cwd=ROOT / "frontend",
                env=test_env,
            )
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["up", "down", "reset", "logs", "test"])
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--ca-cert", help="PEM CA bundle; defaults to configured/host trust")
    args = parser.parse_args()
    env = dict(os.environ)
    if args.command in {"up", "reset", "test"}:
        try:
            env = build_environment(args.ca_cert)
        except ValueError as error:
            parser.error(str(error))
    compose = [
        "docker",
        "compose",
        "--env-file",
        "/dev/null",
        "-f",
        str(ROOT / "playground/compose.yml"),
    ]
    if args.command in {"up", "reset", "test"} and env.get("DTVP_BUILD_CA"):
        compose += ["-f", str(ROOT / "playground/compose.ca.yml")]
    if args.command == "up":
        command = compose + ["up", "-d", "--wait"]
        if not args.skip_build:
            command.append("--build")
    elif args.command == "reset":
        subprocess.run(compose + ["down", "--volumes"], check=True, cwd=ROOT, env=env)
        command = compose + ["up", "-d", "--wait"]
    elif args.command == "down":
        command = compose + ["down"]
    elif args.command == "test":
        test_stack(compose, args.skip_build, env)
        return
    else:
        command = compose + ["logs", "--tail", "100"]
    subprocess.run(command, check=True, cwd=ROOT, env=env)
    if args.command in {"up", "reset"}:
        print(
            f"Playground ready: http://127.0.0.1:{os.getenv('DTVP_PLAYGROUND_PORT', '8900')} — synthetic data, no external accounts"
        )


if __name__ == "__main__":
    main()
