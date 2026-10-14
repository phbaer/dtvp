"""Dump/restore into a new PostgreSQL volume; never mutate the old cluster.

Stop DTVP writers first. This command creates a validated candidate, retaining
the source container and volume. Production cutover remains an explicit change
of the database URL after checking the candidate with the application.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-container", required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--target-major", type=int, choices=[18], default=18)
    parser.add_argument("--database", default="dtvp")
    parser.add_argument("--user", default="dtvp")
    parser.add_argument("--backup-dir", type=Path, default=Path("data/engine-upgrades"))
    parser.add_argument("--port", type=int, default=55433)
    parser.add_argument("--writers-stopped", action="store_true", required=True)
    args = parser.parse_args()
    for value in [args.source_container, args.target_name, args.database, args.user]:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            parser.error("Names must contain only letters, numbers, underscores or hyphens")
    password = os.getenv("DTVP_UPGRADE_TARGET_PASSWORD")
    if not password or len(password) < 16:
        parser.error("Set DTVP_UPGRADE_TARGET_PASSWORD to a new password of at least 16 characters")
    args.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    dump = args.backup_dir / f"{args.target_name}.dump"
    if dump.exists():
        parser.error("Backup already exists; use a new target name, no files will be overwritten")
    fd = os.open(dump, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        docker(
            "exec",
            args.source_container,
            "pg_dump",
            "-U",
            args.user,
            "-d",
            args.database,
            "--format=custom",
            "--no-owner",
            "--no-acl",
            stdout=stream,
        )
    with dump.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = dump.with_suffix(".manifest.json")
    manifest.write_text(
        json.dumps(
            {
                "source_container": args.source_container,
                "database": args.database,
                "target_major": args.target_major,
                "sha256": checksum,
                "note": "Application-owned database only; configure custom roles, extensions and server settings separately.",
            },
            indent=2,
        )
    )
    # Pass the password through Docker's environment lookup, not argv/logged command text.
    env = {**os.environ, "POSTGRES_PASSWORD": password}
    docker(
        "run",
        "--name",
        args.target_name,
        "--label",
        "dtvp.purpose=engine-upgrade",
        "-e",
        "POSTGRES_PASSWORD",
        "-e",
        f"POSTGRES_USER={args.user}",
        "-e",
        f"POSTGRES_DB={args.database}",
        "-v",
        f"{args.target_name}:/var/lib/postgresql",
        "-p",
        f"127.0.0.1:{args.port}:5432",
        "-d",
        f"postgres:{args.target_major}",
        env=env,
        stdout=subprocess.DEVNULL,
    )
    for _ in range(60):
        result = subprocess.run(
            [
                "docker",
                "exec",
                args.target_name,
                "pg_isready",
                "-U",
                args.user,
                "-d",
                args.database,
            ],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Candidate cluster did not become ready; source and backup are retained")
    with dump.open("rb") as stream:
        docker(
            "exec",
            "-i",
            args.target_name,
            "pg_restore",
            "-U",
            args.user,
            "-d",
            args.database,
            "--exit-on-error",
            "--single-transaction",
            "--no-owner",
            "--no-acl",
            stdin=stream,
        )
    docker(
        "exec",
        args.target_name,
        "psql",
        "-U",
        args.user,
        "-d",
        args.database,
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "SELECT version(); SELECT version_num FROM alembic_version;",
    )
    print(
        f"Candidate restored on 127.0.0.1:{args.port}. Verify DTVP readiness/snapshots/access before changing its database URL."
    )
    print(f"Source container/volume retained. Verified dump: {dump}; SHA-256: {checksum}")


if __name__ == "__main__":
    main()
