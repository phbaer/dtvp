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
from uuid import uuid4


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def output(*args):
    return docker(*args, capture_output=True, text=True, timeout=30).stdout.strip()


def server_major(container, user, database):
    value = output(
        "exec", container, "psql", "-U", user, "-d", database, "-Atqc", "SHOW server_version_num"
    )
    if not re.fullmatch(r"[0-9]{6}", value):
        raise RuntimeError("PostgreSQL returned an unsupported server version number")
    return int(value) // 10_000


def write_manifest(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-container", required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--target-major", type=int, choices=[18], default=18)
    parser.add_argument("--database", default="dtvp")
    parser.add_argument("--user", default="dtvp")
    parser.add_argument("--backup-dir", type=Path, default=Path("data/engine-upgrades"))
    parser.add_argument("--port", type=int, default=55433)
    parser.add_argument("--writers-stopped", action="store_true", required=True)
    args = parser.parse_args(argv)
    for value in [args.source_container, args.target_name, args.database, args.user]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
            parser.error("Names must contain only letters, numbers, underscores or hyphens")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    password = os.getenv("DTVP_UPGRADE_TARGET_PASSWORD")
    if not password or len(password) < 16:
        parser.error("Set DTVP_UPGRADE_TARGET_PASSWORD to a new password of at least 16 characters")
    # Read-only preflight, before any backup or Docker resource creation.
    if output(
        "container", "ls", "-a", "--filter", f"name=^/{args.target_name}$", "--format", "{{.Names}}"
    ):
        parser.error("Target container already exists; choose a new target name")
    if output("volume", "ls", "--filter", f"name=^{args.target_name}$", "--format", "{{.Name}}"):
        parser.error("Target-named volume already exists; choose a new target name")
    image = output("image", "inspect", f"postgres:{args.target_major}", "--format", "{{.Id}}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        parser.error("A local PostgreSQL target image is required")
    source_major = server_major(args.source_container, args.user, args.database)
    if not 10 <= source_major < args.target_major:
        parser.error("Source major must be at least 10 and older than the target major")
    nonce = uuid4().hex
    volume = f"{args.target_name}-{nonce}"
    args.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    dump = args.backup_dir / f"{args.target_name}.dump"
    manifest = dump.with_suffix(".manifest.json")
    if dump.exists() or manifest.exists():
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
        stream.flush()
        os.fsync(stream.fileno())
    with dump.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    write_manifest(
        manifest,
        {
            "source_container": args.source_container,
            "source_major": source_major,
            "database": args.database,
            "target_major": args.target_major,
            "target_container": args.target_name,
            "target_volume": volume,
            "target_image": image,
            "sha256": checksum,
            "note": "Application-owned database only; configure custom roles, extensions and server settings separately.",
        },
    )
    # A fresh unpredictable volume plus ownership verification avoids reusing a
    # user volume. Docker's named-volume create alone is not exclusive.
    docker(
        "volume",
        "create",
        "--label",
        "dtvp.purpose=engine-upgrade",
        "--label",
        f"dtvp.upgrade={nonce}",
        volume,
        stdout=subprocess.DEVNULL,
    )
    owner = output("volume", "inspect", volume, "--format", '{{index .Labels "dtvp.upgrade"}}')
    if owner != nonce:
        raise RuntimeError("Candidate volume ownership differs; no container was started")
    # Pass the password through Docker's environment lookup, not argv/logged command text.
    env = {**os.environ, "POSTGRES_PASSWORD": password}
    docker(
        "run",
        "--pull=never",
        "--name",
        args.target_name,
        "--label",
        "dtvp.purpose=engine-upgrade",
        "--label",
        f"dtvp.upgrade={nonce}",
        "-e",
        "POSTGRES_PASSWORD",
        "-e",
        f"POSTGRES_USER={args.user}",
        "-e",
        f"POSTGRES_DB={args.database}",
        "--mount",
        f"type=volume,source={volume},target=/var/lib/postgresql",
        "-p",
        f"127.0.0.1:{args.port}:5432",
        "-d",
        image,
        env=env,
        stdout=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    args.target_name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    args.user,
                    "-d",
                    args.database,
                ],
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Candidate cluster did not become ready; source and backup are retained")
    if server_major(args.target_name, args.user, args.database) != args.target_major:
        raise RuntimeError(
            "Candidate server major differs from the selected target; restore refused"
        )
    with dump.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            raise RuntimeError("Backup changed since its manifest was sealed; restore refused")
        stream.seek(0)
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
    print(
        f"Candidate volume: {volume}. Source container/volume retained. Verified dump: {dump}; SHA-256: {checksum}"
    )


if __name__ == "__main__":
    main()
