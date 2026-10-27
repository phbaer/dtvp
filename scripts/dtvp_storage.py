"""Back up and restore the DTVP database together with source artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
import sys

from sqlalchemy.engine import URL, make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dtvp.artifact_store import ArtifactStore
from dtvp.database import get_database_url


def _database_details() -> tuple[URL, dict[str, str]]:
    url = make_url(str(get_database_url()))
    environment = os.environ.copy()
    if url.password:
        environment["PGPASSWORD"] = url.password
    if url.query.get("sslmode"):
        environment["PGSSLMODE"] = str(url.query["sslmode"])
    return url, environment


def _pg_args(url: URL) -> list[str]:
    args: list[str] = []
    for option, value in (
        ("--host", url.host),
        ("--port", str(url.port) if url.port else None),
        ("--username", url.username),
        ("--dbname", url.database),
    ):
        if value:
            args.extend([option, value])
    return args


def _sqlite_path(url: URL) -> Path:
    if not url.database or url.database == ":memory:":
        raise ValueError("DTVP backup requires a file-backed SQLite database")
    path = Path(url.database).expanduser()
    return path if path.is_absolute() else Path.cwd() / path


def _safe_archive_members(archive: tarfile.TarFile):
    members = archive.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Backup archive contains an unsafe path")
        if not (member.isfile() or member.isdir()):
            raise ValueError("Backup archive contains an unsupported file type")
    return members


def _artifact_digest(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    if len(relative.parts) != 2 or not relative.name.endswith(".json"):
        raise ValueError(f"Unexpected artifact path: {relative}")
    digest = relative.parts[0] + relative.name[:-5]
    if len(digest) != 64:
        raise ValueError(f"Invalid content-addressed artifact path: {relative}")
    return digest


def _verify_artifacts(root: Path) -> int:
    count = 0
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("Artifact archive contains a non-regular file")
        digest = _artifact_digest(path, root)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Artifact failed SHA-256 verification: {path.name}")
        count += 1
    return count


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _create_database_copy(destination: Path) -> str:
    url, environment = _database_details()
    if url.get_backend_name() == "sqlite":
        source_path = _sqlite_path(url)
        if not source_path.is_file():
            raise FileNotFoundError(f"DTVP SQLite database not found: {source_path}")
        with sqlite3.connect(f"file:{source_path}?mode=ro", uri=True) as source:
            with sqlite3.connect(destination) as target:
                source.backup(target)
        return "sqlite"
    if url.get_backend_name() == "postgresql":
        command = ["pg_dump", "--format=custom", "--no-owner", "--no-acl"]
        command.extend(_pg_args(url))
        with destination.open("wb") as output:
            subprocess.run(command, env=environment, stdout=output, check=True)
        return "postgresql"
    raise ValueError(f"Unsupported DTVP database dialect: {url.get_backend_name()}")


def backup(output_dir: Path) -> Path:
    artifact_root = ArtifactStore().root.resolve()
    output_dir = output_dir.expanduser().resolve()
    if output_dir == artifact_root or artifact_root in output_dir.parents:
        raise ValueError("Backup output must be outside the artifact store")
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    final_path = output_dir / f"dtvp-backup-{timestamp}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="dtvp-backup-") as temporary:
        stage = Path(temporary)
        database_path = stage / "database"
        dialect = _create_database_copy(database_path)
        artifact_bundle = stage / "artifacts.tar"
        artifact_count = 0
        if artifact_root.exists():
            artifact_count = _verify_artifacts(artifact_root)
            with tarfile.open(artifact_bundle, "w") as artifacts:
                artifacts.add(artifact_root, arcname="artifacts", recursive=True)
        else:
            with tarfile.open(artifact_bundle, "w"):
                pass

        manifest = {
            "format": "dtvp-storage-backup/v1",
            "created_at": datetime.now(UTC).isoformat(),
            "database_dialect": dialect,
            "database_file": "database",
            "database_sha256": _sha256_file(database_path),
            "artifact_count": artifact_count,
            "artifact_directory": str(artifact_root),
        }
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".dtvp-backup-", suffix=".tmp", dir=output_dir
        )
        os.close(descriptor)
        try:
            with tarfile.open(temporary_path, "w:gz") as bundle:
                bundle.add(stage / "manifest.json", arcname="manifest.json")
                bundle.add(database_path, arcname="database")
                bundle.add(artifact_bundle, arcname="artifacts.tar")
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, final_path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
    return final_path


def _restore_artifacts(bundle: Path, destination: Path, expected_count: int) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(bundle, "r") as archive:
        members = _safe_archive_members(archive)
        root_members = [member for member in members if member.name != "artifacts"]
        if any(not member.name.startswith("artifacts/") for member in root_members):
            raise ValueError("Artifact bundle contains files outside its root")
        count = 0
        for member in root_members:
            if not member.isfile():
                continue
            relative = PurePosixPath(member.name).relative_to("artifacts")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Could not read an artifact from the backup")
            content = source.read()
            digest = str(relative.parts[0]) + relative.name[:-5]
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError(f"Artifact failed SHA-256 verification: {member.name}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != content:
                raise ValueError(f"Conflicting artifact already exists: {target}")
            if not target.exists():
                target.write_bytes(content)
            count += 1
    if count != expected_count:
        raise ValueError(
            f"Artifact count mismatch: expected {expected_count}, restored {count}"
        )
    return count


def restore(backup_path: Path, *, replace: bool) -> dict[str, object]:
    if not replace:
        raise ValueError("Restore replaces DTVP database state; pass --replace to proceed")
    with tempfile.TemporaryDirectory(prefix="dtvp-restore-") as temporary:
        stage = Path(temporary)
        with tarfile.open(backup_path, "r:gz") as archive:
            members = _safe_archive_members(archive)
            allowed = {"manifest.json", "database", "artifacts.tar"}
            if {member.name for member in members} != allowed:
                raise ValueError("Backup archive has an unexpected file set")
            for member in members:
                if not member.isfile():
                    raise ValueError("Backup archive entries must be regular files")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Could not read {member.name} from backup")
                (stage / member.name).write_bytes(source.read())

        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("format") != "dtvp-storage-backup/v1":
            raise ValueError("Unsupported DTVP backup format")
        url, environment = _database_details()
        dialect = url.get_backend_name()
        if dialect != manifest.get("database_dialect"):
            raise ValueError("Backup database dialect does not match the configured DTVP database")
        if _sha256_file(stage / "database") != manifest.get("database_sha256"):
            raise ValueError("Backup database failed SHA-256 verification")

        artifact_root = ArtifactStore().root.expanduser().resolve()
        artifact_count = _restore_artifacts(
            stage / "artifacts.tar",
            artifact_root,
            int(manifest.get("artifact_count") or 0),
        )

        if dialect == "sqlite":
            target = _sqlite_path(url)
            target.parent.mkdir(parents=True, exist_ok=True)
            replacement = target.with_name(f".{target.name}.restore.tmp")
            shutil.copyfile(stage / "database", replacement)
            os.replace(replacement, target)
        elif dialect == "postgresql":
            command = [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--exit-on-error",
                "--single-transaction",
            ]
            command.extend(_pg_args(url))
            command.append(str(stage / "database"))
            subprocess.run(command, env=environment, check=True)
        else:
            raise ValueError(f"Unsupported DTVP database dialect: {dialect}")

    return {
        "database_dialect": dialect,
        "artifact_count": artifact_count,
        "created_at": manifest.get("created_at"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backup_parser = commands.add_parser("backup")
    backup_parser.add_argument("--output-dir", type=Path, default=Path("data/backups"))
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.command == "backup":
        print(backup(args.output_dir))
    else:
        print(json.dumps(restore(args.backup, replace=args.replace), indent=2))


if __name__ == "__main__":
    main()
