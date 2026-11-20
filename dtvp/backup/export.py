"""Online export of an instance dump.

The export runs beside a running backend: it holds the export lock, not the
instance lock, snapshots each database, and streams the records from the
copies. Consistency is per database file.
"""

import getpass
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import IO, Any, Callable

from ..bundle_io import atomic_output
from ..file_io_services import atomic_write_bytes
from ..instance_stores import (
    InstanceStores,
    resolve_instance_stores,
    try_lock_exclusive,
    unlock,
)
from ..settings_files import SETTINGS_FILE_NAMES
from ..version import BUILD_COMMIT, VERSION
from . import schemas
from .checks import RecordChecker
from .container import DumpWriter
from .entities import ENTITIES
from .errors import DumpError, Finding
from .manifest import sanitize_dependency_track_url
from .sqlite_source import (
    SqliteDumpSource,
    check_migration_state,
    copy_tree_free_space_needed,
    free_bytes,
    snapshot_store,
)

logger = logging.getLogger("dtvp.backup")

DUMP_SUFFIX = ".dtvp-dump.zip"
TMP_PREFIX = ".dtvp-dump-tmp-"
READ_ATTEMPTS = 3
READ_RETRY_SECONDS = 0.1
DEFAULT_LABEL = "dtvp"
MAX_LISTED_WARNINGS = 5


def get_backup_path() -> str:
    return os.getenv("DTVP_BACKUP_PATH", "").strip() or os.path.join("data", "backups")


@dataclass
class ExportResult:
    path: str | None
    sidecar: str | None
    bytes: int
    duration_seconds: float
    records: dict[str, int]
    warnings: list[str]
    manifest: dict[str, Any] = field(repr=False)


def dump_filename(label: str, created: datetime, *, with_credentials: bool) -> str:
    stamp = created.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = "-with-credentials" if with_credentials else ""
    return f"{label}-{stamp}{suffix}"


def dump_name_pattern(label: str) -> re.Pattern[str]:
    """The full file names ``dump_filename`` and ``_free_name`` give a dump
    of ``label``, and no others: a dump labelled ``dtvp-before-upgrade``
    does not belong to the label ``dtvp``."""
    return re.compile(
        re.escape(label)
        + r"-\d{8}T\d{6}Z(?:-with-credentials)?(?:-\d+)?"
        + re.escape(DUMP_SUFFIX)
    )


def _free_name(directory: str, stem: str) -> str:
    """A dump name in ``directory`` that no other export can take.

    The name is reserved by creating an empty file exclusively, so two
    exports into one directory with the same label in the same second (two
    instances sharing a backup directory, or a scheduled and a manual dump)
    get different names. The export replaces the reservation with the dump,
    or removes it when it fails.
    """
    number = 1
    while True:
        name = stem + DUMP_SUFFIX if number == 1 else f"{stem}-{number}{DUMP_SUFFIX}"
        candidate = os.path.join(directory, name)
        try:
            descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            number += 1
            continue
        os.close(descriptor)
        return candidate


def _release_reservation(path: str | None) -> None:
    """Remove a name reserved by ``_free_name`` that never got its dump."""
    if not path:
        return
    try:
        if os.path.getsize(path) == 0:
            os.remove(path)
    except OSError:
        pass


def _read_file(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def read_stable(path: str, *, must_be_object: bool = False) -> bytes | None:
    """Read a file twice and compare (E2); refuse one that is not JSON (E3).
    None when it does not exist."""
    for attempt in range(READ_ATTEMPTS):
        try:
            first = _read_file(path)
            second = _read_file(path)
        except FileNotFoundError:
            if os.path.exists(path):  # pragma: no cover - appeared in between
                continue
            return None
        if hashlib.sha256(first).digest() == hashlib.sha256(second).digest():
            break
        if attempt + 1 < READ_ATTEMPTS:
            time.sleep(READ_RETRY_SECONDS)
    else:
        raise DumpError("E2", f"{path} changed while it was read; try again")
    try:
        parsed = json.loads(first)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DumpError("E3", f"{path} is not JSON: {exc}") from exc
    if must_be_object and not isinstance(parsed, dict):
        raise DumpError("E3", f"{path} is not a JSON object")
    return first


def summarize(findings: list[Finding]) -> list[str]:
    """Warnings as text, at most a few per rule."""
    by_code: dict[str, list[Finding]] = {}
    for finding in findings:
        by_code.setdefault(finding.code, []).append(finding)
    lines: list[str] = []
    for code, items in by_code.items():
        lines.extend(str(item) for item in items[:MAX_LISTED_WARNINGS])
        if len(items) > MAX_LISTED_WARNINGS:
            lines.append(f"{code}: and {len(items) - MAX_LISTED_WARNINGS} more")
    return lines


def _dependency_track_url() -> str | None:
    try:
        from ..dt_client import DTSettings

        return sanitize_dependency_track_url(DTSettings().api_url)
    except Exception:  # pragma: no cover - configuration errors
        return None


def snapshot_dir_prefix(stores: InstanceStores) -> str:
    """The name prefix of this instance's snapshot directories. It carries a
    digest of the instance's export lock, so that instances sharing a backup
    or temporary directory never take each other's directories for stale."""
    owner = hashlib.sha256(os.path.realpath(stores.export_lock_path).encode()).hexdigest()
    return f"{TMP_PREFIX}{owner[:16]}-"


def sweep_stale_temp_dirs(tmp_root: str, prefix: str) -> list[str]:
    """Remove snapshot directories of this instance's exports that did not
    clean up. Only called while holding this instance's export lock, so none
    of the directories with this instance's ``prefix`` is in use; those of
    other instances are left alone."""
    removed = []
    for path in glob.glob(os.path.join(glob.escape(tmp_root), glob.escape(prefix) + "*")):
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
            removed.append(path)
    return removed


def _describe(entity: str) -> Callable[[dict[str, Any]], str]:
    natural_key = ENTITIES[entity].natural_key
    return lambda record: repr(natural_key(record))


def _validated(entity: str, records, checker: RecordChecker):
    for record in records:
        problems = schemas.errors(entity, record)
        if problems:
            raise DumpError(
                "S1",
                f"The {entity} record {_describe(entity)(record)} cannot be dumped: "
                + "; ".join(schemas.describe(problem) for problem in problems[:3]),
            )
        checker.add(entity, record)
        yield record


def write_dump(
    source: SqliteDumpSource,
    output: IO[bytes],
    *,
    dump_id: str,
    created_at: datetime,
    created_by: str,
    reason: str,
    dependency_track_url: str | None,
) -> tuple[dict[str, Any], RecordChecker]:
    """Stream every entity, the settings and the manifest into ``output``."""
    writer = DumpWriter(output)
    try:
        manifest, checker = _write_dump(
            source,
            writer,
            dump_id=dump_id,
            created_at=created_at,
            created_by=created_by,
            reason=reason,
            dependency_track_url=dependency_track_url,
        )
    except BaseException:
        writer.abort()
        raise
    writer.close()
    return manifest, checker


def _write_dump(
    source: SqliteDumpSource,
    writer: DumpWriter,
    *,
    dump_id: str,
    created_at: datetime,
    created_by: str,
    reason: str,
    dependency_track_url: str | None,
) -> tuple[dict[str, Any], RecordChecker]:
    checker = RecordChecker()
    entities: dict[str, Any] = {}
    for name in schemas.ENTITY_ORDER:
        entities[name] = writer.write_entity(
            name,
            _validated(name, source.iter_entity(name), checker),
            describe=_describe(name),
        )
    sequences = source.sequences()
    config = source.config()
    config_entries = {name: writer.write_config(name, config.get(name)) for name in SETTINGS_FILE_NAMES}
    checker.finish(sequences)
    if checker.errors:
        raise DumpError(checker.errors[0].code, checker.errors[0].message)
    features = [schemas.FEATURE_CREDENTIALS] if source.include_access_tokens else []
    excluded = []
    if not source.include_source:
        excluded.append("source")
    if not source.include_access_tokens:
        excluded.append("access_tokens")
    manifest = {
        "format": schemas.FORMAT,
        "format_version": schemas.FORMAT_VERSION,
        "format_minor": schemas.FORMAT_MINOR,
        "required_features": features,
        "dump_id": dump_id,
        "created_at": created_at.astimezone(UTC).isoformat(),
        "created_by": created_by,
        "reason": reason,
        "scope": {"kind": schemas.SCOPE_INSTANCE},
        "dtvp": {"version": str(VERSION), "build_commit": str(BUILD_COMMIT)},
        "source": {"dependency_track_url": dependency_track_url},
        "stores": [info.as_manifest() for info in source.stores()],
        "entities": entities,
        "config": config_entries,
        "excluded": excluded,
        "contains_credentials": bool(features),
        "cut_point": {"sequences": sequences, "event_log_high_water_mark": None},
        "warnings": summarize(checker.warnings),
    }
    problems = schemas.errors("manifest", manifest)
    if problems:  # pragma: no cover - a bug in this module
        raise DumpError("F5", "; ".join(schemas.describe(p) for p in problems))
    writer.write_manifest(manifest)
    return manifest, checker


def open_snapshot_source(
    stores: InstanceStores,
    tmp_dir: str,
    *,
    include_access_tokens: bool,
    include_source: bool,
) -> SqliteDumpSource:
    """Snapshot every store (outbox, main, tokens, code analysis), check
    their migration state, and read the record files and settings."""
    order = {"assessment_outbox": 0, "main": 1, "access_tokens": 2, "code_analysis_results": 3}
    snapshots = []
    for store in sorted(stores.sqlite_records, key=lambda item: order.get(item.name, 9)):
        snapshot = snapshot_store(store, tmp_dir, include_access_tokens=include_access_tokens)
        check_migration_state(snapshot)
        snapshots.append(snapshot)
    by_name = {snapshot.name: snapshot for snapshot in snapshots}
    snapshots = [by_name[store.name] for store in stores.sqlite_records]
    return SqliteDumpSource(
        snapshots,
        tmrescore=read_stable(stores.json_record_path("tmrescore_proposals"), must_be_object=True),
        config={item.name: read_stable(item.path) for item in stores.config},
        include_access_tokens=include_access_tokens,
        include_source=include_source,
    )


def export_dump(
    *,
    out: str | None = None,
    directory: str | None = None,
    label: str = DEFAULT_LABEL,
    include_access_tokens: bool = False,
    include_source: bool = True,
    tmp_dir: str | None = None,
    reason: str = "manual",
    created_by: str | None = None,
    stores: InstanceStores | None = None,
    stdout: IO[bytes] | None = None,
) -> ExportResult:
    """Write a dump of the instance. ``out`` is a file, or ``-`` for
    standard output; otherwise a new file in ``directory`` (default
    ``DTVP_BACKUP_PATH``)."""
    started = time.monotonic()
    stores = stores or resolve_instance_stores()
    created_at = datetime.now(UTC)
    if stores.journals():
        raise DumpError(
            "E6",
            "A restore of this instance did not finish; run `python -m dtvp.backup "
            "recover --resume` or `--abort` first",
        )
    os.makedirs(stores.dt_cache_dir, exist_ok=True)
    lock = try_lock_exclusive(stores.export_lock_path)
    if lock is None:
        raise DumpError("E5", "Another export or a restore is running")
    to_stdout = out == "-"
    if to_stdout:
        path = None
        tmp_root = tmp_dir or stores.dt_cache_dir
    else:
        if out:
            path = os.path.abspath(out)
        else:
            target_dir = os.path.abspath(directory or get_backup_path())
            os.makedirs(target_dir, exist_ok=True)
            path = _free_name(
                target_dir,
                dump_filename(label, created_at, with_credentials=include_access_tokens),
            )
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp_root = tmp_dir or os.path.dirname(path)
    snapshot_dir = None
    source = None
    reserved = path if (path and not out and not to_stdout) else None
    written = False
    try:
        os.makedirs(tmp_root, exist_ok=True)
        prefix = snapshot_dir_prefix(stores)
        sweep_stale_temp_dirs(tmp_root, prefix)
        needed = copy_tree_free_space_needed([store.path for store in stores.sqlite_records])
        available = free_bytes(tmp_root)
        if available < needed:
            raise DumpError(
                "E7",
                f"{tmp_root} has {available} bytes free; the snapshots need about {needed}",
            )
        snapshot_dir = tempfile.mkdtemp(prefix=prefix, dir=tmp_root)
        source = open_snapshot_source(
            stores,
            snapshot_dir,
            include_access_tokens=include_access_tokens,
            include_source=include_source,
        )
        details = dict(
            dump_id=str(uuid.uuid4()),
            created_at=created_at,
            created_by=created_by or _user(),
            reason=reason,
            dependency_track_url=_dependency_track_url(),
        )
        if to_stdout:
            output = stdout or sys.stdout.buffer
            manifest, checker = write_dump(source, output, **details)
            output.flush()
            size = 0
            sidecar = None
        else:
            with atomic_output(path, mode=0o600) as handle:
                manifest, checker = write_dump(source, handle, **details)
            written = True
            size = os.path.getsize(path)
            sidecar = path + ".sha256"
            atomic_write_bytes(
                sidecar,
                f"{_file_sha256(path)}  {os.path.basename(path)}\n".encode(),
                mode=0o600,
            )
    finally:
        if source is not None:
            source.close()
        if snapshot_dir is not None:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        if reserved and not written:
            _release_reservation(reserved)
        unlock(lock)
    result = ExportResult(
        path=path,
        sidecar=sidecar,
        bytes=size,
        duration_seconds=time.monotonic() - started,
        records={name: spec["records"] for name, spec in manifest["entities"].items()},
        warnings=list(manifest["warnings"]),
        manifest=manifest,
    )
    logger.info(
        "Instance dump %s written in %.1f s (%d bytes): %s%s",
        os.path.basename(path) if path else "to standard output",
        result.duration_seconds,
        result.bytes,
        ", ".join(f"{count} {name}" for name, count in result.records.items() if count) or "no records",
        f"; {len(result.warnings)} warning(s)" if result.warnings else "",
    )
    return result


def _user() -> str:
    try:
        return getpass.getuser() or "unknown"
    except Exception:
        return "unknown"


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
