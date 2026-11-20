"""Scheduled instance dumps inside the backend, and pruning of old dumps.

Off by default (``DTVP_BACKUP_INTERVAL_SECONDS=0``). A host cron job running
``python -m dtvp.backup export`` and ``prune`` is an equal alternative. Each
run exports, verifies the new file, prunes, and records its outcome for
``/api/performance-status``; it is skipped while another export or a restore
holds the export lock.
"""

import asyncio
import logging
import os
import re
import threading
from datetime import UTC, datetime
from typing import Any

from .container import DumpReader
from .errors import DumpError
from .export import dump_name_pattern, export_dump, get_backup_path
from .verify import verify_dump

logger = logging.getLogger("dtvp.backup")

MINIMUM_INTERVAL_SECONDS = 3600
ENABLED_VALUES = {"1", "true", "yes", "on", "enabled"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip() or default)
    except ValueError:
        return default


def get_backup_interval_seconds() -> int:
    """0 means off; a positive value below an hour is raised to an hour."""
    value = _int_env("DTVP_BACKUP_INTERVAL_SECONDS", 0)
    if value <= 0:
        return 0
    if value < MINIMUM_INTERVAL_SECONDS:
        logger.warning(
            "DTVP_BACKUP_INTERVAL_SECONDS=%d is below the minimum; using %d",
            value,
            MINIMUM_INTERVAL_SECONDS,
        )
        return MINIMUM_INTERVAL_SECONDS
    return value


def get_backup_retention_count() -> int:
    return max(1, _int_env("DTVP_BACKUP_RETENTION_COUNT", 7))


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ENABLED_VALUES


def get_backup_label() -> str:
    return os.getenv("DTVP_BACKUP_LABEL", "").strip() or "dtvp"


_status_lock = threading.Lock()
_status: dict[str, Any] = {
    "last_success_at": None,
    "last_file": None,
    "last_bytes": None,
    "last_duration_seconds": None,
    "last_error": None,
    "last_error_at": None,
}


def get_backup_status() -> dict[str, Any]:
    """For /api/performance-status: no paths, no secrets."""
    interval = get_backup_interval_seconds()
    with _status_lock:
        return {"enabled": interval > 0, "interval_seconds": interval, **_status}


def _record(**values: Any) -> None:
    with _status_lock:
        _status.update(values)


def reset_backup_status() -> None:
    _record(**dict.fromkeys(_status))


def prune_dumps(directory: str, keep: int, *, label: str = "dtvp") -> list[str]:
    """Delete the oldest dumps beyond ``keep``, each with its sidecar.

    Only files named exactly as an export names a dump of ``label``
    (``<label>-<yyyymmddTHHMMSSZ>[-with-credentials][-N].dtvp-dump.zip``)
    whose container and manifest check out are considered, ordered by the manifest's
    ``created_at`` (never by file time). Other files are never deleted.
    """
    keep = max(1, int(keep))
    pattern = dump_name_pattern(label)
    candidates: list[tuple[str, str]] = []
    if not os.path.isdir(directory):
        return []
    for name in sorted(os.listdir(directory)):
        if not pattern.fullmatch(name):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        try:
            with DumpReader(path) as reader:
                candidates.append((reader.manifest["created_at"], path))
        except (DumpError, OSError) as exc:
            logger.info("Not pruning %s: it is not a readable dump (%s)", name, exc)
    candidates.sort(reverse=True)
    removed = []
    for _created, path in candidates[keep:]:
        for victim in (path, path + ".sha256"):
            try:
                os.remove(victim)
            except FileNotFoundError:
                pass
        removed.append(path)
    return removed


def run_scheduled_backup_once() -> dict[str, Any] | None:
    """Export, verify, prune. Returns the outcome, or None when skipped
    because another export or a restore is running."""
    directory = get_backup_path()
    label = get_backup_label()
    try:
        result = export_dump(
            directory=directory,
            label=label,
            include_access_tokens=_flag("DTVP_BACKUP_INCLUDE_ACCESS_TOKENS", False),
            include_source=_flag("DTVP_BACKUP_INCLUDE_SOURCE", True),
            reason="scheduled",
            created_by="scheduler",
        )
    except DumpError as exc:
        if exc.code == "E5":
            logger.info("Scheduled dump skipped: another export or a restore is running")
            return None
        _failed(exc)
        return None
    except Exception as exc:  # noqa: BLE001 - reported in the status
        _failed(exc)
        return None
    try:
        verified = verify_dump(result.path)
        if verified.errors:
            raise DumpError(verified.errors[0].code, verified.errors[0].message)
        removed = prune_dumps(directory, get_backup_retention_count(), label=label)
    except Exception as exc:  # noqa: BLE001 - reported in the status
        _failed(exc)
        return None
    _record(
        last_success_at=datetime.now(UTC).isoformat(),
        last_file=os.path.basename(result.path),
        last_bytes=result.bytes,
        last_duration_seconds=round(result.duration_seconds, 3),
        last_error=None,
        last_error_at=None,
    )
    return {"file": os.path.basename(result.path), "pruned": [os.path.basename(p) for p in removed]}


_PATH = re.compile(r"(?:/[^\s:,;'\"()]+)+")


def _without_paths(message: str) -> str:
    """The status is shown in the UI: file names only, no directories."""
    return _PATH.sub(lambda match: os.path.basename(match.group(0)), message)


def _failed(exc: BaseException) -> None:
    logger.warning("Scheduled instance dump failed: %s", exc)
    _record(
        last_error=_without_paths(str(exc)),
        last_error_at=datetime.now(UTC).isoformat(),
    )


async def run_backup_loop() -> None:
    """Dump every DTVP_BACKUP_INTERVAL_SECONDS; returns at once when off."""
    interval = get_backup_interval_seconds()
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        await asyncio.to_thread(run_scheduled_backup_once)
        interval = get_backup_interval_seconds() or interval
