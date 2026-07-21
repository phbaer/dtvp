"""Operational checks for DTVP's durable local state."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .analysis_queue_state_services import get_analysis_queue_state_path
from .code_analysis_result_services import get_code_analysis_results_sqlite_path
from .dt_cache import get_dt_cache_path
from .grouped_vuln_summary_index_services import get_grouped_vuln_summary_index_path
from .project_archive_services import (
    get_project_archive_expanded_path,
    get_project_archive_path,
)
from .security_audit import get_security_audit_path
from .tmrescore_cache_services import get_tmrescore_cache_path


@dataclass(frozen=True, slots=True)
class StatePath:
    name: str
    path: str
    kind: str


def get_backup_status_path() -> str:
    return os.getenv("DTVP_BACKUP_STATUS_PATH", "data/backup_status.json").strip()


def get_backup_max_age_seconds() -> int:
    raw = os.getenv("DTVP_BACKUP_MAX_AGE_SECONDS", "0")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def get_storage_min_free_bytes() -> int:
    raw = os.getenv("DTVP_STORAGE_MIN_FREE_BYTES", str(128 * 1024 * 1024))
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 128 * 1024 * 1024


def durable_state_paths() -> list[StatePath]:
    paths = [
        StatePath("vulnerability_cache", get_dt_cache_path(), "directory"),
        StatePath(
            "grouped_summary_index",
            get_grouped_vuln_summary_index_path(),
            "sqlite",
        ),
        StatePath("analysis_queue", get_analysis_queue_state_path(), "sqlite"),
        StatePath(
            "analysis_results",
            get_code_analysis_results_sqlite_path(),
            "sqlite",
        ),
        StatePath("tmrescore_proposals", get_tmrescore_cache_path(), "json"),
        StatePath("project_archives", get_project_archive_path(), "directory"),
        StatePath("security_audit", get_security_audit_path(), "append_log"),
        StatePath(
            "team_mapping",
            os.getenv("TEAM_MAPPING_PATH", "data/team_mapping.json"),
            "json",
        ),
        StatePath(
            "user_roles",
            os.getenv("USER_ROLES_PATH", "data/user_roles.json"),
            "json",
        ),
        StatePath(
            "rescore_rules",
            os.getenv("RESCORE_RULES_PATH", "data/rescore_rules.json"),
            "json",
        ),
        StatePath(
            "auto_analysis_guidance",
            os.getenv(
                "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH",
                "data/auto_analysis_guidance.json",
            ),
            "json",
        ),
    ]
    if os.getenv("DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        paths.append(
            StatePath(
                "expanded_project_archives",
                get_project_archive_expanded_path(),
                "directory",
            )
        )
    return [item for item in paths if item.path]


def _nearest_existing_parent(path: Path) -> Path:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _sqlite_integrity(path: Path) -> str:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
        row = connection.execute("PRAGMA quick_check").fetchone()
    return str(row[0]) if row else "no result"


def inspect_state_path(item: StatePath, *, min_free_bytes: int) -> dict[str, Any]:
    path = Path(item.path)
    exists = path.exists()
    parent = path if item.kind == "directory" else path.parent
    access_target = _nearest_existing_parent(parent)
    write_target = path if exists else access_target
    writable = os.access(write_target, os.W_OK)
    readable = not exists or os.access(path, os.R_OK)
    free_bytes: int | None = None
    error: str | None = None
    integrity: str | None = None
    try:
        stats = os.statvfs(access_target)
        free_bytes = int(stats.f_bavail * stats.f_frsize)
        if exists and item.kind == "directory" and not path.is_dir():
            error = "Expected a directory"
        elif exists and item.kind != "directory" and not path.is_file():
            error = "Expected a regular file"
        elif exists and item.kind == "sqlite":
            integrity = _sqlite_integrity(path)
            if integrity.lower() != "ok":
                error = f"SQLite quick_check returned {integrity}"
        elif exists and item.kind == "json":
            with path.open(encoding="utf-8") as handle:
                json.load(handle)
            integrity = "ok"
    except (OSError, sqlite3.DatabaseError, json.JSONDecodeError) as exc:
        error = f"{exc.__class__.__name__}: {exc}"

    enough_space = free_bytes is None or free_bytes >= min_free_bytes
    healthy = writable and readable and enough_space and error is None
    return {
        "kind": item.kind,
        "path": str(path),
        "exists": exists,
        "readable": readable,
        "writable": writable,
        "free_bytes": free_bytes,
        "minimum_free_bytes": min_free_bytes,
        "integrity": integrity,
        "healthy": healthy,
        "error": error,
    }


def backup_health(*, now: datetime | None = None) -> dict[str, Any]:
    status_path = Path(get_backup_status_path())
    max_age_seconds = get_backup_max_age_seconds()
    payload: dict[str, Any] = {}
    error: str | None = None
    if status_path.exists():
        try:
            loaded = json.loads(status_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("backup status must be a JSON object")
            payload = loaded
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            error = f"{exc.__class__.__name__}: {exc}"

    completed_at = payload.get("completed_at")
    age_seconds: int | None = None
    if completed_at and error is None:
        try:
            completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
            if completed.tzinfo is None:
                completed = completed.replace(tzinfo=UTC)
            age = (now or datetime.now(UTC)) - completed.astimezone(UTC)
            if age.total_seconds() < -300:
                raise ValueError("completed_at is more than five minutes in the future")
            age_seconds = max(0, int(age.total_seconds()))
        except ValueError as exc:
            error = f"ValueError: invalid completed_at: {exc}"

    configured = max_age_seconds > 0
    healthy = error is None and (
        not configured
        or (age_seconds is not None and age_seconds <= max_age_seconds)
    )
    return {
        "configured": configured,
        "status_path": str(status_path),
        "completed_at": completed_at,
        "age_seconds": age_seconds,
        "maximum_age_seconds": max_age_seconds,
        "healthy": healthy,
        "error": error,
    }


def durable_storage_health(
    paths: Iterable[StatePath] | None = None,
) -> dict[str, Any]:
    min_free_bytes = get_storage_min_free_bytes()
    stores = {
        item.name: inspect_state_path(item, min_free_bytes=min_free_bytes)
        for item in (paths if paths is not None else durable_state_paths())
    }
    backup = backup_health()
    stores_healthy = all(store["healthy"] for store in stores.values())
    return {
        "healthy": stores_healthy and backup["healthy"],
        "stores_healthy": stores_healthy,
        "stores": stores,
        "backup": backup,
    }


def validate_durable_storage() -> None:
    status = durable_storage_health()
    unhealthy = [
        name for name, details in status["stores"].items() if not details["healthy"]
    ]
    if unhealthy:
        raise RuntimeError(
            "DTVP durable storage is unavailable or corrupt: " + ", ".join(unhealthy)
        )
