"""Durable, bounded SQLite storage for asynchronous assessment jobs."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from src.api.jobs import Job


JOB_STORE_SCHEMA_VERSION = 1
TERMINAL_JOB_STATUSES = ("completed", "failed", "cancelled")


def get_job_store_path() -> str:
    configured_path = os.environ.get("AGENTYZER_JOB_STORE_PATH", "").strip()
    if configured_path:
        return configured_path
    repos_dir = os.environ.get("AGENTYZER_REPOS_DIR", "repos")
    return os.path.join(repos_dir, "agentyzer_jobs.sqlite")


def get_job_retention_seconds() -> int:
    raw_value = os.environ.get("AGENTYZER_JOB_RETENTION_SECONDS", "604800")
    try:
        return max(0, int(raw_value))
    except (TypeError, ValueError):
        return 604800


def get_job_max_records() -> int:
    raw_value = os.environ.get("AGENTYZER_JOB_MAX_RECORDS", "1000")
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        return 1000


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class JobStore:
    path_provider: Callable[[], str] = get_job_store_path
    retention_seconds_provider: Callable[[], int] = get_job_retention_seconds
    max_records_provider: Callable[[], int] = get_job_max_records
    now_provider: Callable[[], datetime] = _utc_now
    logger: Any = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _initialized_path: str | None = field(default=None, init=False)

    def _raw_connect(self, path: str) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _ensure_initialized_locked(self, path: str) -> None:
        if self._initialized_path == path:
            return
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with closing(self._raw_connect(path)) as connection:
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if schema_version > JOB_STORE_SCHEMA_VERSION:
                raise RuntimeError(
                    "Agentyzer job store schema is newer than this service supports: "
                    f"{schema_version} > {JOB_STORE_SCHEMA_VERSION}"
                )
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS jobs (
                        job_id TEXT PRIMARY KEY,
                        owner TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        finished_at TEXT,
                        updated_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS jobs_owner_created_idx "
                    "ON jobs (owner, created_at)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS jobs_status_finished_idx "
                    "ON jobs (status, finished_at)"
                )
                connection.execute(f"PRAGMA user_version = {JOB_STORE_SCHEMA_VERSION}")
        try:
            os.chmod(path, 0o600)
        except OSError:
            if self.logger:
                self.logger.warning("Could not restrict job database permissions: %s", path)
        self._initialized_path = path

    def _connect_locked(self) -> sqlite3.Connection:
        path = self.path_provider()
        self._ensure_initialized_locked(path)
        return self._raw_connect(path)

    def _prune_locked(self, connection: sqlite3.Connection) -> set[str]:
        removed: set[str] = set()
        retention_seconds = self.retention_seconds_provider()
        if retention_seconds > 0:
            cutoff = (self.now_provider() - timedelta(seconds=retention_seconds)).isoformat()
            rows = connection.execute(
                """
                SELECT job_id
                FROM jobs
                WHERE status IN (?, ?, ?)
                  AND COALESCE(finished_at, created_at) < ?
                """,
                (*TERMINAL_JOB_STATUSES, cutoff),
            ).fetchall()
            removed.update(str(row[0]) for row in rows)

        total = int(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
        excess = max(0, total - len(removed) - self.max_records_provider())
        if excess:
            placeholders = ",".join("?" for _ in removed)
            exclusion = f"AND job_id NOT IN ({placeholders})" if removed else ""
            rows = connection.execute(
                f"""
                SELECT job_id
                FROM jobs
                WHERE status IN (?, ?, ?)
                {exclusion}
                ORDER BY COALESCE(finished_at, created_at) ASC
                LIMIT ?
                """,
                (*TERMINAL_JOB_STATUSES, *sorted(removed), excess),
            ).fetchall()
            removed.update(str(row[0]) for row in rows)

        if removed:
            placeholders = ",".join("?" for _ in removed)
            connection.execute(
                f"DELETE FROM jobs WHERE job_id IN ({placeholders})",
                tuple(sorted(removed)),
            )
        return removed

    def load(self) -> dict[str, Job]:
        with self._lock, closing(self._connect_locked()) as connection:
            with connection:
                self._prune_locked(connection)
            rows = connection.execute(
                "SELECT job_id, payload_json FROM jobs ORDER BY created_at ASC"
            ).fetchall()

        jobs: dict[str, Job] = {}
        for job_id, payload_json in rows:
            try:
                record = json.loads(payload_json)
                job = Job.from_record(record)
                if job.id != job_id:
                    raise ValueError("job ID does not match persisted key")
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                if self.logger:
                    self.logger.warning(
                        "Ignoring invalid persisted Agentyzer job %s: %s",
                        job_id,
                        exc,
                    )
                continue
            jobs[job.id] = job
        return jobs

    def save(self, job: Job) -> set[str]:
        updated_at = self.now_provider().isoformat()
        payload_json = json.dumps(
            job.to_record(),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock, closing(self._connect_locked()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO jobs (
                        job_id,
                        owner,
                        status,
                        created_at,
                        finished_at,
                        updated_at,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(job_id) DO UPDATE SET
                        owner = excluded.owner,
                        status = excluded.status,
                        created_at = excluded.created_at,
                        finished_at = excluded.finished_at,
                        updated_at = excluded.updated_at,
                        payload_json = excluded.payload_json
                    """,
                    (
                        job.id,
                        job.owner,
                        job.status.value,
                        job.created_at,
                        job.finished_at,
                        updated_at,
                        payload_json,
                    ),
                )
                return self._prune_locked(connection)

    def prune(self) -> set[str]:
        with self._lock, closing(self._connect_locked()) as connection:
            with connection:
                return self._prune_locked(connection)

    def delete(self, job_id: str) -> None:
        with self._lock, closing(self._connect_locked()) as connection:
            with connection:
                connection.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
