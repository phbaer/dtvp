import copy
import json
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .sqlite_migration_services import run_sqlite_migrations


ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE = "assessment_outbox"
AssessmentKey = tuple[str, str, str]


class AssessmentOutboxConflictError(Exception):
    pass


class AssessmentRevisionConflictError(Exception):
    def __init__(
        self,
        key: AssessmentKey,
        expected_revision: int,
        current_revision: int,
    ) -> None:
        self.key = key
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            "Assessment revision changed for "
            f"{'/'.join(key)}: expected {expected_revision}, "
            f"found {current_revision}"
        )


def get_assessment_outbox_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "assessment_outbox"


def get_assessment_outbox_path(cache_path: str | None = None) -> str:
    configured = os.getenv("DTVP_ASSESSMENT_OUTBOX_PATH", "").strip()
    if configured:
        return configured
    resolved_cache_path = cache_path or os.getenv(
        "DTVP_DT_CACHE_PATH",
        "data/dt_cache",
    )
    return str(Path(resolved_cache_path) / "assessment_outbox.sqlite")


def assessment_key(payload: dict[str, Any]) -> AssessmentKey | None:
    values = tuple(
        str(payload.get(field) or "").strip()
        for field in (
            "project_uuid",
            "component_uuid",
            "vulnerability_uuid",
        )
    )
    if not all(values):
        return None
    return values  # type: ignore[return-value]


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _payload_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _decode_payload(value: Any) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


class AssessmentOutboxStore:
    def __init__(self, path: str, logger: Any = None) -> None:
        self.path = path
        self.logger = logger
        self._lock = threading.RLock()
        self._initialized = False
        self._states: dict[AssessmentKey, dict[str, Any]] = {}
        self._pending: dict[AssessmentKey, dict[str, Any]] = {}

    def _connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _ensure_initialized(self) -> None:
        with self._lock:
            if self._initialized:
                return
            with closing(self._connect()) as connection:
                run_sqlite_migrations(
                    connection,
                    namespace=ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE,
                    migrations_path=get_assessment_outbox_migrations_path(),
                    logger=self.logger,
                )
                state_rows = connection.execute(
                    """
                    SELECT *
                    FROM assessment_state
                    """
                ).fetchall()
                pending_rows = connection.execute(
                    """
                    SELECT *
                    FROM assessment_outbox
                    ORDER BY created_at, update_id
                    """
                ).fetchall()
            self._states = {
                self._row_key(row): self._state_record(row)
                for row in state_rows
            }
            self._pending = {
                self._row_key(row): self._pending_record(row)
                for row in pending_rows
            }
            self._initialized = True

    @staticmethod
    def _row_key(row: sqlite3.Row) -> AssessmentKey:
        return (
            str(row["project_uuid"]),
            str(row["component_uuid"]),
            str(row["vulnerability_uuid"]),
        )

    @staticmethod
    def _state_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "project_uuid": str(row["project_uuid"]),
            "component_uuid": str(row["component_uuid"]),
            "vulnerability_uuid": str(row["vulnerability_uuid"]),
            "revision": int(row["revision"]),
            "analysisState": str(row["analysis_state"]),
            "analysisDetails": str(row["analysis_details"]),
            "isSuppressed": bool(row["suppressed"]),
            "sync_status": str(row["sync_status"]),
            "update_id": row["update_id"],
            "last_error": row["last_error"],
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _pending_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["update_id"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "revision": int(row["revision"]),
            "attempts": int(row["attempts"]),
            "next_attempt_at": row["next_attempt_at"],
            "last_error": row["last_error"],
            "payload": _decode_payload(row["payload_json"]),
        }

    def enqueue_many(
        self,
        payloads: Iterable[dict[str, Any]],
        *,
        replace: bool = True,
        expected_revisions: dict[AssessmentKey, int] | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_initialized()
        deduplicated: dict[AssessmentKey, dict[str, Any]] = {}
        for payload in payloads:
            normalized = dict(payload)
            key = assessment_key(normalized)
            if key is None:
                raise ValueError("Assessment payload is missing its finding identity")
            deduplicated.pop(key, None)
            deduplicated[key] = normalized
        if not deduplicated:
            return []

        now = _utc_now_iso()
        records: list[tuple[AssessmentKey, dict[str, Any], dict[str, Any]]] = []
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    for key, payload in deduplicated.items():
                        existing_state = connection.execute(
                            """
                            SELECT revision
                            FROM assessment_state
                            WHERE project_uuid = ?
                              AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        ).fetchone()
                        current_revision = (
                            int(existing_state["revision"])
                            if existing_state is not None
                            else 0
                        )
                        expected_revision = (
                            expected_revisions.get(key)
                            if expected_revisions is not None
                            else None
                        )
                        if (
                            expected_revision is not None
                            and expected_revision != current_revision
                        ):
                            raise AssessmentRevisionConflictError(
                                key,
                                expected_revision,
                                current_revision,
                            )

                        existing_pending = connection.execute(
                            """
                            SELECT update_id, created_at
                            FROM assessment_outbox
                            WHERE project_uuid = ?
                              AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        ).fetchone()
                        if existing_pending is not None and not replace:
                            raise AssessmentOutboxConflictError(
                                "A pending update already exists for this finding."
                            )

                        revision = current_revision + 1
                        update_id = str(uuid.uuid4())
                        created_at = (
                            str(existing_pending["created_at"])
                            if existing_pending is not None
                            else now
                        )
                        connection.execute(
                            """
                            INSERT INTO assessment_state (
                                project_uuid,
                                component_uuid,
                                vulnerability_uuid,
                                revision,
                                analysis_state,
                                analysis_details,
                                suppressed,
                                sync_status,
                                update_id,
                                last_error,
                                updated_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, ?)
                            ON CONFLICT (
                                project_uuid,
                                component_uuid,
                                vulnerability_uuid
                            ) DO UPDATE SET
                                revision = excluded.revision,
                                analysis_state = excluded.analysis_state,
                                analysis_details = excluded.analysis_details,
                                suppressed = excluded.suppressed,
                                sync_status = excluded.sync_status,
                                update_id = excluded.update_id,
                                last_error = NULL,
                                updated_at = excluded.updated_at
                            """,
                            (
                                *key,
                                revision,
                                str(payload.get("state") or "NOT_SET"),
                                str(payload.get("details") or ""),
                                int(bool(payload.get("suppressed", False))),
                                update_id,
                                now,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO assessment_outbox (
                                project_uuid,
                                component_uuid,
                                vulnerability_uuid,
                                revision,
                                update_id,
                                payload_json,
                                attempts,
                                next_attempt_at,
                                last_error,
                                created_at,
                                updated_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
                            ON CONFLICT (
                                project_uuid,
                                component_uuid,
                                vulnerability_uuid
                            ) DO UPDATE SET
                                revision = excluded.revision,
                                update_id = excluded.update_id,
                                payload_json = excluded.payload_json,
                                attempts = 0,
                                next_attempt_at = NULL,
                                last_error = NULL,
                                updated_at = excluded.updated_at
                            """,
                            (
                                *key,
                                revision,
                                update_id,
                                _payload_json(payload),
                                created_at,
                                now,
                            ),
                        )
                        state = {
                            "project_uuid": key[0],
                            "component_uuid": key[1],
                            "vulnerability_uuid": key[2],
                            "revision": revision,
                            "analysisState": str(payload.get("state") or "NOT_SET"),
                            "analysisDetails": str(payload.get("details") or ""),
                            "isSuppressed": bool(payload.get("suppressed", False)),
                            "sync_status": "pending",
                            "update_id": update_id,
                            "last_error": None,
                            "updated_at": now,
                        }
                        pending = {
                            "id": update_id,
                            "created_at": created_at,
                            "updated_at": now,
                            "revision": revision,
                            "attempts": 0,
                            "next_attempt_at": None,
                            "last_error": None,
                            "payload": copy.deepcopy(payload),
                        }
                        records.append((key, state, pending))

            for key, state, pending in records:
                self._states[key] = state
                self._pending[key] = pending
            return [copy.deepcopy(pending) for _key, _state, pending in records]

    def get_overlay(self, key: AssessmentKey) -> dict[str, Any] | None:
        self._ensure_initialized()
        with self._lock:
            state = self._states.get(key)
            return copy.deepcopy(state) if state is not None else None

    def get_revision(self, key: AssessmentKey) -> int:
        overlay = self.get_overlay(key)
        return int(overlay.get("revision") or 0) if overlay else 0

    def list_pending(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        with self._lock:
            values = sorted(
                self._pending.values(),
                key=lambda value: (
                    str(value.get("created_at") or ""),
                    str(value.get("id") or ""),
                ),
            )
            return copy.deepcopy(values)

    def list_due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        return [
            record
            for record in self.list_pending()
            if self._is_due(record.get("next_attempt_at"), current)
        ]

    @staticmethod
    def _is_due(value: Any, now: datetime) -> bool:
        if not value:
            return True
        try:
            due_at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if due_at.tzinfo is None:
                due_at = due_at.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return True
        return due_at.astimezone(UTC) <= now

    def pending_count(self) -> int:
        self._ensure_initialized()
        with self._lock:
            return len(self._pending)

    def mark_synced(self, key: AssessmentKey, revision: int) -> bool:
        self._ensure_initialized()
        now = _utc_now_iso()
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    deleted = connection.execute(
                        """
                        DELETE FROM assessment_outbox
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (*key, revision),
                    ).rowcount
                    if not deleted:
                        return False
                    connection.execute(
                        """
                        UPDATE assessment_state
                        SET sync_status = 'synced',
                            last_error = NULL,
                            updated_at = ?
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (now, *key, revision),
                    )
            pending = self._pending.get(key)
            if pending is not None and int(pending.get("revision") or 0) == revision:
                self._pending.pop(key, None)
            state = self._states.get(key)
            if state is not None and int(state.get("revision") or 0) == revision:
                state["sync_status"] = "synced"
                state["last_error"] = None
                state["updated_at"] = now
            return True

    def mark_failed(
        self,
        key: AssessmentKey,
        revision: int,
        error: str,
        *,
        next_attempt_at: str | None = None,
    ) -> bool:
        self._ensure_initialized()
        now = _utc_now_iso()
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    updated = connection.execute(
                        """
                        UPDATE assessment_outbox
                        SET attempts = attempts + 1,
                            next_attempt_at = ?,
                            last_error = ?,
                            updated_at = ?
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (next_attempt_at, error, now, *key, revision),
                    ).rowcount
                    if not updated:
                        return False
                    connection.execute(
                        """
                        UPDATE assessment_state
                        SET sync_status = 'error',
                            last_error = ?,
                            updated_at = ?
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (error, now, *key, revision),
                    )
            pending = self._pending.get(key)
            if pending is not None and int(pending.get("revision") or 0) == revision:
                pending["attempts"] = int(pending.get("attempts") or 0) + 1
                pending["next_attempt_at"] = next_attempt_at
                pending["last_error"] = error
                pending["updated_at"] = now
            state = self._states.get(key)
            if state is not None and int(state.get("revision") or 0) == revision:
                state["sync_status"] = "error"
                state["last_error"] = error
                state["updated_at"] = now
            return True

    def discard(self, update_id: str) -> bool:
        self._ensure_initialized()
        now = _utc_now_iso()
        with self._lock:
            pending_match = next(
                (
                    (key, record)
                    for key, record in self._pending.items()
                    if record.get("id") == update_id
                ),
                None,
            )
            if pending_match is None:
                return False
            key, pending = pending_match
            revision = int(pending.get("revision") or 0)
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        DELETE FROM assessment_outbox
                        WHERE update_id = ?
                        """,
                        (update_id,),
                    )
                    connection.execute(
                        """
                        UPDATE assessment_state
                        SET sync_status = 'cancelled',
                            updated_at = ?
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (now, *key, revision),
                    )
            self._pending.pop(key, None)
            state = self._states.get(key)
            if state is not None and int(state.get("revision") or 0) == revision:
                state["sync_status"] = "cancelled"
                state["updated_at"] = now
            return True

    def import_legacy(self, entries: Iterable[dict[str, Any]]) -> int:
        self._ensure_initialized()
        marker_key = "legacy_pending_updates_imported"
        with self._lock:
            with closing(self._connect()) as connection:
                imported = connection.execute(
                    """
                    SELECT value
                    FROM assessment_outbox_metadata
                    WHERE key = ?
                    """,
                    (marker_key,),
                ).fetchone()
            if imported is not None:
                return 0

        payloads = [
            dict(entry.get("payload") or {})
            for entry in entries
            if isinstance(entry, dict) and assessment_key(entry.get("payload") or {})
        ]
        records = self.enqueue_many(payloads, replace=True) if payloads else []
        now = _utc_now_iso()
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO assessment_outbox_metadata (
                            key,
                            value,
                            updated_at
                        )
                        VALUES (?, ?, ?)
                        """,
                        (marker_key, str(len(records)), now),
                    )
        return len(records)
