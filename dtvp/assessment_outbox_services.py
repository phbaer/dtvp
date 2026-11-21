import copy
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

from .assessment_model import PENDING_REVIEW_MARKER, parse_assessment, version_override
from .local_store import get_database_path
from .sqlite_migration_services import run_sqlite_migrations
from .startup_progress import report_startup_progress


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


class AssessmentRecordChangedError(Exception):
    """A record changed since the caller read it: it was created, saved
    again, discarded or superseded in the meantime."""

    def __init__(self, key: AssessmentKey, expected: str, found: str) -> None:
        self.key = key
        super().__init__(
            f"Assessment record of {'/'.join(key)} changed: expected {expected}, "
            f"found {found}"
        )


LEGACY_FILE_IMPORT_KEY = "legacy_outbox_file_imported"
LEGACY_STATE_COLUMNS = (
    "project_uuid, component_uuid, vulnerability_uuid, revision, "
    "analysis_state, analysis_details, suppressed, sync_status, update_id, "
    "last_error, updated_at"
)
LEGACY_OUTBOX_COLUMNS = (
    "project_uuid, component_uuid, vulnerability_uuid, revision, update_id, "
    "payload_json, attempts, next_attempt_at, last_error, created_at, updated_at"
)


def get_assessment_outbox_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "assessment_outbox"


def get_legacy_assessment_outbox_path(cache_path: str | None = None) -> str:
    """Where the outbox lived as its own file before it joined the database."""
    resolved_cache_path = cache_path or os.getenv(
        "DTVP_DT_CACHE_PATH",
        "data/dt_cache",
    )
    return str(Path(resolved_cache_path) / "assessment_outbox.sqlite")


def get_assessment_outbox_path(cache_path: str | None = None) -> str:
    configured = os.getenv("DTVP_ASSESSMENT_OUTBOX_PATH", "").strip()
    if configured:
        return configured
    resolved_cache_path = cache_path or os.getenv(
        "DTVP_DT_CACHE_PATH",
        "data/dt_cache",
    )
    return get_database_path(resolved_cache_path)


FIELD_MIGRATION_REPORT_EVERY = 2000

SYNC_SYNCED = "synced"
SYNC_PENDING = "pending"
SYNC_ERROR = "error"
SYNC_CANCELLED = "cancelled"
# The finding is no longer reported by the source; its assessment is kept.
SYNC_INACTIVE = "inactive"
# Carried over to the finding that replaced this one; kept as history.
SYNC_SUPERSEDED = "superseded"

ORIGIN_USER = "user"
ORIGIN_IMPORT = "import"
# A source value with a version override marker was adopted; the marker
# says something about the other versions that DTVP checks with a review.
ORIGIN_IMPORT_REVIEW = "import-review"
ORIGIN_RESOLUTION = "conflict-resolution"
ORIGIN_DISCARD = "export-discarded"



def assessment_value(
    state: Any,
    details: Any,
    suppressed: Any,
) -> dict[str, Any]:
    """An assessment as the three fields both sides exchange."""
    return {
        "state": str(state or "NOT_SET"),
        "details": str(details or ""),
        "suppressed": bool(suppressed),
    }


def same_assessment(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    """Whether two assessment values mean the same; surrounding whitespace in
    the details is not a difference."""
    if left is None or right is None:
        return left is right
    return (
        str(left.get("state") or "NOT_SET") == str(right.get("state") or "NOT_SET")
        and str(left.get("details") or "").strip()
        == str(right.get("details") or "").strip()
        and bool(left.get("suppressed")) == bool(right.get("suppressed"))
    )


_REVIEW_MARKER = re.compile(r"\s*\[Status: Pending Review\]", re.IGNORECASE)


def source_matches_base(theirs: dict[str, Any], base: dict[str, Any] | None) -> bool:
    """Whether the source still holds the value a local change started from.

    DTVP can show an imported assessment with a pending-review marker it
    added itself; the source's copy does not have it. That marker alone is
    not a change made in the source.
    """
    if base is None:
        return False
    if same_assessment(theirs, base):
        return True
    return same_assessment(
        {**theirs, "details": _REVIEW_MARKER.sub("", str(theirs.get("details") or ""))},
        {**base, "details": _REVIEW_MARKER.sub("", str(base.get("details") or ""))},
    )


def is_blank_assessment(value: dict[str, Any] | None) -> bool:
    """No state, no text, not suppressed: there is nothing to lose here."""
    return value is not None and same_assessment(
        value, {"state": "NOT_SET", "details": "", "suppressed": False}
    )


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


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
    def __init__(
        self,
        path: str,
        logger: Any = None,
        *,
        legacy_path: str | None = None,
    ) -> None:
        self.path = path
        self.logger = logger
        self.legacy_path = legacy_path
        self.legacy_import_report: str | None = None
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
                self._import_legacy_file(connection)
                self._seed_missing_revisions(connection)
                self._sync_fields(connection, None)
                # Row by row: loading every row at once made the start need
                # about twice the memory the records hold.
                self._states = {
                    self._row_key(row): self._state_record(row)
                    for row in connection.execute(
                        """
                        SELECT project_uuid, component_uuid, vulnerability_uuid,
                               revision, analysis_state, analysis_details,
                               suppressed, sync_status, update_id, last_error,
                               updated_at, export_rejections,
                               base_state, base_suppressed,
                               base_same, base_details,
                               remote_state, remote_details, remote_suppressed
                        FROM assessment_state
                        """
                    )
                }
                pending_rows = connection.execute(
                    """
                    SELECT *
                    FROM assessment_outbox
                    ORDER BY created_at, update_id
                    """
                ).fetchall()
            self._pending = {
                self._row_key(row): self._pending_record(row)
                for row in pending_rows
            }
            self._initialized = True

    def _import_legacy_file(self, connection: sqlite3.Connection) -> None:
        """Copy the former stand-alone outbox file into this database once.

        The copy and its marker commit together; the old file is left in
        place and is not read again.
        """
        legacy_path = self.legacy_path
        if (
            not legacy_path
            or not os.path.isfile(legacy_path)
            or os.path.abspath(legacy_path) == os.path.abspath(self.path)
        ):
            return
        marker = connection.execute(
            "SELECT 1 FROM assessment_outbox_metadata WHERE key = ?",
            (LEGACY_FILE_IMPORT_KEY,),
        ).fetchone()
        if marker is not None:
            return
        connection.execute("ATTACH DATABASE ? AS legacy_outbox", (legacy_path,))
        try:
            legacy_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM legacy_outbox.sqlite_master WHERE type = 'table'"
                )
            }
            copied = {"assessments": 0, "pending": 0}
            with connection:
                if "assessment_state" in legacy_tables:
                    copied["assessments"] = connection.execute(
                        f"""
                        INSERT OR IGNORE INTO assessment_state ({LEGACY_STATE_COLUMNS})
                        SELECT {LEGACY_STATE_COLUMNS}
                        FROM legacy_outbox.assessment_state
                        """
                    ).rowcount
                if "assessment_outbox" in legacy_tables:
                    copied["pending"] = connection.execute(
                        f"""
                        INSERT OR IGNORE INTO assessment_outbox ({LEGACY_OUTBOX_COLUMNS})
                        SELECT {LEGACY_OUTBOX_COLUMNS}
                        FROM legacy_outbox.assessment_outbox
                        """
                    ).rowcount
                if "assessment_outbox_metadata" in legacy_tables:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO assessment_outbox_metadata (
                            key, value, updated_at
                        )
                        SELECT key, value, updated_at
                        FROM legacy_outbox.assessment_outbox_metadata
                        """
                    )
                connection.execute(
                    """
                    INSERT INTO assessment_outbox_metadata (key, value, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        LEGACY_FILE_IMPORT_KEY,
                        f"{copied['assessments']} assessments, "
                        f"{copied['pending']} pending",
                        _utc_now_iso(),
                    ),
                )
        finally:
            connection.execute("DETACH DATABASE legacy_outbox")
        # Usually runs before logging is configured; the owner reports it.
        self.legacy_import_report = (
            f"Copied the assessment outbox {legacy_path} into the local "
            f"database {self.path} ({copied['assessments']} assessments, "
            f"{copied['pending']} pending exports). The old file is no "
            "longer read."
        )

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
            "export_rejections": int(row["export_rejections"] or 0),
            "base": AssessmentOutboxStore.resolve_base_value(row),
            "remote": (
                None
                if row["remote_state"] is None
                else assessment_value(
                    row["remote_state"],
                    row["remote_details"],
                    row["remote_suppressed"],
                )
            ),
        }

    @staticmethod
    def resolve_base_value(row: Any) -> dict[str, Any] | None:
        """The value last agreed with the source, from a state row.

        None without a base state. Its text is ``base_details``, or the
        record's own text when that is NULL: usually the base is the
        record's own text, which is then not stored again. ``base_same`` is
        only a storage hint and is not consulted; a row may carry
        ``base_same = 1`` with ``base_details`` still set until the fields
        are synchronised. The instance dump resolves the base the same way.
        """
        if row["base_state"] is None:
            return None
        return assessment_value(
            row["base_state"],
            row["analysis_details"]
            if row["base_details"] is None
            else row["base_details"],
            row["base_suppressed"],
        )

    @staticmethod
    def _local_value(state: dict[str, Any]) -> dict[str, Any]:
        return assessment_value(
            state["analysisState"], state["analysisDetails"], state["isSuppressed"]
        )

    @staticmethod
    def _append_revision(
        connection: sqlite3.Connection,
        key: AssessmentKey,
        revision: int,
        value: dict[str, Any],
        *,
        origin: str,
        author: str | None,
        now: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO assessment_revisions (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                analysis_state, analysis_details, suppressed,
                origin, author, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *key,
                revision,
                value["state"],
                value["details"],
                int(value["suppressed"]),
                origin,
                author,
                now,
            ),
        )

    def _reload_keys(
        self,
        connection: sqlite3.Connection,
        keys: Iterable[AssessmentKey],
    ) -> None:
        """Refresh the in-memory view of the given findings from the database."""
        for key in keys:
            state_row = connection.execute(
                """
                SELECT * FROM assessment_state
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                key,
            ).fetchone()
            if state_row is None:
                self._states.pop(key, None)
            else:
                self._states[key] = self._state_record(state_row)
            pending_row = connection.execute(
                """
                SELECT * FROM assessment_outbox
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                key,
            ).fetchone()
            if pending_row is None:
                self._pending.pop(key, None)
            else:
                self._pending[key] = self._pending_record(pending_row)
        self._sync_fields(connection, keys)

    def _sync_fields(
        self,
        connection: sqlite3.Connection,
        keys: Iterable[AssessmentKey] | None,
    ) -> int:
        """Store the atomic fields of assessments whose text changed.

        ``keys`` limits the check to those findings; ``None`` checks all, as
        on startup, which is also how existing assessments get their fields
        once. Returns how many were written.
        """
        if keys is None:
            rows = connection.execute(
                """
                SELECT s.* FROM assessment_state s
                LEFT JOIN assessment_fields f
                  ON f.project_uuid = s.project_uuid
                 AND f.component_uuid = s.component_uuid
                 AND f.vulnerability_uuid = s.vulnerability_uuid
                WHERE f.revision IS NULL OR f.revision != s.revision
                   OR f.state != s.analysis_state OR f.suppressed != s.suppressed
                """
            ).fetchall()
            wanted = None
        else:
            wanted = list(dict.fromkeys(keys))
            rows = []
            for key in wanted:
                row = connection.execute(
                    """
                    SELECT * FROM assessment_state
                    WHERE project_uuid = ? AND component_uuid = ?
                      AND vulnerability_uuid = ?
                    """,
                    key,
                ).fetchone()
                if row is not None:
                    rows.append(row)
        if wanted is not None:
            with connection:
                for key in wanted:
                    # The agreed value equals the record: store it once.
                    connection.execute(
                        """
                        UPDATE assessment_state
                        SET base_details = NULL, base_same = 1
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND base_state IS NOT NULL
                          AND base_details IS analysis_details
                        """,
                        key,
                    )
                    # A writer that stored a differing agreed value did not
                    # touch the marker; keep it truthful.
                    connection.execute(
                        """
                        UPDATE assessment_state SET base_same = 0
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND base_same = 1 AND base_details IS NOT NULL
                        """,
                        key,
                    )
        written = 0
        # Reading every existing assessment once takes a while on a large
        # installation; say so on the console and the start page.
        announce = wanted is None and len(rows) > 0
        started = time.monotonic()
        if announce:
            report_startup_progress(
                f"Data migration: reading {len(rows)} assessments into fields"
            )
        with connection:
            if wanted is not None:
                present = {self._row_key(row) for row in rows}
                for key in wanted:
                    if key not in present:
                        self._delete_fields(connection, key)
            for row in rows:
                key = self._row_key(row)
                details = str(row["analysis_details"])
                digest = hashlib.sha256(details.encode("utf-8")).hexdigest()
                current = connection.execute(
                    """
                    SELECT revision, details_digest, state, suppressed
                    FROM assessment_fields
                    WHERE project_uuid = ? AND component_uuid = ?
                      AND vulnerability_uuid = ?
                    """,
                    key,
                ).fetchone()
                if current is not None and (
                    int(current["revision"]), current["details_digest"],
                    current["state"], int(current["suppressed"]),
                ) == (
                    int(row["revision"]), digest,
                    str(row["analysis_state"]), int(row["suppressed"]),
                ):
                    continue
                fields = parse_assessment(
                    row["analysis_state"], details, row["suppressed"]
                )
                self._delete_fields(connection, key)
                connection.execute(
                    """
                    INSERT INTO assessment_fields (
                        project_uuid, component_uuid, vulnerability_uuid,
                        revision, details_digest, state, suppressed,
                        pending_review, rescored_score, rescored_vector,
                        free_text, form, response,
                        version_override, version_override_reason
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *key, int(row["revision"]), digest, fields["state"],
                        int(fields["suppressed"]), int(fields["pending_review"]),
                        fields["rescored_score"], fields["rescored_vector"],
                        fields["free_text"], fields["form"], fields["response"],
                        (fields["version_override"] or {}).get("label"),
                        (fields["version_override"] or {}).get("reason"),
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO assessment_team_fields (
                        project_uuid, component_uuid, vulnerability_uuid,
                        position, team, state, justification, assessed_by,
                        reviewed_by, assessed_at_ms, rescored_score,
                        rescored_vector, ssvc, ssvc_details, assigned_json,
                        historical, copied_from, details, ticket,
                        evidence_reviewed, version_coverage
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    [
                        (
                            *key, position, team["team"], team["state"],
                            team["justification"], team["assessed_by"],
                            team["reviewed_by"], team["assessed_at_ms"],
                            team["rescored_score"], team["rescored_vector"],
                            team["ssvc"], team["ssvc_details"],
                            json.dumps(team["assigned"]),
                            int(team["historical"]), team["copied_from"],
                            team["details"], team["ticket"],
                            team["evidence_reviewed"], team["version_coverage"],
                        )
                        for position, team in enumerate(fields["teams"])
                    ],
                )
                written += 1
                if announce and written % FIELD_MIGRATION_REPORT_EVERY == 0:
                    report_startup_progress(
                        f"Data migration: {written} of {len(rows)} assessments "
                        "read into fields"
                    )
        if announce:
            report_startup_progress(
                f"Data migration: {written} assessments read into fields in "
                f"{time.monotonic() - started:.1f} s",
                done=True,
            )
        return written

    def rebuild_derived_fields(self, connection: sqlite3.Connection) -> int:
        """Read every assessment into its atomic fields. A restore calls
        this on its staged database; the connection needs ``sqlite3.Row``
        rows."""
        return self._sync_fields(connection, None)

    @staticmethod
    def _delete_fields(connection: sqlite3.Connection, key: AssessmentKey) -> None:
        for table in ("assessment_team_fields", "assessment_fields"):
            connection.execute(
                f"""
                DELETE FROM {table}
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                key,
            )

    def get_fields(self, key: AssessmentKey) -> dict[str, Any] | None:
        """The stored atomic fields of a finding's assessment, if it has a
        local record."""
        self._ensure_initialized()
        with self._lock:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM assessment_fields
                    WHERE project_uuid = ? AND component_uuid = ?
                      AND vulnerability_uuid = ?
                    """,
                    key,
                ).fetchone()
                if row is None:
                    return None
                teams = connection.execute(
                    """
                    SELECT * FROM assessment_team_fields
                    WHERE project_uuid = ? AND component_uuid = ?
                      AND vulnerability_uuid = ?
                    ORDER BY position
                    """,
                    key,
                ).fetchall()
        return {
            "revision": int(row["revision"]),
            "state": row["state"],
            "suppressed": bool(row["suppressed"]),
            "pending_review": bool(row["pending_review"]),
            "rescored_score": row["rescored_score"],
            "rescored_vector": row["rescored_vector"],
            "response": row["response"],
            "version_override": (
                {"label": row["version_override"], "reason": row["version_override_reason"]}
                if row["version_override"]
                else None
            ),
            "free_text": row["free_text"],
            "form": row["form"],
            "teams": [
                {
                    "team": team["team"],
                    "state": team["state"],
                    "justification": team["justification"],
                    "assessed_by": team["assessed_by"],
                    "reviewed_by": team["reviewed_by"],
                    "assessed_at_ms": team["assessed_at_ms"],
                    "rescored_score": team["rescored_score"],
                    "rescored_vector": team["rescored_vector"],
                    "ssvc": team["ssvc"],
                    "ssvc_details": team["ssvc_details"],
                    "assigned": json.loads(team["assigned_json"]),
                    "ticket": team["ticket"],
                    "evidence_reviewed": team["evidence_reviewed"],
                    "version_coverage": team["version_coverage"],
                    "historical": bool(team["historical"]),
                    "copied_from": team["copied_from"],
                    "details": team["details"],
                }
                for team in teams
            ],
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
        origin: str = ORIGIN_USER,
        author: str | None = None,
        bases: dict[AssessmentKey, dict[str, Any]] | None = None,
        supersedes: dict[AssessmentKey, list[AssessmentKey]] | None = None,
        expected_records: dict[AssessmentKey, int | None] | None = None,
        skip_changed: bool = False,
    ) -> list[dict[str, Any]]:
        """Record local assessment values and queue them for export.

        ``bases`` gives, for findings without a local assessment yet, the
        value the source is believed to hold. It becomes the reference an
        import later compares the source against.

        ``supersedes`` names, per saved finding, the records its value was
        carried over from. In the same transaction their queued exports are
        dropped and they become ``superseded``: kept, but no longer active.

        ``expected_records`` is what the caller read, checked in the same
        transaction: ``None`` for a finding that had no record, else the
        revision of a record that was neither discarded nor superseded. It
        covers saved findings and the records they supersede. A mismatch
        raises ``AssessmentRecordChangedError``; with ``skip_changed`` that
        finding is left out instead (as is one with a queued export when
        ``replace`` is false), and the rest is saved.
        """
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
        records: list[tuple[AssessmentKey, dict[str, Any]]] = []
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    for key, payload in deduplicated.items():
                        existing_state = connection.execute(
                            """
                            SELECT *
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
                            if skip_changed:
                                continue
                            raise AssessmentOutboxConflictError(
                                "A pending update already exists for this finding."
                            )
                        if expected_records is not None:
                            try:
                                for checked in [key, *(supersedes or {}).get(key, [])]:
                                    if checked in expected_records:
                                        self._check_expected_record(
                                            connection, checked, expected_records[checked]
                                        )
                            except AssessmentRecordChangedError:
                                if skip_changed:
                                    continue
                                raise

                        revision = current_revision + 1
                        update_id = str(uuid.uuid4())
                        value = assessment_value(
                            payload.get("state"),
                            payload.get("details"),
                            payload.get("suppressed", False),
                        )
                        sync_status = SYNC_PENDING
                        if existing_state is None:
                            base = (bases or {}).get(key)
                        else:
                            existing = self._state_record(existing_state)
                            base = existing["base"]
                            if existing["sync_status"] == SYNC_SYNCED and base is None:
                                base = self._local_value(existing)
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
                                updated_at,
                                base_state,
                                base_details,
                                base_suppressed
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
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
                                updated_at = excluded.updated_at,
                                base_state = excluded.base_state,
                                base_details = excluded.base_details,
                                base_suppressed = excluded.base_suppressed
                            """,
                            (
                                *key,
                                revision,
                                value["state"],
                                value["details"],
                                int(value["suppressed"]),
                                sync_status,
                                update_id,
                                now,
                                None if base is None else str(base.get("state") or "NOT_SET"),
                                None if base is None else str(base.get("details") or ""),
                                None if base is None else int(bool(base.get("suppressed"))),
                            ),
                        )
                        self._append_revision(
                            connection,
                            key,
                            revision,
                            value,
                            origin=origin,
                            author=author,
                            now=now,
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
                        records.append((key, pending))
                    superseded = [
                        old
                        for key, _pending in records
                        for old in (supersedes or {}).get(key, [])
                        if old != key
                    ]
                    for old in superseded:
                        self._supersede(connection, old, now)
                self._reload_keys(
                    connection,
                    [key for key, _pending in records] + superseded,
                )

            return [copy.deepcopy(pending) for _key, pending in records]

    def get_overlay(self, key: AssessmentKey) -> dict[str, Any] | None:
        self._ensure_initialized()
        with self._lock:
            state = self._states.get(key)
            return copy.deepcopy(state) if state is not None else None

    def keys_with_text_and_no_state(self, project_uuid: str) -> set[AssessmentKey]:
        """Findings of a project whose record has a text and no state.

        The source lists the text of an assessment only for findings with a
        state, so for these it has to be read finding by finding.
        """
        self._ensure_initialized()
        with self._lock:
            return {
                key
                for key, state in self._states.items()
                if key[0] == project_uuid
                and (value := self._local_value(state))["state"] == "NOT_SET"
                and value["details"].strip()
            }

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
                            updated_at = ?,
                            base_state = analysis_state,
                            base_details = analysis_details,
                            base_suppressed = suppressed,
                            remote_state = NULL,
                            remote_details = NULL,
                            remote_suppressed = NULL
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (now, *key, revision),
                    )
                self._reload_keys(connection, [key])
            return True

    def reconcile_remote(
        self,
        remote: dict[AssessmentKey, dict[str, Any]],
        *,
        fetched_at: datetime,
        retry_delay: Callable[[int], int] | None = None,
    ) -> dict[str, list[AssessmentKey]]:
        """Compare assessments just read from the source with the local record.

        The local database is the record: the source never changes a local
        assessment. ``fetched_at`` is when the read started; a local
        assessment changed after that is left alone, because the source value
        may predate it. The outcomes, per finding:

        - ``adopted``: the finding had no local record yet and the source
          holds an assessment. It becomes the local record, at revision 0.
        - ``settled``: the source holds the local value; a pending export is
          dropped.
        - ``requeued``: the source holds something else, or nothing. The
          local value is queued for export. When the source keeps dropping a
          value that was exported to it, the exports are spaced out with
          ``retry_delay`` (seconds for the n-th repetition) and reported as
          failing.
        - ``replaced``: a discarded export whose previous value was unknown;
          the source value replaces the local one.
        """
        self._ensure_initialized()
        outcomes: dict[str, list[AssessmentKey]] = {
            "adopted": [],
            "settled": [],
            "requeued": [],
            "replaced": [],
        }
        fetched = fetched_at.astimezone(UTC)
        now = _utc_now_iso()
        values = {
            key: assessment_value(
                item.get("state"), item.get("details"), item.get("suppressed")
            )
            for key, item in remote.items()
        }
        with self._lock:
            new_keys: list[AssessmentKey] = []
            candidates: list[AssessmentKey] = []
            for key, theirs in values.items():
                known = self._states.get(key)
                if known is None:
                    if not is_blank_assessment(theirs):
                        new_keys.append(key)
                elif not (
                    # The common case, answered without touching the database.
                    known["sync_status"] == SYNC_SYNCED
                    and not known["export_rejections"]
                    and same_assessment(theirs, self._local_value(known))
                ):
                    candidates.append(key)
            if not new_keys and not candidates:
                return outcomes
            touched: list[AssessmentKey] = []
            with closing(self._connect()) as connection:
                with connection:
                    for key in new_keys:
                        if self._adopt_new(connection, key, values[key], now):
                            outcomes["adopted"].append(key)
                            touched.append(key)
                    for key in candidates:
                        row = connection.execute(
                            """
                            SELECT * FROM assessment_state
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        ).fetchone()
                        if row is None:
                            continue
                        state = self._state_record(row)
                        updated_at = _parse_time(state["updated_at"])
                        if updated_at is None or updated_at >= fetched:
                            continue
                        outcome = self._reconcile_one(
                            connection, key, state, values[key], now, retry_delay
                        )
                        if outcome is not None:
                            outcomes[outcome].append(key)
                        touched.append(key)
                self._reload_keys(connection, touched)
        return outcomes

    def _adopt_new(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        value: dict[str, Any],
        now: str,
    ) -> bool:
        """Create the local record of a finding from the source's assessment.

        Revision 0 means "as imported": a client that loaded the finding
        before it had a record still saves against the revision it saw.
        """
        inserted = connection.execute(
            """
            INSERT OR IGNORE INTO assessment_state (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                analysis_state, analysis_details, suppressed, sync_status,
                update_id, last_error, updated_at,
                base_state, base_details, base_suppressed, base_same
            )
            VALUES (?, ?, ?, 0, ?, ?, ?, 'synced', NULL, NULL, ?, ?, NULL, ?, 1)
            """,
            (
                *key,
                value["state"], value["details"], int(value["suppressed"]),
                now,
                value["state"], int(value["suppressed"]),
            ),
        ).rowcount
        if not inserted:
            return False
        # The entry's text is the record's until the record changes; a
        # database trigger writes it here at that moment.
        self._append_revision(
            connection, key, 0, {**value, "details": ""},
            origin=ORIGIN_IMPORT, author=None, now=now,
        )
        connection.execute(
            """
            UPDATE assessment_revisions SET text_in_record = 1
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ? AND revision = 0 AND origin = ?
            """,
            (*key, ORIGIN_IMPORT),
        )
        self._review_adopted_override(connection, key, value, 0, now)
        return True

    def _review_adopted_override(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        value: dict[str, Any],
        revision: int,
        now: str,
    ) -> None:
        """After adopting ``value`` (stored unchanged as ``revision``): when it
        carries a version override marker, the next revision (origin
        ``import-review``) marks it pending review and is exported. Nothing
        else of the value changes (ADR 0010, design section 9)."""
        details = str(value["details"] or "")
        if version_override(details) is None or PENDING_REVIEW_MARKER.casefold() in details.casefold():
            return
        reviewed = {**value, "details": f"{details.rstrip()}\n\n{PENDING_REVIEW_MARKER}"}
        revision += 1
        update_id = str(uuid.uuid4())
        connection.execute(
            """
            UPDATE assessment_state
            SET revision = ?, analysis_details = ?, update_id = ?
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (revision, reviewed["details"], update_id, *key),
        )
        self._set_sync_fields(
            connection, key, status=SYNC_PENDING, base=value, remote=None, now=now
        )
        self._append_revision(
            connection, key, revision, reviewed,
            origin=ORIGIN_IMPORT_REVIEW, author=None, now=now,
        )
        payload = {
            "project_uuid": key[0],
            "component_uuid": key[1],
            "vulnerability_uuid": key[2],
            "state": reviewed["state"],
            "details": reviewed["details"],
            "suppressed": bool(reviewed["suppressed"]),
        }
        connection.execute(
            """
            INSERT INTO assessment_outbox (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                update_id, payload_json, attempts, next_attempt_at,
                last_error, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
            ON CONFLICT (project_uuid, component_uuid, vulnerability_uuid)
            DO UPDATE SET
                revision = excluded.revision,
                update_id = excluded.update_id,
                payload_json = excluded.payload_json,
                attempts = 0, next_attempt_at = NULL, last_error = NULL,
                updated_at = excluded.updated_at
            """,
            (*key, revision, update_id, _payload_json(payload), now, now),
        )

    def _set_sync_fields(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        *,
        status: str,
        base: dict[str, Any] | None,
        remote: dict[str, Any] | None,
        now: str,
    ) -> None:
        connection.execute(
            """
            UPDATE assessment_state
            SET sync_status = ?,
                last_error = NULL,
                updated_at = ?,
                base_state = ?, base_details = ?, base_suppressed = ?,
                remote_state = ?, remote_details = ?, remote_suppressed = ?
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (
                status,
                now,
                None if base is None else base["state"],
                None if base is None else base["details"],
                None if base is None else int(base["suppressed"]),
                None if remote is None else remote["state"],
                None if remote is None else remote["details"],
                None if remote is None else int(remote["suppressed"]),
                *key,
            ),
        )

    def _adopt_value(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        state: dict[str, Any],
        value: dict[str, Any],
        *,
        origin: str,
        author: str | None,
        now: str,
    ) -> None:
        """Make ``value`` the local assessment as a new, synchronized revision."""
        revision = int(state["revision"]) + 1
        connection.execute(
            """
            DELETE FROM assessment_outbox
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            key,
        )
        connection.execute(
            """
            UPDATE assessment_state
            SET revision = ?,
                analysis_state = ?, analysis_details = ?, suppressed = ?,
                update_id = NULL
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (
                revision,
                value["state"],
                value["details"],
                int(value["suppressed"]),
                *key,
            ),
        )
        self._set_sync_fields(
            connection, key, status=SYNC_SYNCED, base=value, remote=None, now=now
        )
        self._append_revision(
            connection, key, revision, value, origin=origin, author=author, now=now
        )
        if origin == ORIGIN_IMPORT:
            self._review_adopted_override(connection, key, value, revision, now)

    def _queue_export(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        state: dict[str, Any],
        now: str,
        *,
        attempts: int = 0,
        next_attempt_at: str | None = None,
        last_error: str | None = None,
    ) -> None:
        """Ensure the current local value is waiting for export."""
        local = self._local_value(state)
        update_id = str(uuid.uuid4())
        payload = {
            "project_uuid": key[0],
            "component_uuid": key[1],
            "vulnerability_uuid": key[2],
            **local,
        }
        connection.execute(
            """
            INSERT INTO assessment_outbox (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                update_id, payload_json, attempts, next_attempt_at,
                last_error, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (project_uuid, component_uuid, vulnerability_uuid)
            DO UPDATE SET
                attempts = excluded.attempts,
                next_attempt_at = excluded.next_attempt_at,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (
                *key, int(state["revision"]), update_id, _payload_json(payload),
                attempts, next_attempt_at, last_error, now, now,
            ),
        )
        connection.execute(
            """
            UPDATE assessment_state
            SET update_id = (
                SELECT update_id FROM assessment_outbox
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
            )
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (*key, *key),
        )

    def _set_rejections(
        self, connection: sqlite3.Connection, key: AssessmentKey, count: int
    ) -> None:
        connection.execute(
            """
            UPDATE assessment_state SET export_rejections = ?
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (count, *key),
        )

    def _reconcile_one(
        self,
        connection: sqlite3.Connection,
        key: AssessmentKey,
        state: dict[str, Any],
        theirs: dict[str, Any],
        now: str,
        retry_delay: Callable[[int], int] | None,
    ) -> str | None:
        ours = self._local_value(state)
        status = state["sync_status"]
        # A finding that is reported again (inactive or superseded record)
        # is handled like a synchronised one below. Its value did not
        # change, so no revision is written: when and why it went and came
        # back is kept on the finding (finding_lifecycle_services).

        if same_assessment(theirs, ours):
            # Both sides agree, whatever happened before.
            if status == SYNC_SYNCED and not state["export_rejections"]:
                return None
            connection.execute(
                """
                DELETE FROM assessment_outbox
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                key,
            )
            self._set_sync_fields(
                connection, key, status=SYNC_SYNCED, base=ours, remote=None, now=now
            )
            self._set_rejections(connection, key, 0)
            return "settled"

        if status == SYNC_CANCELLED:
            # A discarded export whose previous value was not known: the
            # reviewer chose not to send the local value, so the source's
            # value is the one to keep.
            self._adopt_value(
                connection, key, state, theirs,
                origin=ORIGIN_IMPORT, author=None, now=now,
            )
            return "replaced"

        if status in (SYNC_PENDING, SYNC_ERROR):
            # Already waiting for export, which overwrites the source. Keep
            # what the source holds for display only.
            if not same_assessment(theirs, state["remote"]):
                self._set_sync_fields(
                    connection, key,
                    status=status, base=state["base"], remote=theirs, now=now,
                )
                if status == SYNC_ERROR:
                    connection.execute(
                        """
                        UPDATE assessment_state SET last_error = ?
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND vulnerability_uuid = ?
                        """,
                        (state["last_error"], *key),
                    )
            return None

        # Synchronized or inactive, and the source holds something else or
        # nothing: it lost or changed a value it had. Send the record again.
        rejections = (
            int(state["export_rejections"]) + 1 if status == SYNC_SYNCED else 0
        )
        if rejections > 1:
            # The source did not keep the previous export either. Space the
            # exports out and report them as failing instead of looping.
            delay = retry_delay(rejections - 1) if retry_delay else 60
            error = (
                "Dependency-Track did not keep the exported assessment "
                f"({rejections - 1} time{'s' if rejections > 2 else ''})"
            )
            self._queue_export(
                connection, key, state, now,
                attempts=rejections - 1,
                next_attempt_at=(
                    datetime.now(UTC) + timedelta(seconds=delay)
                ).isoformat(),
                last_error=error,
            )
            self._set_sync_fields(
                connection, key,
                status=SYNC_ERROR, base=state["base"], remote=theirs, now=now,
            )
            connection.execute(
                """
                UPDATE assessment_state SET last_error = ?
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                (error, *key),
            )
        else:
            self._queue_export(connection, key, state, now)
            self._set_sync_fields(
                connection, key,
                status=SYNC_PENDING, base=state["base"], remote=theirs, now=now,
            )
        self._set_rejections(connection, key, rejections)
        return "requeued"

    def note_exported(self, key: AssessmentKey, payload: dict[str, Any]) -> None:
        """Record what the source now holds after an export that a newer
        local change has already superseded. Without this the next export
        would mistake that value for someone else's change."""
        self._ensure_initialized()
        value = assessment_value(
            payload.get("state"), payload.get("details"), payload.get("suppressed")
        )
        with self._lock:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        UPDATE assessment_state
                        SET base_state = ?, base_details = ?, base_suppressed = ?
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND sync_status IN ('pending', 'error')
                        """,
                        (
                            value["state"],
                            value["details"],
                            int(value["suppressed"]),
                            *key,
                        ),
                    )
                self._reload_keys(connection, [key])

    def pending_revision(self, key: AssessmentKey) -> int | None:
        """The revision currently queued for a finding, if any."""
        self._ensure_initialized()
        with self._lock:
            pending = self._pending.get(key)
            return int(pending["revision"]) if pending is not None else None

    def _seed_missing_revisions(self, connection: sqlite3.Connection) -> None:
        """Give assessments from before the history existed one entry, so
        their value is not lost from view when it is first replaced."""
        with connection:
            connection.execute(
                """
                INSERT INTO assessment_revisions (
                    project_uuid, component_uuid, vulnerability_uuid, revision,
                    analysis_state, analysis_details, suppressed,
                    origin, author, created_at
                )
                SELECT s.project_uuid, s.component_uuid, s.vulnerability_uuid,
                       s.revision, s.analysis_state, s.analysis_details,
                       s.suppressed, 'before-history', NULL, s.updated_at
                FROM assessment_state AS s
                WHERE NOT EXISTS (
                    SELECT 1 FROM assessment_revisions AS r
                    WHERE r.project_uuid = s.project_uuid
                      AND r.component_uuid = s.component_uuid
                      AND r.vulnerability_uuid = s.vulnerability_uuid
                )
                """
            )

    def list_revisions(
        self,
        key: AssessmentKey,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """History of a finding's local assessment, newest first."""
        self._ensure_initialized()
        limit = max(1, min(int(limit), 500))
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT r.revision, r.analysis_state, r.suppressed, r.origin,
                       r.author, r.created_at,
                       CASE WHEN r.text_in_record
                            THEN s.analysis_details
                            ELSE r.analysis_details END AS analysis_details
                FROM assessment_revisions r
                LEFT JOIN assessment_state s
                  ON s.project_uuid = r.project_uuid
                 AND s.component_uuid = r.component_uuid
                 AND s.vulnerability_uuid = r.vulnerability_uuid
                WHERE r.project_uuid = ? AND r.component_uuid = ?
                  AND r.vulnerability_uuid = ?
                ORDER BY r.revision_id DESC
                LIMIT ?
                """,
                (*key, limit),
            ).fetchall()
        return [
            {
                "revision": int(row["revision"]),
                "analysisState": str(row["analysis_state"]),
                "analysisDetails": str(row["analysis_details"]),
                "isSuppressed": bool(row["suppressed"]),
                "origin": str(row["origin"]),
                "author": row["author"],
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def list_ticket_histories(self) -> dict[AssessmentKey, list[dict[str, Any]]]:
        """Every version of the assessments that ever named a ticket.

        Per finding, oldest first. Only findings with a ``[Ticket: …]`` tag in
        some version are returned: the others have no ticket to lose.
        """
        self._ensure_initialized()
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                WITH texts AS (
                    SELECT r.revision_id, r.project_uuid, r.component_uuid,
                           r.vulnerability_uuid, r.origin, r.created_at,
                           CASE WHEN r.text_in_record
                                THEN s.analysis_details
                                ELSE r.analysis_details END AS analysis_details
                    FROM assessment_revisions r
                    LEFT JOIN assessment_state s
                      ON s.project_uuid = r.project_uuid
                     AND s.component_uuid = r.component_uuid
                     AND s.vulnerability_uuid = r.vulnerability_uuid
                )
                SELECT * FROM texts
                WHERE (project_uuid, component_uuid, vulnerability_uuid) IN (
                    SELECT project_uuid, component_uuid, vulnerability_uuid
                    FROM texts WHERE analysis_details LIKE '%[Ticket:%'
                )
                ORDER BY revision_id
                """
            ).fetchall()
        histories: dict[AssessmentKey, list[dict[str, Any]]] = {}
        for row in rows:
            histories.setdefault(self._row_key(row), []).append(
                {
                    "analysisDetails": str(row["analysis_details"] or ""),
                    "origin": str(row["origin"]),
                    "created_at": str(row["created_at"]),
                }
            )
        return histories

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
                self._reload_keys(connection, [key])
            return True

    def drop_missing_finding(self, key: AssessmentKey, revision: int) -> bool:
        """Stop exporting to a finding the source no longer has.

        The queued export is removed. The assessment itself is kept and
        marked inactive, so it is there again should the finding return.
        """
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
                        SET sync_status = ?,
                            update_id = NULL,
                            last_error = NULL,
                            updated_at = ?
                        WHERE project_uuid = ?
                          AND component_uuid = ?
                          AND vulnerability_uuid = ?
                          AND revision = ?
                        """,
                        (SYNC_INACTIVE, now, *key, revision),
                    )
                self._reload_keys(connection, [key])
            return True

    @staticmethod
    def _check_expected_record(
        connection: sqlite3.Connection, key: AssessmentKey, expected: int | None
    ) -> None:
        row = connection.execute(
            """
            SELECT revision, sync_status FROM assessment_state
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            key,
        ).fetchone()
        if expected is None:
            if row is not None:
                raise AssessmentRecordChangedError(
                    key, "no record", f"revision {int(row['revision'])}"
                )
            return
        if row is None:
            raise AssessmentRecordChangedError(key, f"revision {expected}", "no record")
        if int(row["revision"]) != expected or row["sync_status"] in (
            SYNC_CANCELLED, SYNC_SUPERSEDED,
        ):
            raise AssessmentRecordChangedError(
                key,
                f"revision {expected}",
                f"revision {int(row['revision'])} ({row['sync_status']})",
            )

    @staticmethod
    def _supersede(
        connection: sqlite3.Connection, key: AssessmentKey, now: str
    ) -> None:
        connection.execute(
            """
            DELETE FROM assessment_outbox
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            key,
        )
        connection.execute(
            """
            UPDATE assessment_state
            SET sync_status = ?, update_id = NULL, updated_at = ?
            WHERE project_uuid = ? AND component_uuid = ?
              AND vulnerability_uuid = ?
            """,
            (SYNC_SUPERSEDED, now, *key),
        )

    def project_states(self, project_uuid: str) -> dict[AssessmentKey, dict[str, Any]]:
        """The local records of one project's findings, by finding."""
        self._ensure_initialized()
        with self._lock:
            return {
                key: copy.deepcopy(state)
                for key, state in self._states.items()
                if key[0] == project_uuid
            }

    def retire_missing(
        self,
        project_uuid: str,
        gone: dict[AssessmentKey, str],
        *,
        fetched_at: datetime,
    ) -> list[AssessmentKey]:
        """Stop following the records of findings the source no longer
        reports. ``gone`` maps each such finding to why it went.

        Synchronised, pending and failed records become ``inactive``: the
        value is kept, a queued export is dropped. A record changed after
        ``fetched_at`` is left alone, as the read may predate the change. A
        cancelled record (a discarded export) stays cancelled, so the
        discarded value is not revived should the finding return. The reason
        is kept with the finding, not here. Returns the retired findings.
        """
        self._ensure_initialized()
        fetched = fetched_at.astimezone(UTC)
        now = _utc_now_iso()
        with self._lock:
            targets: list[AssessmentKey] = []
            dropped: dict[str, int] = {}
            for key, reason in gone.items():
                if key[0] != project_uuid:
                    continue
                state = self._states.get(key)
                if state is None or state.get("sync_status") not in (
                    SYNC_SYNCED, SYNC_PENDING, SYNC_ERROR,
                ):
                    continue
                updated_at = _parse_time(state.get("updated_at"))
                if updated_at is None or updated_at >= fetched:
                    continue
                targets.append(key)
                if key in self._pending:
                    dropped[reason] = dropped.get(reason, 0) + 1
            if not targets:
                return []
            with closing(self._connect()) as connection:
                with connection:
                    for key in targets:
                        connection.execute(
                            """
                            DELETE FROM assessment_outbox
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        )
                        connection.execute(
                            """
                            UPDATE assessment_state
                            SET sync_status = ?, update_id = NULL,
                                last_error = NULL, updated_at = ?
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            (SYNC_INACTIVE, now, *key),
                        )
                self._reload_keys(connection, targets)
        if self.logger:
            for reason, count in sorted(dropped.items()):
                self.logger.info(
                    "%d queued export(s) of %s dropped: finding gone (%s)",
                    count, project_uuid, reason,
                )
        return targets

    def mark_inactive(
        self,
        project_uuid: str,
        present: set[AssessmentKey],
        *,
        fetched_at: datetime,
    ) -> list[AssessmentKey]:
        """Mark the synchronized assessments of a project whose findings the
        source no longer reports. ``present`` is every finding just read.

        Assessments still waiting for export are left alone: the export
        finds out for itself whether the finding is gone.
        """
        self._ensure_initialized()
        fetched = fetched_at.astimezone(UTC)
        now = _utc_now_iso()
        with self._lock:
            candidates = []
            for key, state in self._states.items():
                if key[0] != project_uuid or key in present:
                    continue
                if state.get("sync_status") != SYNC_SYNCED:
                    continue
                updated_at = _parse_time(state.get("updated_at"))
                if updated_at is not None and updated_at < fetched:
                    candidates.append(key)
            if not candidates:
                return []
            with closing(self._connect()) as connection:
                with connection:
                    for key in candidates:
                        connection.execute(
                            """
                            UPDATE assessment_state
                            SET sync_status = ?, updated_at = ?
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            (SYNC_INACTIVE, now, *key),
                        )
                self._reload_keys(connection, candidates)
            return candidates

    def discard(self, update_id: str, *, author: str | None = None) -> bool:
        """Drop a queued export; see ``discard_many``."""
        return bool(self.discard_many([update_id], author=author))

    def discard_many(
        self,
        update_ids: Iterable[str],
        *,
        author: str | None = None,
    ) -> list[AssessmentKey]:
        """Drop queued exports: the changes will not be sent to the source.

        Where the value last agreed with the source is known, the local
        assessment goes back to it as a new revision, so both sides match
        again and the discarded value stays in the history. Where it is not
        known (changes queued before bases were recorded) the local value
        is kept and marked cancelled; the next import replaces it.

        Returns the findings whose export was dropped. Unknown ids are
        ignored.
        """
        wanted = {str(update_id) for update_id in update_ids}
        self._ensure_initialized()
        now = _utc_now_iso()
        with self._lock:
            targets = [
                key
                for key, record in self._pending.items()
                if str(record.get("id")) in wanted
            ]
            if not targets:
                return []
            with closing(self._connect()) as connection:
                with connection:
                    for key in targets:
                        row = connection.execute(
                            """
                            SELECT * FROM assessment_state
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        ).fetchone()
                        state = self._state_record(row) if row is not None else None
                        if state is not None and state["base"] is not None:
                            self._adopt_value(
                                connection, key, state, state["base"],
                                origin=ORIGIN_DISCARD, author=author, now=now,
                            )
                            continue
                        connection.execute(
                            """
                            DELETE FROM assessment_outbox
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            key,
                        )
                        connection.execute(
                            """
                            UPDATE assessment_state
                            SET sync_status = ?,
                                update_id = NULL,
                                last_error = NULL,
                                remote_state = NULL,
                                remote_details = NULL,
                                remote_suppressed = NULL,
                                updated_at = ?
                            WHERE project_uuid = ? AND component_uuid = ?
                              AND vulnerability_uuid = ?
                            """,
                            (SYNC_CANCELLED, now, *key),
                        )
                self._reload_keys(connection, targets)
            return targets

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
