"""The SQLite adapter of ``DumpTarget``: staged database files built from a
dump with the target's own migrations.

Records are written with plain INSERTs, full texts and their original ids;
no UPDATE ever touches ``assessment_state.analysis_details``, so the trigger
``assessment_state_keep_replaced_text`` never fires and the history is
written exactly as dumped. The storage tricks of migration 0007 are then
applied again (``COMPACTION_SQL``) and the derived tables rebuilt.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from typing import Any, Iterable

from ..access_token_services import ACCESS_TOKEN_MIGRATION_NAMESPACE
from ..assessment_outbox_services import (
    ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE,
    LEGACY_FILE_IMPORT_KEY,
    AssessmentOutboxStore,
    _payload_json,
)
from ..code_analysis_result_services import (
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
    CodeAnalysisResultStore,
    _legacy_json_path_for_configured_path,
    code_analysis_result_row,
    get_code_analysis_results_path,
)
from ..file_io_services import fsync_directory
from ..finding_lifecycle_services import (
    FINDING_LIFECYCLE_MIGRATION_NAMESPACE,
    PRESENCE_BACKFILL_KEY,
)
from ..instance_stores import SqliteStore
from ..local_store import (
    LEGACY_IMPORT_KEY,
    LOCAL_STORE_MIGRATION_NAMESPACE,
    _dump,
    _finding_row,
    _project_row,
    _project_vulnerability_row,
    source_analysis_row,
)
from ..sqlite_migration_services import run_sqlite_migrations
from .entities import MIGRATION_PATHS
from .errors import DumpError

LEGACY_PENDING_UPDATES_KEY = "legacy_pending_updates_imported"

# The two compaction statements of migration 0007, verbatim. The migration
# file itself is never changed (its checksum is enforced); a test checks that
# both statements occur in it unchanged. Neither sets analysis_details of
# assessment_state, so the trigger does not fire.
COMPACTION_SQL = (
    """UPDATE assessment_state
SET base_details = NULL, base_same = 1
WHERE base_state IS NOT NULL AND base_details IS analysis_details;""",
    """UPDATE assessment_revisions
SET analysis_details = '', text_in_record = 1
WHERE revision = 0 AND origin = 'import'
  AND EXISTS (
      SELECT 1 FROM assessment_state
      WHERE assessment_state.project_uuid = assessment_revisions.project_uuid
        AND assessment_state.component_uuid = assessment_revisions.component_uuid
        AND assessment_state.vulnerability_uuid = assessment_revisions.vulnerability_uuid
        AND assessment_state.revision = 0
        AND assessment_state.analysis_details IS assessment_revisions.analysis_details
  );""",
)

SIDE_FILES = ("-journal", "-wal", "-shm")


def as_restored(entity: str, record: dict[str, Any]) -> dict[str, Any]:
    """A record as a restore writes it, where that differs from the dump.

    Session versions come back one higher: a restore ends every session of
    the restored users and can never bring back a revoked one, also not one
    revoked after the dump was taken (docs/backup-and-restore.md).
    """
    if entity == "session_version":
        return {**record, "version": int(record["version"]) + 1}
    return record


def staged_path(target: str, dump_id: str) -> str:
    return f"{target}.restore-{dump_id}"


def remove_stale(path: str) -> None:
    """Remove an earlier staged file of the same dump: DTVP's own temporary."""
    for suffix in ("", *SIDE_FILES):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass


def _key(record: dict[str, Any]) -> tuple[str, str, str]:
    key = record["key"]
    return (key["project_uuid"], key["component_uuid"], key["vulnerability_uuid"])


def _value_columns(value: dict[str, Any] | None) -> tuple[Any, Any, Any]:
    if value is None:
        return (None, None, None)
    return (value["state"], value["details"], int(value["suppressed"]))


def _payload_text(record: dict[str, Any], encode) -> str:
    if "payload_raw" in record:
        return record["payload_raw"]
    return encode(record["payload"])


def integrity_problems(connection: sqlite3.Connection) -> list[str]:
    problems = [
        str(row[0])
        for row in connection.execute("PRAGMA integrity_check").fetchall()
        if str(row[0]) != "ok"
    ]
    problems += [
        f"foreign key: {tuple(row)}"
        for row in connection.execute("PRAGMA foreign_key_check").fetchall()
    ]
    return problems


class SqliteDumpTarget:
    """Builds the staged files of one instance from dump records."""

    def __init__(self, stores: Iterable[SqliteStore], dump_id: str) -> None:
        self.dump_id = dump_id
        self.stores = list(stores)
        self.staged: dict[str, str] = {}
        self._connections: dict[str, sqlite3.Connection] = {}
        self._namespace_connection: dict[str, sqlite3.Connection] = {}
        now = datetime.now(UTC).isoformat()
        self.now = now
        for store in self.stores:
            path = staged_path(store.path, dump_id)
            remove_stale(path)
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            connection = sqlite3.connect(path)
            os.chmod(path, 0o600)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=DELETE")
            # A staged file is not used until it is complete, checked and
            # synced as a whole (finish); a crash before that discards it.
            connection.execute("PRAGMA synchronous=OFF")
            for namespace in store.namespaces:
                run_sqlite_migrations(
                    connection,
                    namespace=namespace,
                    migrations_path=MIGRATION_PATHS[namespace](),
                )
                self._namespace_connection[namespace] = connection
            self.staged[store.path] = path
            self._connections[path] = connection
        for connection in self._connections.values():
            connection.execute("BEGIN")

    def _db(self, namespace: str) -> sqlite3.Connection:
        return self._namespace_connection[namespace]

    # -- records -------------------------------------------------------------

    def write_entity(self, name: str, records: Iterable[dict[str, Any]]) -> int:
        writer = getattr(self, f"_write_{name}", None)
        count = 0
        for record in records:
            if writer is not None:
                writer(record)
            count += 1
        return count

    def _write_assessment(self, record: dict[str, Any]) -> None:
        sync = record["sync"]
        base = sync["base"]
        self._db(ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO assessment_state (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                analysis_state, analysis_details, suppressed, sync_status,
                update_id, last_error, updated_at, base_state, base_details,
                base_suppressed, remote_state, remote_details, remote_suppressed,
                export_rejections, base_same
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                *_key(record),
                record["revision"],
                *_value_columns(record["value"]),
                sync["status"],
                sync["update_id"],
                sync["last_error"],
                record["updated_at"],
                *_value_columns(base),
                *_value_columns(sync["remote"]),
                sync["export_rejections"],
            ),
        )

    def _write_revision(self, record: dict[str, Any]) -> None:
        self._db(ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO assessment_revisions (
                revision_id, project_uuid, component_uuid, vulnerability_uuid,
                revision, analysis_state, analysis_details, suppressed, origin,
                author, created_at, text_in_record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                record["revision_id"],
                *_key(record),
                record["revision"],
                *_value_columns(record["value"]),
                record["origin"],
                record["author"],
                record["created_at"],
            ),
        )

    def _write_outbox_entry(self, record: dict[str, Any]) -> None:
        self._db(ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO assessment_outbox (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                update_id, payload_json, attempts, next_attempt_at, last_error,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *_key(record),
                record["revision"],
                record["update_id"],
                _payload_text(record, _payload_json),
                record["attempts"],
                record["next_attempt_at"],
                record["last_error"],
                record["created_at"],
                record["updated_at"],
            ),
        )

    def _write_known_project(self, record: dict[str, Any]) -> None:
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO known_projects VALUES (?, ?, ?, ?, ?)",
            (
                record["project_uuid"],
                record["name"],
                record["version"],
                record["first_seen_at"],
                record["last_seen_at"],
            ),
        )

    def _write_source_snapshot(self, record: dict[str, Any]) -> None:
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO source_snapshots (kind, project_uuid, item_count, raw_json, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                record["kind"],
                record["project_uuid"],
                record["item_count"],
                _dump(record["raw"]) if record["form"] == "raw" else None,
                record["updated_at"],
            ),
        )

    @staticmethod
    def _with_raw(row: tuple[Any, ...], record: dict[str, Any]) -> tuple[Any, ...]:
        if "payload_raw" in record:
            return (*row[:-1], record["payload_raw"])
        return row

    def _write_source_project(self, record: dict[str, Any]) -> None:
        row = _project_row(record["position"], record.get("payload"))
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO source_projects VALUES (?, ?, ?, ?, ?)", self._with_raw(row, record)
        )

    def _write_source_finding(self, record: dict[str, Any]) -> None:
        row = _finding_row(record["project_uuid"], record["position"], record.get("payload"))
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO source_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._with_raw(row, record),
        )

    def _write_source_project_vulnerability(self, record: dict[str, Any]) -> None:
        row = _project_vulnerability_row(
            record["project_uuid"], record["position"], record.get("payload")
        )
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO source_project_vulnerabilities VALUES (?, ?, ?, ?, ?)",
            self._with_raw(row, record),
        )

    def _write_source_bom(self, record: dict[str, Any]) -> None:
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO source_boms (project_uuid, payload_json, updated_at) VALUES (?, ?, ?)",
            (record["project_uuid"], _payload_text(record, _dump), record["updated_at"]),
        )

    def _write_source_analysis(self, record: dict[str, Any]) -> None:
        row = source_analysis_row(_key(record), record.get("payload"), record["updated_at"])
        if "payload_raw" in record:
            row = source_analysis_row(_key(record), {}, record["updated_at"])
            row = (*row[:6], record["payload_raw"], row[7])
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO source_analyses (
                project_uuid, component_uuid, vulnerability_uuid,
                analysis_state, analysis_details, suppressed, payload_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    def _write_token_audit(self, record: dict[str, Any]) -> None:
        target = (
            record["target_raw"]
            if "target_raw" in record
            else json.dumps(record["target"], sort_keys=True)
        )
        self._db(ACCESS_TOKEN_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO access_token_audit (
                audit_id, occurred_at, username, token_id, agent, action,
                outcome, target_json, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["audit_id"],
                record["occurred_at"],
                record["username"],
                record["token_id"],
                record["agent"],
                record["action"],
                record["outcome"],
                target,
                record["detail"],
            ),
        )

    def _write_access_token(self, record: dict[str, Any]) -> None:
        self._db(ACCESS_TOKEN_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO access_tokens (
                token_id, username, name, token_hash, scopes, created_at,
                expires_at, last_used_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["token_id"],
                record["username"],
                record["name"],
                record["token_hash"],
                " ".join(record["scopes"]),
                record["created_at"],
                record["expires_at"],
                record["last_used_at"],
                record["revoked_at"],
            ),
        )

    def _write_code_analysis_result(self, record: dict[str, Any]) -> None:
        self._db(CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE).execute(
            """
            INSERT INTO code_analysis_results (
                analysis_run_id, project_name_lower, vuln_id_lower,
                component_name_lower, source_lower, context_fingerprint,
                finished_at, submitted_at, recorded_at, record_timestamp,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            result_row(record),
        )

    def _write_code_analysis_application(self, record: dict[str, Any]) -> None:
        self._db(CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE).execute(
            "INSERT INTO code_analysis_result_applications (analysis_run_id, finding_uuid, "
            "group_id_lower, workflow_id, status, applied_by, applied_at, payload_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["analysis_run_id"],
                record["finding_uuid"],
                record["group_id_lower"],
                record["workflow_id"],
                record["status"],
                record["applied_by"],
                record["applied_at"],
                record["payload_fingerprint"],
            ),
        )

    def _write_code_evidence(self, record: dict[str, Any]) -> None:
        db = self._db(CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE)
        db.execute(
            """
            INSERT INTO code_evidence (
                evidence_id, schema_version, source, project_name,
                project_name_lower, vuln_id, scope, targets_json, title,
                body_markdown, references_json, suggested_state,
                suggested_justification, confidence, author_username,
                token_id, agent_label, authority, idempotency_key, created_at,
                withdrawn_at, withdrawn_by, withdrawn_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["evidence_id"],
                record["schema_version"],
                record["source"],
                record["project_name"],
                record["project_name"].lower(),
                record["vuln_id"],
                record["scope"],
                json.dumps(record["targets"], sort_keys=True),
                record["title"],
                record["body_markdown"],
                json.dumps(record["references"]),
                record["suggested_state"],
                record["suggested_justification"],
                record["confidence"],
                record["author_username"],
                record["token_id"],
                record["agent_label"],
                record["authority"],
                record["idempotency_key"],
                record["created_at"],
                record["withdrawn_at"],
                record["withdrawn_by"],
                record["withdrawn_reason"],
            ),
        )
        db.executemany(
            "INSERT INTO code_evidence_vuln_ids (evidence_id, vuln_id_lower) VALUES (?, ?)",
            [(record["evidence_id"], value) for value in record["vuln_ids"]],
        )

    def _write_code_evidence_application(self, record: dict[str, Any]) -> None:
        self._db(CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE).execute(
            "INSERT INTO code_evidence_applications (evidence_id, finding_uuid, "
            "workflow_id, status, applied_by, applied_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record["evidence_id"],
                record["finding_uuid"],
                record["workflow_id"],
                record["status"],
                record["applied_by"],
                record["applied_at"],
            ),
        )

    def _write_finding_presence(self, record: dict[str, Any]) -> None:
        columns = (
            "vuln_id",
            "component_name",
            "component_version",
            "component_purl",
            "component_identity",
            "first_seen_at",
            "status",
            "gone_at",
            "last_seen_at",
            "gone_reason",
            "successor_component_uuid",
            "carry_over",
            "returned_at",
            # Optional: dumps written before acknowledgements or causes
            # lack them.
            "acknowledged_by",
            "acknowledged_at",
            "gone_cause",
            "predates_tracking",
            # Optional: a confirmed same-issue match (dumps before have none).
            "same_issue_component_uuid",
            "same_issue_vulnerability_uuid",
            "same_issue_reason",
            "same_issue_confirmed_by",
            "same_issue_confirmed_at",
        )
        self._db(FINDING_LIFECYCLE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO finding_presence (project_uuid, component_uuid, "
            f"vulnerability_uuid, {', '.join(columns)}) "
            f"VALUES (?, ?, ?, {', '.join('?' for _ in columns)})",
            (
                *_key(record),
                *(
                    int(record.get(column) or 0) if column == "predates_tracking"
                    else record.get(column)
                    for column in columns
                ),
            ),
        )

    def _write_finding_read(self, record: dict[str, Any]) -> None:
        went = record["went_raw"] if "went_raw" in record else _dump(record.get("went") or {})
        self._db(FINDING_LIFECYCLE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO finding_reads (project_uuid, read_at, went_json, returned, "
            "carried_over, not_carried) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record["project_uuid"],
                record["read_at"],
                went,
                record["returned"],
                record["carried_over"],
                record["not_carried"],
            ),
        )

    def _write_session_version(self, record: dict[str, Any]) -> None:
        record = as_restored("session_version", record)
        self._db(ACCESS_TOKEN_MIGRATION_NAMESPACE).execute(
            "INSERT INTO session_versions (username, version, revoked_at) VALUES (?, ?, ?)",
            (record["username"], record["version"], record["revoked_at"]),
        )

    def _write_instance_metadata(self, record: dict[str, Any]) -> None:
        self._db(LOCAL_STORE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO store_metadata (key, value_json, updated_at) VALUES (?, ?, ?)",
            (record["key"], _dump(record["value"]), self.now),
        )

    def write_sequences(self, sequences: dict[str, int]) -> None:
        for table, namespace in (
            ("assessment_revisions", ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE),
            ("access_token_audit", ACCESS_TOKEN_MIGRATION_NAMESPACE),
        ):
            value = int(sequences.get(table, 0))
            if value <= 0:
                continue
            connection = self._db(namespace)
            updated = connection.execute(
                "UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (value, table)
            ).rowcount
            if not updated:
                connection.execute(
                    "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, value)
                )

    # -- after the records -------------------------------------------------

    def finish(self) -> None:
        """Compact, rebuild the derived tables, write the 'done' markers,
        check integrity and close. Leaves complete files with no side
        files."""
        outbox = self._db(ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE)
        for statement in COMPACTION_SQL:
            outbox.execute(statement)
        local = self._db(LOCAL_STORE_MIGRATION_NAMESPACE)
        local.execute(
            "INSERT INTO store_metadata (key, value_json, updated_at) VALUES (?, ?, ?)",
            (
                LEGACY_IMPORT_KEY,
                _dump({"restored_from": self.dump_id, "restored_at": self.now}),
                self.now,
            ),
        )
        for key in (LEGACY_FILE_IMPORT_KEY, LEGACY_PENDING_UPDATES_KEY):
            outbox.execute(
                "INSERT INTO assessment_outbox_metadata (key, value, updated_at) VALUES (?, ?, ?)",
                (key, f"restored from dump {self.dump_id}", self.now),
            )
        # The presence backfill ran on the dumped instance; its rows are records.
        self._db(FINDING_LIFECYCLE_MIGRATION_NAMESPACE).execute(
            "INSERT INTO finding_lifecycle_metadata (key, value, updated_at) VALUES (?, ?, ?)",
            (PRESENCE_BACKFILL_KEY, f"restored from dump {self.dump_id}", self.now),
        )
        results = self._db(CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE)
        legacy_json = _legacy_json_path_for_configured_path(get_code_analysis_results_path())
        results.execute(
            "INSERT INTO code_analysis_result_meta (key, value) VALUES (?, ?)",
            (f"legacy_json_imported:{os.path.abspath(legacy_json)}", self.now),
        )
        for connection in self._connections.values():
            connection.commit()
        # Derived tables, through the stores' own code.
        AssessmentOutboxStore(":unused:").rebuild_derived_fields(outbox)
        with results:
            CodeAnalysisResultStore().rebuild_assessment_metadata(results)
        for path, connection in self._connections.items():
            # The compaction freed the space of the texts written twice;
            # a fresh file is cheap to rewrite without it.
            connection.execute("VACUUM")
            problems = integrity_problems(connection)
            if problems:
                raise DumpError("P1", f"The staged database {path} is damaged: {problems[:3]}")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.close()
        self._connections = {}
        for path in self.staged.values():
            leftovers = [path + suffix for suffix in SIDE_FILES if os.path.exists(path + suffix)]
            if leftovers:
                raise DumpError("P3", f"Side files left beside a staged database: {leftovers}")
            fsync_file(path)
            fsync_directory(os.path.dirname(path))

    def close(self) -> None:
        for connection in self._connections.values():
            try:
                connection.close()
            except sqlite3.Error:
                pass
        self._connections = {}


def result_row(record: dict[str, Any]) -> tuple[Any, ...]:
    """The stored row of a dumped code-analysis result; the dumped run id
    wins over one inside the payload."""
    run_id = record["analysis_run_id"]
    if "payload_raw" in record:
        row = code_analysis_result_row({"analysis_run_id": run_id})
        return (*row[:-1], record["payload_raw"])
    row = code_analysis_result_row(record["payload"]) or code_analysis_result_row(
        {**record["payload"], "analysis_run_id": run_id}
    )
    return (run_id, *row[1:])


def fsync_file(path: str) -> None:
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())


def table_has_rows(path: str, tables: dict[str, str | None]) -> list[str]:
    """Tables of a database that hold rows (``tables`` maps a table to an
    optional WHERE clause)."""
    if not os.path.exists(path):
        return []
    found = []
    # Without a WAL file, read the file as immutable so that no -wal or -shm
    # file is created beside a database the restore may move aside.
    mode = "mode=ro" if os.path.exists(path + "-wal") else "mode=ro&immutable=1"
    with closing(sqlite3.connect(f"file:{path}?{mode}", uri=True, timeout=30)) as connection:
        existing = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table, where in tables.items():
            if table not in existing:
                continue
            query = f"SELECT 1 FROM {table}" + (f" WHERE {where}" if where else "") + " LIMIT 1"
            if connection.execute(query).fetchone() is not None:
                found.append(table)
    return found
