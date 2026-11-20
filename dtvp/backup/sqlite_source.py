"""The SQLite adapter of ``DumpSource``: snapshots of the live databases,
and the records read from them with every storage detail resolved."""

import json
import os
import shutil
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterator

from ..assessment_outbox_services import AssessmentOutboxStore, assessment_value
from ..instance_stores import InstanceStores, SqliteStore
from ..sqlite_migration_services import load_sqlite_migrations
from .entities import ENTITIES, INSTANCE_METADATA_KEYS, MIGRATION_PATHS
from .errors import DumpError
from .ports import MigrationInfo, StoreInfo

SNAPSHOT_TIMEOUT_SECONDS = 300.0
BACKUP_PAGES_PER_STEP = 256
BACKUP_STEP_SLEEP = 0.01
BUSY_TIMEOUT_SECONDS = 30.0


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _connect_ro(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{path}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SECONDS
    )
    connection.row_factory = sqlite3.Row
    return connection


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def live_bytes(path: str) -> int:
    """Pages in use times page size: about the size of a compact copy."""
    if not os.path.exists(path):
        return 0
    with closing(_connect_ro(path)) as connection:
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        free = connection.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    return max(0, page_count - free) * page_size


def code_migrations(namespace: str) -> list[MigrationInfo]:
    return [
        MigrationInfo(namespace, migration.version, migration.name, migration.checksum)
        for migration in load_sqlite_migrations(MIGRATION_PATHS[namespace]())
    ]


def stored_migrations(connection: sqlite3.Connection, namespace: str) -> list[MigrationInfo]:
    if "schema_migrations" not in _tables(connection):
        return []
    return [
        MigrationInfo(namespace, int(row[0]), str(row[1]), str(row[2]))
        for row in connection.execute(
            "SELECT version, name, checksum FROM schema_migrations "
            "WHERE namespace = ? ORDER BY version",
            (namespace,),
        )
    ]


@dataclass(frozen=True)
class SnapshotStore:
    """A store to read records from: a snapshot copy or a file read as is."""

    name: str
    path: str | None
    namespaces: tuple[str, ...]
    info: StoreInfo


def snapshot_store(
    store: SqliteStore,
    tmp_dir: str,
    *,
    include_access_tokens: bool,
    timeout: float | None = None,
) -> SnapshotStore:
    """Copy a live database consistently without blocking its writers.

    WAL files are copied with ``VACUUM INTO`` (one read transaction); other
    files with the backup API in steps that release the lock in between,
    under an overall deadline. Without ``include_access_tokens`` the token
    rows are deleted from the copy at once, with ``secure_delete``.
    """
    if not os.path.exists(store.path):
        return SnapshotStore(
            store.name, None, store.namespaces, StoreInfo(store.name, store.namespaces)
        )
    target = os.path.join(tmp_dir, f"{store.name}.sqlite")
    snapshot_at = _now()
    with closing(_connect_ro(store.path)) as source:
        journal_mode = str(source.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if journal_mode == "wal":
            method = "vacuum-into"
            source.execute("VACUUM INTO ?", (target,))
        else:
            method = "backup-api"
            if timeout is None:
                timeout = SNAPSHOT_TIMEOUT_SECONDS
            deadline = time.monotonic() + timeout

            def progress(_status: int, _remaining: int, _total: int) -> None:
                if time.monotonic() > deadline:
                    raise TimeoutError

            with closing(sqlite3.connect(target)) as copy:
                try:
                    source.backup(
                        copy,
                        pages=BACKUP_PAGES_PER_STEP,
                        progress=progress,
                        sleep=BACKUP_STEP_SLEEP,
                    )
                except TimeoutError:
                    raise DumpError(
                        "E8",
                        f"Copying {store.path} did not finish within {timeout:.0f} s "
                        "because it kept changing; try again when it is quieter",
                    ) from None
    os.chmod(target, 0o600)
    with closing(sqlite3.connect(target)) as copy:
        copy.execute("PRAGMA journal_mode=DELETE")
        if not include_access_tokens and "access_tokens" in _tables(copy):
            copy.execute("PRAGMA secure_delete=ON")
            copy.execute("DELETE FROM access_tokens")
            copy.commit()
    for suffix in ("-journal", "-wal", "-shm"):
        if os.path.exists(target + suffix):
            os.chmod(target + suffix, 0o600)
    with closing(_connect_ro(target)) as copy:
        migrations = tuple(
            migration
            for namespace in store.namespaces
            for migration in stored_migrations(copy, namespace)
        )
    info = StoreInfo(store.name, store.namespaces, migrations, snapshot_at, method)
    return SnapshotStore(store.name, target, store.namespaces, info)


def direct_store(store: SqliteStore) -> SnapshotStore:
    """A store read as it is, for staged files that nobody else writes."""
    if not os.path.exists(store.path):
        return SnapshotStore(
            store.name, None, store.namespaces, StoreInfo(store.name, store.namespaces)
        )
    with closing(_connect_ro(store.path)) as connection:
        migrations = tuple(
            migration
            for namespace in store.namespaces
            for migration in stored_migrations(connection, namespace)
        )
    return SnapshotStore(
        store.name,
        store.path,
        store.namespaces,
        StoreInfo(store.name, store.namespaces, migrations, None, "absent"),
    )


def check_migration_state(store: SnapshotStore) -> None:
    """E1: every namespace in a snapshot is at exactly the code's migrations.

    A namespace that was never initialised in the file (no migration
    applied) holds no records and is accepted.
    """
    for namespace in store.namespaces:
        stored = [m for m in store.info.migrations if m.namespace == namespace]
        if not stored:
            continue
        expected = code_migrations(namespace)
        if [(m.version, m.checksum) for m in stored] != [
            (m.version, m.checksum) for m in expected
        ]:
            raise DumpError(
                "E1",
                f"The {namespace} database in {store.name} is at a different "
                "migration state than this DTVP version; start the matching "
                "backend once, or use the matching DTVP version",
            )


def _reject_constant(value: str) -> Any:
    raise ValueError(value)


def embedded(text: Any, field: str = "payload", *, require_object: bool = False) -> dict[str, Any]:
    """A stored JSON text as ``{field: value}``, or ``{field_raw: text}`` when
    it is not JSON (or not an object where one is required)."""
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except (TypeError, ValueError):
        return {f"{field}_raw": str(text)}
    if require_object and not isinstance(value, dict):
        return {f"{field}_raw": str(text)}
    return {field: value}


def _key(row: sqlite3.Row) -> dict[str, str]:
    return {
        "project_uuid": row["project_uuid"],
        "component_uuid": row["component_uuid"],
        "vulnerability_uuid": row["vulnerability_uuid"],
    }


def _value(state: Any, details: Any, suppressed: Any) -> dict[str, Any]:
    return assessment_value(state, details, suppressed)


class SqliteDumpSource:
    """Reads the records of an instance from SQLite files (snapshot copies,
    or staged files in direct mode), the record files and the settings."""

    def __init__(
        self,
        stores: list[SnapshotStore],
        *,
        tmrescore: bytes | None,
        config: dict[str, bytes | None],
        include_access_tokens: bool,
        include_source: bool,
    ) -> None:
        self._stores = stores
        self._tmrescore = tmrescore
        self._config = config
        self.include_access_tokens = include_access_tokens
        self.include_source = include_source
        self._connections: dict[str, sqlite3.Connection] = {}

    def stores(self) -> list[StoreInfo]:
        return [store.info for store in self._stores]

    def _connection(self, namespace: str) -> sqlite3.Connection | None:
        for store in self._stores:
            if namespace in store.namespaces:
                if store.path is None:
                    return None
                connection = self._connections.get(store.path)
                if connection is None:
                    connection = _connect_ro(store.path)
                    self._connections[store.path] = connection
                if not any(m.namespace == namespace for m in store.info.migrations):
                    return None
                return connection
        return None

    def close(self) -> None:
        for connection in self._connections.values():
            connection.close()
        self._connections = {}

    def config(self) -> dict[str, bytes | None]:
        return dict(self._config)

    def sequences(self) -> dict[str, int]:
        result = {}
        for name, table, namespace, id_column in (
            ("assessment_revisions", "assessment_revisions", "assessment_outbox", "revision_id"),
            ("access_token_audit", "access_token_audit", "access_tokens", "audit_id"),
        ):
            connection = self._connection(namespace)
            value = 0
            if connection is not None:
                row = None
                if "sqlite_sequence" in _tables(connection):
                    row = connection.execute(
                        "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
                    ).fetchone()
                if row is not None:
                    value = int(row[0])
                else:
                    value = int(
                        connection.execute(
                            f"SELECT COALESCE(MAX({id_column}), 0) FROM {table}"
                        ).fetchone()[0]
                    )
            result[name] = value
        return result

    def iter_entity(self, name: str) -> Iterator[dict[str, Any]]:
        spec = ENTITIES[name]
        if spec.group == "source" and not self.include_source:
            return iter(())
        if spec.group == "credentials" and not self.include_access_tokens:
            return iter(())
        if name == "tmrescore_proposal":
            return self._tmrescore_records()
        connection = self._connection(spec.namespace)
        if connection is None:
            return iter(())
        return getattr(self, f"_{name}")(connection)

    # -- entities ------------------------------------------------------------

    def _assessment(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM assessment_state "
            "ORDER BY project_uuid, component_uuid, vulnerability_uuid"
        ):
            yield {
                "key": _key(row),
                "revision": int(row["revision"]),
                "value": _value(row["analysis_state"], row["analysis_details"], row["suppressed"]),
                "updated_at": row["updated_at"],
                "sync": {
                    "status": row["sync_status"],
                    "update_id": row["update_id"],
                    "last_error": row["last_error"],
                    "export_rejections": int(row["export_rejections"] or 0),
                    "base": AssessmentOutboxStore.resolve_base_value(row),
                    "remote": None
                    if row["remote_state"] is None
                    else _value(
                        row["remote_state"], row["remote_details"], row["remote_suppressed"]
                    ),
                },
            }

    def _revision(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            """
            SELECT r.revision_id, r.project_uuid, r.component_uuid,
                   r.vulnerability_uuid, r.revision, r.analysis_state,
                   r.suppressed, r.origin, r.author, r.created_at,
                   r.text_in_record, s.project_uuid IS NOT NULL AS has_state,
                   CASE WHEN r.text_in_record
                        THEN s.analysis_details
                        ELSE r.analysis_details END AS analysis_details
            FROM assessment_revisions r
            LEFT JOIN assessment_state s
              ON s.project_uuid = r.project_uuid
             AND s.component_uuid = r.component_uuid
             AND s.vulnerability_uuid = r.vulnerability_uuid
            ORDER BY r.revision_id
            """
        ):
            if row["text_in_record"] and not row["has_state"]:
                raise DumpError(
                    "R3",
                    f"History entry {row['revision_id']} keeps its text in an "
                    "assessment record that does not exist; its text cannot be resolved",
                )
            yield {
                "revision_id": int(row["revision_id"]),
                "key": _key(row),
                "revision": int(row["revision"]),
                "value": _value(row["analysis_state"], row["analysis_details"], row["suppressed"]),
                "origin": row["origin"],
                "author": row["author"],
                "created_at": row["created_at"],
            }

    def _outbox_entry(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM assessment_outbox "
            "ORDER BY project_uuid, component_uuid, vulnerability_uuid"
        ):
            yield {
                "key": _key(row),
                "revision": int(row["revision"]),
                "update_id": row["update_id"],
                **embedded(row["payload_json"]),
                "attempts": int(row["attempts"]),
                "next_attempt_at": row["next_attempt_at"],
                "last_error": row["last_error"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def _known_project(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute("SELECT * FROM known_projects ORDER BY project_uuid"):
            yield {
                "project_uuid": row["project_uuid"],
                "name": row["name"],
                "version": row["version"],
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
            }

    def _source_snapshot(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM source_snapshots ORDER BY kind, project_uuid"
        ):
            record = {
                "kind": row["kind"],
                "project_uuid": row["project_uuid"],
                "item_count": int(row["item_count"]),
                "updated_at": row["updated_at"],
                "form": "list" if row["raw_json"] is None else "raw",
            }
            if row["raw_json"] is not None:
                try:
                    record["raw"] = json.loads(row["raw_json"], parse_constant=_reject_constant)
                except ValueError as exc:
                    raise DumpError(
                        "S1",
                        f"The stored {row['kind']} document of {row['project_uuid']!r} is not JSON",
                    ) from exc
            yield record

    def _source_project(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT position, payload_json FROM source_projects ORDER BY position"
        ):
            yield {"position": int(row["position"]), **embedded(row["payload_json"])}

    def _source_list(self, connection: sqlite3.Connection, table: str) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            f"SELECT project_uuid, position, payload_json FROM {table} "
            "ORDER BY project_uuid, position"
        ):
            yield {
                "project_uuid": row["project_uuid"],
                "position": int(row["position"]),
                **embedded(row["payload_json"]),
            }

    def _source_finding(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        return self._source_list(connection, "source_findings")

    def _source_project_vulnerability(
        self, connection: sqlite3.Connection
    ) -> Iterator[dict[str, Any]]:
        return self._source_list(connection, "source_project_vulnerabilities")

    def _source_bom(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute("SELECT * FROM source_boms ORDER BY project_uuid"):
            yield {
                "project_uuid": row["project_uuid"],
                **embedded(row["payload_json"]),
                "updated_at": row["updated_at"],
            }

    def _source_analysis(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT project_uuid, component_uuid, vulnerability_uuid, payload_json, "
            "updated_at FROM source_analyses "
            "ORDER BY project_uuid, component_uuid, vulnerability_uuid"
        ):
            yield {
                "key": _key(row),
                **embedded(row["payload_json"]),
                "updated_at": row["updated_at"],
            }

    def _token_audit(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute("SELECT * FROM access_token_audit ORDER BY audit_id"):
            yield {
                "audit_id": int(row["audit_id"]),
                "occurred_at": row["occurred_at"],
                "username": row["username"],
                "token_id": row["token_id"],
                "agent": row["agent"],
                "action": row["action"],
                "outcome": row["outcome"],
                **embedded(row["target_json"], "target"),
                "detail": row["detail"],
            }

    def _access_token(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute("SELECT * FROM access_tokens ORDER BY token_id"):
            yield {
                "token_id": row["token_id"],
                "username": row["username"],
                "name": row["name"],
                "token_hash": row["token_hash"],
                "scopes": str(row["scopes"]).split(),
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "last_used_at": row["last_used_at"],
                "revoked_at": row["revoked_at"],
            }

    def _code_analysis_result(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT analysis_run_id, payload_json FROM code_analysis_results "
            "ORDER BY analysis_run_id"
        ):
            yield {
                "analysis_run_id": row["analysis_run_id"],
                **embedded(row["payload_json"], require_object=True),
            }

    def _code_evidence(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        vuln_ids: dict[str, list[str]] = {}
        for row in connection.execute(
            "SELECT evidence_id, vuln_id_lower FROM code_evidence_vuln_ids "
            "ORDER BY evidence_id, vuln_id_lower"
        ):
            vuln_ids.setdefault(row["evidence_id"], []).append(row["vuln_id_lower"])
        for row in connection.execute("SELECT * FROM code_evidence ORDER BY evidence_id"):
            yield {
                "evidence_id": row["evidence_id"],
                "schema_version": row["schema_version"],
                "source": row["source"],
                "project_name": row["project_name"],
                "vuln_id": row["vuln_id"],
                "vuln_ids": vuln_ids.get(row["evidence_id"], []),
                "scope": row["scope"],
                **embedded(row["targets_json"], "targets"),
                "title": row["title"],
                "body_markdown": row["body_markdown"],
                **embedded(row["references_json"], "references"),
                **{
                    column: row[column]
                    for column in (
                        "suggested_state",
                        "suggested_justification",
                        "confidence",
                        "author_username",
                        "token_id",
                        "agent_label",
                        "authority",
                        "idempotency_key",
                        "created_at",
                        "withdrawn_at",
                        "withdrawn_by",
                        "withdrawn_reason",
                    )
                },
            }

    def _code_evidence_application(
        self, connection: sqlite3.Connection
    ) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM code_evidence_applications ORDER BY evidence_id, finding_uuid"
        ):
            yield {
                column: row[column]
                for column in (
                    "evidence_id",
                    "finding_uuid",
                    "workflow_id",
                    "status",
                    "applied_by",
                    "applied_at",
                )
            }

    def _finding_presence(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM finding_presence "
            "ORDER BY project_uuid, component_uuid, vulnerability_uuid"
        ):
            yield {
                "key": _key(row),
                **{
                    column: row[column]
                    for column in (
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
                    )
                },
            }

    def _finding_read(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        for row in connection.execute("SELECT * FROM finding_reads ORDER BY project_uuid"):
            yield {
                "project_uuid": row["project_uuid"],
                "read_at": row["read_at"],
                **embedded(row["went_json"], "went", require_object=True),
                "returned": int(row["returned"]),
                "carried_over": int(row["carried_over"]),
                "not_carried": int(row["not_carried"]),
            }

    def _session_version(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        if "session_versions" not in _tables(connection):
            return
        for row in connection.execute("SELECT * FROM session_versions ORDER BY username"):
            yield {
                "username": row["username"],
                "version": int(row["version"]),
                "revoked_at": row["revoked_at"],
            }

    def _code_analysis_application(
        self, connection: sqlite3.Connection
    ) -> Iterator[dict[str, Any]]:
        for row in connection.execute(
            "SELECT * FROM code_analysis_result_applications "
            "ORDER BY analysis_run_id, finding_uuid"
        ):
            yield {
                column: row[column]
                for column in (
                    "analysis_run_id",
                    "finding_uuid",
                    "group_id_lower",
                    "workflow_id",
                    "status",
                    "applied_by",
                    "applied_at",
                    "payload_fingerprint",
                )
            }

    def _instance_metadata(self, connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
        placeholders = ",".join("?" for _ in INSTANCE_METADATA_KEYS)
        for row in connection.execute(
            f"SELECT key, value_json FROM store_metadata WHERE key IN ({placeholders}) "
            "ORDER BY key",
            INSTANCE_METADATA_KEYS,
        ):
            try:
                value = json.loads(row["value_json"], parse_constant=_reject_constant)
            except ValueError as exc:
                raise DumpError("S1", f"store_metadata {row['key']} is not JSON") from exc
            yield {"key": row["key"], "value": value}

    def _tmrescore_records(self) -> Iterator[dict[str, Any]]:
        if self._tmrescore is None:
            return
        cache = json.loads(self._tmrescore)
        for project_name in sorted(cache):
            yield {"project_name": project_name, "snapshot": cache[project_name]}


def copy_tree_free_space_needed(paths: list[str]) -> int:
    """1.1 times the live bytes of the given databases."""
    return int(1.1 * sum(live_bytes(path) for path in paths))


def free_bytes(directory: str) -> int:
    return shutil.disk_usage(directory).free
