"""The local database for data imported from a vulnerability source.

Projects, findings, vulnerability details, BOMs, and the last known source
assessments live in one SQLite file (see docs/adr/0002). Documents are
addressed by a ``DocumentRef``; every document round-trips losslessly, and
lists are stored one row per item with lookup columns derived from the item.

The store is synchronous. Callers decide which thread runs it; every thread
gets its own connection, which it keeps until ``close``.
"""

import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .sqlite_migration_services import run_sqlite_migrations

LOCAL_STORE_MIGRATION_NAMESPACE = "local_store"
DATABASE_FILENAME = "dtvp.sqlite3"

KIND_PROJECTS = "projects"
KIND_FINDINGS = "findings"
KIND_PROJECT_VULNERABILITIES = "project_vulnerabilities"
KIND_BOM = "bom"
KIND_ANALYSIS = "analysis"
KIND_METADATA = "metadata"

LEGACY_IMPORT_KEY = "legacy_json_import"
MISSING: Any = object()


@dataclass(frozen=True)
class DocumentRef:
    kind: str
    project_uuid: str = ""
    component_uuid: str = ""
    vulnerability_uuid: str = ""
    name: str = ""


def get_database_path(cache_path: str) -> str:
    configured_path = os.getenv("DTVP_DATABASE_PATH", "").strip()
    if configured_path:
        return configured_path
    return os.path.join(cache_path, DATABASE_FILENAME)


def get_default_database_path() -> str:
    """The database path for stores that are not handed a data directory."""
    return get_database_path(os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache"))


def get_local_store_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "local_store"


def safe_filename(value: str) -> str:
    """The file-name form of an identifier in the former JSON cache."""
    if not value:
        return ""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _nested(item: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(item, dict):
            return None
        item = item.get(key)
    return item


def _project_row(position: int, item: Any) -> tuple[Any, ...]:
    return (
        position,
        _text(_nested(item, "uuid")),
        _text(_nested(item, "name")),
        _text(_nested(item, "version")),
        _dump(item),
    )


def _finding_row(project_uuid: str, position: int, item: Any) -> tuple[Any, ...]:
    return (
        project_uuid,
        position,
        _text(_nested(item, "component", "uuid")),
        _text(_nested(item, "vulnerability", "uuid")),
        _text(_nested(item, "vulnerability", "vulnId")),
        _text(_nested(item, "vulnerability", "severity")),
        _text(_nested(item, "component", "name")),
        _text(_nested(item, "component", "version")),
        _dump(item),
    )


def _project_vulnerability_row(
    project_uuid: str, position: int, item: Any
) -> tuple[Any, ...]:
    return (
        project_uuid,
        position,
        _text(_nested(item, "uuid")),
        _text(_nested(item, "vulnId")),
        _dump(item),
    )


_LIST_TABLES = {
    KIND_PROJECTS: "source_projects",
    KIND_FINDINGS: "source_findings",
    KIND_PROJECT_VULNERABILITIES: "source_project_vulnerabilities",
}


class LocalStore:
    def __init__(self, path: str, logger: Any = None) -> None:
        self.path = path
        self.logger = logger
        self._lock = threading.RLock()
        self._initialized = False
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []

    # -- connection -------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        """This thread's connection. Opening one per call cost milliseconds,
        which adds up over the per-finding lookups of a large project."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return connection
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Used by its own thread only; the flag just lets close() run
        # from whichever thread shuts the store down.
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        # Source data can be imported again; durability to the last
        # checkpoint is enough and keeps large imports fast.
        connection.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            if not self._initialized:
                run_sqlite_migrations(
                    connection,
                    namespace=LOCAL_STORE_MIGRATION_NAMESPACE,
                    migrations_path=get_local_store_migrations_path(),
                    logger=self.logger,
                )
                self._initialized = True
            self._connections.append(connection)
        self._local.connection = connection
        return connection

    def close(self) -> None:
        """Close every thread's connection. The store must not be used after."""
        with self._lock:
            connections, self._connections = self._connections, []
        for connection in connections:
            try:
                connection.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()

    # -- reading ----------------------------------------------------------

    def read(self, ref: DocumentRef) -> Any:
        """Return the stored document, or ``MISSING`` when it was never stored."""
        return self._read(self._connection(), ref)

    def exists(self, ref: DocumentRef) -> bool:
        return self._exists(self._connection(), ref)

    def _exists(self, connection: sqlite3.Connection, ref: DocumentRef) -> bool:
        if ref.kind == KIND_METADATA:
            query, params = (
                "SELECT 1 FROM store_metadata WHERE key = ?",
                (ref.name,),
            )
        elif ref.kind == KIND_ANALYSIS:
            query, params = (
                """
                SELECT 1 FROM source_analyses
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                (ref.project_uuid, ref.component_uuid, ref.vulnerability_uuid),
            )
        elif ref.kind == KIND_BOM:
            query, params = (
                "SELECT 1 FROM source_boms WHERE project_uuid = ?",
                (ref.project_uuid,),
            )
        else:
            query, params = (
                "SELECT 1 FROM source_snapshots WHERE kind = ? AND project_uuid = ?",
                (ref.kind, ref.project_uuid),
            )
        return connection.execute(query, params).fetchone() is not None

    def _read(self, connection: sqlite3.Connection, ref: DocumentRef) -> Any:
        if ref.kind == KIND_METADATA:
            row = connection.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                (ref.name,),
            ).fetchone()
            return MISSING if row is None else json.loads(row[0])
        if ref.kind == KIND_ANALYSIS:
            row = connection.execute(
                """
                SELECT payload_json FROM source_analyses
                WHERE project_uuid = ? AND component_uuid = ?
                  AND vulnerability_uuid = ?
                """,
                (ref.project_uuid, ref.component_uuid, ref.vulnerability_uuid),
            ).fetchone()
            return MISSING if row is None else json.loads(row[0])
        if ref.kind == KIND_BOM:
            row = connection.execute(
                "SELECT payload_json FROM source_boms WHERE project_uuid = ?",
                (ref.project_uuid,),
            ).fetchone()
            return MISSING if row is None else json.loads(row[0])

        table = _LIST_TABLES[ref.kind]
        snapshot = connection.execute(
            "SELECT raw_json FROM source_snapshots WHERE kind = ? AND project_uuid = ?",
            (ref.kind, ref.project_uuid),
        ).fetchone()
        if snapshot is None:
            return MISSING
        if snapshot[0] is not None:
            return json.loads(snapshot[0])
        if ref.kind == KIND_PROJECTS:
            rows = connection.execute(
                f"SELECT payload_json FROM {table} ORDER BY position"
            )
        else:
            rows = connection.execute(
                f"SELECT payload_json FROM {table} WHERE project_uuid = ? "
                "ORDER BY position",
                (ref.project_uuid,),
            )
        return [json.loads(row[0]) for row in rows]

    # -- writing ----------------------------------------------------------

    def write(self, ref: DocumentRef, data: Any) -> None:
        connection = self._connection()
        with connection:
            self._write(connection, ref, data)

    def write_many(self, documents: Iterable[tuple[DocumentRef, Any]]) -> int:
        """Store several documents in one transaction."""
        count = 0
        connection = self._connection()
        with connection:
            for ref, data in documents:
                self._write(connection, ref, data)
                count += 1
        return count

    def _write(self, connection: sqlite3.Connection, ref: DocumentRef, data: Any) -> None:
        now = _now()
        if ref.kind == KIND_METADATA:
            connection.execute(
                """
                INSERT INTO store_metadata (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT (key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (ref.name, _dump(data), now),
            )
            return
        if ref.kind == KIND_ANALYSIS:
            analysis = data if isinstance(data, dict) else {}
            suppressed = analysis.get("isSuppressed", analysis.get("is_suppressed"))
            connection.execute(
                """
                INSERT INTO source_analyses (
                    project_uuid, component_uuid, vulnerability_uuid,
                    analysis_state, analysis_details, suppressed,
                    payload_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (project_uuid, component_uuid, vulnerability_uuid)
                DO UPDATE SET
                    analysis_state = excluded.analysis_state,
                    analysis_details = excluded.analysis_details,
                    suppressed = excluded.suppressed,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    ref.project_uuid,
                    ref.component_uuid,
                    ref.vulnerability_uuid,
                    _text(analysis.get("analysisState") or analysis.get("state")),
                    _text(
                        analysis.get("analysisDetails")
                        or analysis.get("analysis_details")
                    ),
                    None if suppressed is None else int(bool(suppressed)),
                    _dump(data),
                    now,
                ),
            )
            return
        if ref.kind == KIND_BOM:
            connection.execute(
                """
                INSERT INTO source_boms (project_uuid, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT (project_uuid) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (ref.project_uuid, _dump(data), now),
            )
            return

        table = _LIST_TABLES[ref.kind]
        if ref.kind == KIND_PROJECTS:
            connection.execute(f"DELETE FROM {table}")
        else:
            connection.execute(
                f"DELETE FROM {table} WHERE project_uuid = ?",
                (ref.project_uuid,),
            )
        raw_json: str | None = None
        item_count = 0
        if isinstance(data, list):
            item_count = len(data)
            if ref.kind == KIND_PROJECTS:
                connection.executemany(
                    f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?)",
                    (_project_row(i, item) for i, item in enumerate(data)),
                )
                # Remembered beyond the list, which the next import replaces.
                connection.executemany(
                    """
                    INSERT INTO known_projects (
                        project_uuid, name, version, first_seen_at, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (project_uuid) DO UPDATE SET
                        name = COALESCE(excluded.name, known_projects.name),
                        version = COALESCE(excluded.version, known_projects.version),
                        last_seen_at = excluded.last_seen_at
                    """,
                    (
                        (
                            _text(_nested(item, "uuid")),
                            _text(_nested(item, "name")),
                            _text(_nested(item, "version")),
                            now,
                            now,
                        )
                        for item in data
                        if _text(_nested(item, "uuid"))
                    ),
                )
            elif ref.kind == KIND_FINDINGS:
                connection.executemany(
                    f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        _finding_row(ref.project_uuid, i, item)
                        for i, item in enumerate(data)
                    ),
                )
            else:
                connection.executemany(
                    f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?)",
                    (
                        _project_vulnerability_row(ref.project_uuid, i, item)
                        for i, item in enumerate(data)
                    ),
                )
        else:
            # Not a list (for example null): keep it verbatim.
            raw_json = _dump(data)
        connection.execute(
            """
            INSERT INTO source_snapshots (
                kind, project_uuid, item_count, raw_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (kind, project_uuid) DO UPDATE SET
                item_count = excluded.item_count,
                raw_json = excluded.raw_json,
                updated_at = excluded.updated_at
            """,
            (ref.kind, ref.project_uuid, item_count, raw_json, now),
        )

    # -- inventory --------------------------------------------------------

    def counts(self) -> dict[str, int]:
        connection = self._connection()

        def count(query: str, *params: Any) -> int:
            return int(connection.execute(query, params).fetchone()[0])

        return {
            "findings": count(
                "SELECT COUNT(*) FROM source_snapshots WHERE kind = ?",
                KIND_FINDINGS,
            ),
            "boms": count("SELECT COUNT(*) FROM source_boms"),
            "analyses": count("SELECT COUNT(*) FROM source_analyses"),
        }

    def project_uuids_with_findings(self) -> list[str]:
        rows = self._connection().execute(
            "SELECT project_uuid FROM source_snapshots WHERE kind = ? "
            "ORDER BY project_uuid",
            (KIND_FINDINGS,),
        ).fetchall()
        return [row[0] for row in rows]

    def describe_projects(
        self,
        project_uuids: Iterable[str],
    ) -> dict[str, dict[str, Any]]:
        """Name and version of projects, including ones the source no longer
        lists.

        A project seen in an import is remembered with the time it was last
        listed. For one that vanished before that record existed, the name
        and version are taken from its stored BOM, whose root component is
        the product.
        """
        connection = self._connection()
        described: dict[str, dict[str, Any]] = {}
        for project_uuid in sorted({str(value) for value in project_uuids if value}):
            row = connection.execute(
                "SELECT name, version, last_seen_at FROM known_projects "
                "WHERE project_uuid = ?",
                (project_uuid,),
            ).fetchone()
            if row is not None and row[0]:
                described[project_uuid] = {
                    "name": row[0],
                    "version": row[1],
                    "last_seen_at": row[2],
                }
                continue
            try:
                bom = connection.execute(
                    """
                    SELECT json_extract(payload_json, '$.metadata.component.name'),
                           json_extract(payload_json, '$.metadata.component.version'),
                           updated_at
                    FROM source_boms WHERE project_uuid = ?
                    """,
                    (project_uuid,),
                ).fetchone()
            except sqlite3.Error:
                bom = None
            if bom is not None and isinstance(bom[0], str) and bom[0]:
                described[project_uuid] = {
                    "name": bom[0],
                    "version": bom[1] if isinstance(bom[1], str) else None,
                    "last_seen_at": bom[2],
                }
        return described

    def describe_findings(
        self,
        keys: Iterable[tuple[str, str, str]],
    ) -> dict[tuple[str, str, str], dict[str, Any]]:
        """Readable labels for findings, from the stored lookup columns."""
        wanted = set(keys)
        described: dict[tuple[str, str, str], dict[str, Any]] = {}
        connection = self._connection()
        for project_uuid in sorted({key[0] for key in wanted}):
            rows = connection.execute(
                """
                SELECT component_uuid, vulnerability_uuid, vuln_id,
                       component_name, component_version
                FROM source_findings
                WHERE project_uuid = ?
                """,
                (project_uuid,),
            )
            for component_uuid, vulnerability_uuid, vuln_id, name, version in rows:
                key = (project_uuid, component_uuid, vulnerability_uuid)
                if key in wanted:
                    described[key] = {
                        "vuln_id": vuln_id,
                        "component_name": name,
                        "component_version": version,
                    }
        return described

    def read_project_analyses(
        self, project_uuid: str
    ) -> dict[tuple[str, str], Any]:
        """Every stored source assessment of a project, keyed by
        (component UUID, vulnerability UUID), in one query."""
        rows = self._connection().execute(
            """
            SELECT component_uuid, vulnerability_uuid, payload_json
            FROM source_analyses
            WHERE project_uuid = ?
            """,
            (project_uuid,),
        ).fetchall()
        return {(row[0], row[1]): json.loads(row[2]) for row in rows}

    # -- one-time import of the JSON cache --------------------------------

    def import_legacy_json_cache(self, base_path: str) -> dict[str, int] | None:
        """Import the JSON cache directory once. The files are left in place.

        Returns the imported counts, or ``None`` when the import already ran.
        Documents are streamed into one transaction, so a large cache is not
        held in memory and a crash leaves nothing half imported.
        """
        marker = DocumentRef(KIND_METADATA, name=LEGACY_IMPORT_KEY)
        with self._lock:
            if self.exists(marker):
                return None
            counts = {
                "projects": 0,
                "findings": 0,
                "project_vulnerabilities": 0,
                "boms": 0,
                "analyses": 0,
                "skipped": 0,
            }
            self.write_many(self._legacy_documents(base_path, counts, marker))
            return counts

    def _legacy_documents(
        self,
        base_path: str,
        counts: dict[str, int],
        marker: DocumentRef,
    ) -> Iterable[tuple[DocumentRef, Any]]:
        def load(path: str) -> Any:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            except Exception as exc:
                counts["skipped"] += 1
                if self.logger is not None:
                    self.logger.warning(
                        "Skipped unreadable cache file %s: %s", path, exc
                    )
                return MISSING

        def json_files(directory: str) -> list[tuple[str, str]]:
            folder = os.path.join(base_path, directory)
            if not os.path.isdir(folder):
                return []
            return [
                (name[:-5], os.path.join(folder, name))
                for name in sorted(os.listdir(folder))
                if name.endswith(".json") and not name.startswith(".")
            ]

        # File names are sanitised UUIDs; recover the real UUID where the
        # project list knows it. Dependency-Track UUIDs need no sanitising.
        uuid_by_stem: dict[str, str] = {}
        projects_path = os.path.join(base_path, "projects.json")
        if os.path.isfile(projects_path):
            projects = load(projects_path)
            if projects is not MISSING:
                if isinstance(projects, list):
                    counts["projects"] = len(projects)
                    for project in projects:
                        project_uuid = _text(_nested(project, "uuid"))
                        if project_uuid:
                            uuid_by_stem[safe_filename(project_uuid)] = project_uuid
                yield DocumentRef(KIND_PROJECTS), projects
        for name in ("projects_meta", "active_projects"):
            path = os.path.join(base_path, f"{name}.json")
            if os.path.isfile(path):
                value = load(path)
                if value is not MISSING:
                    yield DocumentRef(KIND_METADATA, name=name), value

        for directory, kind, counter in (
            ("findings", KIND_FINDINGS, "findings"),
            (
                "project_vulnerabilities",
                KIND_PROJECT_VULNERABILITIES,
                "project_vulnerabilities",
            ),
            ("boms", KIND_BOM, "boms"),
        ):
            for stem, path in json_files(directory):
                value = load(path)
                if value is MISSING:
                    continue
                counts[counter] += 1
                yield DocumentRef(
                    kind, project_uuid=uuid_by_stem.get(stem, stem)
                ), value

        for stem, path in json_files("analysis"):
            parts = stem.split("__")
            if len(parts) != 3 or not all(parts):
                counts["skipped"] += 1
                if self.logger is not None:
                    self.logger.warning(
                        "Skipped cache file with an unexpected name: %s", path
                    )
                continue
            value = load(path)
            if value is MISSING:
                continue
            counts["analyses"] += 1
            yield DocumentRef(
                KIND_ANALYSIS,
                project_uuid=uuid_by_stem.get(parts[0], parts[0]),
                component_uuid=parts[1],
                vulnerability_uuid=parts[2],
            ), value

        # The marker commits with the data: a crash imports again from the
        # untouched files instead of leaving a partial database.
        yield marker, {"imported_at": _now(), **counts}
