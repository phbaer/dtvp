import json
import logging
import os
import re
import sqlite3
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def get_knowledge_store_path() -> str:
    return os.getenv("DTVP_KNOWLEDGE_STORE_PATH", "data/knowledge_store")


def get_knowledge_store_backend() -> str:
    return os.getenv("DTVP_KNOWLEDGE_STORE_BACKEND", "json").strip().lower()


def _safe_filename(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _atomic_write(path: str, data: Any) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_file = None
    try:
        fd, tmp_file = tempfile.mkstemp(dir=directory or ".", prefix=".tmp-", text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(tmp_file, path)
    finally:
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass


def _read_json(path: str, default: Any = None) -> Any:
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        logger.warning("Failed to read knowledge store file %s: %s", path, exc)
        return default


def _normalize_component_identity(component: Dict[str, Any]) -> str:
    purl = str(component.get("purl") or "").strip().lower()
    if purl:
        return re.sub(r"@[^?]+", "", purl, count=1)
    return str(component.get("name") or "").strip().lower()


def _normalize_vulnerability_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().upper()
    if not normalized:
        return ""
    if normalized.startswith(("CVE-", "GHSA-")):
        return normalized
    if re.match(r"^[A-Z]+-[A-Z0-9_.-]+$", normalized):
        return normalized
    return normalized


def _collect_string_aliases(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


def _iter_alias_values(aliases: Any) -> Iterable[str]:
    if isinstance(aliases, list):
        values: list[str] = []
        for alias in aliases:
            if isinstance(alias, dict):
                for raw in alias.values():
                    values.extend(_collect_string_aliases(raw))
                continue
            values.extend(_collect_string_aliases(alias))
        return values
    if isinstance(aliases, dict):
        values: list[str] = []
        for raw in aliases.values():
            values.extend(_collect_string_aliases(raw))
        return values
    return []


def collect_vulnerability_aliases(vulnerability: Dict[str, Any]) -> list[str]:
    identifiers = [
        _normalize_vulnerability_id(vulnerability.get("vulnId")),
        _normalize_vulnerability_id(vulnerability.get("name")),
    ]
    identifiers.extend(
        _normalize_vulnerability_id(value)
        for value in _iter_alias_values(vulnerability.get("aliases"))
    )
    deduped: list[str] = []
    for identifier in identifiers:
        if identifier and identifier not in deduped:
            deduped.append(identifier)
    return deduped


def select_canonical_vulnerability_id(vulnerability: Dict[str, Any]) -> str:
    aliases = collect_vulnerability_aliases(vulnerability)
    if not aliases:
        fallback_uuid = str(vulnerability.get("uuid") or "").strip()
        return f"UUID:{fallback_uuid}" if fallback_uuid else ""

    def _priority(identifier: str) -> tuple[int, str]:
        if identifier.startswith("CVE-"):
            return (0, identifier)
        if identifier.startswith("GHSA-"):
            return (1, identifier)
        return (2, identifier)

    return min(aliases, key=_priority)


def assessment_primary_key(component_uuid: str, canonical_vulnerability_id: str) -> str:
    return "__".join(
        [
            _safe_filename(component_uuid.strip()),
            _safe_filename(canonical_vulnerability_id.strip()),
        ]
    )


def assessment_triplet_key(
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
) -> str:
    return "__".join(
        [
            _safe_filename(project_uuid.strip()),
            _safe_filename(component_uuid.strip()),
            _safe_filename(vulnerability_uuid.strip()),
        ]
    )


def _build_finding_lookup_request(
    component: Optional[Dict[str, Any]],
    vulnerability: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    component_data = component or {}
    vulnerability_data = vulnerability or {}
    component_uuid = str(component_data.get("uuid") or "").strip()
    canonical_vulnerability_id = select_canonical_vulnerability_id(vulnerability_data)
    aliases = sorted(set(collect_vulnerability_aliases(vulnerability_data)))
    if canonical_vulnerability_id and canonical_vulnerability_id not in aliases:
        aliases.append(canonical_vulnerability_id)
    return {
        "component_uuid": component_uuid,
        "canonical_vulnerability_id": canonical_vulnerability_id,
        "component_identity": _normalize_component_identity(component_data),
        "aliases": aliases,
    }


def _serialize_queue_items(items: Dict[str, Any]) -> Dict[str, Any]:
    serialized: Dict[str, Any] = {}
    for queue_id, item in items.items():
        if hasattr(item, "model_dump"):
            serialized[queue_id] = item.model_dump()
        elif isinstance(item, dict):
            serialized[queue_id] = dict(item)
    return serialized


def _build_assessment_record(
    *,
    payload: Dict[str, Any],
    component: Optional[Dict[str, Any]],
    vulnerability: Optional[Dict[str, Any]],
    existing: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    component_uuid = str(payload.get("component_uuid") or "").strip()
    if not component_uuid:
        return None

    vulnerability_data = vulnerability or {}
    canonical_vulnerability_id = select_canonical_vulnerability_id(vulnerability_data)
    if not canonical_vulnerability_id:
        fallback_vulnerability_uuid = str(
            payload.get("vulnerability_uuid") or ""
        ).strip()
        if not fallback_vulnerability_uuid:
            return None
        canonical_vulnerability_id = f"UUID:{fallback_vulnerability_uuid}"

    component_data = component or {}
    aliases = collect_vulnerability_aliases(vulnerability_data)
    if canonical_vulnerability_id not in aliases:
        aliases.append(canonical_vulnerability_id)

    merged_aliases = sorted(
        {*(existing or {}).get("vulnerability_aliases", []), *aliases}
    )
    triplets = list((existing or {}).get("triplets", []))
    project_uuid = str(payload.get("project_uuid") or "").strip()
    vulnerability_uuid = str(payload.get("vulnerability_uuid") or "").strip()
    if project_uuid and vulnerability_uuid:
        triplet = {
            "project_uuid": project_uuid,
            "component_uuid": component_uuid,
            "vulnerability_uuid": vulnerability_uuid,
        }
        if triplet not in triplets:
            triplets.append(triplet)

    return {
        "primary_key": assessment_primary_key(
            component_uuid, canonical_vulnerability_id
        ),
        "component_uuid": component_uuid,
        "component_identity": _normalize_component_identity(component_data)
        or (existing or {}).get("component_identity", ""),
        "component_name": component_data.get("name")
        or (existing or {}).get("component_name"),
        "component_purl": component_data.get("purl")
        or (existing or {}).get("component_purl"),
        "canonical_vulnerability_id": canonical_vulnerability_id,
        "vulnerability_aliases": merged_aliases,
        "vulnerability_uuid": payload.get("vulnerability_uuid"),
        "analysis": {
            "analysisState": payload.get("state") or "NOT_SET",
            "analysisDetails": payload.get("details") or "",
            "isSuppressed": bool(payload.get("suppressed", False)),
        },
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "triplets": triplets,
    }


class KnowledgeStoreBackend(ABC):
    def __init__(self, base_path: str):
        self.base_path = base_path

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def initialize(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def synchronize_active_projects(
        self,
        project_uuids: Iterable[str],
        *,
        grace_period_days: int,
        now: Optional[datetime] = None,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def purge_expired_knowledge(self, *, now: Optional[datetime] = None) -> int:
        raise NotImplementedError

    @abstractmethod
    def persist_assessment(
        self,
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_assessment_by_triplet(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_assessment_for_finding(
        self,
        *,
        component: Optional[Dict[str, Any]],
        vulnerability: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_assessments_for_findings(
        self,
        *,
        findings: Iterable[tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]],
    ) -> list[Optional[Dict[str, Any]]]:
        raise NotImplementedError

    @abstractmethod
    def save_code_analysis_queue_state(
        self,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def load_code_analysis_queue_state(self) -> Dict[str, Any]:
        raise NotImplementedError


class JsonKnowledgeStoreBackend(KnowledgeStoreBackend):
    def __init__(self, base_path: str):
        super().__init__(base_path)
        self._lock = RLock()
        self._cached_state: Optional[Dict[str, Any]] = None

    def _store_path(self) -> str:
        return os.path.join(self.base_path, "knowledge_store.json")

    def _empty_state(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "assessments": {},
            "assessment_triplet_index": {},
            "code_analysis_queue": {"items": {}, "order": []},
        }

    def _load_state(self) -> Dict[str, Any]:
        if self._cached_state is not None:
            return self._cached_state
        state = _read_json(self._store_path(), self._empty_state())
        if not isinstance(state, dict):
            state = self._empty_state()
        merged = self._empty_state()
        merged.update(state)
        if not isinstance(merged.get("assessments"), dict):
            merged["assessments"] = {}
        if not isinstance(merged.get("assessment_triplet_index"), dict):
            merged["assessment_triplet_index"] = {}
        queue_state = merged.get("code_analysis_queue") or {}
        if not isinstance(queue_state, dict):
            queue_state = {}
        merged["code_analysis_queue"] = {
            "items": queue_state.get("items") or {},
            "order": queue_state.get("order") or [],
        }
        self._cached_state = merged
        return merged

    def _save_state(self, state: Dict[str, Any]) -> None:
        self._cached_state = state
        _atomic_write(self._store_path(), state)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            state = self._load_state()
        queue_items = state.get("code_analysis_queue", {}).get("items", {})
        terminal_status_counts: Dict[str, int] = {}
        for item in queue_items.values():
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "unknown")
            terminal_status_counts[status] = terminal_status_counts.get(status, 0) + 1
        return {
            "store_type": "json",
            "path": self.base_path,
            "assessment_records": len(state.get("assessments", {})),
            "assessment_triplet_index_entries": len(
                state.get("assessment_triplet_index", {})
            ),
            "code_analysis_queue_items": len(queue_items),
            "code_analysis_queue_status_counts": terminal_status_counts,
        }

    def initialize(self) -> None:
        with self._lock:
            self._load_state()

    def synchronize_active_projects(
        self,
        project_uuids: Iterable[str],
        *,
        grace_period_days: int,
        now: Optional[datetime] = None,
    ) -> None:
        return None

    def purge_expired_knowledge(self, *, now: Optional[datetime] = None) -> int:
        return 0

    def persist_assessment(
        self,
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._load_state()
            existing = None
            component_uuid = str(payload.get("component_uuid") or "").strip()
            vulnerability_data = vulnerability or {}
            canonical_vulnerability_id = select_canonical_vulnerability_id(
                vulnerability_data
            )
            if component_uuid and canonical_vulnerability_id:
                existing = state["assessments"].get(
                    assessment_primary_key(component_uuid, canonical_vulnerability_id)
                )
            record = _build_assessment_record(
                payload=payload,
                component=component,
                vulnerability=vulnerability,
                existing=existing,
            )
            if not record:
                return None
            for triplet in record.get("triplets", []):
                state["assessment_triplet_index"][
                    assessment_triplet_key(
                        triplet["project_uuid"],
                        triplet["component_uuid"],
                        triplet["vulnerability_uuid"],
                    )
                ] = record["primary_key"]
            state["assessments"][record["primary_key"]] = record
            self._save_state(state)
            return record

    def get_assessment_by_triplet(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._load_state()
            primary_key = state["assessment_triplet_index"].get(
                assessment_triplet_key(project_uuid, component_uuid, vulnerability_uuid)
            )
            if not primary_key:
                return None
            record = state["assessments"].get(primary_key)
            if not isinstance(record, dict):
                return None
            return record.get("analysis")

    def get_assessment_for_finding(
        self,
        *,
        component: Optional[Dict[str, Any]],
        vulnerability: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        results = self.get_assessments_for_findings(
            findings=[(component, vulnerability)]
        )
        return results[0] if results else None

    def get_assessments_for_findings(
        self,
        *,
        findings: Iterable[tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]],
    ) -> list[Optional[Dict[str, Any]]]:
        requests = [
            _build_finding_lookup_request(component, vulnerability)
            for component, vulnerability in findings
        ]
        with self._lock:
            state = self._load_state()
            alias_matches: Dict[tuple[str, str], Dict[str, Any]] = {}
            for record in state["assessments"].values():
                if not isinstance(record, dict):
                    continue
                component_identity = str(record.get("component_identity") or "")
                for alias in record.get("vulnerability_aliases", []) or []:
                    if isinstance(alias, str) and alias:
                        alias_matches.setdefault(
                            (component_identity, alias),
                            record.get("analysis"),
                        )

            results: list[Optional[Dict[str, Any]]] = []
            for request in requests:
                component_uuid = request["component_uuid"]
                canonical_vulnerability_id = request["canonical_vulnerability_id"]
                if component_uuid and canonical_vulnerability_id:
                    primary_key = assessment_primary_key(
                        component_uuid, canonical_vulnerability_id
                    )
                    record = state["assessments"].get(primary_key)
                    if isinstance(record, dict):
                        results.append(record.get("analysis"))
                        continue

                component_identity = request["component_identity"]
                matched = None
                for alias in request["aliases"]:
                    matched = alias_matches.get((component_identity, alias))
                    if matched is not None:
                        break
                results.append(matched)
            return results

    def save_code_analysis_queue_state(
        self,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        with self._lock:
            state = self._load_state()
            state["code_analysis_queue"] = {
                "items": _serialize_queue_items(items),
                "order": list(order),
            }
            self._save_state(state)

    def load_code_analysis_queue_state(self) -> Dict[str, Any]:
        with self._lock:
            state = self._load_state()
            queue_state = state.get("code_analysis_queue") or {}
            items = queue_state.get("items") or {}
            order = queue_state.get("order") or []
            return {
                "items": dict(items),
                "order": [queue_id for queue_id in order if queue_id in items],
            }


class SqliteKnowledgeStoreBackend(KnowledgeStoreBackend):
    def __init__(self, base_path: str):
        super().__init__(base_path)
        self._lock = RLock()
        self._initialized = False

    def _db_path(self) -> str:
        return os.path.join(self.base_path, "knowledge_store.db")

    def _json_store_path(self) -> str:
        return os.path.join(self.base_path, "knowledge_store.json")

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(self.base_path, exist_ok=True)
        connection = sqlite3.connect(self._db_path(), timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _connection(self) -> Iterable[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_initialized(self) -> None:
        with self._lock:
            if self._initialized:
                return
            with self._connection() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS assessments (
                        primary_key TEXT PRIMARY KEY,
                        component_uuid TEXT NOT NULL,
                        component_identity TEXT,
                        component_name TEXT,
                        component_purl TEXT,
                        canonical_vulnerability_id TEXT NOT NULL,
                        vulnerability_uuid TEXT,
                        analysis_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS assessment_aliases (
                        primary_key TEXT NOT NULL,
                        alias TEXT NOT NULL,
                        PRIMARY KEY (primary_key, alias),
                        FOREIGN KEY (primary_key) REFERENCES assessments(primary_key) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS assessment_triplets (
                        triplet_key TEXT PRIMARY KEY,
                        primary_key TEXT NOT NULL,
                        project_uuid TEXT NOT NULL,
                        component_uuid TEXT NOT NULL,
                        vulnerability_uuid TEXT NOT NULL,
                        FOREIGN KEY (primary_key) REFERENCES assessments(primary_key) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_assessments_component_identity
                    ON assessments(component_identity);

                    CREATE INDEX IF NOT EXISTS idx_assessment_aliases_alias
                    ON assessment_aliases(alias);

                    CREATE INDEX IF NOT EXISTS idx_assessment_triplets_primary_key
                    ON assessment_triplets(primary_key);

                    CREATE TABLE IF NOT EXISTS queue_items (
                        queue_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        position INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS project_reachability (
                        project_uuid TEXT PRIMARY KEY,
                        is_active INTEGER NOT NULL,
                        last_seen_at TEXT,
                        purge_after TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_project_reachability_active
                    ON project_reachability(is_active, purge_after);
                    """
                )
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM assessments"
                ).fetchone()
                if row is not None and row["count"] == 0:
                    self._bootstrap_from_json(connection)
            self._initialized = True

    def initialize(self) -> None:
        self._ensure_initialized()

    def _bootstrap_from_json(self, connection: sqlite3.Connection) -> None:
        state = _read_json(self._json_store_path(), None)
        if not isinstance(state, dict):
            return
        for record in (state.get("assessments") or {}).values():
            if isinstance(record, dict):
                self._upsert_record(connection, record)
        queue_state = state.get("code_analysis_queue") or {}
        self._replace_queue_state(
            connection,
            items=queue_state.get("items") or {},
            order=queue_state.get("order") or [],
        )

    def _upsert_record(
        self, connection: sqlite3.Connection, record: Dict[str, Any]
    ) -> None:
        connection.execute(
            """
            INSERT INTO assessments (
                primary_key, component_uuid, component_identity, component_name,
                component_purl, canonical_vulnerability_id, vulnerability_uuid,
                analysis_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(primary_key) DO UPDATE SET
                component_uuid=excluded.component_uuid,
                component_identity=excluded.component_identity,
                component_name=excluded.component_name,
                component_purl=excluded.component_purl,
                canonical_vulnerability_id=excluded.canonical_vulnerability_id,
                vulnerability_uuid=excluded.vulnerability_uuid,
                analysis_json=excluded.analysis_json,
                updated_at=excluded.updated_at
            """,
            (
                record["primary_key"],
                record["component_uuid"],
                record.get("component_identity") or "",
                record.get("component_name"),
                record.get("component_purl"),
                record.get("canonical_vulnerability_id") or "",
                record.get("vulnerability_uuid"),
                json.dumps(record.get("analysis") or {}),
                record.get("updated_at") or datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.execute(
            "DELETE FROM assessment_aliases WHERE primary_key = ?",
            (record["primary_key"],),
        )
        aliases = [
            (record["primary_key"], alias)
            for alias in record.get("vulnerability_aliases", []) or []
            if isinstance(alias, str) and alias
        ]
        if aliases:
            connection.executemany(
                "INSERT OR IGNORE INTO assessment_aliases (primary_key, alias) VALUES (?, ?)",
                aliases,
            )
        for triplet in record.get("triplets", []) or []:
            if not isinstance(triplet, dict):
                continue
            project_uuid = str(triplet.get("project_uuid") or "").strip()
            component_uuid = str(triplet.get("component_uuid") or "").strip()
            vulnerability_uuid = str(triplet.get("vulnerability_uuid") or "").strip()
            if not (project_uuid and component_uuid and vulnerability_uuid):
                continue
            connection.execute(
                """
                INSERT OR REPLACE INTO assessment_triplets (
                    triplet_key, primary_key, project_uuid, component_uuid, vulnerability_uuid
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    assessment_triplet_key(
                        project_uuid, component_uuid, vulnerability_uuid
                    ),
                    record["primary_key"],
                    project_uuid,
                    component_uuid,
                    vulnerability_uuid,
                ),
            )

    def _replace_queue_state(
        self,
        connection: sqlite3.Connection,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        connection.execute("DELETE FROM queue_items")
        rows: list[tuple[str, str, int]] = []
        ordered_ids = [queue_id for queue_id in order if queue_id in items]
        seen = set(ordered_ids)
        for position, queue_id in enumerate(ordered_ids):
            rows.append((queue_id, json.dumps(items[queue_id]), position))
        for queue_id in items:
            if queue_id in seen:
                continue
            rows.append((queue_id, json.dumps(items[queue_id]), len(rows)))
        if rows:
            connection.executemany(
                "INSERT INTO queue_items (queue_id, payload_json, position) VALUES (?, ?, ?)",
                rows,
            )

    def get_status(self) -> Dict[str, Any]:
        self._ensure_initialized()
        with self._connection() as connection:
            assessment_records = connection.execute(
                "SELECT COUNT(*) AS count FROM assessments"
            ).fetchone()["count"]
            triplet_entries = connection.execute(
                "SELECT COUNT(*) AS count FROM assessment_triplets"
            ).fetchone()["count"]
            queue_rows = connection.execute(
                "SELECT payload_json FROM queue_items ORDER BY position ASC"
            ).fetchall()
            orphaned_records = connection.execute(
                "SELECT COUNT(*) AS count FROM project_reachability WHERE is_active = 0"
            ).fetchone()["count"]
        terminal_status_counts: Dict[str, int] = {}
        for row in queue_rows:
            payload = json.loads(row["payload_json"])
            status = str(payload.get("status") or "unknown")
            terminal_status_counts[status] = terminal_status_counts.get(status, 0) + 1
        return {
            "store_type": "sqlite",
            "path": self.base_path,
            "database_path": self._db_path(),
            "assessment_records": assessment_records,
            "assessment_triplet_index_entries": triplet_entries,
            "orphaned_project_records": orphaned_records,
            "code_analysis_queue_items": len(queue_rows),
            "code_analysis_queue_status_counts": terminal_status_counts,
        }

    def synchronize_active_projects(
        self,
        project_uuids: Iterable[str],
        *,
        grace_period_days: int,
        now: Optional[datetime] = None,
    ) -> None:
        self._ensure_initialized()
        active_project_ids = sorted(
            {
                str(project_uuid).strip()
                for project_uuid in project_uuids
                if str(project_uuid).strip()
            }
        )
        timestamp = (now or datetime.now(timezone.utc)).isoformat()
        purge_after = (
            (now or datetime.now(timezone.utc)) + timedelta(days=grace_period_days)
        ).isoformat()
        with self._connection() as connection:
            if active_project_ids:
                connection.executemany(
                    """
                    INSERT INTO project_reachability (project_uuid, is_active, last_seen_at, purge_after)
                    VALUES (?, 1, ?, NULL)
                    ON CONFLICT(project_uuid) DO UPDATE SET
                        is_active = 1,
                        last_seen_at = excluded.last_seen_at,
                        purge_after = NULL
                    """,
                    [(project_uuid, timestamp) for project_uuid in active_project_ids],
                )

            if active_project_ids:
                placeholders = ",".join("?" for _ in active_project_ids)
                connection.execute(
                    f"""
                    UPDATE project_reachability
                    SET is_active = 0,
                        purge_after = COALESCE(purge_after, ?)
                    WHERE is_active = 1
                      AND project_uuid NOT IN ({placeholders})
                    """,
                    (purge_after, *active_project_ids),
                )
            else:
                connection.execute(
                    """
                    UPDATE project_reachability
                    SET is_active = 0,
                        purge_after = COALESCE(purge_after, ?)
                    WHERE is_active = 1
                    """,
                    (purge_after,),
                )

    def purge_expired_knowledge(self, *, now: Optional[datetime] = None) -> int:
        self._ensure_initialized()
        cutoff = (now or datetime.now(timezone.utc)).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT assessments.primary_key
                FROM assessments
                WHERE EXISTS (
                    SELECT 1
                    FROM assessment_triplets
                    WHERE assessment_triplets.primary_key = assessments.primary_key
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM assessment_triplets
                    LEFT JOIN project_reachability
                        ON project_reachability.project_uuid = assessment_triplets.project_uuid
                    WHERE assessment_triplets.primary_key = assessments.primary_key
                      AND (
                        project_reachability.project_uuid IS NULL
                        OR project_reachability.is_active = 1
                        OR project_reachability.purge_after IS NULL
                        OR project_reachability.purge_after > ?
                      )
                )
                """,
                (cutoff,),
            ).fetchall()
            primary_keys = [row["primary_key"] for row in rows]
            if not primary_keys:
                return 0
            placeholders = ",".join("?" for _ in primary_keys)
            connection.execute(
                f"DELETE FROM assessments WHERE primary_key IN ({placeholders})",
                primary_keys,
            )
            return len(primary_keys)

    def persist_assessment(
        self,
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        self._ensure_initialized()
        component_uuid = str(payload.get("component_uuid") or "").strip()
        vulnerability_data = vulnerability or {}
        existing = None
        canonical_vulnerability_id = select_canonical_vulnerability_id(
            vulnerability_data
        )
        if component_uuid and canonical_vulnerability_id:
            primary_key = assessment_primary_key(
                component_uuid, canonical_vulnerability_id
            )
            with self._connection() as connection:
                assessment_row = connection.execute(
                    "SELECT * FROM assessments WHERE primary_key = ?",
                    (primary_key,),
                ).fetchone()
                if assessment_row is not None:
                    aliases = [
                        row["alias"]
                        for row in connection.execute(
                            "SELECT alias FROM assessment_aliases WHERE primary_key = ?",
                            (primary_key,),
                        ).fetchall()
                    ]
                    triplets = [
                        {
                            "project_uuid": row["project_uuid"],
                            "component_uuid": row["component_uuid"],
                            "vulnerability_uuid": row["vulnerability_uuid"],
                        }
                        for row in connection.execute(
                            "SELECT project_uuid, component_uuid, vulnerability_uuid FROM assessment_triplets WHERE primary_key = ?",
                            (primary_key,),
                        ).fetchall()
                    ]
                    existing = {
                        "component_identity": assessment_row["component_identity"],
                        "component_name": assessment_row["component_name"],
                        "component_purl": assessment_row["component_purl"],
                        "vulnerability_aliases": aliases,
                        "triplets": triplets,
                    }
        record = _build_assessment_record(
            payload=payload,
            component=component,
            vulnerability=vulnerability,
            existing=existing,
        )
        if not record:
            return None
        with self._connection() as connection:
            self._upsert_record(connection, record)
        return record

    def get_assessment_by_triplet(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        self._ensure_initialized()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT assessments.analysis_json
                FROM assessment_triplets
                JOIN assessments ON assessments.primary_key = assessment_triplets.primary_key
                WHERE assessment_triplets.triplet_key = ?
                """,
                (
                    assessment_triplet_key(
                        project_uuid, component_uuid, vulnerability_uuid
                    ),
                ),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["analysis_json"])

    def get_assessment_for_finding(
        self,
        *,
        component: Optional[Dict[str, Any]],
        vulnerability: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        results = self.get_assessments_for_findings(
            findings=[(component, vulnerability)]
        )
        return results[0] if results else None

    def get_assessments_for_findings(
        self,
        *,
        findings: Iterable[tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]],
    ) -> list[Optional[Dict[str, Any]]]:
        self._ensure_initialized()
        requests = [
            _build_finding_lookup_request(component, vulnerability)
            for component, vulnerability in findings
        ]
        if not requests:
            return []

        results: list[Optional[Dict[str, Any]]] = [None] * len(requests)
        with self._connection() as connection:
            primary_keys = sorted(
                {
                    assessment_primary_key(
                        request["component_uuid"],
                        request["canonical_vulnerability_id"],
                    )
                    for request in requests
                    if request["component_uuid"]
                    and request["canonical_vulnerability_id"]
                }
            )
            primary_key_matches: Dict[str, Dict[str, Any]] = {}
            if primary_keys:
                placeholders = ",".join("?" for _ in primary_keys)
                rows = connection.execute(
                    f"SELECT primary_key, analysis_json FROM assessments WHERE primary_key IN ({placeholders})",
                    primary_keys,
                ).fetchall()
                primary_key_matches = {
                    row["primary_key"]: json.loads(row["analysis_json"]) for row in rows
                }

            alias_values: list[tuple[int, str, str]] = []
            for index, request in enumerate(requests):
                component_uuid = request["component_uuid"]
                canonical_vulnerability_id = request["canonical_vulnerability_id"]
                if component_uuid and canonical_vulnerability_id:
                    primary_key = assessment_primary_key(
                        component_uuid, canonical_vulnerability_id
                    )
                    matched = primary_key_matches.get(primary_key)
                    if matched is not None:
                        results[index] = matched
                        continue

                if not request["component_identity"]:
                    continue
                for alias in request["aliases"]:
                    alias_values.append((index, request["component_identity"], alias))

            if alias_values:
                placeholders = ", ".join("(?, ?, ?)" for _ in alias_values)
                query = f"""
                    WITH requested(request_index, component_identity, alias) AS (
                        VALUES {placeholders}
                    ),
                    ranked_matches AS (
                        SELECT
                            requested.request_index,
                            assessments.analysis_json,
                            ROW_NUMBER() OVER (
                                PARTITION BY requested.request_index
                                ORDER BY assessments.updated_at DESC
                            ) AS row_number
                        FROM requested
                        JOIN assessment_aliases
                            ON assessment_aliases.alias = requested.alias
                        JOIN assessments
                            ON assessments.primary_key = assessment_aliases.primary_key
                        WHERE assessments.component_identity = requested.component_identity
                    )
                    SELECT request_index, analysis_json
                    FROM ranked_matches
                    WHERE row_number = 1
                """
                parameters = [value for triplet in alias_values for value in triplet]
                rows = connection.execute(query, parameters).fetchall()
                for row in rows:
                    request_index = int(row["request_index"])
                    if results[request_index] is None:
                        results[request_index] = json.loads(row["analysis_json"])
        return results

    def save_code_analysis_queue_state(
        self,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        self._ensure_initialized()
        with self._connection() as connection:
            self._replace_queue_state(
                connection,
                items=_serialize_queue_items(items),
                order=list(order),
            )

    def load_code_analysis_queue_state(self) -> Dict[str, Any]:
        self._ensure_initialized()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT queue_id, payload_json FROM queue_items ORDER BY position ASC"
            ).fetchall()
        return {
            "items": {row["queue_id"]: json.loads(row["payload_json"]) for row in rows},
            "order": [row["queue_id"] for row in rows],
        }


class KnowledgeStore:
    def __init__(self, base_path: Optional[str] = None):
        self._base_path = base_path or get_knowledge_store_path()
        self._lock = RLock()
        self._backend: Optional[KnowledgeStoreBackend] = None
        self._backend_name: Optional[str] = None

    @property
    def base_path(self) -> str:
        return self._base_path

    @base_path.setter
    def base_path(self, value: str) -> None:
        self._base_path = value
        self._reset_backend()

    def _reset_backend(self) -> None:
        with self._lock:
            self._backend = None
            self._backend_name = None

    def _resolve_backend(self) -> KnowledgeStoreBackend:
        backend_name = get_knowledge_store_backend()
        with self._lock:
            if self._backend is not None and self._backend_name == backend_name:
                return self._backend
            if backend_name == "sqlite":
                self._backend = SqliteKnowledgeStoreBackend(self.base_path)
                self._backend_name = "sqlite"
            else:
                self._backend = JsonKnowledgeStoreBackend(self.base_path)
                self._backend_name = "json"
            return self._backend

    def get_status(self) -> Dict[str, Any]:
        return self._resolve_backend().get_status()

    def initialize(self) -> None:
        self._resolve_backend().initialize()

    def synchronize_active_projects(
        self,
        project_uuids: Iterable[str],
        *,
        grace_period_days: int,
        now: Optional[datetime] = None,
    ) -> None:
        self._resolve_backend().synchronize_active_projects(
            project_uuids,
            grace_period_days=grace_period_days,
            now=now,
        )

    def purge_expired_knowledge(self, *, now: Optional[datetime] = None) -> int:
        return self._resolve_backend().purge_expired_knowledge(now=now)

    def persist_assessment(
        self,
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        return self._resolve_backend().persist_assessment(
            payload=payload,
            component=component,
            vulnerability=vulnerability,
        )

    def get_assessment_by_triplet(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        return self._resolve_backend().get_assessment_by_triplet(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
        )

    def get_assessment_for_finding(
        self,
        *,
        component: Optional[Dict[str, Any]],
        vulnerability: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        return self._resolve_backend().get_assessment_for_finding(
            component=component,
            vulnerability=vulnerability,
        )

    def get_assessments_for_findings(
        self,
        *,
        findings: Iterable[tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]],
    ) -> list[Optional[Dict[str, Any]]]:
        return self._resolve_backend().get_assessments_for_findings(findings=findings)

    def save_code_analysis_queue_state(
        self,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        self._resolve_backend().save_code_analysis_queue_state(items=items, order=order)

    def load_code_analysis_queue_state(self) -> Dict[str, Any]:
        return self._resolve_backend().load_code_analysis_queue_state()


knowledge_store = KnowledgeStore()
