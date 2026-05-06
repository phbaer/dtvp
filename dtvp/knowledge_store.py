import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def get_knowledge_store_path() -> str:
    return os.getenv("DTVP_KNOWLEDGE_STORE_PATH", "data/knowledge_store")


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


def _iter_alias_values(aliases: Any) -> Iterable[str]:
    if not aliases:
        return []
    values: list[str] = []
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str):
                values.append(alias)
                continue
            if isinstance(alias, dict):
                for raw in alias.values():
                    if isinstance(raw, str):
                        values.append(raw)
                    elif isinstance(raw, list):
                        values.extend(
                            str(item) for item in raw if isinstance(item, str)
                        )
    elif isinstance(aliases, dict):
        for raw in aliases.values():
            if isinstance(raw, str):
                values.append(raw)
            elif isinstance(raw, list):
                values.extend(str(item) for item in raw if isinstance(item, str))
    return values


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

    return sorted(aliases, key=_priority)[0]


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


class KnowledgeStore:
    def __init__(self, base_path: Optional[str] = None):
        self._base_path = base_path or get_knowledge_store_path()
        self._lock = RLock()
        self._cached_state: Optional[Dict[str, Any]] = None

    @property
    def base_path(self) -> str:
        return self._base_path

    @base_path.setter
    def base_path(self, value: str) -> None:
        self._base_path = value
        self._cached_state = None

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
            "path": self.base_path,
            "assessment_records": len(state.get("assessments", {})),
            "assessment_triplet_index_entries": len(
                state.get("assessment_triplet_index", {})
            ),
            "code_analysis_queue_items": len(queue_items),
            "code_analysis_queue_status_counts": terminal_status_counts,
        }

    def persist_assessment(
        self,
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        component_uuid = str(payload.get("component_uuid") or "").strip()
        if not component_uuid:
            return None

        vulnerability_data = vulnerability or {}
        canonical_vulnerability_id = select_canonical_vulnerability_id(
            vulnerability_data
        )
        if not canonical_vulnerability_id:
            fallback_vulnerability_uuid = str(
                payload.get("vulnerability_uuid") or ""
            ).strip()
            if not fallback_vulnerability_uuid:
                return None
            canonical_vulnerability_id = f"UUID:{fallback_vulnerability_uuid}"

        primary_key = assessment_primary_key(component_uuid, canonical_vulnerability_id)
        analysis = {
            "analysisState": payload.get("state") or "NOT_SET",
            "analysisDetails": payload.get("details") or "",
            "isSuppressed": bool(payload.get("suppressed", False)),
        }

        component_data = component or {}
        alias_set = collect_vulnerability_aliases(vulnerability_data)
        if canonical_vulnerability_id not in alias_set:
            alias_set.append(canonical_vulnerability_id)

        record = {
            "primary_key": primary_key,
            "component_uuid": component_uuid,
            "component_identity": _normalize_component_identity(component_data),
            "component_name": component_data.get("name"),
            "component_purl": component_data.get("purl"),
            "canonical_vulnerability_id": canonical_vulnerability_id,
            "vulnerability_aliases": sorted(alias_set),
            "vulnerability_uuid": payload.get("vulnerability_uuid"),
            "analysis": analysis,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        project_uuid = str(payload.get("project_uuid") or "").strip()
        vulnerability_uuid = str(payload.get("vulnerability_uuid") or "").strip()

        with self._lock:
            state = self._load_state()
            existing = state["assessments"].get(primary_key) or {}
            merged_aliases = sorted(
                {
                    *existing.get("vulnerability_aliases", []),
                    *record["vulnerability_aliases"],
                }
            )
            existing_triplets = (
                existing.get("triplets", [])
                if isinstance(existing.get("triplets"), list)
                else []
            )
            triplets = list(existing_triplets)

            if project_uuid and vulnerability_uuid:
                triplet = {
                    "project_uuid": project_uuid,
                    "component_uuid": component_uuid,
                    "vulnerability_uuid": vulnerability_uuid,
                }
                if triplet not in triplets:
                    triplets.append(triplet)
                state["assessment_triplet_index"][
                    assessment_triplet_key(
                        project_uuid, component_uuid, vulnerability_uuid
                    )
                ] = primary_key

            record.update(
                {
                    "component_identity": record["component_identity"]
                    or existing.get("component_identity", ""),
                    "component_name": record["component_name"]
                    or existing.get("component_name"),
                    "component_purl": record["component_purl"]
                    or existing.get("component_purl"),
                    "vulnerability_aliases": merged_aliases,
                    "triplets": triplets,
                }
            )
            state["assessments"][primary_key] = record
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
        component_data = component or {}
        vulnerability_data = vulnerability or {}
        component_uuid = str(component_data.get("uuid") or "").strip()
        canonical_vulnerability_id = select_canonical_vulnerability_id(
            vulnerability_data
        )

        with self._lock:
            state = self._load_state()
            if component_uuid and canonical_vulnerability_id:
                primary_key = assessment_primary_key(
                    component_uuid, canonical_vulnerability_id
                )
                record = state["assessments"].get(primary_key)
                if isinstance(record, dict):
                    return record.get("analysis")

            component_identity = _normalize_component_identity(component_data)
            aliases = set(collect_vulnerability_aliases(vulnerability_data))
            if canonical_vulnerability_id:
                aliases.add(canonical_vulnerability_id)
            for record in state["assessments"].values():
                if not isinstance(record, dict):
                    continue
                if component_identity and component_identity != record.get(
                    "component_identity"
                ):
                    continue
                if aliases and not aliases.intersection(
                    set(record.get("vulnerability_aliases", []))
                ):
                    continue
                return record.get("analysis")
        return None

    def save_code_analysis_queue_state(
        self,
        *,
        items: Dict[str, Any],
        order: list[str],
    ) -> None:
        serialized_items = {}
        for queue_id, item in items.items():
            if hasattr(item, "model_dump"):
                serialized_items[queue_id] = item.model_dump()
            elif isinstance(item, dict):
                serialized_items[queue_id] = dict(item)

        with self._lock:
            state = self._load_state()
            state["code_analysis_queue"] = {
                "items": serialized_items,
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


knowledge_store = KnowledgeStore()
