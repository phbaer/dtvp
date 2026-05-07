import asyncio
import json
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .dt_client import DTClient, DTSettings
from .knowledge_store import knowledge_store
from .logic import RE_SCORE

logger = logging.getLogger(__name__)


class PendingUpdateExistsError(Exception):
    pass


class KnowledgeStoreWriteBuffer:
    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def enqueue(
        self,
        key: Tuple[str, str, str],
        *,
        payload: Dict[str, Any],
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._entries[key] = {
            "payload": dict(payload),
            "component": dict(component or {}),
            "vulnerability": dict(vulnerability or {}),
        }

    def drain(self) -> List[Tuple[Tuple[str, str, str], Dict[str, Any]]]:
        drained = list(self._entries.items())
        self._entries = {}
        return drained

    def requeue(self, key: Tuple[str, str, str], entry: Dict[str, Any]) -> None:
        self._entries[key] = entry

    def reset(self) -> None:
        self._entries = {}


def get_dt_cache_path() -> str:
    return os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache")


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
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
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
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to read cache file %s: %s", path, exc)
        return default


def _normalize_analysis_details(details: Optional[str]) -> str:
    if not isinstance(details, str):
        return ""
    return details.strip()


def _get_analysis_details(analysis: Optional[Dict[str, Any]]) -> str:
    if not analysis:
        return ""
    return _normalize_analysis_details(
        analysis.get("analysisDetails") or analysis.get("analysis_details")
    )


def _get_analysis_state(analysis: Optional[Dict[str, Any]]) -> str:
    if not analysis:
        return "NOT_SET"
    return analysis.get("analysisState") or analysis.get("analysis_state") or "NOT_SET"


def _get_analysis_suppressed(analysis: Optional[Dict[str, Any]]) -> bool:
    if not analysis:
        return False
    if "isSuppressed" in analysis:
        return bool(analysis.get("isSuppressed"))
    return bool(analysis.get("is_suppressed", False))


def _has_meaningful_assessment(analysis: Optional[Dict[str, Any]]) -> bool:
    return bool(_get_analysis_details(analysis))


def _mark_assessment_for_review(analysis: Dict[str, Any]) -> Dict[str, Any]:
    details = _get_analysis_details(analysis)
    if not details:
        return {
            "analysisState": _get_analysis_state(analysis),
            "analysisDetails": "",
            "isSuppressed": _get_analysis_suppressed(analysis),
        }

    if "[Status: Pending Review]" not in details:
        details = f"{details}\n\n[Status: Pending Review]"

    return {
        "analysisState": _get_analysis_state(analysis),
        "analysisDetails": details,
        "isSuppressed": _get_analysis_suppressed(analysis),
    }


def _extract_threadmodel_score(analysis: Optional[Dict[str, Any]]) -> Optional[float]:
    details = _get_analysis_details(analysis)
    if not details:
        return None

    match = RE_SCORE.search(details)
    if not match:
        return None

    try:
        return float(match.group(1))
    except ValueError:
        return None


def _threadmodel_score_changed(
    previous_analysis: Optional[Dict[str, Any]],
    current_analysis: Optional[Dict[str, Any]],
) -> Tuple[bool, Optional[float], Optional[float]]:
    previous_score = _extract_threadmodel_score(previous_analysis)
    current_score = _extract_threadmodel_score(current_analysis)
    if previous_score is None or current_score is None:
        return False, previous_score, current_score
    return previous_score != current_score, previous_score, current_score


def _mark_assessment_for_review_with_threadmodel_change(
    analysis: Dict[str, Any],
    previous_score: Optional[float],
    current_score: Optional[float],
) -> Dict[str, Any]:
    marked = _mark_assessment_for_review(analysis)
    if (
        previous_score is None
        or current_score is None
        or previous_score == current_score
    ):
        return marked

    details = _get_analysis_details(marked)
    change_note = f"TM rescoring changed from {previous_score} to {current_score}."
    if change_note not in details:
        details = f"{details}\n\n{change_note}"
    marked["analysisDetails"] = details
    return marked


def _build_assessment_persistence_payload(
    *,
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
    analysis: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "project_uuid": project_uuid,
        "component_uuid": component_uuid,
        "vulnerability_uuid": vulnerability_uuid,
        "state": _get_analysis_state(analysis),
        "details": _get_analysis_details(analysis),
        "suppressed": _get_analysis_suppressed(analysis),
    }


def _component_cache_identity(component: Dict[str, Any]) -> Optional[str]:
    purl = (component.get("purl") or "").strip().lower()
    if purl:
        return re.sub(r"@[^?]+", "", purl, count=1)

    name = (component.get("name") or "").strip().lower()
    if name:
        return name

    return None


def _vulnerability_cache_identity(
    vulnerability: Dict[str, Any],
) -> Optional[Tuple[str, ...]]:
    identifiers: List[str] = []

    vuln_id = (vulnerability.get("vulnId") or "").strip().upper()
    if vuln_id:
        identifiers.append(vuln_id)

    name = (vulnerability.get("name") or "").strip().upper()
    if name and name not in identifiers:
        identifiers.append(name)

    for alias_obj in vulnerability.get("aliases", []) or []:
        if not isinstance(alias_obj, dict):
            continue
        for value in alias_obj.values():
            if not isinstance(value, str):
                continue
            normalized = value.strip().upper()
            if normalized and normalized not in identifiers:
                identifiers.append(normalized)

    if not identifiers:
        return None

    return tuple(sorted(identifiers))


class CacheManager:
    def __init__(
        self,
        base_path: str = None,
        refresh_interval_seconds: int = None,
        knowledge_store_flush_interval_seconds: int = None,
    ):
        self.base_path = base_path or get_dt_cache_path()
        self.refresh_interval_seconds = (
            int(os.getenv("DTVP_DT_CACHE_REFRESH_SECONDS", "60"))
            if refresh_interval_seconds is None
            else refresh_interval_seconds
        )
        self.knowledge_store_flush_interval_seconds = (
            int(os.getenv("DTVP_KNOWLEDGE_STORE_WRITE_FLUSH_INTERVAL_SECONDS", "1"))
            if knowledge_store_flush_interval_seconds is None
            else knowledge_store_flush_interval_seconds
        )
        self.lock = asyncio.Lock()
        self.pending_updates: List[Dict[str, Any]] = []
        self.active_project_uuids: Set[str] = set()
        self.project_query_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._knowledge_store_write_buffer = KnowledgeStoreWriteBuffer()
        self.cache_meta: Dict[str, Any] = {
            "fully_cached": False,
            "last_refreshed_at": None,
        }
        self._memory_cache: Dict[str, Any] = {}
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        os.makedirs(self.base_path, exist_ok=True)
        for name in ["findings", "project_vulnerabilities", "boms", "analysis"]:
            os.makedirs(os.path.join(self.base_path, name), exist_ok=True)

    def _projects_path(self) -> str:
        return os.path.join(self.base_path, "projects.json")

    def _pending_path(self) -> str:
        return os.path.join(self.base_path, "pending_updates.json")

    def _active_projects_path(self) -> str:
        return os.path.join(self.base_path, "active_projects.json")

    def _findings_path(self, project_uuid: str) -> str:
        return os.path.join(
            self.base_path, "findings", f"{_safe_filename(project_uuid)}.json"
        )

    def _projects_meta_path(self) -> str:
        return os.path.join(self.base_path, "projects_meta.json")

    def _load_projects_meta(self) -> Dict[str, Any]:
        return self._load_cache_file(
            self._projects_meta_path(),
            {"fully_cached": False, "last_refreshed_at": None},
        ) or {"fully_cached": False, "last_refreshed_at": None}

    def _save_projects_meta(self, meta: Dict[str, Any]) -> None:
        self._save_cache_file(self._projects_meta_path(), meta, touch_meta=False)

    def get_cache_status(self) -> Dict[str, Any]:
        projects = self._load_project_cache(self._projects_path(), []) or []
        pending = self._load_pending_updates()
        active = list(self.active_project_uuids)

        findings_dir = os.path.join(self.base_path, "findings")
        boms_dir = os.path.join(self.base_path, "boms")
        analysis_dir = os.path.join(self.base_path, "analysis")

        cached_findings = (
            len([f for f in os.listdir(findings_dir) if f.endswith(".json")])
            if os.path.isdir(findings_dir)
            else 0
        )
        cached_boms = (
            len([f for f in os.listdir(boms_dir) if f.endswith(".json")])
            if os.path.isdir(boms_dir)
            else 0
        )
        cached_analyses = (
            len([f for f in os.listdir(analysis_dir) if f.endswith(".json")])
            if os.path.isdir(analysis_dir)
            else 0
        )

        return {
            "fully_cached": self.cache_meta.get("fully_cached", False),
            "last_refreshed_at": self.cache_meta.get("last_refreshed_at"),
            "projects": len(projects),
            "active_projects": len(active),
            "cached_findings": cached_findings,
            "cached_boms": cached_boms,
            "cached_analyses": cached_analyses,
            "pending_updates": len(pending),
        }

    def _touch_cache_meta(self) -> None:
        self.cache_meta["last_refreshed_at"] = datetime.now(timezone.utc).isoformat()
        self._save_projects_meta(self.cache_meta)

    def _project_vulns_path(self, project_uuid: str) -> str:
        return os.path.join(
            self.base_path,
            "project_vulnerabilities",
            f"{_safe_filename(project_uuid)}.json",
        )

    def _bom_path(self, project_uuid: str) -> str:
        return os.path.join(
            self.base_path, "boms", f"{_safe_filename(project_uuid)}.json"
        )

    def _analysis_path(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> str:
        key = "__".join(
            [
                _safe_filename(project_uuid),
                _safe_filename(component_uuid),
                _safe_filename(vulnerability_uuid),
            ]
        )
        return os.path.join(self.base_path, "analysis", f"{key}.json")

    def _lookup_cached_finding(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        findings = self._load_project_cache(self._findings_path(project_uuid), []) or []
        for finding in findings:
            component = finding.get("component") or {}
            vulnerability = finding.get("vulnerability") or {}
            if (
                component.get("uuid") == component_uuid
                and vulnerability.get("uuid") == vulnerability_uuid
            ):
                return finding
        return None

    def _persist_analysis_to_knowledge_store(
        self,
        payload: Dict[str, Any],
        *,
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = self._pending_update_key(payload)
        if not key:
            return
        self._knowledge_store_write_buffer.enqueue(
            key,
            payload=payload,
            component=component,
            vulnerability=vulnerability,
        )

    def _flush_analysis_to_knowledge_store(
        self,
        payload: Dict[str, Any],
        *,
        component: Optional[Dict[str, Any]] = None,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> None:
        project_uuid = payload.get("project_uuid")
        component_uuid = payload.get("component_uuid")
        vulnerability_uuid = payload.get("vulnerability_uuid")

        cached_finding = None
        if project_uuid and component_uuid and vulnerability_uuid:
            cached_finding = self._lookup_cached_finding(
                str(project_uuid),
                str(component_uuid),
                str(vulnerability_uuid),
            )

        knowledge_store.persist_assessment(
            payload=payload,
            component=component or ((cached_finding or {}).get("component") or {}),
            vulnerability=vulnerability
            or ((cached_finding or {}).get("vulnerability") or {}),
        )

    def flush_queued_knowledge_store_writes(self) -> int:
        queued_items = self._knowledge_store_write_buffer.drain()
        if not queued_items:
            return 0

        flushed = 0
        for key, entry in queued_items:
            try:
                self._flush_analysis_to_knowledge_store(
                    entry.get("payload", {}),
                    component=entry.get("component") or {},
                    vulnerability=entry.get("vulnerability") or {},
                )
                flushed += 1
            except Exception as exc:
                logger.warning(
                    "Failed to flush knowledge-store write %s: %s",
                    key,
                    exc,
                )
                self._knowledge_store_write_buffer.requeue(key, entry)
        return flushed

    async def background_knowledge_store_write_loop(self) -> None:
        try:
            while True:
                self.flush_queued_knowledge_store_writes()
                await asyncio.sleep(self.knowledge_store_flush_interval_seconds)
        except asyncio.CancelledError:
            self.flush_queued_knowledge_store_writes()
            raise

    def _load_pending_updates(self) -> List[Dict[str, Any]]:
        return self._load_cache_file(self._pending_path(), []) or []

    def _save_pending_updates(self, pending: List[Dict[str, Any]]) -> None:
        self._save_cache_file(self._pending_path(), pending, touch_meta=False)

    def _pending_update_key(
        self, payload: Dict[str, Any]
    ) -> Optional[tuple[str, str, str]]:
        project_uuid = payload.get("project_uuid")
        component_uuid = payload.get("component_uuid")
        vulnerability_uuid = payload.get("vulnerability_uuid")
        if not (project_uuid and component_uuid and vulnerability_uuid):
            return None
        return (project_uuid, component_uuid, vulnerability_uuid)

    def _has_pending_update(self, payload: Dict[str, Any]) -> bool:
        key = self._pending_update_key(payload)
        if not key:
            return False
        for entry in self._load_pending_updates():
            pending_key = self._pending_update_key(entry.get("payload", {}))
            if pending_key == key:
                return True
        return False

    def _load_active_projects(self) -> List[str]:
        return self._load_cache_file(self._active_projects_path(), []) or []

    def _save_active_projects(self, uuids: List[str]) -> None:
        self._save_cache_file(
            self._active_projects_path(), sorted(set(uuids)), touch_meta=False
        )

    def reset(self, base_path: str = None) -> None:
        if base_path:
            self.base_path = base_path
        self.lock = asyncio.Lock()
        self.pending_updates = []
        self.active_project_uuids = set()
        self.project_query_cache = {}
        self._knowledge_store_write_buffer.reset()
        self.cache_meta = {"fully_cached": False, "last_refreshed_at": None}
        self._memory_cache = {}
        self._ensure_directories()

    def _load_cache_file(self, path: str, default: Any = None) -> Any:
        if path in self._memory_cache:
            return self._memory_cache[path]

        data = _read_json(path, default)
        self._memory_cache[path] = data
        return data

    def _save_cache_file(self, path: str, data: Any, touch_meta: bool = True) -> None:
        _atomic_write(path, data)
        self._memory_cache[path] = data
        if touch_meta:
            self._touch_cache_meta()

    def _save_project_cache(self, path: str, data: Any) -> None:
        self._save_cache_file(path, data)

    def _load_project_cache(self, path: str, default: Any = None) -> Any:
        return self._load_cache_file(path, default)

    async def initialize(self) -> None:
        async with self.lock:
            self.pending_updates = self._load_pending_updates()
            self.active_project_uuids = set(self._load_active_projects())
            self.cache_meta = self._load_projects_meta()

        settings = DTSettings()
        try:
            async with DTClient(settings.api_url, api_key=settings.api_key) as client:
                await self.flush_pending_updates(client)
        except Exception as exc:
            logger.warning("Dependency-Track cache initialization failed: %s", exc)

    async def background_sync_loop(self) -> None:
        settings = DTSettings()
        while True:
            try:
                async with DTClient(
                    settings.api_url, api_key=settings.api_key
                ) as client:
                    await self.flush_pending_updates(client)
                    await self._refresh_project_list(client)
                    await self._refresh_active_projects(client)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Cache background sync failed: %s", exc)
            await asyncio.sleep(self.refresh_interval_seconds)

    async def _refresh_project_list(self, client: DTClient) -> None:
        try:
            projects = await client.get_projects("")
            async with self.lock:
                self._save_project_cache(self._projects_path(), projects)
                self.cache_meta["fully_cached"] = True
                self._touch_cache_meta()
        except Exception as exc:
            logger.debug("Failed to refresh project list: %s", exc)

    async def _refresh_active_projects(self, client: DTClient) -> None:
        active = list(self.active_project_uuids)
        for project_uuid in active:
            try:
                await self.refresh_project(project_uuid, client)
            except Exception as exc:
                logger.debug("Failed to refresh project %s: %s", project_uuid, exc)

    async def refresh_project(self, project_uuid: str, client: DTClient) -> None:
        await self.get_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_project_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_bom(client, project_uuid, refresh=True)
        async with self.lock:
            self._touch_cache_meta()

    async def record_project_access(self, project_uuid: str) -> None:
        async with self.lock:
            self.active_project_uuids.add(project_uuid)
            self._save_active_projects(list(self.active_project_uuids))

    async def get_projects(
        self, client: DTClient, name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        async with self.lock:
            projects = self._load_project_cache(self._projects_path(), []) or []
            projects_meta = self.cache_meta

        if not name:
            projects = await client.get_projects("")
            async with self.lock:
                self._save_project_cache(self._projects_path(), projects)
                self.cache_meta["fully_cached"] = True
                self._touch_cache_meta()
            return projects

        if projects_meta.get("fully_cached"):
            return [
                project
                for project in projects
                if name.lower() in (project.get("name", "") or "").lower()
            ]

        if name in self.project_query_cache:
            return self.project_query_cache[name]

        results = await client.get_projects(name)
        self.project_query_cache[name] = results
        if results:
            async with self.lock:
                current = self._load_project_cache(self._projects_path(), []) or []
                existing_uuids = {p.get("uuid") for p in current if p.get("uuid")}
                merged = list(current)
                for project in results:
                    if project.get("uuid") not in existing_uuids:
                        merged.append(project)
                self._save_project_cache(self._projects_path(), merged)
        return results

    async def get_vulnerabilities(
        self,
        client: DTClient,
        project_uuid: str,
        cve: Optional[str] = None,
        refresh: bool = False,
    ) -> List[Dict[str, Any]]:
        await self.record_project_access(project_uuid)
        path = self._findings_path(project_uuid)
        findings = None
        previous_findings = None

        if not refresh:
            async with self.lock:
                findings = self._load_project_cache(path, None)

        if findings is None:
            async with self.lock:
                previous_findings = self._load_project_cache(path, None)
            findings = await client.get_vulnerabilities(project_uuid, cve=None)
            findings = self._restore_recreated_finding_assessments(
                project_uuid,
                findings,
                previous_findings or [],
            )
            findings = self._overlay_local_analysis(project_uuid, findings)
            async with self.lock:
                self._save_project_cache(path, findings)
        else:
            findings = self._overlay_local_analysis(project_uuid, findings)

        if cve:
            cve_upper = cve.upper()
            filtered = []
            for finding in findings:
                vuln = finding.get("vulnerability", {})
                if (
                    cve_upper in (vuln.get("vulnId") or "").upper()
                    or cve_upper in (vuln.get("name") or "").upper()
                ):
                    filtered.append(finding)
                else:
                    for alias_obj in vuln.get("aliases", []):
                        for alias in alias_obj.values():
                            if isinstance(alias, str) and cve_upper in alias.upper():
                                filtered.append(finding)
                                break
                        else:
                            continue
                        break
            findings = filtered

        return findings

    async def get_project_vulnerabilities(
        self,
        client: DTClient,
        project_uuid: str,
        refresh: bool = False,
    ) -> List[Dict[str, Any]]:
        path = self._project_vulns_path(project_uuid)
        vulns = None
        if not refresh:
            async with self.lock:
                vulns = self._load_project_cache(path, None)
        if vulns is None:
            vulns = await client.get_project_vulnerabilities(project_uuid)
            async with self.lock:
                self._save_project_cache(path, vulns)
        return vulns

    async def get_bom(
        self,
        client: DTClient,
        project_uuid: str,
        refresh: bool = False,
    ) -> Optional[Dict[str, Any]]:
        await self.record_project_access(project_uuid)
        path = self._bom_path(project_uuid)
        bom = None
        if not refresh:
            async with self.lock:
                bom = self._load_project_cache(path, None)
        if bom is None:
            bom = await client.get_bom(project_uuid)
            async with self.lock:
                self._save_project_cache(path, bom)
        return bom

    async def get_analysis(
        self,
        client: DTClient,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        refresh: bool = False,
    ) -> Optional[Dict[str, Any]]:
        path = self._analysis_path(project_uuid, component_uuid, vulnerability_uuid)
        analysis = None
        cached_analysis = None
        if not refresh:
            async with self.lock:
                analysis = self._load_project_cache(path, None)
        if analysis is None:
            async with self.lock:
                cached_analysis = self._load_project_cache(path, None)
            analysis = await client.get_analysis(
                project_uuid=project_uuid,
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
            )
            if _get_analysis_details(analysis):
                self._persist_analysis_to_knowledge_store(
                    _build_assessment_persistence_payload(
                        project_uuid=project_uuid,
                        component_uuid=component_uuid,
                        vulnerability_uuid=vulnerability_uuid,
                        analysis=analysis,
                    )
                )
            analysis = self._merge_blank_source_analysis(
                cached_analysis,
                analysis,
            )
            async with self.lock:
                self._save_project_cache(path, analysis)
        return analysis

    def _finding_cache_identity(
        self, finding: Dict[str, Any]
    ) -> Optional[Tuple[str, Tuple[str, ...]]]:
        component = finding.get("component", {}) or {}
        vulnerability = finding.get("vulnerability", {}) or {}

        component_identity = _component_cache_identity(component)
        vulnerability_identity = _vulnerability_cache_identity(vulnerability)
        if not component_identity or not vulnerability_identity:
            return None

        return component_identity, vulnerability_identity

    def _finding_analysis_key(
        self, project_uuid: str, finding: Dict[str, Any]
    ) -> Optional[Tuple[str, str, str]]:
        component_uuid = (finding.get("component", {}) or {}).get("uuid")
        vulnerability_uuid = (finding.get("vulnerability", {}) or {}).get("uuid")
        if not component_uuid or not vulnerability_uuid:
            return None
        return project_uuid, component_uuid, vulnerability_uuid

    def _merge_blank_source_analysis(
        self,
        cached_analysis: Optional[Dict[str, Any]],
        source_analysis: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if _get_analysis_details(source_analysis):
            return source_analysis

        if not _has_meaningful_assessment(cached_analysis):
            return source_analysis

        return _mark_assessment_for_review(cached_analysis)

    def _restore_recreated_finding_assessments(
        self,
        project_uuid: str,
        findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings or not previous_findings:
            return findings

        previous_candidates: Dict[
            Tuple[str, Tuple[str, ...]],
            List[Tuple[Tuple[str, str, str], Dict[str, Any]]],
        ] = {}

        for previous_finding in previous_findings:
            identity = self._finding_cache_identity(previous_finding)
            analysis_key = self._finding_analysis_key(project_uuid, previous_finding)
            if not identity or not analysis_key:
                continue

            previous_analysis = self._load_project_cache(
                self._analysis_path(*analysis_key),
                previous_finding.get("analysis"),
            )
            if not _has_meaningful_assessment(previous_analysis):
                continue

            previous_candidates.setdefault(identity, []).append(
                (analysis_key, previous_analysis)
            )

        store_analyses = knowledge_store.get_assessments_for_findings(
            findings=[
                (
                    finding.get("component") or {},
                    finding.get("vulnerability") or {},
                )
                for finding in findings
            ]
        )

        for index, finding in enumerate(findings):
            source_analysis = finding.get("analysis") or {}
            identity = self._finding_cache_identity(finding)
            analysis_key = self._finding_analysis_key(project_uuid, finding)
            if not analysis_key:
                continue

            current_path = self._analysis_path(*analysis_key)
            current_cached_analysis = self._load_project_cache(current_path, None)
            store_analysis = (
                store_analyses[index] if index < len(store_analyses) else None
            )

            if _get_analysis_details(source_analysis):
                self._persist_analysis_to_knowledge_store(
                    _build_assessment_persistence_payload(
                        project_uuid=project_uuid,
                        component_uuid=analysis_key[1],
                        vulnerability_uuid=analysis_key[2],
                        analysis=source_analysis,
                    ),
                    component=(finding.get("component") or {}),
                    vulnerability=(finding.get("vulnerability") or {}),
                )
                previous_analysis = (
                    store_analysis
                    if _has_meaningful_assessment(store_analysis)
                    else current_cached_analysis
                    if _has_meaningful_assessment(current_cached_analysis)
                    else None
                )
                if previous_analysis is None and identity:
                    candidates = previous_candidates.get(identity, [])
                    if len(candidates) == 1:
                        _, previous_analysis = candidates[0]

                if previous_analysis:
                    changed, previous_score, current_score = _threadmodel_score_changed(
                        previous_analysis, source_analysis
                    )
                    if changed:
                        marked = _mark_assessment_for_review_with_threadmodel_change(
                            source_analysis, previous_score, current_score
                        )
                        self._save_project_cache(current_path, marked)
                        finding["analysis"] = marked
                        continue
                continue

            if _has_meaningful_assessment(current_cached_analysis):
                finding["analysis"] = _mark_assessment_for_review(
                    current_cached_analysis
                )
                continue

            if _has_meaningful_assessment(store_analysis):
                preserved_from_store = _mark_assessment_for_review(store_analysis)
                self._save_project_cache(current_path, preserved_from_store)
                self._persist_analysis_to_knowledge_store(
                    _build_assessment_persistence_payload(
                        project_uuid=project_uuid,
                        component_uuid=analysis_key[1],
                        vulnerability_uuid=analysis_key[2],
                        analysis=preserved_from_store,
                    ),
                    component=(finding.get("component") or {}),
                    vulnerability=(finding.get("vulnerability") or {}),
                )
                finding["analysis"] = preserved_from_store
                continue

            if not identity:
                continue

            candidates = previous_candidates.get(identity, [])
            if len(candidates) != 1:
                continue

            _, previous_analysis = candidates[0]
            preserved_analysis = _mark_assessment_for_review(previous_analysis)
            self._save_project_cache(current_path, preserved_analysis)
            self._persist_analysis_to_knowledge_store(
                _build_assessment_persistence_payload(
                    project_uuid=project_uuid,
                    component_uuid=analysis_key[1],
                    vulnerability_uuid=analysis_key[2],
                    analysis=preserved_analysis,
                ),
                component=(finding.get("component") or {}),
                vulnerability=(finding.get("vulnerability") or {}),
            )
            finding["analysis"] = preserved_analysis

        return findings

    def _overlay_local_analysis(
        self,
        project_uuid: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        pending = self._load_pending_updates()
        store_lookup_indices: List[int] = []
        store_lookup_findings: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        current_cached_analyses: Dict[int, Optional[Dict[str, Any]]] = {}

        for index, finding in enumerate(findings):
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if not comp_uuid or not vuln_uuid:
                continue
            analysis = self._load_project_cache(
                self._analysis_path(project_uuid, comp_uuid, vuln_uuid), None
            )
            current_cached_analyses[index] = analysis
            if analysis is None:
                store_lookup_indices.append(index)
                store_lookup_findings.append((component, vulnerability))

        store_lookup_results = knowledge_store.get_assessments_for_findings(
            findings=store_lookup_findings
        )
        store_analyses_by_index = {
            finding_index: store_lookup_results[result_index]
            for result_index, finding_index in enumerate(store_lookup_indices)
            if result_index < len(store_lookup_results)
        }

        for finding_index, finding in enumerate(findings):
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if comp_uuid and vuln_uuid:
                analysis_path = self._analysis_path(project_uuid, comp_uuid, vuln_uuid)
                analysis = current_cached_analyses.get(finding_index)
                from_store = False
                if analysis is None:
                    analysis = store_analyses_by_index.get(finding_index)
                    from_store = analysis is not None
                if analysis is None:
                    for pending_update in pending:
                        payload = pending_update.get("payload", {})
                        if (
                            payload.get("project_uuid") == project_uuid
                            and payload.get("component_uuid") == comp_uuid
                            and payload.get("vulnerability_uuid") == vuln_uuid
                        ):
                            analysis = {
                                "analysisState": payload.get("state"),
                                "analysisDetails": payload.get("details"),
                                "isSuppressed": payload.get("suppressed", False),
                            }
                            break
                if analysis is not None:
                    if from_store:
                        self._save_project_cache(analysis_path, analysis)
                    if not from_store and _get_analysis_details(analysis):
                        self._persist_analysis_to_knowledge_store(
                            _build_assessment_persistence_payload(
                                project_uuid=project_uuid,
                                component_uuid=comp_uuid,
                                vulnerability_uuid=vuln_uuid,
                                analysis=analysis,
                            ),
                            component=component,
                            vulnerability=vulnerability,
                        )
                    finding["analysis"] = analysis
        return findings

    async def queue_analysis_update(
        self, payload: Dict[str, Any], replace: bool = False
    ) -> str:
        update_id = str(uuid.uuid4())
        entry = {
            "id": update_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        async with self.lock:
            pending = self._load_pending_updates()
            if self._has_pending_update(payload):
                if not replace:
                    raise PendingUpdateExistsError(
                        "A pending update already exists for this finding."
                    )
                # Remove old pending entry for the same key
                key = self._pending_update_key(payload)
                pending = [
                    e
                    for e in pending
                    if self._pending_update_key(e.get("payload", {})) != key
                ]
            pending.append(entry)
            self._save_pending_updates(pending)
            self._save_local_analysis(payload)
        return update_id

    async def remove_pending_update(self, update_id: str) -> None:
        async with self.lock:
            pending = self._load_pending_updates()
            pending = [entry for entry in pending if entry.get("id") != update_id]
            self._save_pending_updates(pending)

    async def flush_pending_updates(self, client: DTClient) -> None:
        async with self.lock:
            pending = self._load_pending_updates()

        if not pending:
            return

        remaining = []
        for entry in pending:
            payload = entry.get("payload", {})
            update_id = entry.get("id")
            try:
                await client.update_analysis(**payload)
                self._save_local_analysis(payload)
            except Exception as exc:
                logger.warning(
                    "Failed to flush pending DT update %s: %s",
                    update_id,
                    exc,
                )
                remaining.append(entry)

        async with self.lock:
            self._save_pending_updates(remaining)

    def _save_local_analysis(self, payload: Dict[str, Any]) -> None:
        project_uuid = payload.get("project_uuid")
        component_uuid = payload.get("component_uuid")
        vulnerability_uuid = payload.get("vulnerability_uuid")
        if not (project_uuid and component_uuid and vulnerability_uuid):
            return

        analysis_data = {
            "analysisState": payload.get("state"),
            "analysisDetails": payload.get("details"),
            "isSuppressed": payload.get("suppressed", False),
        }
        self._save_project_cache(
            self._analysis_path(project_uuid, component_uuid, vulnerability_uuid),
            analysis_data,
        )
        self._persist_analysis_to_knowledge_store(payload)


cache_manager = CacheManager()
