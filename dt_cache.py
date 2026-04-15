import asyncio
import json
import os
import re
import tempfile
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from dt_client import DTClient, DTSettings

logger = logging.getLogger(__name__)


class PendingUpdateExistsError(Exception):
    pass


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


class CacheManager:
    def __init__(self, base_path: str = None, refresh_interval_seconds: int = None):
        self.base_path = base_path or get_dt_cache_path()
        self.refresh_interval_seconds = (
            int(os.getenv("DTVP_DT_CACHE_REFRESH_SECONDS", "60"))
            if refresh_interval_seconds is None
            else refresh_interval_seconds
        )
        self.lock = asyncio.Lock()
        self.pending_updates: List[Dict[str, Any]] = []
        self.active_project_uuids: Set[str] = set()
        self.project_query_cache: Dict[str, List[Dict[str, Any]]] = {}
        self.cache_meta: Dict[str, Any] = {"fully_cached": False, "last_refreshed_at": None}
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
        return _read_json(self._projects_meta_path(), {"fully_cached": False, "last_refreshed_at": None}) or {"fully_cached": False, "last_refreshed_at": None}

    def _save_projects_meta(self, meta: Dict[str, Any]) -> None:
        _atomic_write(self._projects_meta_path(), meta)

    def get_cache_status(self) -> Dict[str, Any]:
        projects = self._load_project_cache(self._projects_path(), []) or []
        pending = self._load_pending_updates()
        active = list(self.active_project_uuids)

        findings_dir = os.path.join(self.base_path, "findings")
        boms_dir = os.path.join(self.base_path, "boms")
        analysis_dir = os.path.join(self.base_path, "analysis")

        cached_findings = len([f for f in os.listdir(findings_dir) if f.endswith(".json")]) if os.path.isdir(findings_dir) else 0
        cached_boms = len([f for f in os.listdir(boms_dir) if f.endswith(".json")]) if os.path.isdir(boms_dir) else 0
        cached_analyses = len([f for f in os.listdir(analysis_dir) if f.endswith(".json")]) if os.path.isdir(analysis_dir) else 0

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
        return os.path.join(self.base_path, "boms", f"{_safe_filename(project_uuid)}.json")

    def _analysis_path(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> str:
        key = "__".join(
            [_safe_filename(project_uuid), _safe_filename(component_uuid), _safe_filename(vulnerability_uuid)]
        )
        return os.path.join(self.base_path, "analysis", f"{key}.json")

    def _load_pending_updates(self) -> List[Dict[str, Any]]:
        return _read_json(self._pending_path(), []) or []

    def _save_pending_updates(self, pending: List[Dict[str, Any]]) -> None:
        _atomic_write(self._pending_path(), pending)

    def _pending_update_key(self, payload: Dict[str, Any]) -> Optional[tuple[str, str, str]]:
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
        return _read_json(self._active_projects_path(), []) or []

    def _save_active_projects(self, uuids: List[str]) -> None:
        _atomic_write(self._active_projects_path(), sorted(set(uuids)))

    def reset(self, base_path: str = None) -> None:
        if base_path:
            self.base_path = base_path
        self.lock = asyncio.Lock()
        self.pending_updates = []
        self.active_project_uuids = set()
        self.project_query_cache = {}
        self.cache_meta = {"fully_cached": False, "last_refreshed_at": None}
        self._ensure_directories()

    def _save_project_cache(self, path: str, data: Any) -> None:
        _atomic_write(path, data)

    def _load_project_cache(self, path: str, default: Any = None) -> Any:
        return _read_json(path, default)

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
                async with DTClient(settings.api_url, api_key=settings.api_key) as client:
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

        if not refresh:
            async with self.lock:
                findings = self._load_project_cache(path, None)

        if findings is None:
            findings = await client.get_vulnerabilities(project_uuid, cve=None)
            async with self.lock:
                self._save_project_cache(path, findings)

        findings = self._overlay_local_analysis(project_uuid, findings)

        if cve:
            cve_upper = cve.upper()
            filtered = []
            for finding in findings:
                vuln = finding.get("vulnerability", {})
                if cve_upper in (vuln.get("vulnId") or "").upper() or cve_upper in (vuln.get("name") or "").upper():
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
        if not refresh:
            async with self.lock:
                analysis = self._load_project_cache(path, None)
        if analysis is None:
            analysis = await client.get_analysis(
                project_uuid=project_uuid,
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
            )
            async with self.lock:
                self._save_project_cache(path, analysis)
        return analysis

    def _overlay_local_analysis(
        self,
        project_uuid: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        pending = self._load_pending_updates()
        for finding in findings:
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if comp_uuid and vuln_uuid:
                analysis = self._load_project_cache(
                    self._analysis_path(project_uuid, comp_uuid, vuln_uuid), None
                )
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
        _atomic_write(
            self._analysis_path(project_uuid, component_uuid, vulnerability_uuid),
            analysis_data,
        )


cache_manager = CacheManager()
