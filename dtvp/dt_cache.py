import asyncio
import copy
import json
import os
import re
import tempfile
import threading
import time
import logging
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import httpx

from .assessment_outbox_services import (
    AssessmentOutboxConflictError,
    AssessmentOutboxStore,
    AssessmentKey,
    assessment_key,
    get_assessment_outbox_path,
)
from .artifact_store import ArtifactStore
from .catalog_repository import (
    get_latest_snapshot_for_source_project,
    list_source_catalog_projects,
)
from .catalog_repository import (
    get_current_assessment,
    get_source_finding_analysis,
    persist_assessment_revisions,
)
from .source_import_service import _safe_base_url
from .source_connectors.dependency_track import DependencyTrackConnector
from .snapshot_projection import (
    project_advisories,
    project_bom,
    project_findings,
)
from .source_import_service import discover_source_projects, import_source_scope
from .dt_client import DTClient, DTSettings

logger = logging.getLogger(__name__)
CACHE_STATUS_TTL_SECONDS = 5.0


class PendingUpdateExistsError(Exception):
    pass


def _is_missing_finding_error(exc: Exception) -> bool:
    return (
        isinstance(exc, httpx.HTTPStatusError)
        and exc.response is not None
        and exc.response.status_code == 404
    )


def get_dt_cache_path() -> str:
    return os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache")


def _positive_int_env(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


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
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
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
    def __init__(
        self,
        base_path: str = None,
        refresh_interval_seconds: int = None,
        project_list_ttl_seconds: int = None,
        active_project_ttl_seconds: int = None,
        active_project_limit: int = None,
        memory_cache_max_entries: int = None,
        project_query_cache_max_entries: int = None,
    ):
        self.base_path = base_path or get_dt_cache_path()
        self.refresh_interval_seconds = (
            int(os.getenv("DTVP_DT_CACHE_REFRESH_SECONDS", "60"))
            if refresh_interval_seconds is None
            else refresh_interval_seconds
        )
        self.project_list_ttl_seconds = (
            _positive_int_env("DTVP_DT_PROJECT_LIST_TTL_SECONDS", 30, minimum=0)
            if project_list_ttl_seconds is None
            else max(0, project_list_ttl_seconds)
        )
        self.active_project_ttl_seconds = (
            _positive_int_env(
                "DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS",
                900,
                minimum=60,
            )
            if active_project_ttl_seconds is None
            else max(60, active_project_ttl_seconds)
        )
        self.active_project_limit = (
            _positive_int_env("DTVP_DT_ACTIVE_PROJECT_LIMIT", 8)
            if active_project_limit is None
            else max(1, active_project_limit)
        )
        self.memory_cache_max_entries = (
            _positive_int_env("DTVP_DT_MEMORY_CACHE_MAX_ENTRIES", 256)
            if memory_cache_max_entries is None
            else max(1, memory_cache_max_entries)
        )
        self.project_query_cache_max_entries = (
            _positive_int_env("DTVP_DT_PROJECT_QUERY_CACHE_MAX_ENTRIES", 128)
            if project_query_cache_max_entries is None
            else max(1, project_query_cache_max_entries)
        )
        self.lock = asyncio.Lock()
        self.pending_updates: List[Dict[str, Any]] = []
        self.active_project_uuids: Set[str] = set()
        self._active_project_last_access: Dict[str, float] = {}
        self.project_query_cache: OrderedDict[str, List[Dict[str, Any]]] = (
            OrderedDict()
        )
        self._cache_meta_lock = threading.RLock()
        self.cache_meta: Dict[str, Any] = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
            "project_revisions": {},
        }
        self._memory_cache: OrderedDict[str, Any] = OrderedDict()
        self._memory_cache_lock = threading.RLock()
        self._dirty_memory_paths: Dict[str, int] = {}
        self._inflight_fetches: Dict[Tuple[str, ...], asyncio.Task[Any]] = {}
        self._write_state_lock = threading.RLock()
        self._write_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="dtvp-cache-writer",
        )
        self._last_write_future: Future[Any] | None = None
        self._write_errors: List[BaseException] = []
        self._cache_status_lock = threading.RLock()
        self._cache_status_snapshot: Optional[Dict[str, Any]] = None
        self._cache_status_expires_at = 0.0
        self._assessment_sync_lock = asyncio.Lock()
        self._assessment_sync_wakeup = asyncio.Event()
        self._legacy_assessments_migrated: Set[str] = set()
        self._ensure_directories()
        self.assessment_outbox = AssessmentOutboxStore(
            get_assessment_outbox_path(self.base_path),
            logger=logger,
        )
        self._import_legacy_pending_updates()

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
            {
                "fully_cached": False,
                "last_refreshed_at": None,
                "projects_refreshed_at": None,
                "revision": 0,
                "project_revisions": {},
            },
        ) or {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
            "project_revisions": {},
        }

    def _read_startup_cache_state(
        self,
    ) -> tuple[List[Dict[str, Any]], Dict[str, float], Dict[str, Any]]:
        meta_default = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
            "project_revisions": {},
        }
        pending = self._load_pending_updates()
        active = self._normalize_active_projects(
            _read_json(self._active_projects_path(), {})
        )
        meta = _read_json(self._projects_meta_path(), meta_default) or meta_default
        return pending, active, meta

    def _remember_startup_cache_state(
        self,
        pending: List[Dict[str, Any]],
        active: Dict[str, float],
        meta: Dict[str, Any],
    ) -> None:
        self._cache_memory_value(self._active_projects_path(), active)
        self._cache_memory_value(self._projects_meta_path(), meta)

    def _save_projects_meta(self, meta: Dict[str, Any]) -> None:
        # cache_meta is mutated in place, so an equality-based no-op check cannot
        # reliably detect its changes. Always persist an explicit metadata save.
        self._save_cache_file(
            self._projects_meta_path(),
            copy.deepcopy(meta),
            touch_meta=False,
            force=True,
        )

    def get_cache_status(self) -> Dict[str, Any]:
        with self._cache_status_lock:
            now = time.monotonic()
            if (
                self._cache_status_snapshot is not None
                and now < self._cache_status_expires_at
            ):
                return copy.deepcopy(self._cache_status_snapshot)

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

            snapshot = {
                "fully_cached": self.cache_meta.get("fully_cached", False),
                "last_refreshed_at": self.cache_meta.get("last_refreshed_at"),
                "projects": len(projects),
                "active_projects": len(active),
                "cached_findings": cached_findings,
                "cached_boms": cached_boms,
                "cached_analyses": cached_analyses,
                "pending_updates": len(pending),
            }
            self._cache_status_snapshot = snapshot
            self._cache_status_expires_at = now + CACHE_STATUS_TTL_SECONDS
            return copy.deepcopy(snapshot)

    def get_runtime_stats(self) -> Dict[str, Any]:
        """Return cheap in-process cache pressure counters for diagnostics."""
        with self._memory_cache_lock:
            memory_entries = len(self._memory_cache)
            dirty_entries = len(self._dirty_memory_paths)
        with self._write_state_lock:
            last_write = self._last_write_future
            write_errors = len(self._write_errors)
        return {
            "memory_entries": memory_entries,
            "memory_entry_limit": self.memory_cache_max_entries,
            "dirty_entries": dirty_entries,
            "write_pending": bool(last_write and not last_write.done()),
            "write_errors": write_errors,
            "named_project_queries": len(self.project_query_cache),
            "named_project_query_limit": self.project_query_cache_max_entries,
            "active_projects": len(self.active_project_uuids),
            "active_project_limit": self.active_project_limit,
        }

    def get_cached_project_versions(self) -> List[Dict[str, Any]]:
        projects = list_source_catalog_projects()
        if projects:
            return projects
        # Before the DTVP catalog migration, the local project list was the
        # only source of project identities. Keep it as a one-way fallback for
        # installations that have not imported their catalog yet.
        return self._load_project_cache(self._projects_path(), []) or []

    def get_cached_project_snapshot(
        self,
        project_uuid: str,
    ) -> Optional[
        Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]
    ]:
        record = get_latest_snapshot_for_source_project(project_uuid)
        if record is not None:
            try:
                snapshot = ArtifactStore().get_json(record["payload_sha256"])
                findings = project_findings(snapshot)
                project_vulnerabilities = project_advisories(snapshot)
                bom = project_bom(snapshot)
            except (OSError, ValueError):
                logger.exception("Could not read imported project snapshot %s", project_uuid)
                return None
        else:
            findings = self._load_project_cache(self._findings_path(project_uuid), None)
            if findings is None:
                return None
            project_vulnerabilities = self._load_project_cache(
                self._project_vulns_path(project_uuid), []
            ) or []
            bom = self._load_project_cache(self._bom_path(project_uuid), {}) or {}

        # Overlay locally stored assessments so callers (e.g. the automatic
        # code-analysis sweep) see the same analysis state as the live project
        # view. Without this, a vulnerability assessed in DTVP but whose cached
        # findings file predates that assessment still looks NOT_SET here and
        # would be incorrectly treated as "open" and re-queued for analysis.
        findings = self._overlay_local_analysis(project_uuid, findings)

        return findings, project_vulnerabilities, bom

    def _touch_cache_meta(
        self,
        *,
        project_uuids: Set[str] | None = None,
    ) -> None:
        self._invalidate_cache_status()
        with self._cache_meta_lock:
            self.cache_meta["last_refreshed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            self.cache_meta["revision"] = int(
                self.cache_meta.get("revision") or 0
            ) + 1
            project_revisions = self.cache_meta.setdefault("project_revisions", {})
            if not isinstance(project_revisions, dict):
                project_revisions = {}
                self.cache_meta["project_revisions"] = project_revisions
            for project_uuid in project_uuids or set():
                normalized_uuid = str(project_uuid or "").strip()
                if normalized_uuid:
                    project_revisions[normalized_uuid] = (
                        int(project_revisions.get(normalized_uuid) or 0) + 1
                    )
            self._save_projects_meta(self.cache_meta)

    def get_cache_revision(self) -> int:
        with self._cache_meta_lock:
            return int(self.cache_meta.get("revision") or 0)

    def get_grouped_cache_revision(
        self,
        *,
        name: str = "",
        versions: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """Return a stable revision limited to the grouped project's inputs."""
        selected_versions = versions
        if selected_versions is None:
            cached_versions = self._load_project_cache(self._projects_path(), []) or []
            normalized_name = str(name or "").strip().lower()
            selected_versions = [
                project
                for project in cached_versions
                if not normalized_name
                or str(project.get("name") or "").strip().lower()
                == normalized_name
            ]

        version_fingerprint = sorted(
            (
                str(project.get("uuid") or ""),
                str(project.get("name") or ""),
                str(project.get("version") or ""),
                str(project.get("lastBomImport") or ""),
                str(project.get("lastRiskScore") or ""),
                bool(project.get("active", True)),
            )
            for project in selected_versions
        )
        with self._cache_meta_lock:
            raw_project_revisions = self.cache_meta.get("project_revisions") or {}
            project_revisions = (
                raw_project_revisions
                if isinstance(raw_project_revisions, dict)
                else {}
            )
            revisions = [
                (project_uuid, int(project_revisions.get(project_uuid) or 0))
                for project_uuid, *_rest in version_fingerprint
                if project_uuid
            ]
        return {
            "versions": version_fingerprint,
            "project_revisions": revisions,
        }

    def _mark_project_list_refreshed(self) -> None:
        self.cache_meta["fully_cached"] = True
        self.cache_meta["projects_refreshed_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        self.project_query_cache.clear()

    def _invalidate_cache_status(self) -> None:
        with self._cache_status_lock:
            self._cache_status_snapshot = None
            self._cache_status_expires_at = 0.0

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
        return self.assessment_outbox.list_pending()

    def _import_legacy_pending_updates(self) -> None:
        legacy_pending = _read_json(self._pending_path(), []) or []
        imported = self.assessment_outbox.import_legacy(legacy_pending)
        if imported:
            logger.info(
                "Imported %d legacy pending assessment update(s) into SQLite",
                imported,
            )

    def _normalize_active_projects(self, value: Any) -> Dict[str, float]:
        now = time.time()
        if isinstance(value, list):
            return {
                str(project_uuid): now
                for project_uuid in value
                if str(project_uuid or "").strip()
            }
        if not isinstance(value, dict):
            return {}

        normalized: Dict[str, float] = {}
        for raw_uuid, raw_accessed_at in value.items():
            project_uuid = str(raw_uuid or "").strip()
            if not project_uuid:
                continue
            try:
                accessed_at = float(raw_accessed_at)
            except (TypeError, ValueError):
                accessed_at = now
            normalized[project_uuid] = accessed_at
        return normalized

    def _load_active_projects(self) -> Dict[str, float]:
        return self._normalize_active_projects(
            self._load_cache_file(self._active_projects_path(), {})
        )

    def _save_active_projects(self, accesses: Dict[str, float]) -> None:
        self._save_cache_file(
            self._active_projects_path(),
            dict(sorted(accesses.items())),
            touch_meta=False,
        )

    def _prune_active_projects(self, *, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        cutoff = current_time - self.active_project_ttl_seconds
        retained = sorted(
            (
                (project_uuid, accessed_at)
                for project_uuid, accessed_at in self._active_project_last_access.items()
                if accessed_at >= cutoff
            ),
            key=lambda item: item[1],
            reverse=True,
        )[: self.active_project_limit]
        retained_accesses = dict(retained)
        changed = retained_accesses != self._active_project_last_access
        self._active_project_last_access = retained_accesses
        self.active_project_uuids = set(retained_accesses)
        if changed:
            self._invalidate_cache_status()
        return changed

    def reset(self, base_path: str = None) -> None:
        self._write_executor.shutdown(wait=True, cancel_futures=False)
        if base_path:
            self.base_path = base_path
        self.lock = asyncio.Lock()
        self.pending_updates = []
        self.active_project_uuids = set()
        self._active_project_last_access = {}
        self.project_query_cache = OrderedDict()
        self._cache_meta_lock = threading.RLock()
        self.cache_meta = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
            "project_revisions": {},
        }
        self._memory_cache = OrderedDict()
        self._memory_cache_lock = threading.RLock()
        self._dirty_memory_paths = {}
        self._inflight_fetches = {}
        self._write_state_lock = threading.RLock()
        self._write_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="dtvp-cache-writer",
        )
        self._last_write_future = None
        self._write_errors = []
        self._cache_status_lock = threading.RLock()
        self._cache_status_snapshot = None
        self._cache_status_expires_at = 0.0
        self._assessment_sync_lock = asyncio.Lock()
        self._assessment_sync_wakeup = asyncio.Event()
        self._ensure_directories()
        self.assessment_outbox = AssessmentOutboxStore(
            get_assessment_outbox_path(self.base_path),
            logger=logger,
        )
        self._import_legacy_pending_updates()

    async def _singleflight_fetch(
        self,
        key: Tuple[str, ...],
        loader: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Share one upstream fetch without sharing its mutable result."""
        async with self.lock:
            task = self._inflight_fetches.get(key)
            if task is None:
                task = asyncio.create_task(loader())
                self._inflight_fetches[key] = task

                def cleanup(completed: asyncio.Task[Any]) -> None:
                    asyncio.create_task(self._remove_inflight_fetch(key, completed))

                task.add_done_callback(cleanup)

        try:
            result = await asyncio.shield(task)
        finally:
            if task.done():
                await self._remove_inflight_fetch(key, task)
        return copy.deepcopy(result)

    async def _remove_inflight_fetch(
        self,
        key: Tuple[str, ...],
        task: asyncio.Task[Any],
    ) -> None:
        async with self.lock:
            if self._inflight_fetches.get(key) is task:
                self._inflight_fetches.pop(key, None)

    def load_persisted_runtime_state(self) -> None:
        (
            pending_updates,
            active_project_uuids,
            cache_meta,
        ) = self._read_startup_cache_state()
        self.pending_updates = pending_updates
        self._active_project_last_access = dict(active_project_uuids)
        active_changed = self._prune_active_projects()
        self.cache_meta = cache_meta
        self._invalidate_cache_status()
        self._remember_startup_cache_state(
            pending_updates,
            self._active_project_last_access,
            cache_meta,
        )
        if active_changed:
            self._save_active_projects(self._active_project_last_access)

    def _load_cache_file(self, path: str, default: Any = None) -> Any:
        with self._memory_cache_lock:
            if path in self._memory_cache:
                self._memory_cache.move_to_end(path)
                return self._memory_cache[path]

        data = _read_json(path, default)
        self._cache_memory_value(path, data)
        return data

    def _save_cache_file(
        self,
        path: str,
        data: Any,
        touch_meta: bool = True,
        *,
        force: bool = False,
    ) -> bool:
        with self._memory_cache_lock:
            cached = self._memory_cache.get(path)
            has_cached = path in self._memory_cache
            write_pending = self._dirty_memory_paths.get(path, 0) > 0
            if (
                not force
                and has_cached
                and cached == data
                and (write_pending or os.path.exists(path))
            ):
                self._memory_cache.move_to_end(path)
                return False
            self._dirty_memory_paths[path] = self._dirty_memory_paths.get(path, 0) + 1
        self._cache_memory_value(path, data)
        write = self._submit_atomic_write(path, data)

        def mark_clean(_completed: Future[Any]) -> None:
            with self._memory_cache_lock:
                remaining = self._dirty_memory_paths.get(path, 1) - 1
                if remaining > 0:
                    self._dirty_memory_paths[path] = remaining
                else:
                    self._dirty_memory_paths.pop(path, None)
                self._enforce_memory_cache_limit_locked()

        write.add_done_callback(mark_clean)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            write.result()
        if touch_meta:
            self._touch_cache_meta()
        return True

    def _cache_memory_value(self, path: str, data: Any) -> None:
        with self._memory_cache_lock:
            self._memory_cache[path] = data
            self._memory_cache.move_to_end(path)
            self._enforce_memory_cache_limit_locked()

    def _enforce_memory_cache_limit_locked(self) -> None:
        while len(self._memory_cache) > self.memory_cache_max_entries:
            evicted = False
            for candidate in tuple(self._memory_cache):
                if self._dirty_memory_paths.get(candidate, 0) > 0:
                    continue
                self._memory_cache.pop(candidate, None)
                evicted = True
                break
            if not evicted:
                break

    def _submit_atomic_write(self, path: str, data: Any) -> Future[Any]:
        with self._write_state_lock:
            future = self._write_executor.submit(_atomic_write, path, data)
            self._last_write_future = future

        def remember_error(completed: Future[Any]) -> None:
            try:
                error = completed.exception()
            except BaseException as exc:
                error = exc
            if error is not None:
                with self._write_state_lock:
                    self._write_errors.append(error)

        future.add_done_callback(remember_error)
        return future

    async def flush_cache_writes(self) -> None:
        with self._write_state_lock:
            last_write = self._last_write_future
        write_error: BaseException | None = None
        if last_write is not None:
            try:
                # Do not depend on a cross-thread future callback to wake the
                # event loop. A short timer-backed poll remains responsive and
                # is reliable when completion races callback registration.
                while not last_write.done():
                    await asyncio.sleep(0.01)
                last_write.result()
            except BaseException as exc:
                write_error = exc
        with self._write_state_lock:
            if self._write_errors:
                write_error = write_error or self._write_errors[0]
                self._write_errors.clear()
        if write_error is not None:
            raise write_error

    async def close(self) -> None:
        await self.flush_cache_writes()
        self._write_executor.shutdown(wait=True, cancel_futures=False)

    def _save_project_cache(
        self,
        path: str,
        data: Any,
        *,
        project_uuid: str | None = None,
    ) -> bool:
        changed = self._save_cache_file(path, data, touch_meta=False)
        if changed:
            inferred_project_uuid = project_uuid or self._project_uuid_for_cache_path(
                path
            )
            self._touch_cache_meta(
                project_uuids={inferred_project_uuid}
                if inferred_project_uuid
                else None
            )
        elif os.path.abspath(path) == os.path.abspath(self._projects_path()):
            # A successful no-op project-list refresh still updates its TTL.
            self._save_projects_meta(self.cache_meta)
        return changed

    def _project_uuid_for_cache_path(self, path: str) -> str | None:
        try:
            relative_path = os.path.relpath(path, self.base_path)
        except ValueError:
            return None
        parts = relative_path.split(os.sep)
        if len(parts) != 2 or parts[0] not in {
            "findings",
            "project_vulnerabilities",
            "boms",
            "analysis",
        }:
            return None
        filename = parts[1]
        if not filename.endswith(".json"):
            return None
        stem = filename[:-5]
        if parts[0] == "analysis":
            stem = stem.split("__", 1)[0]
        return stem or None

    def _load_project_cache(self, path: str, default: Any = None) -> Any:
        return self._load_cache_file(path, default)

    async def initialize(self) -> None:
        pending_updates, active_project_uuids, cache_meta = await asyncio.to_thread(
            self._read_startup_cache_state
        )
        async with self.lock:
            self.pending_updates = pending_updates
            self._active_project_last_access = dict(active_project_uuids)
            active_changed = self._prune_active_projects()
            self.cache_meta = cache_meta
            self._invalidate_cache_status()
            self._remember_startup_cache_state(
                pending_updates,
                self._active_project_last_access,
                cache_meta,
            )
            if active_changed:
                self._save_active_projects(self._active_project_last_access)
        if active_changed:
            await self.flush_cache_writes()

    async def background_sync_loop(self) -> None:
        settings = DTSettings()
        async with DTClient(settings.api_url, api_key=settings.api_key) as client:
            next_cache_refresh = 0.0
            while True:
                try:
                    await self.flush_pending_updates(client)
                    now = time.monotonic()
                    if now >= next_cache_refresh:
                        await self._refresh_project_list(client)
                        await self._refresh_active_projects(client)
                        next_cache_refresh = now + self.refresh_interval_seconds
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("Cache background sync failed: %s", exc)
                self._assessment_sync_wakeup.clear()
                timeout = max(
                    0.1,
                    min(1.0, next_cache_refresh - time.monotonic()),
                )
                try:
                    await asyncio.wait_for(
                        self._assessment_sync_wakeup.wait(),
                        timeout=timeout,
                    )
                except TimeoutError:
                    pass

    async def _refresh_project_list(self, client: DTClient) -> None:
        try:
            projects = await discover_source_projects(
                connector=DependencyTrackConnector(),
                client=client,
                source_base_url=client.base_url,
            )
            async with self.lock:
                self._mark_project_list_refreshed()
                self._save_project_cache(self._projects_path(), projects)
            await self.flush_cache_writes()
        except Exception as exc:
            logger.debug("Failed to refresh project list: %s", exc)

    async def _refresh_active_projects(self, client: DTClient) -> None:
        async with self.lock:
            changed = self._prune_active_projects()
            active = list(self.active_project_uuids)
            if changed:
                self._save_active_projects(self._active_project_last_access)
        if changed:
            await self.flush_cache_writes()
        for project_uuid in active:
            try:
                await self.refresh_project(project_uuid, client)
            except Exception as exc:
                logger.debug("Failed to refresh project %s: %s", project_uuid, exc)

    async def refresh_project(self, project_uuid: str, client: DTClient) -> None:
        await self.record_project_access(project_uuid)
        snapshot = await self._get_imported_project_snapshot(client, project_uuid)
        if snapshot is not None and (
            (snapshot.get("provenance") or {}).get("source_type")
            != "dependency-track"
        ):
            return
        await self._import_project(client, project_uuid)

    async def record_project_access(self, project_uuid: str) -> None:
        project_uuid = str(project_uuid or "").strip()
        if not project_uuid:
            return
        should_persist = False
        async with self.lock:
            now = time.time()
            previous_access = self._active_project_last_access.get(project_uuid)
            self._active_project_last_access[project_uuid] = now
            changed = self._prune_active_projects(now=now)
            should_persist = (
                previous_access is None
                or now - previous_access
                >= min(300, max(30, self.refresh_interval_seconds))
                or changed
            )
            if should_persist:
                self._save_active_projects(self._active_project_last_access)

    async def get_projects(
        self, client: DTClient | None, name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        async with self.lock:
            projects = self._load_project_cache(self._projects_path(), []) or []
        discovered = await asyncio.to_thread(list_source_catalog_projects)
        if client is None:
            catalog = discovered or projects
            if name:
                normalized_name = name.casefold()
                catalog = [
                    project for project in catalog
                    if normalized_name in str(project.get("name") or "").casefold()
                ]
            return copy.deepcopy(catalog)

        # Reads stay on the DTVP catalog. The background refresh loop owns
        # provider discovery, so an old-but-valid catalog remains available
        # during a source outage without making each API request call DT.
        if discovered:
            catalog = discovered
        else:
            try:
                catalog = await self._singleflight_fetch(
                    ("source-project-catalog", _safe_base_url(client.base_url)),
                    lambda: discover_source_projects(
                        connector=DependencyTrackConnector(),
                        client=client,
                        source_base_url=client.base_url,
                    ),
                )
                async with self.lock:
                    self._mark_project_list_refreshed()
                    self._save_project_cache(self._projects_path(), catalog)
            except Exception:
                if discovered:
                    logger.warning(
                        "Project discovery unavailable; using %d DTVP catalog entries",
                        len(discovered),
                    )
                    catalog = discovered
                elif projects:
                    logger.warning(
                        "Project discovery unavailable; using %d legacy cached entries",
                        len(projects),
                    )
                    catalog = projects
                else:
                    raise

        if name:
            normalized_name = name.casefold()
            catalog = [
                project for project in catalog
                if normalized_name in str(project.get("name") or "").casefold()
            ]
        return copy.deepcopy(catalog)

    async def _get_imported_project_snapshot(
        self, client: DTClient, project_uuid: str
    ) -> Optional[Dict[str, Any]]:
        try:
            base_url = _safe_base_url(client.base_url)
            record = await asyncio.to_thread(
                get_latest_snapshot_for_source_project,
                project_uuid,
                base_url,
            )
            if record is None:
                return None
            return await asyncio.to_thread(
                ArtifactStore().get_json, record["payload_sha256"]
            )
        except (OSError, ValueError) as exc:
            logger.warning("Could not read DTVP snapshot for project %s: %s", project_uuid, exc)
            return None

    async def _get_discovered_projects(self, client: DTClient) -> List[Dict[str, Any]]:
        try:
            return await asyncio.to_thread(
                list_source_catalog_projects,
            )
        except (OSError, ValueError) as exc:
            logger.warning("Could not list DTVP source project catalog: %s", exc)
            return []

    async def _import_project(self, client: DTClient, project_uuid: str) -> None:
        """Fetch a complete source scope and publish it before serving the read."""
        async def import_once() -> dict:
            run = await import_source_scope(
                connector=DependencyTrackConnector(),
                client=client,
                source_base_url=client.base_url,
                request_id=f"cache-refresh:{project_uuid}:{uuid4()}",
                initiated_by="system:cache-refresh",
                scope={"project_id": project_uuid},
            )
            if run.get("status") != "succeeded":
                raise RuntimeError(
                    run.get("error_summary") or "Dependency-Track import did not succeed"
                )
            return run

        await self._singleflight_fetch(("dtvp-import", project_uuid), import_once)
        await self._migrate_pending_local_assessments(project_uuid)

    async def _migrate_pending_local_assessments(
        self, project_uuid: str, *, source_type: str = "dependency-track"
    ) -> bool:
        """Promote legacy local decision states after their snapshot exists."""
        if project_uuid in self._legacy_assessments_migrated:
            return True
        states = await asyncio.to_thread(
            self.assessment_outbox.list_states_for_project, project_uuid
        )
        # The earlier cache also wrote accepted local decisions as individual
        # JSON overlays. Promote those only for findings present in the
        # imported snapshot; file names alone are not a reliable identity map.
        legacy_analyses = []
        snapshot_record = await asyncio.to_thread(
            get_latest_snapshot_for_source_project,
            project_uuid,
            None,
            source_type,
        )
        if snapshot_record is not None:
            try:
                snapshot = await asyncio.to_thread(
                    ArtifactStore().get_json, snapshot_record["payload_sha256"]
                )
                findings = (snapshot.get("source_artifacts") or {}).get("findings") or []
                for finding in findings:
                    component = finding.get("component") or {}
                    vulnerability = finding.get("vulnerability") or {}
                    component_id = str(component.get("uuid") or "")
                    vulnerability_id = str(vulnerability.get("uuid") or "")
                    if not component_id or not vulnerability_id:
                        continue
                    legacy = self._load_project_cache(
                        self._analysis_path(project_uuid, component_id, vulnerability_id),
                        None,
                    )
                    if not isinstance(legacy, dict):
                        continue
                    legacy_analyses.append({
                        "project_uuid": project_uuid,
                        "component_uuid": component_id,
                        "vulnerability_uuid": vulnerability_id,
                        "state": legacy.get("analysisState") or legacy.get("analysis_state") or "NOT_SET",
                        "details": legacy.get("analysisDetails") or legacy.get("analysis_details") or "",
                        "suppressed": legacy.get("isSuppressed", legacy.get("is_suppressed", False)),
                    })
            except (OSError, ValueError):
                logger.exception("Could not inspect legacy assessment cache for %s", project_uuid)
                return False
        publication_enabled = os.getenv(
            "DTVP_DT_ASSESSMENT_SYNC_ENABLED", "false"
        ).strip().lower() in {"1", "true", "yes", "on", "enabled"}
        all_migrated = True
        for state in states:
            migrated = {
                "project_uuid": project_uuid,
                "component_uuid": state.get("component_uuid"),
                "vulnerability_uuid": state.get("vulnerability_uuid"),
                "state": state.get("analysisState"),
                "details": state.get("analysisDetails") or "",
                "suppressed": bool(state.get("isSuppressed", False)),
            }
            try:
                await asyncio.to_thread(
                    persist_assessment_revisions,
                    [migrated],
                    actor="migration:legacy-local-queue",
                    only_if_absent=True,
                    source_type=source_type,
                )
            except Exception:
                all_migrated = False
                logger.exception(
                    "Could not migrate a pre-existing local assessment "
                    "(project_uuid=%s, update_id=%s)",
                    project_uuid,
                    state.get("update_id"),
                )
                continue
            if (
                not publication_enabled
                and state.get("sync_status") in {"pending", "error"}
                and state.get("update_id")
            ):
                await asyncio.to_thread(
                    self.assessment_outbox.discard, state["update_id"]
                )
        for legacy in legacy_analyses:
            try:
                await asyncio.to_thread(
                    persist_assessment_revisions,
                    [legacy],
                    actor="migration:legacy-analysis-cache",
                    only_if_absent=True,
                    source_type=source_type,
                )
            except Exception:
                all_migrated = False
                logger.exception(
                    "Could not migrate legacy cached assessment (project_uuid=%s)",
                    project_uuid,
                )
        if all_migrated:
            self._legacy_assessments_migrated.add(project_uuid)
        return all_migrated

    async def _get_or_import_snapshot(
        self, client: DTClient, project_uuid: str, *, refresh: bool
    ) -> Optional[Dict[str, Any]]:
        snapshot = await self._get_imported_project_snapshot(client, project_uuid)
        if snapshot is not None:
            source_type = (snapshot.get("provenance") or {}).get("source_type")
            if source_type != "dependency-track":
                return snapshot
        if snapshot is not None and not refresh:
            await self._migrate_pending_local_assessments(project_uuid)
            return snapshot
        try:
            await self._import_project(client, project_uuid)
        except Exception:
            if snapshot is not None:
                logger.exception(
                    "DTVP refresh failed; serving last published snapshot "
                    "(project_uuid=%s)",
                    project_uuid,
                )
                return snapshot
            raise
        published = await self._get_imported_project_snapshot(client, project_uuid)
        if published is None:
            raise RuntimeError(
                f"DTVP has no published inventory snapshot for project {project_uuid}"
            )
        return published

    async def get_vulnerabilities(
        self,
        client: DTClient,
        project_uuid: str,
        cve: Optional[str] = None,
        refresh: bool = False,
        preserve_source_payload: bool = False,
    ) -> List[Dict[str, Any]]:
        await self.record_project_access(project_uuid)
        snapshot = await self._get_or_import_snapshot(
            client, project_uuid, refresh=refresh
        )
        if preserve_source_payload:
            findings = copy.deepcopy(
                ((snapshot.get("source_artifacts") or {}).get("findings") or [])
            )
        else:
            findings = project_findings(snapshot)
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
        preserve_source_payload: bool = False,
    ) -> List[Dict[str, Any]]:
        snapshot = await self._get_or_import_snapshot(
            client, project_uuid, refresh=refresh
        )
        if preserve_source_payload:
            return copy.deepcopy(
                ((snapshot.get("source_artifacts") or {}).get("advisories") or [])
            )
        return project_advisories(snapshot)

    async def get_bom(
        self,
        client: DTClient,
        project_uuid: str,
        refresh: bool = False,
        preserve_source_payload: bool = False,
    ) -> Optional[Dict[str, Any]]:
        await self.record_project_access(project_uuid)
        snapshot = await self._get_or_import_snapshot(
            client, project_uuid, refresh=refresh
        )
        if preserve_source_payload:
            return copy.deepcopy(((snapshot.get("source_artifacts") or {}).get("bom")))
        return project_bom(snapshot)

    async def get_analysis(
        self,
        client: DTClient,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        refresh: bool = False,
    ) -> Optional[Dict[str, Any]]:
        overlay = self.get_assessment_overlay(
            project_uuid, component_uuid, vulnerability_uuid
        )
        if overlay is not None:
            return overlay
        snapshot = await self._get_or_import_snapshot(
            client, project_uuid, refresh=refresh
        )
        for finding in ((snapshot.get("security") or {}).get("findings") or []):
            vulnerability = finding.get("vulnerability") or {}
            if (
                str(finding.get("component_external_id") or "") == component_uuid
                and str(vulnerability.get("external_id") or "") == vulnerability_uuid
            ):
                return copy.deepcopy(finding.get("source_analysis") or {})
        return None

    def get_assessment_overlay(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        local_decision = get_current_assessment(
            project_uuid, component_uuid, vulnerability_uuid
        )
        if local_decision is not None:
            sync_enabled = os.getenv(
                "DTVP_DT_ASSESSMENT_SYNC_ENABLED", "false"
            ).strip().lower() in {"1", "true", "yes", "on", "enabled"}
            if sync_enabled:
                publication = self.assessment_outbox.get_overlay(
                    (project_uuid, component_uuid, vulnerability_uuid)
                )
                if publication is not None:
                    local_decision["dtvpSyncStatus"] = publication.get("sync_status")
                    local_decision["dtvpUpdateId"] = publication.get("update_id")
                    local_decision["dtvpSyncError"] = publication.get("last_error")
            return local_decision
        overlay = self.assessment_outbox.get_overlay(
            (project_uuid, component_uuid, vulnerability_uuid)
        )
        if overlay is None:
            return None
        return {
            "analysisState": overlay.get("analysisState") or "NOT_SET",
            "analysisDetails": overlay.get("analysisDetails") or "",
            "isSuppressed": bool(overlay.get("isSuppressed", False)),
            "dtvpRevision": int(overlay.get("revision") or 0),
            "dtvpSyncStatus": overlay.get("sync_status") or "synced",
            "dtvpUpdateId": overlay.get("update_id"),
            "dtvpSyncError": overlay.get("last_error"),
        }

    def get_cached_assessment_details(self, instances: List[Dict[str, Any]]) -> List[str]:
        """Read trusted metadata without fetching Dependency-Track on the write path."""
        result = []
        for instance in instances:
            key = tuple(instance[name] for name in (
                "project_uuid", "component_uuid", "vulnerability_uuid"
            ))
            analysis = self.get_assessment_overlay(*key)
            if analysis is None:
                analysis = get_source_finding_analysis(*key)
            result.append(analysis.get("analysisDetails") or analysis.get("analysis_details") or "")
        return result

    def _overlay_local_analysis(
        self,
        project_uuid: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        for finding in findings:
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if comp_uuid and vuln_uuid:
                overlay = self.get_assessment_overlay(
                    project_uuid,
                    comp_uuid,
                    vuln_uuid,
                )
                if overlay is not None:
                    finding["analysis"] = overlay
        return findings

    async def queue_analysis_update(
        self, payload: Dict[str, Any], replace: bool = False
    ) -> str:
        entries = await self.persist_assessment_updates(
            [payload],
            replace=replace,
        )
        return str(entries[0]["id"])

    async def persist_assessment_updates(
        self,
        payloads: List[Dict[str, Any]],
        *,
        replace: bool = True,
        expected_revisions: dict[AssessmentKey, int] | None = None,
        actor: str | None = None,
        source_type: str = "dependency-track",
    ) -> List[Dict[str, Any]]:
        if not payloads:
            return []
        try:
            entries = await asyncio.to_thread(
                persist_assessment_revisions,
                payloads,
                actor=actor,
                expected_revisions=expected_revisions,
                source_type=source_type,
            )
        except AssessmentOutboxConflictError as exc:
            raise PendingUpdateExistsError(str(exc)) from exc
        if os.getenv("DTVP_DT_ASSESSMENT_SYNC_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on", "enabled"
        }:
            try:
                await asyncio.to_thread(
                    self.assessment_outbox.enqueue_many,
                    payloads,
                    replace=replace,
                )
                self._assessment_sync_wakeup.set()
            except Exception:
                logger.exception(
                    "DTVP decision persisted, but optional Dependency-Track "
                    "publication could not be queued"
                )
        async with self.lock:
            self.pending_updates = self._load_pending_updates()
            self._invalidate_cache_status()
            self._touch_cache_meta(
                project_uuids={
                    str(payload.get("project_uuid") or "").strip()
                    for payload in payloads
                    if str(payload.get("project_uuid") or "").strip()
                }
            )
        return entries

    async def queue_analysis_updates(
        self,
        payloads: List[Dict[str, Any]],
        replace: bool = False,
    ) -> List[str]:
        """Persist and coalesce several writes in one SQLite transaction."""
        persisted_entries = await self.persist_assessment_updates(
            payloads,
            replace=replace,
        )
        return [str(entry["id"]) for entry in persisted_entries]

    async def remove_pending_update(self, update_id: str) -> None:
        await asyncio.to_thread(self.assessment_outbox.discard, update_id)
        self.pending_updates = self._load_pending_updates()
        self._invalidate_cache_status()

    async def flush_pending_updates(self, client: DTClient) -> None:
        if os.getenv("DTVP_DT_ASSESSMENT_SYNC_ENABLED", "false").strip().lower() not in {
            "1", "true", "yes", "on", "enabled"
        }:
            return
        async with self._assessment_sync_lock:
            pending = await asyncio.to_thread(self.assessment_outbox.list_due)
            if not pending:
                return

            next_index = 0
            saved_local = False
            state_lock = asyncio.Lock()

            async def worker() -> None:
                nonlocal next_index, saved_local
                while True:
                    async with state_lock:
                        if next_index >= len(pending):
                            return
                        entry = pending[next_index]
                        next_index += 1
                    payload = entry.get("payload", {})
                    key = assessment_key(payload)
                    revision = int(entry.get("revision") or 0)
                    if key is None:
                        continue
                    try:
                        await client.update_analysis(**payload)
                        marked = await asyncio.to_thread(
                            self.assessment_outbox.mark_synced,
                            key,
                            revision,
                        )
                        if marked:
                            async with self.lock:
                                self._save_local_analysis(payload)
                                saved_local = True
                    except Exception as exc:
                        failure_message = str(exc)
                        if _is_missing_finding_error(exc):
                            try:
                                finding_exists = await client.finding_exists(
                                    project_uuid=key[0],
                                    component_uuid=key[1],
                                    vulnerability_uuid=key[2],
                                )
                            except Exception as verification_exc:
                                failure_message = (
                                    f"{exc}; could not verify the exact finding "
                                    f"through Dependency-Track: {verification_exc}"
                                )
                            else:
                                if not finding_exists:
                                    dropped = await asyncio.to_thread(
                                        self.assessment_outbox.drop_missing_finding,
                                        key,
                                        revision,
                                    )
                                    if dropped:
                                        logger.info(
                                            "Dropped pending DT update %s after "
                                            "confirming its exact finding no "
                                            "longer exists",
                                            entry.get("id"),
                                        )
                                    continue
                                failure_message = (
                                    f"{exc}; Dependency-Track findings API is "
                                    "reachable and the exact finding still exists"
                                )
                        attempts = int(entry.get("attempts") or 0) + 1
                        retry_delay = min(60, 2 ** min(attempts - 1, 6))
                        next_attempt_at = (
                            datetime.now(timezone.utc)
                            + timedelta(seconds=retry_delay)
                        ).isoformat()
                        await asyncio.to_thread(
                            self.assessment_outbox.mark_failed,
                            key,
                            revision,
                            failure_message,
                            next_attempt_at=next_attempt_at,
                        )
                        logger.warning(
                            "Failed to flush pending DT update %s; retrying in "
                            "%d seconds: %s",
                            entry.get("id"),
                            retry_delay,
                            failure_message,
                        )

            concurrency = _positive_int_env(
                "DTVP_ASSESSMENT_SYNC_CONCURRENCY",
                4,
            )
            workers = [
                asyncio.create_task(worker())
                for _ in range(min(concurrency, len(pending)))
            ]
            await asyncio.gather(*workers)
            self.pending_updates = self._load_pending_updates()
            self._invalidate_cache_status()
            if saved_local:
                await self.flush_cache_writes()

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
            project_uuid=project_uuid,
        )

    def _save_local_analyses(self, payloads: List[Dict[str, Any]]) -> None:
        """Persist local overlays while updating cache metadata only once."""
        changed_projects: Set[str] = set()
        for payload in payloads:
            project_uuid = payload.get("project_uuid")
            component_uuid = payload.get("component_uuid")
            vulnerability_uuid = payload.get("vulnerability_uuid")
            if not (project_uuid and component_uuid and vulnerability_uuid):
                continue
            analysis_data = {
                "analysisState": payload.get("state"),
                "analysisDetails": payload.get("details"),
                "isSuppressed": payload.get("suppressed", False),
            }
            changed = self._save_cache_file(
                self._analysis_path(
                    project_uuid,
                    component_uuid,
                    vulnerability_uuid,
                ),
                analysis_data,
                touch_meta=False,
            )
            if changed:
                changed_projects.add(str(project_uuid))
        if changed_projects:
            self._touch_cache_meta(project_uuids=changed_projects)


cache_manager = CacheManager()
