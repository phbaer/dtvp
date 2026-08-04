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

import httpx

from .assessment_outbox_services import (
    AssessmentOutboxConflictError,
    AssessmentOutboxStore,
    AssessmentKey,
    assessment_key,
    get_assessment_outbox_path,
)
from .dt_client import DTClient, DTSettings
from .logic import RE_SCORE

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
    return (
        analysis.get("analysisState")
        or analysis.get("analysis_state")
        or "NOT_SET"
    )


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
    if previous_score is None or current_score is None or previous_score == current_score:
        return marked

    details = _get_analysis_details(marked)
    change_note = f"TM rescoring changed from {previous_score} to {current_score}."
    if change_note not in details:
        details = f"{details}\n\n{change_note}"
    marked["analysisDetails"] = details
    return marked


def _component_cache_identity(component: Dict[str, Any]) -> Optional[str]:
    purl = (component.get("purl") or "").strip().lower()
    if purl:
        return re.sub(r"@[^?]+", "", purl, count=1)

    name = (component.get("name") or "").strip().lower()
    if name:
        return name

    return None


def _vulnerability_cache_identity(vulnerability: Dict[str, Any]) -> Optional[Tuple[str, ...]]:
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
        self.cache_meta: Dict[str, Any] = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
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
            },
        ) or {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
        }

    def _read_startup_cache_state(
        self,
    ) -> tuple[List[Dict[str, Any]], Dict[str, float], Dict[str, Any]]:
        meta_default = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
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
        self._save_cache_file(self._projects_meta_path(), meta, touch_meta=False)

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
        projects = self._load_project_cache(self._projects_path(), []) or []
        versions_by_uuid: Dict[str, Dict[str, Any]] = {
            project.get("uuid"): project
            for project in projects
            if project.get("uuid")
        }

        for project_uuid in self.active_project_uuids:
            if project_uuid and project_uuid not in versions_by_uuid:
                versions_by_uuid[project_uuid] = {
                    "uuid": project_uuid,
                    "name": project_uuid,
                    "version": "",
                }

        findings_dir = os.path.join(self.base_path, "findings")
        if os.path.isdir(findings_dir):
            for filename in os.listdir(findings_dir):
                if not filename.endswith(".json"):
                    continue
                project_uuid = filename[:-5]
                if project_uuid and project_uuid not in versions_by_uuid:
                    versions_by_uuid[project_uuid] = {
                        "uuid": project_uuid,
                        "name": project_uuid,
                        "version": "",
                    }

        return list(versions_by_uuid.values())

    def get_cached_project_snapshot(
        self,
        project_uuid: str,
    ) -> Optional[
        Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]
    ]:
        findings = self._load_project_cache(self._findings_path(project_uuid), None)
        if findings is None:
            return None

        # Overlay locally stored assessments so callers (e.g. the automatic
        # code-analysis sweep) see the same analysis state as the live project
        # view. Without this, a vulnerability assessed in DTVP but whose cached
        # findings file predates that assessment still looks NOT_SET here and
        # would be incorrectly treated as "open" and re-queued for analysis.
        findings = self._overlay_local_analysis(project_uuid, findings)

        project_vulnerabilities = self._load_project_cache(
            self._project_vulns_path(project_uuid),
            [],
        ) or []
        bom = self._load_project_cache(self._bom_path(project_uuid), {}) or {}
        return findings, project_vulnerabilities, bom

    def _touch_cache_meta(self) -> None:
        self._invalidate_cache_status()
        self.cache_meta["last_refreshed_at"] = datetime.now(timezone.utc).isoformat()
        self.cache_meta["revision"] = int(self.cache_meta.get("revision") or 0) + 1
        self._save_projects_meta(self.cache_meta)

    def get_cache_revision(self) -> int:
        return int(self.cache_meta.get("revision") or 0)

    def _project_list_is_fresh(self) -> bool:
        if (
            not self.cache_meta.get("fully_cached")
            or self.project_list_ttl_seconds <= 0
        ):
            return False
        refreshed_value = self.cache_meta.get("projects_refreshed_at")
        if not refreshed_value:
            return False
        try:
            refreshed_at = datetime.fromisoformat(str(refreshed_value))
            if refreshed_at.tzinfo is None:
                refreshed_at = refreshed_at.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return False
        return datetime.now(timezone.utc) - refreshed_at <= timedelta(
            seconds=self.project_list_ttl_seconds
        )

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
        self.cache_meta = {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
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

    def _save_cache_file(self, path: str, data: Any, touch_meta: bool = True) -> None:
        with self._memory_cache_lock:
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

    def _save_project_cache(self, path: str, data: Any) -> None:
        self._save_cache_file(path, data)

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
            projects = await client.get_projects("")
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
        await self.get_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_project_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_bom(client, project_uuid, refresh=True)

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
        self, client: DTClient, name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        async with self.lock:
            projects = self._load_project_cache(self._projects_path(), []) or []
            projects_meta = self.cache_meta
            full_list_is_fresh = self._project_list_is_fresh()

        if not name:
            if full_list_is_fresh:
                return copy.deepcopy(projects)
            try:

                async def fetch_all_projects() -> List[Dict[str, Any]]:
                    fresh_projects = await client.get_projects("")
                    async with self.lock:
                        self._mark_project_list_refreshed()
                        self._save_project_cache(
                            self._projects_path(), fresh_projects
                        )
                    return fresh_projects

                projects = await self._singleflight_fetch(
                    ("projects", "all"),
                    fetch_all_projects,
                )
                return projects
            except Exception:
                if projects:
                    logger.warning(
                        "Dependency-Track project list unavailable; using stale "
                        "cached project list with %d entries",
                        len(projects),
                    )
                    return copy.deepcopy(projects)
                raise

        if projects_meta.get("fully_cached"):
            return copy.deepcopy(
                [
                    project
                    for project in projects
                    if name.lower() in (project.get("name", "") or "").lower()
                ]
            )

        if name in self.project_query_cache:
            self.project_query_cache.move_to_end(name)
            return copy.deepcopy(self.project_query_cache[name])

        try:

            async def fetch_matching_projects() -> List[Dict[str, Any]]:
                fresh_results = await client.get_projects(name)
                async with self.lock:
                    self.project_query_cache[name] = fresh_results
                    self.project_query_cache.move_to_end(name)
                    while (
                        len(self.project_query_cache)
                        > self.project_query_cache_max_entries
                    ):
                        self.project_query_cache.popitem(last=False)
                    if fresh_results:
                        current = self._load_project_cache(
                            self._projects_path(), []
                        ) or []
                        existing_uuids = {
                            project.get("uuid")
                            for project in current
                            if project.get("uuid")
                        }
                        merged = list(current)
                        for project in fresh_results:
                            if project.get("uuid") not in existing_uuids:
                                merged.append(project)
                        self._save_project_cache(self._projects_path(), merged)
                return fresh_results

            results = await self._singleflight_fetch(
                ("projects", "query", name),
                fetch_matching_projects,
            )
        except Exception:
            cached_matches = [
                project
                for project in projects
                if name.lower() in (project.get("name", "") or "").lower()
            ]
            if cached_matches:
                logger.warning(
                    "Dependency-Track project search for %r unavailable; using "
                    "stale cached matches with %d entries",
                    name,
                    len(cached_matches),
                )
                return copy.deepcopy(cached_matches)
            raise
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

            async def fetch_findings() -> List[Dict[str, Any]]:
                async with self.lock:
                    cached_findings = self._load_project_cache(path, None)
                fresh_findings = await client.get_vulnerabilities(
                    project_uuid,
                    cve=None,
                )
                fresh_findings = self._restore_recreated_finding_assessments(
                    project_uuid,
                    fresh_findings,
                    cached_findings or [],
                )
                fresh_findings = self._overlay_local_analysis(
                    project_uuid,
                    fresh_findings,
                )
                async with self.lock:
                    self._save_project_cache(path, fresh_findings)
                return fresh_findings

            findings = await self._singleflight_fetch(
                ("vulnerabilities", project_uuid),
                fetch_findings,
            )
        else:
            findings = copy.deepcopy(findings)
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

            async def fetch_project_vulnerabilities() -> List[Dict[str, Any]]:
                fresh_vulns = await client.get_project_vulnerabilities(project_uuid)
                async with self.lock:
                    self._save_project_cache(path, fresh_vulns)
                return fresh_vulns

            return await self._singleflight_fetch(
                ("project_vulnerabilities", project_uuid),
                fetch_project_vulnerabilities,
            )
        return copy.deepcopy(vulns)

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

            async def fetch_bom() -> Optional[Dict[str, Any]]:
                fresh_bom = await client.get_bom(project_uuid)
                async with self.lock:
                    self._save_project_cache(path, fresh_bom)
                return fresh_bom

            return await self._singleflight_fetch(
                ("bom", project_uuid),
                fetch_bom,
            )
        return copy.deepcopy(bom)

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
            overlay = self.get_assessment_overlay(
                project_uuid,
                component_uuid,
                vulnerability_uuid,
            )
            if overlay is not None:
                return overlay
            async with self.lock:
                analysis = self._load_project_cache(path, None)
        if analysis is None:

            async def fetch_analysis() -> Optional[Dict[str, Any]]:
                async with self.lock:
                    previous_analysis = self._load_project_cache(path, None)
                fresh_analysis = await client.get_analysis(
                    project_uuid=project_uuid,
                    component_uuid=component_uuid,
                    vulnerability_uuid=vulnerability_uuid,
                )
                fresh_analysis = self._merge_blank_source_analysis(
                    previous_analysis,
                    fresh_analysis,
                )
                async with self.lock:
                    self._save_project_cache(path, fresh_analysis)
                overlay = self.get_assessment_overlay(
                    project_uuid,
                    component_uuid,
                    vulnerability_uuid,
                )
                if overlay is not None:
                    return overlay
                if isinstance(fresh_analysis, dict):
                    fresh_analysis = dict(fresh_analysis)
                    fresh_analysis["dtvpRevision"] = 0
                    fresh_analysis["dtvpSyncStatus"] = "synced"
                return fresh_analysis

            return await self._singleflight_fetch(
                (
                    "analysis",
                    project_uuid,
                    component_uuid,
                    vulnerability_uuid,
                ),
                fetch_analysis,
            )
        return copy.deepcopy(analysis)

    def get_assessment_overlay(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
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
            Tuple[str, Tuple[str, ...]], List[Tuple[Tuple[str, str, str], Dict[str, Any]]]
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

        for finding in findings:
            source_analysis = finding.get("analysis") or {}
            identity = self._finding_cache_identity(finding)
            analysis_key = self._finding_analysis_key(project_uuid, finding)
            if not analysis_key:
                continue

            current_path = self._analysis_path(*analysis_key)
            current_cached_analysis = self._load_project_cache(current_path, None)

            if _get_analysis_details(source_analysis):
                previous_analysis = (
                    current_cached_analysis
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
                finding["analysis"] = _mark_assessment_for_review(current_cached_analysis)
                continue

            if not identity:
                continue

            candidates = previous_candidates.get(identity, [])
            if len(candidates) != 1:
                continue

            _, previous_analysis = candidates[0]
            preserved_analysis = _mark_assessment_for_review(previous_analysis)
            self._save_project_cache(current_path, preserved_analysis)
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
        for finding in findings:
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if comp_uuid and vuln_uuid:
                analysis = self._load_project_cache(
                    self._analysis_path(project_uuid, comp_uuid, vuln_uuid), None
                )
                overlay = self.get_assessment_overlay(
                    project_uuid,
                    comp_uuid,
                    vuln_uuid,
                )
                if overlay is not None:
                    analysis = overlay
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
    ) -> List[Dict[str, Any]]:
        if not payloads:
            return []
        try:
            entries = await asyncio.to_thread(
                self.assessment_outbox.enqueue_many,
                payloads,
                replace=replace,
                expected_revisions=expected_revisions,
            )
        except AssessmentOutboxConflictError as exc:
            raise PendingUpdateExistsError(str(exc)) from exc
        async with self.lock:
            self.pending_updates = self._load_pending_updates()
            self._invalidate_cache_status()
            self._touch_cache_meta()
        self._assessment_sync_wakeup.set()
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
        )

    def _save_local_analyses(self, payloads: List[Dict[str, Any]]) -> None:
        """Persist local overlays while updating cache metadata only once."""
        saved = False
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
            self._save_cache_file(
                self._analysis_path(
                    project_uuid,
                    component_uuid,
                    vulnerability_uuid,
                ),
                analysis_data,
                touch_meta=False,
            )
            saved = True
        if saved:
            self._touch_cache_meta()


cache_manager = CacheManager()
