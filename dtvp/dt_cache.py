import asyncio
import copy
import json
import os
import tempfile
import threading
import time
import logging
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple

import httpx

from .assessment_model import (
    canonical_assessment_text,
    parse_assessment,
    with_analysis_response,
)
from .cyclonedx_export import (
    VARIANT_INVENTORY,
    build_inventory,
    build_vdr,
    complete_findings,
)
from .assessment_outbox_services import (
    AssessmentOutboxConflictError,
    AssessmentOutboxStore,
    AssessmentKey,
    assessment_key,
    get_assessment_outbox_path,
    get_legacy_assessment_outbox_path,
)
from .dt_client import DTClient, DTSettings
from .fixed_versions import slim_affected_components
from .finding_lifecycle_services import (
    ORIGIN_CARRIED_OVER,
    ORIGIN_CARRIED_OVER_BY_VULNERABILITY,
    REASON_MISSING_AT_EXPORT,
    BomIndex,
    FindingLifecycleStore,
    FindingsImport,
    component_identity as _component_cache_identity,
    follow_findings_plan,
    index_bom,
    read_summary,
    record_carry_over,
)
from .instance_stores import claim_instance, get_dt_cache_path, release_instance
from .ports import AffectedVersionSource, AssessmentSink, VulnerabilitySource
from .source_sync_state import (
    KIND_BOM,
    KIND_FINDINGS,
    KIND_VULNS,
    SyncStateStore,
    bom_digest,
    classify_analysis_changes,
    findings_digests,
    vulns_digest,
)
from .local_store import (
    KIND_ANALYSIS,
    KIND_BOM,
    KIND_FINDINGS,
    KIND_METADATA,
    KIND_PROJECT_VULNERABILITIES,
    KIND_PROJECTS,
    MISSING,
    DocumentRef,
    LocalStore,
    get_database_path,
    safe_filename,
)
from .logic import RE_SCORE, without_historical_blocks

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


def _positive_int_env(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _safe_filename(value: str) -> str:
    return safe_filename(value)


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


def export_retry_delay_seconds(attempts: int) -> int:
    """How long to wait before retrying a failed export.

    Doubles from one second to a minute, as before, to ride out a short
    outage. An export that keeps failing after that is not going to be
    fixed by the next minute either: it backs off further, to 15 minutes,
    instead of asking the source twice a minute indefinitely.
    """
    if attempts <= 10:
        return min(60, 2 ** min(max(attempts, 1) - 1, 6))
    return min(900, 60 * 2 ** min(attempts - 10, 4))


EXPORT_MODE_AUTO = "auto"
EXPORT_MODE_MANUAL = "manual"


def _refresh_seconds_from_env() -> int:
    """The background refresh interval; an unusable value falls back to the
    default instead of stopping the start."""
    try:
        return max(1, int(os.getenv("DTVP_DT_CACHE_REFRESH_SECONDS", "60").strip()))
    except ValueError:
        logger.warning("DTVP_DT_CACHE_REFRESH_SECONDS is not a whole number; using 60")
        return 60


def _whole_number_from_env(name: str, default: int) -> int:
    """A positive whole number from the environment; an unusable value falls
    back to the default instead of stopping the start."""
    try:
        return max(1, int(os.getenv(name, str(default)).strip()))
    except ValueError:
        logger.warning("%s is not a whole number; using %s", name, default)
        return default


def _fixed_versions_refresh_days_from_env() -> int:
    """After how many days the version ranges of a vulnerability are read
    again; a changed record is read again at once."""
    return _whole_number_from_env("DTVP_FIXED_VERSIONS_REFRESH_DAYS", 7)


def _fixed_versions_reads_per_cycle_from_env() -> int:
    """How many vulnerabilities' version ranges one refresh cycle reads."""
    return _whole_number_from_env("DTVP_FIXED_VERSIONS_READS_PER_CYCLE", 200)


FIXED_VERSIONS_CONCURRENCY = 4


class ReadBudget:
    """How many reads one refresh cycle may still make."""

    def __init__(self, reads: int) -> None:
        self.remaining = max(0, reads)

    def take(self, wanted: int) -> int:
        granted = min(self.remaining, max(0, wanted))
        self.remaining -= granted
        return granted


def _updated_text(value: Any) -> str:
    return "" if value is None else str(value)


def _parse_time(value: Any) -> Optional[datetime]:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def fixed_versions_retry_delay(failures: int) -> timedelta:
    """How long a vulnerability waits after its n-th failed range read in a
    row: one minute, doubling up to a day."""
    return timedelta(seconds=min(86400, 60 * 2 ** min(max(failures, 1) - 1, 11)))


def fixed_versions_due(
    row: Optional[Dict[str, Any]],
    updated: str,
    now: datetime,
    ttl: timedelta,
) -> bool:
    """Whether the version ranges of one vulnerability are to be read.

    Never read, a record changed since the read, or a read (or a not-found
    answer) older than the TTL. After a failed read only once the retry
    delay since that attempt has passed.
    """
    if row is None:
        return True
    if row.get("status") == "failed":
        attempted = _parse_time(row.get("attempted_at"))
        delay = fixed_versions_retry_delay(int(row.get("failures") or 0))
        return attempted is None or now - attempted >= delay
    if (row.get("vuln_updated") or "") != updated:
        return True
    read_at = _parse_time(row.get("read_at"))
    return read_at is None or now - read_at >= ttl


def fixed_versions_order(
    key: Tuple[str, str], row: Optional[Dict[str, Any]]
) -> Tuple[int, str, Tuple[str, str]]:
    """Never read first, then changed or stale ones, then failed ones, the
    longest waiting first: reads that keep failing cannot use up a cycle's
    budget ahead of the others."""
    if row is None:
        return (0, "", key)
    if row.get("status") == "failed":
        return (2, str(row.get("attempted_at") or ""), key)
    return (1, "", key)


def get_export_mode() -> str:
    """``auto`` exports local assessments in the background as they are
    saved; ``manual`` keeps them local until an export is requested."""
    mode = os.getenv("DTVP_EXPORT_MODE", EXPORT_MODE_AUTO).strip().lower()
    return EXPORT_MODE_MANUAL if mode == EXPORT_MODE_MANUAL else EXPORT_MODE_AUTO


def _is_incomplete_source_assessment(analysis: Any) -> bool:
    """An assessed finding whose details could not be read.

    The source always sends details for an assessed finding. A state without
    the details field means the per-finding read failed; treating that as
    "no details" would look like the source had emptied the assessment.
    """
    if not isinstance(analysis, dict):
        return False
    state = (
        analysis.get("analysisState")
        or analysis.get("analysis_state")
        or analysis.get("state")
        or "NOT_SET"
    )
    return state != "NOT_SET" and not any(
        name in analysis for name in ("analysisDetails", "analysis_details", "detail")
    )


def _source_assessment_value(analysis: Any) -> Dict[str, Any]:
    """State, details, and suppression of an assessment as the source sent it."""
    if not isinstance(analysis, dict):
        analysis = {}
    return {
        "state": str(
            analysis.get("analysisState")
            or analysis.get("analysis_state")
            or analysis.get("state")
            or "NOT_SET"
        ),
        "details": str(
            analysis.get("analysisDetails") or analysis.get("analysis_details") or ""
        ),
        "suppressed": _get_analysis_suppressed(analysis),
    }


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

    match = RE_SCORE.search(without_historical_blocks(details))
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
        fixed_versions_refresh_days: int = None,
        fixed_versions_reads_per_cycle: int = None,
    ):
        self.base_path = base_path or get_dt_cache_path()
        self.refresh_interval_seconds = (
            _refresh_seconds_from_env()
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
        self.fixed_versions_refresh_days = (
            _fixed_versions_refresh_days_from_env()
            if fixed_versions_refresh_days is None
            else max(1, fixed_versions_refresh_days)
        )
        self.fixed_versions_reads_per_cycle = (
            _fixed_versions_reads_per_cycle_from_env()
            if fixed_versions_reads_per_cycle is None
            else max(0, fixed_versions_reads_per_cycle)
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
            "source_revisions": {},
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
        self._assessment_change_listeners: List[
            Callable[..., None]
        ] = []
        # Local assessment writes not yet confirmed in the live snapshots;
        # see ``_note_assessment_writes_locked``. In memory, like the snapshots.
        self._assessment_write_seq = 0
        self._unapplied_writes_floor = 0
        self._unapplied_assessment_writes: Dict[str, Dict[AssessmentKey, int]] = {}
        self._project_list_listeners: List[
            Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], None]
        ] = []
        self._source_state_listeners: List[
            Callable[[bool, BaseException | None], None]
        ] = []
        self._cache_status_listeners: List[Callable[[], None]] = []
        self._instance_claim: str | None = None
        self._open_stores()

    def _open_stores(self) -> None:
        self._ensure_directories()
        # Before any database is opened or migrated: one process per data
        # directory, and none while a restore is unfinished.
        self._instance_claim = claim_instance(self.base_path)
        self._document_refs: Dict[str, DocumentRef] = {}
        self.store = LocalStore(get_database_path(self.base_path), logger=logger)
        imported = self.store.import_legacy_json_cache(self.base_path)
        # This runs at import time, before logging is configured; the result
        # is reported when the application initialises the cache.
        self._legacy_import_report = (
            imported if imported is not None and any(imported.values()) else None
        )
        self.assessment_outbox = AssessmentOutboxStore(
            get_assessment_outbox_path(self.base_path),
            logger=logger,
            legacy_path=get_legacy_assessment_outbox_path(self.base_path),
        )
        self._import_legacy_pending_updates()
        # What happened to findings: DTVP's record, next to the assessments.
        self.finding_lifecycle = FindingLifecycleStore(
            get_assessment_outbox_path(self.base_path), logger=logger
        )
        self.finding_lifecycle.backfill_once(self.store.stored_findings)
        # Per-version sync state (ADR 0004), in the local store's database.
        self.sync_state = SyncStateStore(self.store._connection)

    def _ensure_directories(self) -> None:
        os.makedirs(self.base_path, exist_ok=True)

    # Documents keep their former file path as an opaque address. Each
    # address maps to a typed location in the local database.

    def _address(self, path: str, ref: DocumentRef) -> str:
        self._document_refs[path] = ref
        return path

    def _read_document(self, path: str, default: Any = None) -> Any:
        ref = self._document_refs.get(path)
        if ref is None:
            return _read_json(path, default)
        try:
            value = self.store.read(ref)
        except Exception as exc:
            logger.warning("Failed to read %s from the local database: %s", path, exc)
            return default
        return default if value is MISSING else value

    def _persist_document(self, path: str, data: Any) -> None:
        ref = self._document_refs.get(path)
        if ref is None:
            _atomic_write(path, data)
        else:
            self.store.write(ref, data)

    def _document_exists(self, path: str) -> bool:
        ref = self._document_refs.get(path)
        if ref is None:
            return os.path.exists(path)
        return self.store.exists(ref)

    def _projects_path(self) -> str:
        return self._address(
            os.path.join(self.base_path, "projects.json"),
            DocumentRef(KIND_PROJECTS),
        )

    def _pending_path(self) -> str:
        return os.path.join(self.base_path, "pending_updates.json")

    def _active_projects_path(self) -> str:
        return self._address(
            os.path.join(self.base_path, "active_projects.json"),
            DocumentRef(KIND_METADATA, name="active_projects"),
        )

    def _findings_path(self, project_uuid: str) -> str:
        return self._address(
            os.path.join(
                self.base_path, "findings", f"{_safe_filename(project_uuid)}.json"
            ),
            DocumentRef(KIND_FINDINGS, project_uuid=project_uuid),
        )

    def _projects_meta_path(self) -> str:
        return self._address(
            os.path.join(self.base_path, "projects_meta.json"),
            DocumentRef(KIND_METADATA, name="projects_meta"),
        )

    def _load_projects_meta(self) -> Dict[str, Any]:
        return self._load_cache_file(
            self._projects_meta_path(),
            {
                "fully_cached": False,
                "last_refreshed_at": None,
                "projects_refreshed_at": None,
                "revision": 0,
                "project_revisions": {},
                "source_revisions": {},
            },
        ) or {
            "fully_cached": False,
            "last_refreshed_at": None,
            "projects_refreshed_at": None,
            "revision": 0,
            "project_revisions": {},
            "source_revisions": {},
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
            "source_revisions": {},
        }
        pending = self._load_pending_updates()
        active = self._normalize_active_projects(
            self._read_document(self._active_projects_path(), {})
        )
        meta = (
            self._read_document(self._projects_meta_path(), meta_default)
            or meta_default
        )
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

            stored = self.store.counts()
            cached_findings = stored["findings"]
            cached_boms = stored["boms"]
            cached_analyses = stored["analyses"]

            snapshot = {
                "fully_cached": self.cache_meta.get("fully_cached", False),
                "last_refreshed_at": self.cache_meta.get("last_refreshed_at"),
                "projects": len(projects),
                "active_projects": len(active),
                "cached_findings": cached_findings,
                "cached_boms": cached_boms,
                "cached_analyses": cached_analyses,
                "pending_updates": len(pending),
                # Findings changed both here and in the source; their export
                # waits for a decision.
                # Exports whose last attempt failed, and how long the oldest
                # queued change has been waiting.
                "failed_exports": sum(
                    1 for entry in pending if entry.get("last_error")
                ),
                "oldest_pending_at": min(
                    (str(entry.get("created_at")) for entry in pending if entry.get("created_at")),
                    default=None,
                ),
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

        for project_uuid in self.store.project_uuids_with_findings():
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

    def _touch_cache_meta(
        self,
        *,
        project_uuids: Set[str] | None = None,
        assessment_keys: Iterable[AssessmentKey] | None = None,
    ) -> None:
        """Note that stored data changed.

        ``assessment_keys`` says the change is a local assessment write of
        these findings, which the caller also patches into the live grouped
        snapshots. It then counts in ``project_revisions`` only. An empty
        ``assessment_keys`` is a change no snapshot shows a difference for
        (an export of a value already shown). Every other change also counts
        in ``source_revisions``, which decides whether a grouped snapshot has
        to be built again.
        """
        self._invalidate_cache_status()
        with self._cache_meta_lock:
            self.cache_meta["last_refreshed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            self.cache_meta["revision"] = int(
                self.cache_meta.get("revision") or 0
            ) + 1
            names = ["project_revisions"]
            if assessment_keys is None:
                names.append("source_revisions")
            for name in names:
                revisions = self.cache_meta.setdefault(name, {})
                if not isinstance(revisions, dict):
                    revisions = {}
                    self.cache_meta[name] = revisions
                for project_uuid in project_uuids or set():
                    normalized_uuid = str(project_uuid or "").strip()
                    if normalized_uuid:
                        revisions[normalized_uuid] = (
                            int(revisions.get(normalized_uuid) or 0) + 1
                        )
            keys = list(assessment_keys or ())
            if keys:
                self._note_assessment_writes_locked(keys)
            self._save_projects_meta(self.cache_meta)

    # -- assessment writes that live snapshots still have to show ------------
    #
    # A local assessment write does not make a grouped snapshot outdated when
    # the snapshot is patched with it. Until that patch is confirmed, the
    # write is "unapplied": a snapshot built before it may not be reused.

    _UNAPPLIED_WRITES_LIMIT = 20000

    def _note_assessment_writes_locked(self, keys: Iterable[AssessmentKey]) -> None:
        self._assessment_write_seq += 1
        seq = self._assessment_write_seq
        for key in keys:
            if not (isinstance(key, tuple) and len(key) == 3 and all(key)):
                continue
            self._unapplied_assessment_writes.setdefault(str(key[0]), {})[
                (str(key[0]), str(key[1]), str(key[2]))
            ] = seq
        total = sum(len(v) for v in self._unapplied_assessment_writes.values())
        if total > self._UNAPPLIED_WRITES_LIMIT:
            # Forget them, and with them every snapshot built before now.
            self._unapplied_assessment_writes.clear()
            self._unapplied_writes_floor = seq

    def assessment_write_seq(self) -> int:
        """A number that grows with every local assessment write. A snapshot
        whose build started at this number contains every write up to it."""
        with self._cache_meta_lock:
            return self._assessment_write_seq

    def has_unapplied_assessment_writes(
        self, project_uuids: Iterable[str], *, after_seq: int
    ) -> bool:
        """Whether a snapshot of these project versions whose build started at
        ``after_seq`` lacks a local assessment write."""
        with self._cache_meta_lock:
            if after_seq < self._unapplied_writes_floor:
                return True
            for project_uuid in project_uuids:
                pending = self._unapplied_assessment_writes.get(str(project_uuid))
                if pending and max(pending.values()) > after_seq:
                    return True
        return False

    def confirm_assessment_writes_applied(
        self, applied: Iterable[tuple[AssessmentKey, Dict[str, Any]]]
    ) -> None:
        """The live snapshots now show these values (state, details,
        suppressed per finding). A write counts as applied only when the
        value shown is the one on record: an older value patched late does
        not hide a newer write."""
        for key, shown in applied:
            if not (isinstance(key, tuple) and len(key) == 3):
                continue
            key = (str(key[0]), str(key[1]), str(key[2]))
            with self._cache_meta_lock:
                seq = self._unapplied_assessment_writes.get(key[0], {}).get(key)
            if seq is None:
                continue
            overlay = self.assessment_outbox.get_overlay(key)
            if overlay is None:
                continue
            recorded = self.assessment_outbox._local_value(overlay)
            if (
                str(shown.get("state") or "NOT_SET") != str(recorded.get("state") or "NOT_SET")
                or str(shown.get("details") or "").strip()
                != str(recorded.get("details") or "").strip()
                or bool(shown.get("suppressed")) != bool(recorded.get("suppressed"))
            ):
                continue
            with self._cache_meta_lock:
                pending = self._unapplied_assessment_writes.get(key[0])
                # Written again meanwhile: that write is still unapplied.
                if pending is not None and pending.get(key) == seq:
                    del pending[key]
                    if not pending:
                        del self._unapplied_assessment_writes[key[0]]

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
                # Not lastRiskScore: every export changes it (ADR 0004).
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

    def get_grouped_source_revision(
        self,
        *,
        name: str = "",
        versions: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """Like ``get_grouped_cache_revision``, without the local assessment
        writes that live snapshots are patched with. A change here means a
        grouped snapshot has to be built again."""
        revision = self.get_grouped_cache_revision(name=name, versions=versions)
        with self._cache_meta_lock:
            raw = self.cache_meta.get("source_revisions") or {}
            source = raw if isinstance(raw, dict) else {}
            revision["project_revisions"] = [
                (project_uuid, int(source.get(project_uuid) or 0))
                for project_uuid, _count in revision["project_revisions"]
            ]
        return revision

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
        self._notify_sync(self._cache_status_listeners)

    def add_project_list_listener(
        self,
        listener: Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], None],
    ) -> None:
        """Be told ``(previous, current)`` after the stored project list was
        saved. Called synchronously; the listener must be quick."""
        self._project_list_listeners.append(listener)

    def add_source_state_listener(
        self,
        listener: Callable[[bool, BaseException | None], None],
    ) -> None:
        """Be told whether a project-list read from the source succeeded."""
        self._source_state_listeners.append(listener)

    def add_cache_status_listener(self, listener: Callable[[], None]) -> None:
        """Be told that the cache status changed. Called on any thread, at
        times with the cache lock held; the listener must only set a flag."""
        self._cache_status_listeners.append(listener)

    @staticmethod
    def _notify_sync(listeners: List[Callable[..., None]], *args: Any) -> None:
        for listener in list(listeners):
            try:
                listener(*args)
            except Exception:
                logger.exception("Cache listener failed")

    def _project_vulns_path(self, project_uuid: str) -> str:
        return self._address(
            os.path.join(
                self.base_path,
                "project_vulnerabilities",
                f"{_safe_filename(project_uuid)}.json",
            ),
            DocumentRef(KIND_PROJECT_VULNERABILITIES, project_uuid=project_uuid),
        )

    def _bom_path(self, project_uuid: str) -> str:
        return self._address(
            os.path.join(
                self.base_path, "boms", f"{_safe_filename(project_uuid)}.json"
            ),
            DocumentRef(KIND_BOM, project_uuid=project_uuid),
        )

    def _analysis_path(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> str:
        key = "__".join(
            [_safe_filename(project_uuid), _safe_filename(component_uuid), _safe_filename(vulnerability_uuid)]
        )
        return self._address(
            os.path.join(self.base_path, "analysis", f"{key}.json"),
            DocumentRef(
                KIND_ANALYSIS,
                project_uuid=project_uuid,
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
            ),
        )

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

    def _release_instance(self) -> None:
        claim, self._instance_claim = self._instance_claim, None
        release_instance(claim)

    def reset(self, base_path: str = None) -> None:
        self._write_executor.shutdown(wait=True, cancel_futures=False)
        self.store.close()
        self._release_instance()
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
            "source_revisions": {},
        }
        self._assessment_write_seq = 0
        self._unapplied_writes_floor = 0
        self._unapplied_assessment_writes = {}
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
        self._open_stores()

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
        self._report_legacy_import()
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

        data = self._read_document(path, default)
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
                and (write_pending or self._document_exists(path))
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
            future = self._write_executor.submit(self._persist_document, path, data)
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
        self.store.close()
        self._release_instance()

    def _save_project_cache(
        self,
        path: str,
        data: Any,
        *,
        project_uuid: str | None = None,
        assessment_keys: Iterable[AssessmentKey] | None = None,
    ) -> bool:
        changed = self._save_cache_file(path, data, touch_meta=False)
        if changed:
            inferred_project_uuid = project_uuid or self._project_uuid_for_cache_path(
                path
            )
            self._touch_cache_meta(
                project_uuids={inferred_project_uuid}
                if inferred_project_uuid
                else None,
                assessment_keys=assessment_keys,
            )
        elif os.path.abspath(path) == os.path.abspath(self._projects_path()):
            # A successful no-op project-list refresh still updates its TTL.
            self._save_projects_meta(self.cache_meta)
        return changed

    def _project_uuid_for_cache_path(self, path: str) -> str | None:
        ref = self._document_refs.get(path)
        if ref is not None:
            return ref.project_uuid or None
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

    def _project_analysis_reader(
        self, project_uuid: str
    ) -> Callable[..., Any]:
        """Like ``_load_project_cache`` for the stored assessments of one
        project, but fetching everything not yet in memory with one query
        instead of one lookup per finding."""
        stored: Dict[Tuple[str, str], Any] | None = None

        def read(
            component_uuid: str,
            vulnerability_uuid: str,
            default: Any = None,
        ) -> Any:
            nonlocal stored
            path = self._analysis_path(
                project_uuid, component_uuid, vulnerability_uuid
            )
            with self._memory_cache_lock:
                if path in self._memory_cache:
                    self._memory_cache.move_to_end(path)
                    return self._memory_cache[path]
            if stored is None:
                try:
                    stored = self.store.read_project_analyses(project_uuid)
                except Exception as exc:
                    logger.warning(
                        "Failed to read stored assessments of %s: %s",
                        project_uuid,
                        exc,
                    )
                    stored = {}
            value = stored.get((component_uuid, vulnerability_uuid), MISSING)
            data = default if value is MISSING else value
            self._cache_memory_value(path, data)
            return data

        return read

    def _report_legacy_import(self) -> None:
        outbox_report = self.assessment_outbox.legacy_import_report
        if outbox_report:
            self.assessment_outbox.legacy_import_report = None
            logger.warning("%s", outbox_report)
        imported, self._legacy_import_report = self._legacy_import_report, None
        if imported:
            logger.warning(
                "Imported the JSON cache in %s into the local database %s: %s. "
                "The JSON files are no longer read and can be removed once "
                "the database is verified.",
                self.base_path,
                self.store.path,
                ", ".join(f"{count} {name}" for name, count in imported.items()),
            )

    async def initialize(self) -> None:
        self._report_legacy_import()
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
                    await self.export_if_automatic(client)
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

    async def _refresh_project_list(self, client: VulnerabilitySource) -> None:
        try:
            projects = await client.get_projects("")
            async with self.lock:
                previous = self._load_project_cache(self._projects_path(), []) or []
                self._mark_project_list_refreshed()
                self._save_project_cache(self._projects_path(), projects)
            await self.flush_cache_writes()
            self._record_sync_state(self.sync_state.record_project_list, projects)
            self._notify_sync(self._project_list_listeners, previous, projects)
            self._notify_sync(self._source_state_listeners, True, None)
        except Exception as exc:
            self._notify_sync(self._source_state_listeners, False, exc)
            logger.debug("Failed to refresh project list: %s", exc)

    async def _refresh_active_projects(self, client: VulnerabilitySource) -> None:
        async with self.lock:
            changed = self._prune_active_projects()
            active = list(self.active_project_uuids)
            if changed:
                self._save_active_projects(self._active_project_last_access)
        if changed:
            await self.flush_cache_writes()
        # One cap on the version-range reads for the whole cycle.
        budget = ReadBudget(self.fixed_versions_reads_per_cycle)
        for project_uuid in active:
            try:
                await self.refresh_project(
                    project_uuid, client, fixed_versions_budget=budget
                )
            except Exception as exc:
                logger.debug("Failed to refresh project %s: %s", project_uuid, exc)

    async def refresh_project(
        self,
        project_uuid: str,
        client: VulnerabilitySource,
        *,
        fixed_versions_budget: Optional[ReadBudget] = None,
    ) -> None:
        """Read a project version again from the source, in the background.

        The last step reads the version ranges of its vulnerabilities that
        are missing or stale, for the VDR's recommendation; its failure does
        not fail the refresh.
        """
        await self.get_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_project_vulnerabilities(client, project_uuid, refresh=True)
        await self.get_bom(client, project_uuid, refresh=True)
        try:
            await self.refresh_fixed_versions(
                client, project_uuid, budget=fixed_versions_budget
            )
        except Exception as exc:
            logger.warning(
                "Failed to read the fixed versions of project %s: %s", project_uuid, exc
            )

    async def refresh_fixed_versions(
        self,
        client: Any,
        project_uuid: str,
        *,
        budget: Optional[ReadBudget] = None,
    ) -> int:
        """Read the version ranges of the project's vulnerabilities that have
        no recommendation and are missing or stale in the local database.

        Background only: an export reads the stored rows and never calls
        the source. The rows are shared by all projects, and one read per
        vulnerability is in flight at a time. Returns the number of reads.
        """
        if not isinstance(client, AffectedVersionSource):
            return 0
        async with self.lock:
            records = self._load_project_cache(
                self._project_vulns_path(project_uuid), None
            )
        wanted: Dict[Tuple[str, str], str] = {}
        for record in records if isinstance(records, list) else []:
            if not isinstance(record, dict):
                continue
            source = str(record.get("source") or "").strip()
            vuln_id = str(record.get("vulnId") or "").strip()
            if source and vuln_id and not str(record.get("recommendation") or "").strip():
                wanted[(source, vuln_id)] = _updated_text(record.get("updated"))
        if not wanted:
            return 0
        rows = await asyncio.to_thread(self.store.fixed_version_entries, wanted)
        now = datetime.now(timezone.utc)
        ttl = timedelta(days=self.fixed_versions_refresh_days)
        due = sorted(
            (
                key for key in wanted
                if fixed_versions_due(rows.get(key), wanted[key], now, ttl)
            ),
            key=lambda key: fixed_versions_order(key, rows.get(key)),
        )
        if budget is None:
            budget = ReadBudget(self.fixed_versions_reads_per_cycle)
        due = due[: budget.take(len(due))]
        if not due:
            return 0
        semaphore = asyncio.Semaphore(FIXED_VERSIONS_CONCURRENCY)

        async def read(key: Tuple[str, str]) -> None:
            async with semaphore:
                await self._singleflight_fetch(
                    ("fixed_versions", *key),
                    lambda: self._read_fixed_versions(client, key, wanted[key], ttl),
                )

        await asyncio.gather(*(read(key) for key in due))
        return len(due)

    async def _read_fixed_versions(
        self,
        client: Any,
        key: Tuple[str, str],
        updated: str,
        ttl: timedelta,
    ) -> str:
        source, vuln_id = key
        # Another project may have read it since this one looked.
        rows = await asyncio.to_thread(self.store.fixed_version_entries, [key])
        now = datetime.now(timezone.utc)
        if not fixed_versions_due(rows.get(key), updated, now, ttl):
            return "fresh"
        at = now.isoformat()
        try:
            answer = await client.get_vulnerability_affected(source, vuln_id)
            if answer is not None and not isinstance(answer, dict):
                raise TypeError("Unexpected answer for the affected versions")
        except Exception as exc:
            logger.info(
                "Could not read the affected versions of %s %s: %s", source, vuln_id, exc
            )
            await asyncio.to_thread(
                self.store.save_fixed_version_entry,
                source, vuln_id, status="failed", at=at,
            )
            return "failed"
        if answer is None:
            status, payload = "not_found", None
        else:
            status = "read"
            payload = slim_affected_components(answer.get("affectedComponents"))
        await asyncio.to_thread(
            self.store.save_fixed_version_entry,
            source, vuln_id, status=status, payload=payload,
            vuln_updated=updated, at=at,
        )
        return status

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
        self, client: VulnerabilitySource, name: Optional[str] = None
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
                        previous = (
                            self._load_project_cache(self._projects_path(), [])
                            or []
                        )
                        self._mark_project_list_refreshed()
                        self._save_project_cache(
                            self._projects_path(), fresh_projects
                        )
                    self._record_sync_state(
                        self.sync_state.record_project_list, fresh_projects
                    )
                    self._notify_sync(
                        self._project_list_listeners, previous, fresh_projects
                    )
                    self._notify_sync(self._source_state_listeners, True, None)
                    return fresh_projects

                projects = await self._singleflight_fetch(
                    ("projects", "all"),
                    fetch_all_projects,
                )
                return projects
            except Exception as exc:
                self._notify_sync(self._source_state_listeners, False, exc)
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
                merged: List[Dict[str, Any]] | None = None
                previous: List[Dict[str, Any]] = []
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
                        previous = list(current)
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
                if merged is not None:
                    self._record_sync_state(
                        self.sync_state.record_project_list, merged, complete=False
                    )
                    self._notify_sync(
                        self._project_list_listeners, previous, merged
                    )
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
        client: VulnerabilitySource,
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
                return (await self.import_findings(client, project_uuid)).findings

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

    async def import_findings(
        self,
        client: VulnerabilitySource,
        project_uuid: str,
    ) -> FindingsImport:
        """Read a project's findings from the source and follow them.

        The assessments the source holds are compared with the record.
        Findings the source no longer has are kept as gone, with a reason,
        their records are retired, and an assessment of a replaced finding
        is carried over to its successor. Every read is acted on: a read
        taken while the source still re-analyses the project heals on the
        next one (``finding_lifecycle_services``).
        """
        path = self._findings_path(project_uuid)
        fetch_started_at = datetime.now(timezone.utc)
        try:
            fresh_findings = await client.get_vulnerabilities(project_uuid, cve=None)
        except Exception as exc:
            self._record_sync_state(self.sync_state.record_failure, project_uuid, exc)
            raise
        # Over the raw response, before anything of DTVP's is read into it.
        findings_identity, analyses, analyses_index = findings_digests(fresh_findings)
        # Which analyses the source changed, and which are DTVP's own export
        # coming back; against the record before this read is merged into it.
        try:
            analysis_origins = classify_analysis_changes(
                self.sync_state.previous_analyses_index(project_uuid),
                analyses_index,
                fresh_findings,
                lambda component_uuid, vulnerability_uuid: self._recorded_value(
                    (project_uuid, component_uuid, vulnerability_uuid)
                ),
            )
        except Exception:
            logger.exception("Failed to classify the analysis changes")
            analysis_origins = {}
        await self._read_texts_without_state(client, project_uuid, fresh_findings)
        source_analyses = {
            key: finding.get("analysis")
            for finding in fresh_findings or []
            if isinstance(finding, dict)
            and (key := self._finding_analysis_key(project_uuid, finding))
        }
        await self._merge_source_assessments(source_analyses, fetch_started_at)

        result = FindingsImport(
            findings=fresh_findings,
            read_at=fetch_started_at.isoformat(),
        )
        plan = None
        if isinstance(fresh_findings, list):
            plan = await self._follow_findings(
                client, project_uuid, fresh_findings, source_analyses,
                fetch_started_at,
            )
            result.went = dict(plan.presence.went)
            result.returned = plan.presence.returned
            result.carried_over = [carry.target for carry in plan.carried]
            result.not_carried = plan.carry.not_carried
            # Before the overlay, which shows why a finding went.
            await asyncio.to_thread(
                self.finding_lifecycle.record_read,
                project_uuid,
                [plan.presence.rows[key] for key in plan.presence.changed],
            )
        fresh_findings = self._restore_recreated_finding_assessments(
            project_uuid, fresh_findings
        )
        fresh_findings = self._overlay_local_analysis(project_uuid, fresh_findings)
        async with self.lock:
            self._save_project_cache(path, fresh_findings, project_uuid=project_uuid)
        result.findings = fresh_findings
        self._record_sync_state(
            self.sync_state.record_read,
            project_uuid,
            KIND_FINDINGS,
            (findings_identity, analyses),
            at=fetch_started_at.isoformat(),
            analyses_index=analyses_index,
            origins=analysis_origins,
        )
        if plan is not None:
            await asyncio.to_thread(
                self.finding_lifecycle.record_read, project_uuid, [], read_summary(plan)
            )
            changed = sorted(
                set(plan.retired)
                | {carry.target for carry in plan.carried}
                | {key for carry in plan.carried for key in carry.candidates}
            )
            if changed:
                async with self.lock:
                    self.pending_updates = self._load_pending_updates()
                    self._invalidate_cache_status()
                    self._touch_cache_meta(project_uuids={project_uuid})
                await self._notify_assessments_changed(changed)
        return result

    def _record_sync_state(self, record: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Record a read in the sync state; never fails the read itself."""
        try:
            record(*args, **kwargs)
        except Exception:
            logger.exception("Failed to record the sync state")

    def _recorded_value(
        self, key: AssessmentKey
    ) -> Optional[Tuple[str, str, bool]]:
        """The value DTVP holds for a finding (what it exports), or ``None``."""
        overlay = self.assessment_outbox.get_overlay(key)
        if overlay is None:
            return None
        value = self.assessment_outbox._local_value(overlay)
        return (
            str(value.get("state") or "NOT_SET"),
            str(value.get("details") or ""),
            bool(value.get("suppressed")),
        )

    async def _stored_bom_index(self, project_uuid: str) -> Optional[BomIndex]:
        async with self.lock:
            bom = self._load_project_cache(self._bom_path(project_uuid), None)
        return index_bom(bom)

    async def _read_bom_for_lifecycle(
        self, client: VulnerabilitySource, project_uuid: str
    ) -> Optional[BomIndex]:
        try:
            bom = await client.get_bom(project_uuid)
        except Exception as exc:
            logger.warning("Could not read the BOM of %s: %s", project_uuid, exc)
            return None
        if not isinstance(bom, dict):
            return None
        async with self.lock:
            self._save_project_cache(
                self._bom_path(project_uuid), bom, project_uuid=project_uuid
            )
        return index_bom(bom)

    async def _follow_findings(
        self,
        client: VulnerabilitySource,
        project_uuid: str,
        findings: List[Any],
        source_analyses: Dict[AssessmentKey, Any],
        started_at: datetime,
    ) -> Any:
        """Record the findings of a read, mark what went and carry
        assessments over. See ``finding_lifecycle_services``."""
        loop = asyncio.get_running_loop()
        bom_state: Dict[str, Optional[BomIndex]] = {}

        def previous_bom() -> Optional[BomIndex]:
            # The BOM stored before this read, which may still list
            # components the source no longer has.
            if "previous" not in bom_state:
                bom_state["previous"] = asyncio.run_coroutine_threadsafe(
                    self._stored_bom_index(project_uuid), loop
                ).result()
            return bom_state["previous"]

        def read_bom() -> Optional[BomIndex]:
            # Called from the worker thread; read once, only when needed.
            if "index" not in bom_state:
                previous_bom()  # before the read replaces it
                bom_state["index"] = asyncio.run_coroutine_threadsafe(
                    self._read_bom_for_lifecycle(client, project_uuid), loop
                ).result()
            return bom_state["index"]

        def has_source_value(key: AssessmentKey) -> bool:
            analysis = source_analyses.get(key)
            if _is_incomplete_source_assessment(analysis):
                return True
            value = _source_assessment_value(analysis)
            return not (
                value["state"] == "NOT_SET"
                and not value["details"].strip()
                and not value["suppressed"]
            )

        plan = await asyncio.to_thread(
            lambda: follow_findings_plan(
                project_uuid=project_uuid,
                findings=findings,
                has_source_value=has_source_value,
                started_at=started_at,
                lifecycle=self.finding_lifecycle,
                outbox=self.assessment_outbox,
                bom=read_bom,
                previous_bom=previous_bom,
            )
        )
        carried = []
        for origin in (ORIGIN_CARRIED_OVER, ORIGIN_CARRIED_OVER_BY_VULNERABILITY):
            group = [carry for carry in plan.carry.carries if carry.origin == origin]
            if not group:
                continue
            payloads = [
                {
                    "project_uuid": carry.target[0],
                    "component_uuid": carry.target[1],
                    "vulnerability_uuid": carry.target[2],
                    "state": carry.value["state"],
                    # A recreated component is the same one: its assessment
                    # stays as it was (approved stays approved).
                    "details": carry.value["details"]
                    if carry.recreated
                    else _mark_assessment_for_review(
                        {
                            "analysisState": carry.value["state"],
                            "analysisDetails": carry.value["details"],
                            "isSuppressed": carry.value["suppressed"],
                        }
                    )["analysisDetails"],
                    "suppressed": carry.value["suppressed"],
                }
                for carry in group
            ]
            # The plan was made from a snapshot of the records. A target
            # assessed, or a candidate saved again, since then keeps its
            # value: that carry is left out, for the next read to decide.
            expected: Dict[AssessmentKey, Optional[int]] = {}
            for carry in group:
                expected[carry.target] = None
                for candidate in carry.candidates:
                    expected[candidate] = int(
                        (plan.records.get(candidate) or {}).get("revision") or 0
                    )
            entries = await self.persist_assessment_updates(
                payloads,
                origin=origin,
                author=None,
                replace=False,
                supersedes={carry.target: carry.candidates for carry in group},
                expected_records=expected,
                skip_changed=True,
            )
            saved = {
                (
                    str(entry["payload"]["project_uuid"]),
                    str(entry["payload"]["component_uuid"]),
                    str(entry["payload"]["vulnerability_uuid"]),
                )
                for entry in entries
            }
            skipped = [carry.target for carry in group if carry.target not in saved]
            if skipped:
                logger.warning(
                    "%d assessment(s) of %s not carried over: the finding or "
                    "the record changed during the read",
                    len(skipped), project_uuid,
                )
            carried.extend(carry for carry in group if carry.target in saved)
        if carried:
            logger.info(
                "Carried %d assessment(s) of %s over to the findings that "
                "replaced theirs (%d onto a recreated component, unchanged; "
                "the others pending review)",
                len(carried), project_uuid,
                sum(1 for carry in carried if carry.recreated),
            )
        record_carry_over(plan, carried, has_source_value=has_source_value)
        return plan

    async def get_project_vulnerabilities(
        self,
        client: VulnerabilitySource,
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
                try:
                    fresh_vulns = await client.get_project_vulnerabilities(project_uuid)
                except Exception as exc:
                    self._record_sync_state(
                        self.sync_state.record_failure, project_uuid, exc
                    )
                    raise
                self._record_sync_state(
                    self.sync_state.record_read,
                    project_uuid,
                    KIND_VULNS,
                    (vulns_digest(fresh_vulns),),
                )
                async with self.lock:
                    self._save_project_cache(
                        path,
                        fresh_vulns,
                        project_uuid=project_uuid,
                    )
                return fresh_vulns

            return await self._singleflight_fetch(
                ("project_vulnerabilities", project_uuid),
                fetch_project_vulnerabilities,
            )
        return copy.deepcopy(vulns)

    async def get_bom(
        self,
        client: VulnerabilitySource,
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
                try:
                    fresh_bom = await client.get_bom(project_uuid)
                except Exception as exc:
                    self._record_sync_state(
                        self.sync_state.record_failure, project_uuid, exc
                    )
                    raise
                self._record_sync_state(
                    self.sync_state.record_read,
                    project_uuid,
                    KIND_BOM,
                    (bom_digest(fresh_bom),),
                )
                async with self.lock:
                    self._save_project_cache(
                        path,
                        fresh_bom,
                        project_uuid=project_uuid,
                    )
                return fresh_bom

            return await self._singleflight_fetch(
                ("bom", project_uuid),
                fetch_bom,
            )
        return copy.deepcopy(bom)

    async def get_analysis(
        self,
        client: VulnerabilitySource,
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
                fetch_started_at = datetime.now(timezone.utc)
                fresh_analysis = await client.get_analysis(
                    project_uuid=project_uuid,
                    component_uuid=component_uuid,
                    vulnerability_uuid=vulnerability_uuid,
                )
                if isinstance(fresh_analysis, dict):
                    await self._merge_source_assessments(
                        {
                            (
                                project_uuid,
                                component_uuid,
                                vulnerability_uuid,
                            ): fresh_analysis
                        },
                        fetch_started_at,
                    )
                fresh_analysis = self._merge_blank_source_analysis(
                    previous_analysis,
                    fresh_analysis,
                )
                async with self.lock:
                    self._save_project_cache(
                        path,
                        fresh_analysis,
                        project_uuid=project_uuid,
                    )
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

    async def export_cyclonedx(
        self,
        client: VulnerabilitySource,
        project_uuid: str,
        variant: str,
        *,
        assessment_source: str,
        property_prefix: str,
        tool_version: str = "",
        unowned_teams: Tuple[str, ...] = (),
        ticket_prefixes: Tuple[str, ...] = (),
    ) -> Optional[Dict[str, Any]]:
        """A CycloneDX document of one project version, from local state.

        ``inventory`` is the stored BOM; ``vdr`` adds every finding with its
        assessment in standard fields. ``None`` when the project has no BOM.
        """
        bom = await self.get_bom(client, project_uuid)
        if not isinstance(bom, dict) or not bom:
            return None
        findings = [
            finding
            for finding in await self.get_vulnerabilities(client, project_uuid)
            if isinstance(finding, dict)
        ]
        if variant == VARIANT_INVENTORY:
            return build_inventory(bom, findings, property_prefix=property_prefix)

        # A finding carries a summary of its vulnerability. The complete
        # records have every CVSS version, the dates, and the recommendation.
        advisories_read = True
        try:
            advisories = await self.get_project_vulnerabilities(client, project_uuid)
            if not isinstance(advisories, list):
                raise TypeError("Unexpected vulnerability records")
            findings = complete_findings(findings, advisories)
        except Exception as exc:
            advisories_read = False
            logger.warning(
                "CycloneDX export of %s without complete vulnerability records: %s",
                project_uuid,
                exc,
            )

        findings_read_at = self.store.snapshot_updated_at(
            DocumentRef(KIND_FINDINGS, project_uuid=project_uuid)
        )
        # Every finding of the version gone now, not only those of the last
        # read, so two exports in a row agree.
        findings_gone = await asyncio.to_thread(
            self.finding_lifecycle.gone_counts, project_uuid
        )

        def assemble() -> Dict[str, Any]:
            # The version ranges as the background read stored them; an
            # export never asks the source for them.
            fixed_versions = self.store.fixed_version_entries(
                {
                    (
                        str((finding.get("vulnerability") or {}).get("source") or ""),
                        str((finding.get("vulnerability") or {}).get("vulnId") or ""),
                    )
                    for finding in findings
                }
            )
            assessments = []
            incomplete = 0
            for finding in findings:
                analysis = finding.get("analysis")
                if _is_incomplete_source_assessment(analysis):
                    incomplete += 1
                value = _source_assessment_value(analysis)
                assessments.append(
                    parse_assessment(
                        value["state"], value["details"], value["suppressed"]
                    )
                )
            document = build_vdr(
                bom,
                findings,
                assessments,
                assessment_source=assessment_source,
                property_prefix=property_prefix,
                tool_version=tool_version,
                unowned_teams=unowned_teams,
                ticket_prefixes=ticket_prefixes,
                findings_read_at=findings_read_at or "",
                fixed_versions=fixed_versions,
                findings_gone=findings_gone,
            )
            if not advisories_read:
                # Ratings, dates, and recommendations are those of the
                # findings alone: say so.
                document["metadata"]["properties"].append(
                    {
                        "name": f"{property_prefix}:export_advisory_records",
                        "value": "unavailable",
                    }
                )
            if incomplete:
                # Assessed findings whose text could not be read from the
                # source: say so instead of exporting them as if empty.
                document["metadata"]["properties"].append(
                    {
                        "name": f"{property_prefix}:export_incomplete_findings",
                        "value": str(incomplete),
                    }
                )
            return document

        return await asyncio.to_thread(assemble)

    async def _read_texts_without_state(
        self,
        client: VulnerabilitySource,
        project_uuid: str,
        findings: Any,
    ) -> None:
        """Read the text of findings that are recorded with a text and no state.

        The findings list carries the text of assessed findings only. Without
        this, the source would seem to have dropped the text of such a record
        at every import, and the record would be exported again and again.
        """
        if not isinstance(findings, list):
            return
        wanted = await asyncio.to_thread(
            self.assessment_outbox.keys_with_text_and_no_state, project_uuid
        )
        if not wanted:
            return
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            key = self._finding_analysis_key(project_uuid, finding)
            if key not in wanted:
                continue
            listed = finding.get("analysis")
            if isinstance(listed, dict) and (
                _get_analysis_state(listed) != "NOT_SET" or _get_analysis_details(listed)
            ):
                continue  # the list already says what the source holds
            try:
                analysis = await client.get_analysis(
                    project_uuid=key[0],
                    component_uuid=key[1],
                    vulnerability_uuid=key[2],
                )
            except Exception as exc:
                logger.warning(
                    "Could not read the analysis of %s/%s in %s: %s",
                    key[1], key[2], project_uuid, exc,
                )
                continue
            if isinstance(analysis, dict):
                finding["analysis"] = {
                    **(listed if isinstance(listed, dict) else {}),
                    **analysis,
                }

    async def _merge_source_assessments(
        self,
        source_analyses: Dict[AssessmentKey, Any],
        fetch_started_at: datetime,
    ) -> None:
        """Compare assessments just read from the source with the local record.

        The local database is the record. An assessment the source holds for
        a finding without a local record is adopted once; after that the
        source never changes local state. Where it holds something else, the
        local value is exported again.
        """
        remote = {
            key: _source_assessment_value(analysis)
            for key, analysis in source_analyses.items()
            if not _is_incomplete_source_assessment(analysis)
        }
        if not remote:
            return
        outcomes = await asyncio.to_thread(
            self.assessment_outbox.reconcile_remote,
            remote,
            fetched_at=fetch_started_at,
            retry_delay=export_retry_delay_seconds,
        )
        if not any(outcomes.values()):
            return
        logger.info(
            "Compared source assessments: %s",
            ", ".join(
                f"{len(keys)} {name}" for name, keys in outcomes.items() if keys
            ),
        )
        # Adopting a value does not change what is shown for the finding.
        changed = {
            key
            for name, keys in outcomes.items()
            if name != "adopted"
            for key in keys
        }
        if not changed:
            return
        async with self.lock:
            self.pending_updates = self._load_pending_updates()
            self._invalidate_cache_status()
            self._touch_cache_meta(project_uuids={key[0] for key in changed})
        self._assessment_sync_wakeup.set()
        await self._notify_assessments_changed(sorted(changed))

    def add_assessment_change_listener(
        self,
        listener: Callable[..., None],
    ) -> None:
        """Be told when a merge changed local assessments outside a save, so
        views built from them can follow. Called on a worker thread as
        ``listener(keys, value_changed=...)``; ``value_changed`` is False
        when only the sync status changed (an export)."""
        self._assessment_change_listeners.append(listener)

    async def _notify_assessments_changed(
        self, keys: List[AssessmentKey], *, value_changed: bool = True
    ) -> None:
        for listener in list(self._assessment_change_listeners):
            try:
                await asyncio.to_thread(
                    listener, keys, value_changed=value_changed
                )
            except Exception:
                logger.exception("Assessment change listener failed")

    def list_export_queue(self, *, include_texts: bool = True) -> List[Dict[str, Any]]:
        """Local assessments not yet in the source, oldest first, with what
        is needed to review them before exporting."""
        projects = {
            project.get("uuid"): project
            for project in self._load_project_cache(self._projects_path(), []) or []
            if isinstance(project, dict)
        }
        entries = self.assessment_outbox.list_pending()
        keys = [assessment_key(entry.get("payload") or {}) for entry in entries]
        described = self.store.describe_findings([key for key in keys if key])
        # Projects the source no longer lists still have a name on record.
        remembered = self.store.describe_projects(
            key[0] for key in keys if key and key[0] not in projects
        )
        queue = []
        for entry, key in zip(entries, keys):
            if key is None:
                continue
            state = self.assessment_outbox.get_overlay(key) or {}
            history = self.assessment_outbox.list_revisions(key, limit=1)
            project = projects.get(key[0]) or remembered.get(key[0]) or {}
            finding = described.get(key) or {}
            base = state.get("base")
            remote = state.get("remote")
            queue.append(
                {
                    "update_id": entry.get("id"),
                    "project_uuid": key[0],
                    "component_uuid": key[1],
                    "vulnerability_uuid": key[2],
                    # False when the project is not in the source's project
                    # list any more, the usual reason an export cannot land.
                    "project_known": key[0] in projects,
                    # When the source last listed a project it no longer has.
                    "project_last_seen_at": (
                        None
                        if key[0] in projects
                        else (remembered.get(key[0]) or {}).get("last_seen_at")
                    ),
                    "project_name": project.get("name"),
                    "project_version": project.get("version"),
                    "component_name": finding.get("component_name"),
                    "component_version": finding.get("component_version"),
                    "vulnerability_id": finding.get("vuln_id"),
                    "revision": int(entry.get("revision") or 0),
                    "status": state.get("sync_status") or "pending",
                    "queued_at": entry.get("created_at"),
                    "updated_at": entry.get("updated_at"),
                    "attempts": int(entry.get("attempts") or 0),
                    "last_error": entry.get("last_error"),
                    "author": history[0]["author"] if history else None,
                    "origin": history[0]["origin"] if history else None,
                    "local": {
                        "analysisState": state.get("analysisState"),
                        **(
                            {"analysisDetails": state.get("analysisDetails")}
                            if include_texts else {}
                        ),
                        "isSuppressed": state.get("isSuppressed"),
                    },
                    # What the export replaces, when known.
                    "source": (
                        None
                        if (remote or base) is None
                        else {
                            "analysisState": (remote or base)["state"],
                            **(
                                {"analysisDetails": (remote or base)["details"]}
                                if include_texts else {}
                            ),
                            "isSuppressed": (remote or base)["suppressed"],
                        }
                    ),
                }
            )
        return queue

    def get_assessment_history(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        *,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        return self.assessment_outbox.list_revisions(
            (project_uuid, component_uuid, vulnerability_uuid), limit=limit
        )

    def get_ticket_histories(self) -> Dict[AssessmentKey, List[Dict[str, Any]]]:
        """The versions of every assessment that ever named a ticket."""
        return self.assessment_outbox.list_ticket_histories()

    def get_assessment_fields(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        """The assessment of a finding as atomic fields; ``None`` when the
        finding has no local record."""
        return self.assessment_outbox.get_fields(
            (project_uuid, component_uuid, vulnerability_uuid)
        )

    def get_assessment_overlay(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        key = (project_uuid, component_uuid, vulnerability_uuid)
        overlay = self.assessment_outbox.get_overlay(key)
        if overlay is None:
            return None
        if (
            int(overlay.get("revision") or 0) == 0
            and overlay.get("sync_status") == "synced"
        ):
            # Adopted from the source and never changed here: the imported
            # analysis is the same value and carries the source's other
            # fields (justification, response, comments) as well.
            return None
        fields = self._overlay_fields(overlay)
        remote = overlay.get("remote")
        if remote is not None and overlay.get("sync_status") in ("pending", "error"):
            # What the source holds while the local value waits for export.
            fields["dtvpRemote"] = {
                "analysisState": remote["state"],
                "analysisDetails": remote["details"],
                "isSuppressed": remote["suppressed"],
            }
        gone = self.finding_lifecycle.gone_row(key)
        if gone is not None:
            # The source no longer reports the finding: why, and where its
            # assessment went.
            fields["dtvpGoneReason"] = gone.get("gone_reason")
            fields["dtvpSupersededBy"] = gone.get("successor_component_uuid")
        return fields

    @staticmethod
    def _overlay_fields(overlay: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "analysisState": overlay.get("analysisState") or "NOT_SET",
            "analysisDetails": overlay.get("analysisDetails") or "",
            "isSuppressed": bool(overlay.get("isSuppressed", False)),
            "dtvpRevision": int(overlay.get("revision") or 0),
            "dtvpSyncStatus": overlay.get("sync_status") or "synced",
            "dtvpUpdateId": overlay.get("update_id"),
            "dtvpSyncError": overlay.get("last_error"),
        }

    def get_cached_assessments(
        self, instances: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """The stored assessment of each finding, looked up by its
        project/component/vulnerability identity only.

        Reads local state without fetching Dependency-Track. Use this, never
        caller-supplied text, as the base of a write.
        """
        finding_analyses: dict[str, dict[tuple[str, str, str], dict]] = {}
        readers: dict[str, Callable[..., Any]] = {}
        result = []
        for instance in instances:
            key = tuple(instance[name] for name in (
                "project_uuid", "component_uuid", "vulnerability_uuid"
            ))
            analysis = self.get_assessment_overlay(*key)
            recorded = analysis is not None
            if analysis is None:
                if key[0] not in readers:
                    readers[key[0]] = self._project_analysis_reader(key[0])
                analysis = readers[key[0]](key[1], key[2], None)
            if analysis is None:
                project_uuid = key[0]
                if project_uuid not in finding_analyses:
                    findings = self._load_project_cache(self._findings_path(project_uuid), []) or []
                    finding_analyses[project_uuid] = {
                        self._finding_analysis_key(project_uuid, finding): finding.get("analysis") or {}
                        for finding in findings
                    }
                analysis = finding_analyses[project_uuid].get(key, {})
            result.append(
                {
                    "state": str(
                        analysis.get("analysisState")
                        or analysis.get("analysis_state")
                        or analysis.get("state")
                        or "NOT_SET"
                    ),
                    "details": analysis.get("analysisDetails")
                    or analysis.get("analysis_details")
                    or "",
                    "suppressed": _get_analysis_suppressed(analysis),
                    "revision": int(analysis.get("dtvpRevision") or 0),
                    "sync_status": analysis.get("dtvpSyncStatus") or "synced",
                    # Whether DTVP holds a record of the finding, as opposed
                    # to a value read from the source's findings.
                    "recorded": recorded,
                }
            )
        return result

    def get_cached_assessment_details(self, instances: List[Dict[str, Any]]) -> List[str]:
        """Read trusted metadata without fetching Dependency-Track on the write path."""
        return [
            assessment["details"]
            for assessment in self.get_cached_assessments(instances)
        ]

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
    ) -> List[Dict[str, Any]]:
        """Mark stored assessments of a finding for review where the source
        sent none, or changed a threat-model rescoring.

        Assessments of replaced findings are carried over from the record
        (``import_findings``), not from the previous snapshot.
        """
        if not findings:
            return findings

        read_analysis = self._project_analysis_reader(project_uuid)
        for finding in findings:
            source_analysis = finding.get("analysis") or {}
            analysis_key = self._finding_analysis_key(project_uuid, finding)
            if not analysis_key:
                continue

            current_path = self._analysis_path(*analysis_key)
            current_cached_analysis = read_analysis(
                analysis_key[1], analysis_key[2], None
            )

            if _get_analysis_details(source_analysis):
                if _has_meaningful_assessment(current_cached_analysis):
                    changed, previous_score, current_score = _threadmodel_score_changed(
                        current_cached_analysis, source_analysis
                    )
                    if changed:
                        marked = _mark_assessment_for_review_with_threadmodel_change(
                            source_analysis, previous_score, current_score
                        )
                        self._save_project_cache(
                            current_path,
                            marked,
                            project_uuid=project_uuid,
                        )
                        finding["analysis"] = marked
                continue

            if _has_meaningful_assessment(current_cached_analysis):
                finding["analysis"] = _mark_assessment_for_review(current_cached_analysis)

        return findings

    def _overlay_local_analysis(
        self,
        project_uuid: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        pending = self._load_pending_updates()
        read_analysis = self._project_analysis_reader(project_uuid)
        for finding in findings:
            component = finding.get("component", {})
            vulnerability = finding.get("vulnerability", {})
            comp_uuid = component.get("uuid")
            vuln_uuid = vulnerability.get("uuid")
            if comp_uuid and vuln_uuid:
                analysis = read_analysis(comp_uuid, vuln_uuid, None)
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
        author: str | None = None,
        origin: str = "user",
        seen: dict[AssessmentKey, Dict[str, Any]] | None = None,
        supersedes: dict[AssessmentKey, List[AssessmentKey]] | None = None,
        expected_records: dict[AssessmentKey, int | None] | None = None,
        skip_changed: bool = False,
    ) -> List[Dict[str, Any]]:
        """Record local assessments and queue them for export.

        ``seen`` is the value each change was made on top of, where the
        caller knows it. It is the reference for conflict detection on a
        first edit; without it the stored source value is used, which can be
        newer than what the author was looking at.

        ``supersedes`` names the records a value was carried over from; they
        become ``superseded`` in the same transaction. ``expected_records``
        and ``skip_changed`` guard against records that changed since the
        caller read them; see ``AssessmentOutboxStore.enqueue_many``.
        """
        if not payloads:
            return []
        for payload in payloads:
            # Every writer's text gets the same layout here, in place, so the
            # caller reports what was stored.
            if isinstance(payload.get("details"), str):
                payload["details"] = canonical_assessment_text(
                    payload.get("state"), payload["details"], payload.get("suppressed")
                )
        try:
            entries = await asyncio.to_thread(
                self._enqueue_with_bases,
                payloads,
                seen or {},
                replace=replace,
                expected_revisions=expected_revisions,
                author=author,
                origin=origin,
                supersedes=supersedes,
                expected_records=expected_records,
                skip_changed=skip_changed,
            )
        except AssessmentOutboxConflictError as exc:
            raise PendingUpdateExistsError(str(exc)) from exc
        async with self.lock:
            self.pending_updates = self._load_pending_updates()
            self._invalidate_cache_status()
            # A local write: the caller patches the live snapshots with it
            # (``confirm_assessment_writes_applied``); until then a snapshot
            # built before it is not reused.
            self._touch_cache_meta(
                project_uuids={
                    str(payload.get("project_uuid") or "").strip()
                    for payload in payloads
                    if str(payload.get("project_uuid") or "").strip()
                },
                assessment_keys=[
                    key for payload in payloads
                    if (key := assessment_key(payload)) is not None
                ],
            )
        self._assessment_sync_wakeup.set()
        return entries

    def _enqueue_with_bases(
        self,
        payloads: List[Dict[str, Any]],
        seen: dict[AssessmentKey, Dict[str, Any]],
        **options: Any,
    ) -> List[Dict[str, Any]]:
        """Queue local values, recording for each first-time edit what the
        source was last known to hold. A later import compares against it."""
        first_edits = [
            payload
            for payload in payloads
            if (key := assessment_key(payload)) is not None
            and self.assessment_outbox.get_overlay(key) is None
        ]
        bases = {
            assessment_key(payload): {
                "state": stored["state"],
                "details": stored["details"],
                "suppressed": stored["suppressed"],
            }
            for payload, stored in zip(
                first_edits, self.get_cached_assessments(first_edits)
            )
        }
        bases.update({key: value for key, value in seen.items() if key in bases})
        return self.assessment_outbox.enqueue_many(payloads, bases=bases, **options)

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
        await self.discard_exports([update_id])

    async def discard_exports(
        self,
        update_ids: List[str],
        *,
        author: str | None = None,
    ) -> List[AssessmentKey]:
        """Drop queued exports so they are never sent; see
        ``AssessmentOutboxStore.discard_many``."""
        keys = await asyncio.to_thread(
            self.assessment_outbox.discard_many, update_ids, author=author
        )
        if keys:
            async with self.lock:
                self.pending_updates = self._load_pending_updates()
                self._invalidate_cache_status()
                # The listeners bring the live snapshots in step.
                self._touch_cache_meta(
                    project_uuids={key[0] for key in keys}, assessment_keys=keys
                )
            await self._notify_assessments_changed(keys)
        return keys

    async def export_if_automatic(self, client: AssessmentSink) -> bool:
        """The background export step. In manual mode local changes wait
        until someone exports them; importing continues either way."""
        if get_export_mode() != EXPORT_MODE_AUTO:
            return False
        await self.flush_pending_updates(client)
        return True

    async def flush_pending_updates(
        self,
        client: AssessmentSink,
        *,
        update_ids: Set[str] | None = None,
    ) -> None:
        """Export due local assessments; ``update_ids`` limits it to a
        chosen subset of the queue."""
        async with self._assessment_sync_lock:
            pending = await asyncio.to_thread(self.assessment_outbox.list_due)
            if update_ids is not None:
                pending = [
                    entry for entry in pending if str(entry.get("id")) in update_ids
                ]
            if not pending:
                return

            next_index = 0
            saved_local = False
            exported_keys: List[AssessmentKey] = []
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
                    if self.assessment_outbox.pending_revision(key) != revision:
                        # Saved again since this batch was read: the newer
                        # value is queued and goes out with the next batch.
                        continue
                    try:
                        await client.update_analysis(
                            **with_analysis_response(payload)
                        )
                        marked = await asyncio.to_thread(
                            self.assessment_outbox.mark_synced,
                            key,
                            revision,
                        )
                        if marked:
                            async with self.lock:
                                self._save_local_analysis(payload, exported=True)
                                saved_local = True
                                exported_keys.append(key)
                        else:
                            # Saved again while the write was in flight. The
                            # source now holds this older value of ours.
                            await asyncio.to_thread(
                                self.assessment_outbox.note_exported, key, payload
                            )
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
                                        await asyncio.to_thread(
                                            self.finding_lifecycle.mark_gone,
                                            key,
                                            reason=REASON_MISSING_AT_EXPORT,
                                            at=datetime.now(timezone.utc).isoformat(),
                                        )
                                    continue
                                failure_message = (
                                    f"{exc}; Dependency-Track findings API is "
                                    "reachable and the exact finding still exists"
                                )
                        attempts = int(entry.get("attempts") or 0) + 1
                        retry_delay = export_retry_delay_seconds(attempts)
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
            if exported_keys:
                # The assessments are the same; their sync status changed.
                await self._notify_assessments_changed(
                    exported_keys, value_changed=False
                )

    def _save_local_analysis(
        self, payload: Dict[str, Any], *, exported: bool = False
    ) -> None:
        """Store what the source holds for a finding. ``exported`` says it is
        DTVP's own value that just went out: the assessment shown does not
        change, only its sync status, which the caller reports to the
        assessment change listeners. It is not an unapplied write either: a
        snapshot that shows the value stays reusable; its sync status is
        patched when the export batch ends."""
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
            # Not a source change: the value is the one already shown.
            assessment_keys=() if exported else None,
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
