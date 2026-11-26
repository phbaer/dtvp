import asyncio
import copy
import hashlib
import inspect
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Awaitable, Callable, Literal, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from .ssvc_services import (
    get_models as get_ssvc_models,
    summarize_group as summarize_ssvc_group,
)
from .ssvc_enrichment_services import get_service as get_ssvc_enrichment_service
from .evidence_services import evidence_sources

from .access_token_services import forwardable_bearer
from .cyclonedx_export import (
    DEFAULT_ASSESSMENT_SOURCE,
    DEFAULT_PROPERTY_PREFIX,
    valid_property_prefix,
    valid_ticket_prefix,
)
from .same_issue import REASON_UNKNOWN_COMPONENT, SameIssueIndex, facts_by_uuid
from .finding_lifecycle_services import (
    ORIGIN_CARRIED_OVER_BY_ALIAS,
    ORIGIN_CARRIED_OVER_BY_SAME_ISSUE,
    alias_map,
    vuln_ids_by_uuid,
    alias_proposal,
    describe_gone_findings,
    earlier_assessments,
)
from .gone_component_names import resolve_gone_component_names
from .project_archive_services import get_project_archive_path
from .team_mapping import normalize_team_values
from .version import get_app_version
from .assessment_outbox_services import AssessmentRevisionConflictError, assessment_key
from .assessment_use_cases import (
    AssessmentConflictError,
    AssessmentPermissionError,
    AssessmentRequest,
    AssessmentValidationError,
    accepted_assessment_results as _accepted_assessment_results,
    clean_up_assessment,
    delete_assessment,
    record_code_analysis_applications as _record_code_analysis_applications,
    save_assessment,
)
from .assessment_restore_services import (
    refresh_group_restore_metadata,
    update_component_restore_metadata,
)
from .assessment_snapshot_services import (
    assessment_group_index_matches,
    assessment_identity_key,
    build_assessment_group_index,
    find_assessment_group_ids,
)
from .bulk_workflows.assessment_restore import (
    build_assessment_restore_payloads as workflow_assessment_restore_payloads,
    build_assessment_restore_preview as workflow_assessment_restore_preview,
)
from .bulk_workflows.assessment_repair import create_assessment_repair_workflow
from .bulk_workflows.automatic_assessments import (
    automatic_assessment_filter_facets,
    create_automatic_assessment_workflow,
)
from .bulk_workflows.base import (
    CHANGED_SINCE_PREVIEW,
    BulkWorkflowContext,
    BulkWorkflowRegistry,
    build_preview_token,
    diff_items,
    preview_as_shown,
    group_fingerprints,
)
from .bulk_workflows.team_assessment_restore import (
    create_team_assessment_restore_workflow,
)
from .team_assessment_restore_services import (
    RestoreSourceError,
    RestoreSourceStore,
    read_assessment_history,
    read_dependency_track_vdr,
)
from .ports import AssessmentHistorySource
from . import team_assessment_restore_services
from .code_analysis_assessment_services import (
    assessment_status_for_group,
    build_assessment_match_index,
    discover_assessment_metadata,
    records_for_group,
    record_vulnerability_id,
)
from .dt_cache import get_export_mode
from .dt_client import DTClient
from .grouped_vuln_services import (
    build_grouped_vuln_statistics_rollup,
    summarize_grouped_vulnerabilities,
)
from .logic import (
    RE_SCORE,
    RE_VECTOR,
    populate_group_dependency_chains,
    sanitize_rescored_vector,
    score_to_severity,
    without_historical_blocks,
)
from .rescore_rule_services import (
    RescoreRuleError,
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
)
from .query_execution_services import QueryCapacityError, QuerySupersededError
from .first_seen import normalize_cutoff
from .task_group_query_services import (
    get_or_build_task_group_query_index,
    query_task_groups,
    split_query_values,
)
from .team_group_services import (
    team_values,
    canonical_team_group_structure,
    resolve_team_groups,
)


class AssessmentDetailsRequest(BaseModel):
    instances: list[dict]


class GoneFindingRef(BaseModel):
    component_uuid: str = Field(min_length=1, max_length=200)
    vulnerability_uuid: str = Field(min_length=1, max_length=200)


class GoneFindingsAcknowledgeRequest(BaseModel):
    project_uuid: str = Field(min_length=1, max_length=200)
    # One finding, or a whole group as the view shows it.
    findings: list[GoneFindingRef] = Field(min_length=1, max_length=20000)
    # False withdraws the acknowledgement.
    acknowledged: bool = True


class GoneFindingAliasRequest(BaseModel):
    project_uuid: str = Field(min_length=1, max_length=200)
    component_uuid: str = Field(min_length=1, max_length=200)
    # The gone finding, and its vulnerability under another id that is still
    # reported on the same component.
    vulnerability_uuid: str = Field(min_length=1, max_length=200)
    alias_vulnerability_uuid: str = Field(min_length=1, max_length=200)
    # The alias's component when the source recreated the component (same
    # identity and version, another UUID); the gone finding's otherwise.
    alias_component_uuid: str | None = Field(default=None, min_length=1, max_length=200)


class GoneFindingSameIssueRequest(BaseModel):
    project_uuid: str = Field(min_length=1, max_length=200)
    # A gone or reported finding, and the reported finding DTVP proposed it
    # to be the same issue as (no source names either as the other's alias).
    component_uuid: str = Field(min_length=1, max_length=200)
    vulnerability_uuid: str = Field(min_length=1, max_length=200)
    other_component_uuid: str = Field(min_length=1, max_length=200)
    other_vulnerability_uuid: str = Field(min_length=1, max_length=200)
    # False withdraws the confirmation.
    confirmed: bool = True


class ExportDiscardRequest(BaseModel):
    update_ids: list[str]


class AssessmentDeletionRequest(BaseModel):
    instances: list[dict]
    # A team name, "General", or omitted/null for the whole assessment.
    team: Optional[str] = None


class AssessmentCleanupRequest(BaseModel):
    # The findings to change.
    instances: list[dict]
    # "apply": give them the assessment of ``source``; "clear": remove theirs.
    action: Literal["apply", "clear"]
    # A team name, "General", or omitted/null for the whole assessment.
    team: Optional[str] = None
    # The finding whose stored assessment is kept (for "apply").
    source: Optional[dict] = None
    # "project|component|vulnerability" to the revision a preview showed.
    revisions: Optional[dict[str, int]] = None
    dry_run: bool = False


class ExportRequest(BaseModel):
    # Omit to export everything that is due.
    update_ids: Optional[list[str]] = None


class AssessmentRestoreRequest(BaseModel):
    task_id: str
    group_ids: Optional[list[str]] = None


class BulkWorkflowFilters(BaseModel):
    original_severity: list[str] = Field(default_factory=list)
    ssvc: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    q: str = ""
    lifecycle: list[str] = Field(default_factory=list)
    inconsistency_reason: list[str] = Field(default_factory=list)
    analysis: list[str] = Field(default_factory=list)
    tag: str = ""
    team: str = ""
    teams: list[str] = Field(default_factory=list)
    team_assessment: Literal["ANY", "MISSING", "DOCUMENTED"] = "ANY"
    id: str = ""
    component: str = ""
    assignee: str = ""
    dependency: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    cvss_mismatch: bool = False
    not_rescored: bool = False
    new_findings: bool = False
    awaiting_review: bool = False
    cutoff: str = ""
    cutoff_mode: Literal["before", "after"] = "before"
    # Empty: published, or attributed for the retired attribution-age filter.
    cutoff_basis: Literal["", "published", "attributed"] = ""
    # Retired (ADR 0015): read as ``cutoff=<N>d`` when no cutoff is given.
    attributed_before_days: Optional[int] = None
    attribution_mode: str = "older"

    @field_validator("cutoff")
    @classmethod
    def _valid_cutoff(cls, value: str) -> str:
        return normalize_cutoff(value)
    tmrescore: list[str] = Field(default_factory=list)
    tmrescore_proposal_ids: list[str] = Field(default_factory=list)
    automatic_assessment: list[str] = Field(default_factory=list)
    automatic_assessment_ids: list[str] = Field(default_factory=list)
    automatic_assessment_outcome: list[str] = Field(default_factory=list)
    automatic_assessment_rescore: list[str] = Field(default_factory=list)
    # One vulnerability group, by its exact id: a workflow run for that
    # vulnerability only (the card's Repair…). The other filters still apply.
    group_id: str = ""


class BulkWorkflowRequest(BaseModel):
    task_id: str
    filters: BulkWorkflowFilters = Field(default_factory=BulkWorkflowFilters)
    # An uploaded input (``POST /bulk-workflows/sources``) for a workflow
    # that reads one.
    source_id: Optional[str] = None


class BulkWorkflowApplyRequest(BulkWorkflowRequest):
    group_ids: list[str] = Field(default_factory=list)
    preview_token: str
    # Per selected group, the fingerprint of its preview item as the preview
    # showed it (``group_fingerprints`` of the preview response).
    group_fingerprints: dict[str, str] = Field(default_factory=dict)
    # The preview items the fingerprints were taken from: a refused apply
    # reports which fields of a selected group changed (never used to write).
    group_items: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Selected groups whose new findings (added by a new project version)
    # are to be synchronized too. Nothing is copied onto them otherwise.
    include_new_findings: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class GeneralApiRouteDeps:
    cache_manager: Any
    logger: Any
    tasks: dict[str, Any]
    dt_settings_cls: Callable[[], Any]
    get_dt_client_cls: Callable[[], type]
    create_tracked_task: Callable[[Any], Any]
    process_grouped_vulns_task: Callable[
        [str, str, Optional[str], DTClient, str], Awaitable[None]
    ]
    sort_projects_by_version: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    load_team_mapping: Callable[[], dict[str, Any]]
    load_team_groups: Callable[[], dict[str, Any]]
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    collect_version_snapshots: Callable[
        ...,
        Awaitable[
            tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, int]]]
        ],
    ]
    group_vulnerabilities: Callable[..., list[dict[str, Any]]]
    calculate_statistics: Callable[[list[dict[str, Any]]], dict[str, Any]]
    get_user_role: Callable[[str], str]
    fetch_current_assessment_analyses: Callable[
        [Any, DTClient], Awaitable[list[Any]]
    ]
    collect_assessment_conflicts: Callable[
        [AssessmentRequest, list[Any]], list[dict[str, Any]]
    ]
    build_assessment_payloads: Callable[
        [AssessmentRequest, str, str], list[tuple[dict, dict]]
    ]
    apply_assessment_payloads: Callable[..., Awaitable[list[dict[str, Any]]]]
    finalize_assessment_results: Callable[
        [list[dict[str, Any]]], Awaitable[list[dict[str, Any]]]
    ]
    get_bom_analysis_cache_cls: Callable[[], type]
    default_dependency_chain_limit: int
    service_unavailable_response: dict[int | str, dict[str, Any]]
    not_found_response: dict[int | str, dict[str, Any]]
    code_analysis_result_store: Any = None
    # Agent code evidence (see code_evidence_services); None disables it.
    code_evidence_store: Any = None
    # A user's read of a product renews its interest for the background sync
    # (``ProductInterest.touch``; ADR 0004, "Interest and leases").
    note_interest: Callable[[str, Optional[str]], None] = lambda *_args: None
    get_grouped_vuln_cache_revision: Callable[..., Any] = lambda **_kwargs: None
    group_query_executor: Any = None
    detail_executor: Any = None
    task_event_hub: Any = None
    # The team mapping as stored (``logic.load_team_mapping_document``): it
    # lists every team, also one without entries, for team groups and
    # aliases. ``None`` reads them from ``load_team_mapping``.
    load_team_mapping_document: Optional[Callable[[], dict[str, Any]]] = None


def _team_document(deps: Any, team_mapping: dict[str, Any]) -> dict[str, Any]:
    """The mapping that names every team: the stored document, or the
    selector mapping where the deps do not offer it."""
    load = getattr(deps, "load_team_mapping_document", None)
    return load() if callable(load) else team_mapping


_TASK_SNAPSHOT_REFRESH_LOCK = threading.RLock()
# Reading findings' assessment history for a restore: one source request per
# finding, a few at a time.
HISTORY_SOURCE_MAX_FINDINGS = 20000
HISTORY_SOURCE_CONCURRENCY = 6
TASK_EVENT_LOG_TAIL = 20


def _task_for_user(
    deps: GeneralApiRouteDeps,
    task_id: str,
    user: str,
) -> dict[str, Any] | None:
    task = deps.tasks.get(task_id)
    if not isinstance(task, dict):
        return None
    owners = task.get("_owners")
    if task.get("_owner") != user and (
        not isinstance(owners, set) or user not in owners
    ):
        return None
    task["_last_accessed_at"] = datetime.now(timezone.utc)
    return task


def _public_task_status(
    task: dict[str, Any],
    *,
    include_result: bool,
    log_limit: int | None = None,
) -> dict[str, Any]:
    payload = {
        key: value
        for key, value in task.items()
        if not key.startswith("_") and (include_result or key != "result")
    }
    log = payload.get("log")
    if log_limit is not None and isinstance(log, list) and len(log) > log_limit:
        payload["log_offset"] = len(log) - log_limit
        payload["log"] = log[-log_limit:]
    return payload


def _grouped_vuln_task_key(
    deps: GeneralApiRouteDeps,
    *,
    name: str,
    cve: Optional[str],
    response_mode: str,
) -> tuple[str, str, str, str, str]:
    cache_revision = deps.get_grouped_vuln_cache_revision(name=name)
    team_mapping = deps.load_team_mapping()
    revision_text = json.dumps(cache_revision, sort_keys=True, default=str)
    mapping_text = json.dumps(team_mapping, sort_keys=True, default=str)
    mapping_fingerprint = hashlib.sha256(mapping_text.encode("utf-8")).hexdigest()
    return (
        str(name or "").strip().lower(),
        str(cve or "").strip().lower(),
        response_mode,
        revision_text,
        mapping_fingerprint,
    )


def _grouped_vuln_task_identity(
    task_key: tuple[str, str, str, str, str],
) -> tuple[str, str, str, str]:
    return task_key[0], task_key[1], task_key[2], task_key[4]


def _finalize_grouped_vuln_task_key(
    deps: GeneralApiRouteDeps,
    task_id: str,
) -> None:
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        task = deps.tasks.get(task_id)
        task_key = task.get("_task_key") if isinstance(task, dict) else None
        if (
            not isinstance(task, dict)
            or task.get("status") != "completed"
            or not isinstance(task_key, tuple)
            or len(task_key) != 5
        ):
            return
        revision_text = json.dumps(
            deps.get_grouped_vuln_cache_revision(name=task_key[0]),
            sort_keys=True,
            default=str,
        )
        covered_at_start = _task_project_uuids(task)
        task["_task_key"] = (
            task_key[0],
            task_key[1],
            task_key[2],
            revision_text,
            task_key[4],
        )
        task["_task_key_finalized"] = True
        read_seq = getattr(_ASSESSMENT_WRITE_TRACKER, "assessment_write_seq", None)
        if (
            not _task_project_uuids(task) <= covered_at_start
            and callable(read_seq)
            and int(read_seq()) > int(task.get("_assessment_write_seq") or 0)
        ):
            # The build covers versions it did not know when it started (the
            # project list was not loaded, or a version was added), so saves
            # on them during the build did not mark it. Assume one was missed.
            task["_assessment_patch_missed"] = True
        created_at = task.get("created_at")
        logger = getattr(deps, "logger", None)
        if logger is not None and isinstance(created_at, datetime):
            logger.info(
                "Grouped snapshot of %s: built in %.1f s (task %s)",
                task_key[0] or "all projects",
                (datetime.now(timezone.utc) - created_at).total_seconds(),
                task_id,
            )


# The cache manager that knows which local assessment writes the live
# snapshots do not show yet (``CacheManager.confirm_assessment_writes_applied``).
# Without one, a snapshot is reused on its revision alone.
_ASSESSMENT_WRITE_TRACKER: Any = None


def configure_assessment_write_tracker(tracker: Any) -> None:
    global _ASSESSMENT_WRITE_TRACKER
    _ASSESSMENT_WRITE_TRACKER = tracker


def _task_project_uuids(task: dict[str, Any]) -> set[str]:
    """The project versions a grouped task covers, from its revision."""
    task_key = task.get("_task_key")
    if not isinstance(task_key, tuple) or len(task_key) != 5:
        return set()
    try:
        revision = json.loads(task_key[3])
    except (TypeError, ValueError):
        return set()
    versions = revision.get("versions") if isinstance(revision, dict) else None
    return {
        str(version[0])
        for version in versions or []
        if isinstance(version, (list, tuple)) and version and version[0]
    }


def _snapshot_lacks_assessment_write(task: dict[str, Any]) -> str | None:
    """Why a snapshot, built or still building, cannot stand for the current assessments,
    or ``None`` when it can."""
    if task.get("_assessment_patch_missed"):
        return "an assessment change could not be patched into the snapshot"
    tracker = _ASSESSMENT_WRITE_TRACKER
    check = getattr(tracker, "has_unapplied_assessment_writes", None)
    if not callable(check):
        return None
    if check(
        _task_project_uuids(task),
        after_seq=int(task.get("_assessment_write_seq") or 0),
    ):
        return "an assessment was saved that the snapshot does not show yet"
    return None


def _claim_reusable_grouped_vuln_task(
    deps: GeneralApiRouteDeps,
    *,
    task_key: tuple[str, str, str, str, str],
    user: str,
    reasons: list[str] | None = None,
) -> dict[str, Any] | None:
    """A running or current task for the same request, claimed for ``user``.
    ``reasons`` collects why snapshots of the same project were passed over."""
    task_identity = _grouped_vuln_task_identity(task_key)
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        for task in reversed(list(deps.tasks.values())):
            if not isinstance(task, dict):
                continue
            status = str(task.get("status") or "").lower()
            existing_key = task.get("_task_key")
            if not isinstance(existing_key, tuple) or len(existing_key) != 5:
                continue
            same_request = _grouped_vuln_task_identity(existing_key) == task_identity
            if status in {"pending", "running"} or (
                status == "completed" and task.get("_task_key_finalized") is not True
            ):
                # Still building, or built and not yet finalized: join it
                # unless it is already known to lack an assessment write.
                matches = same_request
            elif status == "completed":
                matches = existing_key == task_key
                if same_request and not matches and reasons is not None:
                    reasons.append("the stored source data changed")
            else:
                matches = False
            if matches:
                lacking = _snapshot_lacks_assessment_write(task)
                if lacking is not None:
                    matches = False
                    if reasons is not None:
                        reasons.append(lacking)
            if not matches:
                continue
            owners = task.setdefault(
                "_owners",
                {str(task.get("_owner") or "")},
            )
            if not isinstance(owners, set):
                owners = set(owners if isinstance(owners, (list, tuple)) else ())
                task["_owners"] = owners
            owners.add(user)
            task["_reuse_count"] = int(task.get("_reuse_count") or 0) + 1
            task["_last_accessed_at"] = datetime.now(timezone.utc)
            return task
    return None


def _assessment_identity_key(source: dict[str, Any]) -> tuple[str, str, str] | None:
    return assessment_identity_key(source)


def _build_assessment_payload_lookup(
    payloads: list[tuple[dict, dict]],
) -> tuple[
    dict[str, tuple[dict[str, Any], tuple[str, str, str] | None]],
    dict[tuple[str, str, str], dict[str, Any]],
]:
    by_finding_uuid: dict[
        str, tuple[dict[str, Any], tuple[str, str, str] | None]
    ] = {}
    by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}

    for instance, payload in payloads:
        identity = _assessment_identity_key(instance)
        finding_uuid = instance.get("finding_uuid")
        if finding_uuid:
            by_finding_uuid[str(finding_uuid)] = (payload, identity)
        if identity is not None:
            by_identity[identity] = payload

    return by_finding_uuid, by_identity


def _assessment_payload_for_component(
    component: dict[str, Any],
    by_finding_uuid: dict[str, tuple[dict[str, Any], tuple[str, str, str] | None]],
    by_identity: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    identity = _assessment_identity_key(component)
    finding_uuid = component.get("finding_uuid")
    if finding_uuid and str(finding_uuid) in by_finding_uuid:
        payload, payload_identity = by_finding_uuid[str(finding_uuid)]
        # The finding UUID comes from the caller. When both sides name a
        # project/component/vulnerability they must agree, or one finding's
        # assessment could be painted onto another in the shared snapshot.
        if payload_identity is None or identity is None or payload_identity == identity:
            return payload

    if identity is None:
        return None
    return by_identity.get(identity)


def _assessment_payload_from_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    suppressed = (
        analysis.get("isSuppressed")
        if "isSuppressed" in analysis
        else analysis.get("is_suppressed", False)
    )
    payload = {
        "state": analysis.get("analysisState")
        or analysis.get("analysis_state")
        or "NOT_SET",
        "details": analysis.get("analysisDetails")
        or analysis.get("analysis_details")
        or "",
        "suppressed": bool(suppressed),
        "justification": analysis.get("analysisJustification")
        or analysis.get("justification")
        or "NOT_SET",
    }
    if analysis.get("dtvpSyncStatus"):
        payload["sync_status"] = analysis["dtvpSyncStatus"]
        payload["source_assessment"] = analysis.get("dtvpRemote")
    return payload


def _apply_assessment_payload_to_group(
    group: dict[str, Any],
    by_finding_uuid: dict[str, dict[str, Any]],
    by_identity: dict[tuple[str, str, str], dict[str, Any]],
) -> bool:
    changed = False
    for affected_version in group.get("affected_versions") or []:
        for component in affected_version.get("components") or []:
            payload = _assessment_payload_for_component(
                component,
                by_finding_uuid,
                by_identity,
            )
            if payload is None:
                continue

            component["analysis_state"] = payload.get("state", "NOT_SET")
            component["analysis_details"] = payload.get("details", "")
            component["is_suppressed"] = bool(payload.get("suppressed", False))
            if "justification" in payload:
                component["justification"] = payload.get("justification")
            if "sync_status" in payload:
                component["sync_status"] = payload["sync_status"]
                if payload.get("source_assessment"):
                    component["source_assessment"] = payload["source_assessment"]
                else:
                    component.pop("source_assessment", None)
            update_component_restore_metadata(component)
            changed = True
    if changed:
        _refresh_group_rescoring_metadata(group)
    return changed


def _refresh_group_rescoring_metadata(group: dict[str, Any]) -> None:
    """Rebuild aggregate rescoring fields after component detail updates."""
    group["ssvc_summary"] = summarize_ssvc_group(group)
    best_score: float | None = None
    best_vector: str | None = None
    fallback_vector: str | None = None
    vector_adjusted = False
    base_vector = group.get("cvss_vector")

    for affected_version in group.get("affected_versions") or []:
        for component in affected_version.get("components") or []:
            # Historical blocks are records; they do not rescore the finding.
            details = without_historical_blocks(component.get("analysis_details") or "")
            score_match = RE_SCORE.search(details)
            vector_match = RE_VECTOR.search(details)
            score: float | None = None
            if score_match:
                try:
                    score = float(score_match.group(1))
                except ValueError:
                    score = None
            vector = vector_match.group(1).strip() if vector_match else None
            if vector and base_vector:
                sanitized = sanitize_rescored_vector(base_vector, vector)
                vector_adjusted = vector_adjusted or sanitized != vector
                vector = sanitized
            if vector and fallback_vector is None:
                fallback_vector = vector
            if score is not None and (best_score is None or score > best_score):
                best_score = score
                best_vector = vector

    group["rescored_cvss"] = best_score
    group["rescored_vector"] = best_vector or fallback_vector
    group["rescored_vector_adjusted"] = vector_adjusted
    effective_score = best_score if best_score is not None else group.get("cvss_score")
    if effective_score is not None:
        group["severity"] = score_to_severity(float(effective_score))


def _get_or_build_assessment_group_index(
    task: dict[str, Any],
    key: str,
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    index = task.get(key)
    if not assessment_group_index_matches(index, groups):
        index = build_assessment_group_index(groups)
        task[key] = index
    return index


def _prepare_grouped_task_replacements(
    groups: list[dict[str, Any]],
    index: dict[str, Any],
    group_ids: set[str],
    by_finding_uuid: dict[str, dict[str, Any]],
    by_identity: dict[tuple[str, str, str], dict[str, Any]],
    team_mapping: dict[str, Any],
) -> dict[int, tuple[dict[str, Any], dict[str, Any]]]:
    positions = index["positions"]
    candidates: list[tuple[int, dict[str, Any]]] = []
    for group_id in group_ids:
        position = positions.get(group_id)
        if not isinstance(position, int) or not 0 <= position < len(groups):
            continue
        candidate = copy.deepcopy(groups[position])
        if _apply_assessment_payload_to_group(
            candidate,
            by_finding_uuid,
            by_identity,
        ):
            refresh_group_restore_metadata(candidate)
            candidates.append((position, candidate))

    if not candidates:
        return {}

    summaries = summarize_grouped_vulnerabilities(
        [candidate for _position, candidate in candidates],
        team_mapping,
    )
    replacements: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    for (position, candidate), summary in zip(candidates, summaries):
        candidate["list_metadata"] = summary.get("list_metadata") or {}
        replacements[position] = (candidate, summary)
    return replacements


def _apply_grouped_task_replacements(
    groups: list[dict[str, Any]],
    replacements: dict[int, tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    for position, (candidate, _summary) in replacements.items():
        groups[position] = candidate


def _apply_summary_replacements(
    summaries: list[dict[str, Any]],
    replacements: dict[int, tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    fallback_positions: dict[str, int] | None = None
    for source_position, (_candidate, summary) in replacements.items():
        group_id = str(summary.get("id") or "")
        target_position = source_position
        if (
            target_position >= len(summaries)
            or summaries[target_position].get("id") != group_id
        ):
            if fallback_positions is None:
                fallback_positions = {
                    str(item.get("id")): position
                    for position, item in enumerate(summaries)
                    if item.get("id")
                }
            target_position = fallback_positions.get(group_id, -1)
        if 0 <= target_position < len(summaries):
            summaries[target_position] = summary


def _refresh_grouped_vuln_task_snapshots(
    tasks: dict[str, Any],
    payloads: list[tuple[dict, dict]],
    team_mapping: dict[str, Any],
    *,
    value_changed: bool = True,
) -> int:
    """Patch the live snapshots with these assessment changes.
    ``value_changed`` is False when only the sync status changed (an
    export): a build in progress then still shows the right assessment."""
    tracker = _ASSESSMENT_WRITE_TRACKER
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        # Read the record inside the lock: patches can run in any order,
        # and the last one must not put an older value back.
        payloads = _payloads_as_recorded(tracker, payloads)
        refreshed = _refresh_grouped_vuln_task_snapshots_locked(
            tasks,
            payloads,
            team_mapping,
            flag_running=value_changed,
        )
        # Inside the lock: a request that starts now either sees the write
        # as unapplied, or the snapshots patched.
        confirm = getattr(tracker, "confirm_assessment_writes_applied", None)
        if callable(confirm):
            confirm(
                (identity, payload)
                for instance, payload in payloads
                if (identity := _assessment_identity_key(instance)) is not None
            )
        return refreshed


def _payloads_as_recorded(
    tracker: Any,
    payloads: list[tuple[dict, dict]],
) -> list[tuple[dict, dict]]:
    """The payloads with the value and sync status on record. A payload the
    record has moved past (a later save, patched first) is replaced by the
    recorded value, so the snapshot never goes back to an older one. A save
    changes the sync status too (to pending), and the patched snapshot is
    all that shows it until the next build."""
    read = getattr(tracker, "get_assessment_overlay", None)
    if not callable(read):
        return payloads
    current = []
    for instance, payload in payloads:
        identity = _assessment_identity_key(instance)
        if identity is None:
            current.append((instance, payload))
            continue
        try:
            analysis = read(*identity)
        except Exception:
            analysis = None
        if isinstance(analysis, dict):
            recorded = _assessment_payload_from_analysis(analysis)
            if (
                recorded["state"] != str(payload.get("state") or "NOT_SET")
                or str(recorded["details"]).strip()
                != str(payload.get("details") or "").strip()
                or recorded["suppressed"] != bool(payload.get("suppressed"))
            ):
                payload = {**payload, **recorded}
            elif analysis.get("dtvpSyncStatus") and "sync_status" not in payload:
                payload = {
                    **payload,
                    "sync_status": analysis["dtvpSyncStatus"],
                    "source_assessment": analysis.get("dtvpRemote"),
                }
        current.append((instance, payload))
    return current


def _refresh_grouped_vuln_task_snapshots_locked(
    tasks: dict[str, Any],
    payloads: list[tuple[dict, dict]],
    team_mapping: dict[str, Any],
    *,
    flag_running: bool = True,
) -> int:
    refreshed = 0
    now = datetime.now(timezone.utc)
    by_finding_uuid, by_identity = _build_assessment_payload_lookup(payloads)

    changed_projects = {
        str(instance.get("project_uuid"))
        for instance, _payload in payloads
        if instance.get("project_uuid")
    }

    for task in list(tasks.values()):
        if not isinstance(task, dict):
            continue
        if (
            flag_running
            and changed_projects
            and str(task.get("status") or "").lower() in {"pending", "running"}
        ):
            covered = _task_project_uuids(task)
            # Still building: what it already read may lack this change and
            # there may be nothing to patch yet. Do not reuse it afterwards.
            # A build that started without knowing its versions (project
            # list not loaded yet) may cover any of them.
            if not covered or changed_projects & covered:
                task["_assessment_patch_missed"] = True

        for _attempt in range(3):
            full_result = task.get("_full_result")
            partial_full_result = task.get("_partial_full_result")
            result = task.get("result")
            full_replacements: dict[
                int, tuple[dict[str, Any], dict[str, Any]]
            ] = {}
            partial_replacements: dict[
                int, tuple[dict[str, Any], dict[str, Any]]
            ] = {}
            result_replacements: dict[
                int, tuple[dict[str, Any], dict[str, Any]]
            ] = {}

            if isinstance(full_result, list):
                full_index = _get_or_build_assessment_group_index(
                    task,
                    "_assessment_full_group_index",
                    full_result,
                )
                full_group_ids = find_assessment_group_ids(
                    full_index,
                    by_finding_uuid,
                    by_identity,
                )
                full_replacements = _prepare_grouped_task_replacements(
                    full_result,
                    full_index,
                    full_group_ids,
                    by_finding_uuid,
                    by_identity,
                    team_mapping,
                )

            if (
                isinstance(partial_full_result, list)
                and partial_full_result is not full_result
            ):
                partial_index = _get_or_build_assessment_group_index(
                    task,
                    "_assessment_partial_group_index",
                    partial_full_result,
                )
                partial_group_ids = find_assessment_group_ids(
                    partial_index,
                    by_finding_uuid,
                    by_identity,
                )
                partial_replacements = _prepare_grouped_task_replacements(
                    partial_full_result,
                    partial_index,
                    partial_group_ids,
                    by_finding_uuid,
                    by_identity,
                    team_mapping,
                )

            if (
                not full_replacements
                and not partial_replacements
                and isinstance(result, list)
            ):
                result_index = _get_or_build_assessment_group_index(
                    task,
                    "_assessment_result_group_index",
                    result,
                )
                result_group_ids = find_assessment_group_ids(
                    result_index,
                    by_finding_uuid,
                    by_identity,
                )
                result_replacements = _prepare_grouped_task_replacements(
                    result,
                    result_index,
                    result_group_ids,
                    by_finding_uuid,
                    by_identity,
                    team_mapping,
                )

            if not (
                full_replacements
                or partial_replacements
                or result_replacements
            ):
                break

            if (
                task.get("_full_result") is not full_result
                or task.get("_partial_full_result") is not partial_full_result
                or task.get("result") is not result
            ):
                continue

            if full_replacements and isinstance(full_result, list):
                _apply_grouped_task_replacements(
                    full_result,
                    full_replacements,
                )
                full_by_id = task.get("_full_result_by_id")
                if not isinstance(full_by_id, dict):
                    full_by_id = {
                        item.get("id"): item
                        for item in full_result
                        if item.get("id")
                    }
                    task["_full_result_by_id"] = full_by_id
                for candidate, _summary in full_replacements.values():
                    if candidate.get("id"):
                        full_by_id[candidate["id"]] = candidate
                if task.get("result_mode") == "summary":
                    if isinstance(result, list):
                        _apply_summary_replacements(result, full_replacements)
                else:
                    task["result"] = full_result
            elif partial_replacements and isinstance(partial_full_result, list):
                _apply_grouped_task_replacements(
                    partial_full_result,
                    partial_replacements,
                )
                if task.get("result_mode") == "summary":
                    if isinstance(result, list):
                        _apply_summary_replacements(result, partial_replacements)
                else:
                    task["result"] = partial_full_result
            elif result_replacements and isinstance(result, list):
                _apply_grouped_task_replacements(result, result_replacements)

            if (
                full_replacements
                and partial_replacements
                and isinstance(partial_full_result, list)
            ):
                _apply_grouped_task_replacements(
                    partial_full_result,
                    partial_replacements,
                )

            task.pop("_group_query_index", None)
            task["updated_at"] = now
            refreshed += 1
            break
        else:
            # The snapshot kept changing under the patch: it was not applied.
            task["_assessment_patch_missed"] = True

    return refreshed


def start_grouped_vuln_task(
    deps: GeneralApiRouteDeps,
    *,
    name: str,
    cve: Optional[str],
    response_mode: str,
    user: str,
    token: str | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Start the grouped-vulnerability computation for a project, or join a
    matching one. Returns ``{"task_id", "reused"}``."""
    deps.note_interest(user, name)
    task_key = _grouped_vuln_task_key(
        deps,
        name=name,
        cve=cve,
        response_mode=response_mode,
    )
    reasons: list[str] = []
    reusable_task = _claim_reusable_grouped_vuln_task(
        deps,
        task_key=task_key,
        user=user,
        reasons=reasons,
    )
    if reusable_task is not None:
        _log_grouped_snapshot_choice(deps, name, reusable_task, None)
        return {"task_id": reusable_task["id"], "reused": True}

    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    read_seq = getattr(_ASSESSMENT_WRITE_TRACKER, "assessment_write_seq", None)
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        # Recheck under the registry lock so simultaneous requests cannot
        # create duplicate computations between the first lookup and insert.
        reusable_task = _claim_reusable_grouped_vuln_task(
            deps,
            task_key=task_key,
            user=user,
        )
        if reusable_task is not None:
            _log_grouped_snapshot_choice(deps, name, reusable_task, None)
            return {"task_id": reusable_task["id"], "reused": True}
        deps.tasks[task_id] = {
            "id": task_id,
            "_owner": user,
            "_owners": {user},
            "_project_name": name,
            "_task_key": task_key,
            "_task_key_finalized": False,
            # Every local assessment write up to here is in what the build
            # reads; later ones have to be patched in.
            "_assessment_write_seq": int(read_seq()) if callable(read_seq) else 0,
            "_reuse_count": 0,
            "status": "pending",
            "message": "Starting...",
            "progress": 0,
            "created_at": now,
            "updated_at": now,
            "_last_accessed_at": now,
            "result": None,
            "log": ["Starting..."],
        }

    async def task_wrapper():
        settings = deps.dt_settings_cls()
        client_cls = deps.get_dt_client_cls()
        async with client_cls(
            settings.api_url,
            api_key=settings.api_key,
            token=token or "",
            cookies=cookies or {},
        ) as client:
            await deps.process_grouped_vulns_task(
                task_id,
                name,
                cve,
                client,
                response_mode,
            )
            _finalize_grouped_vuln_task_key(deps, task_id)

    _log_grouped_snapshot_choice(
        deps, name, None, "; ".join(dict.fromkeys(reasons)) or "no snapshot yet"
    )
    deps.create_tracked_task(task_wrapper())
    return {"task_id": task_id, "reused": False}


def _log_grouped_snapshot_choice(
    deps: GeneralApiRouteDeps,
    name: str,
    reused: dict[str, Any] | None,
    rebuild_reason: str | None,
) -> None:
    """One line per request for a project's grouped snapshot: whether an
    existing one served it, or why a new one is built."""
    logger = getattr(deps, "logger", None)
    if logger is None:
        return
    if reused is not None:
        logger.info(
            "Grouped snapshot of %s: reused task %s (%s)",
            name or "all projects", reused.get("id"), reused.get("status"),
        )
    else:
        logger.info(
            "Grouped snapshot of %s: building a new one (%s)",
            name or "all projects", rebuild_reason,
        )


def refresh_grouped_vuln_task_snapshots(
    tasks: dict[str, Any],
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    team_mapping: dict[str, Any],
) -> int:
    """Apply accepted assessment changes to the live task snapshots."""
    return _refresh_grouped_vuln_task_snapshots(tasks, payloads, team_mapping)


def refresh_task_snapshots_for_assessments(
    deps: GeneralApiRouteDeps,
    keys: list[tuple[str, str, str]],
    *,
    value_changed: bool = True,
) -> int:
    """Bring the live task snapshots up to date with the stored assessments
    of the given findings, for changes that did not come through a save.
    ``value_changed`` is False when only their sync status changed."""
    payloads = []
    for project_uuid, component_uuid, vulnerability_uuid in keys:
        analysis = deps.cache_manager.get_assessment_overlay(
            project_uuid, component_uuid, vulnerability_uuid
        )
        if analysis is None:
            continue
        payloads.append(
            (
                {
                    "project_uuid": project_uuid,
                    "component_uuid": component_uuid,
                    "vulnerability_uuid": vulnerability_uuid,
                },
                _assessment_payload_from_analysis(analysis),
            )
        )
    if not payloads:
        return 0
    return _refresh_grouped_vuln_task_snapshots(
        deps.tasks,
        payloads,
        deps.load_team_mapping(),
        value_changed=value_changed,
    )


def task_for_user(
    deps: GeneralApiRouteDeps,
    task_id: str,
    user: str,
) -> dict[str, Any] | None:
    return _task_for_user(deps, task_id, user)


def hydrate_task_group_detail(
    deps: GeneralApiRouteDeps,
    task: dict[str, Any],
    group: dict[str, Any],
) -> dict[str, Any]:
    """Full detail for one group: evidence, dependency chains, analyzer status."""
    hydrated = copy.deepcopy(group)
    hydrated["evidence_sources"] = evidence_sources(
        hydrated, get_ssvc_enrichment_service().filter_snapshot()
    )
    populate_group_dependency_chains(
        hydrated,
        task.get("_bom_cache_map") or {},
    )
    _, context = _task_group_query_context(deps, task)
    _annotate_code_assessment_status([hydrated], context["assessment_records"])
    return hydrated


GROUP_QUERY_DEFAULTS: dict[str, Any] = {
    "q": "",
    "lifecycle": [],
    "inconsistency_reason": [],
    "original_severity": [],
    "ssvc": [],
    "evidence": [],
    "analysis": [],
    "tag": "",
    "team": "",
    "teams": [],
    "team_assessment": "ANY",
    "vuln_id": "",
    "component": "",
    "assignee": "",
    "dependency": [],
    "versions": [],
    "cvss_mismatch": False,
    "not_rescored": False,
    "new_findings": False,
    "awaiting_review": False,
    "cutoff": "",
    "cutoff_mode": "before",
    "cutoff_basis": "",
    "attributed_before_days": None,
    "attribution_mode": "older",
    "tmrescore": [],
    "tmrescore_proposal_ids": [],
    "automatic_assessment": [],
    "automatic_assessment_ids": [],
    "automatic_assessment_outcome": [],
    "automatic_assessment_rescore": [],
    "sort_by": "rescored-severity",
    "sort_order": "desc",
    "offset": 0,
    "limit": 100,
    "cursor": "",
    "include_counts": True,
}


def query_task_group_window(
    deps: GeneralApiRouteDeps,
    task: dict[str, Any],
    **filters: Any,
) -> dict[str, Any]:
    """Filter, sort, and page a completed task's groups.

    Accepts the same filters as ``GET /tasks/{task_id}/groups``; anything
    omitted takes the route's default.
    """
    unknown = sorted(set(filters) - set(GROUP_QUERY_DEFAULTS))
    if unknown:
        raise ValueError(f"Unknown group filter: {', '.join(unknown)}")
    return _query_task_group_window(
        deps,
        task,
        {**copy.deepcopy(GROUP_QUERY_DEFAULTS), **filters},
    )


def _register_project_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    @router.get("/projects", responses=deps.service_unavailable_response)
    async def search_projects(
        name: Optional[str] = None,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        try:
            return await deps.cache_manager.get_projects(client, name or "")
        except Exception as exc:
            deps.logger.error("Error fetching projects from Dependency-Track: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Dependency-Track unavailable for project search. Please check DT server settings.",
            )


def _register_task_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.post("/tasks/group-vulns")
    async def start_group_vulns_task(
        name: str,
        request: Request,
        cve: Optional[str] = None,
        response_mode: str = Query("full", pattern="^(full|summary)$"),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        token = forwardable_bearer(request.headers.get("Authorization"))
        return start_grouped_vuln_task(
            deps,
            name=name,
            cve=cve,
            response_mode=response_mode,
            user=user,
            token=token,
            cookies=dict(request.cookies),
        )

    @router.get("/tasks/{task_id}")
    async def get_task_status(
        task_id: str,
        include_result: bool = True,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = _task_for_user(deps, task_id, user)
        if not task:
            return {"status": "not_found"}
        # The task lease of an open project.
        deps.note_interest(user, task.get("_project_name"))
        return _public_task_status(task, include_result=include_result)

    @router.get("/tasks/{task_id}/events")
    async def stream_task_events(
        task_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        async def event_stream():
            last_payload = ""
            while True:
                task = _task_for_user(deps, task_id, user)
                if not task:
                    payload = {"status": "not_found"}
                    version = 0
                else:
                    payload = _public_task_status(
                        task,
                        include_result=False,
                        log_limit=TASK_EVENT_LOG_TAIL,
                    )
                    version = (
                        deps.task_event_hub.version(task_id)
                        if deps.task_event_hub is not None
                        else 0
                    )

                build_payload = lambda: json.dumps(payload, default=str)
                text = (
                    deps.task_event_hub.serialized_payload(
                        task_id,
                        version,
                        build_payload,
                    )
                    if task is not None and deps.task_event_hub is not None
                    else build_payload()
                )
                if text != last_payload:
                    yield text + "\n"
                    last_payload = text

                status = str(payload.get("status") or "").lower()
                if status in {"completed", "failed", "not_found"}:
                    break
                if deps.task_event_hub is None:
                    await asyncio.sleep(1)
                    continue

                next_version = await deps.task_event_hub.wait(
                    task_id,
                    version,
                    timeout_seconds=15,
                )
                if next_version == version:
                    yield "\n"

        return StreamingResponse(
            event_stream(),
            media_type="application/x-ndjson",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @router.get("/tasks/{task_id}/groups")
    async def get_task_groups(
        task_id: str,
        q: str = "",
        lifecycle: list[str] | None = Query(default=None),
        inconsistency_reason: list[str] | None = Query(default=None),
        original_severity: list[str] | None = Query(default=None),
        ssvc: list[str] | None = Query(default=None),
        evidence: list[str] | None = Query(default=None),
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
        team: str = "",
        teams: list[str] | None = Query(default=None),
        team_assessment: str = Query("ANY", pattern="^(ANY|MISSING|DOCUMENTED)$"),
        vuln_id: str = Query("", alias="id"),
        component: str = "",
        assignee: str = "",
        dependency: list[str] | None = Query(default=None),
        versions: list[str] | None = Query(default=None),
        cvss_mismatch: bool = False,
        not_rescored: bool = False,
        new_findings: bool = False,
        awaiting_review: bool = False,
        cutoff: str = "",
        cutoff_mode: str = Query("before", pattern="^(before|after)$"),
        cutoff_basis: str = Query("", pattern="^(|published|attributed)$"),
        attributed_before_days: int | None = Query(default=None, ge=1),
        attribution_mode: str = Query("older", pattern="^(older|younger)$"),
        tmrescore: list[str] | None = Query(default=None),
        tmrescore_proposal_ids: list[str] | None = Query(default=None),
        automatic_assessment: list[str] | None = Query(default=None),
        automatic_assessment_ids: list[str] | None = Query(default=None),
        automatic_assessment_outcome: list[str] | None = Query(default=None),
        automatic_assessment_rescore: list[str] | None = Query(default=None),
        sort: str = Query("rescored-severity"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        offset: int = Query(0, ge=0),
        cursor: str = "",
        limit: int = Query(100, ge=1, le=1000),
        include_counts: bool = True,
        generation: int = Query(0, ge=0),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        is_partial_summary = (
            task.get("result_mode") == "summary"
            and task.get("partial_result_available")
            and task.get("_group_query_index") is not None
        )
        if task.get("status") != "completed" and not is_partial_summary:
            raise HTTPException(status_code=409, detail="Task is not completed")

        try:
            query_args = (
                deps,
                task,
                {
                    "q": q,
                    "lifecycle": split_query_values(lifecycle),
                    "inconsistency_reason": split_query_values(
                        inconsistency_reason
                    ),
                    "original_severity": split_query_values(original_severity),
                    "ssvc": split_query_values(ssvc),
                    "evidence": split_query_values(evidence),
                    "analysis": split_query_values(analysis),
                    "tag": tag,
                    "team": team,
                    "teams": teams or [],
                    "team_assessment": team_assessment,
                    "vuln_id": vuln_id,
                    "component": component,
                    "assignee": assignee,
                    "dependency": split_query_values(dependency),
                    "versions": split_query_values(versions),
                    "cvss_mismatch": cvss_mismatch,
                    "not_rescored": not_rescored,
                    "new_findings": new_findings,
                    "awaiting_review": awaiting_review,
                    "cutoff": cutoff,
                    "cutoff_mode": cutoff_mode,
                    "cutoff_basis": cutoff_basis,
                    "attributed_before_days": attributed_before_days,
                    "attribution_mode": attribution_mode,
                    "tmrescore": split_query_values(tmrescore),
                    "tmrescore_proposal_ids": split_query_values(
                        tmrescore_proposal_ids
                    ),
                    "automatic_assessment": split_query_values(
                        automatic_assessment
                    ),
                    "automatic_assessment_ids": split_query_values(
                        automatic_assessment_ids
                    ),
                    "automatic_assessment_outcome": split_query_values(
                        automatic_assessment_outcome
                    ),
                    "automatic_assessment_rescore": split_query_values(
                        automatic_assessment_rescore
                    ),
                    "sort_by": sort,
                    "sort_order": order,
                    "offset": offset,
                    "limit": limit,
                    "cursor": cursor,
                    "include_counts": include_counts,
                },
            )
            if deps.group_query_executor is None:
                response = await asyncio.to_thread(
                    _query_task_group_window,
                    *query_args,
                )
            else:
                response = await deps.group_query_executor.run(
                    _query_task_group_window,
                    *query_args,
                    key=(user, task_id, "groups"),
                    generation=generation,
                )
        except QuerySupersededError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except QueryCapacityError as exc:
            raise HTTPException(
                status_code=429,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        response["result_mode"] = task.get("result_mode")
        response["partial"] = task.get("status") != "completed"
        response["partial_versions_completed"] = task.get("partial_versions_completed")
        response["partial_total_versions"] = task.get("partial_total_versions")
        response["partial_publish_in_progress"] = task.get(
            "partial_publish_in_progress"
        )
        response["versions_completed"] = task.get("versions_completed")
        response["versions_total"] = task.get("versions_total")
        return response

    @router.get("/tasks/{task_id}/group-details")
    async def get_task_group_details_window(
        task_id: str,
        q: str = "",
        lifecycle: list[str] | None = Query(default=None),
        inconsistency_reason: list[str] | None = Query(default=None),
        original_severity: list[str] | None = Query(default=None),
        ssvc: list[str] | None = Query(default=None),
        evidence: list[str] | None = Query(default=None),
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
        team: str = "",
        teams: list[str] | None = Query(default=None),
        team_assessment: str = Query("ANY", pattern="^(ANY|MISSING|DOCUMENTED)$"),
        vuln_id: str = Query("", alias="id"),
        component: str = "",
        assignee: str = "",
        dependency: list[str] | None = Query(default=None),
        versions: list[str] | None = Query(default=None),
        cvss_mismatch: bool = False,
        not_rescored: bool = False,
        new_findings: bool = False,
        awaiting_review: bool = False,
        cutoff: str = "",
        cutoff_mode: str = Query("before", pattern="^(before|after)$"),
        cutoff_basis: str = Query("", pattern="^(|published|attributed)$"),
        attributed_before_days: int | None = Query(default=None, ge=1),
        attribution_mode: str = Query("older", pattern="^(older|younger)$"),
        tmrescore: list[str] | None = Query(default=None),
        tmrescore_proposal_ids: list[str] | None = Query(default=None),
        automatic_assessment: list[str] | None = Query(default=None),
        automatic_assessment_ids: list[str] | None = Query(default=None),
        automatic_assessment_outcome: list[str] | None = Query(default=None),
        automatic_assessment_rescore: list[str] | None = Query(default=None),
        sort: str = Query("rescored-severity"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        offset: int = Query(0, ge=0),
        cursor: str = "",
        limit: int = Query(100, ge=1, le=1000),
        include_counts: bool = True,
        generation: int = Query(0, ge=0),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.get("status") != "completed":
            raise HTTPException(status_code=409, detail="Task is not completed")

        try:
            query_args = (
                deps,
                task,
                {
                    "q": q,
                    "lifecycle": split_query_values(lifecycle),
                    "inconsistency_reason": split_query_values(
                        inconsistency_reason
                    ),
                    "original_severity": split_query_values(original_severity),
                    "ssvc": split_query_values(ssvc),
                    "evidence": split_query_values(evidence),
                    "analysis": split_query_values(analysis),
                    "tag": tag,
                    "team": team,
                    "teams": teams or [],
                    "team_assessment": team_assessment,
                    "vuln_id": vuln_id,
                    "component": component,
                    "assignee": assignee,
                    "dependency": split_query_values(dependency),
                    "versions": split_query_values(versions),
                    "cvss_mismatch": cvss_mismatch,
                    "not_rescored": not_rescored,
                    "new_findings": new_findings,
                    "awaiting_review": awaiting_review,
                    "cutoff": cutoff,
                    "cutoff_mode": cutoff_mode,
                    "cutoff_basis": cutoff_basis,
                    "attributed_before_days": attributed_before_days,
                    "attribution_mode": attribution_mode,
                    "tmrescore": split_query_values(tmrescore),
                    "tmrescore_proposal_ids": split_query_values(
                        tmrescore_proposal_ids
                    ),
                    "automatic_assessment": split_query_values(
                        automatic_assessment
                    ),
                    "automatic_assessment_ids": split_query_values(
                        automatic_assessment_ids
                    ),
                    "automatic_assessment_outcome": split_query_values(
                        automatic_assessment_outcome
                    ),
                    "automatic_assessment_rescore": split_query_values(
                        automatic_assessment_rescore
                    ),
                    "sort_by": sort,
                    "sort_order": order,
                    "offset": offset,
                    "limit": limit,
                    "cursor": cursor,
                    "include_counts": include_counts,
                },
            )
            if deps.group_query_executor is None:
                response = await asyncio.to_thread(
                    _query_task_group_window,
                    *query_args,
                    hydrate_full=True,
                )
            else:
                response = await deps.group_query_executor.run(
                    _query_task_group_window,
                    *query_args,
                    hydrate_full=True,
                    key=(user, task_id, "group-details"),
                    generation=generation,
                )
        except QuerySupersededError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except QueryCapacityError as exc:
            raise HTTPException(
                status_code=429,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        response["result_mode"] = "full"
        response["source_result_mode"] = task.get("result_mode")
        return response

    @router.get("/tasks/{task_id}/groups/{group_id:path}")
    async def get_task_group_detail(
        task_id: str,
        group_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        full_by_id = task.get("_full_result_by_id") or {}
        group = full_by_id.get(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="Vulnerability group not found")

        def hydrate_group_detail() -> dict[str, Any]:
            return hydrate_task_group_detail(deps, task, group)

        if deps.detail_executor is None:
            return await asyncio.to_thread(hydrate_group_detail)
        return await deps.detail_executor.run(hydrate_group_detail)

    @router.get("/tasks/{task_id}/statistics")
    async def get_task_statistics(
        task_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.get("status") != "completed":
            raise HTTPException(status_code=409, detail="Task is not completed")

        grouped = task.get("_full_result")
        if not isinstance(grouped, list):
            grouped = task.get("result") if isinstance(task.get("result"), list) else []

        stats = await asyncio.to_thread(deps.calculate_statistics, grouped)
        stats.update(task.get("_statistics_rollup") or {})
        return stats


def _register_statistics_route(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    @router.get("/statistics", responses=deps.service_unavailable_response)
    async def get_statistics(
        name: Optional[str] = None,
        cve: Optional[str] = None,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        try:
            projects = await deps.cache_manager.get_projects(client, name or "")
        except Exception as exc:
            deps.logger.error("Error fetching projects from Dependency-Track: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Dependency-Track unavailable when fetching statistics. Please verify DT server is reachable.",
            )

        versions = [p for p in projects if p.get("name") == name] if name else projects
        if not versions:
            return {
                "severity_counts": {},
                "state_counts": {},
                "total_unique": 0,
                "total_findings": 0,
                "affected_projects_count": 0,
                "version_counts": {},
            }

        versions = deps.sort_projects_by_version(versions)
        team_mapping = deps.load_team_mapping()
        (
            combined_data,
            bom_cache_map,
            version_severity_counts,
        ) = await deps.collect_version_snapshots(
            versions,
            client,
            cve,
            team_mapping,
        )
        version_counts = {
            entry["version"].get("version"): len(entry["vulnerabilities"])
            for entry in combined_data
        }
        grouped = deps.group_vulnerabilities(
            combined_data, project_boms={}, processed_boms=bom_cache_map
        )
        stats = deps.calculate_statistics(grouped)
        stats.update(
            build_grouped_vuln_statistics_rollup(
                versions,
                combined_data,
                version_counts,
                version_severity_counts,
            )
        )
        return stats


def _completed_task_full_groups(
    deps: GeneralApiRouteDeps,
    task_id: str,
    user: str,
) -> list[dict[str, Any]]:
    task = _task_for_user(deps, task_id, user)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Task is not completed")

    full_result = task.get("_full_result")
    if isinstance(full_result, list):
        return full_result
    result = task.get("result")
    if isinstance(result, list) and task.get("result_mode") != "summary":
        return result
    raise HTTPException(status_code=409, detail="Full task result is unavailable")


def _assessment_filter_ids(
    records: list[dict[str, Any]],
    requested_ids: list[str] | None = None,
) -> list[str]:
    """Return metadata-backed IDs while retaining older API clients' hints."""
    return sorted(
        {
            normalized
            for value in [
                *(requested_ids or []),
                *(record_vulnerability_id(record) for record in records),
            ]
            if (normalized := str(value or "").strip().lower())
        }
    )


def _team_alias_map(team_mapping: dict[str, Any]) -> dict[str, str]:
    """Team or alias (lower case) to its team, from either mapping format."""
    aliases: dict[str, str] = {}
    for raw_value in team_values(team_mapping):
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        teams = [
            str(value or "").strip()
            for value in values
            if str(value or "").strip()
        ]
        if not teams:
            continue
        primary = teams[0]
        for team in teams:
            aliases.setdefault(team.lower(), primary)
    return aliases


def _configured_rescore_rules(deps: Any) -> dict[str, Any]:
    """Rescore rules are optional; a deployment without them simply skips them."""
    load_rescore_rules = getattr(deps, "load_rescore_rules", None)
    if not callable(load_rescore_rules):
        return {}
    return load_rescore_rules() or {}


def _stable_query_context_digest(*values: Any) -> str:
    payload = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _assessment_metadata_revision(result_store: Any) -> int | None:
    revision = getattr(result_store, "get_assessment_metadata_revision", None)
    if not callable(revision):
        return 0 if result_store is None else None
    try:
        return int(revision())
    except (TypeError, ValueError):
        return None


def _automatic_assessment_filter_facets(
    group_index: dict[str, Any],
    records: list[dict[str, Any]],
    rescore_rules: dict[str, Any] | None = None,
) -> dict[str, dict[str, str]]:
    record_index = build_assessment_match_index(records)
    facets: dict[str, dict[str, str]] = {}
    for row in group_index.get("rows") or []:
        group = row.get("group") if isinstance(row, dict) else None
        if not isinstance(group, dict):
            continue
        group_id = str(group.get("id") or "").strip().lower()
        if not group_id:
            continue
        matched_records = records_for_group(group, records, record_index)
        classification = automatic_assessment_filter_facets(
            group,
            matched_records,
            rescore_rules,
        )
        if classification is not None:
            facets[group_id] = classification
    return facets


def _task_group_query_context(
    deps: GeneralApiRouteDeps,
    task: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    group_index = get_or_build_task_group_query_index(task)
    rescore_rules = _configured_rescore_rules(deps)
    load_team_mapping = getattr(deps, "load_team_mapping", None)
    team_mapping = load_team_mapping() if callable(load_team_mapping) else {}
    load_team_groups = getattr(deps, "load_team_groups", None)
    team_group_config = load_team_groups() if callable(load_team_groups) else {}
    assessment_revision = _assessment_metadata_revision(
        deps.code_analysis_result_store
    )
    team_document = _team_document(deps, team_mapping)
    config_digest = _stable_query_context_digest(
        rescore_rules,
        team_mapping,
        team_document,
        team_group_config,
    )
    cache_key = (id(group_index), assessment_revision, config_digest)
    context_lock = task.setdefault("_group_query_context_lock", threading.RLock())

    with context_lock:
        cached = task.get("_group_query_context")
        if (
            assessment_revision is not None
            and isinstance(cached, dict)
            and cached.get("cache_key") == cache_key
        ):
            return group_index, cached

        assessment_records = discover_assessment_metadata(
            deps.code_analysis_result_store,
            project_name=task.get("_project_name") or None,
        )
        assessment_facets = _automatic_assessment_filter_facets(
            group_index,
            assessment_records,
            rescore_rules,
        )
        try:
            team_groups = resolve_team_groups(
                team_group_config,
                team_document,
            )
            team_group_structure = canonical_team_group_structure(
                team_group_config,
                team_document,
            )
        except ValueError as exc:
            deps.logger.warning(
                "Ignoring invalid team group configuration: %s",
                exc,
            )
            team_groups = {}
            team_group_structure = {}

        context = {
            "cache_key": cache_key,
            "dynamic_context_key": (
                _stable_query_context_digest(
                    id(group_index),
                    assessment_revision,
                    config_digest,
                )
                if assessment_revision is not None
                else ""
            ),
            "assessment_records": assessment_records,
            "assessment_facets": assessment_facets,
            "team_aliases": _team_alias_map(team_document),
            "team_groups": team_groups,
            "team_group_structure": team_group_structure,
        }
        if assessment_revision is not None:
            task["_group_query_context"] = context
        return group_index, context


def _annotate_code_assessment_status(
    groups: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    record_index = build_assessment_match_index(records)
    for group in groups:
        if not isinstance(group, dict):
            continue
        group["code_assessment_status"] = assessment_status_for_group(
            group,
            records,
            record_index,
        )


def _query_task_group_window(
    deps: GeneralApiRouteDeps,
    task: dict[str, Any],
    query_options: dict[str, Any],
    *,
    hydrate_full: bool = False,
) -> dict[str, Any]:
    group_index, context = _task_group_query_context(deps, task)
    assessment_records = context["assessment_records"]
    options = dict(query_options)
    requested_assessment_ids = options.pop("automatic_assessment_ids", [])
    options["automatic_assessment_ids"] = _assessment_filter_ids(
        assessment_records,
        requested_assessment_ids,
    )
    assessment_facets = context["assessment_facets"]
    options["automatic_assessment_facets"] = assessment_facets
    options["team_aliases"] = context["team_aliases"]
    options["team_groups"] = context["team_groups"]
    options["team_group_structure"] = context["team_group_structure"]
    options["dynamic_context_key"] = context["dynamic_context_key"]
    response = query_task_groups(
        group_index,
        **options,
    )
    if hydrate_full:
        full_by_id = task.get("_full_result_by_id") or {}
        response["items"] = [
            {**full_by_id.get(item.get("id"), item), "evidence_sources": item.get("evidence_sources", [])}
            if isinstance(item, dict)
            else item
            for item in response["items"]
        ]
    else:
        response["items"] = [
            dict(item) if isinstance(item, dict) else item
            for item in response["items"]
        ]
    _annotate_code_assessment_status(response["items"], assessment_records)
    for item in response["items"]:
        if not isinstance(item, dict):
            continue
        facets = assessment_facets.get(
            str(item.get("id") or "").strip().lower()
        )
        item["automatic_assessment_outcome"] = (
            facets.get("outcome") if facets else None
        )
        item["automatic_assessment_rescore"] = (
            facets.get("rescore") if facets else None
        )
    return response


def _filter_bulk_workflow_groups(
    groups: list[dict[str, Any]] | dict[str, Any],
    filters: BulkWorkflowFilters,
    team_aliases: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    result = query_task_groups(
        groups,
        q=filters.q,
        team_aliases=team_aliases,
        lifecycle=filters.lifecycle,
        inconsistency_reason=filters.inconsistency_reason,
        original_severity=filters.original_severity,
        ssvc=filters.ssvc,
        evidence=filters.evidence,
        analysis=filters.analysis,
        tag=filters.tag,
        team=filters.team,
        teams=filters.teams,
        team_assessment=filters.team_assessment,
        vuln_id=filters.id,
        component=filters.component,
        assignee=filters.assignee,
        dependency=filters.dependency,
        versions=filters.versions,
        cvss_mismatch=filters.cvss_mismatch,
        not_rescored=filters.not_rescored,
        new_findings=filters.new_findings,
        awaiting_review=filters.awaiting_review,
        cutoff=filters.cutoff,
        cutoff_mode=filters.cutoff_mode,
        cutoff_basis=filters.cutoff_basis,
        attributed_before_days=filters.attributed_before_days,
        attribution_mode=filters.attribution_mode,
        tmrescore=filters.tmrescore,
        tmrescore_proposal_ids=filters.tmrescore_proposal_ids,
        automatic_assessment=filters.automatic_assessment,
        automatic_assessment_ids=filters.automatic_assessment_ids,
        automatic_assessment_outcome=filters.automatic_assessment_outcome,
        automatic_assessment_rescore=filters.automatic_assessment_rescore,
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=max(
            1,
            int(groups.get("total") or 0)
            if isinstance(groups, dict)
            else len(groups),
        ),
        include_counts=False,
    )
    return result["items"]


def _filter_bulk_workflow_task_groups(
    deps: GeneralApiRouteDeps,
    task_id: str,
    filters: BulkWorkflowFilters,
    user: str,
    assessment_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    full_groups = _completed_task_full_groups(deps, task_id, user)
    task = _task_for_user(deps, task_id, user)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    summary_index = get_or_build_task_group_query_index(task)
    assessment_filter = {
        str(value or "").strip().upper()
        for value in filters.automatic_assessment
        if str(value or "").strip()
    }
    assessment_outcome_filter = {
        str(value or "").strip().upper()
        for value in filters.automatic_assessment_outcome
        if str(value or "").strip()
    }
    assessment_rescore_filter = {
        str(value or "").strip().upper()
        for value in filters.automatic_assessment_rescore
        if str(value or "").strip()
    }
    base_filters = filters.model_copy(
        update={
            "automatic_assessment": [],
            "automatic_assessment_ids": [],
            "automatic_assessment_outcome": [],
            "automatic_assessment_rescore": [],
        }
    )
    load_team_mapping = getattr(deps, "load_team_mapping", None)
    team_mapping = load_team_mapping() if callable(load_team_mapping) else {}
    filtered_summaries = _filter_bulk_workflow_groups(
        summary_index, base_filters,
        team_aliases=_team_alias_map(_team_document(deps, team_mapping)),
    )
    if filters.group_id:
        filtered_summaries = [
            summary
            for summary in filtered_summaries
            if str(summary.get("id") or "") == filters.group_id
        ]
    full_group_lookup = task.get("_full_result_by_id")
    if not isinstance(full_group_lookup, dict):
        full_group_lookup = {
            str(group.get("id") or ""): group
            for group in full_groups
            if str(group.get("id") or "")
        }
    filtered_groups = []
    for summary in filtered_summaries:
        full_group = full_group_lookup.get(str(summary.get("id") or ""))
        if full_group is None:
            continue
        list_metadata = summary.get("list_metadata")
        filtered_groups.append(
            {
                **full_group,
                **(
                    {"list_metadata": dict(list_metadata)}
                    if isinstance(list_metadata, dict)
                    else {}
                ),
            }
        )
    if (
        not assessment_filter
        and not assessment_outcome_filter
        and not assessment_rescore_filter
    ):
        return filtered_groups
    records = assessment_records or []
    record_index = build_assessment_match_index(records)
    result: list[dict[str, Any]] = []
    for group in filtered_groups:
        matched_records = records_for_group(group, records, record_index)
        facets = automatic_assessment_filter_facets(
            group,
            matched_records,
            _configured_rescore_rules(deps),
        )
        has_assessment = facets is not None
        if assessment_filter and not (
            (
                "WITH_AUTOMATIC_ASSESSMENT" in assessment_filter
                and has_assessment
            )
            or (
                "WITHOUT_AUTOMATIC_ASSESSMENT" in assessment_filter
                and not has_assessment
            )
        ):
            continue
        if (
            assessment_outcome_filter
            and (
                facets is None
                or facets["outcome"] not in assessment_outcome_filter
            )
        ):
            continue
        if (
            assessment_rescore_filter
            and (
                facets is None
                or facets["rescore"] not in assessment_rescore_filter
            )
        ):
            continue
        result.append(group)
    return result


def _bulk_workflow_registry(
    load_rescore_rules_or_raise: Callable[[], dict[str, Any]],
) -> BulkWorkflowRegistry:
    return BulkWorkflowRegistry(
        [
            create_automatic_assessment_workflow(),
            create_assessment_repair_workflow(load_rescore_rules_or_raise),
            create_team_assessment_restore_workflow(),
        ]
    )


def _bulk_workflow_context(
    deps: GeneralApiRouteDeps,
    req: BulkWorkflowRequest,
    user: str,
    workflow_id: str,
    source: Any = None,
) -> BulkWorkflowContext:
    needs_assessment_records = (
        workflow_id == "automatic-assessments"
        or bool(req.filters.automatic_assessment)
        or bool(req.filters.automatic_assessment_outcome)
        or bool(req.filters.automatic_assessment_rescore)
    )
    assessment_diagnostics: dict[str, int] = {}
    assessment_records = (
        discover_assessment_metadata(
            deps.code_analysis_result_store,
            assessment_diagnostics,
        )
        if needs_assessment_records
        else None
    )
    return BulkWorkflowContext(
        task_id=req.task_id,
        groups=_filter_bulk_workflow_task_groups(
            deps,
            req.task_id,
            req.filters,
            user,
            assessment_records,
        ),
        user=user,
        team_mapping=deps.load_team_mapping(),
        rescore_rules=_configured_rescore_rules(deps),
        result_store=deps.code_analysis_result_store,
        assessment_records=assessment_records,
        assessment_diagnostics=assessment_diagnostics,
        ticket_histories=getattr(deps.cache_manager, "get_ticket_histories", None),
        source=source,
        include_new_findings=frozenset(
            str(group_id) for group_id in getattr(req, "include_new_findings", None) or []
        ),
        stored_assessments=getattr(deps.cache_manager, "get_cached_assessments", None),
        unknown_component_records=getattr(
            deps.cache_manager, "unknown_component_records", None
        ),
    )


async def _apply_bulk_workflow_payloads(
    deps: GeneralApiRouteDeps,
    client: DTClient,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    author: str | None = None,
    progress_callback: Callable[[int, int, dict[str, Any]], Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    persisted, payloads, changed = await _persist_local_assessment_payloads(
        deps, payloads, author=author
    )

    try:
        await asyncio.to_thread(
            _refresh_grouped_vuln_task_snapshots,
            deps.tasks,
            payloads,
            deps.load_team_mapping(),
        )
    except Exception:
        deps.logger.exception("Failed to refresh grouped task snapshots after bulk workflow")

    finalized = _accepted_assessment_results(payloads, persisted)
    if progress_callback is not None:
        for completed, result in enumerate(finalized, start=1):
            callback_result = progress_callback(completed, len(finalized), result)
            if inspect.isawaitable(callback_result):
                await callback_result
    outcome = {
        "succeeded": 0,
        "queued": sum(1 for result in finalized if result.get("queued")),
        "failed": 0,
    }
    if changed:
        outcome[CHANGED_SINCE_PREVIEW] = changed
    return finalized, outcome


async def _persist_local_assessment_payloads(
    deps: GeneralApiRouteDeps,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    author: str | None = None,
) -> tuple[
    list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any]]], int
]:
    """Persist bulk payloads; returns what was stored, the payloads it was
    stored for, and how many were left out as changed since the preview.

    A payload carrying ``expected_revision`` is written only while its
    finding still has that revision. One that no longer has it is left out
    and the rest is written: a bulk write never replaces a save made after
    its preview.
    """
    # A payload may name its own origin (a carried assessment keeps the
    # carry's origin, as when applied one by one); the rest are the
    # workflow's. One write per origin.
    by_origin: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for item in payloads:
        by_origin.setdefault(str(item[1].pop("origin", None) or "bulk-workflow"), []).append(item)
    if len(by_origin) > 1:
        all_persisted: list[dict[str, Any]] = []
        all_written: list[tuple[dict[str, Any], dict[str, Any]]] = []
        all_changed = 0
        for origin, items in by_origin.items():
            persisted, written, changed = await _persist_local_assessment_payloads(
                deps, [(i, {**p, "origin": origin}) for i, p in items], author=author
            )
            all_persisted += persisted
            all_written += written
            all_changed += changed
        return all_persisted, all_written, all_changed
    origin = next(iter(by_origin), "bulk-workflow")
    expected: dict[tuple[str, str, str], int] = {}
    for _instance, payload in payloads:
        revision = payload.pop("expected_revision", None)
        key = assessment_key(payload)
        if revision is not None and key is not None:
            expected[key] = int(revision)
    persist = getattr(deps.cache_manager, "persist_assessment_updates", None)
    if callable(persist):
        remaining = list(payloads)
        changed = 0
        # Each conflict removes one payload, so this ends.
        while True:
            try:
                # The reviewer who applied the workflow is the author of each change.
                persisted = await persist(
                    [payload for _instance, payload in remaining],
                    replace=True,
                    origin=origin,
                    author=author,
                    **({"expected_revisions": expected} if expected else {}),
                )
            except AssessmentRevisionConflictError as exc:
                kept = [item for item in remaining if assessment_key(item[1]) != exc.key]
                if len(kept) == len(remaining):
                    raise
                changed += len(remaining) - len(kept)
                remaining = kept
                if not remaining:
                    return [], [], changed
                continue
            return persisted, remaining, changed

    raw_payloads = [payload for _instance, payload in payloads]
    bulk_queue = getattr(deps.cache_manager, "queue_analysis_updates", None)
    if callable(bulk_queue):
        update_ids = await bulk_queue(raw_payloads, replace=True)
        return [
            {
                "id": update_id,
                "revision": 0,
                "payload": payload,
            }
            for update_id, payload in zip(update_ids, raw_payloads)
        ], payloads, 0
    raise RuntimeError("Assessment cache does not support durable updates")


def _create_bulk_workflow_task(
    deps: GeneralApiRouteDeps,
    *,
    kind: str,
    source_task_id: str,
    workflow_id: str,
    user: str,
) -> dict[str, Any]:
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    message = f"Queued bulk workflow {kind}."
    task = {
        "id": task_id,
        "kind": f"bulk_workflow_{kind}",
        "source_task_id": source_task_id,
        "workflow_id": workflow_id,
        "created_by": user,
        "_owner": user,
        "status": "pending",
        "message": message,
        "progress": 0,
        "created_at": now,
        "updated_at": now,
        "result": None,
        "log": [message],
    }
    deps.tasks[task_id] = task
    return task


def _update_bulk_workflow_task(
    task: dict[str, Any],
    *,
    status: str | None = None,
    message: str | None = None,
    progress: int | None = None,
    result: Any = None,
    error: str | None = None,
    error_detail: Any = None,
    append_log: bool = True,
) -> None:
    now = datetime.now(timezone.utc)
    if status is not None:
        task["status"] = status
    if message is not None:
        task["message"] = message
        if append_log:
            task.setdefault("log", []).append(message)
    if progress is not None:
        task["progress"] = progress
    if result is not None:
        task["result"] = result
    if error is not None:
        task["error"] = error
    if error_detail is not None:
        task["error_detail"] = error_detail
    task["updated_at"] = now
    if status in {"completed", "failed"}:
        task["completed_at"] = now


def _bulk_workflow_task_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return str(exc) or exc.__class__.__name__


def check_preview(
    plugin: Any,
    req: BulkWorkflowApplyRequest,
    filter_payload: dict[str, Any],
    preview: dict[str, Any],
    verb: str,
) -> list[str]:
    """The selected groups, if the preview still holds for them. The
    task, filters and file must be those of the preview; each selected
    group must still be selectable and unchanged since the preview
    showed it. Other groups may have changed (the background sync writes
    all the time): they are not checked."""
    expected = build_preview_token(
        plugin,
        task_id=req.task_id,
        filter_payload=filter_payload,
    )
    if req.preview_token != expected:
        raise HTTPException(
            status_code=409,
            detail=f"Bulk workflow preview is stale; reload it before {verb}.",
        )
    selected = list(dict.fromkeys(req.group_ids))
    selectable = set(plugin.selectable_ids(preview))
    current = group_fingerprints(preview)
    given = req.group_fingerprints or {}
    changed = [
        group_id
        for group_id in selected
        if group_id not in selectable
        or given.get(group_id) is None
        or current.get(group_id) != given[group_id]
    ]
    if changed:
        now_items = {
            str(item.get("group_id") or item.get("id") or ""): item
            for item in preview.get("items") or []
        }
        seen_items = req.group_items or {}
        raise HTTPException(
            status_code=409,
            detail={
                "code": "preview_changed",
                "message": (
                    f"{len(changed)} selected group(s) changed since the preview; "
                    f"reload it before {verb}."
                ),
                "changed_groups": changed,
                # Per changed group, the fields that differ from the item the
                # preview showed (empty when the request did not send items).
                "changes": {
                    group_id: diff_items(seen_items.get(group_id), now_items.get(group_id))
                    for group_id in changed
                    if group_id in seen_items or group_id in now_items
                },
            },
        )
    return selected


def _bulk_workflow_error_detail(exc: Exception) -> dict[str, Any] | None:
    """The structured part of an error (e.g. the groups that changed since
    the preview), for the client to act on."""
    if isinstance(exc, HTTPException) and isinstance(exc.detail, dict):
        return exc.detail
    return None


def _register_bulk_workflow_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    def require_reviewer(user: str) -> None:
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")

    def load_rescore_rules_or_raise() -> dict[str, Any]:
        rules = deps.load_rescore_rules()
        if not rules:
            raise HTTPException(status_code=409, detail="Rescore rules are not configured")
        return rules

    registry = _bulk_workflow_registry(load_rescore_rules_or_raise)
    # Uploaded inputs of workflows that read one; memory only, per user.
    source_store = RestoreSourceStore()

    def resolve_source(plugin: Any, req: BulkWorkflowRequest, user: str) -> Any:
        if plugin.source_kind is None:
            return None
        if not req.source_id:
            raise HTTPException(
                status_code=409,
                detail="This bulk workflow needs an uploaded export; upload it first.",
            )
        source = source_store.get(user, req.source_id)
        if source is None:
            raise HTTPException(
                status_code=404, detail="Uploaded export not found; upload it again"
            )
        return source

    def token_filters(req: BulkWorkflowRequest, source: Any) -> dict[str, Any]:
        filters = req.filters.model_dump()
        if source is None:
            return filters
        # Another file gives another token: a preview of one file cannot be
        # applied with another.
        return {**filters, "source_sha256": source.sha256}

    async def workflow_context(
        plugin: Any, req: BulkWorkflowRequest, user: str
    ) -> tuple[BulkWorkflowContext, Any]:
        source = resolve_source(plugin, req, user)
        context = await asyncio.to_thread(
            _bulk_workflow_context,
            deps,
            req,
            user,
            plugin.id,
            source,
        )
        return context, source

    async def prepare_preview_response(
        plugin: Any,
        req: BulkWorkflowRequest,
        user: str,
    ) -> dict[str, Any]:
        context, source = await workflow_context(plugin, req, user)
        preview = await asyncio.to_thread(plugin.preview, context)
        return {
            "task_id": req.task_id,
            "workflow": plugin.metadata(),
            "preview_token": build_preview_token(
                plugin,
                task_id=req.task_id,
                filter_payload=token_filters(req, source),
            ),
            "group_fingerprints": group_fingerprints(preview),
            "selectable_group_ids": plugin.selectable_ids(preview),
            **preview,
        }

    async def prepare_apply_response(
        plugin: Any,
        req: BulkWorkflowApplyRequest,
        user: str,
        client: DTClient,
        progress_callback: Callable[[int, int, dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        context, source = await workflow_context(plugin, req, user)
        # The check is against the preview as shown (see preview_as_shown).
        shown = await asyncio.to_thread(plugin.preview, preview_as_shown(context))
        selected = check_preview(plugin, req, token_filters(req, source), shown, "applying")
        payloads, skipped = await asyncio.to_thread(
            plugin.build_payloads,
            context,
            selected,
        )
        finalized, outcome = await _apply_bulk_workflow_payloads(
            deps,
            client,
            payloads,
            author=user,
            progress_callback=progress_callback,
        )
        await asyncio.to_thread(
            _record_code_analysis_applications,
            deps,
            payloads=payloads,
            finalized=finalized,
            user=user,
            workflow_id=plugin.id,
        )
        summary = {
            "selected_groups": len(selected),
            "attempted": len(payloads),
            **outcome,
            **skipped,
        }
        if CHANGED_SINCE_PREVIEW in outcome and CHANGED_SINCE_PREVIEW in skipped:
            summary[CHANGED_SINCE_PREVIEW] = (
                outcome[CHANGED_SINCE_PREVIEW] + skipped[CHANGED_SINCE_PREVIEW]
            )
        return {
            "task_id": req.task_id,
            "workflow": plugin.metadata(),
            "summary": summary,
            "results": finalized,
        }

    async def prepare_document(
        plugin: Any,
        req: BulkWorkflowApplyRequest,
        user: str,
    ) -> str:
        if plugin.document_builder is None:
            raise HTTPException(
                status_code=409, detail="This bulk workflow does not provide a document"
            )
        context, source = await workflow_context(plugin, req, user)
        shown = await asyncio.to_thread(plugin.preview, preview_as_shown(context))
        selected = check_preview(plugin, req, token_filters(req, source), shown, "exporting")
        return await asyncio.to_thread(
            plugin.build_document,
            context,
            selected,
        )

    @router.post("/bulk-workflows/sources")
    async def upload_bulk_workflow_source(
        file: Annotated[UploadFile, File(...)],
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Read an export for a workflow that needs one; held in memory only."""
        require_reviewer(user)
        limit = team_assessment_restore_services.TEAM_RESTORE_MAX_UPLOAD_BYTES
        content = await file.read(limit + 1)
        if len(content) > limit:
            raise HTTPException(
                status_code=413,
                detail=f"The export is larger than {limit // (1024 * 1024)} MiB.",
            )
        try:
            source = await asyncio.to_thread(read_dependency_track_vdr, content)
        except RestoreSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        source_id = source_store.put(user, source)
        return {
            "source_id": source_id,
            "summary": source.summary(),
            "entries": len(source.entries),
            "team_blocks": source.team_blocks,
        }

    @router.post("/bulk-workflows/sources/history-task")
    async def start_history_source(
        req: BulkWorkflowRequest,
        request: Request,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Read the assessment history of every finding in view from the
        source, as the input of a restore; a polled task. The result is the
        same as an upload's."""
        require_reviewer(user)
        groups = _filter_bulk_workflow_task_groups(deps, req.task_id, req.filters, user)
        findings = [
            {**instance, "vuln_id": group.get("id")}
            for group in groups
            for version in group.get("affected_versions") or []
            for instance in version.get("components") or []
            if isinstance(instance, dict)
            and all(instance.get(key) for key in ("project_uuid", "component_uuid", "vulnerability_uuid"))
        ]
        if len(findings) > HISTORY_SOURCE_MAX_FINDINGS:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"{len(findings)} findings are in view; read the history of at most "
                    f"{HISTORY_SOURCE_MAX_FINDINGS} at a time (filter first)."
                ),
            )
        settings = deps.dt_settings_cls()
        token = forwardable_bearer(request.headers.get("Authorization"))
        cookies = dict(request.cookies)
        operation = _create_bulk_workflow_task(
            deps, kind="source", source_task_id=req.task_id, workflow_id="", user=user,
        )

        async def run() -> None:
            _update_bulk_workflow_task(
                operation, status="running",
                message=f"Reading the history of {len(findings)} findings...", progress=5,
            )
            try:
                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url, api_key=settings.api_key, token=token or "", cookies=cookies,
                ) as client:
                    if not isinstance(client, AssessmentHistorySource):
                        raise HTTPException(
                            status_code=422, detail="The source keeps no assessment history."
                        )
                    limit = asyncio.Semaphore(HISTORY_SOURCE_CONCURRENCY)
                    done = 0
                    failed = 0

                    async def read(instance: dict[str, Any]):
                        nonlocal done, failed
                        async with limit:
                            try:
                                history = await client.get_assessment_history(
                                    instance["project_uuid"],
                                    instance["component_uuid"],
                                    instance["vulnerability_uuid"],
                                )
                            except Exception:
                                failed += 1
                                history = []
                        done += 1
                        if done % 50 == 0 or done == len(findings):
                            _update_bulk_workflow_task(
                                operation,
                                message=f"Read the history of {done} of {len(findings)} findings.",
                                progress=5 + int(90 * done / max(1, len(findings))),
                                append_log=done == len(findings),
                            )
                        return instance, history

                    histories = await asyncio.gather(*(read(item) for item in findings))
                source = read_assessment_history(
                    list(histories),
                    read_at=datetime.now(timezone.utc).isoformat(),
                    failed=failed,
                )
                source_id = source_store.put(user, source)
                _update_bulk_workflow_task(
                    operation, status="completed", message="The history is read.", progress=100,
                    result={
                        "source_id": source_id,
                        "summary": source.summary(),
                        "entries": len(source.entries),
                        "team_blocks": source.team_blocks,
                    },
                )
            except Exception as exc:
                deps.logger.exception("Reading the assessment history failed")
                _update_bulk_workflow_task(
                    operation, status="failed", message="Reading the history failed.",
                    progress=100, error=_bulk_workflow_task_error(exc),
                )

        deps.create_tracked_task(run())
        return {"task_id": operation["id"]}

    @router.post("/bulk-workflows/summary")
    async def bulk_workflow_summary(
        req: BulkWorkflowRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        # Resolving the task also rejects unknown or unfinished ones.
        _completed_task_full_groups(deps, req.task_id, user)
        workflows = [
            {
                **plugin.metadata(),
                "candidate_count": None,
                "summary": {},
            }
            for plugin in registry.all()
        ]
        return {
            "task_id": req.task_id,
            "workflows": workflows,
        }

    @router.post("/bulk-workflows/{workflow_id}/preview")
    async def preview_bulk_workflow(
        workflow_id: str,
        req: BulkWorkflowRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        return await prepare_preview_response(plugin, req, user)

    @router.post("/bulk-workflows/{workflow_id}/apply")
    async def apply_bulk_workflow(
        workflow_id: str,
        req: BulkWorkflowApplyRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        return await prepare_apply_response(plugin, req, user, client)

    @router.post("/bulk-workflows/{workflow_id}/document")
    async def build_bulk_workflow_document(
        workflow_id: str,
        req: BulkWorkflowApplyRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        document = await prepare_document(plugin, req, user)
        return PlainTextResponse(
            document,
            media_type="text/markdown",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{plugin.id}-tickets.md"'
                )
            },
        )

    @router.get("/bulk-workflows/tasks/{operation_id}")
    async def get_bulk_workflow_task(
        operation_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        operation = _task_for_user(deps, operation_id, user)
        if not operation or not str(operation.get("kind", "")).startswith(
            "bulk_workflow_"
        ):
            raise HTTPException(status_code=404, detail="Bulk workflow task not found")
        return {
            key: value
            for key, value in operation.items()
            if not str(key).startswith("_")
        }

    @router.post("/bulk-workflows/{workflow_id}/preview-task")
    async def start_bulk_workflow_preview(
        workflow_id: str,
        req: BulkWorkflowRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        _completed_task_full_groups(deps, req.task_id, user)
        resolve_source(plugin, req, user)  # reject a missing upload up front
        operation = _create_bulk_workflow_task(
            deps,
            kind="preview",
            source_task_id=req.task_id,
            workflow_id=workflow_id,
            user=user,
        )

        async def run_preview() -> None:
            _update_bulk_workflow_task(
                operation,
                status="running",
                message="Preparing bulk workflow preview...",
                progress=10,
            )
            try:
                result = await prepare_preview_response(plugin, req, user)
                _update_bulk_workflow_task(
                    operation,
                    status="completed",
                    message="Bulk workflow preview is ready.",
                    progress=100,
                    result=result,
                )
            except Exception as exc:
                deps.logger.exception("Bulk workflow preview failed")
                _update_bulk_workflow_task(
                    operation,
                    status="failed",
                    message="Bulk workflow preview failed.",
                    progress=100,
                    error=_bulk_workflow_task_error(exc),
                )

        deps.create_tracked_task(run_preview())
        return {"task_id": operation["id"]}

    @router.post("/bulk-workflows/{workflow_id}/apply-task")
    async def start_bulk_workflow_apply(
        workflow_id: str,
        req: BulkWorkflowApplyRequest,
        request: Request,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        _completed_task_full_groups(deps, req.task_id, user)
        resolve_source(plugin, req, user)  # reject a missing upload up front
        settings = deps.dt_settings_cls()
        token = forwardable_bearer(request.headers.get("Authorization"))
        cookies = dict(request.cookies)
        operation = _create_bulk_workflow_task(
            deps,
            kind="apply",
            source_task_id=req.task_id,
            workflow_id=workflow_id,
            user=user,
        )

        async def run_apply() -> None:
            _update_bulk_workflow_task(
                operation,
                status="running",
                message="Applying selected bulk workflow changes...",
                progress=10,
            )
            try:
                progress_counts = {"succeeded": 0, "failed": 0}
                last_progress = 10

                def update_progress(
                    completed: int,
                    total: int,
                    result: dict[str, Any],
                ) -> None:
                    nonlocal last_progress
                    outcome_key = (
                        "succeeded"
                        if result.get("status") == "success"
                        else "failed"
                    )
                    progress_counts[outcome_key] += 1
                    progress = 20 + int(70 * completed / max(1, total))
                    if progress <= last_progress and completed < total:
                        return
                    last_progress = progress
                    _update_bulk_workflow_task(
                        operation,
                        message=(
                            f"Submitted {completed} of {total} assessment updates "
                            f"({progress_counts['succeeded']} succeeded, "
                            f"{progress_counts['failed']} awaiting durable fallback)."
                        ),
                        progress=progress,
                        append_log=(completed == total or progress % 10 == 0),
                    )

                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url,
                    api_key=settings.api_key,
                    token=token or "",
                    cookies=cookies,
                ) as client:
                    result = await prepare_apply_response(
                        plugin,
                        req,
                        user,
                        client,
                        progress_callback=update_progress,
                    )
                _update_bulk_workflow_task(
                    operation,
                    status="completed",
                    message="Bulk workflow changes were applied.",
                    progress=100,
                    result=result,
                )
            except Exception as exc:
                deps.logger.exception("Bulk workflow apply failed")
                _update_bulk_workflow_task(
                    operation,
                    status="failed",
                    message="Bulk workflow apply failed.",
                    progress=100,
                    error=_bulk_workflow_task_error(exc),
                    error_detail=_bulk_workflow_error_detail(exc),
                )

        deps.create_tracked_task(run_apply())
        return {"task_id": operation["id"]}

    @router.post("/bulk-workflows/{workflow_id}/document-task")
    async def start_bulk_workflow_document(
        workflow_id: str,
        req: BulkWorkflowApplyRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        plugin = registry.get(workflow_id)
        if plugin is None:
            raise HTTPException(status_code=404, detail="Bulk workflow not found")
        if plugin.document_builder is None:
            raise HTTPException(
                status_code=409,
                detail="This bulk workflow does not provide a document",
            )
        _completed_task_full_groups(deps, req.task_id, user)
        resolve_source(plugin, req, user)  # reject a missing upload up front
        operation = _create_bulk_workflow_task(
            deps,
            kind="document",
            source_task_id=req.task_id,
            workflow_id=workflow_id,
            user=user,
        )

        async def run_document() -> None:
            _update_bulk_workflow_task(
                operation,
                status="running",
                message="Building the ticket document...",
                progress=10,
            )
            try:
                result = await prepare_document(plugin, req, user)
                _update_bulk_workflow_task(
                    operation,
                    status="completed",
                    message="Ticket document is ready.",
                    progress=100,
                    result=result,
                )
            except Exception as exc:
                deps.logger.exception("Bulk workflow document export failed")
                _update_bulk_workflow_task(
                    operation,
                    status="failed",
                    message="Ticket document export failed.",
                    progress=100,
                    error=_bulk_workflow_task_error(exc),
                    error_detail=_bulk_workflow_error_detail(exc),
                )

        deps.create_tracked_task(run_document())
        return {"task_id": operation["id"]}


def _register_assessment_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    @router.get("/ssvc/models")
    async def ssvc_models(user: Annotated[str, Depends(current_user_dependency)]):
        return {"models": get_ssvc_models()}

    @router.get("/ssvc/exploitation")
    async def ssvc_exploitation(
        user: Annotated[str, Depends(current_user_dependency)],
        cve: Annotated[list[str], Query(max_length=20)] = [],
        refresh: bool = False,
    ):
        try:
            return await get_ssvc_enrichment_service().lookup(cve, force=refresh)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    def load_rescore_rules_or_raise() -> dict[str, Any]:
        rules = deps.load_rescore_rules()
        if not rules:
            raise HTTPException(status_code=409, detail="Rescore rules are not configured")
        return rules

    @router.post("/assessments/details")
    async def get_assessment_details(
        req: AssessmentDetailsRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.logger.info(
            "Fetching assessment details for %d instances (User: %s)",
            len(req.instances),
            user,
        )
        gathered_results = await deps.fetch_current_assessment_analyses(
            req,
            client,
        )

        results = []
        refreshed_payloads: list[tuple[dict, dict]] = []
        for instance, result in zip(req.instances, gathered_results):
            result_item = {
                "finding_uuid": instance.get("finding_uuid"),
                "project_uuid": instance.get("project_uuid"),
                "component_uuid": instance.get("component_uuid"),
                "vulnerability_uuid": instance.get("vulnerability_uuid"),
                "analysis": None,
                "error": None,
            }
            if isinstance(result, Exception):
                deps.logger.error(
                    "Error fetching analysis for %s: %s",
                    instance.get("finding_uuid"),
                    result,
                )
                result_item["error"] = str(result)
            else:
                result_item["analysis"] = result
                if isinstance(result, dict):
                    refreshed_payloads.append(
                        (instance, _assessment_payload_from_analysis(result))
                    )
            results.append(result_item)

        if refreshed_payloads:
            try:
                refreshed_tasks = await asyncio.to_thread(
                    _refresh_grouped_vuln_task_snapshots,
                    deps.tasks,
                    refreshed_payloads,
                    deps.load_team_mapping(),
                )
                if refreshed_tasks:
                    deps.logger.info(
                        "Refreshed %d grouped vulnerability task snapshot(s) "
                        "after assessment detail reload",
                        refreshed_tasks,
                    )
            except Exception:
                deps.logger.exception(
                    "Failed to refresh grouped vulnerability task snapshots "
                    "after assessment detail reload"
                )

        return results

    @router.post("/assessment/delete")
    async def delete_assessment_route(
        req: AssessmentDeletionRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Delete one team's assessment of the given findings, or all of it.
        The deletion is exported like any other change."""

        async def refresh_task_snapshots(
            payloads: list[tuple[dict[str, Any], dict[str, Any]]],
        ) -> None:
            try:
                await asyncio.to_thread(
                    _refresh_grouped_vuln_task_snapshots,
                    deps.tasks,
                    payloads,
                    deps.load_team_mapping(),
                )
            except Exception:
                deps.logger.exception(
                    "Failed to refresh task snapshots after assessment deletion"
                )

        try:
            results = await delete_assessment(
                deps,
                req.instances,
                team=req.team,
                user=user,
                after_persist=refresh_task_snapshots,
            )
        except AssessmentConflictError as exc:
            return JSONResponse(
                status_code=409,
                content={"status": "conflict", "conflicts": exc.conflicts},
            )
        except AssessmentPermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except AssessmentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deps.logger.info(
            "%s deleted %s for %d finding(s)",
            user,
            "the whole assessment" if req.team is None else f"the {req.team} assessment",
            len(results),
        )
        return results

    @router.post("/assessment/cleanup")
    async def clean_up_assessment_route(
        req: AssessmentCleanupRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Make the findings of a vulnerability agree: give the selected ones
        the assessment of one finding, or remove theirs, for one team, the
        Global assessment, or the whole assessment. With ``dry_run`` nothing
        is written and every finding's before and after is returned."""

        async def refresh_task_snapshots(
            payloads: list[tuple[dict[str, Any], dict[str, Any]]],
        ) -> None:
            try:
                await asyncio.to_thread(
                    _refresh_grouped_vuln_task_snapshots,
                    deps.tasks,
                    payloads,
                    deps.load_team_mapping(),
                )
            except Exception:
                deps.logger.exception(
                    "Failed to refresh task snapshots after assessment cleanup"
                )

        try:
            results = await clean_up_assessment(
                deps,
                req.instances,
                action=req.action,
                team=req.team,
                source=req.source,
                user=user,
                revisions=req.revisions,
                dry_run=req.dry_run,
                after_persist=refresh_task_snapshots,
            )
        except AssessmentConflictError as exc:
            return JSONResponse(
                status_code=409,
                content={"status": "conflict", "conflicts": exc.conflicts},
            )
        except AssessmentPermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except AssessmentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not req.dry_run:
            deps.logger.info(
                "%s cleaned up %s for %d finding(s) (%s)",
                user,
                "the whole assessment" if req.team is None else f"the {req.team} assessment",
                len(results),
                req.action,
            )
        return results

    @router.get("/export")
    async def get_export_queue(
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Local assessments waiting for export, for review. The texts of an
        entry are fetched separately; a long queue would carry megabytes."""
        queue = await asyncio.to_thread(
            deps.cache_manager.list_export_queue, include_texts=False
        )
        return {
            "mode": get_export_mode(),
            "pending": queue,
        }

    @router.get("/export/texts")
    async def get_export_texts(
        update_id: str,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """The text a queued export would write and the text it replaces."""
        queue = await asyncio.to_thread(deps.cache_manager.list_export_queue)
        entry = next((item for item in queue if item["update_id"] == update_id), None)
        if entry is None:
            raise HTTPException(status_code=404, detail="No such queued export")
        return {
            "update_id": update_id,
            "local": entry["local"],
            "source": entry["source"],
        }

    @router.post("/export")
    async def export_assessments(
        req: ExportRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Export queued assessments now: all of them, or the chosen ones.
        Conflicting findings are skipped until they are resolved."""
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(
                status_code=403, detail="Only reviewers can export assessments"
            )
        before = await asyncio.to_thread(deps.cache_manager.list_export_queue)
        requested = (
            None if req.update_ids is None else {str(value) for value in req.update_ids}
        )
        deps.logger.info(
            "%s requested an export of %s queued assessment(s)",
            user,
            "all" if requested is None else len(requested),
        )

        def considered(queue: list[dict], chosen: set[str] | None) -> list[dict]:
            return [
                item for item in queue if chosen is None or item["update_id"] in chosen
            ]

        await deps.cache_manager.flush_pending_updates(client, update_ids=requested)
        after = await asyncio.to_thread(deps.cache_manager.list_export_queue)
        exported = dropped = 0
        for item in considered(before, requested):
            overlay = deps.cache_manager.get_assessment_overlay(
                item["project_uuid"],
                item["component_uuid"],
                item["vulnerability_uuid"],
            ) or {}
            if overlay.get("dtvpRevision") != item["revision"]:
                continue  # changed again meanwhile; still in the queue
            if overlay.get("dtvpSyncStatus") == "synced":
                exported += 1
            elif overlay.get("dtvpSyncStatus") == "inactive":
                dropped += 1
        return {
            # The source now holds the value.
            "exported": exported,
            # The source no longer has the finding; the assessment is kept.
            "dropped": dropped,
            "remaining": len(after),
            "failed": [
                {
                    "update_id": item["update_id"],
                    "status": item["status"],
                    "error": item["last_error"],
                }
                for item in considered(after, requested)
                if item["status"] == "error"
            ],
        }

    @router.post("/export/discard")
    async def discard_exports(
        req: ExportDiscardRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Drop queued exports so they are never sent, for example for a
        project that no longer exists in the source."""
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(
                status_code=403, detail="Only reviewers can discard exports"
            )
        if not req.update_ids:
            raise HTTPException(status_code=422, detail="Name the exports to discard")
        keys = await deps.cache_manager.discard_exports(
            [str(value) for value in req.update_ids], author=user
        )
        deps.logger.info(
            "%s discarded %d of %d requested queued export(s)",
            user,
            len(keys),
            len(req.update_ids),
        )
        return {
            "discarded": len(keys),
            "remaining": len(
                await asyncio.to_thread(deps.cache_manager.list_export_queue)
            ),
        }

    @router.get("/assessments/history")
    async def get_assessment_history(
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        limit: int = Query(50, ge=1, le=500),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Every local value a finding's assessment has had, newest first."""
        return await asyncio.to_thread(
            deps.cache_manager.get_assessment_history,
            project_uuid,
            component_uuid,
            vulnerability_uuid,
            limit=limit,
        )

    @router.get("/assessments/fields")
    async def get_assessment_fields(
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """A finding's assessment as atomic fields: state, suppression, review
        status, rescoring, and one entry per team."""
        fields = await asyncio.to_thread(
            deps.cache_manager.get_assessment_fields,
            project_uuid,
            component_uuid,
            vulnerability_uuid,
        )
        if fields is None:
            raise HTTPException(
                status_code=404, detail="No assessment is recorded for this finding"
            )
        return fields

    @router.post("/assessments/restore-preview")
    async def preview_assessment_restore(
        req: AssessmentRestoreRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")

        groups = _completed_task_full_groups(deps, req.task_id, user)
        preview = workflow_assessment_restore_preview(groups, req.group_ids)
        return {"task_id": req.task_id, **preview}

    @router.post("/assessments/rescore-rule-preview")
    async def preview_rescore_rule_sync(
        req: AssessmentRestoreRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")

        groups = _completed_task_full_groups(deps, req.task_id, user)
        try:
            preview = build_rescore_rule_sync_preview(
                groups,
                load_rescore_rules_or_raise(),
                req.group_ids,
            )
        except RescoreRuleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"task_id": req.task_id, **preview}

    @router.post("/assessments/rescore-rule-apply")
    async def apply_rescore_rule_sync(
        req: AssessmentRestoreRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")

        groups = _completed_task_full_groups(deps, req.task_id, user)
        try:
            payloads, skipped = build_rescore_rule_sync_payloads(
                groups,
                load_rescore_rules_or_raise(),
                req.group_ids,
            )
        except RescoreRuleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        finalized, outcome = await _apply_bulk_workflow_payloads(
            deps,
            client,
            payloads,
            author=user,
        )
        return {
            "task_id": req.task_id,
            "summary": {
                "attempted": len(payloads),
                **outcome,
                **skipped,
            },
            "results": finalized,
        }

    @router.post("/assessments/restore-apply")
    async def apply_assessment_restore(
        req: AssessmentRestoreRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")

        groups = _completed_task_full_groups(deps, req.task_id, user)
        payloads, skipped = workflow_assessment_restore_payloads(groups, req.group_ids)
        finalized, outcome = await _apply_bulk_workflow_payloads(
            deps,
            client,
            payloads,
            author=user,
        )
        return {
            "task_id": req.task_id,
            "summary": {
                "attempted": len(payloads),
                **outcome,
                **skipped,
            },
            "results": finalized,
        }

    @router.post("/assessment")
    async def update_assessment(
        req: AssessmentRequest,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.logger.info(
            "Update assessment request from %s for %d instances",
            user,
            len(req.instances),
        )
        deps.logger.info(
            "State: %s, Suppressed: %s, Force: %s, Original Analysis Provided: %s",
            req.state,
            req.suppressed,
            req.force,
            bool(req.original_analysis),
        )

        async def refresh_task_snapshots(
            payloads: list[tuple[dict[str, Any], dict[str, Any]]],
        ) -> None:
            try:
                refreshed_tasks = await asyncio.to_thread(
                    _refresh_grouped_vuln_task_snapshots,
                    deps.tasks,
                    payloads,
                    deps.load_team_mapping(),
                )
                if refreshed_tasks:
                    deps.logger.info(
                        "Refreshed %d grouped vulnerability task snapshot(s) "
                        "after assessment update",
                        refreshed_tasks,
                    )
            except Exception:
                deps.logger.exception(
                    "Failed to refresh grouped vulnerability task snapshots "
                    "after assessment update"
                )

        try:
            return await save_assessment(
                deps,
                req,
                user=user,
                client=client,
                after_persist=refresh_task_snapshots,
            )
        except AssessmentConflictError as exc:
            return JSONResponse(
                status_code=409,
                content={"status": "conflict", "conflicts": exc.conflicts},
            )
        except AssessmentPermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except AssessmentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


def _register_dependency_route(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    client_dependency: Callable[..., Any],
) -> None:
    @router.get("/project/{project_uuid}/component/{component_uuid}/dependency-chains")
    async def get_dependency_chains(
        project_uuid: str,
        component_uuid: str,
        limit: Annotated[
            int, Query(ge=1, le=1000)
        ] = deps.default_dependency_chain_limit,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
    ):
        bom = await deps.cache_manager.get_bom(client, project_uuid)
        if not bom:
            return []
        team_mapping = deps.load_team_mapping()
        processor = deps.get_bom_analysis_cache_cls()(bom, team_mapping)
        return processor.get_dependency_paths(
            component_uuid,
            component_name="",
            max_paths=limit,
        )


def cyclonedx_defaults() -> tuple[str, str]:
    """Configured name of DTVP's own rating source and property namespace."""
    return (
        os.getenv("DTVP_CYCLONEDX_ASSESSMENT_SOURCE", "").strip()
        or DEFAULT_ASSESSMENT_SOURCE,
        os.getenv("DTVP_CYCLONEDX_PROPERTY_PREFIX", "").strip()
        or DEFAULT_PROPERTY_PREFIX,
    )


def cyclonedx_ticket_prefixes(value: str | None = None) -> tuple[str, ...]:
    """Project keys of ticket references, as requested or configured."""
    text = value if value is not None and value.strip() else os.getenv(
        "DTVP_CYCLONEDX_TICKET_PREFIXES", ""
    )
    return tuple(dict.fromkeys(part.strip() for part in text.split(",") if part.strip()))


def _register_cyclonedx_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    async def export(
        client: DTClient,
        project_uuid: str,
        variant: str,
        assessment_source: str | None,
        property_prefix: str | None,
        ticket_prefixes: str | None,
        download: bool,
        label: str,
    ) -> Response:
        default_source, default_prefix = cyclonedx_defaults()
        source = (assessment_source or "").strip() or default_source
        prefix = (property_prefix or "").strip() or default_prefix
        if not valid_property_prefix(prefix):
            raise HTTPException(
                status_code=422,
                detail="property_prefix may contain letters, digits, '.', '_' and '-'",
            )
        tickets = cyclonedx_ticket_prefixes(ticket_prefixes)
        if not all(valid_ticket_prefix(item) for item in tickets):
            raise HTTPException(
                status_code=422,
                detail="ticket_prefixes is a comma-separated list of project keys "
                "(a letter, then letters, digits and '_')",
            )
        # The names the team mapping gives to components no team owns.
        load_team_mapping = getattr(deps, "load_team_mapping", None)
        team_mapping = load_team_mapping() if callable(load_team_mapping) else {}
        unowned = normalize_team_values((team_mapping or {}).get("*"))
        try:
            document = await deps.cache_manager.export_cyclonedx(
                client,
                project_uuid,
                variant,
                assessment_source=source,
                property_prefix=prefix,
                tool_version=get_app_version(),
                unowned_teams=unowned,
                ticket_prefixes=tickets,
            )
        except Exception as exc:
            deps.logger.error("CycloneDX export of %s failed: %s", project_uuid, exc)
            raise HTTPException(
                status_code=503,
                detail="The project could not be read from Dependency-Track "
                "and is not stored locally.",
            ) from exc
        if document is None:
            raise HTTPException(
                status_code=404, detail="No BOM is stored for this project version"
            )
        headers = {}
        if download:
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("_") or project_uuid
            headers["Content-Disposition"] = (
                f'attachment; filename="{safe}.{variant}.cdx.json"'
            )
        return Response(
            content=json.dumps(document, ensure_ascii=False),
            media_type="application/vnd.cyclonedx+json",
            headers=headers,
        )

    @router.get("/project/{project_uuid}/cyclonedx")
    async def get_project_cyclonedx(
        project_uuid: str,
        variant: str = Query("vdr", pattern="^(inventory|vdr)$"),
        assessment_source: str | None = Query(None, max_length=200),
        property_prefix: str | None = Query(None, max_length=100),
        ticket_prefixes: str | None = Query(None, max_length=500),
        download: bool = False,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """CycloneDX of one project version: ``inventory`` (the BOM) or
        ``vdr`` (the BOM with every finding and its assessment)."""
        return await export(
            client, project_uuid, variant, assessment_source, property_prefix,
            ticket_prefixes, download, project_uuid,
        )

    @router.get("/cyclonedx")
    async def get_named_cyclonedx(
        name: str,
        version: str,
        variant: str = Query("vdr", pattern="^(inventory|vdr)$"),
        assessment_source: str | None = Query(None, max_length=200),
        property_prefix: str | None = Query(None, max_length=100),
        ticket_prefixes: str | None = Query(None, max_length=500),
        download: bool = False,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """The same documents, addressed by product name and version."""
        try:
            projects = await deps.cache_manager.get_projects(client, name)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Dependency-Track unavailable for project search.",
            ) from exc
        match = next(
            (
                project for project in projects or []
                if project.get("name") == name
                and str(project.get("version") or "") == version
            ),
            None,
        )
        if match is None or not match.get("uuid"):
            raise HTTPException(
                status_code=404, detail="No project with this name and version"
            )
        return await export(
            client, str(match["uuid"]), variant, assessment_source, property_prefix,
            ticket_prefixes, download, f"{name}-{version}",
        )


def _register_gone_findings_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
    def describe(project_uuid: str) -> dict[str, Any] | None:
        manager = deps.cache_manager
        # Components known only by UUID get their names from local sources
        # once (stored BOM, project archives); see gone_component_names.
        try:
            resolve_gone_component_names(
                manager.finding_lifecycle,
                project_uuid,
                stored_bom=lambda: manager._load_project_cache(
                    manager._bom_path(project_uuid), None
                ),
                archive_dir=get_project_archive_path(),
            )
        except Exception:
            logger = getattr(deps, "logger", None)
            if logger is not None:
                logger.exception("Could not look up gone components of %s", project_uuid)
        name_vulnerabilities(project_uuid)
        aliases = stored_aliases(project_uuid)
        return describe_gone_findings(
            manager.finding_lifecycle,
            manager.assessment_outbox,
            project_uuid,
            aliases=aliases,
            same_issue=same_issue_index(project_uuid, aliases),
        )

    def stored_sources(project_uuid: str) -> tuple[list[Any], list[Any]]:
        manager = deps.cache_manager
        return (
            manager._load_project_cache(manager._findings_path(project_uuid), []) or [],
            manager._load_project_cache(manager._project_vulns_path(project_uuid), []) or [],
        )

    def name_vulnerabilities(project_uuid: str) -> None:
        """Rows made for old records know only the vulnerability's UUID; the
        stored findings and vulnerability records name it."""
        lifecycle = deps.cache_manager.finding_lifecycle
        unnamed = {
            row["vulnerability_uuid"]
            for row in lifecycle.presence(project_uuid).values()
            if not row.get("vuln_id")
        }
        if not unnamed:
            return
        try:
            ids = vuln_ids_by_uuid(DTClient.vulnerability_reference, *stored_sources(project_uuid))
            lifecycle.fill_vuln_ids(
                project_uuid, {uuid: ids[uuid] for uuid in unnamed if uuid in ids}
            )
        except Exception:
            logger = getattr(deps, "logger", None)
            if logger is not None:
                logger.exception("Could not name the vulnerabilities of %s", project_uuid)

    same_issue_facts: dict[tuple[str, ...], tuple[Any, dict[str, Any]]] = {}

    def same_issue_index(
        project_uuid: str, aliases: dict[str, set[str]]
    ) -> SameIssueIndex | None:
        """Probable same-issue matches of the version, from what is stored:
        the vulnerabilities' facts (cached until the stored findings or
        records change) and their stored version ranges. No source call."""
        manager = deps.cache_manager
        try:
            paths = (
                manager._findings_path(project_uuid),
                manager._project_vulns_path(project_uuid),
            )
            stamp = tuple(
                os.path.getmtime(path) if os.path.exists(path) else None for path in paths
            )
            # Keyed by the files, not the project alone: the same project
            # uuid under another data directory (another instance, a test)
            # must not reuse these facts.
            key = (*paths, project_uuid)
            cached = same_issue_facts.get(key)
            if cached is None or cached[0] != stamp:
                facts = facts_by_uuid(
                    DTClient.vulnerability_facts, *stored_sources(project_uuid)
                )
                same_issue_facts[key] = (stamp, facts)
            else:
                facts = cached[1]
            return SameIssueIndex(
                manager.finding_lifecycle.presence(project_uuid), facts, aliases
            )
        except Exception:
            logger = getattr(deps, "logger", None)
            if logger is not None:
                logger.exception("Could not look for same issues in %s", project_uuid)
            return None

    def stored_aliases(project_uuid: str) -> dict[str, set[str]]:
        """The ids of each vulnerability, from what is stored of the
        project version: its findings and its vulnerability records."""
        manager = deps.cache_manager
        try:
            return alias_map(DTClient.vulnerability_ids, *stored_sources(project_uuid))
        except Exception:
            logger = getattr(deps, "logger", None)
            if logger is not None:
                logger.exception("Could not read the aliases of %s", project_uuid)
            return {}

    @router.get("/project/{project_uuid}/gone-findings")
    async def get_gone_findings(
        project_uuid: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Findings of a project version Dependency-Track no longer reports,
        with why and when, and the last read of its findings."""
        described = await asyncio.to_thread(describe, project_uuid)
        return described or {
            "project_uuid": project_uuid,
            "last_read": None,
            "gone": {},
            "findings": [],
        }

    @router.get("/project/{project_uuid}/earlier-assessments")
    async def get_earlier_assessments(
        project_uuid: str,
        vulnerability_uuid: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """The assessments DTVP still holds for gone findings of a
        vulnerability (and of its aliases) in a project version: a starting
        point for a finding without an assessment. Nothing is applied; the
        form saves through the normal flow."""
        manager = deps.cache_manager
        lifecycle = manager.finding_lifecycle
        rows = await asyncio.to_thread(lifecycle.presence, project_uuid)
        own = next(
            (row for row in rows.values() if str(row["vulnerability_uuid"]) == vulnerability_uuid),
            None,
        )
        alias_ids: set[str] = set()
        vuln_id = str((own or {}).get("vuln_id") or "").strip().upper()
        if vuln_id:
            # Aliases from what is stored of the version; no source call.
            aliases = await asyncio.to_thread(stored_aliases, project_uuid)
            alias_ids = {alias for alias in aliases.get(vuln_id, set()) if alias != vuln_id}
        entries = earlier_assessments(
            rows,
            lambda row: manager.assessment_outbox.get_overlay(
                (project_uuid, row["component_uuid"], row["vulnerability_uuid"])
            ),
            vulnerability_uuid,
            alias_ids,
        )
        return {"project_uuid": project_uuid, "vulnerability_uuid": vulnerability_uuid, "earlier": entries}

    @router.post("/gone-findings/acknowledge")
    async def acknowledge_gone_findings(
        request: GoneFindingsAcknowledgeRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Acknowledge gone findings for everyone, with who and when; or
        withdraw it. Reviewers only. Findings that are not gone (any more)
        are skipped."""
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")
        changed = await asyncio.to_thread(
            deps.cache_manager.finding_lifecycle.acknowledge,
            request.project_uuid,
            [(item.component_uuid, item.vulnerability_uuid) for item in request.findings],
            by=user if request.acknowledged else None,
            at=datetime.now(timezone.utc).isoformat(),
        )
        return {"changed": changed}

    @router.post("/gone-findings/same-issue")
    async def confirm_same_issue(
        request: GoneFindingSameIssueRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Confirm, or withdraw, that a finding is the same issue as a
        reported one DTVP proposed for it (the same description on the same
        component), although no source
        names either as the other's alias. Only a confirmed match can be
        applied and is exported. Reviewers only."""
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")
        lifecycle = deps.cache_manager.finding_lifecycle
        finding = (request.component_uuid, request.vulnerability_uuid)
        other = (request.other_component_uuid, request.other_vulnerability_uuid)
        if request.confirmed:
            rows = await asyncio.to_thread(lifecycle.presence, request.project_uuid)
            row = rows.get(finding)
            other_row = rows.get(other)
            if row is None or row.get("status") not in ("gone", "reported"):
                raise HTTPException(status_code=404, detail="Unknown finding")
            if (other_row or {}).get("status") != "reported":
                raise HTTPException(
                    status_code=409, detail="The other finding is not reported"
                )
            aliases = await asyncio.to_thread(stored_aliases, request.project_uuid)
            index = await asyncio.to_thread(
                same_issue_index, request.project_uuid, aliases
            )
            on_component = (
                index is not None
                and any(
                    candidate["component_uuid"] == other[0]
                    and candidate["vulnerability_uuid"] == other[1]
                    for candidate in index.candidates(row)
                )
            )
            reason = index.reason(row, other_row) if on_component else None
            if not reason:
                raise HTTPException(
                    status_code=409,
                    detail="The findings are not proposed as the same issue",
                )
        else:
            reason = None
        changed = await asyncio.to_thread(
            lifecycle.confirm_same_issue,
            request.project_uuid,
            finding,
            other,
            reason=reason,
            by=user if request.confirmed else None,
            at=datetime.now(timezone.utc).isoformat(),
        )
        return {"changed": changed, "reason": reason}

    @router.post("/gone-findings/apply-to-alias")
    async def apply_gone_finding_to_alias(
        request: GoneFindingAliasRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """Propose a gone finding's assessment for its vulnerability under
        another id, still reported on the same component: copied when that
        finding has none, else the team blocks it lacks are added as
        historical blocks. Saved pending review, through the normal
        write path. Reviewers only."""
        if deps.get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Reviewer role required")
        manager = deps.cache_manager
        gone_key = (request.project_uuid, request.component_uuid, request.vulnerability_uuid)
        alias_component = request.alias_component_uuid or request.component_uuid
        alias_key = (request.project_uuid, alias_component, request.alias_vulnerability_uuid)
        await asyncio.to_thread(name_vulnerabilities, request.project_uuid)
        rows = await asyncio.to_thread(
            manager.finding_lifecycle.presence, request.project_uuid
        )
        gone_row = rows.get((request.component_uuid, request.vulnerability_uuid)) or {}
        if gone_row.get("status") != "gone":
            raise HTTPException(status_code=404, detail="The finding is not gone")
        alias_row = rows.get((alias_component, request.alias_vulnerability_uuid)) or {}
        if alias_row.get("status") != "reported":
            raise HTTPException(
                status_code=409, detail="The other finding is not reported on this component"
            )
        # Only the same vulnerability under another id: the gone finding's
        # id and the target's must be aliases of each other.
        known = await asyncio.to_thread(stored_aliases, request.project_uuid)
        gone_id = str(gone_row.get("vuln_id") or "").strip().upper()
        target_id = str(alias_row.get("vuln_id") or "").strip().upper()
        # Or the same issue without an alias, once a person confirmed it.
        same_issue = bool(gone_row.get("same_issue_confirmed_by")) and (
            gone_row.get("same_issue_component_uuid"),
            gone_row.get("same_issue_vulnerability_uuid"),
        ) == (alias_component, request.alias_vulnerability_uuid)
        if not same_issue and (
            not gone_id or not target_id or target_id not in known.get(gone_id, set())
        ):
            raise HTTPException(
                status_code=409, detail="The other finding is not the same vulnerability"
            )
        # A gone finding whose component DTVP never knew, which a person
        # confirmed to be this reported finding of the same vulnerability
        # (the source recreated the component).
        recreated_unknown = (
            same_issue
            and gone_row.get("same_issue_reason") == REASON_UNKNOWN_COMPONENT
            and request.alias_vulnerability_uuid == request.vulnerability_uuid
        )
        if alias_component != request.component_uuid and not recreated_unknown and (
            not gone_row.get("component_purl")
            or any(
                (gone_row.get(name) or None) != (alias_row.get(name) or None)
                for name in ("component_identity", "component_version", "component_purl")
            )
        ):
            # Onto another UUID only for the same component: package URL
            # (identity and version) equal, as the gone findings view
            # proposes it.
            raise HTTPException(
                status_code=409, detail="The other finding is on another component"
            )
        record = manager.assessment_outbox.get_overlay(gone_key)
        alias_record = manager.assessment_outbox.get_overlay(alias_key)
        proposal = alias_proposal(record, alias_record, deps.load_team_mapping())
        if proposal is None:
            raise HTTPException(status_code=409, detail="Nothing to apply")
        instance = {
            "project_uuid": request.project_uuid,
            "component_uuid": alias_component,
            "vulnerability_uuid": request.alias_vulnerability_uuid,
        }
        payload = {
            **instance,
            "state": proposal["state"],
            "details": proposal["details"],
            "suppressed": proposal["suppressed"],
        }
        try:
            # Written only while the other finding has the record this was
            # proposed for.
            persisted = await manager.persist_assessment_updates(
                [payload],
                replace=True,
                origin=(
                    ORIGIN_CARRIED_OVER_BY_SAME_ISSUE
                    if same_issue
                    else ORIGIN_CARRIED_OVER_BY_ALIAS
                ),
                author=user,
                expected_revisions={
                    alias_key: int((alias_record or {}).get("revision") or 0)
                },
            )
        except AssessmentRevisionConflictError:
            raise HTTPException(
                status_code=409, detail="The other finding was saved meanwhile; reload"
            ) from None
        try:
            await asyncio.to_thread(
                _refresh_grouped_vuln_task_snapshots,
                deps.tasks,
                [(instance, payload)],
                deps.load_team_mapping(),
            )
        except Exception:
            deps.logger.exception("Failed to refresh grouped task snapshots after an alias apply")
        return {"kind": proposal["kind"], "results": persisted}

    @router.get("/gone-findings")
    async def get_named_gone_findings(
        name: str = Query(..., min_length=1, max_length=500),
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        """The same for every version of a project. Versions DTVP has no
        record of are left out."""
        try:
            projects = await deps.cache_manager.get_projects(client, name)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Dependency-Track unavailable for project search.",
            ) from exc
        versions = []
        for project in projects or []:
            if project.get("name") != name or not project.get("uuid"):
                continue
            described = await asyncio.to_thread(describe, str(project["uuid"]))
            if described is None:
                continue
            versions.append({"version": str(project.get("version") or ""), **described})
        versions.sort(key=lambda item: item["version"])
        return {"name": name, "versions": versions}


def create_general_api_router(
    deps: GeneralApiRouteDeps,
    *,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()
    _register_project_routes(router, deps, current_user_dependency, client_dependency)
    _register_task_routes(router, deps, current_user_dependency)
    _register_cyclonedx_routes(router, deps, current_user_dependency, client_dependency)
    _register_statistics_route(router, deps, current_user_dependency, client_dependency)
    _register_assessment_routes(
        router, deps, current_user_dependency, client_dependency
    )
    _register_bulk_workflow_routes(
        router, deps, current_user_dependency, client_dependency
    )
    _register_dependency_route(router, deps, client_dependency)
    _register_gone_findings_routes(
        router, deps, current_user_dependency, client_dependency
    )
    return router
