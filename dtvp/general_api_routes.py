import asyncio
import copy
import hashlib
import inspect
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from .assessment_outbox_services import (
    AssessmentRevisionConflictError,
    assessment_key,
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
    create_assessment_restore_workflow,
)
from .bulk_workflows.automatic_assessments import (
    automatic_assessment_filter_facets,
    create_automatic_assessment_workflow,
)
from .bulk_workflows.base import (
    BulkWorkflowContext,
    BulkWorkflowRegistry,
    build_preview_token,
)
from .bulk_workflows.incomplete_sync import create_incomplete_sync_workflow
from .bulk_workflows.rescore_rule_sync import create_rescore_rule_sync_workflow
from .code_analysis_assessment_services import (
    assessment_status_for_group,
    build_assessment_match_index,
    discover_assessment_metadata,
    records_for_group,
    record_vulnerability_id,
)
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
)
from .rescore_rule_services import (
    RescoreRuleError,
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
)
from .query_execution_services import QueryCapacityError, QuerySupersededError
from .task_group_query_services import (
    get_or_build_task_group_query_index,
    query_task_groups,
    split_query_values,
)
from .team_group_services import (
    canonical_team_group_structure,
    resolve_team_groups,
)


class AssessmentRequest(BaseModel):
    instances: list[dict]
    state: str
    details: str
    comment: Optional[str] = None
    justification: Optional[str] = None
    suppressed: bool = False
    team: Optional[str] = None
    assigned: Optional[list[str]] = None
    original_analysis: Optional[dict[str, dict[str, Any]]] = None
    force: bool = False
    comparison_mode: Optional[str] = "MERGE"
    analysis_run_ids: list[str] = Field(default_factory=list)


class AssessmentDetailsRequest(BaseModel):
    instances: list[dict]


class AssessmentRestoreRequest(BaseModel):
    task_id: str
    group_ids: Optional[list[str]] = None


class BulkWorkflowFilters(BaseModel):
    q: str = ""
    lifecycle: list[str] = Field(default_factory=list)
    inconsistency_reason: list[str] = Field(default_factory=list)
    analysis: list[str] = Field(default_factory=list)
    tag: str = ""
    team: str = ""
    id: str = ""
    component: str = ""
    assignee: str = ""
    dependency: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    cvss_mismatch: bool = False
    attributed_before_days: Optional[int] = None
    attribution_mode: str = "older"
    tmrescore: list[str] = Field(default_factory=list)
    tmrescore_proposal_ids: list[str] = Field(default_factory=list)
    automatic_assessment: list[str] = Field(default_factory=list)
    automatic_assessment_ids: list[str] = Field(default_factory=list)
    automatic_assessment_outcome: list[str] = Field(default_factory=list)
    automatic_assessment_rescore: list[str] = Field(default_factory=list)


class BulkWorkflowRequest(BaseModel):
    task_id: str
    filters: BulkWorkflowFilters = Field(default_factory=BulkWorkflowFilters)


class BulkWorkflowApplyRequest(BulkWorkflowRequest):
    group_ids: list[str] = Field(default_factory=list)
    preview_token: str


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
    get_grouped_vuln_cache_revision: Callable[..., Any] = lambda **_kwargs: None
    group_query_executor: Any = None
    detail_executor: Any = None
    task_event_hub: Any = None


_TASK_SNAPSHOT_REFRESH_LOCK = threading.RLock()
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
        task["_task_key"] = (
            task_key[0],
            task_key[1],
            task_key[2],
            revision_text,
            task_key[4],
        )
        task["_task_key_finalized"] = True


def _claim_reusable_grouped_vuln_task(
    deps: GeneralApiRouteDeps,
    *,
    task_key: tuple[str, str, str, str, str],
    user: str,
) -> dict[str, Any] | None:
    task_identity = _grouped_vuln_task_identity(task_key)
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        for task in reversed(list(deps.tasks.values())):
            if not isinstance(task, dict):
                continue
            status = str(task.get("status") or "").lower()
            existing_key = task.get("_task_key")
            if not isinstance(existing_key, tuple) or len(existing_key) != 5:
                continue
            if status in {"pending", "running"}:
                matches = (
                    _grouped_vuln_task_identity(existing_key) == task_identity
                )
            elif status == "completed":
                matches = (
                    existing_key == task_key
                    if task.get("_task_key_finalized") is True
                    else _grouped_vuln_task_identity(existing_key) == task_identity
                )
            else:
                matches = False
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
) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str, str], dict[str, Any]]]:
    by_finding_uuid: dict[str, dict[str, Any]] = {}
    by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}

    for instance, payload in payloads:
        finding_uuid = instance.get("finding_uuid")
        if finding_uuid:
            by_finding_uuid[str(finding_uuid)] = payload

        identity = _assessment_identity_key(instance)
        if identity is not None:
            by_identity[identity] = payload

    return by_finding_uuid, by_identity


def _assessment_payload_for_component(
    component: dict[str, Any],
    by_finding_uuid: dict[str, dict[str, Any]],
    by_identity: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    finding_uuid = component.get("finding_uuid")
    if finding_uuid and str(finding_uuid) in by_finding_uuid:
        return by_finding_uuid[str(finding_uuid)]

    identity = _assessment_identity_key(component)
    if identity is None:
        return None
    return by_identity.get(identity)


def _assessment_payload_from_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    suppressed = (
        analysis.get("isSuppressed")
        if "isSuppressed" in analysis
        else analysis.get("is_suppressed", False)
    )
    return {
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
            update_component_restore_metadata(component)
            changed = True
    if changed:
        _refresh_group_rescoring_metadata(group)
    return changed


def _refresh_group_rescoring_metadata(group: dict[str, Any]) -> None:
    """Rebuild aggregate rescoring fields after component detail updates."""
    best_score: float | None = None
    best_vector: str | None = None
    fallback_vector: str | None = None
    vector_adjusted = False
    base_vector = group.get("cvss_vector")

    for affected_version in group.get("affected_versions") or []:
        for component in affected_version.get("components") or []:
            details = component.get("analysis_details") or ""
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
) -> int:
    with _TASK_SNAPSHOT_REFRESH_LOCK:
        return _refresh_grouped_vuln_task_snapshots_locked(
            tasks,
            payloads,
            team_mapping,
        )


def _refresh_grouped_vuln_task_snapshots_locked(
    tasks: dict[str, Any],
    payloads: list[tuple[dict, dict]],
    team_mapping: dict[str, Any],
) -> int:
    refreshed = 0
    now = datetime.now(timezone.utc)
    by_finding_uuid, by_identity = _build_assessment_payload_lookup(payloads)

    for task in list(tasks.values()):
        if not isinstance(task, dict):
            continue

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

    return refreshed


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
        task_key = _grouped_vuln_task_key(
            deps,
            name=name,
            cve=cve,
            response_mode=response_mode,
        )
        reusable_task = _claim_reusable_grouped_vuln_task(
            deps,
            task_key=task_key,
            user=user,
        )
        if reusable_task is not None:
            return {"task_id": reusable_task["id"], "reused": True}

        task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        with _TASK_SNAPSHOT_REFRESH_LOCK:
            # Recheck under the registry lock so simultaneous requests cannot
            # create duplicate computations between the first lookup and insert.
            reusable_task = _claim_reusable_grouped_vuln_task(
                deps,
                task_key=task_key,
                user=user,
            )
            if reusable_task is not None:
                return {"task_id": reusable_task["id"], "reused": True}
            deps.tasks[task_id] = {
                "id": task_id,
                "_owner": user,
                "_owners": {user},
                "_project_name": name,
                "_task_key": task_key,
                "_task_key_finalized": False,
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

        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
        cookies = dict(request.cookies)

        async def task_wrapper():
            settings = deps.dt_settings_cls()
            client_cls = deps.get_dt_client_cls()
            async with client_cls(
                settings.api_url,
                api_key=settings.api_key,
                token=token or "",
                cookies=cookies,
            ) as client:
                await deps.process_grouped_vulns_task(
                    task_id,
                    name,
                    cve,
                    client,
                    response_mode,
                )
                _finalize_grouped_vuln_task_key(deps, task_id)

        deps.create_tracked_task(task_wrapper())
        return {"task_id": task_id, "reused": False}

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
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
        team: str = "",
        vuln_id: str = Query("", alias="id"),
        component: str = "",
        assignee: str = "",
        dependency: list[str] | None = Query(default=None),
        versions: list[str] | None = Query(default=None),
        cvss_mismatch: bool = False,
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
                    "analysis": split_query_values(analysis),
                    "tag": tag,
                    "team": team,
                    "vuln_id": vuln_id,
                    "component": component,
                    "assignee": assignee,
                    "dependency": split_query_values(dependency),
                    "versions": split_query_values(versions),
                    "cvss_mismatch": cvss_mismatch,
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
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
        team: str = "",
        vuln_id: str = Query("", alias="id"),
        component: str = "",
        assignee: str = "",
        dependency: list[str] | None = Query(default=None),
        versions: list[str] | None = Query(default=None),
        cvss_mismatch: bool = False,
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
                    "analysis": split_query_values(analysis),
                    "tag": tag,
                    "team": team,
                    "vuln_id": vuln_id,
                    "component": component,
                    "assignee": assignee,
                    "dependency": split_query_values(dependency),
                    "versions": split_query_values(versions),
                    "cvss_mismatch": cvss_mismatch,
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
            hydrated = copy.deepcopy(group)
            populate_group_dependency_chains(
                hydrated,
                task.get("_bom_cache_map") or {},
            )
            _, context = _task_group_query_context(deps, task)
            assessment_records = context["assessment_records"]
            _annotate_code_assessment_status([hydrated], assessment_records)
            return hydrated

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
    aliases: dict[str, str] = {}
    for raw_value in team_mapping.values():
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
    config_digest = _stable_query_context_digest(
        rescore_rules,
        team_mapping,
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
                team_mapping,
            )
            team_group_structure = canonical_team_group_structure(
                team_group_config,
                team_mapping,
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
            "team_aliases": _team_alias_map(team_mapping),
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
            dict(full_by_id.get(item.get("id"), item))
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
) -> list[dict[str, Any]]:
    result = query_task_groups(
        groups,
        q=filters.q,
        lifecycle=filters.lifecycle,
        inconsistency_reason=filters.inconsistency_reason,
        analysis=filters.analysis,
        tag=filters.tag,
        team=filters.team,
        vuln_id=filters.id,
        component=filters.component,
        assignee=filters.assignee,
        dependency=filters.dependency,
        versions=filters.versions,
        cvss_mismatch=filters.cvss_mismatch,
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
    filtered_summaries = _filter_bulk_workflow_groups(summary_index, base_filters)
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
            create_incomplete_sync_workflow(),
            create_assessment_restore_workflow(),
            create_rescore_rule_sync_workflow(load_rescore_rules_or_raise),
        ]
    )


def _bulk_workflow_context(
    deps: GeneralApiRouteDeps,
    req: BulkWorkflowRequest,
    user: str,
    workflow_id: str,
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
    )


def _record_code_analysis_applications(
    deps: GeneralApiRouteDeps,
    *,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    finalized: list[dict[str, Any]],
    user: str,
    workflow_id: str,
    fallback_run_ids: list[str] | None = None,
) -> None:
    store = deps.code_analysis_result_store
    if store is None:
        return
    results_by_uuid = {
        str(result.get("uuid") or ""): result
        for result in finalized
        if result.get("uuid")
    }
    try:
        for instance, payload in payloads:
            finding_uuid = str(instance.get("finding_uuid") or "").strip()
            if not finding_uuid:
                continue
            run_ids = list(
                dict.fromkeys(
                    str(run_id).strip()
                    for run_id in (
                        instance.get("analysis_run_ids") or fallback_run_ids or []
                    )
                    if str(run_id).strip()
                )
            )
            if not run_ids:
                continue
            result = results_by_uuid.get(finding_uuid) or {}
            status = (
                "queued"
                if result.get("queued")
                else "applied"
                if result.get("status") == "success"
                else "failed"
            )
            fingerprint = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            group_id = str(
                instance.get("bulk_workflow_group_id")
                or instance.get("vuln_id")
                or instance.get("vulnerability_id")
                or ""
            )
            for run_id in run_ids:
                store.record_application(
                    analysis_run_id=run_id,
                    finding_uuid=finding_uuid,
                    group_id=group_id,
                    status=status,
                    applied_by=user,
                    workflow_id=workflow_id,
                    payload_fingerprint=fingerprint,
                )
    except Exception:
        deps.logger.exception("Failed to persist code-analysis application provenance")


async def _apply_bulk_workflow_payloads(
    deps: GeneralApiRouteDeps,
    client: DTClient,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    progress_callback: Callable[[int, int, dict[str, Any]], Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    persisted = await _persist_local_assessment_payloads(deps, payloads)

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
    return finalized, outcome


async def _persist_local_assessment_payloads(
    deps: GeneralApiRouteDeps,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    raw_payloads = [payload for _instance, payload in payloads]
    persist = getattr(deps.cache_manager, "persist_assessment_updates", None)
    if callable(persist):
        return await persist(raw_payloads, replace=True)

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
        ]
    raise RuntimeError("Assessment cache does not support durable updates")


def _accepted_assessment_results(
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    persisted: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records_by_key = {
        assessment_key(record.get("payload") or {}): record
        for record in persisted
    }
    results: list[dict[str, Any]] = []
    for instance, payload in payloads:
        record = records_by_key.get(assessment_key(payload)) or {}
        results.append(
            {
                "status": "success",
                "uuid": instance.get("finding_uuid"),
                "new_state": payload.get("state"),
                "new_details": payload.get("details"),
                "queued": True,
                "sync_status": "pending",
                "update_id": record.get("id"),
                "revision": int(record.get("revision") or 0),
            }
        )
    return results


def _strict_dt_assessment_conflicts_enabled() -> bool:
    return os.getenv(
        "DTVP_ASSESSMENT_STRICT_DT_CONFLICTS",
        "false",
    ).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _expected_assessment_revisions(
    req: AssessmentRequest,
) -> dict[tuple[str, str, str], int]:
    if req.force or not req.original_analysis:
        return {}
    expected: dict[tuple[str, str, str], int] = {}
    for instance in req.instances:
        finding_uuid = instance.get("finding_uuid")
        original = (
            req.original_analysis.get(finding_uuid)
            if isinstance(finding_uuid, str)
            else None
        )
        if not isinstance(original, dict) or "dtvpRevision" not in original:
            continue
        key = assessment_key(instance)
        if key is None:
            continue
        try:
            expected[key] = max(0, int(original.get("dtvpRevision") or 0))
        except (TypeError, ValueError):
            continue
    return expected


def _local_assessment_conflict(
    deps: GeneralApiRouteDeps,
    req: AssessmentRequest,
    exc: AssessmentRevisionConflictError,
) -> dict[str, Any]:
    instance = next(
        (
            candidate
            for candidate in req.instances
            if assessment_key(candidate) == exc.key
        ),
        {},
    )
    finding_uuid = instance.get("finding_uuid")
    original = (
        req.original_analysis.get(finding_uuid)
        if req.original_analysis and isinstance(finding_uuid, str)
        else None
    )
    current = deps.cache_manager.get_assessment_overlay(*exc.key) or {}
    return {
        "finding_uuid": finding_uuid,
        "project_name": instance.get("project_name"),
        "project_version": instance.get("project_version"),
        "component_name": instance.get("component_name"),
        "component_version": instance.get("component_version"),
        "current": current,
        "original": original or {},
        "your_change": {
            "analysisState": req.state,
            "analysisDetails": req.details,
            "isSuppressed": req.suppressed,
        },
    }


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
    task["updated_at"] = now
    if status in {"completed", "failed"}:
        task["completed_at"] = now


def _bulk_workflow_task_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return str(exc) or exc.__class__.__name__


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

    async def prepare_preview_response(
        plugin: Any,
        req: BulkWorkflowRequest,
        user: str,
    ) -> dict[str, Any]:
        context = await asyncio.to_thread(
            _bulk_workflow_context,
            deps,
            req,
            user,
            plugin.id,
        )
        preview = await asyncio.to_thread(plugin.preview, context)
        return {
            "task_id": req.task_id,
            "workflow": plugin.metadata(),
            "preview_token": build_preview_token(
                plugin,
                task_id=req.task_id,
                filter_payload=req.filters.model_dump(),
                preview=preview,
            ),
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
        context = await asyncio.to_thread(
            _bulk_workflow_context,
            deps,
            req,
            user,
            plugin.id,
        )
        preview = await asyncio.to_thread(plugin.preview, context)
        expected_token = build_preview_token(
            plugin,
            task_id=req.task_id,
            filter_payload=req.filters.model_dump(),
            preview=preview,
        )
        if req.preview_token != expected_token:
            raise HTTPException(
                status_code=409,
                detail="Bulk workflow preview is stale; reload it before applying.",
            )
        selectable = set(plugin.selectable_ids(preview))
        selected = list(dict.fromkeys(req.group_ids))
        if not set(selected).issubset(selectable):
            raise HTTPException(
                status_code=409,
                detail="One or more selected groups no longer match this workflow.",
            )
        payloads, skipped = await asyncio.to_thread(
            plugin.build_payloads,
            context,
            selected,
        )
        finalized, outcome = await _apply_bulk_workflow_payloads(
            deps,
            client,
            payloads,
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
        return {
            "task_id": req.task_id,
            "workflow": plugin.metadata(),
            "summary": {
                "selected_groups": len(selected),
                "attempted": len(payloads),
                **outcome,
                **skipped,
            },
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
        context = await asyncio.to_thread(
            _bulk_workflow_context,
            deps,
            req,
            user,
            plugin.id,
        )
        preview = await asyncio.to_thread(plugin.preview, context)
        expected_token = build_preview_token(
            plugin,
            task_id=req.task_id,
            filter_payload=req.filters.model_dump(),
            preview=preview,
        )
        if req.preview_token != expected_token:
            raise HTTPException(
                status_code=409,
                detail="Bulk workflow preview is stale; reload it before exporting.",
            )
        selectable = set(plugin.selectable_ids(preview))
        selected = list(dict.fromkeys(req.group_ids))
        if not set(selected).issubset(selectable):
            raise HTTPException(
                status_code=409,
                detail="One or more selected groups no longer match this workflow.",
            )
        return await asyncio.to_thread(
            plugin.build_document,
            context,
            selected,
        )

    @router.post("/bulk-workflows/summary")
    async def bulk_workflow_summary(
        req: BulkWorkflowRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        require_reviewer(user)
        _completed_task_full_groups(deps, req.task_id, user)
        workflows = [
            {
                **plugin.metadata(),
                "candidate_count": None,
                "summary": {},
            }
            for plugin in registry.all()
        ]
        return {"task_id": req.task_id, "workflows": workflows}

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
        settings = deps.dt_settings_cls()
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
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
                )

        deps.create_tracked_task(run_document())
        return {"task_id": operation["id"]}


def _register_assessment_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
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

        if (
            _strict_dt_assessment_conflicts_enabled()
            and not req.force
            and req.original_analysis
        ):
            current_analyses = await deps.fetch_current_assessment_analyses(req, client)
            conflicts = deps.collect_assessment_conflicts(req, current_analyses)
            if conflicts:
                return JSONResponse(
                    status_code=409,
                    content={"status": "conflict", "conflicts": conflicts},
                )

        role = deps.get_user_role(user)
        payloads = deps.build_assessment_payloads(req, user, role)
        raw_payloads = [payload for _instance, payload in payloads]
        try:
            persisted = await deps.cache_manager.persist_assessment_updates(
                raw_payloads,
                replace=True,
                expected_revisions=_expected_assessment_revisions(req),
            )
        except AssessmentRevisionConflictError as exc:
            return JSONResponse(
                status_code=409,
                content={
                    "status": "conflict",
                    "conflicts": [_local_assessment_conflict(deps, req, exc)],
                },
            )
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

        finalized = _accepted_assessment_results(payloads, persisted)
        _record_code_analysis_applications(
            deps,
            payloads=payloads,
            finalized=finalized,
            user=user,
            workflow_id="individual-assessment",
            fallback_run_ids=req.analysis_run_ids,
        )
        return finalized


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


def create_general_api_router(
    deps: GeneralApiRouteDeps,
    *,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()
    _register_project_routes(router, deps, current_user_dependency, client_dependency)
    _register_task_routes(router, deps, current_user_dependency)
    _register_statistics_route(router, deps, current_user_dependency, client_dependency)
    _register_assessment_routes(
        router, deps, current_user_dependency, client_dependency
    )
    _register_bulk_workflow_routes(
        router, deps, current_user_dependency, client_dependency
    )
    _register_dependency_route(router, deps, client_dependency)
    return router
