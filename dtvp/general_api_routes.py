import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from .assessment_restore_services import (
    refresh_group_restore_metadata,
    update_component_restore_metadata,
)
from .bulk_workflows.assessment_restore import (
    build_assessment_restore_payloads as workflow_assessment_restore_payloads,
    build_assessment_restore_preview as workflow_assessment_restore_preview,
    create_assessment_restore_workflow,
)
from .bulk_workflows.automatic_assessments import create_automatic_assessment_workflow
from .bulk_workflows.base import (
    BulkWorkflowContext,
    BulkWorkflowRegistry,
    build_preview_token,
)
from .bulk_workflows.incomplete_sync import create_incomplete_sync_workflow
from .bulk_workflows.rescore_rule_sync import create_rescore_rule_sync_workflow
from .code_analysis_assessment_services import (
    assessment_status_for_group,
    discover_assessment_metadata,
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
from .task_group_query_services import (
    build_task_group_query_index,
    get_or_build_task_group_query_index,
    query_task_groups,
    split_query_values,
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
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    collect_version_snapshots: Callable[
        ...,
        Awaitable[
            tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, int]]]
        ],
    ]
    group_vulnerabilities: Callable[..., list[dict[str, Any]]]
    calculate_statistics: Callable[[list[dict[str, Any]]], dict[str, Any]]
    prune_grouped_vuln_tasks: Callable[[], list[str]]
    get_user_role: Callable[[str], str]
    fetch_current_assessment_analyses: Callable[
        [AssessmentRequest, DTClient], Awaitable[list[Any]]
    ]
    collect_assessment_conflicts: Callable[
        [AssessmentRequest, list[Any]], list[dict[str, Any]]
    ]
    build_assessment_payloads: Callable[
        [AssessmentRequest, str, str], list[tuple[dict, dict]]
    ]
    apply_assessment_payloads: Callable[
        [DTClient, list[tuple[dict, dict]]], Awaitable[list[dict[str, Any]]]
    ]
    finalize_assessment_results: Callable[
        [list[dict[str, Any]]], Awaitable[list[dict[str, Any]]]
    ]
    get_bom_analysis_cache_cls: Callable[[], type]
    default_dependency_chain_limit: int
    service_unavailable_response: dict[int | str, dict[str, Any]]
    not_found_response: dict[int | str, dict[str, Any]]
    code_analysis_result_store: Any = None


ASSESSMENT_INSTANCE_KEY_FIELDS = (
    "project_uuid",
    "component_uuid",
    "vulnerability_uuid",
)


def _assessment_identity_key(source: dict[str, Any]) -> tuple[str, str, str] | None:
    values = tuple(str(source.get(key) or "") for key in ASSESSMENT_INSTANCE_KEY_FIELDS)
    return values if all(values) else None


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


def _refresh_grouped_task_groups(
    groups: list[dict[str, Any]],
    by_finding_uuid: dict[str, dict[str, Any]],
    by_identity: dict[tuple[str, str, str], dict[str, Any]],
    team_mapping: dict[str, Any],
) -> bool:
    changed_group_ids: set[str] = set()
    for group in groups:
        if _apply_assessment_payload_to_group(
            group,
            by_finding_uuid,
            by_identity,
        ):
            group_id = group.get("id")
            if group_id:
                changed_group_ids.add(str(group_id))

    if not changed_group_ids:
        return False

    for group in groups:
        if str(group.get("id") or "") not in changed_group_ids:
            continue
        refresh_group_restore_metadata(group)
        summary = summarize_grouped_vulnerabilities([group], team_mapping)
        if summary:
            group["list_metadata"] = summary[0].get("list_metadata") or {}
    return True


def _refresh_grouped_vuln_task_snapshots(
    tasks: dict[str, Any],
    payloads: list[tuple[dict, dict]],
    team_mapping: dict[str, Any],
) -> int:
    refreshed = 0
    now = datetime.now(timezone.utc)
    by_finding_uuid, by_identity = _build_assessment_payload_lookup(payloads)

    for task in tasks.values():
        if not isinstance(task, dict):
            continue

        full_result = task.get("_full_result")
        partial_full_result = task.get("_partial_full_result")
        result = task.get("result")
        full_changed = isinstance(full_result, list) and _refresh_grouped_task_groups(
            full_result,
            by_finding_uuid,
            by_identity,
            team_mapping,
        )
        partial_changed = (
            isinstance(partial_full_result, list)
            and partial_full_result is not full_result
            and _refresh_grouped_task_groups(
                partial_full_result,
                by_finding_uuid,
                by_identity,
                team_mapping,
            )
        )
        result_changed = False

        if full_changed:
            task["_full_result_by_id"] = {
                item.get("id"): item for item in full_result if item.get("id")
            }
            task["result"] = (
                summarize_grouped_vulnerabilities(full_result, team_mapping)
                if task.get("result_mode") == "summary"
                else full_result
            )
        elif partial_changed:
            task["result"] = (
                summarize_grouped_vulnerabilities(partial_full_result, team_mapping)
                if task.get("result_mode") == "summary"
                else partial_full_result
            )
        elif isinstance(result, list):
            result_changed = _refresh_grouped_task_groups(
                result,
                by_finding_uuid,
                by_identity,
                team_mapping,
            )

        if not (full_changed or partial_changed or result_changed):
            continue

        task["_group_query_index"] = build_task_group_query_index(
            task.get("result") if isinstance(task.get("result"), list) else []
        )
        task["updated_at"] = now
        refreshed += 1

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
        deps.prune_grouped_vuln_tasks()
        task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        deps.tasks[task_id] = {
            "id": task_id,
            "status": "pending",
            "message": "Starting...",
            "progress": 0,
            "created_at": now,
            "updated_at": now,
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

        deps.create_tracked_task(task_wrapper())
        return {"task_id": task_id}

    @router.get("/tasks/{task_id}")
    async def get_task_status(
        task_id: str,
        include_result: bool = True,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_grouped_vuln_tasks()
        task = deps.tasks.get(task_id)
        if not task:
            return {"status": "not_found"}
        return {
            key: value
            for key, value in task.items()
            if not key.startswith("_") and (include_result or key != "result")
        }

    @router.get("/tasks/{task_id}/events")
    async def stream_task_events(
        task_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        async def event_stream():
            last_payload = ""
            while True:
                deps.prune_grouped_vuln_tasks()
                task = deps.tasks.get(task_id)
                if not task:
                    payload = {"status": "not_found"}
                else:
                    payload = {
                        key: value
                        for key, value in task.items()
                        if not key.startswith("_") and key != "result"
                    }
                text = json.dumps(payload, default=str)
                if text != last_payload:
                    yield text + "\n"
                    last_payload = text

                status = str(payload.get("status") or "").lower()
                if status in {"completed", "failed", "not_found"}:
                    break
                await asyncio.sleep(1)

        return StreamingResponse(
            event_stream(),
            media_type="application/x-ndjson",
        )

    @router.get("/tasks/{task_id}/groups")
    async def get_task_groups(
        task_id: str,
        q: str = "",
        lifecycle: list[str] | None = Query(default=None),
        inconsistency_reason: list[str] | None = Query(default=None),
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
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
        sort: str = Query("rescored-severity"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        offset: int = Query(0, ge=0),
        cursor: str = "",
        limit: int = Query(100, ge=1, le=1000),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_grouped_vuln_tasks()
        task = deps.tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        is_partial_summary = (
            task.get("result_mode") == "summary"
            and task.get("partial_result_available")
            and task.get("_group_query_index") is not None
        )
        if task.get("status") != "completed" and not is_partial_summary:
            raise HTTPException(status_code=409, detail="Task is not completed")

        assessment_records = await asyncio.to_thread(
            discover_assessment_metadata,
            deps.code_analysis_result_store,
        )
        effective_assessment_ids = _assessment_filter_ids(
            assessment_records,
            split_query_values(automatic_assessment_ids),
        )
        try:
            response = await asyncio.to_thread(
                lambda: query_task_groups(
                    get_or_build_task_group_query_index(task),
                    q=q,
                    lifecycle=split_query_values(lifecycle),
                    inconsistency_reason=split_query_values(inconsistency_reason),
                    analysis=split_query_values(analysis),
                    tag=tag,
                    vuln_id=vuln_id,
                    component=component,
                    assignee=assignee,
                    dependency=split_query_values(dependency),
                    versions=split_query_values(versions),
                    cvss_mismatch=cvss_mismatch,
                    attributed_before_days=attributed_before_days,
                    attribution_mode=attribution_mode,
                    tmrescore=split_query_values(tmrescore),
                    tmrescore_proposal_ids=split_query_values(tmrescore_proposal_ids),
                    automatic_assessment=split_query_values(automatic_assessment),
                    automatic_assessment_ids=effective_assessment_ids,
                    sort_by=sort,
                    sort_order=order,
                    offset=offset,
                    limit=limit,
                    cursor=cursor,
                )
            )
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
        _annotate_code_assessment_status(response["items"], assessment_records)
        return response

    @router.get("/tasks/{task_id}/group-details")
    async def get_task_group_details_window(
        task_id: str,
        q: str = "",
        lifecycle: list[str] | None = Query(default=None),
        inconsistency_reason: list[str] | None = Query(default=None),
        analysis: list[str] | None = Query(default=None),
        tag: str = "",
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
        sort: str = Query("rescored-severity"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        offset: int = Query(0, ge=0),
        cursor: str = "",
        limit: int = Query(100, ge=1, le=1000),
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_grouped_vuln_tasks()
        task = deps.tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.get("status") != "completed":
            raise HTTPException(status_code=409, detail="Task is not completed")

        assessment_records = await asyncio.to_thread(
            discover_assessment_metadata,
            deps.code_analysis_result_store,
        )
        effective_assessment_ids = _assessment_filter_ids(
            assessment_records,
            split_query_values(automatic_assessment_ids),
        )
        try:
            response = await asyncio.to_thread(
                lambda: query_task_groups(
                    get_or_build_task_group_query_index(task),
                    q=q,
                    lifecycle=split_query_values(lifecycle),
                    inconsistency_reason=split_query_values(inconsistency_reason),
                    analysis=split_query_values(analysis),
                    tag=tag,
                    vuln_id=vuln_id,
                    component=component,
                    assignee=assignee,
                    dependency=split_query_values(dependency),
                    versions=split_query_values(versions),
                    cvss_mismatch=cvss_mismatch,
                    attributed_before_days=attributed_before_days,
                    attribution_mode=attribution_mode,
                    tmrescore=split_query_values(tmrescore),
                    tmrescore_proposal_ids=split_query_values(tmrescore_proposal_ids),
                    automatic_assessment=split_query_values(automatic_assessment),
                    automatic_assessment_ids=effective_assessment_ids,
                    sort_by=sort,
                    sort_order=order,
                    offset=offset,
                    limit=limit,
                    cursor=cursor,
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        full_by_id = task.get("_full_result_by_id") or {}
        response["items"] = [
            full_by_id.get(item.get("id"), item) if isinstance(item, dict) else item
            for item in response["items"]
        ]
        _annotate_code_assessment_status(response["items"], assessment_records)
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
        deps.prune_grouped_vuln_tasks()
        task = deps.tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        full_by_id = task.get("_full_result_by_id") or {}
        group = full_by_id.get(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="Vulnerability group not found")
        populate_group_dependency_chains(group, task.get("_bom_cache_map") or {})
        assessment_records = await asyncio.to_thread(
            discover_assessment_metadata,
            deps.code_analysis_result_store,
        )
        _annotate_code_assessment_status([group], assessment_records)
        return group

    @router.get("/tasks/{task_id}/statistics")
    async def get_task_statistics(
        task_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_grouped_vuln_tasks()
        task = deps.tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.get("status") != "completed":
            raise HTTPException(status_code=409, detail="Task is not completed")

        grouped = task.get("_full_result")
        if not isinstance(grouped, list):
            grouped = task.get("result") if isinstance(task.get("result"), list) else []

        stats = deps.calculate_statistics(grouped)
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
) -> list[dict[str, Any]]:
    deps.prune_grouped_vuln_tasks()
    task = deps.tasks.get(task_id)
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


def _annotate_code_assessment_status(
    groups: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    for group in groups:
        if not isinstance(group, dict):
            continue
        group["code_assessment_status"] = assessment_status_for_group(group, records)


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
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=max(
            1,
            int(groups.get("total") or 0)
            if isinstance(groups, dict)
            else len(groups),
        ),
    )
    return result["items"]


def _filter_bulk_workflow_task_groups(
    deps: GeneralApiRouteDeps,
    task_id: str,
    filters: BulkWorkflowFilters,
    assessment_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    full_groups = _completed_task_full_groups(deps, task_id)
    task = deps.tasks[task_id]
    summary_index = get_or_build_task_group_query_index(task)
    assessment_filter = {
        str(value or "").strip().upper()
        for value in filters.automatic_assessment
        if str(value or "").strip()
    }
    base_filters = filters.model_copy(
        update={
            "automatic_assessment": [],
            "automatic_assessment_ids": [],
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
    filtered_groups = [
        full_group
        for summary in filtered_summaries
        if (full_group := full_group_lookup.get(str(summary.get("id") or "")))
        is not None
    ]
    if not assessment_filter or assessment_filter == {
        "WITH_AUTOMATIC_ASSESSMENT",
        "WITHOUT_AUTOMATIC_ASSESSMENT",
    }:
        return filtered_groups
    if assessment_filter == {"WITH_AUTOMATIC_ASSESSMENT"}:
        return [
            group
            for group in filtered_groups
            if assessment_status_for_group(group, assessment_records or []) is not None
        ]
    if assessment_filter == {"WITHOUT_AUTOMATIC_ASSESSMENT"}:
        return [
            group
            for group in filtered_groups
            if assessment_status_for_group(group, assessment_records or []) is None
        ]
    return []


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
            assessment_records,
        ),
        user=user,
        team_mapping=deps.load_team_mapping(),
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
                "applied"
                if result.get("status") == "success"
                else "queued"
                if result.get("queued")
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
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    for _instance, payload in payloads:
        deps.cache_manager._save_local_analysis(payload)

    try:
        _refresh_grouped_vuln_task_snapshots(
            deps.tasks,
            payloads,
            deps.load_team_mapping(),
        )
    except Exception:
        deps.logger.exception("Failed to refresh grouped task snapshots after bulk workflow")

    api_results = await deps.apply_assessment_payloads(client, payloads)
    finalized = await deps.finalize_assessment_results(api_results)
    outcome = {
        "succeeded": sum(1 for result in finalized if result.get("status") == "success"),
        "queued": sum(1 for result in finalized if result.get("queued")),
        "failed": sum(
            1
            for result in finalized
            if result.get("status") == "error" and not result.get("queued")
        ),
    }
    return finalized, outcome


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
) -> None:
    now = datetime.now(timezone.utc)
    if status is not None:
        task["status"] = status
    if message is not None:
        task["message"] = message
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
            deps, client, payloads
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
        _completed_task_full_groups(deps, req.task_id)
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
        deps.prune_grouped_vuln_tasks()
        operation = deps.tasks.get(operation_id)
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
        _completed_task_full_groups(deps, req.task_id)
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
        _completed_task_full_groups(deps, req.task_id)
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
                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url,
                    api_key=settings.api_key,
                    token=token or "",
                    cookies=cookies,
                ) as client:
                    result = await prepare_apply_response(plugin, req, user, client)
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
        _completed_task_full_groups(deps, req.task_id)
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
        analysis_tasks = [
            deps.cache_manager.get_analysis(
                client,
                project_uuid=instance["project_uuid"],
                component_uuid=instance["component_uuid"],
                vulnerability_uuid=instance["vulnerability_uuid"],
                refresh=True,
            )
            for instance in req.instances
        ]
        gathered_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)

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
                refreshed_tasks = _refresh_grouped_vuln_task_snapshots(
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

        groups = _completed_task_full_groups(deps, req.task_id)
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

        groups = _completed_task_full_groups(deps, req.task_id)
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

        groups = _completed_task_full_groups(deps, req.task_id)
        try:
            payloads, skipped = build_rescore_rule_sync_payloads(
                groups,
                load_rescore_rules_or_raise(),
                req.group_ids,
            )
        except RescoreRuleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        for _instance, payload in payloads:
            deps.cache_manager._save_local_analysis(payload)

        try:
            refreshed_tasks = _refresh_grouped_vuln_task_snapshots(
                deps.tasks,
                payloads,
                deps.load_team_mapping(),
            )
            if refreshed_tasks:
                deps.logger.info(
                    "Refreshed %d grouped vulnerability task snapshot(s) "
                    "after CVSS rule sync",
                    refreshed_tasks,
                )
        except Exception:
            deps.logger.exception(
                "Failed to refresh grouped vulnerability task snapshots "
                "after CVSS rule sync"
            )

        api_results = await deps.apply_assessment_payloads(client, payloads)
        finalized = await deps.finalize_assessment_results(api_results)
        queued = sum(1 for result in finalized if result.get("queued"))
        succeeded = sum(1 for result in finalized if result.get("status") == "success")
        failed = sum(
            1
            for result in finalized
            if result.get("status") == "error" and not result.get("queued")
        )
        return {
            "task_id": req.task_id,
            "summary": {
                "attempted": len(payloads),
                "succeeded": succeeded,
                "queued": queued,
                "failed": failed,
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

        groups = _completed_task_full_groups(deps, req.task_id)
        payloads, skipped = workflow_assessment_restore_payloads(groups, req.group_ids)
        for _instance, payload in payloads:
            deps.cache_manager._save_local_analysis(payload)

        try:
            refreshed_tasks = _refresh_grouped_vuln_task_snapshots(
                deps.tasks,
                payloads,
                deps.load_team_mapping(),
            )
            if refreshed_tasks:
                deps.logger.info(
                    "Refreshed %d grouped vulnerability task snapshot(s) "
                    "after assessment restore",
                    refreshed_tasks,
                )
        except Exception:
            deps.logger.exception(
                "Failed to refresh grouped vulnerability task snapshots "
                "after assessment restore"
            )

        api_results = await deps.apply_assessment_payloads(client, payloads)
        finalized = await deps.finalize_assessment_results(api_results)
        queued = sum(1 for result in finalized if result.get("queued"))
        succeeded = sum(1 for result in finalized if result.get("status") == "success")
        failed = sum(
            1
            for result in finalized
            if result.get("status") == "error" and not result.get("queued")
        )
        return {
            "task_id": req.task_id,
            "summary": {
                "attempted": len(payloads),
                "succeeded": succeeded,
                "queued": queued,
                "failed": failed,
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

        if not req.force and req.original_analysis:
            current_analyses = await deps.fetch_current_assessment_analyses(req, client)
            conflicts = deps.collect_assessment_conflicts(req, current_analyses)
            if conflicts:
                return JSONResponse(
                    status_code=409,
                    content={"status": "conflict", "conflicts": conflicts},
                )

        role = deps.get_user_role(user)
        payloads = deps.build_assessment_payloads(req, user, role)
        for _instance, payload in payloads:
            deps.cache_manager._save_local_analysis(payload)
        try:
            refreshed_tasks = _refresh_grouped_vuln_task_snapshots(
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

        api_results = await deps.apply_assessment_payloads(client, payloads)
        finalized = await deps.finalize_assessment_results(api_results)
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
