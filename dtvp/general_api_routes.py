import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .dt_client import DTClient
from .grouped_vuln_services import (
    build_grouped_vuln_statistics_rollup,
    summarize_grouped_vulnerabilities,
)
from .logic import populate_group_dependency_chains
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


class AssessmentDetailsRequest(BaseModel):
    instances: list[dict]


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
            changed = True
    return changed


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

        try:
            response = await asyncio.to_thread(
                lambda: query_task_groups(
                    get_or_build_task_group_query_index(task),
                    q=q,
                    lifecycle=split_query_values(lifecycle),
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
                    automatic_assessment_ids=split_query_values(automatic_assessment_ids),
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
        return response

    @router.get("/tasks/{task_id}/group-details")
    async def get_task_group_details_window(
        task_id: str,
        q: str = "",
        lifecycle: list[str] | None = Query(default=None),
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

        try:
            response = await asyncio.to_thread(
                lambda: query_task_groups(
                    get_or_build_task_group_query_index(task),
                    q=q,
                    lifecycle=split_query_values(lifecycle),
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
                    automatic_assessment_ids=split_query_values(automatic_assessment_ids),
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


def _register_assessment_routes(
    router: APIRouter,
    deps: GeneralApiRouteDeps,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> None:
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
            results.append(result_item)

        return results

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
        return await deps.finalize_assessment_results(api_results)


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
    _register_dependency_route(router, deps, client_dependency)
    return router
