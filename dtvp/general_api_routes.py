import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .dt_client import DTClient


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
        [str, str, Optional[str], DTClient], Awaitable[None]
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
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task_id = str(uuid.uuid4())
        deps.tasks[task_id] = {
            "id": task_id,
            "status": "pending",
            "message": "Starting...",
            "progress": 0,
            "created_at": datetime.now(),
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
                await deps.process_grouped_vulns_task(task_id, name, cve, client)

        deps.create_tracked_task(task_wrapper())
        return {"task_id": task_id}

    @router.get("/tasks/{task_id}")
    async def get_task_status(
        task_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        task = deps.tasks.get(task_id)
        if not task:
            return {"status": "not_found"}
        return task


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
        stats["version_counts"] = version_counts

        major_version_counts = {}
        version_major_details = {}
        major_version_severity_counts = {}

        for version in versions:
            version_label = version.get("version", "unknown")
            major = (
                version_label.split(".")[0]
                if isinstance(version_label, str) and "." in version_label
                else version_label
            )
            major = major or "unknown"

            major_version_counts[major] = major_version_counts.get(
                major, 0
            ) + version_counts.get(version_label, 0)
            version_major_details.setdefault(major, {})[version_label] = (
                version_counts.get(version_label, 0)
            )
            major_version_severity_counts.setdefault(major, {})

            findings = next(
                (
                    combined_entry["vulnerabilities"]
                    for combined_entry in combined_data
                    if combined_entry["version"]["uuid"] == version["uuid"]
                ),
                [],
            )
            for finding in findings:
                severity = (
                    finding.get("vulnerability", {}).get("severity") or "UNKNOWN"
                ).upper()
                major_version_severity_counts[major][severity] = (
                    major_version_severity_counts[major].get(severity, 0) + 1
                )

        stats["major_version_counts"] = major_version_counts
        stats["major_version_details"] = version_major_details
        stats["major_version_severity_counts"] = major_version_severity_counts
        stats["version_severity_counts"] = version_severity_counts
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
