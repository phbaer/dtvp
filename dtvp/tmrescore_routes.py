import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Awaitable, Callable, Coroutine

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile

from .authorization import require_reviewer
from .dt_client import DTClient
from .tmrescore_integration import (
    TMRescoreClient,
    TMRescoreSettings,
    normalize_tmrescore_snapshot,
    sort_projects_by_version,
)
def _merge_responses(
    *responses: dict[int | str, dict[str, Any]],
) -> dict[int | str, dict[str, Any]]:
    merged: dict[int | str, dict[str, Any]] = {}
    for response in responses:
        merged.update(response)
    return merged


@dataclass(frozen=True)
class TMRescoreRouteDeps:
    get_user_role: Callable[[str], str]
    prepare_tmrescore_inventory_or_raise: Callable[
        [str, str, DTClient], Awaitable[dict[str, Any]]
    ]
    prune_tmrescore_analysis_tasks: Callable[[], None]
    create_tracked_task: Callable[[Coroutine[Any, Any, Any]], asyncio.Task[Any]]
    run_tmrescore_analysis_task: Callable[..., Coroutine[Any, Any, Any]]
    build_tmrescore_cached_state: Callable[[dict[str, Any], bool], dict[str, Any]]
    get_latest_tmrescore_project_task: Callable[[str, str], dict[str, Any] | None]
    persist_tmrescore_project_snapshot: Callable[[str, dict[str, Any]], None]
    describe_tmrescore_progress: Callable[[str, int], str]
    tmrescore_project_cache: dict[str, dict[str, Any]]
    tmrescore_analysis_tasks: dict[str, dict[str, Any]]
    logger: logging.Logger
    media_type_json: str
    tmrescore_not_configured_detail: str
    dependency_track_unavailable_detail: str
    tmrescore_disabled_detail: str


def _safe_project_filename(project_name: str) -> str:
    return (
        "".join(
            character if character.isalnum() or character in {"-", "_", "."} else "-"
            for character in project_name
        ).strip("-")
        or "project"
    )


def _tmrescore_task_for_user(
    deps: TMRescoreRouteDeps,
    session_id: str,
    user: str,
) -> dict[str, Any] | None:
    task = deps.tmrescore_analysis_tasks.get(session_id)
    if not isinstance(task, dict) or task.get("_owner") != user:
        return None
    return task


def _require_tmrescore_task_for_user(
    deps: TMRescoreRouteDeps,
    session_id: str,
    user: str,
) -> dict[str, Any]:
    task = _tmrescore_task_for_user(deps, session_id, user)
    if task is None:
        raise HTTPException(status_code=404, detail="TMRescore session not found")
    return task


def _register_tmrescore_context_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    client_dependency: Callable[..., Any],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/projects/{project_name}/tmrescore/context",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    async def get_tmrescore_context(
        project_name: str,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()

        llm_enrichment_available = False
        llm_enrichment_status = "integration_disabled"
        llm_enrichment_warning = None
        llm_backend = None
        llm_provider = None
        llm_model = None

        if settings.enabled:
            try:
                async with TMRescoreClient(settings) as tmrescore_client:
                    health = await tmrescore_client.get_health()
                llm_enrichment_available = bool(
                    health.get("llm_configured", health.get("ollama_configured", False))
                )
                llm_backend = health.get("llm_backend") or (
                    "ollama" if health.get("ollama_configured") else None
                )
                llm_provider = health.get("llm_provider") or (
                    "Ollama" if llm_backend == "ollama" else None
                )
                llm_model = health.get("llm_model")
                llm_enrichment_status = (
                    "available" if llm_enrichment_available else "not_configured"
                )
                if not llm_enrichment_available:
                    llm_enrichment_warning = "LLM enrichment requires a configured LLM backend in vscorer."
            except Exception as exc:
                llm_enrichment_status = "unreachable"
                deps.logger.warning(
                    "Unable to determine vscorer LLM configuration for %s: %s",
                    project_name,
                    exc,
                )
                llm_enrichment_warning = "Could not verify LLM enrichment availability from the tmrescore backend."
        else:
            llm_enrichment_warning = deps.tmrescore_disabled_detail

        try:
            projects = await client.get_projects(project_name)
        except Exception as exc:
            deps.logger.error("Error fetching projects for tmrescore context: %s", exc)
            raise HTTPException(
                status_code=503,
                detail=deps.dependency_track_unavailable_detail,
            )

        versions = [
            project for project in projects if project.get("name") == project_name
        ]
        versions = sort_projects_by_version(versions)
        if not versions:
            raise HTTPException(status_code=404, detail="Project not found")

        latest_version = versions[-1].get("version", "unknown")
        return {
            "enabled": settings.enabled,
            "project_name": project_name,
            "latest_version": latest_version,
            "versions": [version.get("version") for version in versions],
            "recommended_scope": "merged_versions",
            "scopes": [
                {
                    "id": "merged_versions",
                    "label": "Merged Multi-Version SBOM",
                    "description": "Recommended. Builds a synthetic analysis-only SBOM with separate roots per project version so historical findings stay attached to the components that actually carried them.",
                },
                {
                    "id": "latest_only",
                    "label": "Latest Version Only",
                    "description": "Uses only the latest Dependency-Track version. This is a clean single-version snapshot, but it intentionally ignores findings that exist only in older releases.",
                },
            ],
            "warnings": [
                "Do not combine the latest SBOM with vulnerabilities from older versions. That would create false positives on components that are not part of that inventory.",
                "The merged mode produces an analysis-only synthetic SBOM. It is appropriate for threat-model rescoring, but not as a deployable inventory attestation.",
                "Upload the current threat model and optional mapping inputs for each run so the rescoring reflects the latest architecture assumptions.",
            ],
            "llm_enrichment": {
                "available": llm_enrichment_available,
                "status": llm_enrichment_status,
                "model": llm_model,
                "backend": llm_backend,
                "provider": llm_provider,
                "host_configured": llm_enrichment_available,
                "warning": llm_enrichment_warning,
            },
        }


def _register_tmrescore_inventory_routes(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    bad_request_response: dict[int | str, dict[str, Any]],
    not_found_response: dict[int | str, dict[str, Any]],
    service_unavailable_response: dict[int | str, dict[str, Any]],
    client_dependency: Callable[..., Any],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/projects/{project_name}/tmrescore/sbom",
        responses=_merge_responses(
            bad_request_response,
            not_found_response,
            service_unavailable_response,
        ),
    )
    async def download_tmrescore_analysis_sbom(
        project_name: str,
        scope: str = "merged_versions",
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        inventory = await deps.prepare_tmrescore_inventory_or_raise(
            project_name,
            scope,
            client,
        )
        synthetic_sbom = inventory["synthetic_sbom"]
        latest_version = inventory["latest_version"]
        filename = f"{_safe_project_filename(project_name)}-{scope}-{latest_version}-analysis-sbom.cyclonedx.json"
        return Response(
            content=json.dumps(synthetic_sbom, indent=2),
            media_type=deps.media_type_json,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @router.get(
        "/projects/{project_name}/tmrescore/sbom/summary",
        responses=_merge_responses(
            bad_request_response,
            not_found_response,
            service_unavailable_response,
        ),
    )
    async def get_tmrescore_analysis_sbom_summary(
        project_name: str,
        scope: str = "merged_versions",
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        inventory = await deps.prepare_tmrescore_inventory_or_raise(
            project_name,
            scope,
            client,
        )
        synthetic_sbom = inventory["synthetic_sbom"]
        return {
            "scope": scope,
            "latest_version": inventory["latest_version"],
            "analyzed_versions": inventory["analyzed_versions"],
            "component_count": len(synthetic_sbom.get("components") or []),
            "vulnerability_count": len(synthetic_sbom.get("vulnerabilities") or []),
            "strategy_note": inventory["strategy_note"],
        }


def _register_tmrescore_analysis_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    client_dependency: Callable[..., Any],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.post(
        "/projects/{project_name}/tmrescore/analyze",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    async def analyze_project_with_tmrescore(
        project_name: str,
        threatmodel: Annotated[UploadFile, File(...)],
        items_csv: Annotated[UploadFile | None, File()] = None,
        config: Annotated[UploadFile | None, File()] = None,
        countermeasures: Annotated[UploadFile | None, File()] = None,
        scope: Annotated[str, Form()] = "merged_versions",
        chain_analysis: Annotated[bool, Form()] = True,
        prioritize: Annotated[bool, Form()] = True,
        what_if: Annotated[bool, Form()] = False,
        enrich: Annotated[bool, Form()] = False,
        mitre_enrichment: Annotated[bool, Form()] = False,
        offline: Annotated[bool, Form()] = False,
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)
        if enrich and offline:
            raise HTTPException(
                status_code=422,
                detail="LLM enrichment cannot run when offline mode is enabled.",
            )

        inventory = await deps.prepare_tmrescore_inventory_or_raise(
            project_name,
            scope,
            client,
        )
        latest_version = inventory["latest_version"]
        synthetic_sbom = inventory["synthetic_sbom"]
        dtvp_original_proposals = inventory["dtvp_original_proposals"]
        session_version_label = (
            latest_version
            if scope == "latest_only"
            else f"multi-version:{latest_version}"
        )

        threatmodel_bytes = await threatmodel.read()
        items_csv_bytes = await items_csv.read() if items_csv else None
        config_bytes = await config.read() if config else None
        countermeasures_bytes = await countermeasures.read() if countermeasures else None
        deps.prune_tmrescore_analysis_tasks()

        async with TMRescoreClient(settings) as tmrescore_client:
            llm_runtime = {}
            if enrich:
                try:
                    health = await tmrescore_client.get_health()
                    llm_runtime = {
                        "model": health.get("llm_model"),
                        "backend": health.get("llm_backend"),
                        "provider": health.get("llm_provider"),
                    }
                except Exception as exc:
                    deps.logger.warning(
                        "Unable to record the vscorer LLM model for %s: %s",
                        project_name,
                        exc,
                    )
            session = await tmrescore_client.create_session(
                project_name, session_version_label
            )
            session_id = session.get("session_id") or ""
            if session_id and countermeasures_bytes is not None:
                await tmrescore_client.upload_countermeasures(
                    session_id,
                    countermeasures_bytes,
                )

        if not session_id:
            raise HTTPException(
                status_code=503, detail="TMRescore session creation failed"
            )

        task = {
            "_owner": user,
            "session_id": session_id,
            "project_name": project_name,
            "session": session,
            "scope": scope,
            "latest_version": latest_version,
            "analyzed_versions": inventory["analyzed_versions"],
            "sbom_component_count": len(synthetic_sbom.get("components") or []),
            "sbom_vulnerability_count": len(
                synthetic_sbom.get("vulnerabilities") or []
            ),
            "strategy_note": inventory["strategy_note"],
            "llm_enrichment": {
                "enabled": enrich,
                **llm_runtime,
            },
            "analysis_options": {
                "chain_analysis": chain_analysis,
                "prioritize": prioritize,
                "what_if": what_if,
                "mitre_enrichment": mitre_enrichment,
                "offline": offline,
            },
            "status": "running",
            "progress": 10,
            "message": "Queued tmrescore analysis.",
            "log": ["Queued tmrescore analysis."],
            "result": None,
            "error": None,
            "created_at": datetime.now().timestamp(),
            "updated_at": datetime.now().timestamp(),
            "completed_at": None,
        }
        deps.tmrescore_analysis_tasks[session_id] = task

        deps.create_tracked_task(
            deps.run_tmrescore_analysis_task(
                task,
                settings,
                project_name,
                threatmodel_bytes,
                synthetic_sbom,
                dtvp_original_proposals,
                items_csv_bytes,
                config_bytes,
                chain_analysis,
                prioritize,
                what_if,
                enrich,
                mitre_enrichment,
                offline,
            )
        )

        return deps.build_tmrescore_cached_state(task, False)


def _register_tmrescore_cached_state_routes(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    not_found_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/projects/{project_name}/tmrescore/proposals",
        responses=not_found_response,
    )
    async def get_tmrescore_project_proposals(
        project_name: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        cached = deps.tmrescore_project_cache.get(project_name)
        if not cached:
            raise HTTPException(
                status_code=404,
                detail="No cached threat-model proposals are available for this project yet.",
            )
        normalized_cached = normalize_tmrescore_snapshot(cached)
        if normalized_cached != cached:
            deps.persist_tmrescore_project_snapshot(project_name, normalized_cached)
        return normalized_cached

    @router.get(
        "/projects/{project_name}/tmrescore/state",
        responses=not_found_response,
    )
    async def get_tmrescore_project_state(
        project_name: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        task = deps.get_latest_tmrescore_project_task(project_name, user)
        if not task:
            raise HTTPException(
                status_code=404,
                detail="No cached tmrescore analysis state is available for this project.",
            )
        include_result = str(task.get("status") or "").lower() == "completed"
        return deps.build_tmrescore_cached_state(task, include_result)


def _register_tmrescore_progress_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    service_unavailable_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/tmrescore/sessions/{session_id}/progress",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_progress(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        task = _require_tmrescore_task_for_user(deps, session_id, user)
        return deps.build_tmrescore_cached_state(task, False)


def _register_tmrescore_results_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/tmrescore/sessions/{session_id}/results",
        responses={
            409: {"description": "Conflict"},
            503: {"description": "Service unavailable"},
        },
    )
    async def get_tmrescore_results(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        task = _require_tmrescore_task_for_user(deps, session_id, user)
        if task.get("result"):
            return task["result"]
        status = str(task.get("status") or "running").lower()
        if status == "failed":
            raise HTTPException(
                status_code=409,
                detail=task.get("error") or "TMRescore analysis failed",
            )
        raise HTTPException(
            status_code=409,
            detail="TMRescore analysis is not complete yet. Poll /progress until status is completed.",
        )


def _register_tmrescore_download_routes(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    service_unavailable_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/tmrescore/sessions/{session_id}/results/json",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_results_json(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        _require_tmrescore_task_for_user(deps, session_id, user)
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            return await tmrescore_client.get_results_json(session_id)

    @router.get(
        "/tmrescore/sessions/{session_id}/results/vex",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_results_vex(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        _require_tmrescore_task_for_user(deps, session_id, user)
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            return await tmrescore_client.get_results_vex(session_id)

    @router.get(
        "/tmrescore/sessions/{session_id}/outputs/{filename}",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_output_file(
        session_id: str,
        filename: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        deps.prune_tmrescore_analysis_tasks()
        _require_tmrescore_task_for_user(deps, session_id, user)
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            response = await tmrescore_client.get_output_file(session_id, filename)

        media_type = response.headers.get("content-type", "application/octet-stream")
        content_disposition = response.headers.get("content-disposition")
        headers = {}
        if content_disposition:
            headers["content-disposition"] = content_disposition
        return Response(
            content=response.content, media_type=media_type, headers=headers
        )


def create_tmrescore_router(
    deps: TMRescoreRouteDeps,
    *,
    bad_request_response: dict[int | str, dict[str, Any]],
    not_found_response: dict[int | str, dict[str, Any]],
    service_unavailable_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()

    async def reviewer_user(
        user: Annotated[str, Depends(current_user_dependency)],
    ) -> str:
        require_reviewer(deps.get_user_role(user))
        return user

    _register_tmrescore_context_route(
        router,
        deps,
        client_dependency,
        reviewer_user,
    )
    _register_tmrescore_inventory_routes(
        router,
        deps,
        bad_request_response,
        not_found_response,
        service_unavailable_response,
        client_dependency,
        reviewer_user,
    )
    _register_tmrescore_analysis_route(
        router,
        deps,
        client_dependency,
        reviewer_user,
    )
    _register_tmrescore_cached_state_routes(
        router,
        deps,
        not_found_response,
        reviewer_user,
    )
    _register_tmrescore_progress_route(
        router,
        deps,
        service_unavailable_response,
        reviewer_user,
    )
    _register_tmrescore_results_route(router, deps, reviewer_user)
    _register_tmrescore_download_routes(
        router,
        deps,
        service_unavailable_response,
        reviewer_user,
    )

    return router
