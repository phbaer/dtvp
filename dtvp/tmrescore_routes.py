import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Awaitable, Callable, Coroutine

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Response, UploadFile

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


def _get_default_vscorer_ollama_model() -> str:
    return (
        os.getenv("DTVP_VSCORER_OLLAMA_MODEL")
        or os.getenv("DTVP_TMRESCORE_OLLAMA_MODEL")
        or "qwen2.5:7b"
    )


@dataclass(frozen=True)
class TMRescoreRouteDeps:
    prepare_tmrescore_inventory_or_raise: Callable[
        [str, str, DTClient], Awaitable[dict[str, Any]]
    ]
    prune_tmrescore_analysis_tasks: Callable[[], None]
    create_tracked_task: Callable[[Coroutine[Any, Any, Any]], asyncio.Task[Any]]
    run_tmrescore_analysis_task: Callable[..., Coroutine[Any, Any, Any]]
    build_tmrescore_cached_state: Callable[[dict[str, Any], bool], dict[str, Any]]
    get_latest_tmrescore_project_task: Callable[[str], dict[str, Any] | None]
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


def _normalize_vscorer_wizard_context(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload or {})
    editor = normalized.get("editor")
    threat_model_editor = normalized.get("threat_model_editor")
    if editor is None and threat_model_editor is not None:
        normalized["editor"] = threat_model_editor
    if threat_model_editor is None and editor is not None:
        normalized["threat_model_editor"] = editor

    readiness = normalized.get("readiness")
    if (
        normalized.get("missing_inputs") is None
        and isinstance(readiness, dict)
        and isinstance(readiness.get("missing"), dict)
    ):
        normalized["missing_inputs"] = readiness["missing"]

    return normalized


def _store_vscorer_wizard_context(
    task: dict[str, Any],
    wizard_context: dict[str, Any],
    wizard_catalogs: dict[str, Any] | None = None,
) -> None:
    task["wizard_context"] = _normalize_vscorer_wizard_context(wizard_context)
    if wizard_catalogs is not None:
        task["wizard_catalogs"] = wizard_catalogs


def _get_tracked_vscorer_task(
    deps: TMRescoreRouteDeps,
    session_id: str,
) -> dict[str, Any]:
    deps.prune_tmrescore_analysis_tasks()
    task = deps.tmrescore_analysis_tasks.get(session_id)
    if not task:
        raise HTTPException(
            status_code=404,
            detail="No VScorer session is available in DTVP for this session id.",
        )
    return task


def _touch_vscorer_task_message(
    task: dict[str, Any],
    message: str,
    *,
    min_progress: int | None = None,
) -> None:
    now = datetime.now().timestamp()
    task["message"] = message
    task["updated_at"] = now
    if min_progress is not None and str(task.get("status") or "").lower() == "prepared":
        task["progress"] = max(int(task.get("progress") or 0), min_progress)
    log = task.setdefault("log", [])
    if not log or log[-1] != message:
        log.append(message)


def _forward_vscorer_file_response(response: Any) -> Response:
    media_type = response.headers.get("content-type", "application/octet-stream")
    content_disposition = response.headers.get("content-disposition")
    headers = {}
    if content_disposition:
        headers["content-disposition"] = content_disposition
    return Response(content=response.content, media_type=media_type, headers=headers)


def _register_tmrescore_context_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    client_dependency: Callable[..., Any],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/projects/{project_name}/vscorer/context",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
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

        if settings.enabled:
            try:
                async with TMRescoreClient(settings) as tmrescore_client:
                    health = await tmrescore_client.get_health()
                llm_enrichment_available = bool(health.get("ollama_configured"))
                llm_enrichment_status = (
                    "available" if llm_enrichment_available else "not_configured"
                )
                if not llm_enrichment_available:
                    llm_enrichment_warning = "LLM enrichment requires OLLAMA_HOST to be configured on the VScorer backend."
            except Exception as exc:
                llm_enrichment_status = "unreachable"
                deps.logger.warning(
                    "Unable to determine VScorer Ollama configuration for %s: %s",
                    project_name,
                    exc,
                )
                llm_enrichment_warning = "Could not verify LLM enrichment availability from the VScorer backend."
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
        wizard_url = f"{settings.base_url}/wizard" if settings.enabled else None
        return {
            "enabled": settings.enabled,
            "wizard_url": wizard_url,
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
                "default_model": _get_default_vscorer_ollama_model(),
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
        "/projects/{project_name}/vscorer/sbom",
        responses=_merge_responses(
            bad_request_response,
            not_found_response,
            service_unavailable_response,
        ),
    )
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
        "/projects/{project_name}/vscorer/sbom/summary",
        responses=_merge_responses(
            bad_request_response,
            not_found_response,
            service_unavailable_response,
        ),
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
        "/projects/{project_name}/vscorer/import",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.post(
        "/projects/{project_name}/tmrescore/import",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    async def import_project_into_vscorer_wizard(
        project_name: str,
        threatmodel: Annotated[UploadFile, File(...)],
        items_csv: Annotated[UploadFile | None, File()] = None,
        config: Annotated[UploadFile | None, File()] = None,
        scope: Annotated[str, Form()] = "merged_versions",
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        inventory = await deps.prepare_tmrescore_inventory_or_raise(
            project_name,
            scope,
            client,
        )
        latest_version = inventory["latest_version"]
        synthetic_sbom = inventory["synthetic_sbom"]
        session_version_label = (
            latest_version
            if scope == "latest_only"
            else f"multi-version:{latest_version}"
        )

        threatmodel_bytes = await threatmodel.read()
        items_csv_bytes = await items_csv.read() if items_csv else None
        config_bytes = await config.read() if config else None
        deps.prune_tmrescore_analysis_tasks()

        async with TMRescoreClient(settings) as tmrescore_client:
            session = await tmrescore_client.create_session(
                project_name, session_version_label
            )
            session_id = session.get("session_id") or ""
            if not session_id:
                raise HTTPException(
                    status_code=503,
                    detail="VScorer session creation failed",
                )

            upload_results = {
                "threatmodel": await tmrescore_client.upload_threatmodel(
                    session_id,
                    threatmodel_bytes,
                    threatmodel.filename or "threatmodel.tm7",
                ),
                "sbom": await tmrescore_client.upload_sbom(
                    session_id,
                    json.dumps(synthetic_sbom).encode("utf-8"),
                    f"{_safe_project_filename(project_name)}-{scope}-{latest_version}-analysis-sbom.cdx.json",
                ),
            }
            if items_csv_bytes is not None:
                upload_results["items_csv"] = await tmrescore_client.upload_items_csv(
                    session_id,
                    items_csv_bytes,
                    items_csv.filename or "items.csv",
                )
            if config_bytes is not None:
                upload_results["config"] = await tmrescore_client.upload_config(
                    session_id,
                    config_bytes,
                    config.filename or "config.yaml",
                )

            wizard_context = await tmrescore_client.get_wizard_context(session_id)
            wizard_catalogs = await tmrescore_client.get_wizard_catalogs(session_id)

        now = datetime.now().timestamp()
        task = {
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
            "llm_enrichment": {"enabled": False, "ollama_model": None},
            "status": "prepared",
            "progress": 25,
            "message": "VScorer wizard session prepared.",
            "log": [
                "Created VScorer session.",
                "Uploaded threat model and synthetic SBOM to VScorer.",
                "Loaded VScorer wizard context and catalogs.",
            ],
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
            "wizard_context": _normalize_vscorer_wizard_context(wizard_context),
            "wizard_catalogs": wizard_catalogs,
            "wizard_url": f"{settings.base_url}/wizard",
            "upload_results": upload_results,
            "dtvp_original_proposals": inventory["dtvp_original_proposals"],
        }
        deps.tmrescore_analysis_tasks[session_id] = task

        return deps.build_tmrescore_cached_state(task, False)

    @router.post(
        "/vscorer/sessions/{session_id}/analyze",
        responses={
            404: {"description": "Not found"},
            409: {"description": "Conflict"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.post(
        "/tmrescore/sessions/{session_id}/analyze",
        responses={
            404: {"description": "Not found"},
            409: {"description": "Conflict"},
            503: {"description": "Service unavailable"},
        },
    )
    async def analyze_prepared_vscorer_session(
        session_id: str,
        chain_analysis: Annotated[bool, Form()] = True,
        prioritize: Annotated[bool, Form()] = True,
        what_if: Annotated[bool, Form()] = False,
        enrich: Annotated[bool, Form()] = False,
        ollama_model: Annotated[str, Form()] = "qwen2.5:7b",
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        deps.prune_tmrescore_analysis_tasks()
        task = deps.tmrescore_analysis_tasks.get(session_id)
        if not task:
            raise HTTPException(
                status_code=404,
                detail="No prepared VScorer session is available in DTVP for this session id.",
            )

        normalized_status = str(task.get("status") or "").lower()
        if normalized_status == "running":
            return deps.build_tmrescore_cached_state(task, False)
        if normalized_status == "completed":
            return deps.build_tmrescore_cached_state(task, True)
        if normalized_status not in {"prepared", "created", "failed"}:
            raise HTTPException(
                status_code=409,
                detail=f"VScorer session cannot be started from status '{task.get('status')}'.",
            )

        now = datetime.now().timestamp()
        task["status"] = "running"
        task["progress"] = max(int(task.get("progress") or 0), 30)
        task["message"] = "Queued VScorer analysis from prepared wizard session."
        task["llm_enrichment"] = {
            "enabled": enrich,
            "ollama_model": ollama_model if enrich else None,
        }
        task["error"] = None
        task["updated_at"] = now
        task["completed_at"] = None
        log = task.setdefault("log", [])
        if not log or log[-1] != task["message"]:
            log.append(task["message"])

        deps.create_tracked_task(
            deps.run_tmrescore_analysis_task(
                task,
                settings,
                task["project_name"],
                None,
                None,
                task.get("dtvp_original_proposals") or {},
                None,
                None,
                chain_analysis,
                prioritize,
                what_if,
                enrich,
                ollama_model,
                True,
            )
        )

        return deps.build_tmrescore_cached_state(task, False)

    @router.post(
        "/vscorer/sessions/{session_id}/wizard/refresh",
        responses={
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.post(
        "/tmrescore/sessions/{session_id}/wizard/refresh",
        responses={
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    async def refresh_prepared_vscorer_wizard_context(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        task = _get_tracked_vscorer_task(deps, session_id)

        async with TMRescoreClient(settings) as tmrescore_client:
            _store_vscorer_wizard_context(
                task,
                await tmrescore_client.get_wizard_context(session_id),
                await tmrescore_client.get_wizard_catalogs(session_id),
            )

        task["wizard_url"] = f"{settings.base_url}/wizard"
        _touch_vscorer_task_message(
            task,
            "Refreshed VScorer wizard context.",
            min_progress=25,
        )

        return deps.build_tmrescore_cached_state(task, False)

    @router.post(
        "/vscorer/sessions/{session_id}/wizard/validate",
        responses={
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.post(
        "/tmrescore/sessions/{session_id}/wizard/validate",
        responses={
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    async def validate_prepared_vscorer_wizard_inputs(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        task = _get_tracked_vscorer_task(deps, session_id)

        async with TMRescoreClient(settings) as tmrescore_client:
            validation = await tmrescore_client.get_validator_report(session_id)
            context = await tmrescore_client.get_wizard_context(session_id)

        normalized_context = _normalize_vscorer_wizard_context(context)
        normalized_context["validation"] = validation
        task["wizard_context"] = normalized_context
        task["wizard_validation"] = validation
        _touch_vscorer_task_message(
            task,
            "Validated VScorer wizard inputs.",
            min_progress=28,
        )

        return deps.build_tmrescore_cached_state(task, False)

    @router.get(
        "/vscorer/sessions/{session_id}/wizard/editor",
        responses={
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.get(
        "/tmrescore/sessions/{session_id}/wizard/editor",
        responses={
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    async def get_prepared_vscorer_wizard_editor(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        task = _get_tracked_vscorer_task(deps, session_id)

        async with TMRescoreClient(settings) as tmrescore_client:
            editor = await tmrescore_client.get_threat_model_editor(session_id)

        context = _normalize_vscorer_wizard_context(task.get("wizard_context") or {})
        context["editor"] = editor
        context["threat_model_editor"] = editor
        task["wizard_context"] = context
        task["wizard_editor"] = editor
        _touch_vscorer_task_message(
            task,
            "Loaded VScorer threat-model editor state.",
            min_progress=28,
        )

        return deps.build_tmrescore_cached_state(task, False)

    @router.patch(
        "/vscorer/sessions/{session_id}/wizard/editor",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.patch(
        "/tmrescore/sessions/{session_id}/wizard/editor",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            422: {"description": "Unprocessable content"},
            503: {"description": "Service unavailable"},
        },
    )
    async def patch_prepared_vscorer_wizard_editor(
        session_id: str,
        patches: Annotated[list[dict[str, Any]], Body(embed=True)],
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)
        if not patches:
            raise HTTPException(
                status_code=400,
                detail="At least one VScorer editor patch is required.",
            )

        task = _get_tracked_vscorer_task(deps, session_id)

        async with TMRescoreClient(settings) as tmrescore_client:
            editor_result = await tmrescore_client.patch_threat_model_editor(
                session_id,
                patches,
            )
            context = await tmrescore_client.get_wizard_context(session_id)

        editor = editor_result.get("editor") or editor_result
        normalized_context = _normalize_vscorer_wizard_context(context)
        normalized_context["editor"] = editor
        normalized_context["threat_model_editor"] = editor
        task["wizard_context"] = normalized_context
        task["wizard_editor"] = editor
        task["wizard_editor_result"] = editor_result
        _touch_vscorer_task_message(
            task,
            "Updated VScorer threat-model editor state.",
            min_progress=30,
        )

        return deps.build_tmrescore_cached_state(task, False)

    @router.get(
        "/vscorer/sessions/{session_id}/wizard/threatmodel",
        responses={
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    @router.get(
        "/tmrescore/sessions/{session_id}/wizard/threatmodel",
        responses={
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
    async def download_prepared_vscorer_threat_model(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

        _get_tracked_vscorer_task(deps, session_id)

        async with TMRescoreClient(settings) as tmrescore_client:
            response = await tmrescore_client.get_threat_model_file(session_id)

        return _forward_vscorer_file_response(response)

    @router.post(
        "/projects/{project_name}/vscorer/analyze",
        responses={
            400: {"description": "Bad request"},
            404: {"description": "Not found"},
            503: {"description": "Service unavailable"},
        },
    )
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
        scope: Annotated[str, Form()] = "merged_versions",
        chain_analysis: Annotated[bool, Form()] = True,
        prioritize: Annotated[bool, Form()] = True,
        what_if: Annotated[bool, Form()] = False,
        enrich: Annotated[bool, Form()] = False,
        ollama_model: Annotated[str, Form()] = "qwen2.5:7b",
        *,
        client: Annotated[DTClient, Depends(client_dependency)],
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(status_code=503, detail=deps.tmrescore_disabled_detail)

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
        deps.prune_tmrescore_analysis_tasks()

        async with TMRescoreClient(settings) as tmrescore_client:
            session = await tmrescore_client.create_session(
                project_name, session_version_label
            )
            session_id = session.get("session_id") or ""

        if not session_id:
            raise HTTPException(
                status_code=503, detail="VScorer session creation failed"
            )

        task = {
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
                "ollama_model": ollama_model if enrich else None,
            },
            "status": "running",
            "progress": 10,
            "message": "Queued VScorer analysis.",
            "log": ["Queued VScorer analysis."],
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
                ollama_model,
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
        "/projects/{project_name}/vscorer/proposals",
        responses=not_found_response,
    )
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
        "/projects/{project_name}/vscorer/state",
        responses=not_found_response,
    )
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
        task = deps.get_latest_tmrescore_project_task(project_name)
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
        "/vscorer/sessions/{session_id}/progress",
        responses=service_unavailable_response,
    )
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
        task = deps.tmrescore_analysis_tasks.get(session_id)
        if task:
            return deps.build_tmrescore_cached_state(task, False)

        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            payload = await tmrescore_client.get_progress(session_id)

        status = str(payload.get("status") or "running")
        progress = int(payload.get("progress") or 0)
        message = payload.get("message") or deps.describe_tmrescore_progress(
            status,
            progress,
        )
        return {
            "session_id": session_id,
            "status": status,
            "progress": progress,
            "message": message,
            "log": [message],
            "error": None,
            "result": None,
        }


def _register_tmrescore_results_route(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/vscorer/sessions/{session_id}/results",
        responses={
            409: {"description": "Conflict"},
            503: {"description": "Service unavailable"},
        },
    )
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
        task = deps.tmrescore_analysis_tasks.get(session_id)
        if task:
            if task.get("result"):
                return task["result"]
            status = str(task.get("status") or "running").lower()
            if status == "failed":
                raise HTTPException(
                    status_code=409,
                    detail=task.get("error") or "VScorer analysis failed",
                )
            raise HTTPException(
                status_code=409,
                detail="VScorer analysis is not complete yet. Poll /progress until status is completed.",
            )

        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            return await tmrescore_client.get_results(session_id)


def _register_tmrescore_download_routes(
    router: APIRouter,
    deps: TMRescoreRouteDeps,
    service_unavailable_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get(
        "/vscorer/sessions/{session_id}/results/json",
        responses=service_unavailable_response,
    )
    @router.get(
        "/tmrescore/sessions/{session_id}/results/json",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_results_json(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            return await tmrescore_client.get_results_json(session_id)

    @router.get(
        "/vscorer/sessions/{session_id}/results/vex",
        responses=service_unavailable_response,
    )
    @router.get(
        "/tmrescore/sessions/{session_id}/results/vex",
        responses=service_unavailable_response,
    )
    async def get_tmrescore_results_vex(
        session_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = TMRescoreSettings()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.tmrescore_not_configured_detail,
            )

        async with TMRescoreClient(settings) as tmrescore_client:
            return await tmrescore_client.get_results_vex(session_id)

    @router.get(
        "/vscorer/sessions/{session_id}/outputs/{filename}",
        responses=service_unavailable_response,
    )
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

    _register_tmrescore_context_route(
        router,
        deps,
        client_dependency,
        current_user_dependency,
    )
    _register_tmrescore_inventory_routes(
        router,
        deps,
        bad_request_response,
        not_found_response,
        service_unavailable_response,
        client_dependency,
        current_user_dependency,
    )
    _register_tmrescore_analysis_route(
        router,
        deps,
        client_dependency,
        current_user_dependency,
    )
    _register_tmrescore_cached_state_routes(
        router,
        deps,
        not_found_response,
        current_user_dependency,
    )
    _register_tmrescore_progress_route(
        router,
        deps,
        service_unavailable_response,
        current_user_dependency,
    )
    _register_tmrescore_results_route(router, deps, current_user_dependency)
    _register_tmrescore_download_routes(
        router,
        deps,
        service_unavailable_response,
        current_user_dependency,
    )

    return router
