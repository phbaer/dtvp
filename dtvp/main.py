import asyncio
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import (
    Any,
    AsyncIterator,
    Dict,
)

from fastapi import (
    APIRouter,
    FastAPI,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .analysis_queue_services import (
    get_next_queued_item as get_next_queued_item_impl,
)
from .analysis_queue_services import (
    process_analysis_queue_item,
    prune_finished_queue_items,
    reindex_queue_items,
    run_analysis_queue_cleanup_loop,
    run_analysis_queue_worker,
    start_analysis_queue_item,
)
from .app_bootstrap import build_cors_origins, normalize_context_path
from .app_constants import (
    BACKEND_SBOM_FILENAME,
    BAD_REQUEST_RESPONSE,
    CODE_ANALYSIS_NOT_CONFIGURED_DETAIL,
    FORBIDDEN_RESPONSE,
    FRONTEND_SBOM_FILENAME,
    HTML_SBOM_FILENAME,
    MEDIA_TYPE_JSON,
    NOT_FOUND_RESPONSE,
    SERVICE_UNAVAILABLE_RESPONSE,
    TMRESCORE_NOT_CONFIGURED_DETAIL,
)
from .app_info_routes import create_app_info_router
from .app_info_services import build_sbom_html, load_changelog_content
from .app_info_services import get_sbom_path as get_sbom_path_impl
from .app_info_services import load_pyproject_metadata as load_pyproject_metadata_impl
from .app_wiring import (
    build_analysis_queue,
    build_analysis_queue_runtime_deps,
    build_analysis_queue_service_deps,
    build_app_info_route_deps,
    build_assessment_service_deps,
    build_code_analysis_route_deps,
    build_frontend_route_deps,
    build_general_api_route_deps,
    build_grouped_vuln_service_deps,
    build_prepare_tmrescore_inventory_or_raise,
    build_project_archive_route_deps,
    build_project_archive_service_deps,
    build_settings_route_deps,
    build_startup_service_deps,
    build_tmrescore_cache_service_deps,
    build_tmrescore_execution_service_deps,
    build_tmrescore_inventory_service_deps,
    build_tmrescore_route_deps,
    build_tmrescore_task_service_deps,
)
from .auth import auth_settings, get_current_user, validate_auth_configuration
from .auth import router as auth_router
from .auto_analysis_services import (
    AutoAnalysisSweepDeps,
    apply_auto_analysis_sweep_plan,
    build_existing_open_vulnerability_sweep_plan,
    get_auto_code_analysis_enabled,
)
from .auto_analysis_services import (
    queue_open_vulnerabilities_for_analysis as queue_open_vulnerabilities_for_analysis_impl,
)
from .code_analysis_integration import CodeAnalysisClient, CodeAnalysisSettings
from .code_analysis_result_services import CodeAnalysisResultStore
from .code_analysis_routes import create_code_analysis_router
from .dt_cache import CacheManager, cache_manager
from .dt_client import DTClient, DTSettings, get_client
from .file_io_services import read_text as read_text_impl
from .file_io_services import (
    write_and_validate_json_bytes as write_and_validate_json_bytes_impl,
)
from .file_io_services import write_bytes as write_bytes_impl
from .file_io_services import write_json as write_json_impl
from .frontend_routes import register_frontend_routes
from .general_api_routes import (
    create_general_api_router,
)
from .grouped_vuln_services import (
    collect_version_snapshots as collect_grouped_vuln_version_snapshots,
)
from .grouped_vuln_summary_index_services import (
    GroupedVulnSummaryIndex,
    get_grouped_vuln_summary_index_path,
)
from .logic import (
    DEFAULT_DEPENDENCY_CHAIN_LIMIT,
    BOMAnalysisCache,
    build_authorized_analyst_assessment_details,
    calculate_aggregated_state,
    get_auto_analysis_guidance_path,
    get_rescore_rules_path,
    get_team_mapping_path,
    get_user_role,
    get_user_roles_path,
    group_vulnerabilities,
    load_auto_analysis_guidance,
    load_rescore_rules,
    load_team_mapping,
    load_user_roles,
    process_assessment_details,
)
from .project_archive_routes import create_project_archive_router
from .project_archive_services import (
    get_project_archive_interval_seconds,
    get_project_archive_path,
    project_archive_snapshots_enabled,
    run_project_archive_snapshot_once,
)
from .runtime_value_services import get_env_int_with_floor
from .runtime_value_services import (
    parse_iso_timestamp as parse_iso_timestamp_impl,
)
from .settings_routes import create_settings_router
from .startup_services import (
    StartupRuntimeTasks,
    start_application_runtime,
    stop_application_runtime,
)
from .startup_page_services import (
    build_startup_page_html,
    build_startup_status_payload,
    contextual_path,
)
from .tmrescore_cache_services import (
    load_tmrescore_project_cache as load_tmrescore_project_cache_impl,
)
from .tmrescore_cache_services import (
    persist_tmrescore_project_snapshot as persist_tmrescore_project_snapshot_impl,
)
from .tmrescore_errors import InventoryPreparationError
from .tmrescore_integration import (
    SUPPORTED_TMRESCORE_SCOPES,
    TMRescoreClient,
    build_analysis_sbom,
    build_dtvp_vulnerability_proposals,
    normalize_tmrescore_snapshot,
    sort_projects_by_version,
)
from .tmrescore_routes import create_tmrescore_router
from .tmrescore_task_services import (
    append_tmrescore_analysis_log as append_tmrescore_analysis_log_impl,
)
from .tmrescore_task_services import (
    build_tmrescore_analysis_response as build_tmrescore_analysis_response_impl,
)
from .tmrescore_task_services import (
    describe_tmrescore_progress as describe_tmrescore_progress_impl,
)
from .tmrescore_task_services import (
    touch_tmrescore_analysis_task as touch_tmrescore_analysis_task_impl,
)
from .version import BUILD_COMMIT, VERSION
from .vulnerability_support_services import (
    cache_tmrescore_project_results as cache_tmrescore_project_results_impl,
)
from .vulnerability_support_services import (
    get_version_fetch_concurrency as get_version_fetch_concurrency_impl,
)
from .vulnerability_support_services import (
    merge_vulnerability_details as merge_vulnerability_details_impl,
)

logger = logging.getLogger("dtvp")
logger.setLevel(logging.INFO)

background_tasks: set[asyncio.Task[Any]] = set()
app_runtime_state: Dict[str, Any] = {
    "status": "ready",
    "message": "DTVP is ready.",
    "error": None,
}
_runtime_tasks: StartupRuntimeTasks | None = None
_startup_task: asyncio.Task[Any] | None = None


def _set_runtime_state(status: str, message: str, error: str | None = None) -> None:
    app_runtime_state.clear()
    app_runtime_state.update(
        {
            "status": status,
            "message": message,
            "error": error,
        }
    )


def _runtime_ready() -> bool:
    return app_runtime_state.get("status") == "ready"


def _path_with_context(suffix: str) -> str:
    return contextual_path(context_path, suffix)


def _is_startup_status_path(path: str) -> bool:
    return path in {
        _path_with_context("/startup"),
        _path_with_context("/api/startup"),
    }


def _is_api_or_auth_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in (
            _path_with_context("/api"),
            _path_with_context("/auth"),
        )
    )


async def _initialize_application_runtime() -> None:
    global _runtime_tasks
    _set_runtime_state("starting", "DTVP runtime is starting.")
    try:
        _runtime_tasks = await start_application_runtime(startup_service_deps)
        snapshot_task = asyncio.create_task(run_project_archive_snapshot_loop())
        background_tasks.add(snapshot_task)
        snapshot_task.add_done_callback(background_tasks.discard)
        _set_runtime_state("ready", "DTVP is ready.")
    except asyncio.CancelledError:
        _set_runtime_state("stopped", "DTVP startup was stopped.")
        raise
    except Exception as exc:
        logger.exception("DTVP runtime startup failed")
        _set_runtime_state(
            "failed",
            "DTVP startup failed. Check the backend logs.",
            str(exc),
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _runtime_tasks, _startup_task
    validate_auth_configuration()
    _runtime_tasks = None
    _startup_task = asyncio.create_task(_initialize_application_runtime())
    try:
        try:
            await asyncio.wait_for(asyncio.shield(_startup_task), timeout=0.25)
        except TimeoutError:
            pass
        yield
    finally:
        if _startup_task and not _startup_task.done():
            _startup_task.cancel()
            try:
                await _startup_task
            except asyncio.CancelledError:
                pass
        if _runtime_tasks:
            await stop_application_runtime(
                _runtime_tasks,
                analysis_queue,
                background_tasks,
            )
        _set_runtime_state("ready", "DTVP is ready.")


app = FastAPI(title="DTVP", version=VERSION, lifespan=lifespan)


origins = build_cors_origins(
    auth_settings,
    os.getenv("DTVP_CORS_ORIGINS"),
    socket.gethostname,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

context_path = normalize_context_path(auth_settings.CONTEXT_PATH)


@app.middleware("http")
async def runtime_startup_gate(request: Request, call_next):
    if _runtime_ready() or _is_startup_status_path(request.url.path):
        return await call_next(request)

    headers = {"Cache-Control": "no-store"}
    if _is_api_or_auth_path(request.url.path):
        headers["Retry-After"] = "2"
        return JSONResponse(
            build_startup_status_payload(app_runtime_state),
            status_code=503,
            headers=headers,
        )

    return HTMLResponse(
        build_startup_page_html(
            state=app_runtime_state,
            context_path=context_path,
        ),
        headers=headers,
    )

# Auth router
app.include_router(auth_router, prefix=context_path)

# API Router
api_router = APIRouter(prefix="/api", tags=["api"])


@app.get(_path_with_context("/startup"), include_in_schema=False)
async def startup_page():
    if _runtime_ready():
        return RedirectResponse(url=_path_with_context("/"))
    return HTMLResponse(
        build_startup_page_html(
            state=app_runtime_state,
            context_path=context_path,
        ),
        headers={"Cache-Control": "no-store"},
    )


@api_router.get("/startup", include_in_schema=False)
async def startup_status():
    return JSONResponse(
        build_startup_status_payload(app_runtime_state),
        headers={"Cache-Control": "no-store"},
    )


tasks = {}
project_archive_tasks: Dict[str, Dict[str, Any]] = {}
tmrescore_project_cache: Dict[str, Dict[str, Any]] = {}
tmrescore_analysis_tasks: Dict[str, Dict[str, Any]] = {}


def _is_auto_code_analysis_active() -> bool:
    if not get_auto_code_analysis_enabled():
        return False
    return CodeAnalysisSettings().enabled


grouped_vuln_summary_index = GroupedVulnSummaryIndex(
    path_provider=get_grouped_vuln_summary_index_path,
    max_entries_provider=lambda: get_env_int_with_floor(
        "DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES",
        default=64,
        minimum=1,
        logger=logger,
    ),
    logger=logger,
)


grouped_vuln_service_deps = build_grouped_vuln_service_deps(
    cache_manager=cache_manager,
    logger=logger,
    tasks=tasks,
    bom_analysis_cache_cls=BOMAnalysisCache,
    get_version_fetch_concurrency=lambda: get_version_fetch_concurrency_impl(logger),
    merge_vulnerability_details=merge_vulnerability_details_impl,
    sort_projects_by_version=sort_projects_by_version,
    load_team_mapping=lambda: load_team_mapping(),
    group_vulnerabilities=group_vulnerabilities,
    queue_open_vulnerabilities_for_analysis=lambda grouped, team_mapping: (
        queue_open_vulnerabilities_for_analysis_impl(
            analysis_queue=analysis_queue,
            grouped_vulns=grouped,
            team_mapping=team_mapping,
            enabled=_is_auto_code_analysis_active(),
            logger=logger,
            tmrescore_project_cache=tmrescore_project_cache,
            result_store=code_analysis_result_store,
            auto_analysis_guidance=load_auto_analysis_guidance(),
        )
    ),
    summary_index=grouped_vuln_summary_index,
    summary_index_cache_revision=lambda: cache_manager.get_cache_status().get(
        "last_refreshed_at"
    ),
)


tmrescore_cache_service_deps = build_tmrescore_cache_service_deps(
    logger=logger,
    normalize_tmrescore_snapshot=normalize_tmrescore_snapshot,
    shared_cache=tmrescore_project_cache,
)


tmrescore_task_service_deps = build_tmrescore_task_service_deps(
    tmrescore_analysis_tasks=tmrescore_analysis_tasks,
    get_tmrescore_task_ttl_seconds=lambda: get_env_int_with_floor(
        "DTVP_TMRESCORE_TASK_TTL_SECONDS",
        default=3600,
        minimum=60,
        logger=logger,
    ),
    context_path=context_path,
)


tmrescore_execution_service_deps = build_tmrescore_execution_service_deps(
    logger=logger,
    get_tmrescore_client_cls=lambda: TMRescoreClient,
    describe_tmrescore_progress=describe_tmrescore_progress_impl,
    touch_tmrescore_analysis_task=touch_tmrescore_analysis_task_impl,
    append_tmrescore_analysis_log=append_tmrescore_analysis_log_impl,
    cache_tmrescore_project_results=lambda project_name, session_id, scope, latest_version, analyzed_versions, vex_results_document, dtvp_original_proposals=None: (
        cache_tmrescore_project_results_impl(
            project_name,
            session_id,
            scope,
            latest_version,
            analyzed_versions,
            vex_results_document,
            lambda project_name, snapshot: persist_tmrescore_project_snapshot_impl(
                tmrescore_cache_service_deps,
                project_name,
                snapshot,
            ),
            dtvp_original_proposals=dtvp_original_proposals,
        )
    ),
    build_tmrescore_analysis_response=lambda result, task: (
        build_tmrescore_analysis_response_impl(
            tmrescore_task_service_deps,
            result,
            task,
        )
    ),
)

tmrescore_inventory_service_deps = build_tmrescore_inventory_service_deps(
    cache_manager=cache_manager,
    logger=logger,
    supported_tmrescore_scopes=SUPPORTED_TMRESCORE_SCOPES,
    get_version_fetch_concurrency=lambda: get_version_fetch_concurrency_impl(logger),
    merge_vulnerability_details=merge_vulnerability_details_impl,
    sort_projects_by_version=sort_projects_by_version,
    build_analysis_sbom=build_analysis_sbom,
    build_dtvp_vulnerability_proposals=build_dtvp_vulnerability_proposals,
    inventory_error_cls=InventoryPreparationError,
)


prepare_tmrescore_inventory_or_raise = build_prepare_tmrescore_inventory_or_raise(
    tmrescore_inventory_service_deps=tmrescore_inventory_service_deps,
    inventory_error_cls=InventoryPreparationError,
)


assessment_service_deps = build_assessment_service_deps(
    cache_manager=cache_manager,
    logger=logger,
    calculate_aggregated_state=calculate_aggregated_state,
    process_assessment_details=process_assessment_details,
    build_authorized_analyst_assessment_details=(
        build_authorized_analyst_assessment_details
    ),
)

project_archive_service_deps = build_project_archive_service_deps(
    cache_manager=cache_manager,
    logger=logger,
    sort_projects_by_version=sort_projects_by_version,
    version=VERSION,
    build_commit=BUILD_COMMIT,
    archive_path_provider=get_project_archive_path,
)

code_analysis_result_store = CodeAnalysisResultStore(logger=logger)


api_router.include_router(
    create_app_info_router(
        app,
        build_app_info_route_deps(
            version=VERSION,
            build_commit=BUILD_COMMIT,
            cache_manager=cache_manager,
            load_pyproject_metadata=load_pyproject_metadata_impl,
            load_changelog_content=load_changelog_content,
            get_sbom_path=get_sbom_path_impl,
            read_text=read_text_impl,
            build_sbom_html=build_sbom_html,
            backend_sbom_filename=BACKEND_SBOM_FILENAME,
            frontend_sbom_filename=FRONTEND_SBOM_FILENAME,
            html_sbom_filename=HTML_SBOM_FILENAME,
            media_type_json=MEDIA_TYPE_JSON,
        ),
        not_found_response=NOT_FOUND_RESPONSE,
    )
)


api_router.include_router(
    create_general_api_router(
        build_general_api_route_deps(
            cache_manager=cache_manager,
            logger=logger,
            tasks=tasks,
            background_tasks=background_tasks,
            grouped_vuln_service_deps=grouped_vuln_service_deps,
            assessment_service_deps=assessment_service_deps,
            code_analysis_result_store=code_analysis_result_store,
            dt_settings_cls=DTSettings,
            get_dt_client_cls=lambda: DTClient,
            get_user_role=lambda user: get_user_role(user),
            load_rescore_rules=lambda: load_rescore_rules(),
            get_bom_analysis_cache_cls=lambda: BOMAnalysisCache,
            default_dependency_chain_limit=DEFAULT_DEPENDENCY_CHAIN_LIMIT,
            service_unavailable_response=SERVICE_UNAVAILABLE_RESPONSE,
            not_found_response=NOT_FOUND_RESPONSE,
            get_grouped_vuln_task_ttl_seconds=lambda: get_env_int_with_floor(
                "DTVP_GROUPED_VULN_TASK_TTL_SECONDS",
                default=3600,
                minimum=60,
                logger=logger,
            ),
        ),
        current_user_dependency=get_current_user,
        client_dependency=get_client,
    )
)


api_router.include_router(
    create_project_archive_router(
        build_project_archive_route_deps(
            archive_tasks=project_archive_tasks,
            service_deps=project_archive_service_deps,
            logger=logger,
            background_tasks=background_tasks,
            get_user_role=lambda user: get_user_role(user),
            dt_settings_cls=DTSettings,
            get_dt_client_cls=lambda: DTClient,
            archive_path_provider=get_project_archive_path,
        ),
        current_user_dependency=get_current_user,
    )
)


api_router.include_router(
    create_tmrescore_router(
        build_tmrescore_route_deps(
            get_user_role=lambda user: get_user_role(user),
            prepare_tmrescore_inventory_or_raise=prepare_tmrescore_inventory_or_raise,
            tmrescore_task_service_deps=tmrescore_task_service_deps,
            tmrescore_cache_service_deps=tmrescore_cache_service_deps,
            tmrescore_execution_service_deps=tmrescore_execution_service_deps,
            background_tasks=background_tasks,
            tmrescore_project_cache=tmrescore_project_cache,
            tmrescore_analysis_tasks=tmrescore_analysis_tasks,
            logger=logger,
            media_type_json=MEDIA_TYPE_JSON,
            tmrescore_not_configured_detail=TMRESCORE_NOT_CONFIGURED_DETAIL,
            dependency_track_unavailable_detail="Dependency-Track unavailable while preparing threat-model analysis context.",
            tmrescore_disabled_detail="TMRescore integration is not configured. Set DTVP_TMRESCORE_URL to enable threat-model analysis.",
        ),
        bad_request_response=BAD_REQUEST_RESPONSE,
        not_found_response=NOT_FOUND_RESPONSE,
        service_unavailable_response=SERVICE_UNAVAILABLE_RESPONSE,
        current_user_dependency=get_current_user,
        client_dependency=get_client,
    )
)
api_router.include_router(
    create_settings_router(
        build_settings_route_deps(
            get_user_role=lambda user: get_user_role(user),
            load_team_mapping=lambda: load_team_mapping(),
            load_auto_analysis_guidance=lambda: load_auto_analysis_guidance(),
            load_user_roles=lambda: load_user_roles(),
            load_rescore_rules=lambda: load_rescore_rules(),
            get_team_mapping_path=lambda: get_team_mapping_path(),
            get_auto_analysis_guidance_path=lambda: get_auto_analysis_guidance_path(),
            get_user_roles_path=lambda: get_user_roles_path(),
            get_rescore_rules_path=lambda: get_rescore_rules_path(),
            write_bytes=write_bytes_impl,
            write_json=write_json_impl,
            write_and_validate_json_bytes=write_and_validate_json_bytes_impl,
        ),
        forbidden_response=FORBIDDEN_RESPONSE,
        current_user_dependency=get_current_user,
    )
)


# ── Analysis Queue ───────────────────────────────────────────────────────────
analysis_queue_runtime_deps = build_analysis_queue_runtime_deps(logger=logger)


analysis_queue_service_deps = build_analysis_queue_service_deps(
    code_analysis_not_configured_detail=CODE_ANALYSIS_NOT_CONFIGURED_DETAIL,
    code_analysis_settings_cls=lambda: CodeAnalysisSettings,
    code_analysis_client_cls=CodeAnalysisClient,
)


analysis_queue = build_analysis_queue(
    runtime_deps=analysis_queue_runtime_deps,
    service_deps=analysis_queue_service_deps,
    get_analysis_queue_ttl_seconds=lambda: get_env_int_with_floor(
        "DTVP_ANALYSIS_QUEUE_TTL_SECONDS",
        default=3600,
        minimum=60,
        logger=logger,
    ),
    get_analysis_queue_capacity=lambda: get_env_int_with_floor(
        "DTVP_ANALYSIS_QUEUE_CAPACITY",
        default=1,
        minimum=1,
        logger=logger,
    ),
    parse_iso_timestamp=parse_iso_timestamp_impl,
    utc_now=lambda: datetime.now(UTC),
    reindex_queue_items=reindex_queue_items,
    prune_finished_queue_items=prune_finished_queue_items,
    get_next_queued_item=get_next_queued_item_impl,
    start_analysis_queue_item=start_analysis_queue_item,
    process_analysis_queue_item=process_analysis_queue_item,
    run_analysis_queue_cleanup_loop=run_analysis_queue_cleanup_loop,
    run_analysis_queue_worker=run_analysis_queue_worker,
    record_completed_result=lambda item: code_analysis_result_store.record_queue_item_result(
        item,
        item.result or {},
    ),
)


_auto_analysis_sweep_executor: ThreadPoolExecutor | None = None
auto_analysis_sweep_task: asyncio.Task[Any] | None = None


def _get_auto_analysis_sweep_executor() -> ThreadPoolExecutor:
    global _auto_analysis_sweep_executor
    if _auto_analysis_sweep_executor is None:
        _auto_analysis_sweep_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="dtvp-auto-analysis",
        )
    return _auto_analysis_sweep_executor


def shutdown_auto_analysis_sweep_executor() -> None:
    global _auto_analysis_sweep_executor
    if _auto_analysis_sweep_executor is None:
        return
    _auto_analysis_sweep_executor.shutdown(wait=False, cancel_futures=True)
    _auto_analysis_sweep_executor = None


def _build_auto_analysis_sweep_worker_deps() -> AutoAnalysisSweepDeps:
    worker_cache_manager = CacheManager(
        base_path=cache_manager.base_path,
        refresh_interval_seconds=cache_manager.refresh_interval_seconds,
    )
    worker_cache_manager.load_persisted_runtime_state()
    worker_grouped_vuln_service_deps = build_grouped_vuln_service_deps(
        cache_manager=worker_cache_manager,
        logger=logger,
        tasks={},
        bom_analysis_cache_cls=BOMAnalysisCache,
        get_version_fetch_concurrency=lambda: get_version_fetch_concurrency_impl(
            logger
        ),
        merge_vulnerability_details=merge_vulnerability_details_impl,
        sort_projects_by_version=sort_projects_by_version,
        load_team_mapping=lambda: load_team_mapping(),
        group_vulnerabilities=group_vulnerabilities,
        queue_open_vulnerabilities_for_analysis=None,
    )
    return AutoAnalysisSweepDeps(
        cache_manager=worker_cache_manager,
        logger=logger,
        sort_projects_by_version=sort_projects_by_version,
        load_team_mapping=lambda: load_team_mapping(),
        load_auto_analysis_guidance=lambda: load_auto_analysis_guidance(),
        collect_version_snapshots=lambda versions, client, cve, team_mapping: (
            collect_grouped_vuln_version_snapshots(
                worker_grouped_vuln_service_deps,
                versions,
                client,
                cve,
                team_mapping,
            )
        ),
        bom_analysis_cache_cls=BOMAnalysisCache,
        merge_vulnerability_details=merge_vulnerability_details_impl,
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=lambda *_args: 0,
        tmrescore_project_cache=tmrescore_project_cache,
        result_store=code_analysis_result_store,
    )


def _run_auto_analysis_sweep_worker():
    async def _run():
        settings = DTSettings()
        async with DTClient(
            settings.api_url,
            api_key=settings.api_key,
        ) as client:
            return await build_existing_open_vulnerability_sweep_plan(
                _build_auto_analysis_sweep_worker_deps(),
                client,
            )

    return asyncio.run(_run())


auto_analysis_sweep_state: dict[str, Any] = {
    "running": False,
    "last_started_at": None,
    "last_finished_at": None,
    "last_queued_count": None,
    "last_error": None,
    "last_trigger": None,
    "next_run_at": None,
}
auto_analysis_sweep_lock = asyncio.Lock()


def _get_auto_analysis_sweep_interval_seconds() -> int:
    return get_env_int_with_floor(
        "DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS",
        default=900,
        minimum=60,
        logger=logger,
    )


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _utc_after_iso(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def get_auto_analysis_sweep_status() -> dict[str, Any]:
    enabled = get_auto_code_analysis_enabled()
    code_analysis_configured = CodeAnalysisSettings().enabled
    return {
        "enabled": enabled,
        "code_analysis_configured": code_analysis_configured,
        "active": enabled and code_analysis_configured,
        "interval_seconds": _get_auto_analysis_sweep_interval_seconds(),
        **auto_analysis_sweep_state,
    }


async def run_auto_analysis_sweep_once(trigger: str) -> dict[str, Any]:
    if auto_analysis_sweep_lock.locked():
        return get_auto_analysis_sweep_status()

    async with auto_analysis_sweep_lock:
        if not _is_auto_code_analysis_active():
            return get_auto_analysis_sweep_status()

        auto_analysis_sweep_state.update(
            {
                "running": True,
                "last_started_at": _utc_now_iso(),
                "last_finished_at": None,
                "last_error": None,
                "last_trigger": trigger,
            }
        )

        try:
            loop = asyncio.get_running_loop()
            plan = await loop.run_in_executor(
                _get_auto_analysis_sweep_executor(),
                _run_auto_analysis_sweep_worker,
            )
            queued_count = apply_auto_analysis_sweep_plan(
                analysis_queue=analysis_queue,
                plan=plan,
                logger=logger,
            )
            auto_analysis_sweep_state["last_queued_count"] = queued_count
            if queued_count:
                logger.info(
                    "Automatic code analysis sweep queued %d scan(s)",
                    queued_count,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            auto_analysis_sweep_state["last_error"] = str(exc)
            logger.warning("Automatic code analysis sweep failed: %s", exc)
        finally:
            auto_analysis_sweep_state.update(
                {
                    "running": False,
                    "last_finished_at": _utc_now_iso(),
                }
            )

        return get_auto_analysis_sweep_status()


def _track_auto_analysis_sweep_task(task: asyncio.Task[Any]) -> None:
    global auto_analysis_sweep_task
    auto_analysis_sweep_task = task
    background_tasks.add(task)

    def _clear(completed_task: asyncio.Task[Any]) -> None:
        global auto_analysis_sweep_task
        background_tasks.discard(completed_task)
        if auto_analysis_sweep_task is completed_task:
            auto_analysis_sweep_task = None

    task.add_done_callback(_clear)


async def run_auto_analysis_sweep_now() -> dict[str, Any]:
    if auto_analysis_sweep_task and not auto_analysis_sweep_task.done():
        return get_auto_analysis_sweep_status()

    task = asyncio.create_task(run_auto_analysis_sweep_once("manual"))
    _track_auto_analysis_sweep_task(task)
    await asyncio.sleep(0)
    return get_auto_analysis_sweep_status()


async def run_auto_analysis_sweep_loop() -> None:
    try:
        while True:
            interval_seconds = _get_auto_analysis_sweep_interval_seconds()
            auto_analysis_sweep_state["next_run_at"] = _utc_after_iso(interval_seconds)
            await asyncio.sleep(interval_seconds)

            await run_auto_analysis_sweep_once("scheduled")
    finally:
        shutdown_auto_analysis_sweep_executor()


async def run_project_archive_snapshot_loop() -> None:
    while True:
        interval_seconds = get_project_archive_interval_seconds()
        if project_archive_snapshots_enabled():
            try:
                settings = DTSettings()
                async with DTClient(settings.api_url, api_key=settings.api_key) as client:
                    results = await run_project_archive_snapshot_once(
                        project_archive_service_deps,
                        client,
                    )
                success_count = sum(
                    1 for result in results if result.get("status") == "success"
                )
                if success_count:
                    logger.info(
                        "Project archive snapshot created %d archive(s)",
                        success_count,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Project archive snapshot loop failed: %s", exc)
        await asyncio.sleep(interval_seconds)


startup_service_deps = build_startup_service_deps(
    logger=logger,
    version=VERSION,
    build_commit=BUILD_COMMIT,
    analysis_queue=analysis_queue,
    tmrescore_project_cache=tmrescore_project_cache,
    load_tmrescore_project_cache=lambda: load_tmrescore_project_cache_impl(
        tmrescore_cache_service_deps
    ),
    initialize_cache_manager=lambda: cache_manager.initialize(),
    run_background_sync_loop=lambda: cache_manager.background_sync_loop(),
    run_auto_analysis_sweep_loop=run_auto_analysis_sweep_loop,
)


api_router.include_router(
    create_code_analysis_router(
        build_code_analysis_route_deps(
            code_analysis_settings_cls=CodeAnalysisSettings,
            code_analysis_client_cls=CodeAnalysisClient,
            analysis_queue=analysis_queue,
            result_store=code_analysis_result_store,
            get_user_role=lambda user: get_user_role(user),
            load_auto_analysis_guidance=lambda: load_auto_analysis_guidance(),
            get_auto_analysis_sweep_status=get_auto_analysis_sweep_status,
            run_auto_analysis_sweep_now=run_auto_analysis_sweep_now,
            code_analysis_not_configured_detail=CODE_ANALYSIS_NOT_CONFIGURED_DETAIL,
            code_analysis_disabled_detail="Code analysis integration is not configured. Set DTVP_CODE_ANALYSIS_URL to enable code analysis.",
            not_found_response=NOT_FOUND_RESPONSE,
            service_unavailable_response=SERVICE_UNAVAILABLE_RESPONSE,
        ),
        current_user_dependency=get_current_user,
    )
)


app.include_router(api_router, prefix=context_path)

register_frontend_routes(
    app,
    build_frontend_route_deps(
        frontend_dist_dir="frontend/dist",
        get_context_path=lambda: context_path,
        get_frontend_url=lambda: auth_settings.FRONTEND_URL or "",
        get_dev_disable_auth=lambda: auth_settings.DEV_DISABLE_AUTH,
        get_default_project_filter=lambda: os.getenv("DTVP_DEFAULT_PROJECT_FILTER", ""),
        get_attribution_age_filter_days=lambda: os.getenv(
            "DTVP_ATTRIBUTION_AGE_FILTER_DAYS",
            "7d,14d,28d",
        ),
        get_jira_create_url=lambda: os.getenv("DTVP_JIRA_CREATE_URL", ""),
        read_text=read_text_impl,
    ),
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("dtvp.boot:app", host="127.0.0.1", port=8000, reload=True)
