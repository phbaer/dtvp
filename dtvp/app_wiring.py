import asyncio
from typing import Any, Awaitable, Callable

from fastapi import HTTPException

from .analysis_queue_runtime import AnalysisQueue, AnalysisQueueDeps
from .analysis_queue_services import AnalysisQueueRuntimeDeps, AnalysisQueueServiceDeps
from .app_info_routes import AppInfoRouteDeps
from .assessment_services import (
    AssessmentServiceDeps,
    apply_assessment_payloads,
    build_assessment_payloads,
    collect_assessment_conflicts,
    fetch_current_assessment_analyses,
    finalize_assessment_results,
)
from .code_analysis_routes import CodeAnalysisRouteDeps
from .dt_client import DTClient
from .frontend_routes import FrontendRouteDeps
from .general_api_routes import GeneralApiRouteDeps
from .grouped_vuln_services import GroupedVulnServiceDeps
from .grouped_vuln_services import (
    collect_version_snapshots as collect_grouped_vuln_version_snapshots,
)
from .grouped_vuln_services import (
    process_grouped_vulns_task as process_grouped_vulns_task_impl,
)
from .grouped_vuln_task_services import (
    prune_grouped_vuln_tasks as prune_grouped_vuln_tasks_impl,
)
from .logic import calculate_statistics, group_vulnerabilities, load_team_mapping
from .project_archive_routes import ProjectArchiveRouteDeps
from .project_archive_services import ProjectArchiveServiceDeps
from .settings_routes import SettingsRouteDeps
from .startup_services import StartupServiceDeps
from .startup_services import build_startup_runtime_details
from .startup_services import create_tracked_task as create_tracked_task_impl
from .tmrescore_cache_services import TMRescoreCacheServiceDeps
from .tmrescore_cache_services import (
    persist_tmrescore_project_snapshot as persist_tmrescore_project_snapshot_impl,
)
from .tmrescore_errors import InventoryPreparationError
from .tmrescore_execution_services import (
    TMRescoreExecutionRequest,
    TMRescoreExecutionServiceDeps,
)
from .tmrescore_execution_services import (
    run_tmrescore_analysis_task as run_tmrescore_analysis_task_impl,
)
from .tmrescore_integration import sort_projects_by_version
from .tmrescore_inventory_services import TMRescoreInventoryServiceDeps
from .tmrescore_inventory_services import (
    prepare_tmrescore_analysis_inventory as prepare_tmrescore_analysis_inventory_impl,
)
from .tmrescore_routes import TMRescoreRouteDeps
from .tmrescore_task_services import TMRescoreTaskServiceDeps
from .tmrescore_task_services import (
    build_tmrescore_cached_state as build_tmrescore_cached_state_impl,
)
from .tmrescore_task_services import (
    describe_tmrescore_progress as describe_tmrescore_progress_impl,
)
from .tmrescore_task_services import (
    get_latest_tmrescore_project_task as get_latest_tmrescore_project_task_impl,
)
from .tmrescore_task_services import (
    prune_tmrescore_analysis_tasks as prune_tmrescore_analysis_tasks_impl,
)


def build_grouped_vuln_service_deps(
    *,
    cache_manager: Any,
    logger: Any,
    tasks: dict[str, Any],
    bom_analysis_cache_cls: type,
    get_version_fetch_concurrency: Callable[[], int],
    merge_vulnerability_details: Callable[..., Any],
    sort_projects_by_version: Callable[..., Any],
    load_team_mapping: Callable[[], dict[str, Any]],
    group_vulnerabilities: Callable[..., Any],
    queue_open_vulnerabilities_for_analysis: (
        Callable[[list[dict[str, Any]], dict[str, Any]], int] | None
    ) = None,
    summary_index: Any = None,
    summary_index_cache_revision: Callable[[], Any] | None = None,
) -> GroupedVulnServiceDeps:
    return GroupedVulnServiceDeps(
        cache_manager=cache_manager,
        logger=logger,
        tasks=tasks,
        bom_analysis_cache_cls=bom_analysis_cache_cls,
        get_version_fetch_concurrency=get_version_fetch_concurrency,
        merge_vulnerability_details=merge_vulnerability_details,
        sort_projects_by_version=sort_projects_by_version,
        load_team_mapping=lambda: load_team_mapping(),
        group_vulnerabilities=group_vulnerabilities,
        queue_open_vulnerabilities_for_analysis=(
            queue_open_vulnerabilities_for_analysis
        ),
        summary_index=summary_index,
        summary_index_cache_revision=summary_index_cache_revision or (lambda: None),
    )


def build_tmrescore_cache_service_deps(
    *,
    logger: Any,
    normalize_tmrescore_snapshot: Callable[[dict[str, Any]], dict[str, Any]],
    shared_cache: dict[str, dict[str, Any]],
) -> TMRescoreCacheServiceDeps:
    return TMRescoreCacheServiceDeps(
        logger=logger,
        normalize_tmrescore_snapshot=normalize_tmrescore_snapshot,
        shared_cache=shared_cache,
    )


def build_tmrescore_task_service_deps(
    *,
    tmrescore_analysis_tasks: dict[str, dict[str, Any]],
    get_tmrescore_task_ttl_seconds: Callable[[], int],
    context_path: str,
) -> TMRescoreTaskServiceDeps:
    return TMRescoreTaskServiceDeps(
        tmrescore_analysis_tasks=tmrescore_analysis_tasks,
        get_tmrescore_task_ttl_seconds=get_tmrescore_task_ttl_seconds,
        context_path=context_path,
    )


def build_tmrescore_execution_service_deps(
    *,
    logger: Any,
    get_tmrescore_client_cls: Callable[[], type],
    describe_tmrescore_progress: Callable[[str, int], str],
    touch_tmrescore_analysis_task: Callable[..., None],
    append_tmrescore_analysis_log: Callable[[dict[str, Any], str], None],
    cache_tmrescore_project_results: Callable[..., None],
    build_tmrescore_analysis_response: Callable[
        [dict[str, Any], dict[str, Any]], dict[str, Any]
    ],
) -> TMRescoreExecutionServiceDeps:
    return TMRescoreExecutionServiceDeps(
        logger=logger,
        get_tmrescore_client_cls=get_tmrescore_client_cls,
        describe_tmrescore_progress=describe_tmrescore_progress,
        touch_tmrescore_analysis_task=touch_tmrescore_analysis_task,
        append_tmrescore_analysis_log=append_tmrescore_analysis_log,
        cache_tmrescore_project_results=cache_tmrescore_project_results,
        build_tmrescore_analysis_response=build_tmrescore_analysis_response,
        sleep=asyncio.sleep,
        loop_time=lambda: asyncio.get_running_loop().time(),
    )


def build_tmrescore_inventory_service_deps(
    *,
    cache_manager: Any,
    logger: Any,
    supported_tmrescore_scopes: set[str] | list[str] | tuple[str, ...],
    get_version_fetch_concurrency: Callable[[], int],
    merge_vulnerability_details: Callable[..., Any],
    sort_projects_by_version: Callable[..., Any],
    build_analysis_sbom: Callable[..., Any],
    build_dtvp_vulnerability_proposals: Callable[..., Any],
    inventory_error_cls: type[InventoryPreparationError],
) -> TMRescoreInventoryServiceDeps:
    return TMRescoreInventoryServiceDeps(
        cache_manager=cache_manager,
        logger=logger,
        supported_tmrescore_scopes=supported_tmrescore_scopes,
        get_version_fetch_concurrency=get_version_fetch_concurrency,
        merge_vulnerability_details=merge_vulnerability_details,
        sort_projects_by_version=sort_projects_by_version,
        build_analysis_sbom=build_analysis_sbom,
        build_dtvp_vulnerability_proposals=build_dtvp_vulnerability_proposals,
        inventory_error_cls=inventory_error_cls,
    )


def build_prepare_tmrescore_inventory_or_raise(
    *,
    tmrescore_inventory_service_deps: TMRescoreInventoryServiceDeps,
    inventory_error_cls: type[InventoryPreparationError],
) -> Callable[[str, str, DTClient], Awaitable[dict[str, Any]]]:
    async def prepare_tmrescore_inventory_or_raise(
        project_name: str,
        scope: str,
        client: DTClient,
    ) -> dict[str, Any]:
        try:
            return await prepare_tmrescore_analysis_inventory_impl(
                tmrescore_inventory_service_deps,
                project_name,
                scope,
                client,
            )
        except inventory_error_cls as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return prepare_tmrescore_inventory_or_raise


def build_assessment_service_deps(
    *,
    cache_manager: Any,
    logger: Any,
    calculate_aggregated_state: Callable[[str], str],
    process_assessment_details: Callable[..., tuple[str, str]],
) -> AssessmentServiceDeps:
    return AssessmentServiceDeps(
        cache_manager=cache_manager,
        logger=logger,
        calculate_aggregated_state=calculate_aggregated_state,
        process_assessment_details=process_assessment_details,
    )


def build_general_api_route_deps(
    *,
    cache_manager: Any,
    logger: Any,
    tasks: dict[str, Any],
    background_tasks: set[asyncio.Task[Any]],
    grouped_vuln_service_deps: GroupedVulnServiceDeps,
    assessment_service_deps: AssessmentServiceDeps,
    dt_settings_cls: Callable[[], Any],
    get_dt_client_cls: Callable[[], type],
    get_user_role: Callable[[str], str],
    get_bom_analysis_cache_cls: Callable[[], type],
    default_dependency_chain_limit: int,
    service_unavailable_response: dict[int | str, dict[str, Any]],
    not_found_response: dict[int | str, dict[str, Any]],
    get_grouped_vuln_task_ttl_seconds: Callable[[], int] | None = None,
) -> GeneralApiRouteDeps:
    return GeneralApiRouteDeps(
        cache_manager=cache_manager,
        logger=logger,
        tasks=tasks,
        dt_settings_cls=dt_settings_cls,
        get_dt_client_cls=get_dt_client_cls,
        create_tracked_task=lambda coro: create_tracked_task_impl(
            background_tasks,
            asyncio.create_task,
            coro,
        ),
        process_grouped_vulns_task=lambda task_id, name, cve, client, response_mode="full": (
            process_grouped_vulns_task_impl(
                grouped_vuln_service_deps,
                task_id,
                name,
                cve,
                client,
                response_mode,
            )
        ),
        sort_projects_by_version=sort_projects_by_version,
        load_team_mapping=lambda: load_team_mapping(),
        collect_version_snapshots=lambda versions, client, cve, team_mapping, progress_callback=None: (
            collect_grouped_vuln_version_snapshots(
                grouped_vuln_service_deps,
                versions,
                client,
                cve,
                team_mapping,
                progress_callback=progress_callback,
            )
        ),
        group_vulnerabilities=group_vulnerabilities,
        calculate_statistics=calculate_statistics,
        prune_grouped_vuln_tasks=lambda: prune_grouped_vuln_tasks_impl(
            tasks,
            ttl_seconds=(
                get_grouped_vuln_task_ttl_seconds()
                if get_grouped_vuln_task_ttl_seconds
                else 3600
            ),
        ),
        get_user_role=get_user_role,
        fetch_current_assessment_analyses=lambda req, client: (
            fetch_current_assessment_analyses(assessment_service_deps, req, client)
        ),
        collect_assessment_conflicts=lambda req, analyses: collect_assessment_conflicts(
            assessment_service_deps, req, analyses
        ),
        build_assessment_payloads=lambda req, user, role: build_assessment_payloads(
            assessment_service_deps,
            req,
            user,
            role,
        ),
        apply_assessment_payloads=lambda client, payloads: apply_assessment_payloads(
            assessment_service_deps, client, payloads
        ),
        finalize_assessment_results=lambda api_results: finalize_assessment_results(
            assessment_service_deps,
            api_results,
        ),
        get_bom_analysis_cache_cls=get_bom_analysis_cache_cls,
        default_dependency_chain_limit=default_dependency_chain_limit,
        service_unavailable_response=service_unavailable_response,
        not_found_response=not_found_response,
    )


def build_tmrescore_route_deps(
    *,
    prepare_tmrescore_inventory_or_raise: Callable[..., Any],
    tmrescore_task_service_deps: TMRescoreTaskServiceDeps,
    tmrescore_cache_service_deps: TMRescoreCacheServiceDeps,
    tmrescore_execution_service_deps: TMRescoreExecutionServiceDeps,
    background_tasks: set[asyncio.Task[Any]],
    tmrescore_project_cache: dict[str, dict[str, Any]],
    tmrescore_analysis_tasks: dict[str, dict[str, Any]],
    logger: Any,
    media_type_json: str,
    tmrescore_not_configured_detail: str,
    dependency_track_unavailable_detail: str,
    tmrescore_disabled_detail: str,
) -> TMRescoreRouteDeps:
    return TMRescoreRouteDeps(
        prepare_tmrescore_inventory_or_raise=prepare_tmrescore_inventory_or_raise,
        prune_tmrescore_analysis_tasks=lambda: prune_tmrescore_analysis_tasks_impl(
            tmrescore_task_service_deps
        ),
        create_tracked_task=lambda coro: create_tracked_task_impl(
            background_tasks,
            asyncio.create_task,
            coro,
        ),
        run_tmrescore_analysis_task=lambda task, settings, project_name, threatmodel_bytes, synthetic_sbom, dtvp_original_proposals, items_csv_bytes, config_bytes, chain_analysis, prioritize, what_if, enrich, ollama_model: (
            run_tmrescore_analysis_task_impl(
                tmrescore_execution_service_deps,
                task,
                settings,
                TMRescoreExecutionRequest(
                    project_name=project_name,
                    threatmodel_bytes=threatmodel_bytes,
                    synthetic_sbom=synthetic_sbom,
                    dtvp_original_proposals=dtvp_original_proposals,
                    items_csv_bytes=items_csv_bytes,
                    config_bytes=config_bytes,
                    chain_analysis=chain_analysis,
                    prioritize=prioritize,
                    what_if=what_if,
                    enrich=enrich,
                    ollama_model=ollama_model,
                ),
            )
        ),
        build_tmrescore_cached_state=lambda task, include_result: (
            build_tmrescore_cached_state_impl(
                task,
                include_result=include_result,
            )
        ),
        get_latest_tmrescore_project_task=lambda project_name: (
            get_latest_tmrescore_project_task_impl(
                tmrescore_task_service_deps,
                project_name,
            )
        ),
        persist_tmrescore_project_snapshot=lambda project_name, snapshot: (
            persist_tmrescore_project_snapshot_impl(
                tmrescore_cache_service_deps,
                project_name,
                snapshot,
            )
        ),
        describe_tmrescore_progress=describe_tmrescore_progress_impl,
        tmrescore_project_cache=tmrescore_project_cache,
        tmrescore_analysis_tasks=tmrescore_analysis_tasks,
        logger=logger,
        media_type_json=media_type_json,
        tmrescore_not_configured_detail=tmrescore_not_configured_detail,
        dependency_track_unavailable_detail=dependency_track_unavailable_detail,
        tmrescore_disabled_detail=tmrescore_disabled_detail,
    )


def build_code_analysis_route_deps(
    *,
    code_analysis_settings_cls: Callable[[], Any],
    code_analysis_client_cls: type,
    analysis_queue: Any,
    get_auto_analysis_sweep_status: Callable[[], dict[str, Any]],
    run_auto_analysis_sweep_now: Callable[[], Any],
    code_analysis_not_configured_detail: str,
    code_analysis_disabled_detail: str,
    not_found_response: dict[int | str, dict[str, Any]],
    service_unavailable_response: dict[int | str, dict[str, Any]],
) -> CodeAnalysisRouteDeps:
    return CodeAnalysisRouteDeps(
        code_analysis_settings_cls=code_analysis_settings_cls,
        code_analysis_client_cls=code_analysis_client_cls,
        analysis_queue=analysis_queue,
        get_auto_analysis_sweep_status=get_auto_analysis_sweep_status,
        run_auto_analysis_sweep_now=run_auto_analysis_sweep_now,
        code_analysis_not_configured_detail=code_analysis_not_configured_detail,
        code_analysis_disabled_detail=code_analysis_disabled_detail,
        not_found_response=not_found_response,
        service_unavailable_response=service_unavailable_response,
    )


def build_frontend_route_deps(
    *,
    frontend_dist_dir: str,
    get_context_path: Callable[[], str],
    get_frontend_url: Callable[[], str],
    get_dev_disable_auth: Callable[[], bool],
    get_default_project_filter: Callable[[], str],
    get_attribution_age_filter_days: Callable[[], str],
    read_text: Callable[[str], str],
) -> FrontendRouteDeps:
    return FrontendRouteDeps(
        frontend_dist_dir=frontend_dist_dir,
        get_context_path=get_context_path,
        get_frontend_url=get_frontend_url,
        get_dev_disable_auth=get_dev_disable_auth,
        get_default_project_filter=get_default_project_filter,
        get_attribution_age_filter_days=get_attribution_age_filter_days,
        read_text=read_text,
    )


def build_app_info_route_deps(
    *,
    version: str,
    build_commit: str,
    cache_manager: Any,
    load_pyproject_metadata: Callable[[], dict[str, Any] | None],
    load_changelog_content: Callable[[], str],
    get_sbom_path: Callable[[str], str | None],
    read_text: Callable[[str], str],
    build_sbom_html: Callable[[str], str],
    backend_sbom_filename: str,
    frontend_sbom_filename: str,
    html_sbom_filename: str,
    media_type_json: str,
) -> AppInfoRouteDeps:
    return AppInfoRouteDeps(
        version=version,
        build_commit=build_commit,
        load_pyproject_metadata=load_pyproject_metadata,
        get_cache_status=lambda: cache_manager.get_cache_status(),
        load_changelog_content=load_changelog_content,
        get_sbom_path=get_sbom_path,
        read_text=read_text,
        build_sbom_html=build_sbom_html,
        backend_sbom_filename=backend_sbom_filename,
        frontend_sbom_filename=frontend_sbom_filename,
        html_sbom_filename=html_sbom_filename,
        media_type_json=media_type_json,
    )


def build_settings_route_deps(
    *,
    get_user_role: Callable[[str], str],
    load_team_mapping: Callable[[], dict[str, Any]],
    load_user_roles: Callable[[], dict[str, Any] | None],
    load_rescore_rules: Callable[[], dict[str, Any] | None],
    get_team_mapping_path: Callable[[], str],
    get_user_roles_path: Callable[[], str],
    get_rescore_rules_path: Callable[[], str],
    write_bytes: Callable[[str, bytes], None],
    write_json: Callable[[str, Any], None],
    write_and_validate_json_bytes: Callable[[str, bytes], None],
) -> SettingsRouteDeps:
    return SettingsRouteDeps(
        get_user_role=get_user_role,
        load_team_mapping=load_team_mapping,
        load_user_roles=load_user_roles,
        load_rescore_rules=load_rescore_rules,
        get_team_mapping_path=get_team_mapping_path,
        get_user_roles_path=get_user_roles_path,
        get_rescore_rules_path=get_rescore_rules_path,
        write_bytes=write_bytes,
        write_json=write_json,
        write_and_validate_json_bytes=write_and_validate_json_bytes,
    )


def build_project_archive_service_deps(
    *,
    cache_manager: Any,
    logger: Any,
    sort_projects_by_version: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
    version: str,
    build_commit: str,
    archive_path_provider: Callable[[], str],
) -> ProjectArchiveServiceDeps:
    return ProjectArchiveServiceDeps(
        cache_manager=cache_manager,
        logger=logger,
        sort_projects_by_version=sort_projects_by_version,
        version=version,
        build_commit=build_commit,
        archive_path_provider=archive_path_provider,
    )


def build_project_archive_route_deps(
    *,
    archive_tasks: dict[str, dict[str, Any]],
    service_deps: ProjectArchiveServiceDeps,
    logger: Any,
    background_tasks: set[asyncio.Task[Any]],
    get_user_role: Callable[[str], str],
    dt_settings_cls: Callable[[], Any],
    get_dt_client_cls: Callable[[], type],
    archive_path_provider: Callable[[], str],
) -> ProjectArchiveRouteDeps:
    return ProjectArchiveRouteDeps(
        archive_tasks=archive_tasks,
        service_deps=service_deps,
        logger=logger,
        get_user_role=get_user_role,
        dt_settings_cls=dt_settings_cls,
        get_dt_client_cls=get_dt_client_cls,
        create_tracked_task=lambda coro: create_tracked_task_impl(
            background_tasks,
            asyncio.create_task,
            coro,
        ),
        archive_path_provider=archive_path_provider,
    )


def build_analysis_queue_runtime_deps(*, logger: Any) -> AnalysisQueueRuntimeDeps:
    return AnalysisQueueRuntimeDeps(
        logger=logger,
        sleep=asyncio.sleep,
    )


def build_analysis_queue_service_deps(
    *,
    code_analysis_not_configured_detail: str,
    code_analysis_settings_cls: Callable[[], type[Any]],
    code_analysis_client_cls: Callable[[], type[Any]] | type[Any],
) -> AnalysisQueueServiceDeps:
    client_cls_provider = (
        code_analysis_client_cls
        if callable(code_analysis_client_cls)
        and not isinstance(code_analysis_client_cls, type)
        else (lambda: code_analysis_client_cls)
    )
    return AnalysisQueueServiceDeps(
        get_code_analysis_settings_cls=code_analysis_settings_cls,
        get_code_analysis_client_cls=client_cls_provider,
        code_analysis_not_configured_detail=code_analysis_not_configured_detail,
        sleep=asyncio.sleep,
    )


def build_analysis_queue(
    *,
    runtime_deps: AnalysisQueueRuntimeDeps,
    service_deps: AnalysisQueueServiceDeps,
    get_analysis_queue_ttl_seconds: Callable[[], int],
    parse_iso_timestamp: Callable[[str | None], float | None],
    utc_now: Callable[[], Any],
    reindex_queue_items: Callable[..., None],
    prune_finished_queue_items: Callable[..., int],
    get_next_queued_item: Callable[..., Any],
    start_analysis_queue_item: Callable[..., None],
    process_analysis_queue_item: Callable[..., Any],
    run_analysis_queue_cleanup_loop: Callable[..., Any],
    run_analysis_queue_worker: Callable[..., Any],
) -> AnalysisQueue:
    return AnalysisQueue(
        AnalysisQueueDeps(
            runtime_deps=runtime_deps,
            service_deps=service_deps,
            get_analysis_queue_ttl_seconds=get_analysis_queue_ttl_seconds,
            parse_iso_timestamp=parse_iso_timestamp,
            utc_now=utc_now,
            reindex_queue_items=reindex_queue_items,
            prune_finished_queue_items=prune_finished_queue_items,
            get_next_queued_item=get_next_queued_item,
            start_analysis_queue_item=start_analysis_queue_item,
            process_analysis_queue_item=process_analysis_queue_item,
            run_analysis_queue_cleanup_loop=run_analysis_queue_cleanup_loop,
            run_analysis_queue_worker=run_analysis_queue_worker,
            create_event=asyncio.Event,
            create_lock=asyncio.Lock,
        )
    )


def build_startup_service_deps(
    *,
    logger: Any,
    version: str,
    build_commit: str,
    analysis_queue: AnalysisQueue,
    tmrescore_project_cache: dict[str, dict[str, Any]],
    load_tmrescore_project_cache: Callable[[], dict[str, dict[str, Any]]],
    initialize_cache_manager: Callable[[], Any],
    run_background_sync_loop: Callable[[], Any],
    run_auto_analysis_sweep_loop: Callable[[], Any],
    runtime_details_provider: Callable[[], dict[str, dict[str, Any]]] = (
        build_startup_runtime_details
    ),
) -> StartupServiceDeps:
    return StartupServiceDeps(
        logger=logger,
        version=version,
        build_commit=build_commit,
        analysis_queue=analysis_queue,
        tmrescore_project_cache=tmrescore_project_cache,
        load_tmrescore_project_cache=load_tmrescore_project_cache,
        runtime_details_provider=runtime_details_provider,
        initialize_cache_manager=initialize_cache_manager,
        run_background_sync_loop=run_background_sync_loop,
        run_auto_analysis_sweep_loop=run_auto_analysis_sweep_loop,
        run_analysis_queue_worker=lambda: analysis_queue.worker(),
        run_analysis_queue_cleanup_loop=lambda: analysis_queue.cleanup_loop(),
        create_task=asyncio.create_task,
    )
