from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from dtvp.app_wiring import (
    build_analysis_queue_service_deps,
    build_general_api_route_deps,
    build_prepare_tmrescore_inventory_or_raise,
    build_tmrescore_execution_service_deps,
)
from dtvp.assessment_services import AssessmentServiceDeps
from dtvp.code_analysis_integration import CodeAnalysisClient, CodeAnalysisSettings
from dtvp.dt_client import DTClient, DTSettings
from dtvp.grouped_vuln_services import GroupedVulnServiceDeps
from dtvp.logic import BOMAnalysisCache
from dtvp.tmrescore_errors import InventoryPreparationError
from dtvp.tmrescore_integration import TMRescoreClient
from dtvp.tmrescore_inventory_services import TMRescoreInventoryServiceDeps


def test_build_analysis_queue_service_deps_normalizes_direct_client_class():
    deps = build_analysis_queue_service_deps(
        code_analysis_not_configured_detail="not configured",
        code_analysis_settings_cls=lambda: CodeAnalysisSettings,
        code_analysis_client_cls=CodeAnalysisClient,
    )

    assert deps.get_code_analysis_settings_cls() is CodeAnalysisSettings
    assert deps.get_code_analysis_client_cls() is CodeAnalysisClient


def test_build_general_api_route_deps_preserves_provider_contracts():
    grouped_vuln_service_deps = GroupedVulnServiceDeps(
        cache_manager=object(),
        logger=object(),
        tasks={},
        bom_analysis_cache_cls=BOMAnalysisCache,
        get_version_fetch_concurrency=lambda: 1,
        merge_vulnerability_details=lambda _findings, _full_vulns: {},
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {},
        group_vulnerabilities=lambda *args, **kwargs: [],
    )
    assessment_service_deps = AssessmentServiceDeps(
        cache_manager=object(),
        logger=object(),
        calculate_aggregated_state=lambda state: state,
        process_assessment_details=lambda *args, **kwargs: ("", ""),
    )
    deps = build_general_api_route_deps(
        cache_manager=object(),
        logger=object(),
        tasks={},
        background_tasks=set(),
        grouped_vuln_service_deps=grouped_vuln_service_deps,
        assessment_service_deps=assessment_service_deps,
        dt_settings_cls=DTSettings,
        get_dt_client_cls=lambda: DTClient,
        get_user_role=lambda _user: "ANALYST",
        load_rescore_rules=lambda: {"metric_rules": {}, "transitions": []},
        get_bom_analysis_cache_cls=lambda: BOMAnalysisCache,
        default_dependency_chain_limit=100,
        service_unavailable_response={},
        not_found_response={},
    )

    assert isinstance(deps.dt_settings_cls(), DTSettings)
    assert deps.get_dt_client_cls() is DTClient
    assert deps.get_bom_analysis_cache_cls() is BOMAnalysisCache


def test_build_tmrescore_execution_service_deps_preserves_client_provider():
    deps = build_tmrescore_execution_service_deps(
        logger=object(),
        get_tmrescore_client_cls=lambda: TMRescoreClient,
        describe_tmrescore_progress=lambda _status, _progress: "",
        touch_tmrescore_analysis_task=lambda *args, **kwargs: None,
        append_tmrescore_analysis_log=lambda *args, **kwargs: None,
        cache_tmrescore_project_results=lambda *args, **kwargs: None,
        build_tmrescore_analysis_response=lambda _result, _task: {},
    )

    assert deps.get_tmrescore_client_cls() is TMRescoreClient


@pytest.mark.asyncio
async def test_build_prepare_tmrescore_inventory_or_raise_translates_inventory_error():
    inventory_service_deps = TMRescoreInventoryServiceDeps(
        cache_manager=object(),
        logger=object(),
        supported_tmrescore_scopes={"latest_only"},
        get_version_fetch_concurrency=lambda: 1,
        merge_vulnerability_details=lambda _findings, _full_vulns: {},
        sort_projects_by_version=lambda versions: versions,
        build_analysis_sbom=lambda *args, **kwargs: {},
        build_dtvp_vulnerability_proposals=lambda _items: {},
        inventory_error_cls=InventoryPreparationError,
    )
    prepare = build_prepare_tmrescore_inventory_or_raise(
        tmrescore_inventory_service_deps=inventory_service_deps,
        inventory_error_cls=InventoryPreparationError,
    )

    with patch(
        "dtvp.app_wiring.prepare_tmrescore_analysis_inventory_impl",
        new=AsyncMock(side_effect=InventoryPreparationError(404, "Project not found")),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await prepare("demo", "latest_only", object())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Project not found"
