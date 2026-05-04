import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .dt_client import DTClient
from .tmrescore_errors import InventoryPreparationError


@dataclass(frozen=True)
class TMRescoreInventoryServiceDeps:
    cache_manager: Any
    logger: Any
    supported_tmrescore_scopes: set[str] | list[str] | tuple[str, ...]
    get_version_fetch_concurrency: Callable[[], int]
    merge_vulnerability_details: Callable[
        [List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, int]
    ]
    sort_projects_by_version: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
    build_analysis_sbom: Callable[[str, List[Dict[str, Any]], str, str], Dict[str, Any]]
    build_dtvp_vulnerability_proposals: Callable[
        [List[Dict[str, Any]]], Dict[str, Dict[str, Any]]
    ]
    inventory_error_cls: type[InventoryPreparationError]


async def fetch_version_analysis_input(
    deps: TMRescoreInventoryServiceDeps,
    client: DTClient,
    version_info: Dict[str, Any],
) -> Dict[str, Any]:
    findings_result, full_vulns_result, bom_result = await asyncio.gather(
        deps.cache_manager.get_vulnerabilities(client, version_info["uuid"]),
        deps.cache_manager.get_project_vulnerabilities(client, version_info["uuid"]),
        deps.cache_manager.get_bom(client, version_info["uuid"]),
        return_exceptions=True,
    )

    if isinstance(findings_result, Exception):
        raise findings_result
    if isinstance(full_vulns_result, Exception):
        raise full_vulns_result

    findings = findings_result
    full_vulns = full_vulns_result
    deps.merge_vulnerability_details(findings, full_vulns)

    if isinstance(bom_result, Exception):
        bom_result = {}

    return {
        "version": version_info,
        "vulnerabilities": findings,
        "bom": bom_result or {},
    }


async def collect_tmrescore_analysis_inputs(
    deps: TMRescoreInventoryServiceDeps,
    versions: List[Dict[str, Any]],
    client: DTClient,
) -> List[Dict[str, Any]]:
    if not versions:
        return []

    concurrency = min(deps.get_version_fetch_concurrency(), len(versions))
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Optional[Dict[str, Any]]] = [None] * len(versions)

    async def worker(index: int, version_info: Dict[str, Any]):
        async with semaphore:
            return index, await fetch_version_analysis_input(deps, client, version_info)

    pending = [
        asyncio.create_task(worker(index, version_info))
        for index, version_info in enumerate(versions)
    ]

    try:
        for pending_task in asyncio.as_completed(pending):
            index, result = await pending_task
            results[index] = result
    finally:
        for pending_task in pending:
            if not pending_task.done():
                pending_task.cancel()

    return [item for item in results if item is not None]


async def prepare_tmrescore_analysis_inventory(
    deps: TMRescoreInventoryServiceDeps,
    project_name: str,
    scope: str,
    client: DTClient,
) -> Dict[str, Any]:
    if scope not in deps.supported_tmrescore_scopes:
        raise deps.inventory_error_cls(
            status_code=400,
            detail="Unsupported tmrescore analysis scope",
        )

    try:
        projects = await deps.cache_manager.get_projects(client, project_name)
    except Exception as exc:
        deps.logger.error("Error fetching projects for tmrescore analysis: %s", exc)
        raise deps.inventory_error_cls(
            status_code=503,
            detail="Dependency-Track unavailable while preparing threat-model analysis.",
        )

    versions = [project for project in projects if project.get("name") == project_name]
    versions = deps.sort_projects_by_version(versions)

    if not versions:
        raise deps.inventory_error_cls(status_code=404, detail="Project not found")

    selected_versions = versions[-1:] if scope == "latest_only" else versions
    latest_version = versions[-1].get("version", "unknown")

    analysis_inputs = await collect_tmrescore_analysis_inputs(
        deps, selected_versions, client
    )
    synthetic_sbom = deps.build_analysis_sbom(
        project_name,
        analysis_inputs,
        scope,
        latest_version,
    )

    analyzed_versions = [
        version.get("version", "unknown") for version in selected_versions
    ]
    strategy_note = (
        "Merged multi-version analysis keeps historical vulnerabilities attached to the versioned components they came from."
        if scope == "merged_versions"
        else "Latest-only analysis is limited to the newest version and does not account for vulnerabilities seen only in older releases."
    )

    return {
        "versions": versions,
        "selected_versions": selected_versions,
        "latest_version": latest_version,
        "dtvp_original_proposals": deps.build_dtvp_vulnerability_proposals(
            analysis_inputs
        ),
        "synthetic_sbom": synthetic_sbom,
        "analyzed_versions": analyzed_versions,
        "strategy_note": strategy_note,
    }
