import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .dt_client import DTClient


@dataclass(frozen=True)
class GroupedVulnServiceDeps:
    cache_manager: Any
    logger: Any
    tasks: dict[str, Any]
    bom_analysis_cache_cls: type
    get_version_fetch_concurrency: Callable[[], int]
    merge_vulnerability_details: Callable[
        [List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, int]
    ]
    sort_projects_by_version: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
    load_team_mapping: Callable[[], Dict[str, Any]]
    group_vulnerabilities: Callable[..., List[Dict[str, Any]]]
    queue_open_vulnerabilities_for_analysis: Optional[
        Callable[[List[Dict[str, Any]], Dict[str, Any]], int]
    ] = None


async def fetch_version_snapshot(
    deps: GroupedVulnServiceDeps,
    client: DTClient,
    version_info: Dict[str, Any],
    cve: Optional[str],
    team_mapping: Dict[str, Any],
) -> tuple[Dict[str, Any], Any, Dict[str, int]]:
    findings_result, full_vulns_result, bom_result = await asyncio.gather(
        deps.cache_manager.get_vulnerabilities(client, version_info["uuid"], cve=cve),
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
    severity_counts = deps.merge_vulnerability_details(findings, full_vulns)

    if isinstance(bom_result, Exception):
        bom_cache = deps.bom_analysis_cache_cls({}, team_mapping)
    else:
        bom_cache = deps.bom_analysis_cache_cls(bom_result or {}, team_mapping)

    return (
        {"version": version_info, "vulnerabilities": findings},
        bom_cache,
        severity_counts,
    )


async def collect_version_snapshots(
    deps: GroupedVulnServiceDeps,
    versions: List[Dict[str, Any]],
    client: DTClient,
    cve: Optional[str],
    team_mapping: Dict[str, Any],
    progress_callback: Callable[[int, int, Dict[str, Any]], None] | None = None,
) -> tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Dict[str, int]]]:
    concurrency = (
        min(deps.get_version_fetch_concurrency(), len(versions)) if versions else 1
    )
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Optional[tuple[Dict[str, Any], Any, Dict[str, int]]]] = [None] * len(
        versions
    )

    async def worker(index: int, version_info: Dict[str, Any]):
        async with semaphore:
            combined_entry, bom_cache, severity_counts = await fetch_version_snapshot(
                deps,
                client,
                version_info,
                cve,
                team_mapping,
            )
            return index, version_info, combined_entry, bom_cache, severity_counts

    pending = [
        asyncio.create_task(worker(index, version_info))
        for index, version_info in enumerate(versions)
    ]

    completed = 0
    try:
        for pending_task in asyncio.as_completed(pending):
            (
                index,
                version_info,
                combined_entry,
                bom_cache,
                severity_counts,
            ) = await pending_task
            results[index] = (combined_entry, bom_cache, severity_counts)
            completed += 1
            if progress_callback:
                progress_callback(completed, len(versions), version_info)
    finally:
        for pending_task in pending:
            if not pending_task.done():
                pending_task.cancel()

    combined_data: List[Dict[str, Any]] = []
    bom_cache_map: Dict[str, Any] = {}
    version_severity_counts: Dict[str, Dict[str, int]] = {}
    for result in results:
        if result is None:
            continue
        combined_entry, bom_cache, severity_counts = result
        version_info = combined_entry["version"]
        combined_data.append(combined_entry)
        bom_cache_map[version_info["uuid"]] = bom_cache
        version_severity_counts[version_info.get("version")] = severity_counts

    return combined_data, bom_cache_map, version_severity_counts


async def process_grouped_vulns_task(
    deps: GroupedVulnServiceDeps,
    task_id: str,
    name: str,
    cve: Optional[str],
    client: DTClient,
) -> None:
    try:
        deps.tasks[task_id]["status"] = "running"
        deps.tasks[task_id]["message"] = "Fetching projects..."
        deps.tasks[task_id].setdefault("log", []).append("Fetching projects...")
        deps.logger.info("Task %s started for grouped vulnerabilities", task_id)

        projects = await deps.cache_manager.get_projects(client, name)
        if name:
            versions = [project for project in projects if project.get("name") == name]
        else:
            versions = projects

        versions = deps.sort_projects_by_version(versions)

        if not versions:
            deps.tasks[task_id]["status"] = "completed"
            deps.tasks[task_id]["progress"] = 100
            deps.tasks[task_id]["result"] = []
            return

        found_msg = f"Found {len(versions)} versions. Fetching vulnerabilities..."
        deps.tasks[task_id]["message"] = found_msg
        deps.tasks[task_id].setdefault("log", []).append(found_msg)

        team_mapping = deps.load_team_mapping()

        def update_progress(
            completed: int, total: int, version_info: Dict[str, Any]
        ) -> None:
            deps.tasks[task_id]["progress"] = int((completed / total) * 90)
            msg = f"Processed version {version_info.get('version')} ({completed}/{total})..."
            deps.tasks[task_id]["message"] = msg
            deps.tasks[task_id].setdefault("log", []).append(msg)

        combined_data, bom_cache_map, _ = await collect_version_snapshots(
            deps,
            versions,
            client,
            cve,
            team_mapping,
            progress_callback=update_progress,
        )

        deps.tasks[task_id]["message"] = "Grouping vulnerabilities..."
        deps.tasks[task_id].setdefault("log", []).append("Grouping vulnerabilities...")

        result = deps.group_vulnerabilities(
            combined_data,
            project_boms={},
            processed_boms=bom_cache_map,
        )

        if deps.queue_open_vulnerabilities_for_analysis:
            try:
                queued_count = deps.queue_open_vulnerabilities_for_analysis(
                    result,
                    team_mapping,
                )
                deps.tasks[task_id]["auto_code_analysis_queued"] = queued_count
                if queued_count:
                    msg = (
                        f"Queued {queued_count} automatic code analysis "
                        f"scan{'s' if queued_count != 1 else ''}."
                    )
                    deps.tasks[task_id].setdefault("log", []).append(msg)
            except Exception:
                deps.logger.exception(
                    "Task %s failed to queue automatic code analysis scans",
                    task_id,
                )

        deps.tasks[task_id]["status"] = "completed"
        deps.tasks[task_id]["progress"] = 100
        deps.tasks[task_id]["result"] = result
    except Exception as exc:
        deps.tasks[task_id]["status"] = "failed"
        deps.tasks[task_id]["message"] = str(exc)
        deps.logger.exception("Task %s failed", task_id)
