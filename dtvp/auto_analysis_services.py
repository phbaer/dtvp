import copy
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional


AUTO_ANALYSIS_SUBMITTED_BY = "dtvp-auto-analysis"

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_TERMINAL_DEDUPE_STATUSES = ("queued", "running", "completed", "failed")


@dataclass(frozen=True)
class AutoAnalysisTarget:
    component_name: str
    team: Optional[str] = None


@dataclass(frozen=True)
class AutoAnalysisSweepDeps:
    cache_manager: Any
    logger: Any
    sort_projects_by_version: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    load_team_mapping: Callable[[], dict[str, Any]]
    collect_version_snapshots: Callable[
        [list[dict[str, Any]], Any, Optional[str], dict[str, Any]],
        Awaitable[
            tuple[
                list[dict[str, Any]],
                dict[str, Any],
                dict[str, dict[str, int]],
            ]
        ],
    ]
    bom_analysis_cache_cls: type
    merge_vulnerability_details: Callable[
        [list[dict[str, Any]], list[dict[str, Any]]],
        Any,
    ]
    group_vulnerabilities: Callable[..., list[dict[str, Any]]]
    queue_grouped_vulnerabilities_for_analysis: Callable[
        [list[dict[str, Any]], dict[str, Any], set[str] | None],
        int,
    ]


def get_auto_code_analysis_enabled() -> bool:
    return (
        os.getenv("DTVP_AUTO_CODE_ANALYSIS_ENABLED", "")
        .strip()
        .lower()
        in _TRUE_VALUES
    )


def _normalize_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_team_name(value: Any) -> str:
    return str(value or "").strip()


def _mapping_primary_team(value: Any) -> str:
    if isinstance(value, list):
        return _normalize_team_name(value[0]) if value else ""
    return _normalize_team_name(value)


def get_primary_team_for_component(
    component_name: Any,
    team_mapping: dict[str, Any],
) -> str:
    target_name = _normalize_name(component_name)
    if not target_name:
        return ""

    for key, value in team_mapping.items():
        if key == "*":
            continue
        if _normalize_name(key) != target_name:
            continue
        return _mapping_primary_team(value)
    return ""


def _path_parts(path: str) -> list[str]:
    raw_parts = [part.strip() for part in path.split(" -> ") if part.strip()]
    parts: list[str] = []
    for part in raw_parts:
        if parts and _normalize_name(parts[-1]) == _normalize_name(part):
            continue
        parts.append(part)
    return parts


def _iter_instances(group: dict[str, Any]) -> list[dict[str, Any]]:
    instances: list[dict[str, Any]] = []
    for version in group.get("affected_versions") or []:
        for component in version.get("components") or []:
            if isinstance(component, dict):
                instances.append(component)
    return instances


def _instance_state(instance: dict[str, Any]) -> str:
    return str(
        instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET"
    ).upper()


def _instance_details(instance: dict[str, Any]) -> str:
    return str(
        instance.get("analysis_details") or instance.get("analysisDetails") or ""
    )


def _normalize_vuln_id(value: Any) -> str:
    return str(value or "").strip().upper()


def _group_vuln_id(group: dict[str, Any]) -> str:
    return _normalize_vuln_id(group.get("id"))


def has_prior_assessment_for_auto_analysis(group: dict[str, Any]) -> bool:
    instances = _iter_instances(group)
    if not instances:
        return False

    return any(
        _instance_state(instance) != "NOT_SET"
        or bool(_instance_details(instance).strip())
        for instance in instances
    )


def _collect_handled_vulnerability_ids(
    grouped_vulns: list[dict[str, Any]],
) -> set[str]:
    handled_ids: set[str] = set()
    for group in grouped_vulns:
        if not has_prior_assessment_for_auto_analysis(group):
            continue
        vuln_id = _group_vuln_id(group)
        if vuln_id:
            handled_ids.add(vuln_id)
    return handled_ids


def _add_target(
    targets: list[AutoAnalysisTarget],
    seen: set[str],
    component_name: Any,
    team: Any = None,
) -> None:
    name = str(component_name or "").strip()
    if not name:
        return
    key = _normalize_name(name)
    if key in seen:
        return
    targets.append(
        AutoAnalysisTarget(
            component_name=name,
            team=_normalize_team_name(team) or None,
        )
    )
    seen.add(key)


def select_auto_analysis_targets(
    group: dict[str, Any],
    team_mapping: dict[str, Any],
) -> list[AutoAnalysisTarget]:
    instances = _iter_instances(group)
    targets: list[AutoAnalysisTarget] = []
    seen: set[str] = set()

    for instance in instances:
        component_name = instance.get("component_name")
        team = get_primary_team_for_component(component_name, team_mapping)
        if team:
            _add_target(targets, seen, component_name, team)

    for instance in instances:
        for path in instance.get("dependency_chains") or []:
            if not isinstance(path, str):
                continue
            parts = _path_parts(path)
            for part in parts[1:]:
                team = get_primary_team_for_component(part, team_mapping)
                if team:
                    _add_target(targets, seen, part, team)
                    break

    if targets:
        return targets

    for instance in instances:
        _add_target(targets, seen, instance.get("component_name"))

    return targets


def is_open_for_auto_analysis(
    group: dict[str, Any],
    team_mapping: dict[str, Any],
) -> bool:
    """Automatic scans only target brand-new, wholly unassessed groups."""
    _ = team_mapping
    instances = _iter_instances(group)
    if not instances:
        return False

    states = [_instance_state(instance) for instance in instances]
    if any(_instance_details(instance).strip() for instance in instances):
        return False

    return all(state == "NOT_SET" for state in states)


def build_auto_analysis_guidance(
    group: dict[str, Any],
    target: AutoAnalysisTarget,
) -> str:
    vuln_id = str(group.get("id") or "this vulnerability")
    if target.team:
        return (
            "Automatic DTVP scan for an open vulnerability. "
            f"Assess {vuln_id} for component {target.component_name} "
            f"owned by {target.team}."
        )
    return (
        "Automatic DTVP scan for an open vulnerability. "
        f"Assess {vuln_id} for component {target.component_name}."
    )


def _queue_key(vuln_id: Any, component_name: Any) -> tuple[str, str]:
    return (
        str(vuln_id or "").strip().lower(),
        str(component_name or "").strip().lower(),
    )


def cancel_stale_automatic_analysis_queue_items(
    *,
    analysis_queue: Any,
    grouped_vulns: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    handled_vulnerability_ids: set[str] | None = None,
) -> int:
    if not hasattr(analysis_queue, "list_all") or not hasattr(analysis_queue, "cancel"):
        return 0

    stale_keys: set[tuple[str, str]] = set()
    open_keys: set[tuple[str, str]] = set()
    handled_ids = {
        _normalize_vuln_id(vuln_id)
        for vuln_id in (handled_vulnerability_ids or set())
        if _normalize_vuln_id(vuln_id)
    }

    for group in grouped_vulns:
        vuln_id = _group_vuln_id(group)
        if not vuln_id:
            continue

        targets = select_auto_analysis_targets(group, team_mapping)
        keys = {
            _queue_key(vuln_id, target.component_name)
            for target in targets
            if target.component_name
        }
        if is_open_for_auto_analysis(group, team_mapping):
            open_keys.update(keys)
        else:
            stale_keys.update(keys)
            if has_prior_assessment_for_auto_analysis(group):
                handled_ids.add(vuln_id)

    stale_keys.difference_update(open_keys)
    if not stale_keys and not handled_ids:
        return 0

    cancelled_count = 0
    for item in analysis_queue.list_all():
        if getattr(item, "source", "") != "automatic":
            continue
        if getattr(item, "status", "") != "queued":
            continue
        item_key = _queue_key(
            getattr(item, "vuln_id", ""),
            getattr(item, "component_name", ""),
        )
        item_vuln_id = _normalize_vuln_id(getattr(item, "vuln_id", ""))
        if item_key not in stale_keys and item_vuln_id not in handled_ids:
            continue
        if analysis_queue.cancel(getattr(item, "queue_id", "")):
            cancelled_count += 1

    return cancelled_count


def queue_open_vulnerabilities_for_analysis(
    *,
    analysis_queue: Any,
    grouped_vulns: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    enabled: bool,
    submitted_by: str = AUTO_ANALYSIS_SUBMITTED_BY,
    logger: Any = None,
    handled_vulnerability_ids: set[str] | None = None,
) -> int:
    if not enabled:
        return 0

    handled_ids = {
        _normalize_vuln_id(vuln_id)
        for vuln_id in (handled_vulnerability_ids or set())
        if _normalize_vuln_id(vuln_id)
    }
    for group in grouped_vulns:
        if has_prior_assessment_for_auto_analysis(group):
            vuln_id = _group_vuln_id(group)
            if vuln_id:
                handled_ids.add(vuln_id)

    cancelled_count = cancel_stale_automatic_analysis_queue_items(
        analysis_queue=analysis_queue,
        grouped_vulns=grouped_vulns,
        team_mapping=team_mapping,
        handled_vulnerability_ids=handled_ids,
    )
    queued_count = 0
    for group in grouped_vulns:
        if not is_open_for_auto_analysis(group, team_mapping):
            continue

        vuln_id = _group_vuln_id(group)
        if not vuln_id:
            continue
        if vuln_id in handled_ids:
            continue

        for target in select_auto_analysis_targets(group, team_mapping):
            _item, created = analysis_queue.submit_once(
                vuln_id=vuln_id,
                component_name=target.component_name,
                submitted_by=submitted_by,
                cvss_vector=group.get("cvss_vector"),
                user_guidance=build_auto_analysis_guidance(group, target),
                source="automatic",
                duplicate_statuses=_TERMINAL_DEDUPE_STATUSES,
            )
            if created:
                queued_count += 1

    if logger:
        if cancelled_count:
            logger.info(
                "Cancelled %d stale automatic code analysis scan(s)",
                cancelled_count,
            )
        if queued_count:
            logger.info("Queued %d automatic code analysis scan(s)", queued_count)

    return queued_count


def _cached_project_group_key(project: dict[str, Any]) -> str:
    return str(project.get("name") or project.get("uuid") or "").strip()


def _collect_cached_version_snapshots(
    deps: AutoAnalysisSweepDeps,
    versions: list[dict[str, Any]],
    team_mapping: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    combined_data: list[dict[str, Any]] = []
    bom_cache_map: dict[str, Any] = {}

    for version in versions:
        project_uuid = str(version.get("uuid") or "").strip()
        if not project_uuid:
            continue

        snapshot = deps.cache_manager.get_cached_project_snapshot(project_uuid)
        if not snapshot:
            continue

        findings, full_vulns, bom = copy.deepcopy(snapshot)
        deps.merge_vulnerability_details(findings, full_vulns)
        combined_data.append({"version": version, "vulnerabilities": findings})
        bom_cache_map[project_uuid] = deps.bom_analysis_cache_cls(
            bom or {},
            team_mapping,
        )

    return combined_data, bom_cache_map


def queue_cached_open_vulnerabilities_for_analysis(
    deps: AutoAnalysisSweepDeps,
    team_mapping: dict[str, Any],
) -> int:
    projects = deps.cache_manager.get_cached_project_versions()
    if not projects:
        return 0

    projects_by_name: dict[str, list[dict[str, Any]]] = {}
    for project in projects:
        project_key = _cached_project_group_key(project)
        if not project_key:
            continue
        projects_by_name.setdefault(project_key, []).append(project)

    grouped_batches: list[tuple[str, list[dict[str, Any]]]] = []
    handled_vulnerability_ids: set[str] = set()
    for project_name, versions in sorted(projects_by_name.items()):
        try:
            sorted_versions = deps.sort_projects_by_version(versions)
            combined_data, bom_cache_map = _collect_cached_version_snapshots(
                deps,
                sorted_versions,
                team_mapping,
            )
            if not combined_data:
                continue

            grouped = deps.group_vulnerabilities(
                combined_data,
                project_boms={},
                processed_boms=bom_cache_map,
            )
            grouped_batches.append((project_name, grouped))
            handled_vulnerability_ids.update(
                _collect_handled_vulnerability_ids(grouped)
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis cached sweep failed for project %s",
                project_name,
            )

    queued_total = 0
    for project_name, grouped in grouped_batches:
        try:
            queued_total += deps.queue_grouped_vulnerabilities_for_analysis(
                grouped,
                team_mapping,
                handled_vulnerability_ids,
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis cached sweep failed for project %s",
                project_name,
            )

    return queued_total


async def queue_existing_open_vulnerabilities_for_analysis(
    deps: AutoAnalysisSweepDeps,
    client: Any,
) -> int:
    team_mapping = deps.load_team_mapping()
    queued_total = queue_cached_open_vulnerabilities_for_analysis(
        deps,
        team_mapping,
    )

    try:
        projects = await deps.cache_manager.get_projects(client, "")
    except Exception:
        deps.logger.exception(
            "Automatic code analysis sweep failed to fetch projects"
        )
        return queued_total

    if not projects:
        return queued_total

    projects_by_name: dict[str, list[dict[str, Any]]] = {}
    for project in projects:
        project_name = str(project.get("name") or "").strip()
        project_uuid = str(project.get("uuid") or "").strip()
        if not project_name or not project_uuid:
            continue
        projects_by_name.setdefault(project_name, []).append(project)

    grouped_batches: list[tuple[str, list[dict[str, Any]]]] = []
    handled_vulnerability_ids: set[str] = set()
    for project_name, versions in sorted(projects_by_name.items()):
        try:
            sorted_versions = deps.sort_projects_by_version(versions)
            combined_data, bom_cache_map, _ = await deps.collect_version_snapshots(
                sorted_versions,
                client,
                None,
                team_mapping,
            )
            grouped = deps.group_vulnerabilities(
                combined_data,
                project_boms={},
                processed_boms=bom_cache_map,
            )
            grouped_batches.append((project_name, grouped))
            handled_vulnerability_ids.update(
                _collect_handled_vulnerability_ids(grouped)
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis sweep failed for project %s",
                project_name,
            )

    for project_name, grouped in grouped_batches:
        try:
            queued_total += deps.queue_grouped_vulnerabilities_for_analysis(
                grouped,
                team_mapping,
                handled_vulnerability_ids,
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis sweep failed for project %s",
                project_name,
            )

    return queued_total
