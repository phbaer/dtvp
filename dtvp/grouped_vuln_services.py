import asyncio
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .dt_client import DTClient
from .grouped_vuln_summary_index_services import (
    build_grouped_vuln_summary_cache_key,
)
from .logic import STATE_PRIORITY, _parse_assessment_blocks
from .task_group_query_services import build_task_group_query_index


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
    summary_index: Any = None
    summary_index_cache_revision: Callable[[], Any] = lambda: None


def _instance_state(instance: Dict[str, Any]) -> str:
    return instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET"


def _instance_details(instance: Dict[str, Any]) -> str:
    return instance.get("analysis_details") or instance.get("analysisDetails") or ""


def _normalize_group_tags(
    tags: List[Any] | None,
    team_mapping: Dict[str, Any],
) -> List[str]:
    if not tags:
        return []

    normalized: List[str] = []
    seen: set[str] = set()
    for tag in tags:
        tag_text = str(tag or "").strip()
        if not tag_text:
            continue

        primary = tag_text
        for mapping_value in team_mapping.values():
            if (
                isinstance(mapping_value, list)
                and len(mapping_value) > 1
                and tag_text in mapping_value[1:]
            ):
                primary = str(mapping_value[0])
                break

        if primary and primary not in seen:
            normalized.append(primary)
            seen.add(primary)

    return normalized


def _unique_non_empty_strings(values: List[Any]) -> List[str]:
    unique: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        unique.append(text)
        seen.add(text)
    return unique


def _parse_attribution_timestamp_ms(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value) or value <= 0:
            return None
        return int(value * 1000 if value < 1_000_000_000_000 else value)

    raw = str(value).strip()
    if not raw:
        return None

    try:
        numeric = float(raw)
        if math.isfinite(numeric) and numeric > 0:
            return int(numeric * 1000 if numeric < 1_000_000_000_000 else numeric)
    except ValueError:
        pass

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _cvss_major_version(vector: Any) -> Optional[str]:
    raw = str(vector or "").strip()
    if raw.startswith("CVSS:4."):
        return "4"
    if raw.startswith("CVSS:3."):
        return "3"
    if raw.startswith("CVSS:2.") or re.match(r"^\(?AV:[NAL]", raw):
        return "2"
    return None


def _has_cvss_version_mismatch(group: Dict[str, Any]) -> bool:
    original_version = _cvss_major_version(group.get("cvss_vector"))
    rescored_version = _cvss_major_version(group.get("rescored_vector"))
    return bool(
        original_version
        and rescored_version
        and original_version != rescored_version
    )


def _dependency_relationship(components: List[Dict[str, Any]]) -> str:
    direct_flags = [
        component.get("is_direct_dependency")
        for component in components
        if isinstance(component.get("is_direct_dependency"), bool)
    ]
    if True in direct_flags:
        return "DIRECT"
    if False in direct_flags:
        return "TRANSITIVE"
    return "UNKNOWN"


def _sort_states_by_priority(states: List[str]) -> List[str]:
    return sorted(states, key=lambda state: STATE_PRIORITY.get(state, 10))


def _normalize_block_signature(block: Dict[str, Any]) -> str:
    details = " ".join(str(block.get("details") or "").split())
    return "|".join(
        [
            str(block.get("team") or ""),
            str(block.get("state") or ""),
            str(block.get("justification") or ""),
            details,
        ]
    )


def _has_open_team_assessment(
    summary: Dict[str, Any],
    required_teams: List[str],
) -> bool:
    assessed_teams = summary["assessed_teams"]
    if required_teams and any(team not in assessed_teams for team in required_teams):
        return True
    if summary["has_missing_component"]:
        return True
    return any(
        block.get("team") != "General" and block.get("state") == "NOT_SET"
        for block in summary["blocks"]
    )


def _build_assessment_summary(group: Dict[str, Any]) -> Dict[str, Any]:
    instances = [
        component
        for affected_version in group.get("affected_versions", [])
        for component in affected_version.get("components", [])
    ]
    component_states = [_instance_state(instance) for instance in instances]
    instance_blocks: List[List[Dict[str, Any]]] = []
    blocks: List[Dict[str, Any]] = []

    for instance in instances:
        _shared, parsed_blocks = _parse_assessment_blocks(_instance_details(instance))
        instance_blocks.append(parsed_blocks)
        blocks.extend(parsed_blocks)

    assessed_teams = {
        block.get("team")
        for block in blocks
        if block.get("team")
        and block.get("team") != "General"
        and block.get("state")
        and block.get("state") != "NOT_SET"
    }
    team_states = _sort_states_by_priority(
        [
            block.get("state")
            for block in blocks
            if block.get("team") != "General"
            and block.get("state")
            and block.get("state") != "NOT_SET"
        ]
    )
    raw_states = _sort_states_by_priority(
        list({state for state in component_states if state != "NOT_SET"})
    )
    global_state = next(
        (
            block.get("state")
            for block in blocks
            if block.get("team") == "General" and block.get("state") != "NOT_SET"
        ),
        None,
    )

    return {
        "instances": instances,
        "component_states": component_states,
        "instance_blocks": instance_blocks,
        "blocks": blocks,
        "assessed_teams": assessed_teams,
        "has_any_assessment": any(state != "NOT_SET" for state in component_states),
        "has_missing_component": "NOT_SET" in component_states,
        "has_global_assessment": bool(global_state),
        "is_pending_review": any(
            "[Status: Pending Review]" in _instance_details(instance)
            for instance in instances
        ),
        "technical_state": global_state or (team_states[0] if team_states else None)
        or (raw_states[0] if raw_states else None)
        or "NOT_SET",
    }


def _derive_group_lifecycle(
    group: Dict[str, Any],
    summary: Dict[str, Any],
    required_teams: List[str],
) -> str:
    instances = summary["instances"]
    component_states = summary["component_states"]
    blocks = summary["blocks"]
    has_any = summary["has_any_assessment"]
    has_missing = summary["has_missing_component"]
    has_global = summary["has_global_assessment"]

    if not instances:
        return "OPEN"

    distinct_non_missing = {state for state in component_states if state != "NOT_SET"}
    if len(distinct_non_missing) > 1:
        return "INCONSISTENT"

    if not blocks and has_any:
        return "ASSESSED_LEGACY"

    if (
        len(blocks) == 1
        and blocks[0].get("team") == "General"
        and blocks[0].get("state") == "NOT_SET"
        and has_any
    ):
        return "ASSESSED_LEGACY"

    if not has_global:
        instance_block_signatures = []
        has_inconsistent_instance_blocks = False
        for instance_blocks in summary["instance_blocks"]:
            significant = [
                block
                for block in instance_blocks
                if block.get("state") != "NOT_SET" and block.get("team") != "General"
            ]
            if not significant:
                continue
            distinct_signatures = sorted(
                {_normalize_block_signature(block) for block in significant}
            )
            instance_block_signatures.append("||".join(distinct_signatures))
            if len(significant) > 1 and len(distinct_signatures) > 1:
                has_inconsistent_instance_blocks = True

        if len(set(instance_block_signatures)) > 1:
            return "INCONSISTENT"
        if has_inconsistent_instance_blocks and len(instance_block_signatures) <= 1:
            return "INCONSISTENT"

    def normalize_details(details: str) -> str:
        cleaned = details
        for pattern in [
            r"\[Date:\s*[^\]]*\]",
            r"\[Assessed By:\s*[^\]]*\]",
            r"\[Rescored:\s*[\d\.]+\]",
            r"\[Rescored Vector:\s*[^\]]+\]",
            r"\[Status: Pending Review\]",
        ]:
            cleaned = re.sub(pattern, "", cleaned)
        return " ".join(cleaned.split()).strip()

    assessed_details = [
        normalize_details(_instance_details(instance))
        for instance in instances
        if _instance_state(instance) != "NOT_SET"
    ]
    assessed_details = [details for details in assessed_details if details]
    if len(assessed_details) > 1 and any(
        details != assessed_details[0] for details in assessed_details
    ):
        return "INCONSISTENT"

    if summary["is_pending_review"]:
        return "NEEDS_APPROVAL"

    if not has_global and any(
        team not in summary["assessed_teams"] for team in required_teams
    ):
        return "INCOMPLETE" if has_any else "OPEN"

    version_states = []
    for affected_version in group.get("affected_versions", []):
        states = {
            _instance_state(component)
            for component in affected_version.get("components", [])
        }
        if not states:
            version_states.append("NOT_SET")
        elif len(states) == 1:
            version_states.append(next(iter(states)))
        else:
            non_missing = [state for state in states if state != "NOT_SET"]
            if len(non_missing) == 1:
                version_states.append(non_missing[0])
            elif len(non_missing) > 1:
                version_states.append("INCONSISTENT_VERSION")
            else:
                version_states.append("NOT_SET")

    non_empty_states = [
        state
        for state in version_states
        if state not in {"NOT_SET", "INCONSISTENT_VERSION"}
    ]
    if len(set(non_empty_states)) > 1 or "INCONSISTENT_VERSION" in version_states:
        return "INCONSISTENT"

    if has_missing and has_any:
        return "INCOMPLETE" if len(set(non_empty_states)) <= 1 else "INCONSISTENT"

    if has_global:
        return "ASSESSED"

    if instances and not has_global:
        return "INCOMPLETE" if has_any else "OPEN"

    return "OPEN"


def _build_group_list_metadata(
    group: Dict[str, Any],
    team_mapping: Dict[str, Any],
) -> Dict[str, Any]:
    affected_versions = group.get("affected_versions") or []
    components = [
        component
        for affected_version in affected_versions
        for component in affected_version.get("components", [])
    ]
    attributed_on_ms_values = _unique_non_empty_strings(
        [
            _parse_attribution_timestamp_ms(component.get("attributed_on"))
            for component in components
        ]
    )
    attributed_on_ms_numbers = [int(value) for value in attributed_on_ms_values]
    normalized_tags = _normalize_group_tags(group.get("tags") or [], team_mapping)
    summary = _build_assessment_summary(group)
    lifecycle = _derive_group_lifecycle(group, summary, normalized_tags)
    is_open = lifecycle == "OPEN" or (
        summary["is_pending_review"]
        and _has_open_team_assessment(summary, normalized_tags)
    )

    return {
        "lifecycle": lifecycle,
        "is_pending": summary["is_pending_review"],
        "is_open": is_open,
        "is_assessed": (
            summary["has_global_assessment"] and not summary["is_pending_review"]
        )
        or lifecycle == "ASSESSED_LEGACY",
        "technical_state": summary["technical_state"],
        "assessed_teams": sorted(summary["assessed_teams"]),
        "component_names": _unique_non_empty_strings(
            [component.get("component_name") for component in components]
        ),
        "versions": _unique_non_empty_strings(
            [
                affected_version.get("project_version")
                or affected_version.get("version")
                for affected_version in affected_versions
            ]
        ),
        "attributed_on_ms_values": attributed_on_ms_numbers,
        "oldest_attributed_on_ms": (
            min(attributed_on_ms_numbers) if attributed_on_ms_numbers else None
        ),
        "instance_count": len(components),
        "dependency_relationship": _dependency_relationship(components),
        "cvss_version_mismatch": _has_cvss_version_mismatch(group),
    }


def _summarize_component(component: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "project_uuid": component.get("project_uuid"),
        "project_name": component.get("project_name"),
        "project_version": component.get("project_version"),
        "component_name": component.get("component_name"),
        "component_version": component.get("component_version"),
        "component_uuid": component.get("component_uuid"),
        "vulnerability_uuid": component.get("vulnerability_uuid"),
        "finding_uuid": component.get("finding_uuid"),
        "attributed_on": component.get("attributed_on"),
        "analysis_state": component.get("analysis_state"),
        "justification": component.get("justification"),
        "is_suppressed": component.get("is_suppressed", False),
        "is_direct_dependency": component.get("is_direct_dependency"),
        "tags": component.get("tags", []),
    }


def summarize_grouped_vulnerabilities(
    groups: List[Dict[str, Any]],
    team_mapping: Dict[str, Any],
) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for group in groups:
        summary = {
            key: group.get(key)
            for key in [
                "id",
                "title",
                "description",
                "severity",
                "cvss",
                "cvss_score",
                "cvss_vector",
                "rescored_cvss",
                "rescored_vector",
                "rescored_vector_adjusted",
                "tags",
                "assignees",
                "aliases",
            ]
        }
        summary["list_metadata"] = _build_group_list_metadata(group, team_mapping)
        summary["affected_versions"] = [
            {
                "project_name": affected_version.get("project_name"),
                "project_version": affected_version.get("project_version"),
                "project_uuid": affected_version.get("project_uuid"),
                "components": [
                    _summarize_component(component)
                    for component in affected_version.get("components", [])
                ],
            }
            for affected_version in group.get("affected_versions", [])
        ]
        summaries.append(summary)
    return summaries


def build_grouped_vuln_statistics_rollup(
    versions: List[Dict[str, Any]],
    combined_data: List[Dict[str, Any]],
    version_counts: Dict[str, int],
    version_severity_counts: Dict[str, Dict[str, int]],
) -> Dict[str, Any]:
    major_version_counts: Dict[str, int] = {}
    version_major_details: Dict[str, Dict[str, int]] = {}
    major_version_severity_counts: Dict[str, Dict[str, int]] = {}

    for version in versions:
        version_label = version.get("version", "unknown")
        major = (
            version_label.split(".")[0]
            if isinstance(version_label, str) and "." in version_label
            else version_label
        )
        major = major or "unknown"

        major_version_counts[major] = major_version_counts.get(major, 0) + (
            version_counts.get(version_label, 0)
        )
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

    return {
        "version_counts": version_counts,
        "major_version_counts": major_version_counts,
        "major_version_details": version_major_details,
        "major_version_severity_counts": major_version_severity_counts,
        "version_severity_counts": version_severity_counts,
    }


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
    partial_callback: (
        Callable[
            [List[Dict[str, Any]], Dict[str, Any], Dict[str, Dict[str, int]]],
            None,
        ]
        | None
    ) = None,
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
            if partial_callback:
                partial_combined_data: List[Dict[str, Any]] = []
                partial_bom_cache_map: Dict[str, Any] = {}
                partial_version_severity_counts: Dict[str, Dict[str, int]] = {}
                for result in results:
                    if result is None:
                        continue
                    (
                        partial_combined_entry,
                        partial_bom_cache,
                        partial_severity_counts,
                    ) = result
                    partial_version_info = partial_combined_entry["version"]
                    partial_combined_data.append(partial_combined_entry)
                    partial_bom_cache_map[partial_version_info["uuid"]] = partial_bom_cache
                    partial_version_severity_counts[
                        partial_version_info.get("version")
                    ] = partial_severity_counts
                partial_callback(
                    partial_combined_data,
                    partial_bom_cache_map,
                    partial_version_severity_counts,
                )
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
    response_mode: str = "full",
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
            now = datetime.now(timezone.utc)
            deps.tasks[task_id]["status"] = "completed"
            deps.tasks[task_id]["progress"] = 100
            deps.tasks[task_id]["result"] = []
            deps.tasks[task_id]["result_mode"] = response_mode
            deps.tasks[task_id]["updated_at"] = now
            deps.tasks[task_id]["completed_at"] = now
            deps.tasks[task_id]["_full_result"] = []
            deps.tasks[task_id]["_full_result_by_id"] = {}
            deps.tasks[task_id]["_group_query_index"] = build_task_group_query_index([])
            return

        found_msg = f"Found {len(versions)} versions. Fetching vulnerabilities..."
        deps.tasks[task_id]["message"] = found_msg
        deps.tasks[task_id].setdefault("log", []).append(found_msg)

        team_mapping = deps.load_team_mapping()
        summary_cache_key = None
        summary_cache_scope: Dict[str, Any] | None = None

        if response_mode == "summary" and deps.summary_index is not None:
            cache_revision = deps.summary_index_cache_revision()
            summary_cache_key = build_grouped_vuln_summary_cache_key(
                name=name,
                cve=cve,
                versions=versions,
                team_mapping=team_mapping,
                cache_revision=cache_revision,
            )
            summary_cache_scope = {
                "name": name or "",
                "cve": cve or "",
                "versions": [
                    {
                        "uuid": version.get("uuid"),
                        "name": version.get("name"),
                        "version": version.get("version"),
                    }
                    for version in versions
                ],
                "cache_revision": cache_revision,
            }
            cached_summary = deps.summary_index.load(summary_cache_key)
            if cached_summary and isinstance(cached_summary.get("result"), list):
                cached_result = cached_summary["result"]
                deps.tasks[task_id]["result_mode"] = response_mode
                deps.tasks[task_id]["result"] = cached_result
                deps.tasks[task_id]["partial_result_available"] = True
                deps.tasks[task_id]["partial_source"] = "summary_index"
                deps.tasks[task_id]["partial_versions_completed"] = int(
                    cached_summary.get("total_versions") or len(versions)
                )
                deps.tasks[task_id]["partial_total_versions"] = len(versions)
                deps.tasks[task_id]["_group_query_index"] = build_task_group_query_index(
                    cached_result
                )
                deps.tasks[task_id]["_statistics_rollup"] = (
                    cached_summary.get("statistics_rollup") or {}
                )
                deps.tasks[task_id].setdefault("log", []).append(
                    "Loaded cached vulnerability summary index."
                )

        def update_progress(
            completed: int, total: int, version_info: Dict[str, Any]
        ) -> None:
            deps.tasks[task_id]["progress"] = int((completed / total) * 90)
            msg = f"Processed version {version_info.get('version')} ({completed}/{total})..."
            deps.tasks[task_id]["message"] = msg
            deps.tasks[task_id].setdefault("log", []).append(msg)

        def publish_partial_summary(
            partial_combined_data: List[Dict[str, Any]],
            partial_bom_cache_map: Dict[str, Any],
            partial_version_severity_counts: Dict[str, Dict[str, int]],
        ) -> None:
            if response_mode != "summary" or not partial_combined_data:
                return

            partial_result = deps.group_vulnerabilities(
                partial_combined_data,
                project_boms={},
                processed_boms=partial_bom_cache_map,
            )
            partial_summaries = summarize_grouped_vulnerabilities(
                partial_result,
                team_mapping,
            )
            partial_version_counts = {
                entry["version"].get("version"): len(entry["vulnerabilities"])
                for entry in partial_combined_data
            }
            partial_versions = [
                entry["version"]
                for entry in partial_combined_data
            ]
            deps.tasks[task_id]["result_mode"] = response_mode
            deps.tasks[task_id]["result"] = partial_summaries
            deps.tasks[task_id]["partial_result_available"] = True
            deps.tasks[task_id]["partial_versions_completed"] = len(partial_combined_data)
            deps.tasks[task_id]["partial_total_versions"] = len(versions)
            deps.tasks[task_id]["_partial_full_result"] = partial_result
            deps.tasks[task_id]["_group_query_index"] = build_task_group_query_index(
                partial_summaries
            )
            deps.tasks[task_id]["_statistics_rollup"] = build_grouped_vuln_statistics_rollup(
                partial_versions,
                partial_combined_data,
                partial_version_counts,
                partial_version_severity_counts,
            )

        (
            combined_data,
            bom_cache_map,
            version_severity_counts,
        ) = await collect_version_snapshots(
            deps,
            versions,
            client,
            cve,
            team_mapping,
            progress_callback=update_progress,
            partial_callback=publish_partial_summary,
        )
        version_counts = {
            entry["version"].get("version"): len(entry["vulnerabilities"])
            for entry in combined_data
        }

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

        now = datetime.now(timezone.utc)
        deps.tasks[task_id]["status"] = "completed"
        deps.tasks[task_id]["progress"] = 100
        deps.tasks[task_id]["result_mode"] = response_mode
        deps.tasks[task_id]["updated_at"] = now
        deps.tasks[task_id]["completed_at"] = now
        deps.tasks[task_id]["partial_result_available"] = False
        deps.tasks[task_id]["_statistics_rollup"] = build_grouped_vuln_statistics_rollup(
            versions,
            combined_data,
            version_counts,
            version_severity_counts,
        )
        deps.tasks[task_id]["_full_result"] = result
        deps.tasks[task_id]["_full_result_by_id"] = {
            item.get("id"): item for item in result if item.get("id")
        }
        deps.tasks[task_id]["result"] = (
            summarize_grouped_vulnerabilities(result, team_mapping)
            if response_mode == "summary"
            else result
        )
        deps.tasks[task_id]["_group_query_index"] = build_task_group_query_index(
            deps.tasks[task_id]["result"]
        )
        if (
            response_mode == "summary"
            and deps.summary_index is not None
            and summary_cache_key
            and summary_cache_scope is not None
        ):
            deps.summary_index.save(
                summary_cache_key,
                scope=summary_cache_scope,
                summaries=deps.tasks[task_id]["result"],
                statistics_rollup=deps.tasks[task_id]["_statistics_rollup"],
                total_versions=len(versions),
            )
    except Exception as exc:
        now = datetime.now(timezone.utc)
        deps.tasks[task_id]["status"] = "failed"
        deps.tasks[task_id]["message"] = str(exc)
        deps.tasks[task_id]["updated_at"] = now
        deps.tasks[task_id]["completed_at"] = now
        deps.logger.exception("Task %s failed", task_id)
