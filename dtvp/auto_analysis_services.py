import asyncio
import copy
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from .team_mapping import (
    ComponentIdentity,
    find_team_mapping_match,
    get_primary_team_for_identity,
)


AUTO_ANALYSIS_SUBMITTED_BY = "dtvp-auto-analysis"

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_TERMINAL_DEDUPE_STATUSES = ("queued", "running", "completed", "failed")


@dataclass(frozen=True)
class AutoAnalysisTarget:
    component_name: str
    team: Optional[str] = None
    component_group: Optional[str] = None
    component_purl: Optional[str] = None
    group_known: bool = False
    team_mapping_selector: Optional[str] = None


@dataclass(frozen=True)
class AutoAnalysisQueueCandidate:
    vuln_id: str
    component_name: str
    project_name: Optional[str] = None
    cvss_vector: Any = None
    user_guidance: str = ""
    affected_product_versions: tuple[str, ...] = ()
    submitted_by: str = AUTO_ANALYSIS_SUBMITTED_BY
    context_fingerprint: Optional[str] = None
    context_summary: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AutoAnalysisQueuePlan:
    candidates: tuple[AutoAnalysisQueueCandidate, ...] = ()
    stale_keys: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    handled_vulnerability_ids: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AutoAnalysisSweepPlan:
    queue_plans: tuple[AutoAnalysisQueuePlan, ...] = ()


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
    queue_grouped_vulnerabilities_for_analysis: Callable[..., int]
    load_auto_analysis_guidance: Callable[[], dict[str, Any]] = lambda: {}
    tmrescore_project_cache: dict[str, dict[str, Any]] | None = None
    result_store: Any = None


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


def get_primary_team_for_component(
    component_name: Any,
    team_mapping: dict[str, Any],
    component_group: Any = None,
    component_purl: Any = None,
    *,
    group_known: bool = False,
) -> str:
    return get_primary_team_for_identity(
        team_mapping,
        component_name,
        component_group,
        component_purl,
        group_known=group_known,
    )


def _find_team_mapping_match_for_component(
    team_mapping: dict[str, Any],
    component_name: Any,
    component_group: Any = None,
    component_purl: Any = None,
    *,
    group_known: bool = False,
):
    return find_team_mapping_match(
        team_mapping,
        ComponentIdentity(
            name=str(component_name or "").strip(),
            group=str(component_group).strip()
            if component_group not in (None, "")
            else None,
            purl=str(component_purl).strip()
            if component_purl not in (None, "")
            else None,
            group_known=group_known,
        ),
        include_wildcard=False,
    )


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


def _group_project_name(group: dict[str, Any]) -> Optional[str]:
    project_names = {
        str(instance.get("project_name") or "").strip()
        for instance in _iter_instances(group)
        if str(instance.get("project_name") or "").strip()
    }
    if len(project_names) == 1:
        return next(iter(project_names))
    return None


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
    *,
    component_group: Any = None,
    component_purl: Any = None,
    group_known: bool = False,
    team_mapping_selector: Any = None,
) -> None:
    name = str(component_name or "").strip()
    if not name:
        return
    key = name
    if key in seen:
        return
    targets.append(
        AutoAnalysisTarget(
            component_name=name,
            team=_normalize_team_name(team) or None,
            component_group=str(component_group).strip()
            if component_group not in (None, "")
            else None,
            component_purl=str(component_purl).strip()
            if component_purl not in (None, "")
            else None,
            group_known=group_known,
            team_mapping_selector=str(team_mapping_selector).strip()
            if team_mapping_selector not in (None, "")
            else None,
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
        component_group = instance.get("component_group")
        component_purl = instance.get("component_purl")
        match = _find_team_mapping_match_for_component(
            team_mapping,
            component_name,
            component_group,
            component_purl,
            group_known="component_group" in instance,
        )
        team = match.tags[0] if match and match.tags else ""
        if team:
            _add_target(
                targets,
                seen,
                component_name,
                team,
                component_group=component_group,
                component_purl=component_purl,
                group_known="component_group" in instance,
                team_mapping_selector=match.key if match else None,
            )

    for instance in instances:
        for path in instance.get("dependency_chains") or []:
            if not isinstance(path, str):
                continue
            parts = _path_parts(path)
            for part in parts[1:]:
                match = _find_team_mapping_match_for_component(
                    team_mapping,
                    part,
                    group_known=False,
                )
                team = match.tags[0] if match and match.tags else ""
                if team:
                    _add_target(
                        targets,
                        seen,
                        part,
                        team,
                        team_mapping_selector=match.key if match else None,
                    )
                    break

    if targets:
        return targets

    return []


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


def _guidance_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return "\n\n".join(
            text
            for text in (_guidance_text(entry) for entry in value)
            if text
        )
    if isinstance(value, dict):
        if value.get("enabled") is False:
            return ""
        for key in (
            "guidance",
            "prompt",
            "additional_prompt",
            "additional_guidance",
            "content",
            "text",
        ):
            text = _guidance_text(value.get(key))
            if text:
                return text
        sections = value.get("sections")
        if isinstance(sections, list):
            return _guidance_text(sections)
        return ""
    return str(value).strip()


def _component_guidance_entries(config: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    components = config.get("components")
    if isinstance(components, dict):
        return components

    reserved = {
        "default",
        "*",
        "components",
        "projects",
        "schema_version",
        "description",
        "notes",
    }
    return {
        str(key): value
        for key, value in config.items()
        if str(key).strip() and str(key).strip().lower() not in reserved
    }


def _component_guidance_identities(
    group: dict[str, Any],
    target: AutoAnalysisTarget,
) -> tuple[ComponentIdentity, ...]:
    target_name = str(target.component_name or "").strip()
    target_key = _normalize_name(target_name)
    identities: list[ComponentIdentity] = []
    seen: set[tuple[str, str, str, bool]] = set()

    def add_identity(identity: ComponentIdentity) -> None:
        identity_key = (
            identity.name,
            identity.group or "",
            identity.purl or "",
            identity.group_known,
        )
        if identity_key in seen:
            return
        seen.add(identity_key)
        identities.append(identity)

    target_identity = ComponentIdentity(
        name=target_name,
        group=target.component_group,
        purl=target.component_purl,
        group_known=target.group_known,
    )
    if target.component_group or target.component_purl or target.group_known:
        add_identity(target_identity)

    for instance in _iter_instances(group):
        if _normalize_name(instance.get("component_name")) != target_key:
            continue
        add_identity(
            ComponentIdentity(
                name=str(instance.get("component_name") or "").strip(),
                group=str(instance.get("component_group")).strip()
                if instance.get("component_group") not in (None, "")
                else None,
                purl=str(instance.get("component_purl")).strip()
                if instance.get("component_purl") not in (None, "")
                else None,
                group_known="component_group" in instance,
            )
        )

    if identities:
        return tuple(identities)
    return (target_identity,)


def _lookup_component_guidance_entry(
    entries: dict[str, Any],
    group: dict[str, Any],
    target: AutoAnalysisTarget,
) -> Any:
    selector = str(target.team_mapping_selector or "").strip()
    if selector:
        for key, value in entries.items():
            if str(key).strip() == selector:
                return value

    for identity in _component_guidance_identities(group, target):
        match = find_team_mapping_match(entries, identity, include_wildcard=False)
        if match:
            return match.value
    return None


def build_component_auto_analysis_guidance_block(
    target: AutoAnalysisTarget,
    component_guidance: Optional[str],
) -> str:
    static_guidance = _guidance_text(component_guidance)
    if not static_guidance:
        return ""

    selector_text = (
        f" Selector: {target.team_mapping_selector}."
        if target.team_mapping_selector
        else ""
    )
    return (
        "Component-specific auto-assessment guidance configured in DTVP "
        f"for scan target {target.component_name}.{selector_text} "
        "Treat this as reviewer context to investigate, not as evidence. "
        "Do not infer dependency presence, version, reachability, or affectedness "
        "from this guidance alone; verify it against code, dependency, SBOM, or "
        "fetched source evidence.\n"
        f"{static_guidance}"
    )


def get_component_auto_analysis_guidance(
    config: dict[str, Any] | None,
    group: dict[str, Any],
    target: AutoAnalysisTarget,
) -> str:
    if not isinstance(config, dict):
        return _guidance_text(config)

    parts: list[str] = []
    default_text = _guidance_text(config.get("default") or config.get("*"))
    if default_text:
        parts.append(default_text)

    component_entry = _lookup_component_guidance_entry(
        _component_guidance_entries(config),
        group,
        target,
    )
    component_text = _guidance_text(component_entry)
    if component_text:
        parts.append(component_text)

    return "\n\n".join(parts)


def build_auto_analysis_guidance(
    group: dict[str, Any],
    target: AutoAnalysisTarget,
    *,
    tmrescore_proposal: Optional[dict[str, Any]] = None,
    component_guidance: Optional[str] = None,
) -> str:
    vuln_id = str(group.get("id") or "this vulnerability")
    guidance_parts: list[str] = []
    if target.team:
        guidance_parts.append(
            "Automatic DTVP scan for an open vulnerability. "
            f"Assess {vuln_id} for component {target.component_name} "
            f"owned by {target.team}."
        )
    else:
        guidance_parts.append(
            "Automatic DTVP scan for an open vulnerability. "
            f"Assess {vuln_id} for component {target.component_name}."
        )
    tmrescore_guidance = build_tmrescore_code_analysis_guidance(tmrescore_proposal)
    if tmrescore_guidance:
        guidance_parts.append(tmrescore_guidance)
    static_guidance = build_component_auto_analysis_guidance_block(
        target,
        component_guidance,
    )
    if static_guidance:
        guidance_parts.append(static_guidance)
    return "\n\n".join(guidance_parts)


def build_tmrescore_code_analysis_guidance(
    proposal: Optional[dict[str, Any]],
) -> str:
    if not isinstance(proposal, dict):
        return ""
    analysis = proposal.get("analysis") if isinstance(proposal.get("analysis"), dict) else {}
    lines = [
        "TMRescore/vscorer guidance. Treat this as reviewer context and verify it against code evidence.",
    ]
    if analysis.get("detail"):
        lines.append(f"TMRescore reasoning: {analysis['detail']}")
    if analysis.get("state"):
        lines.append(f"Suggested analysis state: {analysis['state']}")
    if analysis.get("justification"):
        lines.append(f"Suggested justification: {analysis['justification']}")
    responses = analysis.get("response")
    if isinstance(responses, list):
        response_text = [
            str(response)
            if isinstance(response, str)
            else str(response.get("detail") or response.get("title") or "")
            for response in responses
            if isinstance(response, str) or isinstance(response, dict)
        ]
        response_text = [entry for entry in response_text if entry.strip()]
        if response_text:
            lines.append(f"Suggested response: {'; '.join(response_text)}")
    original_score = proposal.get("original_score")
    rescored_score = proposal.get("rescored_score")
    if original_score is not None or rescored_score is not None:
        lines.append(
            f"Score guidance: {original_score if original_score is not None else 'unknown'} -> {rescored_score if rescored_score is not None else 'unknown'}"
        )
    original_vector = proposal.get("original_vector")
    rescored_vector = proposal.get("rescored_vector")
    if original_vector or rescored_vector:
        lines.append(
            f"Vector guidance: {original_vector or 'unknown'} -> {rescored_vector or 'unknown'}"
        )
    cwe_descriptions = proposal.get("cwe_descriptions")
    if isinstance(cwe_descriptions, dict) and cwe_descriptions:
        lines.append(f"CWE guidance: {cwe_descriptions}")
    affected_refs = proposal.get("affected_refs")
    if isinstance(affected_refs, list) and affected_refs:
        refs = ", ".join(str(ref) for ref in affected_refs[:12])
        lines.append(f"Affected refs from TMRescore: {refs}")
    evaluations = proposal.get("evaluations")
    if evaluations:
        lines.append(f"TMRescore evaluations: {str(evaluations)[:1200]}")
    return "\n".join(lines)


def _find_tmrescore_proposal(
    group: dict[str, Any],
    project_name: Optional[str],
    tmrescore_project_cache: dict[str, dict[str, Any]] | None,
) -> Optional[dict[str, Any]]:
    if not tmrescore_project_cache:
        return None
    project_key = _normalize_team_name(project_name or _group_project_name(group))
    if not project_key:
        return None
    snapshot = tmrescore_project_cache.get(project_key)
    if not isinstance(snapshot, dict):
        return None
    proposals = snapshot.get("proposals")
    if not isinstance(proposals, dict):
        return None
    candidate_ids = [
        _normalize_vuln_id(group.get("id")),
        *[_normalize_vuln_id(alias) for alias in (group.get("aliases") or [])],
    ]
    for candidate_id in candidate_ids:
        if candidate_id and isinstance(proposals.get(candidate_id), dict):
            return proposals[candidate_id]
    return None


def _queue_key(vuln_id: Any, component_name: Any) -> tuple[str, str]:
    return (
        str(vuln_id or "").strip().lower(),
        str(component_name or "").strip().lower(),
    )


def _sorted_texts(values: Any) -> list[str]:
    return sorted(
        {
            str(value or "").strip()
            for value in (values or [])
            if str(value or "").strip()
        }
    )


def _affected_product_versions(group: dict[str, Any]) -> list[str]:
    return _sorted_texts(
        version.get("project_version")
        for version in (group.get("affected_versions") or [])
        if isinstance(version, dict)
    )


def build_auto_analysis_context_summary(
    group: dict[str, Any],
    target: AutoAnalysisTarget,
    project_name: Optional[str],
    component_guidance: Optional[str] = None,
) -> dict[str, Any]:
    instances = _iter_instances(group)
    component_rows: list[dict[str, Any]] = []
    for instance in instances:
        component_rows.append(
            {
                "project_name": instance.get("project_name"),
                "project_version": instance.get("project_version"),
                "component_name": instance.get("component_name"),
                "component_group": instance.get("component_group"),
                "component_version": instance.get("component_version"),
                "component_purl": instance.get("component_purl"),
                "dependency_chains": [
                    path for path in (instance.get("dependency_chains") or []) if path
                ][:5],
            }
        )

    project_versions = _affected_product_versions(group)
    guidance_text = _guidance_text(component_guidance)
    summary = {
        "project_name": project_name,
        "vuln_id": _group_vuln_id(group),
        "aliases": _sorted_texts(group.get("aliases") or []),
        "target_component": target.component_name,
        "target_team": target.team,
        "cvss_vector": group.get("cvss_vector"),
        "project_versions": project_versions,
        "component_versions": _sorted_texts(
            instance.get("component_version") for instance in instances
        ),
        "instance_count": len(instances),
        "components": sorted(
            component_rows,
            key=lambda row: (
                str(row.get("project_version") or ""),
                str(row.get("component_name") or ""),
                str(row.get("component_version") or ""),
            ),
        ),
    }
    if target.component_group is not None:
        summary["target_component_group"] = target.component_group
    if target.component_purl:
        summary["target_component_purl"] = target.component_purl
    if target.group_known:
        summary["target_component_group_known"] = True
    if target.team_mapping_selector:
        summary["target_team_mapping_selector"] = target.team_mapping_selector
    if guidance_text:
        summary["component_guidance_configured"] = True
        summary["component_guidance_fingerprint"] = hashlib.sha256(
            guidance_text.encode("utf-8")
        ).hexdigest()
    return summary


def build_auto_analysis_context_fingerprint(
    group: dict[str, Any],
    target: AutoAnalysisTarget,
    project_name: Optional[str],
    component_guidance: Optional[str] = None,
) -> str:
    summary = build_auto_analysis_context_summary(
        group,
        target,
        project_name,
        component_guidance,
    )
    canonical = json.dumps(summary, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _has_fresh_persisted_result(
    *,
    result_store: Any,
    project_name: Optional[str],
    vuln_id: str,
    target: AutoAnalysisTarget,
    context_fingerprint: str,
) -> bool:
    if not result_store or not hasattr(result_store, "find_latest"):
        return False
    try:
        return bool(
            result_store.find_latest(
                project_name=project_name,
                vuln_id=vuln_id,
                component_name=target.component_name,
                context_fingerprint=context_fingerprint,
            )
        )
    except Exception:
        return False


def cancel_stale_automatic_analysis_queue_items(
    *,
    analysis_queue: Any,
    grouped_vulns: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    handled_vulnerability_ids: set[str] | None = None,
    tmrescore_project_cache: dict[str, dict[str, Any]] | None = None,
    result_store: Any = None,
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> int:
    plan = build_auto_analysis_queue_plan(
        grouped_vulns=grouped_vulns,
        team_mapping=team_mapping,
        enabled=True,
        handled_vulnerability_ids=handled_vulnerability_ids,
        tmrescore_project_cache=tmrescore_project_cache,
        result_store=result_store,
        auto_analysis_guidance=auto_analysis_guidance,
    )
    return cancel_stale_automatic_analysis_queue_items_for_plan(
        analysis_queue=analysis_queue,
        plan=plan,
    )


def build_auto_analysis_queue_plan(
    *,
    grouped_vulns: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    enabled: bool,
    submitted_by: str = AUTO_ANALYSIS_SUBMITTED_BY,
    handled_vulnerability_ids: set[str] | frozenset[str] | None = None,
    tmrescore_project_cache: dict[str, dict[str, Any]] | None = None,
    result_store: Any = None,
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> AutoAnalysisQueuePlan:
    if not enabled:
        return AutoAnalysisQueuePlan()

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

    stale_keys: set[tuple[str, str]] = set()
    open_keys: set[tuple[str, str]] = set()
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
        if not targets:
            handled_ids.add(vuln_id)
        if is_open_for_auto_analysis(group, team_mapping):
            open_keys.update(keys)
        else:
            stale_keys.update(keys)
            if has_prior_assessment_for_auto_analysis(group):
                handled_ids.add(vuln_id)

    stale_keys.difference_update(open_keys)

    candidates: list[AutoAnalysisQueueCandidate] = []
    seen_candidate_keys: set[tuple[str, str]] = set()
    fresh_persisted_keys: set[tuple[str, str]] = set()
    for group in grouped_vulns:
        if not is_open_for_auto_analysis(group, team_mapping):
            continue

        vuln_id = _group_vuln_id(group)
        if not vuln_id:
            continue
        if vuln_id in handled_ids:
            continue

        for target in select_auto_analysis_targets(group, team_mapping):
            key = _queue_key(vuln_id, target.component_name)
            if key in seen_candidate_keys:
                continue
            project_name = _group_project_name(group)
            component_guidance = get_component_auto_analysis_guidance(
                auto_analysis_guidance,
                group,
                target,
            )
            context_summary = build_auto_analysis_context_summary(
                group,
                target,
                project_name,
                component_guidance,
            )
            context_fingerprint = build_auto_analysis_context_fingerprint(
                group,
                target,
                project_name,
                component_guidance,
            )
            if _has_fresh_persisted_result(
                result_store=result_store,
                project_name=project_name,
                vuln_id=vuln_id,
                target=target,
                context_fingerprint=context_fingerprint,
            ):
                fresh_persisted_keys.add(key)
                seen_candidate_keys.add(key)
                continue
            tmrescore_proposal = _find_tmrescore_proposal(
                group,
                project_name,
                tmrescore_project_cache,
            )
            affected_product_versions = tuple(context_summary.get("project_versions") or [])
            candidates.append(
                AutoAnalysisQueueCandidate(
                    vuln_id=vuln_id,
                    component_name=target.component_name,
                    project_name=project_name,
                    cvss_vector=group.get("cvss_vector"),
                    user_guidance=build_auto_analysis_guidance(
                        group,
                        target,
                        tmrescore_proposal=tmrescore_proposal,
                        component_guidance=component_guidance,
                    ),
                    affected_product_versions=affected_product_versions,
                    submitted_by=submitted_by,
                    context_fingerprint=context_fingerprint,
                    context_summary=context_summary,
                )
            )
            seen_candidate_keys.add(key)

    return AutoAnalysisQueuePlan(
        candidates=tuple(candidates),
        stale_keys=frozenset(stale_keys | fresh_persisted_keys),
        handled_vulnerability_ids=frozenset(handled_ids),
    )


def cancel_stale_automatic_analysis_queue_items_for_plan(
    *,
    analysis_queue: Any,
    plan: AutoAnalysisQueuePlan,
) -> int:
    if not hasattr(analysis_queue, "list_all") or not hasattr(analysis_queue, "cancel"):
        return 0

    if not plan.stale_keys and not plan.handled_vulnerability_ids:
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
        if (
            item_key not in plan.stale_keys
            and item_vuln_id not in plan.handled_vulnerability_ids
        ):
            continue
        if analysis_queue.cancel(getattr(item, "queue_id", "")):
            cancelled_count += 1

    return cancelled_count


def refresh_stale_automatic_analysis_queue_items_for_plan(
    *,
    analysis_queue: Any,
    plan: AutoAnalysisQueuePlan,
) -> int:
    if not hasattr(analysis_queue, "list_all"):
        return 0

    candidates_by_key = {
        _queue_key(candidate.vuln_id, candidate.component_name): candidate
        for candidate in plan.candidates
        if str(candidate.context_fingerprint or "").strip()
    }
    if not candidates_by_key:
        return 0

    refreshed_count = 0
    for item in list(analysis_queue.list_all()):
        if getattr(item, "source", "") != "automatic":
            continue
        item_key = _queue_key(
            getattr(item, "vuln_id", ""),
            getattr(item, "component_name", ""),
        )
        candidate = candidates_by_key.get(item_key)
        if not candidate:
            continue

        candidate_fingerprint = str(candidate.context_fingerprint or "").strip()
        item_fingerprint = str(getattr(item, "context_fingerprint", "") or "").strip()
        if item_fingerprint == candidate_fingerprint:
            continue

        queue_id = str(getattr(item, "queue_id", "") or "")
        status = str(getattr(item, "status", "") or "")
        if status == "queued" and hasattr(analysis_queue, "cancel"):
            if analysis_queue.cancel(queue_id):
                refreshed_count += 1
        elif status in {"completed", "failed", "cancelled"} and hasattr(
            analysis_queue,
            "remove_finished",
        ):
            if analysis_queue.remove_finished(queue_id):
                refreshed_count += 1

    return refreshed_count


def apply_auto_analysis_queue_plan(
    *,
    analysis_queue: Any,
    plan: AutoAnalysisQueuePlan,
    logger: Any = None,
) -> int:
    cancelled_count = cancel_stale_automatic_analysis_queue_items_for_plan(
        analysis_queue=analysis_queue,
        plan=plan,
    )
    refreshed_count = refresh_stale_automatic_analysis_queue_items_for_plan(
        analysis_queue=analysis_queue,
        plan=plan,
    )

    queued_count = 0
    for candidate in plan.candidates:
        _item, created = analysis_queue.submit_once(
            vuln_id=candidate.vuln_id,
            component_name=candidate.component_name,
            submitted_by=candidate.submitted_by,
            project_name=candidate.project_name,
            cvss_vector=candidate.cvss_vector,
            user_guidance=candidate.user_guidance,
            affected_product_versions=list(candidate.affected_product_versions),
            source="automatic",
            duplicate_statuses=_TERMINAL_DEDUPE_STATUSES,
            context_fingerprint=candidate.context_fingerprint,
            context_summary=candidate.context_summary,
        )
        if created:
            queued_count += 1

    if logger:
        if cancelled_count:
            logger.info(
                "Cancelled %d stale automatic code analysis scan(s)",
                cancelled_count,
            )
        if refreshed_count:
            logger.info(
                "Replaced %d automatic code analysis scan(s) with refreshed context",
                refreshed_count,
            )
        if queued_count:
            logger.info("Queued %d automatic code analysis scan(s)", queued_count)

    return queued_count


def apply_auto_analysis_sweep_plan(
    *,
    analysis_queue: Any,
    plan: AutoAnalysisSweepPlan,
    logger: Any = None,
) -> int:
    queued_total = 0
    for queue_plan in plan.queue_plans:
        queued_total += apply_auto_analysis_queue_plan(
            analysis_queue=analysis_queue,
            plan=queue_plan,
            logger=logger,
        )
    return queued_total


def queue_open_vulnerabilities_for_analysis(
    *,
    analysis_queue: Any,
    grouped_vulns: list[dict[str, Any]],
    team_mapping: dict[str, Any],
    enabled: bool,
    submitted_by: str = AUTO_ANALYSIS_SUBMITTED_BY,
    logger: Any = None,
    handled_vulnerability_ids: set[str] | None = None,
    tmrescore_project_cache: dict[str, dict[str, Any]] | None = None,
    result_store: Any = None,
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> int:
    plan = build_auto_analysis_queue_plan(
        grouped_vulns=grouped_vulns,
        team_mapping=team_mapping,
        enabled=enabled,
        submitted_by=submitted_by,
        handled_vulnerability_ids=handled_vulnerability_ids,
        tmrescore_project_cache=tmrescore_project_cache,
        result_store=result_store,
        auto_analysis_guidance=auto_analysis_guidance,
    )
    return apply_auto_analysis_queue_plan(
        analysis_queue=analysis_queue,
        plan=plan,
        logger=logger,
    )


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


def _collect_cached_grouped_batches(
    deps: AutoAnalysisSweepDeps,
    team_mapping: dict[str, Any],
) -> tuple[list[tuple[str, list[dict[str, Any]]]], set[str]]:
    projects = deps.cache_manager.get_cached_project_versions()
    if not projects:
        return [], set()

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

    return grouped_batches, handled_vulnerability_ids


def _build_queue_plans_from_grouped_batches(
    grouped_batches: list[tuple[str, list[dict[str, Any]]]],
    team_mapping: dict[str, Any],
    handled_vulnerability_ids: set[str],
    tmrescore_project_cache: dict[str, dict[str, Any]] | None = None,
    result_store: Any = None,
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> tuple[AutoAnalysisQueuePlan, ...]:
    return tuple(
        build_auto_analysis_queue_plan(
            grouped_vulns=grouped,
            team_mapping=team_mapping,
            enabled=True,
            handled_vulnerability_ids=handled_vulnerability_ids,
            tmrescore_project_cache=tmrescore_project_cache,
            result_store=result_store,
            auto_analysis_guidance=auto_analysis_guidance,
        )
        for _project_name, grouped in grouped_batches
    )


def build_cached_open_vulnerability_queue_plans(
    deps: AutoAnalysisSweepDeps,
    team_mapping: dict[str, Any],
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> tuple[AutoAnalysisQueuePlan, ...]:
    grouped_batches, handled_vulnerability_ids = _collect_cached_grouped_batches(
        deps,
        team_mapping,
    )
    return _build_queue_plans_from_grouped_batches(
        grouped_batches,
        team_mapping,
        handled_vulnerability_ids,
        deps.tmrescore_project_cache,
        deps.result_store,
        auto_analysis_guidance
        if auto_analysis_guidance is not None
        else deps.load_auto_analysis_guidance(),
    )


def queue_cached_open_vulnerabilities_for_analysis(
    deps: AutoAnalysisSweepDeps,
    team_mapping: dict[str, Any],
    auto_analysis_guidance: dict[str, Any] | None = None,
) -> int:
    grouped_batches, handled_vulnerability_ids = _collect_cached_grouped_batches(
        deps,
        team_mapping,
    )

    queued_total = 0
    guidance_config = (
        auto_analysis_guidance
        if auto_analysis_guidance is not None
        else deps.load_auto_analysis_guidance()
    )
    for project_name, grouped in grouped_batches:
        try:
            queued_total += deps.queue_grouped_vulnerabilities_for_analysis(
                grouped,
                team_mapping,
                handled_vulnerability_ids,
                guidance_config,
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis cached sweep failed for project %s",
                project_name,
            )

    return queued_total


async def _collect_live_grouped_batches(
    deps: AutoAnalysisSweepDeps,
    client: Any,
    team_mapping: dict[str, Any],
    *,
    yield_control: bool = False,
) -> tuple[list[tuple[str, list[dict[str, Any]]]], set[str]]:
    try:
        projects = await deps.cache_manager.get_projects(client, "")
    except Exception:
        deps.logger.exception(
            "Automatic code analysis sweep failed to fetch projects"
        )
        return [], set()

    if not projects:
        return [], set()

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
        if yield_control:
            await asyncio.sleep(0)
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
        if yield_control:
            await asyncio.sleep(0)

    return grouped_batches, handled_vulnerability_ids


async def build_existing_open_vulnerability_sweep_plan(
    deps: AutoAnalysisSweepDeps,
    client: Any,
) -> AutoAnalysisSweepPlan:
    team_mapping = deps.load_team_mapping()
    auto_analysis_guidance = deps.load_auto_analysis_guidance()
    queue_plans = list(
        build_cached_open_vulnerability_queue_plans(
            deps,
            team_mapping,
            auto_analysis_guidance,
        )
    )

    grouped_batches, handled_vulnerability_ids = await _collect_live_grouped_batches(
        deps,
        client,
        team_mapping,
    )
    queue_plans.extend(
        _build_queue_plans_from_grouped_batches(
            grouped_batches,
            team_mapping,
            handled_vulnerability_ids,
            deps.tmrescore_project_cache,
            deps.result_store,
            auto_analysis_guidance,
        )
    )

    return AutoAnalysisSweepPlan(queue_plans=tuple(queue_plans))


async def queue_existing_open_vulnerabilities_for_analysis(
    deps: AutoAnalysisSweepDeps,
    client: Any,
) -> int:
    team_mapping = deps.load_team_mapping()
    auto_analysis_guidance = deps.load_auto_analysis_guidance()
    await asyncio.sleep(0)
    queued_total = queue_cached_open_vulnerabilities_for_analysis(
        deps,
        team_mapping,
        auto_analysis_guidance,
    )
    await asyncio.sleep(0)

    grouped_batches, handled_vulnerability_ids = await _collect_live_grouped_batches(
        deps,
        client,
        team_mapping,
        yield_control=True,
    )

    for project_name, grouped in grouped_batches:
        await asyncio.sleep(0)
        try:
            queued_total += deps.queue_grouped_vulnerabilities_for_analysis(
                grouped,
                team_mapping,
                handled_vulnerability_ids,
                auto_analysis_guidance,
            )
        except Exception:
            deps.logger.exception(
                "Automatic code analysis sweep failed for project %s",
                project_name,
            )
        await asyncio.sleep(0)

    return queued_total
