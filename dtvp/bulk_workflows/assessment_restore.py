from __future__ import annotations

from typing import Any

from ..assessment_restore_services import (
    ASSESSMENT_RESTORE_STATUS_RECOVERABLE,
    refresh_group_restore_metadata,
    restore_rescoring_tags_in_details,
    update_component_restore_metadata,
)
from .base import BulkWorkflowContext, BulkWorkflowPlugin


def selected_groups(
    groups: list[dict[str, Any]],
    group_ids: list[str] | None,
) -> list[dict[str, Any]]:
    if group_ids is None:
        return groups
    if not group_ids:
        return []
    wanted = {str(group_id) for group_id in group_ids}
    return [group for group in groups if str(group.get("id") or "") in wanted]


def iter_restore_components(
    groups: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    items: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for group in groups:
        refresh_group_restore_metadata(group)
        for affected_version in group.get("affected_versions") or []:
            for component in affected_version.get("components") or []:
                if not isinstance(component, dict):
                    continue
                candidate = update_component_restore_metadata(component)
                if candidate:
                    items.append((group, component, candidate))
    return items


def build_assessment_restore_preview(
    groups: list[dict[str, Any]],
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    selected = selected_groups(groups, group_ids)
    group_items: dict[str, dict[str, Any]] = {}
    totals = {
        "groups": 0,
        "findings": 0,
        "recoverable_findings": 0,
        "ambiguous_findings": 0,
        "no_history_findings": 0,
    }

    for group, component, candidate in iter_restore_components(selected):
        group_id = str(group.get("id") or "")
        if not group_id:
            continue
        item = group_items.setdefault(
            group_id,
            {
                "group_id": group_id,
                "title": group.get("title"),
                "severity": group.get("severity"),
                "status": group.get("assessment_restore_status"),
                "reason": candidate.get("reason"),
                "finding_count": 0,
                "recoverable_finding_count": 0,
                "findings": [],
            },
        )
        status = candidate.get("status")
        item["findings"].append(
            {
                "finding_uuid": component.get("finding_uuid"),
                "project_uuid": component.get("project_uuid"),
                "project_name": component.get("project_name"),
                "project_version": component.get("project_version"),
                "component_uuid": component.get("component_uuid"),
                "component_name": component.get("component_name"),
                "component_version": component.get("component_version"),
                "vulnerability_uuid": component.get("vulnerability_uuid"),
                "status": status,
                "reason": candidate.get("reason"),
                "current_score": candidate.get("current_score"),
                "restored_score": candidate.get("restored_score"),
                "restored_vector": candidate.get("restored_vector"),
                "candidate_vectors": candidate.get("candidate_vectors") or [],
                "source": candidate.get("source"),
            }
        )
        item["finding_count"] += 1
        totals["findings"] += 1
        if status == ASSESSMENT_RESTORE_STATUS_RECOVERABLE:
            item["recoverable_finding_count"] += 1
            totals["recoverable_findings"] += 1
        elif status == "ambiguous":
            totals["ambiguous_findings"] += 1
        elif status == "no_history":
            totals["no_history_findings"] += 1

    items = sorted(group_items.values(), key=lambda item: item["group_id"])
    totals["groups"] = len(items)
    return {"items": items, "summary": totals}


def build_assessment_restore_payloads(
    groups: list[dict[str, Any]],
    group_ids: list[str] | None = None,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    selected = selected_groups(groups, group_ids)
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {"not_recoverable": 0, "unchanged": 0, "missing_identity": 0}

    for _group, component, candidate in iter_restore_components(selected):
        if candidate.get("status") != ASSESSMENT_RESTORE_STATUS_RECOVERABLE:
            skipped["not_recoverable"] += 1
            continue
        restored_vector = candidate.get("restored_vector")
        if not restored_vector:
            skipped["not_recoverable"] += 1
            continue
        project_uuid = component.get("project_uuid")
        component_uuid = component.get("component_uuid")
        vulnerability_uuid = component.get("vulnerability_uuid")
        if not project_uuid or not component_uuid or not vulnerability_uuid:
            skipped["missing_identity"] += 1
            continue
        current_details = component.get("analysis_details") or ""
        restored_details = restore_rescoring_tags_in_details(
            current_details,
            restored_vector=str(restored_vector),
            restored_score=candidate.get("restored_score"),
        )
        if restored_details == current_details:
            skipped["unchanged"] += 1
            continue
        payload = {
            "project_uuid": project_uuid,
            "component_uuid": component_uuid,
            "vulnerability_uuid": vulnerability_uuid,
            "state": component.get("analysis_state") or "NOT_SET",
            "details": restored_details,
            "justification": component.get("justification"),
            "suppressed": bool(component.get("is_suppressed", False)),
        }
        payloads.append((component, payload))
    return payloads, skipped


def create_assessment_restore_workflow() -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="assessment-restore",
        label="Restore CVSS",
        description="Restore missing rescored vectors from Dependency-Track audit history.",
        preview_builder=lambda context: build_assessment_restore_preview(context.groups),
        payload_builder=lambda context, ids: build_assessment_restore_payloads(
            context.groups, ids
        ),
        selection_predicate=lambda item: int(item.get("recoverable_finding_count") or 0) > 0,
    )
