from __future__ import annotations

import re
from typing import Any

from ..logic import STATE_PRIORITY, calculate_aggregated_state
from .assessment_restore import selected_groups
from .base import BulkWorkflowContext, BulkWorkflowPlugin


HEADER_RE = re.compile(r"---\s*(?P<header>(?:\[[^\]]+\]\s*)+)---")
TAG_RE = re.compile(r"\[([^:\]]+):\s*([^\]]*)\]")


def _team_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def _strip_generated_team_summary(details: str) -> str:
    paragraphs = re.split(r"\n\s*\n", str(details or "").strip())
    return "\n\n".join(
        paragraph.strip()
        for paragraph in paragraphs
        if paragraph.strip()
        and not paragraph.strip().casefold().startswith("team assessments:\n")
    )


def _instances(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for version in (group.get("affected_versions") or [])
        for component in (version.get("components") or [])
        if isinstance(component, dict)
    ]


def _parse_blocks(details: str) -> list[dict[str, Any]]:
    matches = list(HEADER_RE.finditer(details or ""))
    blocks: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        tags = {
            key.strip(): value.strip()
            for key, value in TAG_RE.findall(match.group("header"))
        }
        team = tags.get("Team")
        if not team:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(details)
        content = details[match.end() : end].strip()
        content = re.sub(r"\[Status: Pending Review\]", "", content, flags=re.I).strip()
        blocks.append({"tags": tags, "team": team, "details": content})
    return blocks


def _render_block(block: dict[str, Any]) -> str:
    tags = dict(block.get("tags") or {})
    ordered = ["Team", "State", "Assessed By", "Reviewed By", "Date", "Justification", "Assigned", "Evidence Reviewed", "Version Coverage", "Ticket", "Rescored", "Rescored Vector"]
    header_tags = []
    for key in ordered:
        value = tags.pop(key, None)
        if value not in (None, ""):
            header_tags.append(f"[{key}: {value}]")
    header_tags.extend(f"[{key}: {value}]" for key, value in tags.items() if value)
    details = str(block.get("details") or "").strip()
    return f"--- {' '.join(header_tags)} ---" + (f"\n{details}" if details else "")


def _sync_group(group: dict[str, Any]) -> dict[str, Any]:
    instances = _instances(group)
    blocks_by_team: dict[str, dict[str, Any]] = {}
    for instance in instances:
        for block in _parse_blocks(str(instance.get("analysis_details") or "")):
            team_key = _team_key(block["team"])
            existing = blocks_by_team.get(team_key)
            if existing is None or (
                existing["tags"].get("State", "NOT_SET") == "NOT_SET"
                and block["tags"].get("State", "NOT_SET") != "NOT_SET"
            ):
                blocks_by_team[team_key] = block

    states = [
        str(instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET")
        for instance in instances
    ]
    non_empty_states = [state for state in states if state != "NOT_SET"]
    target_state = (
        sorted(non_empty_states, key=lambda value: STATE_PRIORITY.get(value, 10))[0]
        if non_empty_states
        else "NOT_SET"
    )
    general = blocks_by_team.pop("general", None)
    final_blocks: list[dict[str, Any]] = []
    if general is not None:
        general_tags = dict(general.get("tags") or {})
        general_tags["Team"] = "General"
        general = {
            **general,
            "team": "General",
            "tags": general_tags,
            "details": _strip_generated_team_summary(general.get("details") or ""),
        }
        final_blocks.append(general)
    final_blocks.extend(blocks_by_team.values())

    if not final_blocks and target_state != "NOT_SET":
        final_blocks.append(
            {
                "tags": {
                    "Team": "General",
                    "State": target_state,
                    "Assessed By": "General",
                    "Justification": "NOT_SET",
                },
                "team": "General",
                "details": "",
            }
        )
    details = "\n\n".join(_render_block(block) for block in final_blocks)
    return {
        "group_id": str(group.get("id") or ""),
        "title": group.get("title"),
        "severity": group.get("severity"),
        "finding_count": len(instances),
        "block_count": len(final_blocks),
        "target_state": calculate_aggregated_state(details),
        "target_details": details,
        "instances": instances,
    }


def build_incomplete_sync_preview(groups: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [
        group
        for group in groups
        if str((group.get("list_metadata") or {}).get("lifecycle") or "").upper()
        == "INCOMPLETE"
    ]
    items = [_sync_group(group) for group in candidates]
    return {
        "items": items,
        "summary": {
            "groups": len(items),
            "findings": sum(item["finding_count"] for item in items),
        },
    }


def build_incomplete_sync_payloads(
    groups: list[dict[str, Any]],
    group_ids: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {"not_incomplete": 0, "missing_identity": 0}
    for group in selected_groups(groups, group_ids):
        if str((group.get("list_metadata") or {}).get("lifecycle") or "").upper() != "INCOMPLETE":
            skipped["not_incomplete"] += 1
            continue
        change = _sync_group(group)
        for instance in change["instances"]:
            if not all(instance.get(key) for key in ("project_uuid", "component_uuid", "vulnerability_uuid")):
                skipped["missing_identity"] += 1
                continue
            payloads.append(
                (
                    instance,
                    {
                        "project_uuid": instance["project_uuid"],
                        "component_uuid": instance["component_uuid"],
                        "vulnerability_uuid": instance["vulnerability_uuid"],
                        "state": change["target_state"],
                        "details": change["target_details"],
                        "justification": instance.get("justification"),
                        "suppressed": False,
                    },
                )
            )
    return payloads, skipped


def create_incomplete_sync_workflow() -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="incomplete-sync",
        label="Synchronize Incomplete",
        description="Synchronize consistent partial assessments across all matching findings.",
        preview_builder=lambda context: build_incomplete_sync_preview(context.groups),
        payload_builder=lambda context, ids: build_incomplete_sync_payloads(
            context.groups, ids
        ),
        version=2,
    )
