"""Synchronization of partial assessments; a stage of the combined repair."""

from __future__ import annotations

import re
from typing import Any

from ..assessment_model import agreed_response, preserve_response
from ..ssvc_services import preserve_record as preserve_ssvc_record
from ..logic import (
    STATE_PRIORITY,
    calculate_aggregated_state,
    historical_blocks_of,
    insert_assessment_blocks,
)
from .assessment_restore import selected_groups


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


def new_finding_ids(group: dict[str, Any]) -> set[int]:
    """The findings of ``group`` that a new project version added after the
    vulnerability was assessed, by ``id()``.

    Nothing is copied onto them without a choice (ADR 0003 decision 6, ADR
    0010 decision 7): Synchronize leaves them unassessed unless the reviewer
    includes them for that vulnerability.
    """
    # Imported here: grouped_vuln_services imports the workflows' base.
    from ..grouped_vuln_services import refresh_new_finding_flags

    refresh_new_finding_flags(group)
    return {
        id(instance) for instance in _instances(group) if instance.get("is_new_finding")
    }


def new_finding_places(
    group: dict[str, Any], instances: list[dict[str, Any]]
) -> list[str]:
    """Where new findings are, for the preview: "version (component@version)",
    each once, in order."""
    versions = {
        id(component): version.get("project_version")
        for version in (group.get("affected_versions") or [])
        for component in (version.get("components") or [])
        if isinstance(component, dict)
    }
    places: list[str] = []
    for instance in instances:
        version = (
            str(versions.get(id(instance)) or instance.get("project_version") or "").strip()
            or "(no version)"
        )
        name = str(instance.get("component_name") or "").strip()
        component_version = str(instance.get("component_version") or "").strip()
        component = f"{name}@{component_version}" if name and component_version else name
        place = f"{version} ({component})" if component else version
        if place not in places:
            places.append(place)
    return places


def _sync_target_details(change: dict[str, Any]) -> str:
    """The text Synchronize writes; a pending assessment stays pending."""
    target_details = change["target_details"]
    if target_details and any(
        re.search(r"\[Status: Pending Review\]", str(instance.get("analysis_details") or ""), re.I)
        for instance in change["instances"]
    ):
        target_details = f"{target_details}\n\n[Status: Pending Review]"
    return target_details


def _sync_changes(change: dict[str, Any], instance: dict[str, Any]) -> bool:
    """Whether synchronizing would change this finding."""
    old = instance.get("analysis_details") or instance.get("analysisDetails") or ""
    state = str(instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET")
    response = agreed_response(
        other.get("analysis_details") or other.get("analysisDetails") or ""
        for other in change["instances"]
    )
    new = _keep_finding_values(_sync_target_details(change), old, response)
    return new.strip() != str(old).strip() or state != change["target_state"]


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


def _is_historical_block(block: dict[str, Any]) -> bool:
    return str(block["tags"].get("Historical") or "").strip().casefold() == "yes"


_RESCORING_TAG_RE = re.compile(r"\[Rescored(?: Vector)?:\s*[^\]]+\]", re.I)


def with_own_records(merged: str, existing: str) -> str:
    """``merged``, the current blocks every finding of a vulnerability
    receives, with the historical blocks of this one finding added.

    A historical block is the record of one finding: a former team's
    assessment, or one restored from an export into one version. It stays on
    that finding and goes to no other.
    """
    return insert_assessment_blocks(merged, historical_blocks_of(existing))


def _with_own_rescoring(details: str, existing: str) -> str:
    """``details`` with the rescoring this finding stores ahead of its
    blocks, unless the synchronized text has one there already."""
    def lead(text: str) -> str:
        header = HEADER_RE.search(text or "")
        return (text or "")[: header.start()] if header else (text or "")

    own = " ".join(match.group(0) for match in _RESCORING_TAG_RE.finditer(lead(existing)))
    if not own or _RESCORING_TAG_RE.search(lead(details)):
        return details
    return f"{own}\n\n{details}" if details else own


def _keep_finding_values(details: str, existing: str, response: str | None) -> str:
    """The synchronized text with what each finding keeps of its own: its
    historical blocks, the rescoring stored ahead of its blocks, the SSVC
    record and the response. A finding without a response takes
    ``response``, the one the other findings agree on."""
    details = _with_own_rescoring(with_own_records(details, existing), existing)
    return preserve_response(
        preserve_ssvc_record(details, existing), existing, response
    )


def _sync_group(group: dict[str, Any]) -> dict[str, Any]:
    instances = _instances(group)
    blocks_by_team: dict[str, dict[str, Any]] = {}
    for instance in instances:
        for block in _parse_blocks(str(instance.get("analysis_details") or "")):
            if _is_historical_block(block):
                # A record of that one finding: it is neither a team's
                # current assessment nor copied to the other findings.
                continue
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
    items = []
    for group in candidates:
        item = _sync_group(group)
        new_ids = new_finding_ids(group)
        # New findings are listed, not synchronized, unless included; only
        # those that synchronizing would change.
        changing = [
            instance for instance in item["instances"]
            if id(instance) in new_ids and _sync_changes(item, instance)
        ]
        item["new_finding_count"] = len(changing)
        item["new_finding_places"] = new_finding_places(group, changing)
        item["finding_count"] -= len(new_ids)
        items.append(item)
    return {
        "items": items,
        "summary": {
            "groups": len(items),
            "findings": sum(item["finding_count"] for item in items),
            "new_findings": sum(item["new_finding_count"] for item in items),
        },
    }


def build_incomplete_sync_payloads(
    groups: list[dict[str, Any]],
    group_ids: list[str],
    include_new_findings: frozenset[str] | set[str] = frozenset(),
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    """``include_new_findings`` are the ids of the groups whose new findings
    the reviewer chose to synchronize as well."""
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {"not_incomplete": 0, "missing_identity": 0, "new_finding": 0}
    for group in selected_groups(groups, group_ids):
        if str((group.get("list_metadata") or {}).get("lifecycle") or "").upper() != "INCOMPLETE":
            skipped["not_incomplete"] += 1
            continue
        change = _sync_group(group)
        new = (
            set()
            if str(group.get("id") or "") in include_new_findings
            else new_finding_ids(group)
        )
        response = agreed_response(
            instance.get("analysis_details") or instance.get("analysisDetails") or ""
            for instance in change["instances"]
        )
        # Synchronizing is not approving: a pending assessment stays pending.
        target_details = _sync_target_details(change)
        for instance in change["instances"]:
            if id(instance) in new:
                skipped["new_finding"] += 1
                continue
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
                        "details": _keep_finding_values(
                            target_details,
                            instance.get("analysis_details") or instance.get("analysisDetails") or "",
                            response,
                        ),
                        "justification": instance.get("justification"),
                        "suppressed": False,
                    },
                )
            )
    return payloads, skipped

