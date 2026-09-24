from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from ..grouped_vuln_services import _normalize_group_tags
from ..logic import calculate_aggregated_state
from ..ssvc_services import strip_details as strip_ssvc_details
from .assessment_restore import selected_groups
from .base import BulkWorkflowContext, BulkWorkflowPlugin
from .incomplete_sync import _instances, _parse_blocks, _team_key


_HEADER = re.compile(r"---\s*\[Team:\s*([^\]]+)\][^\r\n]*?---")


def _replace_source_header(details: str, source: str) -> str:
    def retire(match: re.Match[str]) -> str:
        header = match.group(0)
        if _team_key(match.group(1)) != _team_key(source):
            return header
        if re.search(r"\[Historical:\s*yes\]", header, re.I):
            return header
        return re.sub(r"\s*---$", " [Historical: yes] ---", header)

    return _HEADER.sub(retire, details)


def _header_value(value: Any) -> str:
    return re.sub(r"[\r\n\[\]]+", " ", str(value or "")).strip()


def team_takeover_component_options(groups: list[dict[str, Any]]) -> list[str]:
    """Actual mapped owner selectors in this task, not vulnerable library names."""
    return sorted({
        str(key).strip()
        for group in groups
        for instance in _instances(group)
        for key in instance.get("owner_mapping_keys") or []
        if str(key).strip()
    }, key=str.casefold)


def _candidate(group: dict[str, Any], context: BulkWorkflowContext) -> dict[str, Any] | None:
    source = context.takeover_from.strip()
    target = context.takeover_to.strip()
    component_keys = {_team_key(name) for name in context.takeover_components if _team_key(name)}
    if not source or not target or not component_keys or _team_key(source) == _team_key(target):
        return None
    canonical_source = _normalize_group_tags([source], context.team_mapping)
    if canonical_source and _team_key(canonical_source[0]) == _team_key(target):
        return None
    current_teams = _normalize_group_tags(group.get("tags") or [], context.team_mapping)
    owners = {_team_key(team) for team in current_teams}
    if _team_key(target) not in owners:
        return None

    findings = []
    source_signatures: set[str] = set()
    for instance in _instances(group):
        owner_keys = instance.get("owner_mapping_keys")
        scoped_keys = owner_keys if isinstance(owner_keys, list) else [instance.get("component_name")]
        if not any(_team_key(key) in component_keys for key in scoped_keys):
            continue
        blocks = _parse_blocks(str(instance.get("analysis_details") or ""))
        source_blocks = [
            block for block in blocks
            if _team_key(block["team"]) == _team_key(source)
            and block["tags"].get("Historical", "").casefold() != "yes"
            and block["tags"].get("State", "NOT_SET") != "NOT_SET"
        ]
        target_blocks = [block for block in blocks if _team_key(block["team"]) == _team_key(target)]
        approved_general = any(
            _team_key(block["team"]) == "general"
            and block["tags"].get("State", "NOT_SET") != "NOT_SET"
            and "[Status: Pending Review]" not in str(instance.get("analysis_details") or "")
            for block in blocks
        )
        finding_owners = {
            _team_key(team)
            for team in _normalize_group_tags(instance.get("tags") or [], context.team_mapping)
        }
        if _team_key(target) not in finding_owners:
            status = "target_not_responsible"
        elif _team_key(source) in finding_owners:
            status = "source_still_responsible"
        elif target_blocks:
            status = "target_exists"
        elif approved_general:
            status = "already_approved"
        elif len(source_blocks) != 1:
            status = "source_missing_or_ambiguous"
        elif not all(instance.get(key) for key in ("project_uuid", "component_uuid", "vulnerability_uuid")):
            status = "missing_identity"
        else:
            status = "ready"
            source_block = source_blocks[0]
            source_signatures.add("|".join([
                str(source_block["tags"].get("State") or ""),
                str(source_block["tags"].get("Justification") or ""),
                strip_ssvc_details(source_block["details"]).strip(),
            ]))
        findings.append({"instance": instance, "status": status, "source": source_blocks[0] if len(source_blocks) == 1 else None})

    if not findings or not any(finding["source"] for finding in findings):
        return None
    if len(source_signatures) > 1:
        for finding in findings:
            if finding["status"] == "ready":
                finding["status"] = "conflicting_source"
    ready = [finding for finding in findings if finding["status"] == "ready"]
    return {
        "group_id": str(group.get("id") or ""),
        "title": group.get("title"),
        "severity": group.get("severity"),
        "target_team": next(team for team in current_teams if _team_key(team) == _team_key(target)),
        "finding_count": len(findings),
        "components": sorted({str(finding["instance"].get("component_name") or "") for finding in findings}),
        "eligible_finding_count": len(ready),
        "skipped": {
            status: sum(finding["status"] == status for finding in findings)
            for status in sorted({finding["status"] for finding in findings if finding["status"] != "ready"})
        },
        "source_hash": hashlib.sha256(
            "\n".join(sorted(
                str(finding["instance"].get("finding_uuid") or "") + ":"
                + str(finding["instance"].get("tags") or "") + ":"
                + str(finding["instance"].get("analysis_details") or "")
                for finding in findings
            )).encode()
        ).hexdigest(),
        "_findings": findings,
    }


def build_team_takeover_preview(context: BulkWorkflowContext) -> dict[str, Any]:
    items = []
    skipped: dict[str, int] = {}
    for group in context.groups:
        candidate = _candidate(group, context)
        if candidate is None:
            continue
        items.append({key: value for key, value in candidate.items() if key != "_findings"})
        for reason, count in candidate["skipped"].items():
            skipped[reason] = skipped.get(reason, 0) + count
    return {
        "items": items,
        "summary": {
            "groups": len(items),
            "eligible_findings": sum(item["eligible_finding_count"] for item in items),
            **skipped,
        },
    }


def build_team_takeover_payloads(
    context: BulkWorkflowContext,
    group_ids: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    payloads = []
    skipped: dict[str, int] = {}
    for group in selected_groups(context.groups, group_ids):
        candidate = _candidate(group, context)
        if candidate is None:
            continue
        for finding in candidate["_findings"]:
            if finding["status"] != "ready":
                reason = finding["status"]
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            instance = finding["instance"]
            source = finding["source"]
            assert source is not None
            source_tags = source["tags"]
            source_details = strip_ssvc_details(source["details"]).strip()
            header = (
                f"--- [Team: {_header_value(candidate['target_team'])}]"
                f" [State: {_header_value(source_tags['State'])}]"
                f" [Assessed By: {_header_value(context.user)}]"
                f" [Date: {int(time.time() * 1000)}]"
                f" [Justification: {_header_value(source_tags.get('Justification', 'NOT_SET'))}]"
                f" [Copied From: {_header_value(source['team'])}] ---"
            )
            old_details = str(instance.get("analysis_details") or "")
            details = _replace_source_header(old_details, source["team"]).strip()
            details = re.sub(r"\s*\[Status: Pending Review\]\s*$", "", details, flags=re.I).strip()
            details = f"{details}\n\n{header}\n{source_details}\n\n[Status: Pending Review]".strip()
            payloads.append((
                instance,
                {
                    "project_uuid": instance["project_uuid"],
                    "component_uuid": instance["component_uuid"],
                    "vulnerability_uuid": instance["vulnerability_uuid"],
                    "state": calculate_aggregated_state(details),
                    "details": details,
                    "justification": instance.get("justification"),
                    "suppressed": bool(instance.get("is_suppressed", False)),
                },
            ))
    return payloads, skipped


def create_team_takeover_workflow() -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="team-takeover",
        label="Take over team assessments",
        description="Copy former-team decisions on selected components into missing current-team assessments.",
        preview_builder=build_team_takeover_preview,
        payload_builder=build_team_takeover_payloads,
        selection_predicate=lambda item: int(item.get("eligible_finding_count") or 0) > 0,
    )
