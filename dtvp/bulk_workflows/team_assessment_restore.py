"""Restore team assessments from a Dependency-Track export.

Reads the VDR a reviewer uploaded (``context.source``), matches its entries
to the findings in view, and adds every team block a finding has in no form
today as a historical block. No state, justification, suppression,
response, rescoring or pending marker changes. See docs/review-workflows.md.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..assessment_model import canonical_assessment_text
from ..logic import STATE_PRIORITY, calculate_aggregated_state
from ..team_assessment_restore_services import (
    MATCH_NAME_VERSION,
    MATCH_PROJECT_NAME_VERSION,
    SKIP_EMPTY,
    SKIP_GENERAL,
    SKIP_PRESENT,
    SKIP_REFERENCE,
    SOURCE_KIND_DEPENDENCY_TRACK_VDR,
    UNMATCHED_REASONS,
    RestoreSource,
    append_blocks,
    match_entries,
    missing_blocks,
    restored_block,
)
from .base import (
    CHANGED_SINCE_PREVIEW,
    BulkWorkflowContext,
    BulkWorkflowPlugin,
    guard_against_later_saves,
)

WORKFLOW_ID = "team-assessment-restore"
UNMATCHED_SAMPLE_LIMIT = 200
TEXT_EXCERPT_LENGTH = 300
UNMATCHED_NOTE = (
    "Entries can be unmatched because the finding is no longer reported or the "
    "current filters exclude it."
)
REVIEW_WORSE_STATE = "A restored assessment has a worse state than the finding today"
REVIEW_NO_ASSESSMENT = "The finding has no assessment today"
REVIEW_LOOSE_MATCH = "Matched by component name and version, or by project name and version"
NOTES_ONLY = "Notes only"


def _source(context: BulkWorkflowContext) -> RestoreSource:
    source = context.source
    if not isinstance(source, RestoreSource):
        raise ValueError("This workflow needs an uploaded Dependency-Track export")
    return source


def _state(instance: dict[str, Any]) -> str:
    return str(instance.get("analysis_state") or "NOT_SET")


def _group_state(group: dict[str, Any]) -> str:
    states = {
        _state(instance)
        for version in group.get("affected_versions") or []
        for instance in version.get("components") or []
        if isinstance(instance, dict)
    }
    assessed = states - {"NOT_SET"}
    if not assessed:
        return "NOT_SET"
    if len(assessed) == 1:
        return "INCOMPLETE" if "NOT_SET" in states else next(iter(assessed))
    return "INCONSISTENT"


def _day(moment: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(moment) / 1000, UTC).date().isoformat() if moment else None
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _plan(context: BulkWorkflowContext) -> dict[str, Any]:
    """Every finding that changes, per group, with the counts of the rest."""
    source = _source(context)
    matches, unmatched = match_entries(source, context.groups, context.team_mapping)
    skipped = {
        SKIP_PRESENT: 0, SKIP_EMPTY: 0, SKIP_REFERENCE: 0, SKIP_GENERAL: 0,
        "unreadable": 0, "state_would_change": 0,
    }
    groups: dict[str, dict[str, Any]] = {}
    for item in matches:
        instance = item.instance
        current = str(instance.get("analysis_details") or "")
        to_restore, report = missing_blocks(current, item.entry.blocks, context.team_mapping)
        for key in (SKIP_PRESENT, SKIP_EMPTY, SKIP_REFERENCE, SKIP_GENERAL):
            skipped[key] += report[key]
        group_id = str(item.group.get("id") or "")
        if not group_id:
            continue
        restored = [restored_block(block) for block in to_restore]
        details = append_blocks(current, restored)
        if restored:
            try:
                canonical_assessment_text(_state(instance), details, instance.get("is_suppressed"))
                unchanged = calculate_aggregated_state(details) == calculate_aggregated_state(current)
            except ValueError:
                skipped["unreadable"] += 1
                continue
            if not unchanged:
                # Defence in depth: historical blocks never count, but a
                # restore must not be able to change a state.
                skipped["state_would_change"] += 1
                continue
        if not restored and not report["notes"]:
            continue
        groups.setdefault(group_id, {"group": item.group, "findings": []})["findings"].append(
            {
                "match": item,
                "sources": to_restore,
                "restored": restored,
                "details": details,
                "notes": report["notes"],
            }
        )
    return {
        "source": source,
        "matches": matches,
        "unmatched": unmatched,
        "groups": groups,
        "skipped": skipped,
    }


def _review_reasons(finding: dict[str, Any]) -> list[str]:
    instance = finding["match"].instance
    current = _state(instance)
    reasons = []
    if any(
        STATE_PRIORITY.get(block["state"], 10) < STATE_PRIORITY.get(current, 10)
        for block in finding["restored"]
    ):
        reasons.append(REVIEW_WORSE_STATE)
    if current == "NOT_SET" and not str(instance.get("analysis_details") or "").strip():
        reasons.append(REVIEW_NO_ASSESSMENT)
    if finding["match"].match in (MATCH_NAME_VERSION, MATCH_PROJECT_NAME_VERSION):
        reasons.append(REVIEW_LOOSE_MATCH)
    return reasons


def build_team_assessment_restore_preview(context: BulkWorkflowContext) -> dict[str, Any]:
    plan = _plan(context)
    source: RestoreSource = plan["source"]
    items = []
    blocks_to_restore = 0
    for group_id, entry in sorted(plan["groups"].items()):
        # A vulnerability with notes only (a present team's lost ticket, say)
        # is listed too, so the reviewer sees them; it has nothing to apply
        # and cannot be selected.
        findings = [finding for finding in entry["findings"] if finding["restored"]]
        group = entry["group"]
        reasons: list[str] = []
        blocks = []
        notes = []
        for finding in entry["findings"]:
            instance = finding["match"].instance
            notes.extend(
                {**note, "component_name": instance.get("component_name"),
                 "project_version": instance.get("project_version")}
                for note in finding["notes"]
            )
        for finding in findings:
            instance = finding["match"].instance
            for reason in _review_reasons(finding):
                if reason not in reasons:
                    reasons.append(reason)
            for source_block, block in zip(finding["sources"], finding["restored"]):
                blocks.append({
                    "project_version": instance.get("project_version"),
                    "component_name": instance.get("component_name"),
                    "component_version": instance.get("component_version"),
                    "match": finding["match"].match,
                    "team": block["team"],
                    "state": block["state"],
                    "justification": block.get("justification"),
                    "assessed_by": block.get("assessed_by"),
                    "date": _day(block.get("assessed_at_ms")),
                    "ticket": block.get("ticket"),
                    "source_historical": bool(source_block.get("historical")),
                    "text_excerpt": str(block.get("details") or "")[:TEXT_EXCERPT_LENGTH],
                })
        blocks_to_restore += len(blocks)
        items.append({
            "group_id": group_id,
            "title": group.get("title"),
            "severity": group.get("severity"),
            "finding_count": len(findings),
            "restore_count": len(blocks),
            "current_state": _group_state(group),
            "status": NOTES_ONLY if not blocks else "Review first" if reasons else "Ready",
            "requires_review": bool(reasons),
            "review": reasons,
            "blocks": blocks,
            "notes": notes,
        })

    unmatched_counts = {reason: 0 for reason in UNMATCHED_REASONS}
    samples = []
    for item in plan["unmatched"]:
        unmatched_counts[item.reason] = unmatched_counts.get(item.reason, 0) + 1
        if len(samples) < UNMATCHED_SAMPLE_LIMIT:
            samples.append({
                "id": item.entry.vuln_id,
                "component_name": item.entry.component.get("name") or None,
                "component_version": item.entry.component.get("version") or None,
                "reason": item.reason,
            })
    summary = {
        "source": {
            key: value for key, value in source.summary().items()
            if key not in ("analyses", "no_team_blocks", "serial_number")
        },
        "entries": len(source.entries),
        "entries_with_blocks": sum(1 for entry in source.entries if entry.blocks),
        "analyses": source.analyses,
        "analyses_without_team_blocks": source.no_team_blocks,
        "matched_entries": len(plan["matches"]),
        "unmatched": unmatched_counts,
        "unmatched_samples": samples,
        "unmatched_note": UNMATCHED_NOTE,
        "blocks_to_restore": blocks_to_restore,
        "skipped": plan["skipped"],
        "groups": sum(1 for item in items if item["restore_count"]),
        "notes_only_groups": sum(1 for item in items if not item["restore_count"]),
        "notes": sum(len(item["notes"]) for item in items),
    }
    return {"items": items, "summary": summary}


def build_team_assessment_restore_payloads(
    context: BulkWorkflowContext,
    group_ids: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    plan = _plan(context)
    wanted = set(group_ids)
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {
        "missing_identity": 0,
        "unchanged": 0,
        "unreadable": plan["skipped"]["unreadable"],
        "state_would_change": plan["skipped"]["state_would_change"],
        CHANGED_SINCE_PREVIEW: 0,
    }
    for group_id, entry in plan["groups"].items():
        if group_id not in wanted:
            continue
        for finding in entry["findings"]:
            instance = finding["match"].instance
            if not finding["restored"]:
                skipped["unchanged"] += 1
                continue
            identity = {
                key: instance.get(key)
                for key in ("project_uuid", "component_uuid", "vulnerability_uuid")
            }
            if not all(identity.values()):
                skipped["missing_identity"] += 1
                continue
            current = str(instance.get("analysis_details") or "")
            if finding["details"] == current:
                skipped["unchanged"] += 1
                continue
            payloads.append((instance, {
                **identity,
                "state": _state(instance),
                "details": finding["details"],
                "justification": instance.get("justification"),
                "suppressed": bool(instance.get("is_suppressed", False)),
            }))
    return guard_against_later_saves(context, payloads, skipped), skipped


def create_team_assessment_restore_workflow() -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id=WORKFLOW_ID,
        label="Restore Team Assessments From Export",
        description=(
            "Adds team assessments a Dependency-Track export has and DTVP has in no "
            "form, as historical assessments. Changes no state."
        ),
        preview_builder=build_team_assessment_restore_preview,
        payload_builder=build_team_assessment_restore_payloads,
        # Notes-only rows have nothing to apply.
        selection_predicate=lambda item: bool(item.get("restore_count")),
        source_kind=SOURCE_KIND_DEPENDENCY_TRACK_VDR,
    )
