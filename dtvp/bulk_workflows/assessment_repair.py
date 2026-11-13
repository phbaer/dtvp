"""Combined assessment repair.

One bulk operation chains every safe, rule-based repair. Each stage works on
the result of the previous one, so a finding receives a single write:

1. restore a rescored CVSS vector that was lost and is recoverable from audit
   history;
2. synchronize a consistent assessment to findings that lack it, move
   assessments of teams that no longer own the vulnerability into the global
   assessment, and combine conflicts that involve no current team;
3. repair missing, incomplete, or incorrect rule-based CVSS rescores.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from ..grouped_vuln_services import _normalize_group_tags
from ..logic import STATE_PRIORITY, calculate_aggregated_state
from ..rescore_rule_services import (
    RescoreRuleError,
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
)
from ..ssvc_services import preserve_record as preserve_ssvc_record
from ..ssvc_services import strip_details as strip_ssvc_details
from .assessment_restore import (
    build_assessment_restore_payloads,
    build_assessment_restore_preview,
    selected_groups,
)
from .base import BulkWorkflowContext, BulkWorkflowPlugin
from .incomplete_sync import (
    HEADER_RE,
    _instances,
    _parse_blocks,
    _render_block,
    _sync_group,
    _team_key,
)


Payload = tuple[dict[str, Any], dict[str, Any]]

REPAIR_RESTORE_CVSS = "restore_cvss"
REPAIR_SYNC_FINDINGS = "sync_findings"
REPAIR_FORMER_TEAMS = "former_teams"
REPAIR_REFER_TEAMS = "refer_teams"
REPAIR_COMBINE_CONFLICT = "combine_conflict"
REPAIR_RESCORING = "rescoring"

SEE_GLOBAL_ASSESSMENT = "See global assessment."
FORMER_TEAM_NOTE = "Former team assessment"
_PENDING_RE = re.compile(r"\[Status: Pending Review\]", re.I)
_IDENTITY_KEYS = ("project_uuid", "component_uuid", "vulnerability_uuid")


def _details(instance: dict[str, Any]) -> str:
    return str(instance.get("analysis_details") or instance.get("analysisDetails") or "")


def _state(instance: dict[str, Any]) -> str:
    return str(instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET")


def _lifecycle(group: dict[str, Any]) -> str:
    return str((group.get("list_metadata") or {}).get("lifecycle") or "").upper()


def _is_historical(block: dict[str, Any]) -> bool:
    return block["tags"].get("Historical", "").casefold() == "yes"


def _is_assessed(block: dict[str, Any]) -> bool:
    return not _is_historical(block) and block["tags"].get("State", "NOT_SET") != "NOT_SET"


def _header_value(value: Any) -> str:
    return re.sub(r"[\r\n\[\]]+", " ", str(value or "")).strip()


def _current_teams(group: dict[str, Any], team_mapping: dict[str, Any]) -> dict[str, str]:
    return {
        _team_key(team): team
        for team in _normalize_group_tags(group.get("tags") or [], team_mapping)
        if _team_key(team) != "unassigned"
    }


def _normalized(text: str) -> str:
    return " ".join(text.split()).casefold()


def _former_team_note(blocks: list[dict[str, Any]], existing: str = "") -> str:
    """Deduplicated record of the removed blocks, kept as plain text.

    A rationale is written once however many teams or decisions share it, and
    not at all when the global assessment (`existing`) already contains it;
    who decided what is always kept.
    """
    by_text: dict[str, dict[str, Any]] = {}
    for block in blocks:
        tags = block["tags"]
        text = strip_ssvc_details(block["details"]).strip()
        entry = by_text.setdefault(_normalized(text), {"text": text, "decisions": {}})
        decision = entry["decisions"].setdefault(
            (tags.get("State", ""), tags.get("Justification", "")),
            {"teams": [], "assessors": []},
        )
        for target, value in (("teams", block["team"]), ("assessors", tags.get("Assessed By"))):
            value = _header_value(value)
            if value and value not in decision[target]:
                decision[target].append(value)

    known = _normalized(strip_ssvc_details(existing))
    notes = []
    for key, entry in by_text.items():
        decisions = []
        for (state, justification), decision in entry["decisions"].items():
            facts = [", ".join(decision["teams"]), state]
            if justification and justification != "NOT_SET":
                facts.append(f"justification {justification}")
            if decision["assessors"]:
                facts.append(f"assessed by {', '.join(decision['assessors'])}")
            decisions.append("; ".join(facts))
        if key in known and all(_normalized(decision) in known for decision in decisions):
            # Both the rationale and who decided it are recorded already.
            continue
        note = f"{FORMER_TEAM_NOTE} ({' | '.join(decisions)})"
        if not key:
            note += "."
        elif key in known:
            note += ": rationale already part of this assessment."
        else:
            note += f":\n{entry['text']}"
        if _normalized(note) not in known:
            notes.append(note)
            known += " " + _normalized(note)
    return "\n\n".join(notes)


def _repair_former_teams(
    blocks: list[dict[str, Any]],
    current: dict[str, str],
    team_mapping: dict[str, Any],
    *,
    user: str,
    pending: bool,
    now_ms: int,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Move assessments of teams that no longer own the group into General.

    The former teams' text is always preserved in the global assessment. It
    only becomes the global *decision* when a current team has no assessment
    of its own; otherwise the current teams' decisions keep deciding. Teams
    without an assessment refer to the global one once that is approved,
    also when there is no former team at all.
    """
    if not current:
        # Unknown ownership is not the same as no ownership.
        return blocks, None

    def canonical_key(team: str) -> str:
        return _team_key((_normalize_group_tags([team], team_mapping) or [team])[0])

    def is_general(block: dict[str, Any]) -> bool:
        return _team_key(block["team"]) == "general"

    former = [
        block
        for block in blocks
        if not is_general(block) and _is_assessed(block) and canonical_key(block["team"]) not in current
    ]
    former_ids = {id(block) for block in former}
    remaining = [block for block in blocks if id(block) not in former_ids]
    covered = {
        canonical_key(block["team"])
        for block in remaining
        if not is_general(block) and _is_assessed(block)
    }
    uncovered = [team for key, team in current.items() if key not in covered]

    general = next((block for block in remaining if is_general(block)), None)
    if not former and (
        pending
        or not uncovered
        or general is None
        or general["tags"].get("State", "NOT_SET") == "NOT_SET"
    ):
        # Without former teams the only repair is pointing teams that have no
        # assessment at a global decision that is already approved.
        return blocks, None
    if general is None:
        general = {
            "team": "General",
            "tags": {"Team": "General", "State": "NOT_SET", "Assessed By": user, "Justification": "NOT_SET"},
            "details": "",
        }
        remaining.insert(0, general)
    else:
        replacement = {**general, "tags": dict(general["tags"])}
        remaining[remaining.index(general)] = replacement
        general = replacement

    promoted = False
    if uncovered and general["tags"].get("State", "NOT_SET") == "NOT_SET":
        decisive = min(former, key=lambda block: STATE_PRIORITY.get(block["tags"].get("State"), 10))
        general["tags"].update(
            {
                "State": decisive["tags"]["State"],
                "Assessed By": user,
                "Date": str(now_ms),
                "Justification": decisive["tags"].get("Justification", "NOT_SET"),
            }
        )
        for tag in ("Rescored", "Rescored Vector"):
            if decisive["tags"].get(tag) and not general["tags"].get(tag):
                general["tags"][tag] = decisive["tags"][tag]
        promoted = True
    existing = str(general.get("details") or "").strip()
    general["details"] = "\n\n".join(
        part for part in (existing, _former_team_note(former, existing)) if part
    )

    referred: list[str] = []
    general_state = general["tags"].get("State", "NOT_SET")
    if uncovered and general_state != "NOT_SET" and not pending:
        for team in uncovered:
            reference = {
                "team": team,
                "tags": {
                    "Team": team,
                    "State": general_state,
                    "Assessed By": user,
                    "Date": str(now_ms),
                    "Justification": general["tags"].get("Justification", "NOT_SET"),
                },
                "details": SEE_GLOBAL_ASSESSMENT,
            }
            placeholder = next(
                (
                    block
                    for block in remaining
                    if not _is_historical(block) and canonical_key(block["team"]) == _team_key(team)
                ),
                None,
            )
            if placeholder is not None:
                remaining[remaining.index(placeholder)] = reference
            else:
                remaining.append(reference)
            referred.append(team)

    return remaining, {
        "former_teams": sorted({block["team"] for block in former}, key=str.casefold),
        "promoted_to_global_decision": promoted,
        "referred_teams": referred,
        "open_teams": [team for team in uncovered if team not in referred],
    }


def _combine_conflict(
    instances: list[dict[str, Any]],
    current: dict[str, str],
    team_mapping: dict[str, Any],
    *,
    user: str,
    now_ms: int,
) -> tuple[str, dict[str, Any]] | None:
    """Merge conflicting former-team and global assessments into one global.

    Only when no current team has an assessment of its own: then nothing a
    responsible team decided is overruled. The worst state wins. Sources that
    disagree on the state produce a new decision, which stays pending review.
    """
    if not current:
        return None

    def canonical_key(team: str) -> str:
        return _team_key((_normalize_group_tags([team], team_mapping) or [team])[0])

    generals: list[dict[str, Any]] = []
    former: list[dict[str, Any]] = []
    historical: dict[str, dict[str, Any]] = {}
    for instance in instances:
        for block in _parse_blocks(_details(instance)):
            if _is_historical(block):
                historical.setdefault(_render_block(block), block)
            elif not _is_assessed(block):
                continue
            elif _team_key(block["team"]) == "general":
                generals.append(block)
            elif canonical_key(block["team"]) in current:
                return None
            else:
                former.append(block)
    sources = generals + former
    if not sources:
        return None

    decisive = min(sources, key=lambda block: STATE_PRIORITY.get(block["tags"].get("State"), 10))
    disagreement = len({block["tags"]["State"] for block in sources}) > 1
    pending = disagreement or any(_PENDING_RE.search(_details(instance)) for instance in instances)

    tags = dict(generals[0]["tags"]) if generals else {}
    for tag in ("Rescored", "Rescored Vector", "Reviewed By"):
        tags.pop(tag, None)
    tags.update(
        {
            "Team": "General",
            "State": decisive["tags"]["State"],
            "Assessed By": user,
            "Date": str(now_ms),
            "Justification": decisive["tags"].get("Justification", "NOT_SET"),
        }
    )
    for tag in ("Rescored", "Rescored Vector"):
        if decisive["tags"].get(tag):
            tags[tag] = decisive["tags"][tag]

    texts: dict[str, str] = {}
    for block in generals:
        text = strip_ssvc_details(block["details"]).strip()
        if text:
            texts.setdefault(_normalized(text), text)
    general = {
        "team": "General",
        "tags": tags,
        "details": "\n\n".join(
            part
            for part in (*texts.values(), _former_team_note(former, "\n\n".join(texts.values())))
            if part
        ),
    }

    referred = [] if pending else list(current.values())
    references = [
        {
            "team": team,
            "tags": {
                "Team": team,
                "State": tags["State"],
                "Assessed By": user,
                "Date": str(now_ms),
                "Justification": tags["Justification"],
            },
            "details": SEE_GLOBAL_ASSESSMENT,
        }
        for team in referred
    ]
    details = _render([general, *historical.values(), *references], pending=pending)
    return details, {
        "state": tags["State"],
        "former_teams": sorted({block["team"] for block in former}, key=str.casefold),
        "had_global": bool(generals),
        "disagreement": disagreement,
        "referred_teams": referred,
        "open_teams": [] if referred else list(current.values()),
    }


def _render(blocks: list[dict[str, Any]], *, preamble: str = "", pending: bool) -> str:
    parts = [preamble.strip(), *(_render_block(block) for block in blocks)]
    if pending:
        parts.append("[Status: Pending Review]")
    return "\n\n".join(part for part in parts if part)


def _payload(instance: dict[str, Any], state: str, details: str) -> dict[str, Any]:
    return {
        "project_uuid": instance["project_uuid"],
        "component_uuid": instance["component_uuid"],
        "vulnerability_uuid": instance["vulnerability_uuid"],
        "state": state,
        "details": details,
        "justification": instance.get("justification"),
        "suppressed": bool(instance.get("is_suppressed", False)),
    }


def _team_stage(
    groups: list[dict[str, Any]],
    context: BulkWorkflowContext,
    now_ms: int,
) -> tuple[list[Payload], dict[str, dict[str, Any]], int]:
    """Synchronize incomplete groups and move former-team assessments."""
    payloads: list[Payload] = []
    info: dict[str, dict[str, Any]] = {}
    missing_identity = 0
    for group in groups:
        lifecycle = _lifecycle(group)
        group_id = str(group.get("id") or "")
        current = _current_teams(group, context.team_mapping)
        instances = _instances(group)
        targets: list[tuple[dict[str, Any], str]] = []
        former: dict[str, Any] | None = None
        conflict: dict[str, Any] | None = None
        synchronized = 0

        if lifecycle == "INCONSISTENT":
            # A conflict between current teams needs a human decision. One
            # that only involves former teams and the global assessment can
            # be combined without overruling anyone responsible.
            combined = _combine_conflict(
                instances, current, context.team_mapping, user=context.user, now_ms=now_ms
            )
            if combined is None:
                continue
            merged, conflict = combined
            for instance in instances:
                old = _details(instance)
                details = preserve_ssvc_record(merged, old)
                if details != old or calculate_aggregated_state(details) != _state(instance):
                    targets.append((instance, details))
            if not targets:
                continue
        elif lifecycle == "INCOMPLETE":
            pending = any(_PENDING_RE.search(_details(instance)) for instance in instances)
            sync_blocks = _parse_blocks(_sync_group(group)["target_details"])
            sync_only = _render(sync_blocks, pending=pending)
            blocks, former = _repair_former_teams(
                sync_blocks,
                current,
                context.team_mapping,
                user=context.user,
                pending=pending,
                now_ms=now_ms,
            )
            merged = _render(blocks, pending=pending)
            for instance in instances:
                old = _details(instance)
                details = preserve_ssvc_record(merged, old)
                if details != old or calculate_aggregated_state(details) != _state(instance):
                    targets.append((instance, details))
                synced = preserve_ssvc_record(sync_only, old)
                if synced != old or calculate_aggregated_state(synced) != _state(instance):
                    synchronized += 1
        else:
            for instance in instances:
                old = _details(instance)
                pending = bool(_PENDING_RE.search(old))
                blocks, result = _repair_former_teams(
                    _parse_blocks(old),
                    current,
                    context.team_mapping,
                    user=context.user,
                    pending=pending,
                    now_ms=now_ms,
                )
                if result is None:
                    continue
                first_header = HEADER_RE.search(old)
                details = _render(
                    blocks,
                    preamble=old[: first_header.start()] if first_header else "",
                    pending=pending,
                )
                targets.append((instance, preserve_ssvc_record(details, old)))
                if former is None:
                    former = {**result}
                else:
                    for key in ("former_teams", "referred_teams", "open_teams"):
                        former[key] = sorted({*former[key], *result[key]}, key=str.casefold)
                    former["promoted_to_global_decision"] |= result["promoted_to_global_decision"]

        for instance, details in targets:
            if not all(instance.get(key) for key in _IDENTITY_KEYS):
                missing_identity += 1
                continue
            payloads.append((instance, _payload(instance, calculate_aggregated_state(details), details)))
        if synchronized or former or conflict:
            info[group_id] = {"synchronized": synchronized, "former": former, "conflict": conflict}
    return payloads, info, missing_identity


def _apply_payloads(
    groups: list[dict[str, Any]],
    payloads: list[Payload],
    origin: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Copy the groups with the payloads applied, for the next stage to read."""
    updates = {id(instance): payload for instance, payload in payloads}
    if not updates:
        return groups
    result = []
    for group in groups:
        versions = []
        for version in group.get("affected_versions") or []:
            components = []
            for component in version.get("components") or []:
                payload = updates.get(id(component)) if isinstance(component, dict) else None
                if payload is None:
                    components.append(component)
                    continue
                updated = {
                    key: value
                    for key, value in component.items()
                    if key not in {"analysisState", "analysisDetails"}
                }
                updated["analysis_state"] = payload["state"]
                updated["analysis_details"] = payload["details"]
                origin[id(updated)] = origin.get(id(component), component)
                components.append(updated)
            versions.append({**version, "components": components})
        result.append({**group, "affected_versions": versions})
    return result


def _run(
    context: BulkWorkflowContext,
    group_ids: list[str] | None,
    load_rules: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    groups = selected_groups(context.groups, group_ids)
    # Stages read copies; `origin` maps every copy back to the stored finding
    # and `keep_alive` pins the copies so their ids stay unique.
    origin: dict[int, dict[str, Any]] = {}
    keep_alive: list[list[dict[str, Any]]] = [groups]
    final: dict[int, Payload] = {}
    skipped: dict[str, int] = {}
    notes: list[str] = []

    def record(payloads: list[Payload], stage_skipped: dict[str, int]) -> None:
        for instance, payload in payloads:
            original = origin.get(id(instance), instance)
            final[id(original)] = (original, payload)
        for reason, count in stage_skipped.items():
            if count:
                skipped[reason] = skipped.get(reason, 0) + count
        keep_alive.append(_apply_payloads(keep_alive[-1], payloads, origin))

    restore_preview = build_assessment_restore_preview(groups)
    record(*build_assessment_restore_payloads(groups))

    team_payloads, team_info, missing_identity = _team_stage(
        keep_alive[-1], context, int(time.time() * 1000)
    )
    record(team_payloads, {"missing_identity": missing_identity})

    rescore_preview: dict[str, Any] = {"items": []}
    try:
        rules = load_rules()
        rescore_preview = build_rescore_rule_sync_preview(keep_alive[-1], rules)
        record(*build_rescore_rule_sync_payloads(keep_alive[-1], rules))
    except RescoreRuleError as error:
        # Other repairs stay available; say why rescoring was left out.
        notes.append(f"Rescoring repair skipped: {error}")

    return {
        "groups": groups,
        "payloads": list(final.values()),
        "skipped": skipped,
        "notes": notes,
        "restore_items": {item["group_id"]: item for item in restore_preview["items"]},
        "team_info": team_info,
        "rescore_items": {item["group_id"]: item for item in rescore_preview["items"]},
    }


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _former_team_label(former: dict[str, Any]) -> str:
    if not former["former_teams"]:
        return f"Refer {', '.join(former['referred_teams'])} to the approved global assessment"
    teams = ", ".join(former["former_teams"])
    label = (
        f"Make former team assessment the global decision: {teams}"
        if former["promoted_to_global_decision"]
        else f"Move former team assessment to global notes: {teams}"
    )
    if former["referred_teams"]:
        label += f"; {', '.join(former['referred_teams'])} refer to global"
    if former["open_teams"]:
        label += f"; {', '.join(former['open_teams'])} still to assess"
    return label


def _conflict_label(conflict: dict[str, Any]) -> str:
    sources = []
    if conflict["former_teams"]:
        sources.append(f"former teams {', '.join(conflict['former_teams'])}")
    if conflict["had_global"]:
        sources.append("existing global assessment")
    label = (
        f"Combine conflicting assessments into one global decision "
        f"({conflict['state']}): {' and '.join(sources)}"
    )
    if conflict["referred_teams"]:
        label += f"; {', '.join(conflict['referred_teams'])} refer to global"
    else:
        reason = "sources disagree, " if conflict["disagreement"] else ""
        label += f"; {reason}pending review, {', '.join(conflict['open_teams'])} still to assess"
    return label


def _group_item(group: dict[str, Any], run: dict[str, Any], finding_count: int) -> dict[str, Any] | None:
    group_id = str(group.get("id") or "")
    repairs: list[dict[str, Any]] = []
    review: list[str] = []

    restore = run["restore_items"].get(group_id)
    if restore:
        recoverable = int(restore.get("recoverable_finding_count") or 0)
        if recoverable:
            repairs.append({
                "id": REPAIR_RESTORE_CVSS,
                "label": f"Restore CVSS vector on {_plural(recoverable, 'finding')}",
            })
        unresolved = int(restore.get("finding_count") or 0) - recoverable
        if unresolved:
            review.append(f"CVSS vector not recoverable on {_plural(unresolved, 'finding')}")

    team = run["team_info"].get(group_id) or {}
    if team.get("synchronized"):
        repairs.append({
            "id": REPAIR_SYNC_FINDINGS,
            "label": f"Synchronize assessment to {_plural(team['synchronized'], 'finding')}",
        })
    if team.get("former"):
        repairs.append({
            "id": REPAIR_FORMER_TEAMS if team["former"]["former_teams"] else REPAIR_REFER_TEAMS,
            "label": _former_team_label(team["former"]),
        })
    if team.get("conflict"):
        repairs.append({"id": REPAIR_COMBINE_CONFLICT, "label": _conflict_label(team["conflict"])})

    rescore = run["rescore_items"].get(group_id)
    if rescore:
        syncable = int(rescore.get("syncable_finding_count") or 0)
        if syncable:
            repairs.append({
                "id": REPAIR_RESCORING,
                "label": f"Repair rescoring on {_plural(syncable, 'finding')}",
            })
        manual = int(rescore.get("review_finding_count") or 0)
        if manual:
            review.append(f"Rescoring needs manual review on {_plural(manual, 'finding')}")

    if not repairs and not review:
        return None
    return {
        "group_id": group_id,
        "title": group.get("title"),
        "severity": group.get("severity"),
        "repairs": repairs,
        "review": review,
        "finding_count": finding_count,
        "repairable": finding_count > 0,
        "former_teams": (team.get("former") or team.get("conflict") or {}).get("former_teams", []),
        "rescore_findings": (rescore or {}).get("findings", []),
    }


def build_assessment_repair_preview(
    context: BulkWorkflowContext,
    load_rules: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    run = _run(context, None, load_rules)
    changed: dict[int, int] = {}
    owner = {id(instance): index for index, group in enumerate(run["groups"]) for instance in _instances(group)}
    for instance, _payload_ in run["payloads"]:
        index = owner.get(id(instance))
        if index is not None:
            changed[index] = changed.get(index, 0) + 1

    items = [
        item
        for index, group in enumerate(run["groups"])
        if (item := _group_item(group, run, changed.get(index, 0)))
    ]
    items.sort(key=lambda item: item["group_id"])
    summary: dict[str, Any] = {
        "groups": len(items),
        "repairable_groups": sum(item["repairable"] for item in items),
        "findings": sum(item["finding_count"] for item in items),
        "review_groups": sum(bool(item["review"]) for item in items),
    }
    for repair_id in (
        REPAIR_RESTORE_CVSS,
        REPAIR_SYNC_FINDINGS,
        REPAIR_FORMER_TEAMS,
        REPAIR_REFER_TEAMS,
        REPAIR_COMBINE_CONFLICT,
        REPAIR_RESCORING,
    ):
        summary[f"{repair_id}_groups"] = sum(
            any(repair["id"] == repair_id for repair in item["repairs"]) for item in items
        )
    return {"items": items, "summary": summary, "notes": run["notes"]}


def build_assessment_repair_payloads(
    context: BulkWorkflowContext,
    group_ids: list[str],
    load_rules: Callable[[], dict[str, Any]],
) -> tuple[list[Payload], dict[str, int]]:
    run = _run(context, group_ids, load_rules)
    return run["payloads"], run["skipped"]


def create_assessment_repair_workflow(
    load_rules: Callable[[], dict[str, Any]],
) -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="assessment-repair",
        label="Repair Assessments",
        description=(
            "Synchronize partial assessments, move assessments of former teams into "
            "the global assessment, restore lost CVSS vectors, and repair rule-based "
            "rescoring. Each vulnerability lists the repairs that apply."
        ),
        preview_builder=lambda context: build_assessment_repair_preview(context, load_rules),
        payload_builder=lambda context, ids: build_assessment_repair_payloads(context, ids, load_rules),
        selection_predicate=lambda item: bool(item.get("repairable")),
    )
