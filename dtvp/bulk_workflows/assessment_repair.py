"""Combined assessment repair.

One bulk operation chains every safe, rule-based repair. Each stage works on
the result of the previous one, so a finding receives a single write:

1. restore a rescored CVSS vector that was lost and is recoverable from audit
   history;
2. synchronize a consistent assessment to findings that lack it, keep
   assessments of teams that no longer own the vulnerability as historical
   blocks, and combine conflicts that involve no current team;
3. repair missing, incomplete, or incorrect rule-based CVSS rescores.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from ..assessment_model import (
    SEE_GLOBAL_ASSESSMENT,
    agreed_response,
    preserve_response,
    preserve_version_override,
)
from ..grouped_vuln_services import _normalize_group_tags
from ..logic import STATE_PRIORITY, calculate_aggregated_state
from ..rescore_rule_services import (
    RescoreRuleError,
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
)
from ..ssvc_services import preserve_record as preserve_ssvc_record
from ..ssvc_services import strip_details as strip_ssvc_details
from ..team_mapping import normalize_team_values
from .assessment_restore import (
    build_assessment_restore_payloads,
    build_assessment_restore_preview,
    selected_groups,
)
from .base import BulkWorkflowContext, BulkWorkflowPlugin
from .incomplete_sync import with_own_records
from .incomplete_sync import (
    HEADER_RE,
    _instances,
    _parse_blocks,
    _render_block,
    _sync_group,
    _team_key,
    new_finding_ids,
    new_finding_places,
)


Payload = tuple[dict[str, Any], dict[str, Any]]

REPAIR_RESTORE_CVSS = "restore_cvss"
REPAIR_RESTORE_TICKETS = "restore_tickets"
REPAIR_SYNC_FINDINGS = "sync_findings"
REPAIR_FORMER_TEAMS = "former_teams"
REPAIR_REFER_TEAMS = "refer_teams"
REPAIR_UNOWNED_REFERENCES = "unowned_references"
REPAIR_COMBINE_CONFLICT = "combine_conflict"
REPAIR_RESCORING = "rescoring"

# Short names for the per-topic selection buttons, in pipeline order.
REPAIR_TOPICS = {
    REPAIR_RESTORE_CVSS: "Restore CVSS",
    REPAIR_RESTORE_TICKETS: "Restore tickets",
    REPAIR_SYNC_FINDINGS: "Synchronize",
    REPAIR_FORMER_TEAMS: "Former teams",
    REPAIR_REFER_TEAMS: "Refer to global",
    REPAIR_UNOWNED_REFERENCES: "No-team references",
    REPAIR_COMBINE_CONFLICT: "Combine conflicts",
    REPAIR_RESCORING: "Rescoring",
}

_PENDING_RE = re.compile(r"\[Status: Pending Review\]", re.I)
_IDENTITY_KEYS = ("project_uuid", "component_uuid", "vulnerability_uuid")
_RESCORED_RE = re.compile(r"\[Rescored:\s*([\d.]+)\]")
_RESCORED_VECTOR_RE = re.compile(r"\[Rescored Vector:\s*[^\]]+\]")


def _details(instance: dict[str, Any]) -> str:
    return str(instance.get("analysis_details") or instance.get("analysisDetails") or "")


def _state(instance: dict[str, Any]) -> str:
    return str(instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET")


def _lifecycle(group: dict[str, Any]) -> str:
    return str((group.get("list_metadata") or {}).get("lifecycle") or "").upper()


def _copied_date(
    decisive: dict[str, Any], sources: list[dict[str, Any]], now_ms: int
) -> str:
    """The date of the assessment a General decision is taken from.

    The repair copies a decision; it does not make one. The date stays that
    of the assessment that decides, else the latest among those it is taken
    from. Only when none of them has a date is it the moment of the repair.
    """
    def date_of(block: dict[str, Any]) -> int:
        value = str(block["tags"].get("Date") or "").strip()
        return int(value) if value.isdigit() else 0

    return str(
        date_of(decisive)
        or max((date_of(block) for block in sources), default=0)
        or now_ms
    )


def _is_historical(block: dict[str, Any]) -> bool:
    return block["tags"].get("Historical", "").casefold() == "yes"


def _is_assessed(block: dict[str, Any]) -> bool:
    return not _is_historical(block) and block["tags"].get("State", "NOT_SET") != "NOT_SET"


def _holds_something(block: dict[str, Any]) -> bool:
    """Whether a block says or tracks anything: a text, a ticket, assignees,
    evidence, version coverage or an SSVC decision. Such a block is never
    replaced or dropped, whatever its state."""
    return bool(
        strip_ssvc_details(block["details"]).strip()
        or any(
            str(block["tags"].get(tag) or "").strip()
            for tag in ("Ticket", "Assigned", "Evidence Reviewed", "Version Coverage", "SSVC")
        )
    )


def _header_value(value: Any) -> str:
    return re.sub(r"[\r\n\[\]]+", " ", str(value or "")).strip()


def _unowned_keys(team_mapping: dict[str, Any]) -> set[str]:
    """The names under which components that no team owns are assessed."""
    return {"unassigned", *(_team_key(name) for name in normalize_team_values(team_mapping.get("*")))}


def _is_reference(block: dict[str, Any]) -> bool:
    return _normalized(strip_ssvc_details(block["details"])) == _normalized(SEE_GLOBAL_ASSESSMENT)


def _current_teams(group: dict[str, Any], team_mapping: dict[str, Any]) -> dict[str, str]:
    # The name the mapping gives to components no team owns is not a team:
    # nobody is there to refer to the global assessment.
    unowned = _unowned_keys(team_mapping)
    return {
        _team_key(team): team
        for team in _normalize_group_tags(group.get("tags") or [], team_mapping)
        if _team_key(team) not in unowned
    }


def _normalized(text: str) -> str:
    return " ".join(text.split()).casefold()


def _ticket_keys(value: Any) -> list[str]:
    """The ticket keys of a ``Ticket`` tag, which may list several."""
    return list(dict.fromkeys(
        key for key in (part.strip() for part in str(value or "").split(",")) if key
    ))


def _carry_tickets(target: dict[str, Any], sources: list[dict[str, Any]]) -> None:
    """Keep the tickets of blocks that are removed on the block that stays.

    A ticket tracks the vulnerability in the product, whoever owned the
    component when it was opened.
    """
    keys = _ticket_keys(target["tags"].get("Ticket"))
    for block in sources:
        keys += [key for key in _ticket_keys(block["tags"].get("Ticket")) if key not in keys]
    if keys:
        target["tags"]["Ticket"] = ", ".join(keys)


def _as_historical(block: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``block`` that no longer counts, with every tag it has."""
    return {**block, "tags": {**block["tags"], "Historical": "yes"}}


def _same_justification(left: Any, right: Any) -> bool:
    def norm(value: Any) -> str:
        return "" if value in (None, "", "NOT_SET") else str(value)

    return norm(left) == norm(right)


def _decisive_rationale(
    decisive: dict[str, Any], former: list[dict[str, Any]]
) -> list[str]:
    """The texts of the former blocks that made the decision General takes:
    same state and justification as ``decisive``, references left out,
    each text once, in block order."""
    state = decisive["tags"].get("State")
    justification = decisive["tags"].get("Justification")
    texts: dict[str, str] = {}
    for block in former:
        if (
            block["tags"].get("State") != state
            or not _same_justification(block["tags"].get("Justification"), justification)
            or _is_reference(block)
        ):
            continue
        text = strip_ssvc_details(block["details"]).strip()
        if text:
            texts.setdefault(_normalized(text), text)
    return list(texts.values())


def _with_rationale(existing: str, texts: list[str]) -> str:
    """``existing`` followed by those of ``texts`` it does not contain yet."""
    parts = [existing] if existing else []
    known = _normalized(existing)
    for text in texts:
        if _normalized(text) not in known:
            parts.append(text)
            known += " " + _normalized(text)
    return "\n\n".join(parts)


def _repair_former_teams(
    blocks: list[dict[str, Any]],
    current: dict[str, str],
    team_mapping: dict[str, Any],
    *,
    user: str,
    pending: bool,
    now_ms: int,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Keep assessments of teams that no longer own the group as historical.

    A former team's block stays with every tag, its ticket and its text, as
    ``[Historical: yes]``: it no longer counts toward state or coverage. Its
    decision only becomes the global *decision* when a current team has no
    assessment of its own and General has none; General then takes the state,
    justification and date, and a copy of the rationale. Teams without an
    assessment refer to the global one once that is approved, also when
    there is no former team at all.
    """
    # An assessment under the name for components no team owns is that of a
    # person for such a component, not a former team's: it stays. Only a
    # reference to the global assessment under that name says nothing, and
    # nobody stands behind it.
    unowned = _unowned_keys(team_mapping)
    stale = [
        block for block in blocks
        if _team_key(block["team"]) in unowned and _is_assessed(block) and _is_reference(block)
    ]
    if stale:
        stale_ids = {id(block) for block in stale}
        blocks = [block for block in blocks if id(block) not in stale_ids]
    removed = sorted({block["team"] for block in stale}, key=str.casefold)
    nothing = (blocks, {
        "former_teams": [], "promoted_to_global_decision": False,
        "referred_teams": [], "open_teams": [], "removed_references": removed,
    }) if stale else (blocks, None)

    if not current:
        # Unknown ownership is not the same as no ownership.
        return nothing

    def canonical_key(team: str) -> str:
        return _team_key((_normalize_group_tags([team], team_mapping) or [team])[0])

    def is_general(block: dict[str, Any]) -> bool:
        return _team_key(block["team"]) == "general"

    former = [
        block
        for block in blocks
        if not is_general(block) and _is_assessed(block)
        and canonical_key(block["team"]) not in current
        and _team_key(block["team"]) not in unowned
    ]
    former_ids = {id(block) for block in former}
    remaining = [
        _as_historical(block) if id(block) in former_ids else block for block in blocks
    ]
    covered = {
        canonical_key(block["team"])
        for block in remaining
        if not is_general(block) and _is_assessed(block)
    }
    uncovered = [team for key, team in current.items() if key not in covered]

    general = next(
        (block for block in remaining if is_general(block) and not _is_historical(block)),
        None,
    )
    if not former and (
        pending
        or not uncovered
        or general is None
        or general["tags"].get("State", "NOT_SET") == "NOT_SET"
    ):
        # Without former teams the only repair is pointing teams that have no
        # assessment at a global decision that is already approved.
        return nothing

    promoted = bool(former) and bool(uncovered) and (
        general is None or general["tags"].get("State", "NOT_SET") == "NOT_SET"
    )
    if promoted:
        # Only a General block that decides is written; none is created just
        # to hold a note, the historical blocks are the record.
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
        decisive = min(former, key=lambda block: STATE_PRIORITY.get(block["tags"].get("State"), 10))
        general["tags"].update(
            {
                "State": decisive["tags"]["State"],
                "Assessed By": user,
                "Date": _copied_date(decisive, former, now_ms),
                "Justification": decisive["tags"].get("Justification", "NOT_SET"),
            }
        )
        for tag in ("Rescored", "Rescored Vector"):
            if decisive["tags"].get(tag) and not general["tags"].get(tag):
                general["tags"][tag] = decisive["tags"][tag]
        # The decision comes with its reasons, so that the global assessment
        # does not stand without a text.
        general["details"] = _with_rationale(
            str(general.get("details") or "").strip(),
            _decisive_rationale(decisive, former),
        )

    referred: list[str] = []
    general_state = (general or {}).get("tags", {}).get("State", "NOT_SET")
    historical_teams = {
        canonical_key(block["team"]) for block in remaining if _is_historical(block)
    }
    if uncovered and general_state != "NOT_SET" and not pending:
        for team in uncovered:
            if _team_key(team) in historical_teams:
                # Never two blocks for one team: the historical one stays,
                # the team is left to assess.
                continue
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
            if placeholder is not None and _holds_something(placeholder):
                # Someone is on it: its text, ticket and assignees stay,
                # and the team is left to assess.
                continue
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
        "removed_references": removed,
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

    Former teams' blocks stay as historical blocks, as do blocks that were
    historical already and General decisions the combined one replaces: one
    per distinct record (team, decision, text, assessor, reviewer, date,
    rescoring), with the tickets of the identical records it stands for. A
    team's block without a decision that holds a text, ticket or assignees
    stays as it is, and that team is not referred to the global assessment.
    """
    if not current:
        return None

    def canonical_key(team: str) -> str:
        return _team_key((_normalize_group_tags([team], team_mapping) or [team])[0])

    unowned = _unowned_keys(team_mapping)
    generals: list[dict[str, Any]] = []
    former: list[dict[str, Any]] = []
    historical: dict[str, dict[str, Any]] = {}
    # Blocks without a decision that still say or track something: kept.
    held: dict[str, dict[str, Any]] = {}
    for instance in instances:
        for block in _parse_blocks(_details(instance)):
            if _is_historical(block):
                historical.setdefault(_render_block(block), block)
            elif not _is_assessed(block):
                if _holds_something(block):
                    held.setdefault(_render_block(block), block)
                continue
            elif _team_key(block["team"]) == "general":
                generals.append(block)
            elif canonical_key(block["team"]) in current:
                return None
            elif _team_key(block["team"]) in unowned:
                if not _is_reference(block):
                    # A person's assessment of a component no team owns
                    # is not a former team's: a human decides.
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
            "Date": _copied_date(decisive, sources, now_ms),
            "Justification": decisive["tags"].get("Justification", "NOT_SET"),
        }
    )
    for tag in ("Rescored", "Rescored Vector"):
        if decisive["tags"].get(tag):
            tags[tag] = decisive["tags"][tag]

    carrier = {"tags": tags}
    _carry_tickets(carrier, generals)

    texts: dict[str, str] = {}
    for block in generals:
        text = strip_ssvc_details(block["details"]).strip()
        if text:
            texts.setdefault(_normalized(text), text)
    general_text = "\n\n".join(texts.values()) or _with_rationale(
        "", _decisive_rationale(decisive, former)
    )

    # Every record stays a historical block of its own, with its assessor,
    # date and tags: blocks that were historical already as they are, and
    # the former teams' blocks. Blocks that differ only in their tickets are
    # one record, with all the tickets.
    # A General decision the combined one replaces stays as a record, with
    # its state, assessor and date. So does a General block without a
    # decision that holds a text or ticket.
    def same_decision(block: dict[str, Any]) -> bool:
        return (
            block["tags"].get("State", "NOT_SET") == tags["State"]
            and _same_justification(block["tags"].get("Justification"), tags["Justification"])
            and str(block["tags"].get("Assessed By") or "") == str(tags["Assessed By"])
            and str(block["tags"].get("Date") or "") == str(tags["Date"])
        )

    replaced = [block for block in generals if not same_decision(block)]
    # Of a team's blocks without a decision, the newest stays as it is (one
    # block per team); any other one is kept as a record.
    open_blocks: dict[str, dict[str, Any]] = {}
    for block in held.values():
        key = canonical_key(block["team"])
        if key == "general":
            replaced.append(block)
            continue
        kept_open = open_blocks.get(key)
        if kept_open is None:
            open_blocks[key] = block
            continue

        def date_of(item: dict[str, Any]) -> int:
            value = str(item["tags"].get("Date") or "").strip()
            return int(value) if value.isdigit() else 0

        newer, older = (block, kept_open) if date_of(block) > date_of(kept_open) else (kept_open, block)
        open_blocks[key] = newer
        historical.setdefault(_render_block(_as_historical(older)), _as_historical(older))

    records: dict[str, dict[str, Any]] = {}
    for block in [
        *historical.values(),
        *(_as_historical(block) for block in replaced),
        *(_as_historical(block) for block in former),
    ]:
        identity = _render_block({**block, "tags": {**block["tags"], "Ticket": ""}})
        kept = records.get(identity)
        if kept is None:
            records[identity] = {**block, "tags": dict(block["tags"])}
        else:
            _carry_tickets(kept, [block])
    kept_blocks = list(records.values())
    general = {"team": "General", "tags": tags, "details": general_text}

    historical_teams = {
        canonical_key(block["team"])
        for block in kept_blocks
        if _team_key(block["team"]) != "general"
    } | set(open_blocks)
    referred = [] if pending else [
        team for key, team in current.items() if key not in historical_teams
    ]
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
    details = _render([general, *open_blocks.values(), *kept_blocks, *references], pending=pending)
    return details, {
        "state": tags["State"],
        "former_teams": sorted({block["team"] for block in former}, key=str.casefold),
        "had_global": bool(generals),
        "disagreement": disagreement,
        "referred_teams": referred,
        "open_teams": [team for team in current.values() if team not in referred],
    }


def _differs(details: str, old: str) -> bool:
    """Whether a rebuilt assessment changes more than its whitespace."""
    return details.split() != old.split()


def _rescoring_preamble(details: str) -> str:
    """Rescoring tags stored ahead of the first block, outside any block."""
    header = HEADER_RE.search(details)
    lead = details[: header.start()] if header else details
    tags = [
        match.group(0)
        for match in (_RESCORED_RE.search(lead), _RESCORED_VECTOR_RE.search(lead))
        if match
    ]
    return " ".join(tags)


def _with_rescoring(merged: str, instances: list[dict[str, Any]]) -> Callable[[str], str]:
    """Keep the rescoring a rebuilt assessment would otherwise lose.

    Rebuilding from blocks drops tags stored ahead of them. A finding keeps
    its own; one without takes the group's most severe complete rescoring,
    as a synchronized finding takes the rest of the assessment.

    The response stands ahead of the blocks as well. Each finding keeps its
    own; one without takes the response the other findings agree on.
    """
    response = agreed_response(_details(instance) for instance in instances)
    if _RESCORED_RE.search(merged) or _RESCORED_VECTOR_RE.search(merged):
        return lambda old: preserve_version_override(
            preserve_response(merged, old, response), old
        )

    def rank(preamble: str) -> tuple[bool, float]:
        score = _RESCORED_RE.search(preamble)
        return bool(_RESCORED_VECTOR_RE.search(preamble)), float(score.group(1)) if score else -1.0

    preambles = [preamble for instance in instances if (preamble := _rescoring_preamble(_details(instance)))]
    shared = max(preambles, key=rank, default="")

    def apply(old: str) -> str:
        preamble = _rescoring_preamble(old) or shared
        rebuilt = f"{preamble}\n\n{merged}" if preamble and merged else merged or preamble
        return preserve_version_override(preserve_response(rebuilt, old, response), old)

    return apply


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


# A workflow copies or moves assessments; it never decides that a ticket no
# longer applies. A ticket that a person removed stays removed.
_WORKFLOW_ORIGINS = frozenset({"bulk-workflow"})


def _names(text: str, key: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(key)}(?![\w-])", text) is not None


def _dropped_tickets(history: list[dict[str, Any]], current: str) -> list[dict[str, str]]:
    """Tickets a workflow removed from an assessment, and from which team.

    ``history`` holds the versions oldest first. A ticket counts when a
    version had it in a ``Ticket`` tag, the next version names it nowhere and
    was written by a workflow, and the current text does not name it either.
    """
    dropped: dict[str, dict[str, str]] = {}
    for before, after in zip(history, history[1:]):
        if after.get("origin") not in _WORKFLOW_ORIGINS:
            continue
        text = str(after.get("analysisDetails") or "")
        for block in _parse_blocks(str(before.get("analysisDetails") or "")):
            for key in _ticket_keys(block["tags"].get("Ticket")):
                if not _names(text, key):
                    dropped[key] = {
                        "ticket": key,
                        "team": block["team"],
                        "assessed_by": str(block["tags"].get("Assessed By") or ""),
                        "date": str(block["tags"].get("Date") or ""),
                    }
    return [drop for key, drop in dropped.items() if not _names(current, key)]


def _ticket_target(blocks: list[dict[str, Any]], drop: dict[str, str]) -> dict[str, Any] | None:
    """The block a dropped ticket returns to.

    The team's current block, else the current General assessment, else
    the exact historical record the ticket was dropped from (same team,
    assessor and date). Any other record is left alone: changing it would
    change what that record says. ``None`` leaves the ticket for a person.
    """
    team = _team_key(drop["team"])

    def of(key: str, historical: bool) -> list[dict[str, Any]]:
        return [
            block for block in blocks
            if _team_key(block["team"]) == key and _is_historical(block) == historical
        ]

    def same_record(block: dict[str, Any]) -> bool:
        return (
            str(block["tags"].get("Assessed By") or "") == drop.get("assessed_by", "")
            and str(block["tags"].get("Date") or "") == drop.get("date", "")
        )

    for candidates in (
        of(team, False),
        of("general", False),
        [block for block in of(team, True) if same_record(block)],
    ):
        if candidates:
            return candidates[0]
    return None


def _ticket_stage(
    groups: list[dict[str, Any]],
    context: BulkWorkflowContext,
) -> tuple[list[Payload], dict[str, dict[str, Any]]]:
    """Give back the tickets that a workflow dropped, from the history.

    The ticket returns to the block of its team when the team still has one,
    else to the General assessment. Without either, it is left for a person.
    """
    histories = context.ticket_histories() if context.ticket_histories else {}
    payloads: list[Payload] = []
    info: dict[str, dict[str, Any]] = {}
    if not histories:
        return payloads, info
    for group in groups:
        restored: list[str] = []
        unplaced: list[str] = []
        findings = 0
        for instance in _instances(group):
            if not all(instance.get(key) for key in _IDENTITY_KEYS):
                continue
            history = histories.get(tuple(str(instance[key]) for key in _IDENTITY_KEYS))
            if not history:
                continue
            old = _details(instance)
            drops = _dropped_tickets(history, old)
            if not drops:
                continue
            blocks = _parse_blocks(old)
            placed = False
            for drop in drops:
                target = _ticket_target(blocks, drop)
                if target is None:
                    if drop["ticket"] not in unplaced:
                        unplaced.append(drop["ticket"])
                    continue
                _carry_tickets(target, [{"tags": {"Ticket": drop["ticket"]}}])
                placed = True
                if drop["ticket"] not in restored:
                    restored.append(drop["ticket"])
            if not placed:
                continue
            first_header = HEADER_RE.search(old)
            details = _render(
                blocks,
                preamble=old[: first_header.start()] if first_header else "",
                pending=bool(_PENDING_RE.search(old)),
            )
            payloads.append(
                (instance, _payload(instance, _state(instance), preserve_ssvc_record(details, old)))
            )
            findings += 1
        if restored or unplaced:
            info[str(group.get("id") or "")] = {
                "restored": restored,
                "unplaced": [key for key in unplaced if key not in restored],
                "findings": findings,
            }
    return payloads, info


def _team_stage(
    groups: list[dict[str, Any]],
    context: BulkWorkflowContext,
    now_ms: int,
) -> tuple[list[Payload], dict[str, dict[str, Any]], int, int]:
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
        # Findings a new project version added stay unassessed: nothing is
        # copied onto them unless the reviewer includes them for this
        # vulnerability (ADR 0010 decision 7).
        new = (
            new_finding_ids(group)
            if lifecycle in ("INCONSISTENT", "INCOMPLETE") else set()
        )
        include_new = group_id in context.include_new_findings
        left_new = 0
        # The new findings this repair would change; one it would leave as
        # it is does not count.
        new_changing: list[dict[str, Any]] = []

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
            rescored = _with_rescoring(merged, instances)
            for instance in instances:
                old = _details(instance)
                details = preserve_ssvc_record(rescored(old), old)
                changes = _differs(details, old) or calculate_aggregated_state(details) != _state(instance)
                if id(instance) in new:
                    if changes:
                        new_changing.append(instance)
                    if not include_new:
                        left_new += int(changes)
                        continue
                if changes:
                    targets.append((instance, details))
            if not targets and not left_new:
                continue
        elif lifecycle == "INCOMPLETE":
            pending = any(_PENDING_RE.search(_details(instance)) for instance in instances)
            # The current blocks, merged. Historical blocks are records of
            # single findings: each finding keeps its own, none is copied to
            # another finding and none becomes a team's current block.
            sync_blocks = _parse_blocks(_sync_group(group)["target_details"])
            sync_only = _render(sync_blocks, pending=pending)
            records: dict[str, dict[str, Any]] = {}
            for instance in instances:
                for block in _parse_blocks(_details(instance)):
                    if _is_historical(block):
                        records.setdefault(_render_block(block), block)
            record_ids = {id(block) for block in records.values()}
            # The records are shown to the former-team repair, which leaves a
            # team that has one to assess for itself, and taken out again.
            blocks, former = _repair_former_teams(
                [*sync_blocks, *records.values()],
                current,
                context.team_mapping,
                user=context.user,
                pending=pending,
                now_ms=now_ms,
            )
            blocks = [block for block in blocks if id(block) not in record_ids]
            rescored = _with_rescoring(_render(blocks, pending=pending), instances)
            rescored_sync = _with_rescoring(sync_only, instances)
            for instance in instances:
                old = _details(instance)
                details = preserve_ssvc_record(with_own_records(rescored(old), old), old)
                changes = _differs(details, old) or calculate_aggregated_state(details) != _state(instance)
                if id(instance) in new:
                    if changes:
                        new_changing.append(instance)
                    if not include_new:
                        left_new += int(changes)
                        continue
                if changes:
                    targets.append((instance, details))
                synced = preserve_ssvc_record(with_own_records(rescored_sync(old), old), old)
                if _differs(synced, old) or calculate_aggregated_state(synced) != _state(instance):
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
                    for key in ("former_teams", "referred_teams", "open_teams", "removed_references"):
                        former[key] = sorted({*former[key], *result[key]}, key=str.casefold)
                    former["promoted_to_global_decision"] |= result["promoted_to_global_decision"]

        for instance, details in targets:
            if not all(instance.get(key) for key in _IDENTITY_KEYS):
                missing_identity += 1
                continue
            payloads.append((instance, _payload(instance, calculate_aggregated_state(details), details)))
        if synchronized or former or conflict or new_changing:
            info[group_id] = {
                "synchronized": synchronized, "former": former, "conflict": conflict,
                # The new findings the repair would change, where they are,
                # and how many this run left.
                "new_findings": len(new_changing),
                "new_finding_places": new_finding_places(group, new_changing),
                "new_findings_left": left_new,
            }
    return payloads, info, missing_identity, sum(
        entry["new_findings_left"] for entry in info.values()
    )


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

    ticket_payloads, ticket_info = _ticket_stage(keep_alive[-1], context)
    record(ticket_payloads, {})

    team_payloads, team_info, missing_identity, new_left = _team_stage(
        keep_alive[-1], context, int(time.time() * 1000)
    )
    record(team_payloads, {"missing_identity": missing_identity, "new_finding": new_left})

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
        "ticket_info": ticket_info,
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
        else f"Keep former team assessment as historical: {teams}"
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

    tickets = run["ticket_info"].get(group_id) or {}
    if tickets.get("restored"):
        repairs.append({
            "id": REPAIR_RESTORE_TICKETS,
            "label": (
                f"Restore {_plural(len(tickets['restored']), 'ticket')} a workflow dropped "
                f"({', '.join(tickets['restored'])}) on {_plural(tickets['findings'], 'finding')}"
            ),
        })
    if tickets.get("unplaced"):
        review.append(
            f"A workflow dropped {', '.join(tickets['unplaced'])}; "
            "no assessment of its team or global one to return it to"
        )

    team = run["team_info"].get(group_id) or {}
    if team.get("synchronized"):
        repairs.append({
            "id": REPAIR_SYNC_FINDINGS,
            "label": f"Synchronize assessment to {_plural(team['synchronized'], 'finding')}",
        })
    stale_references = (team.get("former") or {}).get("removed_references") or []
    if stale_references:
        repairs.append({
            "id": REPAIR_UNOWNED_REFERENCES,
            "label": (
                f"Remove the reference to the global assessment under {', '.join(stale_references)}: "
                "no team owns the component"
            ),
        })
    if team.get("former") and (
        team["former"]["former_teams"] or team["former"]["referred_teams"]
        or team["former"]["open_teams"]
    ):
        repairs.append({
            "id": REPAIR_FORMER_TEAMS if team["former"]["former_teams"] else REPAIR_REFER_TEAMS,
            "label": _former_team_label(team["former"]),
            # A former team's decision becoming binding is a judgement call.
            "needs_review": bool(team["former"]["promoted_to_global_decision"]),
        })
    if team.get("conflict"):
        repairs.append({
            "id": REPAIR_COMBINE_CONFLICT,
            "label": _conflict_label(team["conflict"]),
            "needs_review": True,
        })

    rescore = run["rescore_items"].get(group_id)
    if rescore:
        syncable = int(rescore.get("syncable_finding_count") or 0)
        if syncable:
            converted = sum(
                finding.get("status") == "ready" and bool(finding.get("cross_version"))
                for finding in rescore.get("findings") or []
            )
            label = f"Repair rescoring on {_plural(syncable, 'finding')}"
            if converted:
                label += f"; replaces a stored vector of another CVSS version on {converted}"
            repairs.append({
                "id": REPAIR_RESCORING,
                "label": label,
                # Discards metrics someone recorded in the other CVSS version.
                "needs_review": bool(converted),
            })
        manual = int(rescore.get("review_finding_count") or 0)
        if manual:
            review.append(f"Rescoring needs manual review on {_plural(manual, 'finding')}")

    # Findings a new project version added: listed, and synchronized only
    # when the reviewer includes them for this vulnerability.
    new_findings = int(team.get("new_findings") or 0)
    if not repairs and not review and not new_findings:
        return None
    return {
        "group_id": group_id,
        "title": group.get("title"),
        "severity": group.get("severity"),
        "repairs": repairs,
        "review": review,
        "finding_count": finding_count,
        "new_finding_count": new_findings,
        "new_finding_places": list(team.get("new_finding_places") or []),
        "repairable": finding_count > 0 or new_findings > 0,
        # Not selected by default: the repair makes a decision, part of the
        # vulnerability cannot be repaired automatically, or all it could
        # do is fill new findings, which is the reviewer's choice.
        "requires_review": (
            bool(review)
            or any(repair.get("needs_review") for repair in repairs)
            or (new_findings > 0 and finding_count == 0)
        ),
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
    topics = []
    for repair_id, label in REPAIR_TOPICS.items():
        count = sum(any(repair["id"] == repair_id for repair in item["repairs"]) for item in items)
        summary[f"{repair_id}_groups"] = count
        if count:
            topics.append({"id": repair_id, "label": label, "groups": count})
    summary["new_findings"] = sum(item["new_finding_count"] for item in items)
    summary["review_first_groups"] = sum(
        item["repairable"] and item["requires_review"] for item in items
    )
    return {"items": items, "summary": summary, "notes": run["notes"], "topics": topics}


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
            "Synchronize partial assessments, keep assessments of former teams as "
            "historical, restore lost CVSS vectors, and repair rule-based "
            "rescoring. Each vulnerability lists the repairs that apply."
        ),
        preview_builder=lambda context: build_assessment_repair_preview(context, load_rules),
        payload_builder=lambda context, ids: build_assessment_repair_payloads(context, ids, load_rules),
        selection_predicate=lambda item: bool(item.get("repairable")),
    )
