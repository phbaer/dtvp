"""An assessment as atomic fields.

Dependency-Track keeps an analysis as a state, a suppression flag, and one
free text, so DTVP writes everything else into that text as markup: the
rescoring, the review status, and one block per team. This module reads that
text into fields and writes fields back as that text. DTVP's database stores
the fields; the text is their rendering for Dependency-Track. See ADR 0003.

``parse_assessment(render_assessment(fields))`` returns ``fields``: a save
that sends fields stores exactly those fields.
"""

from __future__ import annotations

import re
from typing import Any

FORM_STRUCTURED = "structured"  # at least one team block
FORM_TEXT = "text"  # text without team blocks (legacy or plain)
FORM_EMPTY = "empty"

# Texts DTVP itself writes into an assessment; readers recognise them by these.
SEE_GLOBAL_ASSESSMENT = "See global assessment."  # a team referring to General
FORMER_TEAM_NOTE = "Former team assessment"  # starts a note about a former team

_SCORE = re.compile(r"\[Rescored:\s*([\d.]+)\]")
_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
_PENDING = re.compile(r"\[Status: Pending Review\]", re.IGNORECASE)

# What is done about a finding: Dependency-Track's ``analysisResponse`` and
# CycloneDX's ``analysis.response``. One value per finding, part of the
# General assessment; ``None`` when not set.
ANALYSIS_RESPONSES = (
    "CAN_NOT_FIX",
    "WILL_NOT_FIX",
    "UPDATE",
    "ROLLBACK",
    "WORKAROUND_AVAILABLE",
)
RESPONSE_NOT_SET = "NOT_SET"
# Only a tag with a value of the list is the field. Anything else in
# brackets stays the text it is.
RESPONSE_TAG_PATTERN = (
    r"\[Response:\s*(" + "|".join((*ANALYSIS_RESPONSES, RESPONSE_NOT_SET)) + r")\s*\]"
)
_RESPONSE = re.compile(RESPONSE_TAG_PATTERN, re.IGNORECASE)
_LEADING_RESCORING = re.compile(r"(?:\s*\[Rescored(?: Vector)?:[^\]]*\])+")


def normalize_response(value: Any) -> str | None:
    """A response of the list in its stored spelling; ``None`` for no value,
    ``NOT_SET``, and anything that is not a response."""
    text = re.sub(r"[\s-]+", "_", str(value or "").strip()).upper()
    return text if text in ANALYSIS_RESPONSES else None


def analysis_response(details: Any) -> str | None:
    """The response an assessment text carries beside its team blocks."""
    from .logic import parse_assessment_blocks  # logic imports nothing from here

    shared, _blocks = parse_assessment_blocks(str(details or ""))
    return _shared_response(shared)


def agreed_response(texts: Any) -> str | None:
    """The response of several findings' texts when those that name one
    name the same; ``None`` when none does or they differ."""
    named = {value for text in texts if (value := analysis_response(text))}
    return next(iter(named)) if len(named) == 1 else None


def preserve_response(details: Any, existing: Any, shared: Any = None) -> str:
    """``details`` with the response of ``existing`` when it names none.

    For writers that rebuild a text from its team blocks (bulk workflows):
    the response stands beside the blocks and would be dropped with
    everything else there. Each finding keeps its own. One without takes
    ``shared``, the response the vulnerability's other findings agree on
    (``agreed_response``), as it takes the rest of their assessment.
    """
    text = str(details or "")
    kept = analysis_response(existing) or normalize_response(shared)
    if kept is None or analysis_response(text) is not None:
        return text
    return with_response(text, kept)


def with_response(details: Any, response: Any) -> str:
    """The assessment text ``details`` with ``response`` as its response;
    ``None`` removes the one it has. Nothing else of the text changes."""
    from .ssvc_services import mask_details as mask_ssvc_details

    text = str(details or "")
    if analysis_response(text) == normalize_response(response):
        return text
    first = _BLOCK_START.search(mask_ssvc_details(text))
    head, blocks = (text[: first.start()], text[first.start():]) if first else (text, "")
    return "\n\n".join(
        part for part in (set_shared_response(head, response), blocks.strip()) if part
    )


def with_analysis_response(payload: dict[str, Any]) -> dict[str, Any]:
    """A stored assessment (``state``, ``details``, ``suppressed`` and the
    finding's identity) as the arguments of a write to Dependency-Track:
    the response its text carries goes into the field of its own."""
    return {**payload, "response": analysis_response(payload.get("details"))}


def _shared_response(shared: str) -> str | None:
    for match in _RESPONSE.finditer(shared):
        value = normalize_response(match.group(1))
        if value is not None:
            return value
    return None


def set_shared_response(shared: str, response: Any) -> str:
    """The text ahead of the team blocks with ``response`` as its response
    tag (none for ``None``), placed where ``render_assessment`` writes it."""
    rest = _RESPONSE.sub("", shared).strip()
    value = normalize_response(response)
    if value is None:
        return rest
    tag = f"[Response: {value}]"
    lead = _LEADING_RESCORING.match(rest)
    if lead:
        return f"{rest[:lead.end()].strip()} {tag}{rest[lead.end():]}"
    return f"{tag}\n\n{rest}" if rest else tag


def _number(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


def team_from_block(block: dict[str, Any]) -> dict[str, Any]:
    """One team's fields from a block of the text parser."""
    return {
        "team": str(block.get("team") or ""),
        "state": str(block.get("state") or "NOT_SET"),
        "justification": (
            None
            if block.get("justification") in (None, "", "NOT_SET")
            else str(block["justification"])
        ),
        "assessed_by": (
            None if block.get("user") in (None, "", "unknown") else str(block["user"])
        ),
        "reviewed_by": block.get("reviewer") or None,
        "assessed_at_ms": (
            int(block["timestamp"]) if _number(block.get("timestamp")) else None
        ),
        "rescored_score": _number(block.get("rescored")),
        "rescored_vector": block.get("vector") or None,
        "ssvc": block.get("ssvc") or None,
        "ssvc_details": block.get("ssvc_details") or None,
        "assigned": [str(name) for name in block.get("assigned") or []],
        "ticket": block.get("ticket") or None,
        "evidence_reviewed": block.get("evidence_reviewed") or None,
        "version_coverage": block.get("version_coverage") or None,
        "historical": bool(block.get("historical")),
        "copied_from": block.get("copied_from") or None,
        "details": str(block.get("details") or ""),
    }


def parse_assessment(state: Any, details: Any, suppressed: Any) -> dict[str, Any]:
    """The fields of one finding's assessment.

    ``free_text`` is everything outside the team blocks, kept as written but
    without the rescoring and status markers. A block's own text is
    ``details``.
    """
    from .logic import parse_assessment_blocks  # logic imports nothing from here

    raw = str(details or "")
    shared, blocks = parse_assessment_blocks(raw)
    score = _SCORE.search(shared)
    vector = _VECTOR.search(shared)
    general = next((b for b in blocks if b.get("team") == "General"), None)
    free_text = _PENDING.sub(
        "", _RESPONSE.sub("", _VECTOR.sub("", _SCORE.sub("", shared)))
    ).strip()
    teams = [team_from_block(block) for block in blocks]
    return {
        "state": str(state or "NOT_SET"),
        "suppressed": bool(suppressed),
        "pending_review": bool(_PENDING.search(raw)),
        "rescored_score": (
            _number(score.group(1)) if score
            else _number((general or {}).get("rescored"))
        ),
        "rescored_vector": (
            vector.group(1).strip() if vector else (general or {}).get("vector") or None
        ),
        "response": _shared_response(shared),
        "free_text": free_text,
        "form": FORM_STRUCTURED if teams else FORM_TEXT if raw.strip() else FORM_EMPTY,
        "teams": teams,
    }


PENDING_REVIEW_MARKER = "[Status: Pending Review]"
_HEADER_UNSAFE = re.compile(r"[\r\n\[\]]+")
_BLOCK_START = re.compile(r"---(?=\s*\[Team:)")


def _header_value(value: Any) -> str:
    """A value that cannot end its tag or the block header."""
    text = _HEADER_UNSAFE.sub(" ", str(value))
    return re.sub(r"\s+", " ", text.replace("---", "- - -")).strip()


def _body(value: Any) -> str:
    """Text that cannot be read as the start of another team block."""
    return _BLOCK_START.sub("- - -", str(value or "")).strip()


def _score(value: Any) -> str | None:
    number = _number(value)
    return None if number is None else repr(float(number))


def normalize_assessment_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """The fields that are stored when ``fields`` are saved.

    Exactly what reading the rendered text gives: values are cleaned so that
    they survive rendering, and anything the reader removes from a text (tag
    look-alikes, the former "-- user" signature) is removed here as well.
    """
    cleaned = _clean_fields(fields)
    stored = parse_assessment(
        cleaned["state"], _render_clean(cleaned), cleaned["suppressed"]
    )
    return stored


def _clean_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Caller-supplied fields with values that survive rendering: header
    values lose line breaks and brackets, and text cannot open a team block."""
    teams = []
    seen: set[str] = set()
    for team in fields.get("teams") or []:
        name = _header_value(team.get("team") or "")
        if not name:
            raise ValueError("Every team assessment needs a team name")
        name = "General" if name.casefold() == "general" else name
        if name.casefold() in seen:
            raise ValueError(f"More than one assessment for team {name}")
        seen.add(name.casefold())
        justification = _header_value(team.get("justification") or "")
        assessed_at = _number(team.get("assessed_at_ms"))
        teams.append(
            {
                "team": name,
                "state": _header_value(team.get("state") or "NOT_SET").upper() or "NOT_SET",
                "justification": (
                    None if justification in ("", "NOT_SET") else justification
                ),
                "assessed_by": _header_value(team.get("assessed_by") or "") or None,
                "reviewed_by": _header_value(team.get("reviewed_by") or "") or None,
                "assessed_at_ms": int(assessed_at) if assessed_at else None,
                "rescored_score": _number(team.get("rescored_score")),
                "rescored_vector": _header_value(team.get("rescored_vector") or "") or None,
                "ssvc": _header_value(team.get("ssvc") or "") or None,
                "ssvc_details": str(team.get("ssvc_details") or "").strip() or None,
                "assigned": [
                    name
                    for name in (
                        _header_value(item).replace(",", " ")
                        for item in team.get("assigned") or []
                    )
                    if name
                ],
                "ticket": _header_value(team.get("ticket") or "") or None,
                "evidence_reviewed": _header_value(team.get("evidence_reviewed") or "") or None,
                "version_coverage": _header_value(team.get("version_coverage") or "") or None,
                "historical": bool(team.get("historical")),
                "copied_from": _header_value(team.get("copied_from") or "") or None,
                "details": _body(team.get("details")),
            }
        )
    free_text = _body(
        _PENDING.sub(
            "",
            _RESPONSE.sub(
                "", _VECTOR.sub("", _SCORE.sub("", str(fields.get("free_text") or "")))
            ),
        )
    )
    general = next((team for team in teams if team["team"] == "General"), None)
    score = _number(fields.get("rescored_score"))
    vector = _header_value(fields.get("rescored_vector") or "") or None
    response = normalize_response(fields.get("response"))
    return {
        "state": str(fields.get("state") or "NOT_SET"),
        "suppressed": bool(fields.get("suppressed")),
        "pending_review": bool(fields.get("pending_review")),
        # As when reading: the General assessment's rescoring is the
        # finding's unless one is given beside the teams.
        "rescored_score": score if score is not None else (general or {}).get("rescored_score"),
        "rescored_vector": vector or (general or {}).get("rescored_vector"),
        "response": response,
        "free_text": free_text,
        "form": FORM_STRUCTURED if teams else FORM_TEXT if (
            free_text or score is not None or vector or response
            or fields.get("pending_review")
        ) else FORM_EMPTY,
        "teams": teams,
    }


def render_assessment(fields: dict[str, Any]) -> str:
    """The text Dependency-Track stores for an assessment given as fields."""
    return _render_clean(_clean_fields(fields))


def _render_clean(fields: dict[str, Any]) -> str:
    general = next((team for team in fields["teams"] if team["team"] == "General"), None)
    parts: list[str] = []
    shared = []
    # Written beside the teams only when it is not the General assessment's
    # own rescoring, which its block carries.
    if fields["rescored_score"] is not None and fields["rescored_score"] != (
        general or {}
    ).get("rescored_score"):
        shared.append(f"[Rescored: {_score(fields['rescored_score'])}]")
    if fields["rescored_vector"] and fields["rescored_vector"] != (general or {}).get(
        "rescored_vector"
    ):
        shared.append(f"[Rescored Vector: {fields['rescored_vector']}]")
    if fields.get("response"):
        shared.append(f"[Response: {fields['response']}]")
    if shared:
        parts.append(" ".join(shared))
    if fields["free_text"]:
        parts.append(fields["free_text"])
    for team in fields["teams"]:
        parts.append(_render_team(team))
    if fields["pending_review"]:
        parts.append(PENDING_REVIEW_MARKER)
    return "\n\n".join(parts)


def finding_key(instance: dict[str, Any]) -> str:
    """One finding, as a key for values kept per finding."""
    return "|".join(
        str(instance.get(name) or "")
        for name in ("project_uuid", "component_uuid", "vulnerability_uuid")
    )


def _render_team(team: dict[str, Any]) -> str:
    tags = [
        f"[Team: {team['team']}]",
        f"[State: {team['state']}]",
        f"[Assessed By: {team['assessed_by'] or 'unknown'}]",
    ]
    if team["reviewed_by"]:
        tags.append(f"[Reviewed By: {team['reviewed_by']}]")
    if team["assessed_at_ms"]:
        tags.append(f"[Date: {team['assessed_at_ms']}]")
    tags.append(f"[Justification: {team['justification'] or 'NOT_SET'}]")
    if team["assigned"]:
        tags.append(f"[Assigned: {', '.join(team['assigned'])}]")
    if team["evidence_reviewed"]:
        tags.append(f"[Evidence Reviewed: {team['evidence_reviewed']}]")
    if team["version_coverage"]:
        tags.append(f"[Version Coverage: {team['version_coverage']}]")
    if team["ticket"]:
        tags.append(f"[Ticket: {team['ticket']}]")
    if team["rescored_score"] is not None:
        tags.append(f"[Rescored: {_score(team['rescored_score'])}]")
    if team["rescored_vector"]:
        tags.append(f"[Rescored Vector: {team['rescored_vector']}]")
    if team["ssvc"]:
        tags.append(f"[SSVC: {team['ssvc']}]")
    if team["historical"]:
        tags.append("[Historical: yes]")
    if team["copied_from"]:
        tags.append(f"[Copied From: {team['copied_from']}]")
    body = team["details"]
    if team["ssvc_details"]:
        body = f"{body}\n\n{team['ssvc_details']}".strip()
    return f"--- {' '.join(tags)} ---\n{body}".rstrip()


def render_team_block(block: dict[str, Any]) -> str:
    """One block of the text parser as text, with every tag it carries."""
    [team] = _clean_fields({"teams": [team_from_block(block)]})["teams"]
    return _render_team(team)


def canonical_assessment_text(state: Any, details: Any, suppressed: Any = False) -> str:
    """``details`` in the one spacing every stored assessment has.

    Writers lay the same assessment out differently (a blank line after a
    block header or none), and identical assessments then looked different.
    Only the layout is changed: when writing the text's fields back would
    change anything but white space, the text is returned as it came.
    """
    text = str(details or "")
    canonical = _render_clean(_clean_fields(parse_assessment(state, text, suppressed)))
    return canonical if "".join(canonical.split()) == "".join(text.split()) else text
