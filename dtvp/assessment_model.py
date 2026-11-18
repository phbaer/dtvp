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

_SCORE = re.compile(r"\[Rescored:\s*([\d.]+)\]")
_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
_PENDING = re.compile(r"\[Status: Pending Review\]", re.IGNORECASE)


def _number(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


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
    free_text = _PENDING.sub("", _VECTOR.sub("", _SCORE.sub("", shared))).strip()
    teams = [
        {
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
        for block in blocks
    ]
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
        _PENDING.sub("", _VECTOR.sub("", _SCORE.sub("", str(fields.get("free_text") or ""))))
    )
    general = next((team for team in teams if team["team"] == "General"), None)
    score = _number(fields.get("rescored_score"))
    vector = _header_value(fields.get("rescored_vector") or "") or None
    return {
        "state": str(fields.get("state") or "NOT_SET"),
        "suppressed": bool(fields.get("suppressed")),
        "pending_review": bool(fields.get("pending_review")),
        # As when reading: the General assessment's rescoring is the
        # finding's unless one is given beside the teams.
        "rescored_score": score if score is not None else (general or {}).get("rescored_score"),
        "rescored_vector": vector or (general or {}).get("rescored_vector"),
        "free_text": free_text,
        "form": FORM_STRUCTURED if teams else FORM_TEXT if (
            free_text or score is not None or vector or fields.get("pending_review")
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
    if shared:
        parts.append(" ".join(shared))
    if fields["free_text"]:
        parts.append(fields["free_text"])
    for team in fields["teams"]:
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
        parts.append(f"--- {' '.join(tags)} ---\n{body}".rstrip())
    if fields["pending_review"]:
        parts.append(PENDING_REVIEW_MARKER)
    return "\n\n".join(parts)


def finding_key(instance: dict[str, Any]) -> str:
    """One finding, as a key for values kept per finding."""
    return "|".join(
        str(instance.get(name) or "")
        for name in ("project_uuid", "component_uuid", "vulnerability_uuid")
    )
