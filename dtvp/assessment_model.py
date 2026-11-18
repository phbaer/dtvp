"""An assessment as atomic fields.

Dependency-Track keeps an analysis as a state, a suppression flag, and one
free text, so DTVP writes everything else into that text as markup: the
rescoring, the review status, and one block per team. This module reads that
text into fields. DTVP's database stores the fields; see ADR 0003.
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
