"""Review feedback belongs to the finding, independently of technical decisions."""

import base64
import binascii
import json
import re
from typing import Any, Iterable
from unicodedata import category


MARKER_NAME = "Team Changes Requested"
MARKER = re.compile(
    rf"^\[{MARKER_NAME}: ([A-Za-z0-9_-]{{1,8000}})\]\r?$",
    re.MULTILINE,
)
REQUEST_CHANGES_ORIGIN = "assessment-changes-requested"
RESUBMIT_CHANGES_ORIGIN = "assessment-changes-resubmitted"
WITHDRAW_CHANGES_ORIGIN = "assessment-changes-withdrawn"
MAX_REVIEW_RATIONALE = 1000


def normalize_changes_requests(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, (list, tuple)):
        return []
    result = {}
    for value in values:
        if not isinstance(value, dict):
            continue
        team, rationale, reviewer, requested_at = (
            value.get(name) for name in ("team", "rationale", "reviewer", "requested_at_ms")
        )
        if not all(isinstance(item, str) and item.strip() for item in (team, rationale, reviewer)):
            continue
        if (
            len(team) > 200
            or len(reviewer) > 200
            or len(rationale) > MAX_REVIEW_RATIONALE
            or team.strip().casefold() == "general"
            or type(requested_at) is not int
            or requested_at <= 0
            or any(category(char) in {"Cc", "Cs"} and char not in "\n\t"
                   for text in (team, rationale, reviewer) for char in text)
        ):
            continue
        result[team.strip().casefold()] = {
            "team": team.strip(),
            "rationale": rationale.strip(),
            "reviewer": reviewer.strip(),
            "requested_at_ms": requested_at,
        }
    return list(result.values())


def changes_requests(details: Any) -> list[dict[str, Any]]:
    """Only leading metadata can carry a review request, never a team body."""
    text = str(details or "")
    if MARKER_NAME not in text:
        return []
    # Team bodies and the SSVC body can quote any text. This record lives in
    # standalone lines at the start, before any other assessment content.
    values = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = MARKER.fullmatch(line)
        if not match:
            break
        encoded = match.group(1)
        try:
            decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            values.append(json.loads(decoded))
        except (binascii.Error, UnicodeError, json.JSONDecodeError, RecursionError):
            continue
    return normalize_changes_requests(values)


def strip_changes_requests(details: Any) -> str:
    """Remove the reserved markup before a normal save or prose rendering."""
    text = str(details or "")
    return MARKER.sub("", text).strip() if MARKER_NAME in text else text


def render_changes_request(value: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return f"[{MARKER_NAME}: {encoded}]"


def with_changes_requests(details: Any, requests: Iterable[dict[str, Any]]) -> str:
    text = strip_changes_requests(details)
    lines = [render_changes_request(value) for value in requests]
    return "\n\n".join(part for part in ("\n".join(lines), text) if part)
