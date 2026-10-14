"""Read-only compatibility for DTVP-tagged and unannotated DT documentation.

Imported author/reviewer names are historical claims, never authorization grants.
Raw analysis remains intact. Original Base facts are separate from legacy rescoring.
"""

import json
import math
import re
from datetime import UTC, datetime

STATES = {
    "EXPLOITABLE": "affected",
    "NOT_AFFECTED": "not_affected",
    "FALSE_POSITIVE": "not_affected",
    "RESOLVED": "fixed",
    "IN_TRIAGE": "under_investigation",
    "affected": "affected",
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "resolved": "fixed",
    "in_triage": "under_investigation",
    "under_investigation": "under_investigation",
}
TAG = re.compile(r"\[([\w\s]+):\s*([^\]]*)\]")
SSVC = re.compile(r"\[SSVC Details\]\s*\n(.*?)\n\[/SSVC Details\]", re.S)
HEADERS = re.compile(r"---\s*(?=\[Team:)", re.I)
KNOWN_TAGS = {
    "team",
    "state",
    "assessed by",
    "reviewed by",
    "rescored",
    "rescored vector",
    "assigned",
    "date",
    "status",
    "justification",
    "historical",
    "copied from",
    "ssvc",
}


def date_value(value):
    if not value:
        return None
    try:
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp /= 1000
        return datetime.fromtimestamp(timestamp, UTC).isoformat()
    except ValueError, OverflowError, OSError:
        return None


def tags(value):
    return {match[1].strip().casefold(): match[2].strip() for match in TAG.finditer(value)}


def prose(value):
    return TAG.sub(
        lambda match: "" if match[1].strip().casefold() in KNOWN_TAGS else match[0], value
    ).strip()


def record(header, body, fallback):
    values = tags(header)
    rescored = values.get("rescored")
    try:
        score = float(rescored) if rescored is not None else None
    except ValueError:
        score = None
    if score is not None and (not math.isfinite(score) or not 0 <= score <= 10):
        score = None
    state = values.get("state", fallback)
    return {
        "team": values.get("team", "General"),
        "state": STATES.get(state),
        "source_state": state,
        "rationale": prose(body),
        "assessor": values.get("assessed by"),
        "reviewer": values.get("reviewed by"),
        "assigned": [
            entry.strip() for entry in values.get("assigned", "").split(",") if entry.strip()
        ],
        "date": values.get("date"),
        "assessed_at": date_value(values.get("date")),
        "pending_review": values.get("status", "").casefold() == "pending review",
        "historical": values.get("historical", "").casefold() == "yes",
        "copied_from": values.get("copied from"),
        "justification": values.get("justification"),
        "rescored_score": score,
        "rescored_vector": values.get("rescored vector"),
        "ssvc_priority": values.get("ssvc"),
        "metadata": values,
    }


def decode(analysis):
    if not isinstance(analysis, dict):
        return None
    original = analysis
    if isinstance(analysis.get("analysis"), dict):
        analysis = {
            **analysis["analysis"],
            "analysisComments": analysis.get("comments", analysis.get("analysisComments", [])),
        }
    text = (
        analysis.get(
            "analysisDetails", analysis.get("analysis_details", analysis.get("detail", ""))
        )
        or ""
    )
    if not isinstance(text, str):
        raise ValueError("DT assessment details must be text")
    source_state = analysis.get(
        "analysisState", analysis.get("analysis_state", analysis.get("state", "NOT_SET"))
    )
    if source_state is not None and not isinstance(source_state, str):
        raise ValueError("DT assessment state must be text")
    if (
        not text
        and source_state in {None, "NOT_SET", "not_set"}
        and not analysis.get("isSuppressed", False)
    ):
        return None
    errors, ssvc = [], []
    for match in SSVC.finditer(text):
        try:
            ssvc.append(json.loads(match[1]))
        except json.JSONDecodeError:
            errors.append("Unparsed SSVC details retained in original text")
    # Keep offsets stable so team-looking JSON strings cannot become assessment blocks.
    masked = SSVC.sub(lambda match: " " * len(match[0]), text)
    headers = list(HEADERS.finditer(masked))
    records = []
    shared = text[: headers[0].start()].strip() if headers else text
    if not headers:
        records.append(record(masked, masked, source_state))
    else:
        if shared:
            records.append(record("", SSVC.sub("", shared), "NOT_SET"))
        for index, match in enumerate(headers):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(masked)
            segment = masked[match.end() : end]
            header_end = segment.find("---")
            if header_end < 0:
                errors.append("Malformed team header retained in original text")
                continue
            records.append(record(segment[:header_end], segment[header_end + 3 :], source_state))
    pending = bool(re.search(r"\[Status:\s*Pending Review\]", masked, re.I))
    # Current team projections use latest dated duplicate; all original blocks stay in history.
    current = {}
    for index, entry in enumerate(records):
        if entry["historical"]:
            continue
        key = entry["team"].casefold()
        prior = current.get(key)
        if prior is None or (entry["assessed_at"] or "", index) >= (
            prior["assessed_at"] or "",
            prior["index"],
        ):
            current[key] = {**entry, "index": index}
    active = list(current.values())
    general = next(
        (entry for entry in active if entry["team"].casefold() == "general" and entry["state"]),
        None,
    )
    states = {entry["state"] for entry in active if entry["state"]}
    state = general["state"] if general else next(iter(states)) if len(states) == 1 else None
    return {
        "schema_version": "dtvp.legacy-dt/1",
        "format": "dtvp-tags" if headers or tags(masked) else "plain-dt",
        "source_state": source_state,
        "state": state or STATES.get(source_state),
        "documented": bool(text),
        "assessed": bool(STATES.get(source_state) or states),
        "pending_review": pending,
        "conflicting": not general and len(states) > 1,
        "records": records,
        "current_records": active,
        "raw_text": text,
        "shared_text": shared,
        "ssvc": ssvc,
        "suppressed": bool(analysis.get("isSuppressed", analysis.get("suppressed", False))),
        "comments": analysis.get("analysisComments", analysis.get("comments", [])),
        "source_analysis": original,
        "errors": errors,
    }


def from_advisory(advisory):
    for entry in advisory.get("properties", []):
        if entry.get("name") == "dtvp:dt-analysis":
            try:
                return decode(json.loads(entry["value"]))
            except json.JSONDecodeError, TypeError:
                return {
                    "format": "unparsed",
                    "errors": ["DT source analysis could not be decoded"],
                    "assessed": False,
                    "pending_review": False,
                    "conflicting": False,
                    "current_records": [],
                    "raw_text": entry.get("value", ""),
                }
    return decode(advisory.get("analysis", {}))
