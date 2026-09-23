"""Resource-driven SSVC: atomic General outcome and a separate JSON details block."""

import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from itertools import product
from pathlib import Path
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field


class SsvcInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    version: str
    answers: dict[str, str]
    rationale: str = Field(default="", max_length=4000)
    exploitation_evidence: str | None = Field(default=None, max_length=8192)


TAG = re.compile(r"\[SSVC:\s*([^\]]+)\]")
GENERAL_HEADER = re.compile(r"---\s*\[Team:\s*General\][^\n]*?---", re.I)
OUTCOMES = ("DEFER", "SCHEDULED", "OUT_OF_CYCLE", "IMMEDIATE")
FILTER_VALUES = (*OUTCOMES, "UNASSESSED", "INCOMPLETE", "MIXED", "INVALID")
SUMMARY = re.compile(r"(?:^|\r?\n(?:\r?\n)?)\[SSVC Summary\]\r?\n.*?\r?\n\[/SSVC Summary\]", re.S)
DETAILS = re.compile(r"(?:^|\r?\n(?:\r?\n)?)\[SSVC Details\]\r?\n(.*?)\r?\n\[/SSVC Details\]", re.S)


def strip_details(text: str) -> str:
    return DETAILS.sub("", text) if "[SSVC Details]" in text else text


def mask_details(text: str) -> str:
    """Hide JSON from header scanning without changing character offsets."""
    return DETAILS.sub(lambda match: " " * len(match[0]), text) if "[SSVC Details]" in text else text


def general_body(details: str) -> str:
    masked = mask_details(details)
    header = GENERAL_HEADER.search(masked)
    if header is None:
        return ""
    following = re.search(r"---\s*\[Team:", masked[header.end():], re.I)
    end = header.end() + following.start() if following else len(details)
    return details[header.end():end]


def outcome_value(record: dict) -> str:
    return priority_label(record).upper().replace("-", "_").replace(" ", "_")


def details_block(record: dict) -> str:
    payload = json.dumps(record, indent=2, ensure_ascii=False)
    # Standard JSON string escapes keep embedded assessment tags inert for
    # legacy text consumers. Structural JSON and ordinary text stay readable.
    payload = re.sub(r'"(?:\\.|[^"\\])*"', lambda match: match[0].replace("[", r"\u005b").replace("--", r"\u002d\u002d"), payload)
    return f"[SSVC Details]\n{payload}\n[/SSVC Details]"


def validate_evidence(selection: SsvcInput) -> dict | None:
    if selection.exploitation_evidence:
        from .ssvc_enrichment_services import verify_evidence
        return verify_evidence(selection.exploitation_evidence, selection.answers)
    return None


def priority_label(record: dict) -> str:
    model = next(m for m in get_models() if (model_id(m), m["version"]) == (record["model"], record["version"]))
    outcome = evaluate(SsvcInput.model_validate({k: record[k] for k in ("model", "version", "answers", "rationale")}))
    return next((value["name"] for value in model["decision_points"][model["outcome"]]["values"] if value["key"] == outcome), "Incomplete")


def documented_summary(record: dict) -> str:
    model = next((m for m in get_models() if (model_id(m), m["version"]) == (record["model"], record["version"])), None)
    if model is None:
        return "[SSVC Summary]\nSSVC priority: Unsupported assessment version\n[/SSVC Summary]"
    lines = ["[SSVC Summary]", f"SSVC priority: {priority_label(record)}", f"Model: {model['name']} v{model['version']}"]
    for key, point in model["decision_points"].items():
        if key != model["outcome"]:
            answer = next((v["name"] for v in point["values"] if v["key"] == record["answers"].get(key)), "Not assessed")
            lines.append(f"{point['name']}: {answer}")
    if record.get("rationale"):
        # Prevent user text from closing the generated documentation region.
        rationale = record["rationale"].replace("---", "—").replace("[", "(").replace("]", ")")
        lines.append(f"SSVC rationale: {rationale}")
    evidence = record.get("evidence")
    if isinstance(evidence, dict) and all(isinstance(evidence.get(key), str) for key in ("source", "cve", "url", "assessed_at", "checked_at")):
        lines.append(f"Exploitation evidence: {evidence['source']} · {evidence['cve']} · {evidence['url']}")
        lines.append(f"Source assessment: {evidence['assessed_at']}; checked: {evidence['checked_at']}" + (" (stale when selected)" if evidence.get("stale") else ""))
    lines.append(f"SSVC assessed by: {record.get('assessor', 'unknown')} · {record.get('assessed_at', 'unknown')}")
    lines.append("[/SSVC Summary]")
    return "\n".join(lines)


def update_documentation(details: str, record: dict | None, historical: str = "") -> str:
    details = SUMMARY.sub("", strip_details(details))
    header = GENERAL_HEADER.search(details)
    if header is None:
        return details
    summary = documented_summary(record) + "\n\n" + details_block(record) if record is not None else historical
    if summary:
        details = details[:header.end()] + "\n\n" + summary + details[header.end():]
    return details


def model_id(model: dict) -> str:
    return f"{model['namespace']}:{model['key']}"


def validate_model(model: dict) -> None:
    points = model["decision_points"]
    outcome = model["outcome"]
    inputs = [key for key in points if key != outcome]
    domains = {key: {v["key"] for v in point["values"]} for key, point in points.items()}
    if any(not values for values in domains.values()):
        raise ValueError("SSVC decision points must have values")
    if any(len(domains[key]) != len(point["values"]) for key, point in points.items()):
        raise ValueError("Duplicate SSVC decision point values")
    seen = set()
    for row in model["mapping"]:
        if set(row) != set(points) or any(row[key] not in domains[key] for key in points):
            raise ValueError("Invalid SSVC decision rule")
        combination = tuple(row[key] for key in inputs)
        if combination in seen:
            raise ValueError("Duplicate SSVC decision rule")
        seen.add(combination)
    if seen != set(product(*(domains[key] for key in inputs))):
        raise ValueError("Incomplete SSVC decision table")


@lru_cache(maxsize=1)
def get_models() -> tuple[dict, ...]:
    models = []
    identities = set()
    for path in sorted((Path(__file__).parent / "resources" / "ssvc").glob("*.json")):
        model = json.loads(path.read_text())
        validate_model(model)
        identity = (model_id(model), model["version"])
        if identity in identities:
            raise ValueError("Duplicate SSVC model version")
        identities.add(identity)
        models.append(model)
    return tuple(models)


def evaluate(selection: SsvcInput) -> str | None:
    model = next((m for m in get_models() if (model_id(m), m["version"]) == (selection.model, selection.version)), None)
    if model is None:
        raise ValueError("Unsupported SSVC model or version")
    inputs = {k: p for k, p in model["decision_points"].items() if k != model["outcome"]}
    for key, value in selection.answers.items():
        if key not in inputs or value not in {v["key"] for v in inputs[key]["values"]}:
            raise ValueError("Invalid SSVC answer")
    if set(selection.answers) != set(inputs):
        return None
    row = next(row for row in model["mapping"] if all(row[key] == value for key, value in selection.answers.items()))
    return row[model["outcome"]]


def read_record(details: str) -> dict | None:
    header = GENERAL_HEADER.search(mask_details(details))
    tags = list(TAG.finditer(header[0])) if header else []
    blocks = list(DETAILS.finditer(general_body(details)))
    if len(tags) > 1 or len(blocks) > 1:
        raise ValueError("Duplicate SSVC metadata")
    if not tags:
        if blocks:
            raise ValueError("SSVC details without an outcome")
        return None
    token = tags[0][1].strip()
    atomic = token in (*OUTCOMES, "INCOMPLETE", "INVALID")
    if atomic:
        if not blocks:
            raise ValueError("SSVC outcome without details")
        record = json.loads(blocks[0][1])
    else:
        if blocks:
            raise ValueError("Conflicting legacy and structured SSVC metadata")
        record = json.loads(unquote(token))
    if not isinstance(record, dict):
        raise ValueError("Invalid SSVC record")
    selection = SsvcInput.model_validate({k: record[k] for k in ("model", "version", "answers", "rationale")})
    if evaluate(selection) != record.get("outcome"):
        raise ValueError("SSVC outcome does not match answers")
    if atomic and token != outcome_value(record):
        raise ValueError("SSVC header does not match the decision")
    return record


def write_record(details: str, record: dict | None) -> str:
    """Replace only General's SSVC metadata, preserving other assessment text."""
    try:
        outcome = outcome_value(record) if record is not None else None
    except (ValueError, KeyError, TypeError, StopIteration):
        outcome = "INVALID"
    details = SUMMARY.sub("", strip_details(details))
    return update_documentation(write_token(details, outcome), record)


def write_token(details: str, token: str | None) -> str:
    header = GENERAL_HEADER.search(details)
    if header is None:
        if token is None:
            return details
        details = "--- [Team: General] [State: NOT_SET] [Assessed By: unknown] ---\n\n" + details
        header = GENERAL_HEADER.search(details)
    replacement = TAG.sub("", header[0]).rstrip("- ")
    if token is not None:
        replacement += f" [SSVC: {token}]"
    replacement += " ---"
    return details[:header.start()] + replacement + details[header.end():]


def preserve_record(details: str, existing: str) -> str:
    try:
        record = read_record(existing)
    except (ValueError, KeyError, TypeError):
        header = GENERAL_HEADER.search(mask_details(existing))
        tags = list(TAG.finditer(header[0])) if header else []
        token = "] [SSVC: ".join(tag[1] for tag in tags) if tags else "INVALID"
        details = write_token(SUMMARY.sub("", strip_details(details)), token)
        historical = SUMMARY.search(existing)
        blocks = [match[0].lstrip() for match in DETAILS.finditer(general_body(existing))]
        documentation = ([historical[0].lstrip()] if historical else []) + blocks
        return update_documentation(details, None, "\n\n".join(documentation))
    # Valid legacy records migrate on the next normal save, not during reads.
    return write_record(details, record)


def new_record(selection: SsvcInput, user: str) -> dict:
    record = {
        **selection.model_dump(),
        "outcome": evaluate(selection),
        "evidence": validate_evidence(selection),
        "assessor": user,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }
    record["priority"] = priority_label(record)
    return record


def summarize_group(group: dict) -> dict:
    records = []
    missing = invalid = 0
    for version in group.get("affected_versions", []):
        for instance in version.get("components", []):
            try:
                record = read_record(instance.get("analysis_details") or instance.get("analysisDetails") or "")
            except (ValueError, KeyError, TypeError):
                invalid += 1
                continue
            if record is None:
                missing += 1
            else:
                records.append(record)
    signatures = {json.dumps({k: r[k] for k in ("model", "version", "answers", "rationale")}, sort_keys=True) for r in records}
    status = "UNASSESSED"
    if invalid:
        status = "INVALID"
    elif len(signatures) > 1:
        status = "MIXED"
    elif records:
        if missing or any(r["outcome"] is None for r in records):
            status = "INCOMPLETE"
        else:
            model = next(m for m in get_models() if (model_id(m), m["version"]) == (records[0]["model"], records[0]["version"]))
            label = next(v["name"] for v in model["decision_points"][model["outcome"]]["values"] if v["key"] == records[0]["outcome"])
            status = label.upper().replace("-", "_").replace(" ", "_")
    return {"status": status, "assessed": len(records), "missing": missing, "invalid": invalid,
            "record": records[0] if len(signatures) == 1 and not invalid else None}
