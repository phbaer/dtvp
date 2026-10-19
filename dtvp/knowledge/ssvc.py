"""Pinned local SSVC evaluation; inputs remain part of ordinary scoped assessment review."""

import json
from functools import lru_cache
from itertools import product
from pathlib import Path

from pydantic import Field

from dtvp.knowledge.journal import Sha
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class SsvcEvidence(RequestModel):
    reference: str = Field(min_length=1, max_length=2000)
    description: str = Field(min_length=1, max_length=4000)


class SsvcInput(RequestModel):
    model: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    model_sha256: Sha
    answers: dict[str, str] = Field(max_length=20)
    rationale: str = Field(min_length=1, max_length=6000)
    evidence: list[SsvcEvidence] = Field(default_factory=list, max_length=50)


def model_id(model):
    return f"{model['namespace']}:{model['key']}"


def validate_model(model):
    """Pure complete-table validation retained from v1's resource-driven evaluator."""
    points = model["decision_points"]
    inputs = [key for key in points if key != model["outcome"]]
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
def models():
    values = []
    directory = Path(__file__).resolve().parents[1] / "resources" / "ssvc"
    for path in sorted(directory.glob("*.json")):
        model = json.loads(path.read_bytes())
        validate_model(model)
        values.append({**model, "id": model_id(model), "sha256": digest(canonical(model))})
    return tuple(values)


def evaluate(selection: SsvcInput, *, submit=False):
    model = next(
        (
            item
            for item in models()
            if item["id"] == selection.model and item["version"] == selection.version
        ),
        None,
    )
    if not model or model["sha256"] != selection.model_sha256:
        raise ValueError("Unsupported or changed SSVC model; reload its exact version and hash")
    inputs = {
        key: point for key, point in model["decision_points"].items() if key != model["outcome"]
    }
    for key, value in selection.answers.items():
        if key not in inputs or value not in {item["key"] for item in inputs[key]["values"]}:
            raise ValueError("Invalid SSVC decision point or answer")
    complete = set(selection.answers) == set(inputs)
    if submit and not complete:
        raise ValueError("Submitting SSVC requires an explicit answer for every decision point")
    outcome = None
    label = None
    if complete:
        row = next(
            row
            for row in model["mapping"]
            if all(row[key] == value for key, value in selection.answers.items())
        )
        outcome = row[model["outcome"]]
        label = next(
            item["name"]
            for item in model["decision_points"][model["outcome"]]["values"]
            if item["key"] == outcome
        )
    return {
        "selection": selection.model_dump(mode="json"),
        "model_sha256": model["sha256"],
        "complete": complete,
        "outcome": outcome,
        "outcome_label": label,
    }


def workspace_summary(coverage):
    latest = (coverage.get("assessment") or {}).get("payload", {}).get("ssvc")
    approved = (
        (coverage.get("approved_assessment") or {}).get("payload", {}).get("ssvc")
        if coverage.get("approved")
        else None
    )
    pending = bool(coverage.get("pending_revision") and latest != approved)
    status = "missing"
    if latest or approved:
        status = (
            "pending"
            if pending
            else (
                "approved"
                if approved
                else {"draft": "draft", "submitted": "submitted"}.get(
                    coverage.get("status"), "stale"
                )
            )
        )
    return {"current": latest, "approved": approved, "pending": pending, "status": status}


def action(summary):
    record = summary.get("approved")
    if not record and summary.get("status") in {"draft", "submitted"}:
        record = summary.get("current")
    return (
        (record.get("outcome_label") or "").upper().replace("-", "_").replace(" ", "_")
        if record
        else ""
    )
