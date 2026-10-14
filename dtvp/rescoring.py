"""Contextual scores are reviewed proposals; original Base facts never change."""

import importlib
import json
from pathlib import Path

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from fastapi import HTTPException

from dtvp.cvss_rules import (
    build_rescored_vector_for_state,
    calculate_cvss_score,
    validate_rescore_rule_config,
)
from dtvp.models import Evidence, Job, Release, RescorePolicy, Snapshot
from dtvp.storage import Artifacts, canonical, digest

BASE = {
    "2.0": {"AV", "AC", "Au", "C", "I", "A"},
    "3.0": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
    "3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
    "4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
}
DEFAULT_PATH = Path(__file__).parent / "defaults" / "rescore_rules.json"


def parse_vector(vector):
    if not isinstance(vector, str) or len(vector) > 1024:
        raise ValueError("Supply a supported CVSS vector")
    version = vector.split("/")[0].removeprefix("CVSS:") if vector.startswith("CVSS:") else "2.0"
    if version not in BASE:
        raise ValueError("Supported CVSS versions: 2.0, 3.0, 3.1 and 4.0")
    raw = vector.removeprefix("CVSS:2.0/")
    try:
        parsed = CVSS2(raw) if version == "2.0" else CVSS4(raw) if version == "4.0" else CVSS3(raw)
    except CVSSError as error:
        raise ValueError(str(error)) from None
    fields = raw.split("/")[1:] if raw.startswith("CVSS:") else raw.split("/")
    metrics = dict(field.split(":", 1) for field in fields)
    if len(metrics) != len(fields):
        raise ValueError("Duplicate CVSS metrics")
    return version, parsed, metrics


def base_fact(vector, score=None):
    try:
        version, parsed, metrics = parse_vector(vector)
        if set(metrics) != BASE[version]:
            return None
        value = float(parsed.scores()[0])
        if score is not None and (
            not isinstance(score, (int, float)) or isinstance(score, bool) or float(score) != value
        ):
            return None
        return {"vector": parsed.clean_vector(), "version": version, "score": value}
    except ValueError, TypeError, KeyError:
        return None


def original_vectors(assertions):
    values = {}
    for assertion in assertions:
        for rating in assertion.get("ratings", []):
            fact = base_fact(rating.get("vector", ""), rating.get("score"))
            if fact:
                values[fact["vector"]] = fact
    return list(values.values())


def calculate(base_vector, vector):
    base_version, baseline, base_metrics = parse_vector(base_vector)
    version, parsed, metrics = parse_vector(vector)
    if (
        set(base_metrics) != BASE[base_version]
        or version != base_version
        or any(metrics.get(key) != base_metrics[key] for key in BASE[version])
    ):
        raise ValueError(
            "Contextual rescoring must retain every original Base metric and CVSS version"
        )
    return {
        "base_vector": baseline.clean_vector(),
        "vector": parsed.clean_vector(),
        "version": version,
        "base_score": float(baseline.scores()[0]),
        "score": calculate_cvss_score(vector, version),
    }


def policy(db, project_id):
    row = db.get(RescorePolicy, project_id)
    config = row.config if row else json.loads(DEFAULT_PATH.read_text())
    return {
        "version": row.version if row else 0,
        "config": config,
        "digest": digest(canonical(config)),
    }


def validate_policy(config):
    errors = validate_rescore_rule_config(config)
    for version, rule in config.get("metric_rules", {}).items():
        if (
            version not in BASE
            or not isinstance(rule, dict)
            or set(rule.get("base_metrics", [])) != BASE.get(version)
        ):
            errors.append(f"metric_rules.{version} must preserve the specification's Base metrics")
        if version in BASE and isinstance(rule, dict):
            constants = importlib.import_module(f"cvss.constants{version[0]}")
            if set(rule.get("metric_order", [])) != set(constants.METRICS_ABBREVIATIONS):
                errors.append(
                    f"metric_rules.{version}.metric_order must enumerate the specification's metrics"
                )
    triggers = [
        str((row.get("trigger") or {}).get("state") or row.get("from"))
        for row in config.get("transitions", [])
        if isinstance(row, dict)
    ]
    if len(set(triggers)) != len(triggers):
        errors.append("Each transition state must be unique")
    for row in config.get("transitions", []):
        if not isinstance(row, dict) or not isinstance(row.get("actions"), dict):
            continue
        for version, actions in row["actions"].items():
            if version not in BASE or not isinstance(actions, dict):
                continue
            constants = importlib.import_module(f"cvss.constants{version[0]}")
            for metric, value in actions.items():
                allowed = constants.METRICS_VALUE_NAMES.get(metric, {})
                if metric in BASE[version] or value not in allowed:
                    errors.append(f"Invalid contextual action {version}/{metric}:{value}")
    if errors:
        raise ValueError("; ".join(errors))


def evidence_candidate(db, finding, evidence_id, detail):
    record = db.get(Evidence, evidence_id)
    if not record or record.finding_id != finding.id:
        raise HTTPException(404, "Evidence unavailable for this occurrence")
    assertion = record.assertion
    reason = ""
    vector, base, supplied_score = "", "", None
    if record.source == "agentyzer" and assertion.get("kind") == "code-analysis":
        if (
            assertion.get("rescoring_eligible") is not True
            or assertion.get("target_verified") is not True
        ):
            reason = "Agentyzer did not verify eligibility and the exact package/version"
        job = db.get(Job, assertion.get("job_id", ""))
        if (
            not job
            or job.kind != "analyse"
            or job.status != "succeeded"
            or job.payload.get("finding_id") != finding.id
            or job.result.get("evidence_id") != record.id
            or job.result.get("report_sha256") != assertion.get("report_sha256")
        ):
            reason = "No verified Agentyzer run exists for this occurrence"
        if not reason:
            report = json.loads(Artifacts(db.info["artifact_dir"]).read(assertion["report_sha256"]))
            adjusted = report.get("assessment", {}).get("adjusted_cvss") or {}
            vector, base, supplied_score = (
                adjusted.get("adjusted_vector", ""),
                adjusted.get("original_vector", ""),
                adjusted.get("adjusted_score"),
            )
    elif record.source == "vscorer" and assertion.get("kind") == "contextual-assessment":
        vector, base, supplied_score = (
            assertion.get("environmental_vector", ""),
            assertion.get("base_vector", ""),
            assertion.get("environmental_score"),
        )
        snapshot = db.get(Snapshot, record.snapshot_id) if record.snapshot_id else None
        frozen = (
            json.loads(Artifacts(db.info["artifact_dir"]).read(snapshot.sha)) if snapshot else {}
        )
        original = next((f for f in frozen.get("findings", []) if f["id"] == finding.id), None)
        if not original or record.input_revision != original["evidence_revision"]:
            reason = "VScorer snapshot inputs no longer match the finding"
    else:
        reason = "Evidence does not contain a supported rescoring proposal"
    if record.published_revision is None or record.published_revision != finding.evidence_revision:
        reason = "Evidence changed after this result; request a current assessment"
    proposal = None
    if not reason:
        try:
            proposal = calculate(base, vector)
            if proposal["base_vector"] not in {
                entry["vector"] for entry in detail["original_vectors"]
            }:
                raise ValueError("Original Base vector is not current source evidence")
            if supplied_score is not None and (
                not isinstance(supplied_score, (int, float))
                or isinstance(supplied_score, bool)
                or float(supplied_score) != proposal["score"]
            ):
                raise ValueError("Reported score disagrees with the vector calculation")
        except (ValueError, TypeError, KeyError) as error:
            reason = str(error)
    return {
        "id": record.id,
        "source": record.source,
        "eligible": not bool(reason),
        "reason": reason,
        "rationale": assertion.get("rationale", assertion.get("summary", "")),
        "proposal": proposal if not reason else None,
    }


def prepare(db, finding, detail, request, state):
    kind = request["kind"]
    reason = request.get("rationale", "").strip()
    if not reason:
        raise ValueError("Explain the contextual score and its supporting evidence")
    metadata = {"kind": kind, "rationale": reason}
    if kind == "evidence":
        candidate = evidence_candidate(db, finding, request.get("evidence_id"), detail)
        if not candidate["eligible"]:
            raise ValueError(candidate["reason"])
        value = candidate["proposal"]
        metadata.update(source=candidate["source"], evidence_id=candidate["id"])
    else:
        base = request.get("base_vector", "")
        if base not in {entry["vector"] for entry in detail["original_vectors"]}:
            raise ValueError("Select an original Base vector from current source evidence")
        vector = request.get("vector", "")
        if kind == "rule":
            release = db.get(Release, finding.release_id)
            configured = policy(db, release.project_id)
            if request.get("policy_digest") != configured["digest"]:
                raise HTTPException(409, "Rescoring rules changed; preview again")
            transitions = {
                "affected": "EXPLOITABLE",
                "not_affected": "NOT_AFFECTED",
                "fixed": "RESOLVED",
                "under_investigation": "IN_TRIAGE",
            }
            trigger = transitions[state]
            if request.get("rule_basis") == "false_positive":
                if state != "not_affected":
                    raise ValueError("The false-positive rule requires not-affected applicability")
                trigger = "FALSE_POSITIVE"
            metadata["rule_basis"] = request.get("rule_basis", "applicability")
            initial = request.get("vector") or base
            initial = calculate(base, initial)["vector"]
            metadata.update(rule_config=configured["config"], input_vector=initial)
            result = build_rescored_vector_for_state(
                configured["config"], state=trigger, base_vector=base, current_vector=initial
            )
            if not result:
                raise ValueError("No rule exists for this applicability and CVSS version")
            vector = result[0]
            metadata.update(
                policy_digest=configured["digest"],
                policy_version=configured["version"],
                rule_state=state,
            )
        value = calculate(base, vector)
    return {**value, **metadata}


def preview_digest(finding, state, proposal):
    return digest(
        canonical(
            {
                "finding_id": finding.id,
                "state_version": finding.state_version,
                "state": state,
                "rescoring": proposal,
            }
        )
    )
