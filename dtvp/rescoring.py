"""Contextual scores are reviewed proposals; original Base facts never change."""

import importlib
from pathlib import Path

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from dtvp.cvss_rules import (
    calculate_cvss_score,
    validate_rescore_rule_config,
)

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
