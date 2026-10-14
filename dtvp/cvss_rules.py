"""Version-aware CVSS transformations retained from v1; no DT persistence or writes."""

from typing import Any

from cvss import CVSS2, CVSS3, CVSS4


class RescoreRuleError(ValueError):
    """A rescore rule or vector cannot be applied safely."""


def validate_rescore_rule_config(config: dict[str, Any] | None) -> list[str]:
    """Return human-readable schema errors for the data-driven CVSS rules."""
    if not isinstance(config, dict):
        return ["Rescore rules must be a JSON object"]

    metric_rules = config.get("metric_rules")
    transitions = config.get("transitions")
    errors: list[str] = []
    if not isinstance(metric_rules, dict) or not metric_rules:
        errors.append("metric_rules must be a non-empty object")
        metric_rules = {}
    if not isinstance(transitions, list):
        errors.append("transitions must be an array")
        transitions = []

    for version, rule in metric_rules.items():
        path = f"metric_rules.{version}"
        if not isinstance(rule, dict):
            errors.append(f"{path} must be an object")
            continue
        for key in ("undefined_values", "base_metrics", "metric_order", "relationships"):
            if not isinstance(rule.get(key), list) or not rule.get(key):
                errors.append(f"{path}.{key} must be a non-empty array")

        base_metrics = set(rule.get("base_metrics") or [])
        metric_order = set(rule.get("metric_order") or [])
        seen_modified: set[str] = set()
        seen_requirements: set[str] = set()
        for index, relationship in enumerate(rule.get("relationships") or []):
            rel_path = f"{path}.relationships[{index}]"
            if not isinstance(relationship, dict) or not relationship.get("base"):
                errors.append(f"{rel_path}.base is required")
                continue
            base = relationship["base"]
            if base not in base_metrics:
                errors.append(f"{rel_path}.base must reference a configured base metric")
            for field, seen in (
                ("modified", seen_modified),
                ("requirement", seen_requirements),
            ):
                metric = relationship.get(field)
                if not metric:
                    continue
                if metric not in metric_order:
                    errors.append(f"{rel_path}.{field} must appear in metric_order")
                if metric in seen:
                    errors.append(f"{rel_path}.{field} is duplicated")
                seen.add(metric)

    for index, transition in enumerate(transitions):
        path = f"transitions[{index}]"
        if not isinstance(transition, dict):
            errors.append(f"{path} must be an object")
            continue
        state = (transition.get("trigger") or {}).get("state") or transition.get("from")
        if not state:
            errors.append(f"{path} must define trigger.state")
        actions = transition.get("actions")
        if not isinstance(actions, dict):
            errors.append(f"{path}.actions must be an object")
            continue
        for version, version_actions in actions.items():
            if version not in metric_rules:
                errors.append(f"{path}.actions.{version} has no matching metric_rules entry")
            if not isinstance(version_actions, dict):
                errors.append(f"{path}.actions.{version} must be an object")
                continue
            if version not in metric_rules:
                continue
            known_metrics = set((metric_rules.get(version) or {}).get("metric_order") or [])
            for metric, value in version_actions.items():
                if metric not in known_metrics:
                    errors.append(
                        f"{path}.actions.{version}.{metric} is not declared in metric_order"
                    )
                if not isinstance(value, str) or not value:
                    errors.append(f"{path}.actions.{version}.{metric} must be a non-empty string")
    return errors


def _detect_version(vector: str) -> str:
    normalized = vector.strip().lstrip("(")
    if normalized.startswith("CVSS:4.0/"):
        return "4.0"
    if normalized.startswith("CVSS:3.1/"):
        return "3.1"
    if normalized.startswith("CVSS:3.0/"):
        return "3.0"
    if normalized.startswith("CVSS:2.0/") or normalized.startswith("AV:"):
        return "2.0"
    raise RescoreRuleError("Unsupported or missing CVSS vector version")


def _parse_vector(vector: str) -> tuple[str, str | None, dict[str, str]]:
    normalized = vector.strip().replace("(", "").replace(")", "")
    version = _detect_version(normalized)
    parts = normalized.split("/")
    prefix = parts.pop(0) if parts and parts[0].startswith("CVSS:") else None
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise RescoreRuleError(f"Invalid CVSS token: {part}")
        key, value = part.split(":", 1)
        if not key or not value:
            raise RescoreRuleError(f"Invalid CVSS token: {part}")
        metrics[key] = value
    return version, prefix, metrics


def _serialize_vector(
    version: str,
    prefix: str | None,
    metrics: dict[str, str],
    metric_rule: dict[str, Any],
) -> str:
    order = metric_rule.get("metric_order") or []
    ordered_keys = [key for key in order if key in metrics]
    ordered_keys.extend(key for key in metrics if key not in ordered_keys)
    parts = [f"{key}:{metrics[key]}" for key in ordered_keys]
    if version != "2.0":
        parts.insert(0, prefix or f"CVSS:{version}")
    return "/".join(parts)


def _transition_for_state(config: dict[str, Any], state: str) -> dict[str, Any] | None:
    normalized_state = str(state or "").strip().upper()
    for transition in config.get("transitions") or []:
        trigger_state = (transition.get("trigger") or {}).get("state") or transition.get("from")
        if str(trigger_state or "").strip().upper() == normalized_state:
            return transition
    return None


def _transition_actions(config: dict[str, Any], state: str, version: str) -> dict[str, str] | None:
    transition = _transition_for_state(config, state)
    if transition:
        actions = (transition.get("actions") or {}).get(version)
        return actions if isinstance(actions, dict) else None
    return None


def _is_defined(value: str | None, undefined_values: set[str]) -> bool:
    return bool(value and value not in undefined_values)


def build_rescored_vector_for_state(
    config: dict[str, Any],
    *,
    state: str,
    base_vector: str,
    current_vector: str | None = None,
    validate_config: bool = True,
) -> tuple[str, str] | None:
    """Build a compliant vector using only relationships declared in config."""
    if validate_config:
        errors = validate_rescore_rule_config(config)
        if errors:
            raise RescoreRuleError("; ".join(errors))

    base_version, base_prefix, base_metrics = _parse_vector(base_vector)
    actions = _transition_actions(config, state, base_version)
    if not actions:
        return None

    metric_rule = config["metric_rules"][base_version]
    missing_base = [key for key in metric_rule["base_metrics"] if not base_metrics.get(key)]
    if missing_base:
        raise RescoreRuleError(
            f"Base vector is missing required metrics: {', '.join(missing_base)}"
        )

    if current_vector:
        current_version, current_prefix, metrics = _parse_vector(current_vector)
        if current_version != base_version:
            raise RescoreRuleError(
                f"Current CVSS {current_version} vector does not match base CVSS {base_version}"
            )
        prefix = current_prefix or base_prefix
    else:
        metrics = dict(base_metrics)
        prefix = base_prefix

    # Rescoring may never change the base metrics supplied by Dependency-Track.
    for key in metric_rule["base_metrics"]:
        metrics[key] = base_metrics[key]

    undefined_values = set(metric_rule["undefined_values"])
    relationships = metric_rule["relationships"]
    by_modified = {
        relationship["modified"]: relationship
        for relationship in relationships
        if relationship.get("modified")
    }
    by_requirement = {
        relationship["requirement"]: relationship
        for relationship in relationships
        if relationship.get("requirement")
    }

    requirement_actions: list[tuple[str, str]] = []
    for key, value in actions.items():
        if key in by_requirement:
            requirement_actions.append((key, value))
            continue
        relationship = by_modified.get(key)
        if relationship:
            base_value = metrics.get(relationship["base"])
            if _is_defined(base_value, undefined_values) and value != base_value:
                metrics[key] = value
            else:
                metrics.pop(key, None)
            continue
        if value in undefined_values:
            metrics.pop(key, None)
        else:
            metrics[key] = value

    for key, value in requirement_actions:
        relationship = by_requirement[key]
        base_value = metrics.get(relationship["base"])
        modified_key = relationship.get("modified")
        applies = _is_defined(base_value, undefined_values)
        if modified_key:
            modified_value = metrics.get(modified_key)
            applies = (
                applies
                and _is_defined(modified_value, undefined_values)
                and modified_value != base_value
            )
        if applies and value not in undefined_values:
            metrics[key] = value
        else:
            metrics.pop(key, None)

    metrics = {key: value for key, value in metrics.items() if value not in undefined_values}
    return _serialize_vector(base_version, prefix, metrics, metric_rule), base_version


def calculate_cvss_score(vector: str, version: str | None = None) -> float:
    version = version or _detect_version(vector)
    normalized = vector
    if version == "2.0" and normalized.startswith("CVSS:2.0/"):
        normalized = normalized[len("CVSS:2.0/") :]
    if version == "2.0":
        scores = CVSS2(normalized).scores()
    elif version in {"3.0", "3.1"}:
        scores = CVSS3(normalized).scores()
    elif version == "4.0":
        scores = CVSS4(normalized).scores()
    else:
        raise RescoreRuleError(f"Unsupported CVSS version: {version}")
    return float(next(score for score in reversed(scores) if score is not None))
