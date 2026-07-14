import re
from typing import Any, Iterable

from cvss import CVSS2, CVSS3, CVSS4


_RE_SCORE = re.compile(r"\[Rescored:\s*([\d.]+)\]")
_RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")


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
                    errors.append(
                        f"{path}.actions.{version}.{metric} must be a non-empty string"
                    )
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


def _transition_actions(
    config: dict[str, Any], state: str, version: str
) -> dict[str, str] | None:
    for transition in config.get("transitions") or []:
        trigger_state = (transition.get("trigger") or {}).get("state") or transition.get("from")
        if trigger_state == state:
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
    missing_base = [
        key for key in metric_rule["base_metrics"] if not base_metrics.get(key)
    ]
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

    metrics = {
        key: value for key, value in metrics.items() if value not in undefined_values
    }
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


def _extract_score(details: str) -> float | None:
    match = _RE_SCORE.search(details)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _extract_vector(details: str) -> str | None:
    match = _RE_VECTOR.search(details)
    return match.group(1).strip() if match else None


def replace_rescoring_tags(
    details: str, *, vector: str, score: float
) -> str:
    """Replace the first score/vector tags in place and remove duplicates."""
    score_tag = f"[Rescored: {score:.1f}]"
    vector_tag = f"[Rescored Vector: {vector}]"

    def replace_once(pattern: re.Pattern[str], source: str, replacement: str) -> tuple[str, bool]:
        replaced = False

        def substitute(_match: re.Match[str]) -> str:
            nonlocal replaced
            if replaced:
                return ""
            replaced = True
            return replacement

        return pattern.sub(substitute, source), replaced

    updated, had_score = replace_once(_RE_SCORE, details or "", score_tag)
    updated, had_vector = replace_once(_RE_VECTOR, updated, vector_tag)
    if had_score and not had_vector:
        updated = updated.replace(score_tag, f"{score_tag} {vector_tag}", 1)
    elif had_vector and not had_score:
        updated = updated.replace(vector_tag, f"{score_tag} {vector_tag}", 1)
    elif not had_score and not had_vector:
        updated = f"{score_tag} {vector_tag}\n\n{updated}".strip()
    return re.sub(r"[ \t]+\n", "\n", updated)


def _iter_group_components(
    groups: Iterable[dict[str, Any]],
) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for group in groups:
        for affected_version in group.get("affected_versions") or []:
            for component in affected_version.get("components") or []:
                if isinstance(component, dict):
                    yield group, component


def _finding_identity(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_uuid": component.get("finding_uuid"),
        "project_uuid": component.get("project_uuid"),
        "project_name": component.get("project_name"),
        "project_version": component.get("project_version"),
        "component_uuid": component.get("component_uuid"),
        "component_name": component.get("component_name"),
        "component_version": component.get("component_version"),
        "vulnerability_uuid": component.get("vulnerability_uuid"),
    }


def _evaluate_component(
    config: dict[str, Any], group: dict[str, Any], component: dict[str, Any]
) -> dict[str, Any] | None:
    state = component.get("analysis_state") or component.get("analysisState") or "NOT_SET"
    base_vector = group.get("cvss_vector")
    if not base_vector:
        return None
    try:
        version = _detect_version(str(base_vector))
    except RescoreRuleError:
        return None
    if not _transition_actions(config, state, version):
        return None

    details = component.get("analysis_details") or component.get("analysisDetails") or ""
    current_vector = _extract_vector(details)
    current_score = _extract_score(details)
    finding = {**_finding_identity(component), "state": state, "cvss_version": version}
    try:
        result = build_rescored_vector_for_state(
            config,
            state=state,
            base_vector=str(base_vector),
            current_vector=current_vector,
            validate_config=False,
        )
        if result is None:
            return None
        proposed_vector, version = result
        proposed_score = calculate_cvss_score(proposed_vector, version)
    except (RescoreRuleError, ValueError, StopIteration) as exc:
        return {
            **finding,
            "status": "review",
            "reasons": [str(exc)],
            "current_vector": current_vector,
            "current_score": current_score,
            "proposed_vector": None,
            "proposed_score": None,
        }

    vector_matches = current_vector == proposed_vector
    score_matches = current_score is not None and abs(current_score - proposed_score) < 0.05
    if vector_matches and score_matches:
        return {**finding, "status": "compliant"}

    reasons: list[str] = []
    if not current_vector:
        reasons.append("Missing rescored vector")
    elif not vector_matches:
        reasons.append("Vector does not match the configured rule")

    _current_version, _current_prefix, current_metrics = _parse_vector(
        current_vector or str(base_vector)
    )
    _proposed_version, _proposed_prefix, proposed_metrics = _parse_vector(proposed_vector)
    requirement_keys = {
        relationship["requirement"]
        for relationship in config["metric_rules"][version]["relationships"]
        if relationship.get("requirement")
    }
    missing_requirements = sorted(
        key for key in requirement_keys if key in proposed_metrics and key not in current_metrics
    )
    if missing_requirements:
        reasons.append(f"Missing requirements: {', '.join(missing_requirements)}")
    if not score_matches:
        reasons.append("Missing or stale rescored score")

    has_identity = all(
        component.get(key)
        for key in ("project_uuid", "component_uuid", "vulnerability_uuid")
    )
    return {
        **finding,
        "status": "ready" if has_identity else "review",
        "reasons": reasons if has_identity else [*reasons, "Finding identity is incomplete"],
        "current_vector": current_vector or str(base_vector),
        "current_score": current_score,
        "proposed_vector": proposed_vector,
        "proposed_score": proposed_score,
    }


def build_rescore_rule_sync_preview(
    groups: list[dict[str, Any]],
    config: dict[str, Any],
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    errors = validate_rescore_rule_config(config)
    if errors:
        raise RescoreRuleError("; ".join(errors))

    wanted = {str(group_id) for group_id in group_ids or []}
    selected = (
        [group for group in groups if str(group.get("id") or "") in wanted]
        if group_ids is not None
        else groups
    )
    grouped: dict[str, dict[str, Any]] = {}
    summary = {
        "groups": 0,
        "findings": 0,
        "syncable_groups": 0,
        "syncable_findings": 0,
        "review_findings": 0,
        "compliant_findings": 0,
    }
    for group, component in _iter_group_components(selected):
        finding = _evaluate_component(config, group, component)
        if not finding:
            continue
        if finding["status"] == "compliant":
            summary["compliant_findings"] += 1
            continue

        group_id = str(group.get("id") or "")
        if not group_id:
            continue
        item = grouped.setdefault(
            group_id,
            {
                "group_id": group_id,
                "title": group.get("title"),
                "severity": group.get("severity"),
                "finding_count": 0,
                "syncable_finding_count": 0,
                "review_finding_count": 0,
                "findings": [],
            },
        )
        item["findings"].append(finding)
        item["finding_count"] += 1
        summary["findings"] += 1
        if finding["status"] == "ready":
            item["syncable_finding_count"] += 1
            summary["syncable_findings"] += 1
        else:
            item["review_finding_count"] += 1
            summary["review_findings"] += 1

    items = sorted(grouped.values(), key=lambda item: item["group_id"])
    summary["groups"] = len(items)
    summary["syncable_groups"] = sum(
        1 for item in items if item["syncable_finding_count"] > 0
    )
    return {"items": items, "summary": summary}


def build_rescore_rule_sync_payloads(
    groups: list[dict[str, Any]],
    config: dict[str, Any],
    group_ids: list[str] | None = None,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    errors = validate_rescore_rule_config(config)
    if errors:
        raise RescoreRuleError("; ".join(errors))
    wanted = {str(group_id) for group_id in group_ids or []}
    selected = (
        [group for group in groups if str(group.get("id") or "") in wanted]
        if group_ids is not None
        else groups
    )
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {"review_required": 0, "unchanged": 0}
    for group, component in _iter_group_components(selected):
        finding = _evaluate_component(config, group, component)
        if not finding or finding["status"] == "compliant":
            continue
        if finding["status"] != "ready":
            skipped["review_required"] += 1
            continue
        details = component.get("analysis_details") or component.get("analysisDetails") or ""
        updated_details = replace_rescoring_tags(
            details,
            vector=finding["proposed_vector"],
            score=finding["proposed_score"],
        )
        if updated_details == details:
            skipped["unchanged"] += 1
            continue
        payloads.append(
            (
                component,
                {
                    "project_uuid": component["project_uuid"],
                    "component_uuid": component["component_uuid"],
                    "vulnerability_uuid": component["vulnerability_uuid"],
                    "state": component.get("analysis_state") or "NOT_SET",
                    "details": updated_details,
                    "justification": component.get("justification"),
                    "suppressed": bool(component.get("is_suppressed", False)),
                },
            )
        )
    return payloads, skipped
