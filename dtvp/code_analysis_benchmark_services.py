import re
from datetime import UTC, datetime
from typing import Any, Optional

from .code_analysis_result_services import summarize_code_analysis_result


BENCHMARK_SCHEMA_VERSION = "dtvp.code-analysis-benchmark/v1"

KNOWN_STATES = {
    "NOT_SET",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "IN_TRIAGE",
    "EXPLOITABLE",
}

SAFE_STATES = {"NOT_AFFECTED", "FALSE_POSITIVE", "RESOLVED"}
TRIAGE_STATES = {"IN_TRIAGE", "NOT_SET"}
STATE_FAMILIES = {
    "EXPLOITABLE": "affected",
    "IN_TRIAGE": "inconclusive",
    "NOT_SET": "unknown",
    "NOT_AFFECTED": "not_affected",
    "FALSE_POSITIVE": "not_affected",
    "RESOLVED": "not_affected",
}

STOPWORDS = {
    "about",
    "after",
    "also",
    "from",
    "have",
    "into",
    "only",
    "that",
    "their",
    "there",
    "this",
    "with",
    "were",
    "will",
    "would",
    "vulnerability",
    "component",
    "analysis",
    "assessment",
    "result",
    "reasoning",
    "summary",
}


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _upper_token(value: Any) -> str:
    return re.sub(r"[^A-Z0-9_]+", "_", _text(value).upper()).strip("_")


def _parse_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _extract_tag(text: str, tag: str) -> str:
    match = re.search(rf"\[{re.escape(tag)}:\s*([^\]]+)\]", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _parse_block_headers(details: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for header in re.findall(r"---\s*((?:\[[^\]]+\]\s*)+)---", details or ""):
        parsed: dict[str, str] = {}
        for key, value in re.findall(r"\[([\w\s]+):\s*([^\]]+)\]", header):
            parsed[key.strip()] = value.strip()
        if parsed:
            blocks.append(parsed)
    return blocks


def _select_human_block(details: str, team: Optional[str]) -> dict[str, str]:
    blocks = _parse_block_headers(details)
    if not blocks:
        return {}

    normalized_team = _text(team).lower()
    if normalized_team:
        for block in blocks:
            if _text(block.get("Team")).lower() == normalized_team:
                return block

    for block in blocks:
        if _text(block.get("Team")).lower() == "general":
            return block

    for block in blocks:
        state = _normalize_state(block.get("State"))
        if state != "NOT_SET":
            return block

    return blocks[0]


def _normalize_state(value: Any) -> str:
    token = _upper_token(value)
    if token in KNOWN_STATES:
        return token
    if token in {"AFFECTED", "VULNERABLE"}:
        return "EXPLOITABLE"
    if token in {"NOT_AFFECTED", "NOTAFFECTED", "NOT_VULNERABLE"}:
        return "NOT_AFFECTED"
    if token in {"FALSE_POSITIVE", "FALSEPOSITIVE"}:
        return "FALSE_POSITIVE"
    if token in {"TRIAGE", "INCONCLUSIVE", "UNKNOWN"}:
        return "IN_TRIAGE"
    return "NOT_SET"


def _state_family(state: str) -> str:
    return STATE_FAMILIES.get(_normalize_state(state), "unknown")


def _state_from_verdict(verdict: Any, affected: Any = None) -> str:
    token = _upper_token(verdict)
    if affected is True or token in {"AFFECTED", "EXPLOITABLE", "VULNERABLE"}:
        return "EXPLOITABLE"
    if token in {"NOT_AFFECTED", "NOTAFFECTED", "NOT_VULNERABLE"}:
        return "NOT_AFFECTED"
    if token in {"FALSE_POSITIVE", "FALSEPOSITIVE"}:
        return "FALSE_POSITIVE"
    if token in {"RESOLVED", "FIXED"}:
        return "RESOLVED"
    if token in {"IN_TRIAGE", "TRIAGE", "INCONCLUSIVE", "UNKNOWN"}:
        return "IN_TRIAGE"
    if affected is False:
        return "NOT_AFFECTED"
    return "IN_TRIAGE"


def _justification_from_exposure(exposure: Any) -> str:
    normalized = _text(exposure).lower()
    if normalized in {"none", "not present", "code not present"}:
        return "CODE_NOT_PRESENT"
    if "not reachable" in normalized or "unreachable" in normalized:
        return "CODE_NOT_REACHABLE"
    return "NOT_SET"


def _normalize_justification(value: Any) -> str:
    token = _upper_token(value)
    return token or "NOT_SET"


def _vector(value: Any) -> str:
    return re.sub(r"\s+", "", _text(value)).upper()


def _details_excerpt(value: Any, limit: int = 360) -> str:
    text = re.sub(r"\s+", " ", _text(value))
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _tokens(value: Any) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_]{4,}", _text(value).lower())
        if token not in STOPWORDS
    }


def _reasoning_overlap(human_text: str, automated_text: str) -> Optional[float]:
    human_tokens = _tokens(human_text)
    automated_tokens = _tokens(automated_text)
    if not human_tokens or not automated_tokens:
        return None
    return len(human_tokens & automated_tokens) / len(human_tokens | automated_tokens)


def _confidence_penalty(confidence: str) -> float:
    normalized = confidence.lower()
    if normalized == "low":
        return 0.5
    if normalized == "medium":
        return 0.25
    return 0.0


def _state_distance(human_family: str, automated_family: str) -> int:
    if human_family == automated_family:
        return 0
    if "unknown" in {human_family, automated_family}:
        return 1
    if "inconclusive" in {human_family, automated_family}:
        return 1
    if {human_family, automated_family} == {"affected", "not_affected"}:
        return 3
    return 2


def _score_to_grade(score: int) -> str:
    return {5: "A", 4: "B", 3: "C", 2: "D", 1: "F"}[score]


def _score_label(score: int) -> str:
    return {
        5: "Strong match",
        4: "Good match",
        3: "Partial match",
        2: "Weak match",
        1: "Contradiction",
    }[score]


def _score_tone(score: int) -> str:
    return {
        5: "green",
        4: "cyan",
        3: "amber",
        2: "orange",
        1: "red",
    }[score]


def _recommendation(score: int, human_family: str, automated_family: str) -> str:
    if score >= 5:
        return "The analysis result strongly agrees with the existing vulnerability assessment."
    if score == 4:
        return "The analysis result is broadly aligned; review the listed differences before adopting details or rescoring."
    if score == 3:
        return "Treat this as a partial match and review the state, evidence, and rescoring differences manually."
    if human_family == "not_affected" and automated_family == "affected":
        return "The existing assessment may be stale or incorrect; review it before closing or suppressing this vulnerability."
    if human_family == "affected" and automated_family == "not_affected":
        return "The analysis may have missed evidence, or the existing assessment may be outdated; review both before lowering severity."
    return "Do not auto-adopt this result; use it as a disagreement requiring reviewer judgment."


def _append_finding(
    findings: list[dict[str, str]],
    *,
    kind: str,
    severity: str,
    title: str,
    detail: str,
) -> None:
    findings.append(
        {
            "kind": kind,
            "severity": severity,
            "title": title,
            "detail": detail,
        }
    )


def _human_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    details = _text(snapshot.get("current_details"))
    team = _text(snapshot.get("current_team")) or None
    block = _select_human_block(details, team)

    state = _normalize_state(snapshot.get("current_state") or block.get("State"))
    justification = _normalize_justification(
        snapshot.get("current_justification")
        or block.get("Justification")
        or _extract_tag(details, "Justification")
    )
    rescored = _parse_float(
        snapshot.get("current_cvss_score")
        if snapshot.get("current_cvss_score") not in (None, "")
        else block.get("Rescored") or _extract_tag(details, "Rescored")
    )
    vector = _text(
        snapshot.get("current_cvss_vector")
        or block.get("Rescored Vector")
        or _extract_tag(details, "Rescored Vector")
    )

    return {
        "team": team or block.get("Team") or "General",
        "state": state,
        "state_family": _state_family(state),
        "justification": justification,
        "cvss_score": rescored,
        "cvss_vector": vector,
        "details_excerpt": _details_excerpt(details),
        "has_details": bool(details),
    }


def _automated_snapshot(record: dict[str, Any]) -> dict[str, Any]:
    result = _as_dict(record.get("result"))
    summary = _as_dict(record.get("summary"))
    if not summary and result:
        summary = summarize_code_analysis_result(result)
    assessment = _as_dict(result.get("assessment"))

    state = _normalize_state(summary.get("analysis") or assessment.get("analysis"))
    if state == "NOT_SET":
        state = _state_from_verdict(
            summary.get("verdict") or assessment.get("verdict"),
            summary.get("affected") if "affected" in summary else assessment.get("affected"),
        )

    justification = _normalize_justification(
        summary.get("justification")
        or assessment.get("justification")
        or _justification_from_exposure(summary.get("exposure") or assessment.get("exposure"))
    )
    automated_text = "\n".join(
        part
        for part in (
            summary.get("summary"),
            summary.get("reasoning"),
            summary.get("details"),
            summary.get("cvss_summary"),
            " ".join(str(reason) for reason in summary.get("cvss_reasons") or []),
        )
        if _text(part)
    )

    return {
        "state": state,
        "state_family": _state_family(state),
        "justification": justification,
        "cvss_score": _parse_float(
            summary.get("adjusted_cvss_score")
            if summary.get("adjusted_cvss_score") not in (None, "")
            else summary.get("cvss_score")
        ),
        "cvss_vector": _text(
            summary.get("adjusted_cvss_vector") or summary.get("cvss_vector")
        ),
        "verdict": _text(summary.get("verdict") or assessment.get("verdict")),
        "confidence": _text(summary.get("confidence") or assessment.get("confidence")),
        "exposure": _text(summary.get("exposure") or assessment.get("exposure")),
        "summary_excerpt": _details_excerpt(summary.get("summary")),
        "reasoning_excerpt": _details_excerpt(summary.get("reasoning")),
        "versions_checked": summary.get("versions_checked") or [],
        "step_count": summary.get("step_count") or 0,
        "source": record.get("source") or "manual",
        "text_for_overlap": automated_text,
    }


def build_code_analysis_benchmark(
    record: dict[str, Any],
    current_assessment: dict[str, Any],
) -> dict[str, Any]:
    human = _human_snapshot(current_assessment)
    automated = _automated_snapshot(record)

    human_family = human["state_family"]
    automated_family = automated["state_family"]
    distance = _state_distance(human_family, automated_family)
    state_match = distance == 0 and human["state"] == automated["state"]
    state_family_match = distance == 0
    justification_match = (
        human["justification"] == automated["justification"]
        or "NOT_SET" in {human["justification"], automated["justification"]}
    )
    cvss_delta = None
    if human["cvss_score"] is not None and automated["cvss_score"] is not None:
        cvss_delta = abs(float(human["cvss_score"]) - float(automated["cvss_score"]))
    vector_match = (
        bool(human["cvss_vector"])
        and bool(automated["cvss_vector"])
        and _vector(human["cvss_vector"]) == _vector(automated["cvss_vector"])
    )
    overlap = _reasoning_overlap(
        current_assessment.get("current_details") or "",
        automated["text_for_overlap"],
    )

    findings: list[dict[str, str]] = []
    penalty = 0.0

    if human_family == "unknown":
        penalty += 1.75
        _append_finding(
            findings,
            kind="baseline",
            severity="warning",
            title="Existing assessment is unset",
            detail="The current assessment is NOT_SET or missing, so the rating mostly reflects evidence completeness rather than agreement.",
        )
    elif distance == 0:
        if human["state"] == automated["state"]:
            _append_finding(
                findings,
                kind="state",
                severity="info",
                title="Assessment state matches",
                detail=f"Both assessments resolve to {human['state']}.",
            )
        else:
            penalty += 0.35
            _append_finding(
                findings,
                kind="state",
                severity="info",
                title="Assessment state is semantically aligned",
                detail=f"Existing state {human['state']} and analysis-result state {automated['state']} are both {human_family.replace('_', ' ')} outcomes.",
            )
        if human_family == "inconclusive":
            penalty += 0.75
    elif distance == 1:
        penalty += 1.4
        _append_finding(
            findings,
            kind="state",
            severity="warning",
            title="One side is inconclusive",
            detail=f"Existing state is {human['state']} while the analysis-result state is {automated['state']}.",
        )
    elif distance == 3:
        penalty += 3.1
        _append_finding(
            findings,
            kind="state",
            severity="high",
            title="Assessment states contradict",
            detail=f"Existing state is {human['state']} while the analysis-result state is {automated['state']}.",
        )
    else:
        penalty += 2.2
        _append_finding(
            findings,
            kind="state",
            severity="warning",
            title="Assessment states differ",
            detail=f"Existing state is {human['state']} while the analysis-result state is {automated['state']}.",
        )

    if not justification_match:
        penalty += 0.45
        _append_finding(
            findings,
            kind="justification",
            severity="warning",
            title="Justification differs",
            detail=f"Existing justification is {human['justification']}; analysis-result justification is {automated['justification']}.",
        )

    if cvss_delta is not None:
        if cvss_delta >= 3.0:
            penalty += 0.9
            severity = "high"
        elif cvss_delta >= 1.0:
            penalty += 0.45
            severity = "warning"
        else:
            severity = "info"
        _append_finding(
            findings,
            kind="cvss",
            severity=severity,
            title="CVSS scores differ",
            detail=f"Existing score {human['cvss_score']} vs analysis-result score {automated['cvss_score']} (difference {cvss_delta:.1f}).",
        )
    elif automated["cvss_score"] is not None and human["cvss_score"] is None:
        _append_finding(
            findings,
            kind="cvss",
            severity="info",
            title="Analysis result proposes CVSS",
            detail=f"Analysis-result score is {automated['cvss_score']}; no existing rescored value is set.",
        )

    if human["cvss_vector"] and automated["cvss_vector"] and not vector_match:
        penalty += 0.2
        _append_finding(
            findings,
            kind="cvss_vector",
            severity="info",
            title="CVSS vectors differ",
            detail="The existing and analysis-result CVSS vectors are not identical.",
        )

    if overlap is not None:
        if overlap < 0.15:
            penalty += 0.45
            severity = "warning"
        elif overlap < 0.35:
            penalty += 0.2
            severity = "info"
        else:
            severity = "info"
        _append_finding(
            findings,
            kind="reasoning",
            severity=severity,
            title="Reasoning overlap",
            detail=f"Keyword overlap between existing assessment details and analysis reasoning is {overlap:.0%}.",
        )

    confidence = automated["confidence"]
    confidence_penalty = _confidence_penalty(confidence)
    if confidence_penalty:
        penalty += confidence_penalty
        _append_finding(
            findings,
            kind="confidence",
            severity="warning",
            title="Analysis confidence is limited",
            detail=f"Analyzer reported {confidence or 'unknown'} confidence.",
        )

    if automated["step_count"] or automated["versions_checked"]:
        _append_finding(
            findings,
            kind="evidence",
            severity="info",
            title="Analyzer evidence is present",
            detail=f"{automated['step_count']} pipeline step(s), {len(automated['versions_checked'])} checked version(s).",
        )

    score = max(1, min(5, round(5 - penalty)))

    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "comparison_method": "deterministic_fallback",
        "evaluator": {
            "provider": "dtvp",
            "probabilistic": False,
            "available": False,
            "reason": "Agentyzer probabilistic benchmark comparison was not used.",
        },
        "analysis_run_id": record.get("analysis_run_id"),
        "queue_id": record.get("queue_id"),
        "project_name": record.get("project_name"),
        "vuln_id": record.get("vuln_id"),
        "component_name": record.get("component_name"),
        "compared_at": _utc_now_iso(),
        "rating": {
            "score": score,
            "max_score": 5,
            "grade": _score_to_grade(score),
            "label": _score_label(score),
            "tone": _score_tone(score),
        },
        "human": human,
        "automated": {key: value for key, value in automated.items() if key != "text_for_overlap"},
        "deltas": {
            "state_match": state_match,
            "state_family_match": state_family_match,
            "state_distance": distance,
            "justification_match": justification_match,
            "cvss_delta": cvss_delta,
            "cvss_vector_match": vector_match if human["cvss_vector"] and automated["cvss_vector"] else None,
            "reasoning_overlap": overlap,
        },
        "findings": findings,
        "recommendation": _recommendation(score, human_family, automated_family),
    }
