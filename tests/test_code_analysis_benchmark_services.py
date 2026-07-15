from dataclasses import dataclass

import pytest

from dtvp.code_analysis_benchmark_services import (
    _as_dict,
    _normalize_state,
    _recommendation,
    _select_human_block,
    _state_distance,
    _state_from_verdict,
    build_code_analysis_benchmark,
)


def _record(**summary_overrides):
    summary = {
        "analysis": "NOT_AFFECTED",
        "verdict": "Not Affected",
        "justification": "CODE_NOT_PRESENT",
        "confidence": "High",
        "summary": "The vulnerable parser package is absent.",
        "reasoning": "No vulnerable parser import exists in the source tree.",
        "adjusted_cvss_score": 0.0,
        "adjusted_cvss_vector": "CVSS:3.1/AV:N/AC:L/C:N",
        "versions_checked": ["1.0.0"],
        "step_count": 3,
    }
    summary.update(summary_overrides)
    return {
        "analysis_run_id": "run-1",
        "queue_id": "queue-1",
        "project_name": "Example",
        "vuln_id": "CVE-2026-0001",
        "component_name": "parser",
        "source": "benchmark",
        "summary": summary,
    }


def _assessment(**overrides):
    assessment = {
        "current_state": "NOT_AFFECTED",
        "current_justification": "CODE_NOT_PRESENT",
        "current_details": "The vulnerable parser package is absent from the source tree.",
        "current_cvss_score": 0.0,
        "current_cvss_vector": "cvss:3.1/av:n/ac:l/c:n",
    }
    assessment.update(overrides)
    return assessment


def _finding(result, title):
    return next(finding for finding in result["findings"] if finding["title"] == title)


def test_matching_benchmark_receives_top_rating_and_normalizes_vectors():
    result = build_code_analysis_benchmark(_record(), _assessment())

    assert result["rating"] == {
        "score": 5,
        "max_score": 5,
        "grade": "A",
        "label": "Strong match",
        "tone": "green",
    }
    assert result["deltas"]["state_match"] is True
    assert result["deltas"]["cvss_vector_match"] is True
    assert result["automated"]["source"] == "benchmark"
    assert "text_for_overlap" not in result["automated"]
    assert _finding(result, "Analyzer evidence is present")["severity"] == "info"
    assert result["recommendation"].startswith("The analysis result strongly agrees")


def test_semantically_aligned_safe_states_report_differences():
    result = build_code_analysis_benchmark(
        _record(
            analysis="NOT_AFFECTED",
            justification="CODE_NOT_REACHABLE",
            confidence="Medium",
            adjusted_cvss_score=4.0,
            adjusted_cvss_vector="CVSS:3.1/AV:L/AC:H/C:L",
            reasoning="Runtime guards prevent attacker controlled deserialization.",
        ),
        _assessment(
            current_state="FALSE_POSITIVE",
            current_details="Package metadata points at a scanner false positive.",
            current_cvss_score=7.5,
        ),
    )

    assert result["deltas"]["state_match"] is False
    assert result["deltas"]["state_family_match"] is True
    assert result["deltas"]["state_distance"] == 0
    assert _finding(result, "Assessment state is semantically aligned")
    assert _finding(result, "Justification differs")["severity"] == "warning"
    assert _finding(result, "CVSS scores differ")["severity"] == "high"
    assert _finding(result, "CVSS vectors differ")["severity"] == "info"
    assert _finding(result, "Reasoning overlap")["severity"] == "warning"
    assert _finding(result, "Analysis confidence is limited")["severity"] == "warning"


def test_unknown_baseline_reports_proposed_cvss():
    result = build_code_analysis_benchmark(
        _record(adjusted_cvss_score=6.4),
        {
            "current_state": "NOT_SET",
            "current_details": "",
        },
    )

    assert result["human"]["state_family"] == "unknown"
    assert _finding(result, "Existing assessment is unset")["severity"] == "warning"
    assert _finding(result, "Analysis result proposes CVSS")["severity"] == "info"
    assert result["deltas"]["cvss_delta"] is None
    assert result["deltas"]["reasoning_overlap"] is None


def test_inconclusive_result_is_penalized_without_being_a_contradiction():
    result = build_code_analysis_benchmark(
        _record(analysis="IN_TRIAGE", verdict="Inconclusive"),
        _assessment(),
    )

    assert result["deltas"]["state_distance"] == 1
    assert _finding(result, "One side is inconclusive")["severity"] == "warning"
    assert not any(
        finding["title"] == "Assessment states contradict"
        for finding in result["findings"]
    )


@pytest.mark.parametrize(
    ("human_state", "automated_state", "recommendation_fragment"),
    [
        ("NOT_AFFECTED", "EXPLOITABLE", "existing assessment may be stale"),
        ("EXPLOITABLE", "NOT_AFFECTED", "analysis may have missed evidence"),
    ],
)
def test_opposite_assessment_families_receive_contradiction_rating(
    human_state,
    automated_state,
    recommendation_fragment,
):
    result = build_code_analysis_benchmark(
        _record(
            analysis=automated_state,
            verdict=automated_state,
            justification="EXPLOITABLE_CODE",
            confidence="Low",
            adjusted_cvss_score=9.8,
        ),
        _assessment(current_state=human_state),
    )

    assert result["rating"]["score"] == 1
    assert result["rating"]["grade"] == "F"
    assert result["deltas"]["state_distance"] == 3
    assert _finding(result, "Assessment states contradict")["severity"] == "high"
    assert recommendation_fragment in result["recommendation"]


def test_benchmark_can_derive_human_fields_from_selected_team_block():
    details = """
--- [Team: General] [State: NOT_SET] ---
Unreviewed.
--- [Team: Payments] [State: RESOLVED] [Justification: CODE_NOT_REACHABLE] [Rescored: 2.1] [Rescored Vector: CVSS:3.1/AV:L] ---
The vulnerable endpoint is unreachable.
"""

    result = build_code_analysis_benchmark(
        _record(
            analysis="RESOLVED",
            justification="CODE_NOT_REACHABLE",
            adjusted_cvss_score=2.1,
            adjusted_cvss_vector="CVSS:3.1/AV:L",
        ),
        {"current_team": "payments", "current_details": details},
    )

    assert result["human"] == {
        "team": "payments",
        "state": "RESOLVED",
        "state_family": "not_affected",
        "justification": "CODE_NOT_REACHABLE",
        "cvss_score": 2.1,
        "cvss_vector": "CVSS:3.1/AV:L",
        "details_excerpt": "--- [Team: General] [State: NOT_SET] --- Unreviewed. --- [Team: Payments] [State: RESOLVED] [Justification: CODE_NOT_REACHABLE] [Rescored: 2.1] [Rescored Vector: CVSS:3.1/AV:L] --- The vulnerable endpoint is unreachable.",
        "has_details": True,
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("affected", "EXPLOITABLE"),
        ("not vulnerable", "NOT_AFFECTED"),
        ("falsepositive", "FALSE_POSITIVE"),
        ("unknown", "IN_TRIAGE"),
        ("unexpected", "NOT_SET"),
    ],
)
def test_normalize_state_aliases(value, expected):
    assert _normalize_state(value) == expected


@pytest.mark.parametrize(
    ("verdict", "affected", "expected"),
    [
        ("anything", True, "EXPLOITABLE"),
        ("false positive", None, "FALSE_POSITIVE"),
        ("fixed", None, "RESOLVED"),
        ("inconclusive", None, "IN_TRIAGE"),
        ("undetermined", False, "NOT_AFFECTED"),
        ("undetermined", None, "IN_TRIAGE"),
    ],
)
def test_state_from_verdict_aliases(verdict, affected, expected):
    assert _state_from_verdict(verdict, affected) == expected


def test_human_block_selection_falls_back_deterministically():
    general = "--- [Team: General] [State: NOT_SET] ---"
    reviewed = "--- [Team: API] [State: RESOLVED] ---"
    unset = "--- [Team: API] [State: NOT_SET] ---"

    assert _select_human_block("plain text", None) == {}
    assert _select_human_block(f"{reviewed}\n{general}", None)["Team"] == "General"
    assert _select_human_block(reviewed, None)["State"] == "RESOLVED"
    assert _select_human_block(unset, None)["State"] == "NOT_SET"


@dataclass
class _ModelDumpValue:
    value: object

    def model_dump(self):
        return self.value


class _LegacyDictValue:
    def __init__(self, value):
        self.value = value

    def dict(self):
        return self.value


def test_as_dict_supports_model_objects_and_rejects_non_mappings():
    assert _as_dict(_ModelDumpValue({"value": 1})) == {"value": 1}
    assert _as_dict(_LegacyDictValue({"value": 2})) == {"value": 2}
    assert _as_dict(_ModelDumpValue(["not", "a", "mapping"])) == {}
    assert _as_dict(_LegacyDictValue("not a mapping")) == {}
    assert _as_dict(object()) == {}


def test_distance_and_recommendation_fallback_helpers():
    assert _state_distance("affected", "other") == 2
    assert "broadly aligned" in _recommendation(4, "affected", "affected")
    assert "partial match" in _recommendation(3, "affected", "affected")
    assert "Do not auto-adopt" in _recommendation(2, "unknown", "unknown")
