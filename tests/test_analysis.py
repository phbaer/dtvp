"""Native-shared Agentyzer evidence eligibility without the retired SQL runtime."""

import pytest

from dtvp.analysis import normalize

SOURCE_COMMIT = "a" * 40


def bound_target():
    return {
        "package_name": "demo-http",
        "version": "1.2.0",
        "source_binding": {
            "status": "known",
            "source_commit": SOURCE_COMMIT,
        },
    }


def report(**changes):
    return {
        "source_input": {
            "binding": "verified_git_commit",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": SOURCE_COMMIT,
            "artifact_verified": False,
        },
        "assessment": {
            "application_eligible": True,
            "rescoring_eligible": False,
            "affected": True,
            "analysis": "EXPLOITABLE",
            "verdict": "Affected",
            "summary": "Reachable dependency",
            "reasoning": "Repository evidence",
            "version_analysis": {
                "detected_version": "1.2.0",
                "comparison_inputs": {"component_name": "demo-http"},
            },
            **changes,
        },
        "steps": [],
    }


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, "affected"),
        ({"application_eligible": "true"}, None),
        ({"affected": False, "analysis": "NOT_AFFECTED"}, None),
        (
            {
                "affected": False,
                "analysis": "NOT_AFFECTED",
                "code_coverage": {"permits_exclusion": True},
            },
            "not_affected",
        ),
        (
            {
                "affected": False,
                "analysis": "IN_TRIAGE",
                "code_coverage": {"permits_exclusion": True},
            },
            None,
        ),
        ({"affected": None}, None),
        (
            {
                "version_analysis": {
                    "detected_version": "9.0.0",
                    "comparison_inputs": {"component_name": "demo-http"},
                }
            },
            None,
        ),
        (
            {
                "version_analysis": {
                    "detected_version": "1.2.0",
                    "comparison_inputs": {"component_name": "other-package"},
                }
            },
            None,
        ),
    ],
)
def test_proposals_require_explicit_eligibility_and_exclusion_coverage(changes, expected):
    assert normalize(report(**changes), bound_target())["proposal_state"] == expected


@pytest.mark.parametrize(
    "source",
    [
        None,
        {},
        {
            "binding": "observed_git_head",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": SOURCE_COMMIT,
        },
        {
            "binding": "verified_git_commit",
            "requested_commit": "b" * 40,
            "resolved_commit": SOURCE_COMMIT,
        },
        {
            "binding": "verified_git_commit",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": "b" * 40,
        },
        {"binding": "verified_git_commit", "requested_commit": SOURCE_COMMIT},
    ],
)
def test_source_provenance_must_match_both_requested_and_resolved_commit(source):
    data = report(rescoring_eligible=True)
    if source is None:
        data.pop("source_input")
    else:
        data["source_input"] = source
    normalized = normalize(data, bound_target())
    assert normalized["source_verified"] is False
    assert normalized["application_eligible"] is False
    assert normalized["rescoring_eligible"] is False
    assert normalized["proposal_state"] is None
    assert normalized["ineligibility_reasons"]


def test_provider_cannot_invent_requested_binding_or_claim_artifact_equivalence():
    target = bound_target()
    target["source_binding"] = {
        "status": "unknown",
        "source_commit": None,
        "reason": "No qualified source",
    }
    result = normalize(report(), target)
    assert not result["source_verified"] and not result["application_eligible"]
    known = normalize(report(), bound_target())
    assert known["source_verified"] and known["application_eligible"]
    assert "artifact_verified" not in known or known["artifact_verified"] is not True
