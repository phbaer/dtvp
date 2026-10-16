"""Received evidence is distinct from jobs, approval and score publication."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.filters import KnowledgeFilters, filter_rows


@pytest.mark.parametrize("provider", ["agentyzer", "vscorer"])
def test_received_evidence_current_and_historical_are_independent_of_eligibility(provider):
    key = "code_analysis" if provider == "agentyzer" else "scoring_proposals"
    flag = "application_eligible" if provider == "agentyzer" else "eligible"
    field = provider + "_evidence"
    rows = [
        {"id": "missing"},
        {"id": "old", key: [{"provider": provider, "current": False, flag: True}]},
        {"id": "blocked", key: [{"provider": provider, "current": True, flag: False}]},
        {
            "id": "eligible",
            key: [
                {"provider": provider, "current": False, flag: False},
                {"provider": provider, "current": True, flag: True},
            ],
        },
        {"id": "unknown", key: [{"provider": provider, flag: True}]},
    ]
    before = copy.deepcopy(rows)
    expected = {
        "missing": ["missing"],
        "current": ["blocked", "eligible"],
        "historical_only": ["old"],
        "eligible": ["eligible"],
    }
    for value, identifiers in expected.items():
        assert [row["id"] for row in filter_rows(rows, {field: value})] == identifiers
    assert rows == before


@pytest.mark.parametrize("provider", ["agentyzer", "vscorer"])
@pytest.mark.parametrize("bad", [None, {}, "current", [None], [False]])
def test_malformed_collections_never_match_received_evidence(provider, bad):
    key = "code_analysis" if provider == "agentyzer" else "scoring_proposals"
    for value in ("missing", "current", "historical_only", "eligible"):
        assert not filter_rows([{key: bad}], {provider + "_evidence": value})


def test_strict_flags_and_provider_isolation_do_not_infer_approval_or_job_submission():
    row = {
        "scoring_proposals": [{"provider": "agentyzer", "current": True, "eligible": True}],
        "jobs": [{"provider": "vscorer", "status": "succeeded"}],
        "coverage": {"approved": True},
        "published_score": {"score": 0},
    }
    assert filter_rows([row], {"agentyzer_evidence": "missing", "vscorer_evidence": "missing"}) == [
        row
    ]
    for current, eligible in ((1, True), ("true", True), (True, 1), (True, "true")):
        assert not filter_rows(
            [{"code_analysis": [{"current": current, "application_eligible": eligible}]}],
            {"agentyzer_evidence": "eligible"},
        )
    assert not filter_rows(
        [{"code_analysis": [{"current": 0}]}], {"agentyzer_evidence": "historical_only"}
    )
    assert not filter_rows(
        [{"code_analysis": [{"current": False}, {}]}], {"agentyzer_evidence": "historical_only"}
    )


@pytest.mark.parametrize("provider", ["agentyzer", "vscorer"])
def test_unknown_received_evidence_filter_is_rejected(provider):
    with pytest.raises(ValidationError):
        KnowledgeFilters.model_validate({provider + "_evidence": "approved"})
