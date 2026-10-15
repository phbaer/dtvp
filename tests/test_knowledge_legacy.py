"""Historical DT prose is evidence, never a new authenticated team approval."""

import copy
import json

import pytest

from dtvp.knowledge.legacy import MAX_ANALYSIS_BYTES, MAX_DEPTH, MAX_PROPERTIES, legacy_claims
from dtvp.rescoring import calculate
from tests.test_rescoring import BASE, VECTOR


def observation(analysis, **changes):
    return {
        "observation_id": "dt-finding",
        "source": "Dependency-Track",
        "identifier": "CVE-2099-10001",
        "ref": "library",
        "advisory": {
            "ratings": [{"vector": BASE, "score": 9.8}],
            "properties": [{"name": "dtvp:dt-analysis", "value": json.dumps(analysis)}],
        },
        **changes,
    }


def test_tagged_v1_history_and_identity_labels_retained_without_human_approval():
    text = """Shared context.
--- [Team: Alpha] [State: not_affected] [Assessed By: Alice] [Reviewed By: Bob] [Date: 1700000000000] [Justification: code_not_reachable] ---
Documented deployment excludes this path.
--- [Team: Alpha] [State: affected] [Historical: Yes] [Copied From: 7.1.0] ---
Previous deployment exposed this path.
"""
    analysis = {
        "analysisState": "NOT_AFFECTED",
        "analysisDetails": text,
        "analysisComments": [{"comment": "Original reviewer comment", "commenter": "Bob"}],
    }
    original = observation(analysis)
    before = copy.deepcopy(original)
    claim = legacy_claims([original])[0]
    assert original == before
    assert claim["status"] == "parsed" and claim["legacy_format"] == "dtvp-tags"
    assert claim["raw_text"] == text
    assert claim["comments"] == analysis["analysisComments"]
    assert len(claim["records"]) == 3
    alpha = next(record for record in claim["current_records"] if record["team"] == "Alpha")
    assert alpha["assessor"] == "Alice" and alpha["reviewer"] == "Bob"
    assert alpha["identity_gaps"] == []
    assert not alpha["approved"] and not alpha["authenticated_identity"]
    assert (
        next(record for record in claim["records"] if record["historical"])["copied_from"]
        == "7.1.0"
    )
    assert claim["proposed_applicability"] == "not_affected"
    assert claim["original_source_ref"]["observation_id"] == "dt-finding"
    assert claim["original_source_ref"]["retained_in"] == "sourcefacts"


def test_plain_legacy_and_missing_metadata_do_not_invent_authors_or_review():
    plain = "Plain documentation, without DTVP metadata.\nDo not rewrite this prose."
    claim = legacy_claims(
        [observation({"analysisState": "EXPLOITABLE", "analysisDetails": plain})]
    )[0]
    assert claim["raw_text"] == plain
    assert claim["legacy_format"] == "plain-dt"
    assert claim["proposed_applicability"] == "affected"
    record = claim["records"][0]
    assert record["team"] == "General"
    assert record["identity_gaps"] == ["assessor", "reviewer"]
    assert record["assessor"] is record["reviewer"] is None
    missing = legacy_claims([observation({"analysisState": "NOT_AFFECTED"})])[0]
    assert missing["proposed_applicability"] == "not_affected"
    assert not missing["documented"]
    assert missing["records"][0]["rationale"] == ""
    assert not missing["approved"]


def test_comments_only_and_empty_analysis_remain_explicit():
    comments = [
        {"comment": "Legacy comment without a state", "timestamp": 1, "commenter": "Unknown user"}
    ]
    claim = legacy_claims([observation({"analysisComments": comments})])[0]
    assert claim["comments"] == comments
    assert claim["proposed_applicability"] is None
    assert claim["status"] == "parsed"
    assert legacy_claims([observation({})])[0]["status"] == "empty"


def test_conflicting_team_and_general_assertions_are_not_global_decisions():
    text = """--- [Team: General] [State: not_affected] ---
Global source assertion.
--- [Team: Alpha] [State: affected] [Status: Pending Review] ---
Team disagrees.
--- [Team: Beta] [State: not_affected] ---
Other context.
"""
    claim = legacy_claims(
        [observation({"analysisDetails": text, "analysisState": "NOT_AFFECTED"})]
    )[0]
    assert claim["conflicting"] and claim["pending_review"]
    assert claim["proposed_applicability"] is None
    assert claim["source_applicability"] == "not_affected"
    assert {record["team"] for record in claim["current_records"]} == {"General", "Alpha", "Beta"}
    assert not claim["approved"]


@pytest.mark.parametrize(
    ("vector", "score", "usable", "blocker"),
    [
        (VECTOR, calculate(BASE, VECTOR)["score"], True, None),
        (None, 2.0, False, "legacy_score_without_vector"),
        ("CVSS:9.0/unknown", 2.0, False, "legacy_vector_unsupported_or_original_base_mismatch"),
        (
            VECTOR.replace("AV:N", "AV:P"),
            2.0,
            False,
            "legacy_vector_unsupported_or_original_base_mismatch",
        ),
        (VECTOR, 4.2, False, "legacy_score_vector_mismatch"),
    ],
)
def test_legacy_scores_are_only_explicit_proposals_never_source_base(
    vector, score, usable, blocker
):
    text = (
        f"[Team: Alpha] [Rescored: {score}]"
        + (f" [Rescored Vector: {vector}]" if vector else "")
        + "\nReason."
    )
    original = observation({"analysisDetails": text, "analysisState": "EXPLOITABLE"})
    claim = legacy_claims([original])[0]
    proposal = claim["scoring_proposals"][0]
    assert proposal["usable_for_preview"] is usable
    assert not proposal["eligible"] and proposal["requires_coordinator_publication"]
    assert original["advisory"]["ratings"][0]["score"] == 9.8
    assert original["advisory"]["ratings"][0]["vector"] == BASE
    if blocker:
        assert blocker in proposal["blockers"]


@pytest.mark.parametrize("raw", ["not JSON", "[]", '{"analysisDetails": 3}', None])
def test_malformed_legacy_fields_retained_explicitly_without_crashing(raw):
    value = observation({})
    value["advisory"]["properties"][0]["value"] = raw
    claim = legacy_claims([value])[0]
    assert claim["status"] == "unparsed"
    assert claim["errors"] and claim["original_retained"]
    assert claim["proposed_applicability"] is None


def test_nesting_size_and_property_limits_remain_visible():
    nested = {}
    for _ in range(MAX_DEPTH + 2):
        nested = {"nested": nested}
    assert legacy_claims([observation(nested)])[0]["status"] == "limited"
    huge = observation({"analysisDetails": "x" * MAX_ANALYSIS_BYTES})
    assert legacy_claims([huge])[0]["status"] == "limited"
    repeated = observation({"analysisState": "EXPLOITABLE"})
    repeated["advisory"]["properties"] *= MAX_PROPERTIES + 2
    claims = legacy_claims([repeated])
    assert len(claims) == MAX_PROPERTIES + 1
    assert claims[-1]["status"] == "limited"
    assert "remaining originals retained" in claims[-1]["errors"][0]


def test_nested_ssvc_content_cannot_create_hidden_team_claims_or_break_serialization():
    text = '[SSVC Details]\n{"note":"--- [Team: Hidden] [State: affected] ---"}\n[/SSVC Details]\nPlain comment'
    claim = legacy_claims(
        [observation({"analysisDetails": text, "analysisState": "NOT_AFFECTED"})]
    )[0]
    assert not any(record["team"] == "Hidden" for record in claim["records"])
    assert claim["ssvc"] == [{"note": "--- [Team: Hidden] [State: affected] ---"}]
    nested = "[" * (MAX_DEPTH + 10) + "0" + "]" * (MAX_DEPTH + 10)
    text = "[SSVC Details]\n" + nested + "\n[/SSVC Details]"
    assert (
        legacy_claims([observation({"analysisDetails": text, "analysisState": "NOT_AFFECTED"})])[0][
            "status"
        ]
        == "limited"
    )


def test_multiple_dt_properties_are_not_silently_discarded():
    value = observation({"analysisState": "EXPLOITABLE", "analysisDetails": "First source history"})
    second = observation(
        {"analysisState": "NOT_AFFECTED", "analysisDetails": "Second source history"}
    )
    value["advisory"]["properties"].extend(second["advisory"]["properties"])
    claims = legacy_claims([value])
    assert len(claims) == 2
    assert {claim["proposed_applicability"] for claim in claims} == {"affected", "not_affected"}
    assert claims[0]["id"] != claims[1]["id"]
