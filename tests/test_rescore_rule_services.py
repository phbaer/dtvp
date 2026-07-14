import json
from pathlib import Path

import pytest

from dtvp.rescore_rule_services import (
    RescoreRuleError,
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
    build_rescored_vector_for_state,
    calculate_cvss_score,
    replace_rescoring_tags,
    validate_rescore_rule_config,
)


@pytest.fixture
def rules():
    return json.loads(Path("data/rescore_rules.json").read_text())


@pytest.mark.parametrize(
    ("version", "vector", "expected_metrics"),
    [
        (
            "4.0",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            (
                "MVC:N",
                "MVI:N",
                "MVA:N",
                "MSC:N",
                "MSI:N",
                "MSA:N",
                "CR:L",
                "IR:L",
                "AR:L",
            ),
        ),
        (
            "3.1",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ("MC:N", "MI:N", "MA:N", "CR:L", "IR:L", "AR:L"),
        ),
        (
            "3.0",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ("MC:N", "MI:N", "MA:N", "CR:L", "IR:L", "AR:L"),
        ),
        (
            "2.0",
            "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            ("CDP:N", "TD:N", "CR:L", "IR:L", "AR:L"),
        ),
    ],
)
def test_build_rescored_vector_uses_configured_relationships(
    rules, version, vector, expected_metrics
):
    result = build_rescored_vector_for_state(
        rules,
        state="NOT_AFFECTED",
        base_vector=vector,
        current_vector=vector,
    )

    assert result is not None
    rescored_vector, detected_version = result
    assert detected_version == version
    for metric in expected_metrics:
        assert metric in rescored_vector
    assert calculate_cvss_score(rescored_vector, version) == 0.0


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    ],
)
@pytest.mark.parametrize("state", ["NOT_AFFECTED", "FALSE_POSITIVE"])
def test_every_shipped_transition_produces_zero_score(rules, vector, state):
    result = build_rescored_vector_for_state(
        rules,
        state=state,
        base_vector=vector,
    )

    assert result is not None
    rescored_vector, version = result
    assert calculate_cvss_score(rescored_vector, version) == 0.0


def test_requirement_relationships_are_not_inferred_from_metric_names(rules):
    confidentiality = next(
        relationship
        for relationship in rules["metric_rules"]["3.1"]["relationships"]
        if relationship.get("requirement") == "CR"
    )
    confidentiality["requirement"] = "RC"
    actions = rules["transitions"][0]["actions"]["3.1"]
    actions.pop("CR")
    actions["RC"] = "C"

    result = build_rescored_vector_for_state(
        rules,
        state="NOT_AFFECTED",
        base_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )

    assert result is not None
    assert "MC:N" in result[0]
    assert "RC:C" in result[0]
    assert "CR:" not in result[0]


def test_sync_preview_detects_missing_requirements_and_builds_payload(rules):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    stale = f"{vector}/MC:N/MI:N/MA:N"
    group = {
        "id": "CVE-2026-0001",
        "title": "Example",
        "severity": "LOW",
        "cvss_vector": vector,
        "affected_versions": [
            {
                "components": [
                    {
                        "finding_uuid": "finding-1",
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": (
                            f"[Rescored: 9.8] [Rescored Vector: {stale}]\n\nKeep this text."
                        ),
                        "justification": "CODE_NOT_PRESENT",
                        "is_suppressed": True,
                    }
                ]
            }
        ],
    }

    preview = build_rescore_rule_sync_preview([group], rules)

    assert preview["summary"]["syncable_groups"] == 1
    finding = preview["items"][0]["findings"][0]
    assert finding["status"] == "ready"
    assert "Missing requirements: AR, CR, IR" in finding["reasons"]
    assert "/CR:L/IR:L/AR:L/" in finding["proposed_vector"]

    payloads, skipped = build_rescore_rule_sync_payloads([group], rules)
    assert skipped == {"review_required": 0, "unchanged": 0}
    assert len(payloads) == 1
    payload = payloads[0][1]
    assert "[Rescored Vector:" in payload["details"]
    assert "CR:L/IR:L/AR:L" in payload["details"]
    assert "Keep this text." in payload["details"]
    assert payload["justification"] == "CODE_NOT_PRESENT"
    assert payload["suppressed"] is True


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    ],
)
@pytest.mark.parametrize("state", ["NOT_AFFECTED", "FALSE_POSITIVE"])
def test_bulk_sync_writes_zero_score_for_every_shipped_transition(
    rules, vector, state
):
    group = {
        "id": "CVE-2026-ZERO",
        "cvss_vector": vector,
        "affected_versions": [
            {
                "components": [
                    {
                        "finding_uuid": "finding-1",
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": state,
                        "analysis_details": "Keep this text.",
                    }
                ]
            }
        ],
    }

    preview = build_rescore_rule_sync_preview([group], rules)
    finding = preview["items"][0]["findings"][0]
    assert finding["status"] == "ready"
    assert finding["proposed_score"] == 0.0

    payloads, skipped = build_rescore_rule_sync_payloads([group], rules)
    assert skipped == {"review_required": 0, "unchanged": 0}
    assert "[Rescored: 0.0]" in payloads[0][1]["details"]


def test_sync_preview_marks_cross_version_vectors_for_review(rules):
    group = {
        "id": "CVE-2026-0002",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_versions": [
            {
                "components": [
                    {
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": (
                            "[Rescored: 8.0] "
                            "[Rescored Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N]"
                        ),
                    }
                ]
            }
        ],
    }

    preview = build_rescore_rule_sync_preview([group], rules)

    finding = preview["items"][0]["findings"][0]
    assert finding["status"] == "review"
    assert "does not match base" in finding["reasons"][0]


def test_config_validation_requires_metric_rules(rules):
    rules.pop("metric_rules")

    assert validate_rescore_rule_config(rules) == [
        "metric_rules must be a non-empty object",
        "transitions[0].actions.4.0 has no matching metric_rules entry",
        "transitions[0].actions.3.1 has no matching metric_rules entry",
        "transitions[0].actions.3.0 has no matching metric_rules entry",
        "transitions[0].actions.2.0 has no matching metric_rules entry",
        "transitions[1].actions.4.0 has no matching metric_rules entry",
        "transitions[1].actions.3.1 has no matching metric_rules entry",
        "transitions[1].actions.3.0 has no matching metric_rules entry",
        "transitions[1].actions.2.0 has no matching metric_rules entry",
    ]
    with pytest.raises(RescoreRuleError, match="metric_rules"):
        build_rescore_rule_sync_preview([], rules)


def test_replace_rescoring_tags_updates_in_place_without_losing_details():
    details = (
        "Before [Rescored: 9.8] [Rescored Vector: old] after\n"
        "[Rescored: 1.0] [Rescored Vector: duplicate]"
    )

    updated = replace_rescoring_tags(details, vector="new", score=2.4)

    assert updated.count("[Rescored:") == 1
    assert updated.count("[Rescored Vector:") == 1
    assert "Before [Rescored: 2.4] [Rescored Vector: new] after" in updated

    zero_score = replace_rescoring_tags("Details", vector="new", score=0.0)
    assert "[Rescored: 0.0]" in zero_score
