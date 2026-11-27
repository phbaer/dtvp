"""The lifecycle decision table (docs/assessment-model.md#lifecycle-decision-table).

The cases in ``lifecycle_cases.json`` are read by the web client's tests as
well (``lifecycleCases.spec.ts``): the server and the client classify a
vulnerability by the same rules, and every row of the table has a case.
"""

import json
from pathlib import Path

import pytest

from dtvp.assessment_use_cases import approval_blocker
from dtvp.bulk_workflows.automatic_assessments import VERDICT_PRIORITY, verdict_state
from dtvp.logic import (
    STATE_ORDER,
    calculate_aggregated_state,
    parse_assessment_blocks,
    with_derived_global_block,
)
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.task_group_query_services import (
    build_task_group_query_index,
    query_task_groups,
)

# The file stays inside the frontend tree: the Docker image builds the
# frontend without the repository's tests/ folder.
FIXTURES = Path(__file__).resolve().parents[1] / "frontend" / "src" / "lib" / "__tests__" / "fixtures"
CASES = json.loads((FIXTURES / "lifecycle_cases.json").read_text())
RULES = {f"R{number}" for number in range(1, 12)}


def _group(case, group_id="CVE-CASE"):
    tags = list(case["tags"])
    group = {
        "id": group_id,
        "title": group_id,
        "tags": tags,
        "affected_versions": [
            {
                "project_name": "Project",
                "project_version": instance["project_version"],
                "components": [{
                    "component_name": "library", "tags": tags,
                    "justification": "NOT_SET", **instance,
                }],
            }
            for instance in case["instances"]
        ],
    }
    return summarize_grouped_vulnerabilities([group], case.get("team_mapping") or {})[0]


def test_every_rule_of_the_table_has_a_case():
    assert {case["rule"] for case in CASES} == RULES


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_lifecycle_is_as_the_decision_table_says(case):
    metadata = _group(case)["list_metadata"]

    assert metadata["lifecycle"] == case["lifecycle"]
    assert metadata["is_pending"] is case["is_pending"]
    assert metadata["is_approval_ready"] is case["is_approval_ready"]
    assert metadata["inconsistency_reasons"] == case["inconsistency_reasons"]
    assert metadata["covers_all_teams"] is case["covers_all_teams"]
    decision = case["global_decision"]
    assert metadata["global_decision_source"] == decision["source"]
    assert metadata["global_decision_state"] == decision["state"]
    assert metadata["global_decision_justification"] == decision["justification"]
    assert metadata["global_decision_teams"] == decision["teams"]
    assert metadata["derived_global_state"] == decision["derived_state"]
    assert metadata["derived_global_teams"] == decision["derived_teams"]
    # Dependency-Track receives the effective decision as the finding's
    # state (of findings that agree; conflicting ones differ by definition).
    for instance in case["instances"] if case["lifecycle"] != "INCONSISTENT" else []:
        if instance["analysis_details"] and decision["source"] != "none":
            assert calculate_aggregated_state(instance["analysis_details"]) == decision["state"]


def test_one_worst_state_order_on_both_sides():
    order = json.loads((FIXTURES / "state_order.json").read_text())
    assert list(STATE_ORDER) == order
    # The analyzer's verdicts map onto the same order.
    verdicts = sorted(VERDICT_PRIORITY, key=VERDICT_PRIORITY.get, reverse=True)
    states = [verdict_state(verdict) for verdict in verdicts]
    assert states == sorted(states, key=order.index)


@pytest.mark.parametrize(("left", "right", "expected"), [
    ("FALSE_POSITIVE", "NOT_AFFECTED", "NOT_AFFECTED"),
    ("FALSE_POSITIVE", "RESOLVED", "RESOLVED"),
    ("NOT_AFFECTED", "RESOLVED", "RESOLVED"),
    ("RESOLVED", "IN_TRIAGE", "IN_TRIAGE"),
    ("IN_TRIAGE", "EXPLOITABLE", "EXPLOITABLE"),
    ("FALSE_POSITIVE", "NOT_SET", "FALSE_POSITIVE"),
])
def test_completed_assessment_priority_in_derived_and_exported_decisions(left, right, expected):
    for first, second in ((left, right), (right, left)):
        text = (
            f"--- [Team: A] [State: {first}] ---\nFirst.\n\n"
            f"--- [Team: B] [State: {second}] ---\nSecond."
        )
        assert calculate_aggregated_state(text) == expected
        approved = with_derived_global_block(text, "reviewer", 1794000000000)
        general = next(block for block in parse_assessment_blocks(approved)[1] if block["team"] == "General")
        assert general["state"] == expected
        # An explicit reviewer decision continues to take precedence.
        assert calculate_aggregated_state(
            text + "\n\n--- [Team: General] [State: FALSE_POSITIVE] ---\nReviewed."
        ) == "FALSE_POSITIVE"


def test_an_approval_records_the_derived_decision_as_the_general_block():
    text = (
        "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.\n\n"
        "--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] [Justification: NOT_SET] ---\nReachable."
    )

    approved = with_derived_global_block(text, "rita", 1794000000000)

    general = next(block for block in parse_assessment_blocks(approved)[1] if block["team"] == "General")
    assert (general["state"], general["justification"], general["user"]) == ("EXPLOITABLE", "NOT_SET", "rita")
    assert "Worst of the team assessments: TeamA." in approved
    assert calculate_aggregated_state(approved) == "EXPLOITABLE"
    # A reviewer's own General decision is left as it is.
    assert with_derived_global_block(approved, "other", 1) == approved


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_approval_is_possible_exactly_when_ready_for_approval(case):
    """The use case's check, on the stored texts, agrees with the table."""
    tags = list(case["tags"])
    instances = [{**instance, "tags": tags} for instance in case["instances"]]
    stored = [
        {"state": instance["analysis_state"], "details": instance["analysis_details"]}
        for instance in instances
    ]

    blocker = approval_blocker(instances, stored, case.get("team_mapping") or {})

    if case["approvable"] or not case["is_pending"]:
        # Nothing pending: an ordinary reviewer save, nothing to refuse.
        assert blocker is None
    else:
        assert blocker and blocker.startswith("Only a vulnerability that is ready for approval")


def _case(name):
    return next(case for case in CASES if case["name"] == name)


PENDING_GLOBAL = "pending global decision covers a team without its own assessment"


def test_a_pending_global_decision_is_ready_for_approval_and_approved_it_is_assessed():
    pending = _case(PENDING_GLOBAL)
    approved = _case("approved global decision covers a team without its own assessment")
    # The same assessment, with and without the pending-review marker.
    assert [i["analysis_details"].replace("\n\n[Status: Pending Review]", "") for i in pending["instances"]] == [
        i["analysis_details"] for i in approved["instances"]
    ]
    assert _group(pending)["list_metadata"]["lifecycle"] == "NEEDS_APPROVAL"
    assert _group(approved)["list_metadata"]["lifecycle"] == "ASSESSED"


def test_filters_facets_and_awaiting_review_follow_the_lifecycle():
    """Ready for approval, Awaiting review and their counts select the
    pending-global group; Incomplete no longer does."""
    groups = [
        _group(_case(PENDING_GLOBAL), "CVE-PENDING-GLOBAL"),
        _group(_case("pending, a team without a block and no General block"), "CVE-NO-GLOBAL"),
        _group(_case("pending, a team without a block and a General block without a decision"), "CVE-UNSET"),
        _group(_case("pending global decision, a team without a block and a finding without a state"), "CVE-FINDING"),
    ]
    index = build_task_group_query_index(groups)

    def ids(**overrides):
        options = {
            "q": "", "lifecycle": [], "analysis": [], "tag": "", "vuln_id": "",
            "component": "", "assignee": "", "dependency": [], "versions": [],
            "cvss_mismatch": False, "attributed_before_days": None,
            "attribution_mode": "older", "tmrescore": [], "tmrescore_proposal_ids": [],
            "sort_by": "id", "sort_order": "asc", "offset": 0, "limit": 50,
            **overrides,
        }
        return [item["id"] for item in query_task_groups(index, **options)["items"]]

    assert ids(lifecycle=["READY_FOR_APPROVAL"]) == ["CVE-PENDING-GLOBAL"]
    assert sorted(ids(lifecycle=["INCOMPLETE"])) == ["CVE-FINDING", "CVE-NO-GLOBAL", "CVE-UNSET"]
    assert len(ids(awaiting_review=True)) == 4
    counts = index["counts"]["lifecycle"]
    assert counts["READY_FOR_APPROVAL"] == 1
    assert counts["INCOMPLETE"] == 3
    assert counts["NEEDS_APPROVAL"] == 4  # the legacy filter value: every pending group
