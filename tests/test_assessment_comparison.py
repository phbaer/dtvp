"""What the findings of a vulnerability must agree on, and what each keeps.

Historical blocks are records of single findings. They do not make the
findings disagree, and Synchronize neither copies them to other findings nor
takes one for a team's current assessment.
"""

import json
from pathlib import Path

import pytest

from dtvp.bulk_workflows.assessment_repair import (
    build_assessment_repair_payloads,
    build_assessment_repair_preview,
)
from dtvp.bulk_workflows.base import BulkWorkflowContext
from dtvp.bulk_workflows.incomplete_sync import build_incomplete_sync_payloads
from dtvp.grouped_vuln_services import (
    comparable_assessment_text,
    summarize_grouped_vulnerabilities,
)
from dtvp.logic import calculate_aggregated_state, parse_assessment_blocks

# Read by the web client's tests as well (assessmentScopeCases.spec.ts). The
# file stays inside the frontend tree: the Docker image builds the frontend
# without the repository's tests/ folder.
CASES = json.loads(
    (
        Path(__file__).resolve().parents[1] / "frontend" / "src" / "lib" / "__tests__"
        / "fixtures" / "assessment_scope_cases.json"
    ).read_text()
)


def _group(instances, tags=("TeamB",), group_id="CVE-CASE"):
    group = {
        "id": group_id,
        "title": group_id,
        "tags": list(tags),
        "affected_versions": [
            {
                "project_name": "Project",
                "project_version": instance["project_version"],
                "components": [{
                    "component_name": "library", "tags": list(tags),
                    "justification": "NOT_SET", **instance,
                }],
            }
            for instance in instances
        ],
    }
    group["list_metadata"] = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    return group


def test_there_are_cases_of_each_kind():
    lifecycles = {case["lifecycle"] for case in CASES}
    assert {"ASSESSED", "INCONSISTENT", "INCOMPLETE", "NEEDS_APPROVAL"} <= lifecycles


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_findings_compare_as_the_shared_cases_say(case):
    metadata = _group(case["instances"], case["tags"])["list_metadata"]

    assert metadata["inconsistency_reasons"] == case["inconsistency_reasons"]
    assert metadata["lifecycle"] == case["lifecycle"]
    assert metadata["technical_state"] == case["technical_state"]


SCOPE_CASES = [case for case in CASES if "scopes" in case]


@pytest.mark.parametrize("case", SCOPE_CASES, ids=[case["name"] for case in SCOPE_CASES])
def test_the_scopes_are_as_the_shared_cases_say(case):
    metadata = _group(case["instances"], case["tags"])["list_metadata"]
    scopes = {scope["name"]: scope for scope in metadata["assessment_scopes"]}

    assert [scope["name"] for scope in metadata["assessment_scopes"]] == [
        expected["name"] for expected in case["scopes"]
    ]
    for expected in case["scopes"]:
        scope = scopes[expected["name"]]
        assert scope["lifecycle"] == expected["lifecycle"]
        assert scope["override_gaps"] == expected.get("override_gaps", [])


def test_groups_without_overrides_carry_no_scopes():
    plain = [case for case in CASES if "scopes" not in case]
    for case in plain:
        assert "assessment_scopes" not in _group(case["instances"], case["tags"])["list_metadata"]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_result_does_not_depend_on_the_order_of_the_findings(case):
    metadata = _group(list(reversed(case["instances"])), case["tags"])["list_metadata"]

    assert metadata["lifecycle"] == case["lifecycle"]
    assert metadata["technical_state"] == case["technical_state"]
    assert sorted(metadata["inconsistency_reasons"]) == sorted(case["inconsistency_reasons"])


def test_states_of_equal_priority_are_ordered_by_name():
    """Unknown states share one priority; the reported state must not depend
    on the order of a set."""
    states = ["ZULU", "ALPHA", "MIKE"]
    for order in (states, states[::-1], [states[1], states[2], states[0]]):
        group = _group([
            {"project_uuid": f"project-{index}", "component_uuid": "c", "vulnerability_uuid": "v",
             "project_version": f"{index}.0", "analysis_state": state, "analysis_details": ""}
            for index, state in enumerate(order, start=1)
        ])
        assert group["list_metadata"]["technical_state"] == "ALPHA"


def test_the_compared_text_leaves_out_records_and_version_coverage():
    current = (
        "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] "
        "[Justification: CODE_NOT_PRESENT] [Version Coverage: 1.0, 2.0] ---\nNot shipped."
    )
    record = (
        "--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Justification: NOT_SET] [Historical: yes] ---\nReachable."
    )

    compared = comparable_assessment_text(f"{record}\n\n{current}\n\n[Status: Pending Review]")

    assert compared == (
        "--- [Team: TeamB] [State: NOT_AFFECTED] [Justification: CODE_NOT_PRESENT] --- "
        "Not shipped."
    )


# --- Synchronize keeps each finding's records --------------------------------

_B = (
    "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Date: 1794000000000] "
    "[Justification: CODE_NOT_PRESENT] ---\nNot shipped."
)
# As a restore from an export adds it to the findings of one version (#292).
_RESTORED = (
    "--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] [Date: 1780000000000] "
    "[Justification: NOT_SET] [Ticket: EXP-1] [Historical: yes] ---\nReachable in 1.0."
)
# A record of the team that also has a current assessment.
_OWN_EARLIER = (
    "--- [Team: TeamB] [State: EXPLOITABLE] [Assessed By: bob] [Date: 1770000000000] "
    "[Justification: NOT_SET] [Historical: yes] ---\nEarlier view."
)


def _finding(index, state, details):
    return {
        "project_uuid": f"project-{index}", "component_uuid": f"component-{index}",
        "vulnerability_uuid": "vulnerability-1", "finding_uuid": f"finding-{index}",
        "project_version": f"{index}.0", "analysis_state": state, "analysis_details": details,
    }


def _restored_into_one_version(first=f"{_B}\n\n{_RESTORED}"):
    """Version 1.0 holds a restored record, 2.0 the same current assessment
    without it, 3.0 nothing yet."""
    return _group(
        [
            _finding(1, "NOT_AFFECTED", first),
            _finding(2, "NOT_AFFECTED", _B),
            _finding(3, "NOT_SET", ""),
        ],
        group_id="CVE-RESTORED",
    )


def _repair_payloads(group):
    context = BulkWorkflowContext(
        task_id="task-1", groups=[group], user="reviewer", team_mapping={},
    )
    assert build_assessment_repair_preview(context, lambda: {})["items"]
    payloads, _skipped = build_assessment_repair_payloads(context, [group["id"]], lambda: {})
    return payloads


def _standalone_payloads(group):
    payloads, _skipped = build_incomplete_sync_payloads([group], [group["id"]])
    return payloads


def _blocks(details):
    return [
        (block["team"], block["state"], bool(block["historical"]), block["details"])
        for block in parse_assessment_blocks(details)[1]
    ]


def _written(payloads):
    return {
        instance["finding_uuid"]: payload["details"] for instance, payload in payloads
    }


def test_a_restore_into_one_version_does_not_make_the_group_conflicting():
    group = _group([
        _finding(1, "NOT_AFFECTED", f"{_B}\n\n{_RESTORED}"),
        _finding(2, "NOT_AFFECTED", _B),
    ])

    assert group["list_metadata"]["inconsistency_reasons"] == []
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"


@pytest.mark.parametrize("payloads_of", [_repair_payloads, _standalone_payloads],
                         ids=["repair", "standalone"])
def test_synchronize_keeps_a_restored_record_on_its_own_version_only(payloads_of):
    group = _restored_into_one_version()
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    written = _written(payloads_of(group))

    # The finding without an assessment receives the current block, and
    # nothing of the record of another version.
    assert _blocks(written["finding-3"]) == [("TeamB", "NOT_AFFECTED", False, "Not shipped.")]
    assert "EXP-1" not in written["finding-3"]
    assert calculate_aggregated_state(written["finding-3"]) == "NOT_AFFECTED"
    # The other findings keep what they have, whether rewritten or not.
    for finding, details in (("finding-1", f"{_B}\n\n{_RESTORED}"), ("finding-2", _B)):
        assert _blocks(written.get(finding, details)) == _blocks(details)


@pytest.mark.parametrize("payloads_of", [_repair_payloads, _standalone_payloads],
                         ids=["repair", "standalone"])
@pytest.mark.parametrize("first", [f"{_OWN_EARLIER}\n\n{_B}", f"{_B}\n\n{_OWN_EARLIER}"],
                         ids=["record-first", "record-last"])
def test_synchronize_never_takes_a_record_for_the_current_assessment(payloads_of, first):
    """The team's own earlier record stands on one finding, in the worst
    case ahead of its current block. The other findings receive the current
    assessment, and the record stays where it is."""
    group = _restored_into_one_version(first=first)

    written = _written(payloads_of(group))

    assert _blocks(written["finding-3"]) == [("TeamB", "NOT_AFFECTED", False, "Not shipped.")]
    first_after = _blocks(written.get("finding-1", first))
    assert ("TeamB", "NOT_AFFECTED", False, "Not shipped.") in first_after
    assert ("TeamB", "EXPLOITABLE", True, "Earlier view.") in first_after
    assert len(first_after) == 2
    assert _blocks(written.get("finding-2", _B)) == _blocks(_B)


@pytest.mark.parametrize("payloads_of", [_repair_payloads, _standalone_payloads],
                         ids=["repair", "standalone"])
def test_a_finding_with_a_record_only_keeps_it_beside_the_synchronized_assessment(payloads_of):
    group = _group(
        [_finding(1, "NOT_AFFECTED", _B), _finding(2, "NOT_SET", _RESTORED)],
        group_id="CVE-RECORD-ONLY",
    )
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    written = _written(payloads_of(group))

    assert _blocks(written["finding-2"]) == [
        ("TeamB", "NOT_AFFECTED", False, "Not shipped."),
        ("TeamA", "EXPLOITABLE", True, "Reachable in 1.0."),
    ]
    # Exactly as stored, tags included.
    assert _RESTORED in written["finding-2"]
    assert "finding-1" not in written or _blocks(written["finding-1"]) == _blocks(_B)


def test_the_standalone_synchronize_keeps_each_findings_rescoring_and_pending_position():
    rescored = f"[Rescored: 4.2] [Rescored Vector: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L]\n\n{_B}"
    group = _group(
        [_finding(1, "NOT_AFFECTED", f"{rescored}\n\n{_RESTORED}"), _finding(2, "NOT_SET", "")],
        group_id="CVE-RESCORED",
    )

    written = _written(_standalone_payloads(group))

    assert written["finding-1"].startswith("[Rescored: 4.2] [Rescored Vector: CVSS:3.1/")
    assert _blocks(written["finding-1"])[-1] == ("TeamA", "EXPLOITABLE", True, "Reachable in 1.0.")
    assert "Rescored" not in written["finding-2"]
