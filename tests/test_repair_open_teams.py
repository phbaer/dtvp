"""A team that never assessed a vulnerability: Repair says so, and a team's
assessment under an alias or another case counts for the team."""

from dtvp.bulk_workflows.assessment_repair import (
    build_assessment_repair_payloads,
    build_assessment_repair_preview,
)
from dtvp.bulk_workflows.base import BulkWorkflowContext
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities

# The shape of CVE-2026-111497 on the production instance (2026-11-23): every
# finding has an empty Core block, a K-Core assessment, a General assessment
# in triage, and the pending-review marker.
GENERAL_TRIAGE = (
    "--- [Team: General] [State: IN_TRIAGE] [Assessed By: a] [Date: 1794394829173] "
    "[Justification: CODE_NOT_REACHABLE] ---\n"
)
CORE_EMPTY = (
    "--- [Team: Core] [State: NOT_SET] [Assessed By: a] [Date: 1794823339887] "
    "[Justification: CODE_NOT_REACHABLE] ---\n"
)
K_CORE = (
    "--- [Team: K-Core] [State: NOT_AFFECTED] [Assessed By: a] [Date: 1794822866568] "
    "[Justification: CODE_NOT_REACHABLE] ---\nNot reachable.\n"
)
PENDING = "[Status: Pending Review]"


def _group(details: list[tuple[str, str]], tags: list[str], mapping=None) -> dict:
    group = {
        "id": "CVE-2026-111497",
        "title": "CVE-2026-111497",
        "tags": tags,
        "affected_versions": [{
            "project_name": "ViewPoint_Product",
            "project_version": f"7.{index}.0",
            "components": [{
                "project_uuid": f"project-{index}",
                "component_uuid": f"component-{index}",
                "component_name": "NodeJS",
                "vulnerability_uuid": "vulnerability-1",
                "finding_uuid": f"finding-{index}",
                "tags": tags,
                "analysis_state": state,
                "analysis_details": text,
                "justification": "NOT_SET",
            }],
        } for index, (state, text) in enumerate(details, start=1)],
    }
    group["list_metadata"] = summarize_grouped_vulnerabilities([group], mapping or {})[0][
        "list_metadata"
    ]
    return group


def _preview(group, mapping=None):
    context = BulkWorkflowContext(
        task_id="t", groups=[group], user="reviewer", team_mapping=mapping or {}
    )
    rules = lambda: {}
    return (
        build_assessment_repair_preview(context, rules),
        build_assessment_repair_payloads(context, [group["id"]], rules),
    )


def test_repair_says_to_approve_the_pending_global_assessment_that_covers_a_team():
    # Ready for approval (ADR 0014): approving the global assessment
    # completes the vulnerability, as an approved one does.
    text = GENERAL_TRIAGE + CORE_EMPTY + K_CORE + PENDING
    group = _group([("IN_TRIAGE", text)] * 3, tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "NEEDS_APPROVAL"
    assert group["list_metadata"]["is_approval_ready"] is True

    preview, (payloads, _skipped) = _preview(group)

    [item] = preview["items"]
    assert item["review"] == [
        "Core has no assessment of their own; the global assessment covers them and "
        "is pending review: approve the Global assessment to complete it"
    ]
    # Nothing to write: listed for the reviewer, not selectable.
    assert payloads == []
    assert item["repairable"] is False
    assert item["requires_review"] is True


def test_repair_names_a_team_to_approve_for_once_the_findings_are_synchronized():
    # Pending global decision, but a finding without a state: Incomplete.
    # Repair synchronizes the finding; approving then completes it.
    text = GENERAL_TRIAGE + CORE_EMPTY + K_CORE + PENDING
    group = _group([("IN_TRIAGE", text), ("IN_TRIAGE", text), ("NOT_SET", "")], tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, (payloads, _) = _preview(group)

    [item] = preview["items"]
    assert item["review"] == [
        "Core has no assessment of their own; the global assessment covers them and "
        "is pending review: approve the Global assessment to complete it"
    ]
    assert payloads


def test_repair_keeps_nothing_to_copy_when_the_pending_global_does_not_decide():
    text = GENERAL_TRIAGE.replace("[State: IN_TRIAGE]", "[State: NOT_SET]") + CORE_EMPTY + K_CORE + PENDING
    group = _group([("NOT_AFFECTED", text)] * 2, tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, _ = _preview(group)

    [item] = preview["items"]
    assert item["review"] == [
        "Core has not assessed this vulnerability yet; nothing to copy: open the "
        "vulnerability to assess it"
    ]


def test_repair_names_an_unassessed_team_without_a_pending_clause():
    text = CORE_EMPTY + K_CORE
    group = _group([("NOT_AFFECTED", text)] * 2, tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, _ = _preview(group)

    [item] = preview["items"]
    assert item["review"] == [
        "Core has not assessed this vulnerability yet; nothing to copy: open the "
        "vulnerability to assess it"
    ]


def test_a_group_repair_completes_is_not_named():
    # Core assessed, one finding not at all: Repair copies the assessment
    # there, and no team stays open.
    core = CORE_EMPTY.replace("[State: NOT_SET]", "[State: NOT_AFFECTED]") + "Not used.\n"
    assessed = ("NOT_AFFECTED", core + K_CORE)
    group = _group([assessed, assessed, ("NOT_SET", "")], tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, (payloads, _) = _preview(group)

    [item] = preview["items"]
    assert item["review"] == []
    assert payloads


def test_an_assessment_under_a_teams_alias_counts_for_the_team():
    mapping = {"NodeJS": ["Core", "DE-Core"]}
    alias = CORE_EMPTY.replace("[Team: Core] [State: NOT_SET]", "[Team: DE-Core] [State: NOT_AFFECTED]")
    group = _group([("NOT_AFFECTED", alias)] * 2, tags=["Core"], mapping=mapping)

    assert group["list_metadata"]["lifecycle"] == "ASSESSED"
    # Without the mapping DE-Core is another team, and Core is missing.
    assert _group([("NOT_AFFECTED", alias)] * 2, tags=["Core"])["list_metadata"][
        "lifecycle"
    ] == "INCOMPLETE"


def test_team_names_match_regardless_of_case_and_space():
    other_case = CORE_EMPTY.replace("[Team: Core] [State: NOT_SET]", "[Team:  core ] [State: NOT_AFFECTED]")
    group = _group([("NOT_AFFECTED", other_case)] * 2, tags=["Core"])
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"


# --- The catch-all team is a team like any other (ADR 0014 Q6) --------------

MAPPING = {"*": "Unknown", "NodeJS": "K-Core"}
GENERAL_DECIDED = GENERAL_TRIAGE.replace("[State: IN_TRIAGE]", "[State: NOT_AFFECTED]")
UNKNOWN_REFERENCE = (
    "--- [Team: Unknown] [State: NOT_AFFECTED] [Assessed By: r] "
    "[Justification: CODE_NOT_REACHABLE] ---\nSee global assessment.\n"
)


def test_repair_names_the_catch_all_team_when_nothing_covers_it():
    group = _group([("NOT_AFFECTED", K_CORE)] * 2, tags=["K-Core", "Unknown"], mapping=MAPPING)
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    [item] = _preview(group, MAPPING)[0]["items"]

    assert item["review"] == [
        "Unknown has not assessed this vulnerability yet; nothing to copy: open the "
        "vulnerability to assess it"
    ]


def test_an_approved_global_decision_covers_the_catch_all_team_without_a_reference():
    group = _group([("NOT_AFFECTED", GENERAL_DECIDED + K_CORE)] * 2, tags=["K-Core", "Unknown"], mapping=MAPPING)
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"
    assert group["list_metadata"]["covers_all_teams"] is True

    preview, (payloads, _) = _preview(group, MAPPING)

    # Nothing to refer, nothing open.
    assert preview["items"] == [] and payloads == []


def test_a_pending_global_decision_covers_the_catch_all_team_once_approved():
    text = GENERAL_DECIDED + K_CORE + PENDING
    group = _group([("NOT_AFFECTED", text)] * 2, tags=["K-Core", "Unknown"], mapping=MAPPING)
    assert group["list_metadata"]["lifecycle"] == "NEEDS_APPROVAL"

    [item] = _preview(group, MAPPING)[0]["items"]

    assert item["review"] == [
        "Unknown has no assessment of their own; the global assessment covers them and "
        "is pending review: approve the Global assessment to complete it"
    ]


def test_a_reference_of_the_catch_all_team_stays_while_no_global_decision_covers_it():
    # Removing it would leave Unknown without an assessment.
    unset = GENERAL_TRIAGE.replace("[State: IN_TRIAGE]", "[State: NOT_SET]")
    group = _group([("NOT_AFFECTED", unset + K_CORE + UNKNOWN_REFERENCE)] * 2, tags=["K-Core", "Unknown"], mapping=MAPPING)
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"

    preview, (payloads, _) = _preview(group, MAPPING)

    assert preview["items"] == [] and payloads == []
