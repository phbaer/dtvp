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


def test_repair_names_a_team_that_has_not_assessed_while_the_global_is_pending():
    text = GENERAL_TRIAGE + CORE_EMPTY + K_CORE + PENDING
    group = _group([("IN_TRIAGE", text)] * 3, tags=["Core", "K-Core"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, (payloads, _skipped) = _preview(group)

    [item] = preview["items"]
    assert item["review"] == [
        "Core has not assessed this vulnerability yet; nothing to copy and the global "
        "assessment is pending review, so no team can refer to it: open the vulnerability "
        "to assess it"
    ]
    # Nothing to write: listed for the reviewer, not selectable.
    assert payloads == []
    assert item["repairable"] is False
    assert item["requires_review"] is True


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
