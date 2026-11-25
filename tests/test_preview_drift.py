"""Why a preview item changes between the preview and the apply, and what
the apply does about it.

A preview's ``finding_count`` is the number of repair payloads of the group
(not the number of its findings); the payloads follow each finding's
assessment in the grouped snapshot. The snapshot is patched when a sync or a
save changes a finding's assessment (the change listener, value_changed).
These tests drive that same refresh path."""

import pytest
from fastapi import HTTPException

from dtvp.bulk_workflows.assessment_repair import build_assessment_repair_preview
from dtvp.bulk_workflows.base import (
    BulkWorkflowContext,
    build_preview_token,
    diff_items,
    group_fingerprints,
)
from dtvp.general_api_routes import (
    BulkWorkflowApplyRequest,
    _refresh_grouped_vuln_task_snapshots,
    check_preview,
)
from tests.test_bulk_workflows import _FORMER_RECORD, _repair_group

TEAMS = {"TeamB": "TeamB", "TeamC": "TeamC"}
# DT's analysis of version 1's finding, made by a team that is not the former one.
TEAM_B_DECISION = (
    "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] "
    "[Justification: CODE_NOT_PRESENT] ---\nNot shipped."
)


class _Plugin:
    id = "assessment-repair"
    version = 1

    def selectable_ids(self, preview):
        return [item["group_id"] for item in preview["items"]]


def _group():
    # Version 1: a former team's decision; version 2: not assessed yet.
    return _repair_group([("NOT_AFFECTED", _FORMER_RECORD), ("NOT_SET", "")], tags=["TeamB", "TeamC"])


def _preview(group):
    context = BulkWorkflowContext(task_id="task-1", groups=[group], user="reviewer", team_mapping=TEAMS)
    return build_assessment_repair_preview(context, lambda: {})


def _request(preview):
    return BulkWorkflowApplyRequest(
        task_id="task-1",
        group_ids=[item["group_id"] for item in preview["items"]],
        preview_token=build_preview_token(_Plugin(), task_id="task-1", filter_payload={}),
        group_fingerprints=group_fingerprints(preview),
        group_items={item["group_id"]: item for item in preview["items"]},
    )


def _listener_refresh(group, details, *, state="NOT_AFFECTED", value_changed=True, origin="sync"):
    """The snapshot patch a sync or a save makes when a finding's assessment
    is stored: the change listener's refresh of the task's grouped snapshot."""
    task = {"status": "completed", "_full_result": [group],
            "_full_result_by_id": {group["id"]: group}, "result": [group]}
    instance = {"project_uuid": "project-1", "component_uuid": "component-1",
                "vulnerability_uuid": "vulnerability-1"}
    payload = {"state": state, "details": details, "suppressed": False, "justification": "NOT_SET"}
    _refresh_grouped_vuln_task_snapshots({"t": task}, [(instance, payload)], TEAMS,
                                         value_changed=value_changed)
    return task["_full_result"][0]


async def test_one_finding_assessed_in_dt_refuses_and_names_the_fields():
    group = _group()
    seen = _preview(group)
    request = _request(seen)
    assert seen["items"][0]["finding_count"] == 2

    # DT's analysis of version 1's finding changed; the sync imports it.
    now = _preview(_listener_refresh(group, TEAM_B_DECISION))
    assert now["items"][0]["finding_count"] == 1  # one finding no longer needs a repair

    with pytest.raises(HTTPException) as refused:
        check_preview(_Plugin(), request, {}, now, "applying")
    detail = refused.value.detail
    assert detail["code"] == "preview_changed" and detail["changed_groups"] == ["CVE-REPAIR"]
    paths = {change["path"] for change in detail["changes"]["CVE-REPAIR"]}
    # TeamC never assessed: both previews list it for review, so the review
    # flag stays; what the repair would do changed.
    assert {"finding_count", "repairs[]"} <= paths


async def test_the_same_value_again_applies():
    """A change listener that fires for a value the snapshot already has
    (the echo of River's own export, or a read of the same assessment) changes
    nothing the apply depends on."""
    group = _listener_refresh(_group(), TEAM_B_DECISION)
    seen = _preview(group)
    request = _request(seen)

    echoed = _listener_refresh(group, TEAM_B_DECISION, value_changed=False, origin="export_echo")
    assert _preview(echoed) == seen
    assert check_preview(_Plugin(), request, {}, _preview(echoed), "applying") == ["CVE-REPAIR"]
    again = _listener_refresh(group, TEAM_B_DECISION)
    assert check_preview(_Plugin(), request, {}, _preview(again), "applying") == ["CVE-REPAIR"]


def test_the_refusal_names_the_fields_of_the_item_it_changed():
    seen = _preview(_group())
    now = _preview(_listener_refresh(_group(), TEAM_B_DECISION))
    changes = {change["path"] for change in diff_items(seen["items"][0], now["items"][0])}
    assert {"finding_count", "repairs[]"} <= changes


async def test_a_finding_a_sync_adds_does_not_reach_the_grouped_snapshot():
    """Characterization, not the wanted behaviour: a finding that a sync adds
    to a version is not in the task's group (its membership is the one the
    grouped build made), so neither the preview nor the apply changes for it.
    The membership is the gap a sync's add or removal needs to close."""
    group = _group()
    before = [dict(version) for version in group["affected_versions"]]
    task = {"status": "completed", "_full_result": [group], "_full_result_by_id": {group["id"]: group},
            "result": [group]}
    instance = {"project_uuid": "project-3", "component_uuid": "component-new",
                "vulnerability_uuid": "vulnerability-1"}
    payload = {"state": "NOT_AFFECTED", "details": TEAM_B_DECISION, "suppressed": False,
               "justification": "NOT_SET"}
    _refresh_grouped_vuln_task_snapshots({"t": task}, [(instance, payload)], TEAMS)
    assert [dict(version) for version in task["_full_result"][0]["affected_versions"]] == before
