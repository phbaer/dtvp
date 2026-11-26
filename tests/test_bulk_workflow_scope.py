"""Bulk Changes on the whole project versus the current list.

Since reviewers start on Awaiting review, the list filter hid every
vulnerability that is incomplete but not pending review, which is what the
Synchronize stage of Repair Assessments repairs across versions. The dialog
now defaults to the whole project (no list filters); the list's filters
still narrow the candidates when the user chooses the current list.
"""

from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities

TEAM_BLOCK = (
    "--- [Team: API] [State: NOT_AFFECTED] [Assessed By: alice] "
    "[Justification: CODE_NOT_REACHABLE] ---\nNo reachable path."
)
GROUP_ID = "CVE-2026-0100"


def _finding(version: str, details: str) -> dict:
    return {
        "project_name": "ExampleApp",
        "project_version": version,
        "project_uuid": f"project-{version}",
        "components": [{
            "finding_uuid": f"finding-{version}",
            "project_uuid": f"project-{version}",
            "component_uuid": "component-1",
            "vulnerability_uuid": "vulnerability-1",
            "component_name": "parser",
            "component_version": "1.0",
            "analysis_state": "NOT_AFFECTED" if details else "NOT_SET",
            "analysis_details": details,
        }],
    }


@pytest.fixture(autouse=True)
def signed_in():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides.pop(main.get_current_user, None)


@pytest.fixture
def task():
    # Assessed in 7.1.1, not in 7.1.2: incomplete across two versions, and
    # nothing in it is pending review.
    group = {
        "id": GROUP_ID, "title": GROUP_ID, "severity": "HIGH",
        "tags": [], "assignees": [], "aliases": [],
        "affected_versions": [_finding("7.1.1", TEAM_BLOCK), _finding("7.1.2", "")],
    }
    summaries = summarize_grouped_vulnerabilities([group], {})
    assert summaries[0]["list_metadata"]["lifecycle"] == "INCOMPLETE"
    task_id = "bulk-scope"
    main.tasks[task_id] = {
        "_owner": "testuser", "status": "completed", "result_mode": "summary",
        "_full_result": [group], "_full_result_by_id": {GROUP_ID: group}, "result": summaries,
    }
    yield task_id
    main.tasks.pop(task_id, None)


def _preview(client, task_id, filters):
    response = client.post(
        "/api/bulk-workflows/assessment-repair/preview",
        json={"task_id": task_id, "filters": filters},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_the_whole_project_finds_what_to_synchronize_across_versions(client, task, mock_dt_client):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        # The reviewer's default list (Awaiting review) holds no candidate.
        listed = _preview(client, task, {"awaiting_review": True})
        project = _preview(client, task, {})
        applied = client.post(
            "/api/bulk-workflows/assessment-repair/apply",
            json={
                "task_id": task, "filters": {}, "group_ids": [GROUP_ID],
                "preview_token": project["preview_token"],
                "group_fingerprints": project["group_fingerprints"],
            },
        )

    assert listed["selectable_group_ids"] == []
    assert project["selectable_group_ids"] == [GROUP_ID]
    assert "sync_findings" in [repair["id"] for repair in project["items"][0]["repairs"]]
    assert applied.status_code == 200, applied.text
    synced = main.cache_manager.get_assessment_overlay("project-7.1.2", "component-1", "vulnerability-1")
    assert "No reachable path." in synced["analysisDetails"]
    assert synced["analysisState"] == "NOT_AFFECTED"


def test_a_version_filter_still_narrows_the_current_list(client, task):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        other = _preview(client, task, {"versions": ["9.9.9"]})
    assert other["selectable_group_ids"] == []


def test_the_preview_is_deterministic_and_a_used_preview_is_refused(client, task, mock_dt_client):
    """As on production (25 Nov): the same preview applied twice. The first
    apply writes the group; the second finds it changed and is refused. Two
    previews without a write in between agree."""
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        first = _preview(client, task, {})
        again = _preview(client, task, {})
        body = {
            "task_id": task, "filters": {}, "group_ids": [GROUP_ID],
            "preview_token": first["preview_token"],
            "group_fingerprints": first["group_fingerprints"],
        }
        applied = client.post("/api/bulk-workflows/assessment-repair/apply", json=body)
        reused = client.post("/api/bulk-workflows/assessment-repair/apply", json=body)

    assert again["group_fingerprints"] == first["group_fingerprints"]
    assert again["items"] == first["items"]
    assert applied.status_code == 200, applied.text
    assert reused.status_code == 409
    assert reused.json()["detail"]["code"] == "preview_changed"
    assert reused.json()["detail"]["changed_groups"] == [GROUP_ID]
