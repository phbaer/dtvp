"""The card's Repair…: the Repair Assessments workflow for one vulnerability.

It is the bulk workflow with one more filter, ``group_id``: the candidates are
those of the bulk run, restricted to the group, and the preview token, the
fingerprints and the write path are the bulk workflow's own.
"""

from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities

TEAM_BLOCK = "--- [Team: API] [State: NOT_AFFECTED] [Assessed By: alice] ---\nNo reachable path."


def _incomplete_group(group_id: str, project: str) -> dict:
    """One finding assessed by its team, one without: Synchronize applies."""
    return {
        "id": group_id,
        "title": group_id,
        "severity": "HIGH",
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_name": "ExampleApp",
                "project_version": "1.0.0",
                "project_uuid": project,
                "components": [
                    {
                        "finding_uuid": f"{group_id}-1",
                        "project_uuid": project,
                        "component_uuid": f"{group_id}-component-1",
                        "vulnerability_uuid": f"{group_id}-vulnerability",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": TEAM_BLOCK,
                    },
                    {
                        "finding_uuid": f"{group_id}-2",
                        "project_uuid": project,
                        "component_uuid": f"{group_id}-component-2",
                        "vulnerability_uuid": f"{group_id}-vulnerability",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                    },
                ],
            }
        ],
    }


@pytest.fixture(autouse=True)
def signed_in():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides.pop(main.get_current_user, None)


@pytest.fixture
def task():
    groups = [_incomplete_group("CVE-2026-0001", "project-1"), _incomplete_group("CVE-2026-0002", "project-2")]
    task_id = "group-scoped-repair"
    main.tasks[task_id] = {
        "_owner": "testuser",
        "status": "completed",
        "result_mode": "summary",
        "_full_result": groups,
        "_full_result_by_id": {group["id"]: group for group in groups},
        "result": summarize_grouped_vulnerabilities(groups, {}),
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


def test_the_group_scoped_preview_is_the_bulk_preview_of_that_group(client, task):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        bulk = _preview(client, task, {})
        scoped = _preview(client, task, {"group_id": "CVE-2026-0002"})
        unknown = _preview(client, task, {"group_id": "CVE-2026-9999"})
        # An id is matched exactly, not as a search.
        partial = _preview(client, task, {"group_id": "CVE-2026-000"})

    assert sorted(bulk["selectable_group_ids"]) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert scoped["selectable_group_ids"] == ["CVE-2026-0002"]
    assert scoped["items"] == [item for item in bulk["items"] if item["group_id"] == "CVE-2026-0002"]
    assert scoped["group_fingerprints"] == {"CVE-2026-0002": bulk["group_fingerprints"]["CVE-2026-0002"]}
    assert [repair["id"] for repair in scoped["items"][0]["repairs"]][:1] == ["sync_findings"]
    # The scope is part of what the token stands for.
    assert scoped["preview_token"] != bulk["preview_token"]
    assert unknown["items"] == [] and unknown["selectable_group_ids"] == []
    assert partial["items"] == []


def test_a_group_scoped_preview_applies_to_that_group_only(client, task):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        scoped = _preview(client, task, {"group_id": "CVE-2026-0002"})
        refused = client.post(
            "/api/bulk-workflows/assessment-repair/apply",
            json={
                "task_id": task, "filters": {},
                "group_ids": ["CVE-2026-0002"], "preview_token": scoped["preview_token"],
                "group_fingerprints": scoped["group_fingerprints"],
            },
        )
        other = client.post(
            "/api/bulk-workflows/assessment-repair/apply",
            json={
                "task_id": task, "filters": {"group_id": "CVE-2026-0002"},
                "group_ids": ["CVE-2026-0001"], "preview_token": scoped["preview_token"],
                "group_fingerprints": scoped["group_fingerprints"],
            },
        )
        applied = client.post(
            "/api/bulk-workflows/assessment-repair/apply",
            json={
                "task_id": task, "filters": {"group_id": "CVE-2026-0002"},
                "group_ids": ["CVE-2026-0002"], "preview_token": scoped["preview_token"],
                "group_fingerprints": scoped["group_fingerprints"],
            },
        )

    # The token of a scoped preview does not apply the unscoped run.
    assert refused.status_code >= 400
    # A group outside the scope is not a candidate.
    assert other.status_code >= 400
    assert applied.status_code == 200, applied.text
    assert applied.json()["summary"]["selected_groups"] == 1
    assert {result.get("uuid") for result in applied.json()["results"]} <= {"CVE-2026-0002-1", "CVE-2026-0002-2"}
    assert main.cache_manager.get_assessment_overlay(
        "project-1", "CVE-2026-0001-component-2", "CVE-2026-0001-vulnerability"
    ) is None


def test_the_group_scoped_repair_is_for_reviewers(client, task):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.post(
            "/api/bulk-workflows/assessment-repair/preview",
            json={"task_id": task, "filters": {"group_id": "CVE-2026-0002"}},
        )
    assert response.status_code == 403
