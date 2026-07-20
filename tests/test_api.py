import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities


@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    # No need to clear here as conftest clears all overrides


def test_search_projects(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"},
        {"name": "OtherProj", "uuid": "uuid2", "version": "1.0"},
    ]

    response = client.get("/api/projects?name=Test")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["name"] == "TestProj"


def test_search_projects_no_name(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"}
    ]

    response = client.get("/api/projects")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1


def test_grouped_vuln_task_status_prunes_expired_terminal_tasks(client, monkeypatch):
    monkeypatch.setenv("DTVP_GROUPED_VULN_TASK_TTL_SECONDS", "60")
    task_id = "expired-grouped-vuln-task"
    main.tasks[task_id] = {
        "id": task_id,
        "status": "completed",
        "result": [],
        "completed_at": datetime.now(timezone.utc) - timedelta(seconds=120),
    }

    try:
        response = client.get(f"/api/tasks/{task_id}")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    assert response.json() == {"status": "not_found"}


def test_grouped_vuln_task_events_stream_status_without_result(client):
    task_id = "task-events"
    main.tasks[task_id] = {
        "id": task_id,
        "status": "completed",
        "message": "Done",
        "progress": 100,
        "result": [{"id": "CVE-heavy"}],
        "partial_result_available": False,
    }

    try:
        response = client.get(f"/api/tasks/{task_id}/events")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    lines = [line for line in response.text.splitlines() if line]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["status"] == "completed"
    assert event["progress"] == 100
    assert "result" not in event


def test_cache_status_endpoint(client):
    mock_status = {
        "fully_cached": True,
        "last_refreshed_at": "2026-04-09T12:00:00Z",
        "projects": 5,
        "active_projects": 2,
        "cached_findings": 3,
        "cached_boms": 2,
        "cached_analyses": 10,
        "pending_updates": 1,
    }
    with patch("dtvp.main.cache_manager.get_cache_status", return_value=mock_status):
        response = client.get("/api/cache-status")
        assert response.status_code == 200
        data = response.json()
        assert data["fully_cached"] is True
        assert data["last_refreshed_at"] == "2026-04-09T12:00:00Z"
        assert data["projects"] == 5
        assert data["active_projects"] == 2
        assert data["cached_findings"] == 3
        assert data["cached_boms"] == 2
        assert data["cached_analyses"] == 10
        assert data["pending_updates"] == 1


def _restore_group():
    vector = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:O/RC:C/AR:L/MAC:H/MA:N"
    )
    group = {
        "id": "CVE-RESTORE",
        "title": "Recover CVSS metadata",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "rescored_cvss": None,
        "rescored_vector": None,
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_uuid": "project-1",
                "project_name": "Project",
                "project_version": "1.0.0",
                "components": [
                    {
                        "project_uuid": "project-1",
                        "project_name": "Project",
                        "project_version": "1.0.0",
                        "component_uuid": "component-1",
                        "component_name": "sqlite",
                        "component_version": "3.0",
                        "vulnerability_uuid": "vuln-1",
                        "finding_uuid": "finding-1",
                        "analysis_state": "NOT_AFFECTED",
                        "justification": "CODE_NOT_REACHABLE",
                        "analysis_details": (
                            "--- [Team: General] [State: NOT_AFFECTED] "
                            "[Assessed By: 100045117] "
                            "[Justification: CODE_NOT_REACHABLE] ---\n\n"
                            "sqlite not used in the product"
                        ),
                        "analysis_comments": [
                            {
                                "timestamp": 1710000000000,
                                "commenter": "100045117",
                                "comment": (
                                    "Details: [Rescored: 0] "
                                    f"[Rescored Vector: {vector}]"
                                ),
                            }
                        ],
                        "is_suppressed": False,
                        "is_direct_dependency": True,
                    }
                ],
            }
        ],
    }
    summarize_grouped_vulnerabilities([group], {})
    return group, vector


def test_assessment_restore_preview_and_apply(client, mock_dt_client):
    group, vector = _restore_group()
    task_id = "restore-task"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            preview_response = client.post(
                "/api/assessments/restore-preview",
                json={"task_id": task_id},
            )
            assert preview_response.status_code == 200
            preview = preview_response.json()
            assert preview["summary"]["recoverable_findings"] == 1
            assert preview["items"][0]["group_id"] == "CVE-RESTORE"
            assert preview["items"][0]["findings"][0]["restored_vector"] == vector

            apply_response = client.post(
                "/api/assessments/restore-apply",
                json={"task_id": task_id},
            )
            assert apply_response.status_code == 200
            assert apply_response.json()["summary"]["attempted"] == 1

        mock_dt_client.update_analysis.assert_called_once()
        _, kwargs = mock_dt_client.update_analysis.call_args
        assert kwargs["project_uuid"] == "project-1"
        assert kwargs["component_uuid"] == "component-1"
        assert kwargs["vulnerability_uuid"] == "vuln-1"
        assert "[Rescored: 0.0]" in kwargs["details"]
        assert f"[Rescored Vector: {vector}]" in kwargs["details"]
        assert "sqlite not used in the product" in kwargs["details"]
        assert group["assessment_restore_count"] == 0
    finally:
        main.tasks.pop(task_id, None)


def test_bulk_workflow_preview_runs_as_polled_background_task(client):
    group, _vector = _restore_group()
    task_id = "background-bulk-preview-source"
    operation_id = None
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            response = client.post(
                "/api/bulk-workflows/assessment-restore/preview-task",
                json={"task_id": task_id, "filters": {}},
            )
            assert response.status_code == 200
            operation_id = response.json()["task_id"]
            assert operation_id != task_id

            for _attempt in range(20):
                status_response = client.get(
                    f"/api/bulk-workflows/tasks/{operation_id}"
                )
                assert status_response.status_code == 200
                status = status_response.json()
                if status["status"] in {"completed", "failed"}:
                    break

        assert status["status"] == "completed"
        assert status["kind"] == "bulk_workflow_preview"
        assert status["source_task_id"] == task_id
        assert status["progress"] == 100
        assert status["result"]["task_id"] == task_id
        assert status["result"]["selectable_group_ids"] == [group["id"]]
    finally:
        main.tasks.pop(task_id, None)
        if operation_id:
            main.tasks.pop(operation_id, None)


def test_incomplete_bulk_workflow_preview_hydrates_summary_lifecycle(client):
    group = {
        "id": "CVE-INCOMPLETE-PREVIEW",
        "title": "Incomplete assessment",
        "severity": "HIGH",
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_name": "ExampleApp",
                "project_version": "1.0.0",
                "project_uuid": "project-1",
                "components": [
                    {
                        "finding_uuid": "finding-1",
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": (
                            "--- [Team: API] [State: NOT_AFFECTED] "
                            "[Assessed By: alice] ---\nNo reachable path."
                        ),
                    },
                    {
                        "finding_uuid": "finding-2",
                        "project_uuid": "project-1",
                        "component_uuid": "component-2",
                        "vulnerability_uuid": "vulnerability-2",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                    },
                ],
            }
        ],
    }
    task_id = "incomplete-bulk-preview-source"
    summaries = summarize_grouped_vulnerabilities([group], {})
    assert summaries[0]["list_metadata"]["lifecycle"] == "INCOMPLETE"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summaries,
    }

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            response = client.post(
                "/api/bulk-workflows/incomplete-sync/preview",
                json={
                    "task_id": task_id,
                    "filters": {"lifecycle": ["INCOMPLETE"]},
                },
            )
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    preview = response.json()
    assert preview["selectable_group_ids"] == [group["id"]]
    assert preview["summary"] == {"groups": 1, "findings": 2}


def test_bulk_workflow_apply_runs_as_polled_background_task(client, mock_dt_client):
    group, _vector = _restore_group()
    task_id = "background-bulk-apply-source"
    operation_id = None
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }

    class BackgroundDTClient:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return mock_dt_client

        async def __aexit__(self, *_args):
            return None

    try:
        with (
            patch("dtvp.main.get_user_role", return_value="REVIEWER"),
            patch("dtvp.main.DTClient", BackgroundDTClient),
        ):
            preview_response = client.post(
                "/api/bulk-workflows/assessment-restore/preview",
                json={"task_id": task_id, "filters": {}},
            )
            assert preview_response.status_code == 200
            preview = preview_response.json()

            response = client.post(
                "/api/bulk-workflows/assessment-restore/apply-task",
                json={
                    "task_id": task_id,
                    "filters": {},
                    "group_ids": [group["id"]],
                    "preview_token": preview["preview_token"],
                },
            )
            assert response.status_code == 200
            operation_id = response.json()["task_id"]

            for _attempt in range(20):
                status_response = client.get(
                    f"/api/bulk-workflows/tasks/{operation_id}"
                )
                assert status_response.status_code == 200
                status = status_response.json()
                if status["status"] in {"completed", "failed"}:
                    break

        assert status["status"] == "completed"
        assert status["kind"] == "bulk_workflow_apply"
        assert status["result"]["summary"]["attempted"] == 1
        mock_dt_client.update_analysis.assert_called_once()
    finally:
        main.tasks.pop(task_id, None)
        if operation_id:
            main.tasks.pop(operation_id, None)


def test_bulk_automatic_assessment_preview_includes_reviewer_started_result(client):
    group = {
        "id": "CVE-2026-MANUAL-RUN",
        "title": "Reviewer-started analyzer result",
        "severity": "HIGH",
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_uuid": "project-manual-run",
                "project_name": "ExampleApp",
                "project_version": "1.0.0",
                "components": [
                    {
                        "project_uuid": "project-manual-run",
                        "project_name": "ExampleApp",
                        "project_version": "1.0.0",
                        "component_uuid": "component-vulnerable",
                        "component_name": "vulnerable-library",
                        "component_version": "1.2.3",
                        "vulnerability_uuid": "vuln-manual-run",
                        "finding_uuid": "finding-manual-run",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                        "is_suppressed": False,
                    }
                ],
            }
        ],
    }
    task_id = "automatic-assessment-manual-run-task"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }
    main.code_analysis_result_store.record_queue_item_result(
        SimpleNamespace(
            queue_id="reviewer-started-run",
            project_name="ExampleApp",
            vuln_id=group["id"],
            component_name="owning-service",
            source="manual",
            status="completed",
            context_summary={
                "project_name": "ExampleApp",
                "target_component": "owning-service",
                "components": [
                    {
                        "project_name": "ExampleApp",
                        "component_name": "vulnerable-library",
                    }
                ],
            },
        ),
        {
            "assessment": {
                "affected": True,
                "verdict": "Probably Affected",
                "confidence": "High",
                "exposure": "reachable",
                "summary": "The vulnerable path may be reachable.",
                "reasoning": "Reviewer-started analysis found a possible path.",
            },
            "versions_checked": ["1.0.0"],
            "steps": [],
        },
    )

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            index_response = client.get(
                "/api/code-analysis/assessment-index",
                params={"project_name": "ExampleApp"},
            )
            response = client.post(
                "/api/bulk-workflows/automatic-assessments/preview",
                json={
                    "task_id": task_id,
                    "filters": {
                        "automatic_assessment": ["WITH_AUTOMATIC_ASSESSMENT"],
                        "automatic_assessment_ids": ["incorrect-client-id"],
                    },
                },
            )
    finally:
        main.tasks.pop(task_id, None)

    assert index_response.status_code == 200
    index = index_response.json()
    assert index["records"] == [
        {
            "analysis_run_id": "reviewer-started-run",
            "vuln_id": group["id"].lower(),
            "project_names": ["exampleapp"],
            "component_names": ["owning-service", "vulnerable-library"],
            "source_kind": "manual",
        }
    ]
    assert index["summary"]["indexed_assessment_results"] == 1
    assert response.status_code == 200
    preview = response.json()
    assert preview["selectable_group_ids"] == [group["id"]]
    assert preview["items"][0]["run_ids"] == ["reviewer-started-run"]
    assert preview["items"][0]["verdict_bucket"] == "PROBABLY_AFFECTED"
    assert preview["items"][0]["target_state"] == "IN_TRIAGE"


def test_bulk_automatic_assessment_preview_imports_source_less_legacy_result(client):
    group = {
        "id": "CVE-2026-LEGACY-RUN",
        "title": "Unclassified legacy analyzer result",
        "severity": "HIGH",
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_uuid": "project-legacy-run",
                "project_name": "ExampleApp",
                "project_version": "1.0.0",
                "components": [
                    {
                        "project_uuid": "project-legacy-run",
                        "project_name": "ExampleApp",
                        "project_version": "1.0.0",
                        "component_uuid": "component-legacy-run",
                        "component_name": "vulnerable-library",
                        "component_version": "1.2.3",
                        "vulnerability_uuid": "vuln-legacy-run",
                        "finding_uuid": "finding-legacy-run",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                        "is_suppressed": False,
                    }
                ],
            }
        ],
    }
    task_id = "automatic-assessment-source-less-run-task"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }
    legacy_path = Path(os.environ["DTVP_CODE_ANALYSIS_RESULTS_PATH"])
    legacy_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "analysis_run_id": "source-less-legacy-run",
                        "compact_context": {
                            "target": {
                                "project_name": "ExampleApp",
                                "vuln_id": group["id"],
                                "component_name": "owning-service",
                            },
                            "request_context": {
                                "context_summary": {
                                    "project_name": "ExampleApp",
                                    "target_component": "owning-service",
                                    "components": [
                                        {
                                            "project_name": "ExampleApp",
                                            "component_name": "vulnerable-library",
                                        }
                                    ],
                                }
                            },
                        },
                        "summary": {
                            "affected": False,
                            "verdict": "Not Affected",
                            "confidence": "High",
                            "exposure": "none",
                            "summary": "The vulnerable code is not present.",
                            "reasoning": "Source inspection ruled out the path.",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    main.code_analysis_result_store.reset()

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            index_response = client.get(
                "/api/code-analysis/assessment-index",
                params={"project_name": "ExampleApp"},
            )
            response = client.post(
                "/api/bulk-workflows/automatic-assessments/preview",
                json={
                    "task_id": task_id,
                    "filters": {
                        "automatic_assessment": ["WITH_AUTOMATIC_ASSESSMENT"],
                        "automatic_assessment_ids": ["incorrect-client-id"],
                    },
                },
            )
    finally:
        main.tasks.pop(task_id, None)

    assert index_response.status_code == 200
    index = index_response.json()
    assert index["records"] == [
        {
            "analysis_run_id": "source-less-legacy-run",
            "vuln_id": group["id"].lower(),
            "project_names": ["exampleapp"],
            "component_names": ["owning-service", "vulnerable-library"],
            "source_kind": "unknown",
        }
    ]
    assert index["summary"]["indexed_assessment_results"] == 1
    assert response.status_code == 200
    preview = response.json()
    assert preview["selectable_group_ids"] == [group["id"]]
    assert preview["items"][0]["run_ids"] == ["source-less-legacy-run"]
    assert preview["items"][0]["verdict_bucket"] == "NOT_AFFECTED"
    assert preview["summary"]["stored_analysis_results"] == 1
    assert preview["summary"]["usable_assessment_results"] == 1
    assert preview["summary"]["matched_analysis_results"] == 1


def test_rescore_rule_sync_preview_and_apply(client, mock_dt_client):
    base_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    stale_vector = f"{base_vector}/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N"
    component = {
        "project_uuid": "project-rule",
        "project_name": "Project",
        "project_version": "1.0.0",
        "component_uuid": "component-rule",
        "component_name": "example",
        "component_version": "1.0.0",
        "vulnerability_uuid": "vuln-rule",
        "finding_uuid": "finding-rule",
        "analysis_state": "NOT_AFFECTED",
        "justification": "CODE_NOT_REACHABLE",
        "analysis_details": (
            f"[Rescored: 9.8] [Rescored Vector: {stale_vector}]\n\n"
            "Preserve the assessment explanation."
        ),
        "is_suppressed": True,
    }
    group = {
        "id": "CVE-RULE-SYNC",
        "title": "Sync CVSS rules",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": base_vector,
        "rescored_cvss": 9.8,
        "rescored_vector": stale_vector,
        "tags": [],
        "assignees": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_uuid": "project-rule",
                "project_name": "Project",
                "project_version": "1.0.0",
                "components": [component],
            }
        ],
    }
    summarize_grouped_vulnerabilities([group], {})
    task_id = "rescore-rule-sync-task"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "result": summarize_grouped_vulnerabilities([group], {}),
    }

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            preview_response = client.post(
                "/api/assessments/rescore-rule-preview",
                json={"task_id": task_id},
            )
            assert preview_response.status_code == 200
            preview = preview_response.json()
            assert preview["summary"]["syncable_groups"] == 1
            finding = preview["items"][0]["findings"][0]
            assert finding["status"] == "ready"
            assert "Missing requirements: AR, CR, IR" in finding["reasons"]

            apply_response = client.post(
                "/api/assessments/rescore-rule-apply",
                json={"task_id": task_id, "group_ids": [group["id"]]},
            )
            assert apply_response.status_code == 200
            assert apply_response.json()["summary"]["attempted"] == 1

        mock_dt_client.update_analysis.assert_called_once()
        _, kwargs = mock_dt_client.update_analysis.call_args
        assert "CR:L/IR:L/AR:L" in kwargs["details"]
        assert "Preserve the assessment explanation." in kwargs["details"]
        assert kwargs["justification"] == "CODE_NOT_REACHABLE"
        assert kwargs["suppressed"] is True

        refreshed_component = group["affected_versions"][0]["components"][0]
        assert "CR:L/IR:L/AR:L" in refreshed_component["analysis_details"]
        assert group["rescored_vector"] == finding["proposed_vector"]
        assert group["rescored_cvss"] == finding["proposed_score"]
    finally:
        main.tasks.pop(task_id, None)


def test_get_task_statistics_reuses_completed_grouped_result(client):
    task_id = "task-statistics"
    main.tasks[task_id] = {
        "status": "completed",
        "_full_result": [
            {
                "id": "CVE-2026-STATS",
                "severity": "HIGH",
                "affected_versions": [
                    {
                        "project_uuid": "project-1",
                        "components": [
                            {"analysis_state": "NOT_SET"},
                            {"analysis_state": "EXPLOITABLE"},
                        ],
                    }
                ],
            }
        ],
        "_statistics_rollup": {
            "version_counts": {"1.0.0": 2},
            "major_version_counts": {"1": 2},
            "major_version_details": {"1": {"1.0.0": 2}},
            "major_version_severity_counts": {"1": {"HIGH": 2}},
            "version_severity_counts": {"1.0.0": {"HIGH": 2}},
        },
    }

    try:
        response = client.get(f"/api/tasks/{task_id}/statistics")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 2
    assert data["state_counts"]["INCOMPLETE"] == 1
    assert data["version_counts"] == {"1.0.0": 2}
    assert data["major_version_counts"] == {"1": 2}


def test_get_task_groups_filters_sorts_and_windows(client):
    task_id = "task-list-query"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-A",
                "title": "Alpha finding",
                "cvss_score": 5.0,
                "tags": ["TeamA"],
                "aliases": [],
                "assignees": ["alice"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                    "component_names": ["library-a"],
                    "versions": ["2.0.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": False,
                    "attributed_on_ms_values": [1],
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-B",
                "title": "Beta finding",
                "cvss_score": 9.8,
                "tags": ["TeamB"],
                "aliases": [],
                "assignees": ["bob"],
                "list_metadata": {
                    "lifecycle": "ASSESSED",
                    "is_open": False,
                    "is_pending": False,
                    "technical_state": "FALSE_POSITIVE",
                    "component_names": ["library-b"],
                    "versions": ["1.0.0"],
                    "dependency_relationship": "TRANSITIVE",
                    "cvss_version_mismatch": False,
                    "attributed_on_ms_values": [2],
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-C",
                "title": "Gamma finding",
                "cvss_score": 7.1,
                "tags": ["TeamA"],
                "aliases": ["GHSA-query"],
                "assignees": ["carol"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "IN_TRIAGE",
                    "component_names": ["library-c"],
                    "versions": ["2.0.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": True,
                    "attributed_on_ms_values": [3],
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "lifecycle": "OPEN",
                "dependency": "DIRECT",
                "versions": "2.0.0",
                "sort": "id",
                "order": "desc",
                "offset": 0,
                "limit": 1,
                "tmrescore_proposal_ids": "GHSA-query",
                "attributed_before_days": 1,
                "attribution_mode": "older",
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["filtered"] == 2
    assert data["offset"] == 0
    assert data["limit"] == 1
    assert data["has_more"] is True
    assert data["next_cursor"]
    assert data["result_mode"] == "summary"
    assert [item["id"] for item in data["items"]] == ["CVE-2026-C"]
    assert data["counts"]["all"]["total"] == 3
    assert data["counts"]["all"]["lifecycle"]["OPEN"] == 2
    assert data["counts"]["all"]["lifecycle"]["ASSESSED"] == 1
    assert data["counts"]["all"]["analysis"]["IN_TRIAGE"] == 1
    assert data["counts"]["all"]["dependency_relationship"] == {
        "direct": 2,
        "transitive": 1,
        "unknown": 0,
    }
    assert data["counts"]["all"]["cvss_version_mismatch"] == 1
    assert data["counts"]["all"]["ids"]["CVE-2026-C"] == 1
    assert data["counts"]["all"]["ids"]["GHSA-query"] == 1
    assert data["counts"]["all"]["versions"]["2.0.0"] == 2
    assert data["counts"]["all"]["tags"]["TeamA"] == 2
    assert data["counts"]["all"]["team_tags"]["TeamA"] == {
        "open": 2,
        "assessed": 0,
    }
    assert data["counts"]["all"]["team_tags"]["TeamB"] == {
        "open": 0,
        "assessed": 1,
    }
    assert data["counts"]["all"]["tmrescore"] == {
        "WITH_PROPOSAL": 1,
        "WITHOUT_PROPOSAL": 2,
    }
    assert data["counts"]["filtered"]["total"] == 2
    assert data["counts"]["filtered"]["analysis"]["IN_TRIAGE"] == 1
    assert data["counts"]["filtered"]["dependency_relationship"]["direct"] == 2
    assert data["counts"]["filtered"]["tmrescore"] == {
        "WITH_PROPOSAL": 1,
        "WITHOUT_PROPOSAL": 1,
    }
    assert data["counts"]["filtered"]["attribution_age"] == 2


def test_get_task_groups_filters_by_inconsistency_reason(client):
    task_id = "task-inconsistency-reason"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-STATE",
                "list_metadata": {
                    "lifecycle": "INCONSISTENT",
                    "inconsistency_reasons": ["ANALYSIS_STATE_MISMATCH"],
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-CVSS",
                "list_metadata": {
                    "lifecycle": "INCONSISTENT",
                    "inconsistency_reasons": ["MISSING_RESCORING_VECTOR"],
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "lifecycle": "INCONSISTENT",
                "inconsistency_reason": "MISSING_RESCORING_VECTOR",
                "sort": "id",
                "order": "asc",
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["filtered"] == 1
    assert [item["id"] for item in data["items"]] == ["CVE-CVSS"]

def test_get_task_groups_accepts_cursor(client):
    task_id = "task-list-query-cursor"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-CURSOR-A",
                "title": "Cursor finding",
                "tags": [],
                "aliases": [],
                "assignees": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                    "component_names": ["library-a"],
                    "versions": ["1.0.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": False,
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-CURSOR-B",
                "title": "Cursor finding",
                "tags": [],
                "aliases": [],
                "assignees": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                    "component_names": ["library-b"],
                    "versions": ["1.0.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": False,
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        first = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"sort": "id", "order": "asc", "limit": 1},
        )
        assert first.status_code == 200
        cursor = first.json()["next_cursor"]

        second = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"sort": "id", "order": "asc", "limit": 1, "cursor": cursor},
        )
        invalid = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"cursor": "invalid"},
        )
    finally:
        main.tasks.pop(task_id, None)

    assert second.status_code == 200
    second_data = second.json()
    assert second_data["offset"] == 1
    assert second_data["items"][0]["id"] == "CVE-2026-CURSOR-B"
    assert second_data["next_cursor"] is None
    assert second_data["has_more"] is False
    assert invalid.status_code == 400


def test_get_task_groups_serves_running_partial_summary_window(client):
    from dtvp.task_group_query_services import build_task_group_query_index

    task_id = "task-partial-summary"
    groups = [
        {
            "id": "CVE-2026-PARTIAL",
            "title": "Partial finding",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": ["library-a"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        }
    ]
    main.tasks[task_id] = {
        "status": "running",
        "result_mode": "summary",
        "result": groups,
        "partial_result_available": True,
        "partial_versions_completed": 1,
        "partial_total_versions": 3,
        "_group_query_index": build_task_group_query_index(groups),
    }

    try:
        response = client.get(f"/api/tasks/{task_id}/groups")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["partial"] is True
    assert data["partial_versions_completed"] == 1
    assert data["partial_total_versions"] == 3
    assert data["items"][0]["id"] == "CVE-2026-PARTIAL"


def test_get_task_groups_field_filters_accept_multiple_terms(client):
    task_id = "task-list-query-terms"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-TERMS",
                "title": "Term finding",
                "tags": ["Platform Security"],
                "aliases": ["GHSA-terms"],
                "assignees": ["alice.smith"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                    "component_names": ["spring security core"],
                    "versions": ["2.0.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": False,
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-OTHER",
                "title": "Other finding",
                "tags": ["Platform"],
                "aliases": [],
                "assignees": ["bob"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                    "component_names": ["spring web"],
                    "versions": ["2.1.0"],
                    "dependency_relationship": "DIRECT",
                    "cvss_version_mismatch": False,
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "tag": "platform security",
                "component": "spring core",
                "assignee": "alice smith",
                "versions": "2.0.0",
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["filtered"] == 1
    assert [item["id"] for item in data["items"]] == ["CVE-2026-TERMS"]


def test_get_task_group_details_window_returns_full_groups(client):
    task_id = "task-detail-window"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-DETAIL-A",
                "title": "Summary A",
                "list_metadata": {
                    "lifecycle": "INCOMPLETE",
                    "is_open": True,
                    "technical_state": "NOT_SET",
                    "component_names": ["library-a"],
                },
                "affected_versions": [
                    {
                        "project_version": "1.0.0",
                        "components": [
                            {
                                "component_name": "library-a",
                                "analysis_state": "NOT_SET",
                            }
                        ],
                    }
                ],
            },
            {
                "id": "CVE-2026-DETAIL-B",
                "title": "Summary B",
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "technical_state": "NOT_SET",
                    "component_names": ["library-b"],
                },
                "affected_versions": [],
            },
        ],
        "_full_result_by_id": {
            "CVE-2026-DETAIL-A": {
                "id": "CVE-2026-DETAIL-A",
                "title": "Full A",
                "affected_versions": [
                    {
                        "project_version": "1.0.0",
                        "components": [
                            {
                                "component_name": "library-a",
                                "analysis_state": "NOT_SET",
                                "analysis_details": "Full reviewer notes",
                                "dependency_chains": ["root > library-a"],
                            }
                        ],
                    }
                ],
            },
            "CVE-2026-DETAIL-B": {
                "id": "CVE-2026-DETAIL-B",
                "title": "Full B",
                "affected_versions": [],
            },
        },
    }

    try:
        response = client.get(
            f"/api/tasks/{task_id}/group-details",
            params={
                "lifecycle": "INCOMPLETE",
                "component": "library-a",
                "sort": "id",
                "order": "asc",
                "offset": 0,
                "limit": 1,
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["result_mode"] == "full"
    assert data["source_result_mode"] == "summary"
    assert data["total"] == 2
    assert data["filtered"] == 1
    assert [item["id"] for item in data["items"]] == ["CVE-2026-DETAIL-A"]
    full_component = data["items"][0]["affected_versions"][0]["components"][0]
    assert full_component["analysis_details"] == "Full reviewer notes"
    assert full_component["dependency_chains"] == ["root > library-a"]


def test_get_task_groups_filters_by_tmrescore_proposal_ids_and_aliases(client):
    task_id = "task-list-query-tmrescore"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-WITH",
                "title": "Direct proposal",
                "aliases": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-ALIAS",
                "title": "Alias proposal",
                "aliases": ["GHSA-alias-proposal"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-WITHOUT",
                "title": "No proposal",
                "aliases": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        with_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "tmrescore": "WITH_PROPOSAL",
                "tmrescore_proposal_ids": [
                    "CVE-2026-WITH",
                    "GHSA-alias-proposal",
                ],
                "sort": "id",
                "order": "asc",
            },
        )
        without_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "tmrescore": "WITHOUT_PROPOSAL",
                "tmrescore_proposal_ids": [
                    "CVE-2026-WITH",
                    "GHSA-alias-proposal",
                ],
                "sort": "id",
                "order": "asc",
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert with_response.status_code == 200
    assert [item["id"] for item in with_response.json()["items"]] == [
        "CVE-2026-ALIAS",
        "CVE-2026-WITH",
    ]
    assert without_response.status_code == 200
    assert [item["id"] for item in without_response.json()["items"]] == [
        "CVE-2026-WITHOUT",
    ]


def test_get_task_groups_filters_by_automatic_assessment_ids_and_aliases(client):
    task_id = "task-list-query-auto-assessment"
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [
            {
                "id": "CVE-2026-AUTO",
                "title": "Direct automatic assessment",
                "aliases": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-AUTO-ALIAS",
                "title": "Alias automatic assessment",
                "aliases": ["GHSA-auto-assessment"],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
            {
                "id": "CVE-2026-MANUAL",
                "title": "No automatic assessment",
                "aliases": [],
                "list_metadata": {
                    "lifecycle": "OPEN",
                    "is_open": True,
                    "is_pending": False,
                    "technical_state": "NOT_SET",
                },
                "affected_versions": [],
            },
        ],
    }

    try:
        with_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "automatic_assessment": "WITH_AUTOMATIC_ASSESSMENT",
                "automatic_assessment_ids": [
                    "CVE-2026-AUTO",
                    "GHSA-auto-assessment",
                ],
                "sort": "id",
                "order": "asc",
            },
        )
        without_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "automatic_assessment": "WITHOUT_AUTOMATIC_ASSESSMENT",
                "automatic_assessment_ids": [
                    "CVE-2026-AUTO",
                    "GHSA-auto-assessment",
                ],
                "sort": "id",
                "order": "asc",
            },
        )
    finally:
        main.tasks.pop(task_id, None)

    assert with_response.status_code == 200
    with_data = with_response.json()
    assert [item["id"] for item in with_data["items"]] == [
        "CVE-2026-AUTO",
        "CVE-2026-AUTO-ALIAS",
    ]
    assert with_data["counts"]["all"]["automatic_assessment"] == {
        "WITH_AUTOMATIC_ASSESSMENT": 2,
        "WITHOUT_AUTOMATIC_ASSESSMENT": 1,
    }
    assert with_data["counts"]["filtered"]["automatic_assessment"] == {
        "WITH_AUTOMATIC_ASSESSMENT": 2,
        "WITHOUT_AUTOMATIC_ASSESSMENT": 0,
    }
    assert without_response.status_code == 200
    assert [item["id"] for item in without_response.json()["items"]] == [
        "CVE-2026-MANUAL",
    ]


def test_get_task_groups_filters_and_annotates_from_persisted_assessment_metadata(client):
    task_id = "task-list-query-persisted-assessment"
    run_id = "run-task-list-persisted-assessment"
    assessed_group = {
        "id": "CVE-2026-PERSISTED-ASSESSMENT",
        "aliases": [],
        "list_metadata": {
            "lifecycle": "OPEN",
            "is_open": True,
            "is_pending": False,
            "technical_state": "NOT_SET",
        },
        "affected_versions": [
            {
                "project_name": "ExampleApp",
                "components": [
                    {
                        "project_name": "ExampleApp",
                        "component_name": "owned-api",
                    }
                ],
            }
        ],
    }
    unassessed_group = {
        **assessed_group,
        "id": "CVE-2026-NO-PERSISTED-ASSESSMENT",
    }
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": [assessed_group, unassessed_group],
    }
    main.code_analysis_result_store.record_queue_item_result(
        SimpleNamespace(
            queue_id=run_id,
            project_name="ExampleApp",
            vuln_id=assessed_group["id"],
            component_name="owned-api",
            source="automatic",
            status="completed",
            submitted_at="2026-07-15T10:00:00+00:00",
            finished_at="2026-07-15T10:01:00+00:00",
        ),
        {
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "analysis": "No reachable path",
            }
        },
    )

    try:
        response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={
                "automatic_assessment": "WITH_AUTOMATIC_ASSESSMENT",
                "sort": "id",
                "order": "asc",
            },
        )
    finally:
        main.tasks.pop(task_id, None)
        main.code_analysis_result_store.delete(run_id)

    assert response.status_code == 200
    data = response.json()
    assert [item["id"] for item in data["items"]] == [assessed_group["id"]]
    assert data["items"][0]["code_assessment_status"] == "auto"
    assert data["counts"]["all"]["automatic_assessment"] == {
        "WITH_AUTOMATIC_ASSESSMENT": 1,
        "WITHOUT_AUTOMATIC_ASSESSMENT": 1,
    }


def test_get_task_groups_rejects_incomplete_task(client):
    task_id = "task-list-running"
    main.tasks[task_id] = {"status": "running", "result": []}
    try:
        response = client.get(f"/api/tasks/{task_id}/groups")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 409
    assert response.json()["detail"] == "Task is not completed"


def test_get_task_status_can_omit_result(client):
    task_id = "task-status-lean"
    main.tasks[task_id] = {
        "id": task_id,
        "status": "completed",
        "message": "Done",
        "progress": 100,
        "result": [{"id": "CVE-2026-LEAN"}],
        "result_mode": "summary",
        "_full_result": [{"id": "CVE-2026-LEAN"}],
    }
    try:
        response = client.get(f"/api/tasks/{task_id}?include_result=false")
    finally:
        main.tasks.pop(task_id, None)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["result_mode"] == "summary"
    assert "result" not in data
    assert "_full_result" not in data


@pytest.mark.asyncio
async def test_get_grouped_vulns_task_flow(client, mock_dt_client):
    # Configure mock for context manager usage
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    # Setup mocks
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]

    # Mock get_vulnerabilities
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "vulnerability": {"vulnId": "CVE-1", "severity": "HIGH"},
            "component": {"name": "c1", "uuid": "comp1", "version": "1.0"},
            "analysis": {"state": "NOT_SET"},
        },
        {
            "vulnerability": {"vulnId": "CVE-OPEN", "severity": "MEDIUM"},
            "component": {"name": "c2", "uuid": "comp2", "version": "1.0"},
            "analysis": {
                "state": "IN_TRIAGE",
                "analysisDetails": "--- [Team: team-a] [State: NOT_SET] ---\n[Status: Pending Review]",
            },
        },
        {
            "vulnerability": {"vulnId": "CVE-2026-TEAM-PARTIAL", "severity": "MEDIUM"},
            "component": {"name": "c3", "uuid": "comp3", "version": "1.0"},
            "analysis": {
                "state": "IN_TRIAGE",
                "analysisDetails": "--- [Team: team-a] [State: NOT_AFFECTED] ---\n--- [Team: team-b] [State: NOT_SET] ---\n[Status: Pending Review]",
            },
        },
    ]
    # Mock project_vulnerabilities
    mock_dt_client.get_project_vulnerabilities.return_value = []
    # Mock get_bom
    mock_dt_client.get_bom.return_value = {}

    # Patch DTClient in main to return our mock when instantiated
    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        # 1. Start Task
        response = client.post("/api/tasks/group-vulns?name=TestApp")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # 2. Poll Status
        await asyncio.sleep(0.1)

        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200
        status = response.json()

        # Poll loop
        for _ in range(10):
            if status["status"] == "completed":
                break
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "failed":
                pytest.fail(f"Task failed: {status['message']}")

    assert status["status"] == "completed"
    data = status["result"]

    assert len(data) == 3

    ids = {item["id"] for item in data}
    assert "CVE-1" in ids
    assert "CVE-OPEN" in ids
    assert "CVE-2026-TEAM-PARTIAL" in ids

    open_group = next(item for item in data if item["id"] == "CVE-OPEN")
    assert len(open_group["affected_versions"]) == 1
    open_comp = open_group["affected_versions"][0]["components"][0]
    assert open_comp["analysis_state"] == "IN_TRIAGE"
    assert "[Status: Pending Review]" in open_comp["analysis_details"]

    partial_group = next(item for item in data if item["id"] == "CVE-2026-TEAM-PARTIAL")
    assert len(partial_group["affected_versions"]) == 1
    partial_comp = partial_group["affected_versions"][0]["components"][0]
    assert partial_comp["analysis_state"] == "IN_TRIAGE"
    assert "Team: team-a" in partial_comp["analysis_details"]
    assert "Team: team-b" in partial_comp["analysis_details"]

    # The partial team case should still show as pending review with open work left
    assert "[Status: Pending Review]" in partial_comp["analysis_details"]


@pytest.mark.asyncio
async def test_get_grouped_vulns_summary_mode_keeps_detail_lookup(
    client, mock_dt_client
):
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "uuid": "finding-1",
            "vulnerability": {
                "vulnId": "CVE-2026-DETAIL",
                "uuid": "vuln-1",
                "severity": "HIGH",
                "cvssV3BaseScore": 8.1,
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            },
            "component": {
                "name": "library-a",
                "uuid": "component-1",
                "version": "2.0",
            },
            "analysis": {
                "state": "IN_TRIAGE",
                "analysisDetails": (
                    "--- [Team: General] [State: IN_TRIAGE] "
                    "[Assessed By: reviewer] [Justification: CODE_NOT_REACHABLE] ---\n"
                    "Full reviewer notes that should not be needed by list rows."
                ),
                "analysisComments": [{"comment": "heavy comment", "timestamp": 1}],
                "justification": "CODE_NOT_REACHABLE",
            },
        }
    ]
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {
        "components": [{"bom-ref": "component-1", "name": "library-a"}],
        "dependencies": [{"ref": "component-1", "dependsOn": []}],
    }

    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        response = client.post(
            "/api/tasks/group-vulns?name=TestApp&response_mode=summary"
        )
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "completed":
                break
            if status["status"] == "failed":
                pytest.fail(f"Task failed: {status['message']}")

    assert status["status"] == "completed"
    assert status["result_mode"] == "summary"
    assert "_full_result" not in status
    assert "_group_query_index" not in status
    assert main.tasks[task_id]["_group_query_index"]["total"] == 1

    summary_group = status["result"][0]
    summary_component = summary_group["affected_versions"][0]["components"][0]
    assert summary_group["id"] == "CVE-2026-DETAIL"
    assert summary_group["list_metadata"]["lifecycle"] == "ASSESSED"
    assert summary_group["list_metadata"]["technical_state"] == "IN_TRIAGE"
    assert summary_component["analysis_state"] == "IN_TRIAGE"
    assert summary_component["justification"] == "CODE_NOT_REACHABLE"
    assert "analysis_details" not in summary_component
    assert "analysis_comments" not in summary_component
    assert "dependency_chains" not in summary_component

    response = client.get(f"/api/tasks/{task_id}/groups/CVE-2026-DETAIL")
    assert response.status_code == 200
    full_group = response.json()
    full_component = full_group["affected_versions"][0]["components"][0]
    assert "Full reviewer notes" in full_component["analysis_details"]
    assert full_component["analysis_comments"][0]["comment"] == "heavy comment"
    assert full_component["dependency_chains"] == ["library-a"]


@pytest.mark.asyncio
async def test_get_grouped_vulns_no_projects(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = []

    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        # Start task
        response = client.post("/api/tasks/group-vulns?name=NonExistent")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # Poll until complete
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "completed":
                break

        assert status["status"] == "completed"
        assert status["result"] == []


@pytest.mark.asyncio
async def test_get_grouped_vulns_task_failure(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.side_effect = Exception("DT API Down")

    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        response = client.post("/api/tasks/group-vulns?name=ErrorApp")
        task_id = response.json()["task_id"]

        # Poll
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "failed":
                break

        assert status["status"] == "failed"
        assert "DT API Down" in status["message"]


def test_get_task_status_not_found(client):
    response = client.get("/api/tasks/unknown-id")
    assert response.status_code == 200
    assert response.json()["status"] == "not_found"


@pytest.mark.asyncio
async def test_statistics_major_version_split(client, mock_dt_client):
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0.0"},
        {"name": "TestApp", "uuid": "uuid2", "version": "2.0.0"},
    ]

    findings_by_uuid = {
        "uuid1": [
            {
                "vulnerability": {"vulnId": "CVE-1", "severity": "HIGH"},
                "component": {"name": "lib", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
        "uuid2": [
            {
                "vulnerability": {"vulnId": "CVE-2", "severity": "CRITICAL"},
                "component": {"name": "lib", "version": "1.1", "uuid": "comp2"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    async def get_vulnerabilities(project_uuid, cve=None):
        return findings_by_uuid[project_uuid]

    mock_dt_client.get_vulnerabilities.side_effect = get_vulnerabilities

    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {}

    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        response = client.get("/api/statistics?name=TestApp")
        assert response.status_code == 200
        data = response.json()

        assert data["version_counts"]["1.0.0"] == 1
        assert data["version_counts"]["2.0.0"] == 1
        assert data["major_version_counts"]["1"] == 1
        assert data["major_version_counts"]["2"] == 1
        assert data["version_severity_counts"]["1.0.0"]["HIGH"] == 1
        assert data["version_severity_counts"]["2.0.0"]["CRITICAL"] == 1
        assert data["major_version_severity_counts"]["1"]["HIGH"] == 1
        assert data["major_version_severity_counts"]["2"]["CRITICAL"] == 1
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["CRITICAL"] == 1
        assert data["unique_severity_counts"]["HIGH"] == 1
        assert data["unique_severity_counts"]["CRITICAL"] == 1
        assert data["finding_state_counts"]["NOT_SET"] == 2


async def test_grouped_vulnerabilities_with_vector_merge(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    # Mock projects
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"}
    ]

    # Mock findings without vector
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "vulnerability": {
                "vulnId": "CVE-2023-001",
                "uuid": "vuuid1",
                "severity": "HIGH",
            },
            "component": {"name": "lib", "version": "1.0", "uuid": "comp1"},
            "analysis": {"state": "NOT_SET"},
        }
    ]

    # Mock full vulnerabilities with vector
    mock_dt_client.get_project_vulnerabilities.return_value = [
        {
            "vulnId": "CVE-2023-001",
            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvssV3BaseScore": 9.8,
        }
    ]
    # Mock get_bom
    mock_dt_client.get_bom.return_value = {}

    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        # Start Task
        response = client.post("/api/tasks/group-vulns?name=TestProj")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # Poll until done
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            if response.json()["status"] == "completed":
                break

    status = response.json()
    assert status["status"] == "completed"
    data = status["result"]

    assert len(data) == 1
    # Verify vector was merged
    assert data[0]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert data[0]["cvss_score"] == 9.8


def test_get_sbom_endpoints(client, tmp_path):
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir(parents=True, exist_ok=True)

    # Create backend and frontend BOM files as well as default
    backend_path = sbom_dir / "dtvp-backend-cyclonedx.json"
    frontend_path = sbom_dir / "dtvp-frontend-cyclonedx.json"
    default_path = sbom_dir / "dtvp-cyclonedx.json"

    backend_path.write_text('{"bomFormat": "CycloneDX", "type": "backend"}')
    frontend_path.write_text('{"bomFormat": "CycloneDX", "type": "frontend"}')
    default_path.write_text('{"bomFormat": "CycloneDX", "type": "default"}')

    # Monkey-patch working directory for the app
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        r = client.get("/api/sbom")
        assert r.status_code == 200
        assert r.json()["type"] == "backend"

        r = client.get("/api/sbom/backend")
        assert r.status_code == 200
        assert r.json()["type"] == "backend"

        r = client.get("/api/sbom/frontend")
        assert r.status_code == 200
        assert r.json()["type"] == "frontend"
    finally:
        os.chdir(original_cwd)


def test_assessment_update(client, mock_dt_client):
    payload = {
        "instances": [
            {
                "project_uuid": "puuid",
                "component_uuid": "cuuid",
                "vulnerability_uuid": "vuuid",
                "finding_uuid": "fuuid",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "Verified as false positive",
        "comment": "False positive",
        "suppressed": True,
    }

    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        response = client.post("/api/assessment", json=payload)
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 1
        assert results[0]["status"] == "success"

    # Verify client call
    mock_dt_client.update_analysis.assert_called_once()
    call_kwargs = mock_dt_client.update_analysis.call_args.kwargs
    assert call_kwargs["project_uuid"] == "puuid"
    assert call_kwargs["state"] == "NOT_AFFECTED"
    # Details now includes the appended user tag
    assert "Verified as false positive" in call_kwargs["details"]
    assert "[Reviewed By: testuser]" in call_kwargs["details"]
    assert call_kwargs["suppressed"] is True


def test_assessment_update_refreshes_grouped_task_windows(client, mock_dt_client):
    from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
    from dtvp.task_group_query_services import build_task_group_query_index

    task_id = "assessment-refreshes-task-window"
    full_group = {
        "id": "CVE-2026-REFRESH",
        "title": "Refresh test",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "tags": [],
        "aliases": [],
        "affected_versions": [
            {
                "project_name": "Project",
                "project_version": "1.0.0",
                "project_uuid": "puuid",
                "components": [
                    {
                        "project_name": "Project",
                        "project_version": "1.0.0",
                        "project_uuid": "puuid",
                        "component_name": "library-a",
                        "component_version": "1.2.3",
                        "component_uuid": "cuuid",
                        "vulnerability_uuid": "vuuid",
                        "finding_uuid": "fuuid",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                        "is_suppressed": False,
                    }
                ],
            }
        ],
    }
    full_result = [full_group]
    summary_result = summarize_grouped_vulnerabilities(full_result, {})
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": summary_result,
        "_full_result": full_result,
        "_full_result_by_id": {full_group["id"]: full_group},
        "_group_query_index": build_task_group_query_index(summary_result),
    }

    payload = {
        "instances": [
            {
                "project_uuid": "puuid",
                "component_uuid": "cuuid",
                "vulnerability_uuid": "vuuid",
                "finding_uuid": "fuuid",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "Reviewed as not affected",
        "suppressed": False,
    }

    try:
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            response = client.post("/api/assessment", json=payload)

        assert response.status_code == 200
        open_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"lifecycle": "OPEN"},
        )
        assessed_response = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"lifecycle": "ASSESSED"},
        )
    finally:
        main.tasks.pop(task_id, None)

    assert open_response.status_code == 200
    assert open_response.json()["filtered"] == 0
    assert assessed_response.status_code == 200
    assessed_data = assessed_response.json()
    assert assessed_data["filtered"] == 1
    assert assessed_data["items"][0]["id"] == "CVE-2026-REFRESH"
    assert assessed_data["items"][0]["list_metadata"]["lifecycle"] == "ASSESSED"
    mock_dt_client.update_analysis.assert_called_once()


def test_assessment_update_failure(client, mock_dt_client):
    mock_dt_client.update_analysis.side_effect = Exception("Analysis update failed")

    payload = {
        "instances": [
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "Fail",
    }

    response = client.post("/api/assessment", json=payload)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert "Analysis update failed" in results[0]["error"]


def test_spa_routing(client):
    # Check if SPA route matches expected catch-all pattern
    # The route path depends on context_path, so finding it by name or analyzing paths is needed.
    # main.py defines it as f"{context_path}/{{path:path}}"

    spa_route_exists = False
    for route in main.app.routes:
        if hasattr(route, "path") and "{path:path}" in route.path:
            spa_route_exists = True
            break

    if not spa_route_exists:
        pytest.skip("SPA routing not enabled (frontend/dist missing)")

    # Ensure dummy asset exists for test
    import os

    os.makedirs("frontend/dist/assets", exist_ok=True)
    with open("frontend/dist/assets/test.css", "w") as f:
        f.write("body {}")

    # 1. Catch-all route should return index.html for unknown paths
    response = client.get("/projects")  # Client-side route
    assert response.status_code == 200

    # 2. Static assets
    response = client.get("/assets/test.css")
    assert response.status_code == 200
