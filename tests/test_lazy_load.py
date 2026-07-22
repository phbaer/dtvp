from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from dtvp import main
from dtvp.dt_client import DTClient
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.task_group_query_services import build_task_group_query_index


@pytest.fixture
def mock_client():
    client = AsyncMock(spec=DTClient)
    client.update_analysis = AsyncMock(return_value=None)
    return client


@pytest.fixture
def api_client(mock_client):
    main.app.dependency_overrides[main.get_client] = lambda: mock_client
    main.app.dependency_overrides[main.get_current_user] = lambda: "test_user"
    with TestClient(main.app) as client:
        yield client
    main.app.dependency_overrides.clear()


def test_get_assessment_details_mock(api_client, mock_client):
    mock_client.get_analysis.return_value = {
        "analysisState": "NOT_SET",
        "analysisDetails": "Some details",
        "isSuppressed": False,
    }

    response = api_client.post(
        "/api/assessments/details",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                },
                {
                    "project_uuid": "p2",
                    "component_uuid": "c2",
                    "vulnerability_uuid": "v2",
                    "finding_uuid": "f2",
                },
            ]
        },
    )

    assert response.status_code == 200
    results = response.json()

    assert len(results) == 2
    assert results[0]["analysis"]["analysisState"] == "NOT_SET"
    assert results[0]["finding_uuid"] == "f1"
    assert mock_client.get_analysis.call_count == 2


def test_get_assessment_details_partial_failure(api_client, mock_client):
    mock_client.get_analysis.side_effect = [
        {"analysisState": "NOT_SET"},
        Exception("DB Error"),
    ]

    response = api_client.post(
        "/api/assessments/details",
        json={
            "instances": [
                {
                    "finding_uuid": "f1",
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                },
                {
                    "finding_uuid": "f2",
                    "project_uuid": "p2",
                    "component_uuid": "c2",
                    "vulnerability_uuid": "v2",
                },
            ]
        },
    )

    assert response.status_code == 200
    results = response.json()

    assert len(results) == 2
    assert results[0]["analysis"] is not None
    assert results[0]["error"] is None

    assert results[1]["analysis"] is None
    assert results[1]["error"] == "DB Error"


def test_get_assessment_details_refreshes_grouped_task_snapshot(api_client, mock_client):
    task_id = "task-card-reload"
    group = {
        "id": "CVE-2026-RELOAD",
        "title": "Reload assessment",
        "tags": [],
        "affected_versions": [
            {
                "project_name": "ReloadProject",
                "project_version": "1.0.0",
                "project_uuid": "reload-project",
                "components": [
                    {
                        "project_name": "ReloadProject",
                        "project_version": "1.0.0",
                        "project_uuid": "reload-project",
                        "component_name": "reload-component",
                        "component_version": "1.0.0",
                        "component_uuid": "reload-component-uuid",
                        "vulnerability_uuid": "reload-vulnerability-uuid",
                        "finding_uuid": "reload-finding-uuid",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                        "is_suppressed": False,
                    }
                ],
            }
        ],
    }
    summaries = summarize_grouped_vulnerabilities([group], {})
    main.tasks[task_id] = {
        "status": "completed",
        "result_mode": "summary",
        "result": summaries,
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "_group_query_index": build_task_group_query_index(summaries),
    }
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Reloaded directly from Dependency-Track",
        "analysisJustification": "REQUIRES_CONFIGURATION",
        "isSuppressed": True,
    }

    try:
        response = api_client.post(
            "/api/assessments/details",
            json={
                "instances": [
                    {
                        "project_uuid": "reload-project",
                        "component_uuid": "reload-component-uuid",
                        "vulnerability_uuid": "reload-vulnerability-uuid",
                        "finding_uuid": "reload-finding-uuid",
                    }
                ]
            },
        )

        assert response.status_code == 200
        refreshed_group = main.tasks[task_id]["_full_result_by_id"][group["id"]]
        component = refreshed_group["affected_versions"][0]["components"][0]
        assert component["analysis_state"] == "EXPLOITABLE"
        assert component["analysis_details"] == "Reloaded directly from Dependency-Track"
        assert component["justification"] == "REQUIRES_CONFIGURATION"
        assert component["is_suppressed"] is True
        assert main.tasks[task_id]["result"][0]["list_metadata"][
            "technical_state"
        ] == "EXPLOITABLE"
    finally:
        main.tasks.pop(task_id, None)


def test_update_assessment_conflict(api_client, mock_client):
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Server changed this",
        "isSuppressed": False,
    }

    response = api_client.post(
        "/api/assessment",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                    "project_name": "Pro",
                    "project_version": "1.0",
                    "component_name": "Comp",
                }
            ],
            "state": "NOT_AFFECTED",
            "details": "My local change",
            "original_analysis": {
                "f1": {
                    "analysisState": "NOT_SET",
                    "analysisDetails": "Original details",
                    "isSuppressed": False,
                }
            },
        },
    )

    assert response.status_code == 409
    content = response.json()
    assert content["status"] == "conflict"
    assert len(content["conflicts"]) == 1
    assert content["conflicts"][0]["finding_uuid"] == "f1"


def test_update_assessment_ignores_timestamp_differences(api_client, mock_client):
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "--- [Team: General] [State: EXPLOITABLE] [Assessed By: tester] [Date: 1710000000000] ---\nDetails\n",
        "isSuppressed": False,
    }

    response = api_client.post(
        "/api/assessment",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                    "project_name": "Pro",
                    "project_version": "1.0",
                    "component_name": "Comp",
                }
            ],
            "state": "EXPLOITABLE",
            "details": "My local change",
            "original_analysis": {
                "f1": {
                    "analysisState": "EXPLOITABLE",
                    "analysisDetails": "--- [Team: General] [State: EXPLOITABLE] [Assessed By: tester2] [Date: 1710001000000] ---\nDetails\n",
                    "isSuppressed": False,
                }
            },
        },
    )

    assert response.status_code == 200
    results = response.json()
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "success"


def test_update_assessment_no_conflict_with_same_analysis_details_key(
    api_client, mock_client
):
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Same details",
        "isSuppressed": False,
    }

    response = api_client.post(
        "/api/assessment",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                    "project_name": "Pro",
                    "project_version": "1.0",
                    "component_name": "Comp",
                }
            ],
            "state": "EXPLOITABLE",
            "details": "My local change",
            "original_analysis": {
                "f1": {
                    "analysisState": "EXPLOITABLE",
                    "analysis_details": "Same details",
                    "is_suppressed": False,
                }
            },
        },
    )

    assert response.status_code == 200
    results = response.json()
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "success"


def test_update_assessment_ignores_empty_current_analysis_if_same_baseline(
    api_client, mock_client
):
    mock_client.get_analysis.return_value = {}

    response = api_client.post(
        "/api/assessment",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                    "project_name": "Pro",
                    "project_version": "1.0",
                    "component_name": "Comp",
                }
            ],
            "state": "NOT_SET",
            "details": "",
            "original_analysis": {
                "f1": {
                    "analysisState": "NOT_SET",
                    "analysisDetails": "",
                    "isSuppressed": False,
                }
            },
        },
    )

    assert response.status_code == 200
    results = response.json()
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "success"


def test_update_assessment_force(api_client, mock_client):
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Server changed this",
        "isSuppressed": False,
    }

    response = api_client.post(
        "/api/assessment",
        json={
            "instances": [
                {
                    "project_uuid": "p1",
                    "component_uuid": "c1",
                    "vulnerability_uuid": "v1",
                    "finding_uuid": "f1",
                }
            ],
            "state": "NOT_AFFECTED",
            "details": "My local change",
            "original_analysis": {
                "f1": {
                    "analysisState": "NOT_SET",
                    "analysisDetails": "Original details",
                    "isSuppressed": False,
                }
            },
            "force": True,
        },
    )

    assert response.status_code == 200
    results = response.json()

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "success"
    mock_client.update_analysis.assert_called_once()
