from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from dtvp import main
from dtvp.dt_client import DTClient
from dtvp.knowledge_store import knowledge_store


@pytest.fixture(autouse=True)
def isolate_knowledge_store(tmp_path):
    original_base_path = knowledge_store.base_path
    knowledge_store.base_path = str(tmp_path / "knowledge")
    yield
    knowledge_store.base_path = original_base_path


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
