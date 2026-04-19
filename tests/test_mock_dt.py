from fastapi.testclient import TestClient

from test_setup import mock_dt


def test_mock_dt_can_override_analysis_state():
    client = TestClient(mock_dt.app)
    params = {
        "project": mock_dt.PROJECT_UUID,
        "component": mock_dt.COMPONENT_UUID,
        "vulnerability": mock_dt.VULN_UUID_1,
    }

    original = client.get("/api/v1/analysis", params=params)
    assert original.status_code == 200
    assert original.json()["analysisState"] != "NOT_AFFECTED"

    override_response = client.post(
        "/api/v1/mock/analysis",
        json={
            "project": mock_dt.PROJECT_UUID,
            "component": mock_dt.COMPONENT_UUID,
            "vulnerability": mock_dt.VULN_UUID_1,
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Simulated conflict state",
        },
    )

    assert override_response.status_code == 200
    assert override_response.json()["analysisState"] == "NOT_AFFECTED"
    assert override_response.json()["analysisDetails"] == "Simulated conflict state"

    updated = client.get("/api/v1/analysis", params=params)
    assert updated.status_code == 200
    assert updated.json()["analysisState"] == "NOT_AFFECTED"
    assert updated.json()["analysisDetails"] == "Simulated conflict state"


def test_mock_dt_can_reset_analysis_state():
    client = TestClient(mock_dt.app)
    params = {
        "project": mock_dt.PROJECT_UUID,
        "component": mock_dt.COMPONENT_UUID,
        "vulnerability": mock_dt.VULN_UUID_1,
    }

    client.post(
        "/api/v1/mock/analysis",
        json={
            "project": mock_dt.PROJECT_UUID,
            "component": mock_dt.COMPONENT_UUID,
            "vulnerability": mock_dt.VULN_UUID_1,
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Temporary state",
        },
    )

    reset_response = client.post("/api/v1/mock/analysis/reset")
    assert reset_response.status_code == 200
    assert reset_response.json()["status"] == "reset"

    restored = client.get("/api/v1/analysis", params=params)
    assert restored.status_code == 200
    assert restored.json()["analysisState"] != "NOT_AFFECTED"
    assert restored.json()["analysisDetails"] != "Temporary state"
