import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from main import app, get_current_user, get_user_client, get_current_user_roles


# Override dependencies
@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.update_analysis = AsyncMock()
    return client


@pytest.fixture
def override_deps(mock_client):
    async def mock_get_user_client():
        yield mock_client

    app.dependency_overrides[get_user_client] = mock_get_user_client
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides = {}


def test_update_assessment_as_reviewer_no_flag(override_deps, mock_client):
    # Setup Reviewer role
    app.dependency_overrides[get_current_user_roles] = lambda: ["REVIEWER"]
    client = TestClient(app)

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
        "details": "Original details",
        "comment": "My comment",
        "justification": "CODE_NOT_REACHABLE",
        "suppressed": False,
    }

    resp = client.post("/api/assessment", json=payload)
    assert resp.status_code == 200
    assert resp.json()[0]["status"] == "success"

    # Verify update_analysis call
    mock_client.update_analysis.assert_called_once()
    _, kwargs = mock_client.update_analysis.call_args

    # Check details has username
    assert "Original details" in kwargs["details"]
    assert "[Reviewed by: testuser]" in kwargs["details"]
    # Ensure pending flag NOT added for Reviewer
    assert "[Status: Pending Review]" not in kwargs["details"]


def test_update_assessment_as_analyst_has_flag(override_deps, mock_client):
    # Setup Analyst role
    app.dependency_overrides[get_current_user_roles] = lambda: ["ANALYST"]
    client = TestClient(app)

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
        "details": "Analyst details",
    }

    resp = client.post("/api/assessment", json=payload)
    assert resp.status_code == 200

    mock_client.update_analysis.assert_called_once()
    _, kwargs = mock_client.update_analysis.call_args

    # Check details has username AND Pending Review flag
    assert "Analyst details" in kwargs["details"]
    assert "[Assessed by: testuser]" in kwargs["details"]
    assert "[Status: Pending Review]" in kwargs["details"]
