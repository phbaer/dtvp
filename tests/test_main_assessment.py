import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from main import app, get_current_user, get_client


# Override dependencies
@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.update_analysis = AsyncMock()
    return client


@pytest.fixture
def override_deps(mock_client):
    app.dependency_overrides[get_client] = lambda: mock_client
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides = {}


def test_update_assessment_appends_user(override_deps, mock_client):
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

    # Mock get_user_role to return REVIEWER (so no extra pending flag)
    with patch("main.get_user_role", return_value="REVIEWER"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200
        assert resp.json()[0]["status"] == "success"

        # Verify update_analysis call
        mock_client.update_analysis.assert_called_once()
        _, kwargs = mock_client.update_analysis.call_args

        # Check details has username in the team block header
        assert "Original details" in kwargs["details"]
        # Using containment check for parts of the header
        assert (
            "[Team: General] [State: NOT_AFFECTED] [Assessed By: testuser]"
            in kwargs["details"]
        )
        assert "[Reviewed By: testuser]" in kwargs["details"]
        # Ensure pending flag NOT added for Reviewer
        assert "[Status: Pending Review]" not in kwargs["details"]


def test_update_assessment_analyst_pending_flag(override_deps, mock_client):
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

    # Mock get_user_role to return ANALYST
    with patch("main.get_user_role", return_value="ANALYST"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_called_once()
        _, kwargs = mock_client.update_analysis.call_args

        # Check details has username AND Pending Review flag
        assert "Analyst details" in kwargs["details"]
        assert (
            "[Team: General] [State: NOT_AFFECTED] [Assessed By: testuser]"
            in kwargs["details"]
        )
        assert "[Status: Pending Review]" in kwargs["details"]
