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


def test_update_assessment_analyst_cannot_rescore(override_deps, mock_client):
    client = TestClient(app)

    # Analyst tries to inject rescoring tags in details
    payload = {
        "instances": [
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            }
        ],
        "state": "EXPLOITABLE",
        "details": "Analyst details [Rescored: 9.9] [Rescored Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L]",
    }

    # Mock get_user_role to return ANALYST
    with patch("main.get_user_role", return_value="ANALYST"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_called_once()
        _, kwargs = mock_client.update_analysis.call_args

        # Verify rescoring tags are STRIPPED or ignored by the backend
        assert "[Rescored: 9.9]" not in kwargs["details"]
        assert "[Rescored Vector: CVSS:4.0" not in kwargs["details"]
        # Ensure it's still marked as pending
        assert "[Status: Pending Review]" in kwargs["details"]


def test_update_assessment_replace_mode_derives_rescored_score(override_deps, mock_client):
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
        "state": "EXPLOITABLE",
        "details": "[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L]\n\n--- [Team: General] [State: EXPLOITABLE] [Assessed By: testuser] ---\nReviewer details",
        "comparison_mode": "REPLACE",
    }

    with patch("main.get_user_role", return_value="REVIEWER"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_called_once()
        _, kwargs = mock_client.update_analysis.call_args

        assert "[Rescored: 7.7]" in kwargs["details"]
        assert "[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L]" in kwargs["details"]
        assert "[Virtual Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L]" in kwargs["details"]


def test_update_assessment_replace_mode_embeds_virtual_vector_for_cvss4(override_deps, mock_client):
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
        "state": "IN_TRIAGE",
        "details": "[Rescored Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L]\n\n--- [Team: General] [State: IN_TRIAGE] [Assessed By: testuser] ---\nReviewer details",
        "comparison_mode": "REPLACE",
    }

    with patch("main.get_user_role", return_value="REVIEWER"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_called_once()
        _, kwargs = mock_client.update_analysis.call_args

        assert "[Rescored: 10.0]" in kwargs["details"]
        assert "[Rescored Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L]" in kwargs["details"]
        assert "[Virtual Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H]" in kwargs["details"]
