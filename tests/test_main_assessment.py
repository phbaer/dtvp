from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from dtvp import main


# Override dependencies
@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.update_analysis = AsyncMock()
    return client


@pytest.fixture
def override_deps(mock_client):
    main.app.dependency_overrides[main.get_client] = lambda: mock_client
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    async def _noop_sync():
        return None

    with patch.object(main.cache_manager, "background_sync_loop", _noop_sync):
        yield
    main.app.dependency_overrides = {}


def test_update_assessment_appends_user(override_deps, mock_client):
    client = TestClient(main.app)

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
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200
        assert resp.json()[0]["status"] == "success"
        assert resp.json()[0]["queued"] is True

        mock_client.update_analysis.assert_not_called()
        queued_payload = main.cache_manager._load_pending_updates()[0]["payload"]

        # Check details has username in the team block header
        assert "Original details" in queued_payload["details"]
        # Using containment check for parts of the header
        assert (
            "[Team: General] [State: NOT_AFFECTED] [Assessed By: testuser]"
            in queued_payload["details"]
        )
        assert "[Reviewed By: testuser]" in queued_payload["details"]
        # Ensure pending flag NOT added for Reviewer
        assert "[Status: Pending Review]" not in queued_payload["details"]


def test_update_assessment_analyst_pending_flag(override_deps, mock_client):
    client = TestClient(main.app)

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
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_not_called()
        queued_payload = main.cache_manager._load_pending_updates()[0]["payload"]

        # Check details has username AND Pending Review flag
        assert "Analyst details" in queued_payload["details"]
        assert (
            "[Team: General] [State: NOT_AFFECTED] [Assessed By: testuser]"
            in queued_payload["details"]
        )
        assert "[Status: Pending Review]" in queued_payload["details"]


def test_update_assessment_analyst_cannot_rescore(override_deps, mock_client):
    client = TestClient(main.app)

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
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200

        mock_client.update_analysis.assert_not_called()
        queued_payload = main.cache_manager._load_pending_updates()[0]["payload"]

        # Verify rescoring tags are STRIPPED or ignored by the backend
        assert "[Rescored: 9.9]" not in queued_payload["details"]
        assert "[Rescored Vector: CVSS:4.0" not in queued_payload["details"]
        # Ensure it's still marked as pending
        assert "[Status: Pending Review]" in queued_payload["details"]


def test_update_assessment_replaces_duplicate_pending_update(
    override_deps, mock_client
):
    client = TestClient(main.app)
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
        "details": "First update",
    }

    # The request durably queues without waiting for Dependency-Track.
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        resp = client.post("/api/assessment", json=payload)
        assert resp.status_code == 200
        assert resp.json()[0]["status"] == "success"
        assert resp.json()[0]["queued"] is True

    # Second request for the same finding should replace the pending update.
    payload2 = {**payload, "details": "Second update"}
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        resp2 = client.post("/api/assessment", json=payload2)
        assert resp2.status_code == 200
        assert resp2.json()[0]["status"] == "success"
        assert resp2.json()[0]["queued"] is True

    pending = main.cache_manager._load_pending_updates()
    assert len(pending) == 1
    assert "Second update" in pending[0]["payload"]["details"]


def test_update_assessment_rejects_stale_local_revision(
    override_deps,
    mock_client,
):
    client = TestClient(main.app)
    instance = {
        "project_uuid": "p1",
        "component_uuid": "c1",
        "vulnerability_uuid": "v1",
        "finding_uuid": "f1",
    }
    first = {
        "instances": [instance],
        "state": "IN_TRIAGE",
        "details": "First update",
        "original_analysis": {
            "f1": {
                "analysisState": "NOT_SET",
                "analysisDetails": "",
                "dtvpRevision": 0,
            }
        },
    }

    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        first_response = client.post("/api/assessment", json=first)
        stale_response = client.post(
            "/api/assessment",
            json={
                **first,
                "state": "NOT_AFFECTED",
                "details": "Stale update",
            },
        )

    assert first_response.status_code == 200
    assert first_response.json()[0]["revision"] == 1
    assert stale_response.status_code == 409
    conflict = stale_response.json()["conflicts"][0]
    assert conflict["current"]["dtvpRevision"] == 1
    assert conflict["current"]["dtvpSyncStatus"] == "pending"
    assert "First update" in conflict["current"]["analysisDetails"]
    assert mock_client.get_analysis.await_count == 0
    assert mock_client.update_analysis.await_count == 0
