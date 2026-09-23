from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from dtvp import main
from dtvp.ssvc_services import SsvcInput, new_record, read_record, write_record


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


def test_ssvc_rules_and_reviewer_only_write_preservation(override_deps, mock_client):
    client = TestClient(main.app)
    models = client.get("/api/ssvc/models")
    assert models.status_code == 200
    assert len(models.json()["models"][0]["mapping"]) == 72
    selection = {"model": "ssvc:DT_DP", "version": "1.0.0", "answers": {}, "rationale": "To assess"}
    instance = {"project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1", "finding_uuid": "f1"}
    payload = {"instances": [instance], "state": "NOT_SET", "details": "Assessment", "ssvc": selection}
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.post("/api/assessment", json=payload).status_code == 403
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        assert client.post("/api/assessment", json={**payload, "team": "Team A"}).status_code == 403
        assert client.post("/api/assessment", json={**payload, "ssvc": {**selection, "version": "unknown"}}).status_code == 422
        assert client.post("/api/assessment", json={**payload, "ssvc": {**selection, "exploitation_evidence": "forged"}}).status_code == 422
        saved = client.post("/api/assessment", json=payload)
        assert saved.status_code == 200
        record = read_record(saved.json()[0]["new_details"])
        assert record["assessor"] == "testuser"
        assert record["outcome"] is None
        assert record["priority"] == "Incomplete"
        assert "[SSVC: INCOMPLETE]" in saved.json()[0]["new_details"]
        assert '[SSVC Details]\n{\n' in saved.json()[0]["new_details"]
        assert "SSVC priority: Incomplete" in saved.json()[0]["new_details"]
    # Client metadata cannot forge or clear reviewer-owned SSVC, even in REPLACE mode.
    forged = write_record("", new_record(SsvcInput(**{**selection, "rationale": "Forged"}), "attacker"))
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        for details in ("Team update", forged):
            updated = client.post("/api/assessment", json={
                "instances": [{**instance, "analysis_details": forged}],
                "state": "IN_TRIAGE", "details": details, "team": "Team A", "comparison_mode": "REPLACE",
                "original_analysis": {"f1": {"analysisDetails": forged}},
            })
            assert updated.status_code == 200
            assert read_record(updated.json()[0]["new_details"]) == record
            assert updated.json()[0]["new_details"].count("SSVC priority: Incomplete") == 1
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        cleared = client.post("/api/assessment", json={**payload, "ssvc": None})
        assert cleared.status_code == 200
        assert read_record(cleared.json()[0]["new_details"]) is None
        assert "SSVC priority:" not in cleared.json()[0]["new_details"]
        assert "[SSVC Details]" not in cleared.json()[0]["new_details"]
    mock_client.get_analysis.assert_not_called()


def test_ssvc_exploitation_route_validates_and_forwards_refresh(override_deps):
    client = TestClient(main.app)
    assert client.get("/api/ssvc/exploitation?cve=invalid").status_code == 422
    assert client.get("/api/ssvc/exploitation?cve=CVE-2024-25522").json()["enabled"] is False
    with patch("dtvp.general_api_routes.get_ssvc_enrichment_service") as get_service:
        get_service.return_value.lookup = AsyncMock(return_value={"sources": [], "suggestion": None})
        response = client.get("/api/ssvc/exploitation?cve=CVE-2024-25522&cve=CVE-2024-4947&refresh=true")
        assert response.status_code == 200
        get_service.return_value.lookup.assert_awaited_once_with(["CVE-2024-25522", "CVE-2024-4947"], force=True)
    main.app.dependency_overrides.pop(main.get_current_user)
    assert client.get("/api/ssvc/exploitation?cve=CVE-2024-25522").status_code == 401


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


@pytest.mark.parametrize("eligible", [None, False])
def test_invalid_analyzer_result_cannot_write_assessment(override_deps, mock_client, eligible):
    assessment = {"verdict": "Not Affected", "adjusted_cvss": {"adjusted_score": 0.0}}
    if eligible is not None:
        assessment["application_eligible"] = eligible
    record = {"status": "completed", "result": {"assessment": assessment}}
    payload = {
        "instances": [{"project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1", "finding_uuid": "f1"}],
        "state": "NOT_AFFECTED", "details": "Invalid analyzer proposal", "justification": "CODE_NOT_REACHABLE",
        "analysis_run_ids": ["invalid-run"], "rescored_cvss": 0.0,
    }
    with patch.object(main.code_analysis_result_store, "get", return_value=record), patch.object(main.cache_manager, "persist_assessment_updates", new_callable=AsyncMock) as persist:
        response = TestClient(main.app).post("/api/assessment", json=payload)
    assert response.status_code == 422
    persist.assert_not_called()
    mock_client.update_analysis.assert_not_called()


@pytest.mark.parametrize("run_ids", ["invalid-run", [{"run": "invalid-run"}], 42])
def test_invalid_instance_run_ids_return_validation_error(override_deps, mock_client, run_ids):
    payload = {
        "instances": [{
            "project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1",
            "finding_uuid": "f1", "analysis_run_ids": run_ids,
        }],
        "state": "NOT_AFFECTED", "details": "Invalid provenance",
    }
    with patch.object(main.cache_manager, "persist_assessment_updates", new_callable=AsyncMock) as persist:
        response = TestClient(main.app).post("/api/assessment", json=payload)
    assert response.status_code == 422
    persist.assert_not_called()


def test_ineligible_component_blocks_assessment_write(override_deps, mock_client):
    record = {
        "result": {
            "assessment": {"application_eligible": True},
            "component_results": [{"assessment": {"application_eligible": False}}],
        },
    }
    payload = {
        "instances": [{
            "project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1",
            "finding_uuid": "f1", "analysis_run_ids": ["invalid-run"],
        }],
        "state": "NOT_AFFECTED", "details": "Invalid component result",
    }
    with patch.object(main.code_analysis_result_store, "get", return_value=record), patch.object(
        main.cache_manager, "persist_assessment_updates", new_callable=AsyncMock,
    ) as persist:
        response = TestClient(main.app).post("/api/assessment", json=payload)
    assert response.status_code == 422
    persist.assert_not_called()
