"""Deleting an assessment is an explicit operation that is exported, unlike
the source merely reporting nothing."""

from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.access_token_services import access_token_store
from dtvp.logic import calculate_aggregated_state, remove_assessment_blocks
from tests.helpers import wait_for_grouped_task

TEAM_A = "--- [Team: Team A] [State: NOT_AFFECTED] [Assessed By: alice] ---\nA's reasoning."
TEAM_B = "--- [Team: Team B] [State: EXPLOITABLE] [Assessed By: bob] ---\nB's reasoning."
GENERAL = (
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
    "[Reviewed By: rita] [Rescored: 0.0] ---\nApproved."
)
FULL = f"[Rescored: 0.0]\n\n{GENERAL}\n\n{TEAM_A}\n\n{TEAM_B}"

INSTANCE = {
    "project_uuid": "p1",
    "component_uuid": "component-1",
    "vulnerability_uuid": "vuln-1",
    "finding_uuid": "finding-1",
}


# -- text ------------------------------------------------------------------


def test_removing_a_team_keeps_everything_else_verbatim():
    result = remove_assessment_blocks(FULL + "\n\n[Status: Pending Review]", "team a")

    assert result == f"[Rescored: 0.0]\n\n{GENERAL}\n\n{TEAM_B}"
    assert remove_assessment_blocks(FULL, "General") == (
        f"[Rescored: 0.0]\n\n{TEAM_A}\n\n{TEAM_B}"
    )
    assert calculate_aggregated_state(remove_assessment_blocks(FULL, "General")) == (
        "EXPLOITABLE"
    )


def test_removing_everything_or_nothing():
    assert remove_assessment_blocks(FULL, None) == ""
    assert remove_assessment_blocks(FULL, "Team Z") == FULL
    assert remove_assessment_blocks("Legacy free text", "Team A") == "Legacy free text"
    assert remove_assessment_blocks("", "Team A") == ""
    assert remove_assessment_blocks(TEAM_A, "Team A") == ""


def test_removing_the_general_block_takes_its_ssvc_record_along():
    with_ssvc = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] "
        "[SSVC: DEFER] ---\nText\n\n[SSVC Details]\n{\"note\": \"--- [Team: X] ---\"}\n"
        "[/SSVC Details]\n\n" + TEAM_A
    )
    assert remove_assessment_blocks(with_ssvc, "General") == TEAM_A


# -- operation ---------------------------------------------------------------


@pytest.fixture
def assessed(client, mock_dt_client):
    """One finding with a General and two team assessments, synchronized."""
    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "p1", "version": "1.0"}
    ]
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "uuid": "finding-1",
            "vulnerability": {"vulnId": "CVE-2026-0001", "uuid": "vuln-1", "severity": "HIGH"},
            "component": {"name": "library-a", "uuid": "component-1", "version": "2.0"},
            "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": FULL, "isSuppressed": True},
        }
    ]
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {"components": [], "dependencies": []}
    mock_dt_client.get_analysis.return_value = {
        "analysisState": "NOT_AFFECTED",
        "analysisDetails": FULL,
        "isSuppressed": True,
    }
    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        task_id = client.post(
            "/api/tasks/group-vulns?name=TestApp&response_mode=summary"
        ).json()["task_id"]
        wait_for_grouped_task(client, task_id)
        yield task_id


def _stored():
    return main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")


def test_analyst_deletes_a_team_assessment_and_it_is_exported(
    client, assessed, mock_dt_client
):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.post(
            "/api/assessment/delete", json={"instances": [INSTANCE], "team": "Team B"}
        )

    assert response.status_code == 200
    result = response.json()[0]
    assert result["uuid"] == "finding-1" and result["revision"] == 1
    stored = _stored()
    assert "[Team: Team B]" not in stored["analysisDetails"]
    assert "A's reasoning." in stored["analysisDetails"]
    assert "[Team: General]" in stored["analysisDetails"]
    assert stored["analysisDetails"].endswith("[Status: Pending Review]")
    assert stored["isSuppressed"] is True  # untouched by a team deletion
    assert stored["dtvpSyncStatus"] == "pending"
    history = main.cache_manager.get_assessment_history("p1", "component-1", "vuln-1")
    assert (history[0]["origin"], history[0]["author"]) == ("assessment-deletion", "rita")
    # The open view follows.
    detail = client.get(f"/api/tasks/{assessed}/groups/CVE-2026-0001").json()
    assert "[Team: Team B]" not in detail["affected_versions"][0]["components"][0][
        "analysis_details"
    ]


def test_a_deletion_keeps_the_grouped_snapshot(client, assessed):
    """It is patched into the snapshot, so the next request does not build
    the project again."""
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.post(
            "/api/assessment/delete", json={"instances": [INSTANCE], "team": "Team B"}
        )
    assert response.status_code == 200

    again = client.post("/api/tasks/group-vulns?name=TestApp&response_mode=summary")

    assert again.json() == {"task_id": assessed, "reused": True}
    detail = client.get(f"/api/tasks/{assessed}/groups/CVE-2026-0001").json()
    component = detail["affected_versions"][0]["components"][0]
    assert "[Team: Team B]" not in component["analysis_details"]


async def test_reviewer_deletes_everything_and_the_source_is_cleared_for_good(
    client, assessed, mock_dt_client
):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        response = client.post("/api/assessment/delete", json={"instances": [INSTANCE]})
    assert response.status_code == 200
    stored = _stored()
    assert (stored["analysisState"], stored["analysisDetails"], stored["isSuppressed"]) == (
        "NOT_SET",
        "",
        False,
    )

    await main.cache_manager.flush_pending_updates(mock_dt_client)

    exported = mock_dt_client.update_analysis.await_args.kwargs
    assert (exported["state"], exported["details"], exported["suppressed"]) == (
        "NOT_SET",
        "",
        False,
    )
    assert _stored()["dtvpSyncStatus"] == "synced"

    # The source now reports nothing, and that is not mistaken for a loss.
    mock_dt_client.get_vulnerabilities.return_value[0]["analysis"] = {
        "analysisState": "NOT_SET",
        "analysisDetails": "",
        "isSuppressed": False,
    }
    mock_dt_client.update_analysis.reset_mock()
    await main.cache_manager.get_vulnerabilities(mock_dt_client, "p1", refresh=True)
    await main.cache_manager.flush_pending_updates(mock_dt_client)
    mock_dt_client.update_analysis.assert_not_awaited()
    assert _stored()["analysisDetails"] == ""


def test_only_reviewers_delete_the_general_assessment_or_everything(client, assessed):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        for body in (
            {"instances": [INSTANCE]},
            {"instances": [INSTANCE], "team": None},
            {"instances": [INSTANCE], "team": "general"},
        ):
            assert client.post("/api/assessment/delete", json=body).status_code == 403
    assert _stored() is None

    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        response = client.post(
            "/api/assessment/delete", json={"instances": [INSTANCE], "team": "General"}
        )
    assert response.status_code == 200
    stored = _stored()
    assert "[Team: General]" not in stored["analysisDetails"]
    assert stored["analysisState"] == "EXPLOITABLE"  # worst remaining team state
    assert "[Status: Pending Review]" not in stored["analysisDetails"]


def test_nothing_to_delete_and_bad_requests_are_refused(client, assessed):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        assert client.post(
            "/api/assessment/delete", json={"instances": [INSTANCE], "team": "Team Z"}
        ).status_code == 422
        assert client.post(
            "/api/assessment/delete", json={"instances": [INSTANCE], "team": "  "}
        ).status_code == 422
        assert client.post(
            "/api/assessment/delete",
            json={"instances": [{"finding_uuid": "finding-1"}], "team": "Team A"},
        ).status_code == 422
        assert client.post("/api/assessment/delete", json={"instances": [INSTANCE]}).status_code == 200
        # Already empty.
        assert client.post("/api/assessment/delete", json={"instances": [INSTANCE]}).status_code == 422
    assert _stored()["dtvpRevision"] == 1


def test_an_access_token_cannot_delete(client, assessed, monkeypatch):
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    main.app.dependency_overrides.pop(main.get_current_user)
    _record, plain = access_token_store.create(
        username="rita", name="bot", scopes=["read", "write"]
    )
    response = client.post(
        "/api/assessment/delete",
        json={"instances": [INSTANCE], "team": "Team A"},
        headers={"Authorization": f"Bearer {plain}"},
    )
    assert response.status_code == 403
    assert _stored() is None


async def test_global_cleanup_without_general_clears_shared_fields_but_keeps_team_assessments(
    client, assessed, mock_dt_client
):
    from dtvp.assessment_model import parse_assessment

    details = f'[Rescored: 0.0] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N] [Response: UPDATE]\n\n{TEAM_A}\n\n{TEAM_B}\n\n[Status: Pending Review]'
    await main.cache_manager.persist_assessment_updates([
        {**{key: INSTANCE[key] for key in ('project_uuid', 'component_uuid', 'vulnerability_uuid')},
         'state': 'EXPLOITABLE', 'details': details, 'suppressed': True}
    ], origin='individual-assessment')
    before = parse_assessment('EXPLOITABLE', _stored()['analysisDetails'], True)
    with patch('dtvp.main.get_user_role', return_value='REVIEWER'):
        response = client.post('/api/assessment/delete', json={'instances': [INSTANCE], 'team': 'General'})
    assert response.status_code == 200
    stored = _stored()
    after = parse_assessment(stored['analysisState'], stored['analysisDetails'], stored['isSuppressed'])
    assert after['teams'] == before['teams']
    assert after['state'] == 'EXPLOITABLE'  # derived from the preserved teams
    assert after['pending_review'] is False
    assert after['rescored_score'] is None and after['rescored_vector'] is None
    assert after['response'] is None and after['suppressed'] is False
    await main.cache_manager.flush_pending_updates(mock_dt_client)
    exported = mock_dt_client.update_analysis.await_args.kwargs
    assert '[Status: Pending Review]' not in exported['details']
    assert '[Team: Team A]' in exported['details'] and '[Team: Team B]' in exported['details']
    with patch('dtvp.main.get_user_role', return_value='REVIEWER'):
        assert client.post('/api/assessment/delete', json={'instances': [INSTANCE], 'team': 'General'}).status_code == 422
