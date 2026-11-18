"""A finding changed both in DTVP and in the source is shown as conflicting
and can be settled either way."""

from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.access_token_services import access_token_store
from tests.helpers import wait_for_grouped_task

KEY = {
    "project_uuid": "p1",
    "component_uuid": "component-1",
    "vulnerability_uuid": "vuln-1",
    "finding_uuid": "finding-1",
}


def _finding(state="NOT_SET", details=""):
    return {
        "uuid": "finding-1",
        "vulnerability": {
            "vulnId": "CVE-2026-0001",
            "uuid": "vuln-1",
            "severity": "HIGH",
            "cvssV3BaseScore": 8.1,
        },
        "component": {"name": "library-a", "uuid": "component-1", "version": "2.0"},
        "analysis": {"analysisState": state, "analysisDetails": details},
    }


@pytest.fixture
def source(client, mock_dt_client):
    main.app.dependency_overrides[main.get_current_user] = lambda: "alice"
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "p1", "version": "1.0"}
    ]
    findings = [_finding()]

    async def get_vulnerabilities(project_uuid, cve=None):
        return findings

    mock_dt_client.get_vulnerabilities.side_effect = get_vulnerabilities
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {"components": [], "dependencies": []}
    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        yield findings


def _load_group(client):
    task_id = client.post(
        "/api/tasks/group-vulns?name=TestApp&response_mode=summary"
    ).json()["task_id"]
    wait_for_grouped_task(client, task_id)
    window = client.get(f"/api/tasks/{task_id}/groups").json()
    detail = client.get(f"/api/tasks/{task_id}/groups/CVE-2026-0001").json()
    return task_id, window, detail


async def _diverge(client, mock_dt_client, source):
    """Assess locally, then let the source report a different change."""
    _load_group(client)
    saved = client.post(
        "/api/assessment",
        json={
            "instances": [KEY],
            "state": "NOT_AFFECTED",
            "details": "Mine",
            "team": "General",
        },
    )
    assert saved.status_code == 200
    source[0] = _finding("EXPLOITABLE", "Theirs")
    await main.cache_manager.get_vulnerabilities(mock_dt_client, "p1", refresh=True)


async def test_an_open_view_follows_a_conflict_found_in_the_background(
    client, mock_dt_client, source
):
    task_id, _window, _detail = _load_group(client)
    client.post(
        "/api/assessment",
        json={"instances": [KEY], "state": "NOT_AFFECTED", "details": "Mine", "team": "General"},
    )
    mock_dt_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Theirs",
        "isSuppressed": False,
    }

    # The export runs in the background and finds the source changed.
    await main.cache_manager.flush_pending_updates(mock_dt_client)

    mock_dt_client.update_analysis.assert_not_awaited()
    window = client.get(f"/api/tasks/{task_id}/groups").json()
    assert window["items"][0]["list_metadata"]["inconsistency_reasons"] == [
        "SOURCE_CONFLICT"
    ]
    detail = client.get(f"/api/tasks/{task_id}/groups/CVE-2026-0001").json()
    component = detail["affected_versions"][0]["components"][0]
    assert component["sync_status"] == "diverged"
    assert component["source_assessment"]["analysisDetails"] == "Theirs"


async def test_conflict_is_listed_as_conflicting_with_its_own_reason(
    client, mock_dt_client, source
):
    await _diverge(client, mock_dt_client, source)

    _task_id, window, detail = _load_group(client)

    row = window["items"][0]
    summary_component = row["affected_versions"][0]["components"][0]
    assert summary_component["sync_status"] == "diverged"
    assert summary_component["source_assessment"]["analysisDetails"] == "Theirs"
    assert row["list_metadata"]["lifecycle"] == "INCONSISTENT"
    assert row["list_metadata"]["inconsistency_reasons"] == ["SOURCE_CONFLICT"]
    assert window["counts"]["all"]["inconsistency_reason"]["SOURCE_CONFLICT"] == 1
    component = detail["affected_versions"][0]["components"][0]
    assert component["sync_status"] == "diverged"
    assert "Mine" in component["analysis_details"]
    assert component["source_assessment"] == {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Theirs",
        "isSuppressed": False,
    }
    assert client.get("/api/cache-status").json()["diverged_assessments"] == 1


@pytest.mark.parametrize(
    ("resolution", "kept", "status"),
    [("remote", "Theirs", "synced"), ("local", "Mine", "pending")],
)
async def test_resolving_updates_the_open_view_and_clears_the_conflict(
    client, mock_dt_client, source, resolution, kept, status
):
    await _diverge(client, mock_dt_client, source)
    task_id, _window, _detail = _load_group(client)

    resolved = client.post(
        "/api/assessments/conflicts/resolve",
        json={"instances": [KEY], "resolution": resolution},
    )

    assert resolved.status_code == 200
    analysis = resolved.json()[0]["analysis"]
    assert resolved.json()[0]["finding_uuid"] == "finding-1"
    assert kept in analysis["analysisDetails"]
    assert analysis["dtvpSyncStatus"] == status
    assert "dtvpRemote" not in analysis
    # The snapshot the user is looking at follows without a reload.
    detail = client.get(f"/api/tasks/{task_id}/groups/CVE-2026-0001").json()
    component = detail["affected_versions"][0]["components"][0]
    assert kept in component["analysis_details"]
    assert component["sync_status"] == status
    assert "source_assessment" not in component
    window = client.get(f"/api/tasks/{task_id}/groups").json()
    assert window["items"][0]["list_metadata"]["inconsistency_reasons"] == []
    assert client.get("/api/cache-status").json()["diverged_assessments"] == 0

    history = client.get(
        "/api/assessments/history",
        params={k: v for k, v in KEY.items() if k != "finding_uuid"},
    ).json()
    assert history[-1]["author"] == "alice"
    assert history[-1]["origin"] == "individual-assessment"
    if resolution == "remote":
        assert (history[0]["origin"], history[0]["author"]) == (
            "conflict-resolution",
            "alice",
        )


async def test_resolution_is_refused_without_a_conflict_or_identity(
    client, mock_dt_client, source
):
    _load_group(client)
    assert client.post(
        "/api/assessments/conflicts/resolve",
        json={"instances": [KEY], "resolution": "remote"},
    ).status_code == 409
    assert client.post(
        "/api/assessments/conflicts/resolve",
        json={"instances": [{"finding_uuid": "finding-1"}], "resolution": "remote"},
    ).status_code == 422
    assert client.post(
        "/api/assessments/conflicts/resolve",
        json={"instances": [KEY], "resolution": "merge"},
    ).status_code == 422


async def test_an_access_token_cannot_resolve_conflicts(
    client, mock_dt_client, source, monkeypatch
):
    await _diverge(client, mock_dt_client, source)
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    main.app.dependency_overrides.pop(main.get_current_user)
    _record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read", "write"]
    )

    refused = client.post(
        "/api/assessments/conflicts/resolve",
        json={"instances": [KEY], "resolution": "local"},
        headers={"Authorization": f"Bearer {plain}"},
    )

    assert refused.status_code == 403
    overlay = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    assert overlay["dtvpSyncStatus"] == "diverged"
