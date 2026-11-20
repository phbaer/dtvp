"""Reviewing and exporting the queue of local assessments."""

from datetime import datetime
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.access_token_services import access_token_store
from dtvp.dt_cache import get_export_mode
from tests.helpers import wait_for_grouped_task


def _finding(suffix):
    return {
        "uuid": f"finding-{suffix}",
        "vulnerability": {"vulnId": f"CVE-2026-000{suffix}", "uuid": f"vuln-{suffix}", "severity": "HIGH"},
        "component": {"name": "library-a", "uuid": f"component-{suffix}", "version": "2.0"},
        "analysis": {"analysisState": "IN_TRIAGE", "analysisDetails": "From the source"},
    }


def _instance(suffix):
    return {
        "project_uuid": "p1",
        "component_uuid": f"component-{suffix}",
        "vulnerability_uuid": f"vuln-{suffix}",
        "finding_uuid": f"finding-{suffix}",
    }


@pytest.fixture
def queued(client, mock_dt_client):
    """Two local assessments waiting for export."""
    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "p1", "version": "1.0"}
    ]
    mock_dt_client.get_vulnerabilities.return_value = [_finding(1), _finding(2)]
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {"components": [], "dependencies": []}
    # The source still holds what was imported.
    mock_dt_client.get_analysis.return_value = {
        "analysisState": "IN_TRIAGE",
        "analysisDetails": "From the source",
        "isSuppressed": False,
    }
    with patch("dtvp.main.DTClient", return_value=mock_dt_client), patch(
        "dtvp.main.get_user_role", return_value="REVIEWER"
    ):
        task_id = client.post(
            "/api/tasks/group-vulns?name=TestApp&response_mode=summary"
        ).json()["task_id"]
        wait_for_grouped_task(client, task_id)
        for suffix in (1, 2):
            assert client.post(
                "/api/assessment",
                json={
                    "instances": [_instance(suffix)],
                    "state": "NOT_AFFECTED",
                    "details": f"Decision {suffix}",
                    "team": "General",
                },
            ).status_code == 200
        yield mock_dt_client


def test_export_mode_defaults_to_automatic(monkeypatch):
    monkeypatch.delenv("DTVP_EXPORT_MODE", raising=False)
    assert get_export_mode() == "auto"
    monkeypatch.setenv("DTVP_EXPORT_MODE", " Manual ")
    assert get_export_mode() == "manual"
    monkeypatch.setenv("DTVP_EXPORT_MODE", "sometimes")
    assert get_export_mode() == "auto"


async def test_background_export_waits_in_manual_mode(queued, monkeypatch):
    monkeypatch.setenv("DTVP_EXPORT_MODE", "manual")
    assert await main.cache_manager.export_if_automatic(queued) is False
    queued.update_analysis.assert_not_awaited()
    assert main.cache_manager.get_cache_status()["pending_updates"] == 2

    monkeypatch.setenv("DTVP_EXPORT_MODE", "auto")
    assert await main.cache_manager.export_if_automatic(queued) is True
    assert queued.update_analysis.await_count == 2


def test_queue_shows_what_would_be_exported_and_what_it_replaces(
    client, queued, monkeypatch
):
    monkeypatch.setenv("DTVP_EXPORT_MODE", "manual")

    body = client.get("/api/export").json()

    assert body["mode"] == "manual"
    assert [item["vulnerability_id"] for item in body["pending"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    first = body["pending"][0]
    assert first["project_name"] == "TestApp" and first["project_version"] == "1.0"
    assert (first["component_name"], first["component_version"]) == ("library-a", "2.0")
    assert first["status"] == "pending"
    assert first["author"] == "rita" and first["origin"] == "individual-assessment"
    assert first["local"]["analysisState"] == "NOT_AFFECTED"
    # The list carries no texts; they are fetched for the entry that is opened.
    assert first["local"] == {"analysisState": "NOT_AFFECTED", "isSuppressed": False}
    assert first["source"] == {"analysisState": "IN_TRIAGE", "isSuppressed": False}
    texts = client.get("/api/export/texts", params={"update_id": first["update_id"]}).json()
    assert texts["update_id"] == first["update_id"]
    assert "Decision 1" in texts["local"]["analysisDetails"]
    assert texts["source"] == {
        "analysisState": "IN_TRIAGE",
        "analysisDetails": "From the source",
        "isSuppressed": False,
    }
    assert client.get("/api/export/texts", params={"update_id": "nope"}).status_code == 404


def test_reviewer_exports_a_chosen_change_then_the_rest(client, queued):
    pending = client.get("/api/export").json()["pending"]

    one = client.post("/api/export", json={"update_ids": [pending[1]["update_id"]]})

    assert one.status_code == 200
    assert one.json() == {
        "exported": 1,
        "dropped": 0,
        "remaining": 1,
        "failed": [],
    }
    assert queued.update_analysis.await_count == 1
    assert "Decision 2" in queued.update_analysis.await_args.kwargs["details"]

    rest = client.post("/api/export", json={})
    assert rest.json()["exported"] == 1 and rest.json()["remaining"] == 0
    assert client.get("/api/export").json()["pending"] == []


def test_failed_exports_are_reported_with_their_error(client, queued):
    queued.update_analysis.side_effect = RuntimeError("source rejected the write")

    result = client.post("/api/export", json={}).json()

    assert result["exported"] == 0 and result["remaining"] == 2
    assert {item["status"] for item in result["failed"]} == {"error"}
    assert "source rejected the write" in result["failed"][0]["error"]


def test_only_reviewers_export(client, queued, monkeypatch):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.post("/api/export", json={}).status_code == 403
        assert client.get("/api/export").status_code == 200
    queued.update_analysis.assert_not_awaited()

    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    main.app.dependency_overrides.pop(main.get_current_user)
    _record, plain = access_token_store.create(
        username="rita", name="bot", scopes=["read", "write"]
    )
    headers = {"Authorization": f"Bearer {plain}"}
    assert client.post("/api/export", json={}, headers=headers).status_code == 403
    assert len(client.get("/api/export", headers=headers).json()["pending"]) == 2
    queued.update_analysis.assert_not_awaited()


def test_a_finding_the_source_dropped_is_not_reported_as_exported(client, queued):
    import httpx

    request = httpx.Request("PUT", "http://dt/api/v1/analysis")
    queued.update_analysis.side_effect = httpx.HTTPStatusError(
        "gone", request=request, response=httpx.Response(404, request=request)
    )
    queued.finding_exists.return_value = False

    result = client.post("/api/export", json={}).json()

    assert result["exported"] == 0
    assert result["dropped"] == 2
    assert result["remaining"] == 0 and result["failed"] == []


def test_failures_are_counted_and_stuck_exports_can_be_discarded(client, queued):
    queued.update_analysis.side_effect = RuntimeError("404 Not Found")
    client.post("/api/export", json={})

    status = client.get("/api/cache-status").json()
    assert status["pending_updates"] == 2 and status["failed_exports"] == 2
    assert status["oldest_pending_at"]
    pending = client.get("/api/export").json()["pending"]
    assert all(item["project_known"] is True and item["attempts"] == 1 for item in pending)

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.post(
            "/api/export/discard", json={"update_ids": [pending[0]["update_id"]]}
        ).status_code == 403
    assert client.post("/api/export/discard", json={"update_ids": []}).status_code == 422

    discarded = client.post(
        "/api/export/discard", json={"update_ids": [pending[0]["update_id"], "nope"]}
    )
    assert discarded.json() == {"discarded": 1, "remaining": 1}
    status = client.get("/api/cache-status").json()
    assert status["pending_updates"] == 1 and status["failed_exports"] == 1
    # The local assessment is back at the value the source holds.
    overlay = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    assert overlay["analysisDetails"] == "From the source"
    assert overlay["dtvpSyncStatus"] == "synced"
    history = client.get(
        "/api/assessments/history",
        params={"project_uuid": "p1", "component_uuid": "component-1", "vulnerability_uuid": "vuln-1"},
    ).json()
    assert (history[0]["origin"], history[0]["author"]) == ("export-discarded", "rita")
    # The same assessment as atomic fields.
    identity = {"project_uuid": "p1", "component_uuid": "component-1", "vulnerability_uuid": "vuln-1"}
    fields = client.get("/api/assessments/fields", params=identity).json()
    assert (fields["form"], fields["free_text"]) == ("text", "From the source")
    missing = client.get(
        "/api/assessments/fields", params={**identity, "component_uuid": "unknown"}
    )
    assert missing.status_code == 404


def test_an_access_token_cannot_discard_exports(client, queued, monkeypatch):
    pending = client.get("/api/export").json()["pending"]
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    main.app.dependency_overrides.pop(main.get_current_user)
    _record, plain = access_token_store.create(
        username="rita", name="bot", scopes=["read", "write"]
    )
    response = client.post(
        "/api/export/discard",
        json={"update_ids": [pending[0]["update_id"]]},
        headers={"Authorization": f"Bearer {plain}"},
    )
    assert response.status_code == 403
    assert main.cache_manager.get_cache_status()["pending_updates"] == 2


async def test_an_export_for_a_deleted_project_still_shows_product_and_version(
    client, queued
):
    # The source stops listing the project.
    queued.get_projects.return_value = []
    main.cache_manager._project_list_refreshed_at = 0
    await main.cache_manager._refresh_project_list(queued)

    pending = client.get("/api/export").json()["pending"]

    assert {item["project_known"] for item in pending} == {False}
    assert (pending[0]["project_name"], pending[0]["project_version"]) == ("TestApp", "1.0")
    assert pending[0]["project_last_seen_at"]
    assert pending[0]["component_name"] == "library-a"


# -- CycloneDX documents -----------------------------------------------------


def test_vdr_carries_the_local_assessments_not_yet_exported(client, queued, monkeypatch):
    queued.get_bom.return_value = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"bom-ref": "component-1", "name": "library-a", "version": "2.0"},
            {"bom-ref": "component-2", "name": "library-a", "version": "2.0"},
        ],
    }
    with patch("dtvp.main.DTClient", return_value=queued):
        response = client.get("/api/project/p1/cyclonedx", params={"variant": "vdr"})
        named = client.get(
            "/api/cyclonedx",
            params={
                "name": "TestApp", "version": "1.0", "download": "true",
                "assessment_source": "ACME", "property_prefix": "acme",
            },
        )
        inventory = client.get("/api/project/p1/cyclonedx", params={"variant": "inventory"})
        bad_prefix = client.get(
            "/api/project/p1/cyclonedx", params={"property_prefix": "a:b"}
        )
        unknown = client.get("/api/cyclonedx", params={"name": "TestApp", "version": "9"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    document = response.json()
    entries = {entry["id"]: entry for entry in document["vulnerabilities"]}
    assert set(entries) == {"CVE-2026-0001", "CVE-2026-0002"}
    first = entries["CVE-2026-0001"]
    # DTVP's value, although Dependency-Track does not hold it yet.
    # When the General assessment was saved.
    assert first["analysis"].pop("lastUpdated").startswith("20")
    assert first["analysis"] == {"state": "not_affected", "detail": "Decision 1"}
    assert first["affects"] == [{"ref": "component-1"}]
    assert {"name": "dtvp:assessed_by", "value": "rita"} in first["properties"]
    assert "[Team:" not in response.text

    assert named.status_code == 200
    assert named.headers["content-disposition"] == (
        'attachment; filename="TestApp-1.0.vdr.cdx.json"'
    )
    assert {"name": "acme:export_assessment_source", "value": "ACME"} in (
        named.json()["metadata"]["properties"]
    )
    assert inventory.status_code == 200 and "vulnerabilities" not in inventory.json()
    assert bad_prefix.status_code == 422
    assert unknown.status_code == 404


def test_vdr_uses_vulnerability_records_ticket_keys_and_the_team_mapping(
    client, queued, monkeypatch
):
    from unittest.mock import AsyncMock

    queued.get_bom.return_value = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"bom-ref": "component-1", "name": "library-a", "version": "2.0"},
            {"bom-ref": "component-2", "name": "library-a", "version": "2.0"},
        ],
    }
    records = [
        {
            "uuid": "vuln-1", "vulnId": "CVE-2026-0001", "source": "NVD",
            "cvssV3BaseScore": 7.5,
            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "cvssV4Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "published": 1777058234490, "updated": 1777144634000,
            "recommendation": "Upgrade.",
        }
    ]
    monkeypatch.setenv("DTVP_CYCLONEDX_TICKET_PREFIXES", "EXP, SEC")
    with patch("dtvp.main.DTClient", return_value=queued), patch(
        "dtvp.main.get_user_role", return_value="REVIEWER"
    ), patch("dtvp.app_wiring.load_team_mapping", return_value={"*": "Unknown"}):
        # The component has no team: the fallback name of the mapping.
        saved = client.post(
            "/api/assessment",
            json={
                "instances": [_instance(1)], "state": "NOT_AFFECTED",
                "details": "See EXP-12.", "team": "Unknown",
            },
        )
        with patch.object(
            main.cache_manager, "get_project_vulnerabilities",
            AsyncMock(return_value=records),
        ):
            response = client.get("/api/project/p1/cyclonedx")
            requested = client.get(
                "/api/project/p1/cyclonedx", params={"ticket_prefixes": "ABC"}
            )
            bad = client.get(
                "/api/project/p1/cyclonedx", params={"ticket_prefixes": "EXP,a-b"}
            )
        with patch.object(
            main.cache_manager, "get_project_vulnerabilities",
            AsyncMock(side_effect=RuntimeError("down")),
        ):
            without = client.get("/api/project/p1/cyclonedx")

    assert saved.status_code == 200 and response.status_code == 200
    document = response.json()
    first = next(e for e in document["vulnerabilities"] if e["id"] == "CVE-2026-0001")
    assert [(r["method"], r["score"]) for r in first["ratings"]] == [
        ("CVSSv4", 8.7), ("CVSSv31", 7.5),
    ]
    assert first["published"] == "2026-04-24T19:17:14.490000+00:00"
    assert first["updated"] == "2026-04-25T19:17:14+00:00"
    assert first["recommendation"] == "Upgrade."
    properties = {item["name"]: item["value"] for item in first["properties"]}
    assert properties["dtvp:spr"] == "EXP-12"
    assert "dtvp:team_state" not in properties
    [annotation] = document["annotations"]
    assert annotation["annotator"] == {"individual": {"name": "rita"}}
    assert annotation["text"] == "See EXP-12."
    metadata = {item["name"]: item["value"] for item in document["metadata"]["properties"]}
    assert metadata["dtvp:export_ticket_prefixes"] == "EXP, SEC"
    assert metadata["dtvp:export_text_only_tickets"] == "1"
    assert "dtvp:export_advisory_records" not in metadata
    # When the findings were last read from Dependency-Track.
    assert datetime.fromisoformat(metadata["dtvp:export_findings_read_at"]).tzinfo is not None

    # The request names other keys than the configuration.
    assert requested.json()["metadata"]["properties"][-2:] == [
        {"name": "dtvp:export_ticket_prefixes", "value": "ABC"},
        {"name": "dtvp:export_text_only_tickets", "value": "0"},
    ]
    assert bad.status_code == 422

    # Without the vulnerability records the document says so.
    assert without.status_code == 200
    assert {"name": "dtvp:export_advisory_records", "value": "unavailable"} in (
        without.json()["metadata"]["properties"]
    )



# -- gone findings -------------------------------------------------------------


async def test_gone_findings_are_listed_per_version_and_by_name(client, queued):
    # Dependency-Track stops reporting the second finding; its BOM has no
    # component left.
    queued.get_vulnerabilities.return_value = [_finding(1)]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)

    with patch("dtvp.main.DTClient", return_value=queued):
        one = client.get("/api/project/p1/gone-findings")
        named = client.get("/api/gone-findings", params={"name": "TestApp"})
        unknown = client.get("/api/project/nothing/gone-findings")
        missing_name = client.get("/api/gone-findings")

    assert one.status_code == 200
    body = one.json()
    assert body["project_uuid"] == "p1"
    assert body["gone"] == {"component_removed": 1}
    assert "complete" not in body["last_read"]
    assert body["last_read"]["went"] == {"component_removed": 1}
    [gone] = body["findings"]
    assert (gone["vuln_id"], gone["component_name"], gone["reason"]) == (
        "CVE-2026-0002", "library-a", "component_removed",
    )
    assert gone["gone_at"] and gone["successor"] is None
    # The saved assessment is kept, no longer exported.
    assert gone["assessment"]["sync_status"] == "inactive"
    assert gone["assessment"]["state"] == "NOT_AFFECTED"

    assert named.status_code == 200
    assert named.json()["name"] == "TestApp"
    assert [(v["version"], v["gone"]) for v in named.json()["versions"]] == [
        ("1.0", {"component_removed": 1})
    ]
    assert unknown.json() == {
        "project_uuid": "nothing", "last_read": None, "gone": {}, "findings": [],
    }
    assert missing_name.status_code == 422
