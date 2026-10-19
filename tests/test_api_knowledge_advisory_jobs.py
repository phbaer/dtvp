"""Native refresh uses known IDs, frozen evidence scope and current authorization."""

import httpx
import pytest
import respx

from dtvp.jobs import work_once
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def configured(client, app, bom, provider="nvd"):
    project_id, _ = setup(client, bom)
    journal = app.state.knowledge
    app.state.settings.providers_enabled = [provider]
    heads = product_heads(journal.references(), project_id)
    identifier = next(
        value["identifier"]
        for value in load_sections(journal, next(iter(heads.values())))["vulnerabilities"].values()
        if value.get("identifier", "").startswith("CVE-")
    )
    data = {
        "request_id": "advisory-test",
        "provider": provider,
        "identifiers": [identifier],
        "expected_versions": heads,
        "expected_evidence": journal.resolve(evidence_ref(project_id)),
        "revision": 1,
    }
    return project_id, identifier, data


def response(provider, identifier):
    if provider == "nvd":
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": identifier,
                        "descriptions": [{"lang": "en", "value": "Source-attributed enrichment"}],
                        "metrics": {},
                        "references": [],
                    }
                }
            ]
        }
    return {
        "cveMetadata": {"cveId": identifier},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Source-attributed enrichment"}],
                "providerMetadata": {"shortName": "Example CNA"},
                "references": [],
            }
        },
    }


@pytest.mark.parametrize("provider", ["nvd", "circl"])
@respx.mock
def test_native_advisory_roundtrip_keeps_baseline_and_never_approves(analyst, app, bom, provider):
    project_id, identifier, data = configured(analyst, app, bom, provider)
    endpoint = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        if provider == "nvd"
        else f"https://vulnerability.circl.lu/api/vulnerability/{identifier}"
    )
    route = respx.get(endpoint).mock(
        return_value=httpx.Response(200, json=response(provider, identifier))
    )
    path = url(project_id, "/advisory-jobs")
    preview = analyst.get(
        url(project_id, "/advisory-refresh"), params={"q": identifier, "limit": 1}
    ).json()
    assert preview["identifiers"] == [identifier] and preview["total"] == 1
    assert preview["expected_versions"] == data["expected_versions"]
    assert preview["expected_evidence"] == data["expected_evidence"]
    selected_provider = next(value for value in preview["providers"] if value["id"] == provider)
    assert selected_provider["enabled"] and selected_provider["next_revision"] == 0
    queued = analyst.post(path, json=data)
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert analyst.post(path, json=data).json() == job
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    completed = analyst.get(path + "/" + job["id"]).json()
    assert completed["status"] == "succeeded", completed
    assert completed["result"]["projection"] == "current"
    captured = completed["result"]["capture_sha256"]
    artifact = analyst.get(
        url(project_id, "/evidence/artifacts/" + captured),
        params={"expected_evidence": completed["result"]["evidence_state"]},
    )
    assert artifact.status_code == 200, artifact.text
    assert artifact.headers["X-Content-SHA256"] == captured
    assert artifact.content == app.state.knowledge.objects.read(captured)
    assert analyst.get(url(project_id, "/evidence/artifacts/" + "f" * 64)).status_code == 404
    refreshed = analyst.get(url(project_id, "/advisory-refresh")).json()
    assert (
        next(value for value in refreshed["providers"] if value["id"] == provider)["next_revision"]
        == 2
    )
    assert route.call_count == 1
    assert all(call.request.method == "GET" for call in respx.calls)
    current = workspace(analyst, project_id)
    assert any("Source-attributed enrichment" in str(item) for item in current["items"])
    assert all(not item["coverage"].get("approved") for item in current["items"])
    assert analyst.get(path, params={"limit": 1}).json()["items"][0]["id"] == job["id"]
    assert analyst.post(f"/api/v1/jobs/{job['id']}/retry").status_code == 404


def test_refresh_permissions_disabled_unknown_ids_cancellation_and_scope_conflicts(
    analyst, app, bom
):
    project_id, _, data = configured(analyst, app, bom)
    path = url(project_id, "/advisory-jobs")
    app.state.settings.providers_enabled = []
    assert analyst.post(path, json=data).status_code == 422
    app.state.settings.providers_enabled = ["nvd"]
    assert analyst.post(path, json={**data, "identifiers": ["CVE-2099-9999999"]}).status_code == 422
    assert analyst.post(path, json={**data, "expected_versions": {}}).status_code == 409
    queued = analyst.post(path, json=data).json()
    assert analyst.post(path, json={**data, "revision": 2}).status_code == 409
    login(analyst, "reviewer")
    assert analyst.get(path + "/" + queued["id"]).status_code == 200
    assert analyst.post(path + "/" + queued["id"] + "/cancel").status_code == 403
    login(analyst, "viewer")
    assert analyst.post(path, json={**data, "request_id": "denied"}).status_code == 404
    assert analyst.post(path + "/" + queued["id"] + "/cancel").status_code == 404
    login(analyst, "analyst")
    cancelled = analyst.post(path + "/" + queued["id"] + "/cancel")
    assert cancelled.json()["status"] == "cancelled"
    assert not work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    assert analyst.post(path + "/" + queued["id"] + "/retry").status_code == 409
