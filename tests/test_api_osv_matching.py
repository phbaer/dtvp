"""Native API, scheduler dispatch, projection and current matching-job authority."""

import httpx

from dtvp.jobs import work_once
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_osv_jobs import install_transport
from tests.test_knowledge_osv_matching import NOVEL, upstream
from tests.test_workflow_api import url

app = knowledge_app


def prepare(client, app, bom):
    project = product(client)
    login(client, "administrator")
    imported(client, project, "matching", body(bom))
    app.state.settings.providers_enabled = ["osv"]
    response = client.get(url(project, "/osv-matching"))
    assert response.status_code == 200, response.text
    inputs = response.json()
    data = {
        "request_id": "osv-native",
        "expected_versions": inputs["expected_versions"],
        "expected_evidence": inputs["expected_evidence"],
        "purls": [inputs["purls"][0]],
        "revision": inputs["next_revision"],
    }
    return project, data


def test_native_scheduler_dispatch_capture_artifacts_projection_and_current_scope(
    analyst, app, bom, monkeypatch
):
    project, data = prepare(analyst, app, bom)
    install_transport(monkeypatch, lambda _: httpx.Response(200, json={"vulns": [upstream()]}))
    queued = analyst.post(url(project, "/osv-jobs"), json=data)
    assert queued.status_code == 202, queued.text
    identity = queued.json()["id"]
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    result = analyst.get(url(project, f"/osv-jobs/{identity}"))
    assert result.status_code == 200 and result.json()["status"] == "succeeded", result.text
    assert result.json()["result"]["projection"] == "current"
    assert (
        result.json()["result"]["remaining_selected_coverage"] == "published_provider_observations"
    )
    sha = result.json()["result"]["capture_sha256"]
    artifact = analyst.get(url(project, f"/osv-jobs/{identity}/artifacts/{sha}"))
    assert artifact.status_code == 200 and artifact.headers["x-content-sha256"] == sha
    state = result.json()["result"]["versions"]["matching"]
    workspace = analyst.get(url(project, "/versions/matching/workspace"))
    assert workspace.status_code == 200 and NOVEL in str(workspace.json())
    assert app.state.knowledge.state(state).version == "matching"
    repeated = analyst.post(url(project, "/osv-jobs"), json=data)
    assert repeated.status_code == 202 and repeated.json()["id"] == identity
    login(analyst, "viewer")
    assert analyst.get(url(project, f"/osv-jobs/{identity}/artifacts/{sha}")).status_code == 200
    assert analyst.post(url(project, f"/osv-jobs/{identity}/retry")).status_code == 404
    assert analyst.post(url(project, "/osv-jobs"), json=data).status_code == 404


def test_matching_inputs_partial_selection_cancel_foreign_artifact_and_disabled_provider(
    analyst, app, bom
):
    project, data = prepare(analyst, app, bom)
    inputs = analyst.get(url(project, "/osv-matching"), params={"limit": 1}).json()
    assert len(inputs["purls"]) == 1 and inputs["total"] > 1 and inputs["next_offset"] == 1
    assert inputs["coverage"]["unqueried_coverage"] == "unknown"
    queued = analyst.post(url(project, "/osv-jobs"), json=data)
    identity = queued.json()["id"]
    assert queued.json()["result"]["unqueried_eligible_purls"] > 0
    assert (
        analyst.get(url(project, f"/osv-jobs/{identity}/artifacts/" + "0" * 64)).status_code == 404
    )
    assert analyst.get(url("foreign", f"/osv-jobs/{identity}")).status_code == 404
    assert (
        analyst.post(url(project, f"/osv-jobs/{identity}/cancel")).json()["status"] == "cancelled"
    )
    app.state.settings.providers_enabled = []
    assert (
        analyst.post(url(project, "/osv-jobs"), json=data | {"request_id": "disabled"}).status_code
        == 422
    )


def test_stale_heads_and_outside_inventory_queries_do_not_enqueue(analyst, app, bom):
    project, data = prepare(analyst, app, bom)
    forged = data | {"request_id": "outside", "purls": ["pkg:npm/not-in-product@1"]}
    assert analyst.post(url(project, "/osv-jobs"), json=forged).status_code == 422
    imported(analyst, project, "parallel", body(bom, request_id="parallel-version"))
    assert analyst.post(url(project, "/osv-jobs"), json=data).status_code == 409
