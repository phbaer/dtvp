import httpx
import respx

from dtvp.jobs import work_once
from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product
from tests.test_knowledge_dependency_track import BASE, EXTERNAL, OTHER, routes
from tests.test_workflow_api import url, workspace

app = knowledge_app


def setup(client, app):
    project_id = product(client)
    app.state.settings.dt_url = BASE
    app.state.settings.dt_api_key = "read-only-secret"
    login(client, "administrator")
    path = url(project_id, "/versions/7.1.1/connectors/dependency-track")
    payload = {"external_project_id": EXTERNAL, "expected_external_project_id": None}
    assert client.put(path, json=payload).status_code == 200
    login(client, "analyst")
    return project_id, {
        "request_id": "native-dt-1",
        "expected": None,
        "build_number": 1,
        "occurred_at": "2026-10-15T06:00:00Z",
    }


def endpoint(project_id):
    return url(project_id, "/versions/7.1.1/imports/dependency-track/jobs")


@respx.mock
def test_native_dt_job_roundtrip_retains_originals_and_plain_legacy_claims(analyst, app, bom):
    project_id, data = setup(analyst, app)
    _, _, _, original = routes(bom)
    response = analyst.post(endpoint(project_id), json=data)
    assert response.status_code == 202, response.text
    job = response.json()
    assert analyst.post(endpoint(project_id), json=data).json() == job
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    result = analyst.get(url(project_id, f"/source-jobs/{job['id']}")).json()
    assert result["status"] == "succeeded", result
    assert result["result"]["projection"] == "current"
    current = workspace(analyst, project_id)
    assert current["items"]
    sections = load_sections(app.state.knowledge, current["state"])
    source = sections["inventory"]["baseline"]["source_provenance"]
    assert not source["remote_snapshot_consistent"]
    assert source["external_project_id"] == EXTERNAL
    from dtvp.storage import digest

    download = analyst.get(
        url(project_id, f"/states/{current['state']}/artifacts/{digest(original)}")
    )
    assert download.content == original
    assert all(row["coverage"]["status"] == "unassessed" for row in current["items"])
    assert any(
        "Plain historical rationale" in str(row.get("legacy_evidence")) for row in current["items"]
    )
    assert all(call.request.method == "GET" for call in respx.calls)
    assert "read-only-secret" not in str(result)
    assert analyst.post(f"/api/v1/jobs/{job['id']}/retry").status_code == 404


def test_version_bindings_are_conditional_independent_and_management_only(analyst, app):
    project_id, _ = setup(analyst, app)
    first = url(project_id, "/versions/7.1.1/connectors/dependency-track")
    second = url(project_id, "/versions/7.1.2/connectors/dependency-track")
    data = {"external_project_id": OTHER, "expected_external_project_id": None}
    assert analyst.put(second, json=data).status_code == 404
    login(analyst, "administrator")
    assert analyst.put(second, json=data).status_code == 200
    assert analyst.put(first, json=data).status_code == 409
    assert analyst.get(first).json()["project_id"] == EXTERNAL
    assert analyst.get(second).json()["project_id"] == OTHER
    assert (
        analyst.put(
            f"/api/v1/projects/{project_id}/connectors/dependency-track",
            json={"external_project_id": OTHER},
        ).status_code
        == 404
    )
    assert analyst.get(first).json()["project_id"] == EXTERNAL
    assert analyst.get(second).json()["project_id"] == OTHER


@respx.mock
def test_partial_dt_fetch_never_publishes_inventory_or_creates_approval(analyst, app, bom):
    project_id, data = setup(analyst, app)
    _, page, _, _ = routes(bom)
    page.mock(return_value=httpx.Response(503))
    before = app.state.knowledge.head()
    queued = analyst.post(endpoint(project_id), json=data).json()
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    result = analyst.get(url(project_id, f"/source-jobs/{queued['id']}")).json()
    assert result["status"] == "failed"
    assert app.state.knowledge.head() == before
    login(analyst, "reviewer")
    assert (
        analyst.post(endpoint(project_id), json={**data, "request_id": "denied"}).status_code == 404
    )
    assert analyst.post(url(project_id, f"/source-jobs/{queued['id']}/retry")).status_code == 404
