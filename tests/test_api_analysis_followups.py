"""New native follow-up route uses exact parent proof and current project authority."""

import httpx
import respx

from dtvp.jobs import work_once
from dtvp.knowledge.agentyzer import derive_analysis_input
from dtvp.knowledge.analysis_followups import parent_material
from dtvp.models import Job
from tests.conftest import login
from tests.test_api_knowledge_analysis_jobs import endpoint, prepared
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import url, workspace

app = knowledge_app
TOKEN = "private-followup-http-service-" + "x" * 32
BASE = "http://agentyzer.test"


def parent(client, app, bom):
    project, payload = prepared(client, app, bom)
    app.state.settings.agentyzer_token = TOKEN
    app.state.settings.agentyzer_reconciliation_enabled = True
    derived = derive_analysis_input(
        app.state.knowledge, payload["expected"], payload["context_id"], payload["vulnerability_id"]
    )
    envelope = report(derived)
    envelope["job"]["job_id"] = "parent-remote"
    respx.post(BASE + "/assess").mock(
        return_value=httpx.Response(202, json={"job_id": "parent-remote"})
    )
    respx.get(BASE + "/jobs/parent-remote").mock(
        return_value=httpx.Response(200, json=envelope["job"])
    )
    respx.get(BASE + "/jobs/parent-remote/result").mock(
        return_value=httpx.Response(200, json=envelope["report"])
    )
    response = client.post(endpoint(project), json=payload)
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    with app.state.sessions() as db:
        selected = db.get(Job, identity)
        assert selected.status == "succeeded", selected.error
        _, pins, scope = parent_material(
            db,
            app.state.knowledge,
            app.state.settings,
            project_id=project,
            version="7.1.1",
            parent_id=identity,
            report_sha=selected.payload["report_sha256"],
        )
        private_nonce = selected.payload["correlation"]["nonce"]
        body = {
            "request_id": "follow-up-http",
            "expected": selected.result["state"],
            "parent_report_sha256": selected.payload["report_sha256"],
            "question": "Check the configured source entry point",
        }
    preflight = respx.get(BASE + "/jobs/parent-remote/dtvp-follow-up-parent").mock(
        return_value=httpx.Response(
            200,
            json={"format": "agentyzer.dtvp-follow-up-parent/1", "parent": pins, "scope": scope},
        )
    )
    return project, identity, body, preflight, private_nonce


@respx.mock
def test_target_authorized_different_analyst_can_queue_exact_parent_and_replay(analyst, app, bom):
    project, parent_id, data, preflight, nonce = parent(analyst, app, bom)
    login(analyst, "reviewer")
    path = url(project, f"/versions/7.1.1/analysis-jobs/{parent_id}/follow-up")
    response = analyst.post(path, json=data)
    assert response.status_code == 202, response.text
    child = response.json()
    assert child["parent_job_id"] == parent_id and child["status"] == "queued"
    assert nonce not in response.text and "credential_id" not in response.text
    replay = analyst.post(path, json=data)
    assert replay.status_code == 202 and replay.json() == child and preflight.call_count == 1
    with app.state.sessions() as db:
        assert db.get(Job, child["id"]).actor_id != db.get(Job, parent_id).actor_id
    assert (
        analyst.post(path, json=data | {"question": "Changed under same request"}).status_code
        == 409
    )
    login(analyst, "operations")
    assert analyst.post(path, json=data).status_code == 404
    assert preflight.call_count == 1


@respx.mock
def test_parent_scope_and_question_validation_precede_remote_preflight(analyst, app, bom):
    project, parent_id, data, preflight, _ = parent(analyst, app, bom)
    path = url(project, f"/versions/7.1.1/analysis-jobs/{parent_id}/follow-up")
    before = app.state.knowledge.head()
    assert analyst.post(path, json=data | {"question": " \t "}).status_code == 422
    assert analyst.post(path, json=data | {"source_commit": "0" * 40}).status_code == 422
    assert analyst.post(path, json=data | {"parent_report_sha256": "0" * 64}).status_code == 409
    assert analyst.post(path, json=data | {"expected": "0" * 64}).status_code == 409
    assert preflight.call_count == 0 and app.state.knowledge.head() == before


@respx.mock
def test_wrong_or_missing_remote_capability_enqueues_nothing_and_does_not_disclose_proof(
    analyst, app, bom
):
    project, parent_id, data, preflight, nonce = parent(analyst, app, bom)
    path = url(project, f"/versions/7.1.1/analysis-jobs/{parent_id}/follow-up")
    preflight.mock(return_value=httpx.Response(404))
    response = analyst.post(path, json=data)
    assert response.status_code == 502 and nonce not in response.text
    with app.state.sessions() as db:
        assert (
            len(list(db.query(Job).filter(Job.project_id == project, Job.kind == "analyse-native")))
            == 1
        )
    assert workspace(analyst, project)["state"] == data["expected"]
