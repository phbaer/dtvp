"""Actor-only authenticated GET recovery never resubmits a remote analysis."""

import copy

import httpx
import respx

from dtvp.models import Job
from tests.conftest import login
from tests.test_api_knowledge_analysis_jobs import prepared
from tests.test_knowledge_agentyzer import derive
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import url

app = knowledge_app
TOKEN = "private-authenticated-service-" + "x" * 32


def pending(client, app, bom):
    project, data = prepared(client, app, bom)
    app.state.settings.agentyzer_token = TOKEN
    app.state.settings.agentyzer_reconciliation_enabled = True
    response = client.post(url(project, "/versions/7.1.1/analysis-jobs"), json=data)
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    with app.state.sessions.begin() as db:
        selected = db.get(Job, identity)
        selected.status = "submission_unknown"
        selected.payload = {**selected.payload, "submission_started": True}
        payload = copy.deepcopy(selected.payload)
    derived = derive(app.state.knowledge, data["expected"])
    proof = {
        "format": "agentyzer.dtvp-binding/1",
        "job_id": "remote-1",
        "status": "completed",
        "binding": payload["correlation"],
        "request": payload["request"],
        "report": report(derived)["report"],
    }
    return project, identity, proof


@respx.mock
def test_http_exact_actor_binding_and_replay_keeps_nonce_private(analyst, app, bom):
    project, identity, proof = pending(analyst, app, bom)
    remote = respx.get("http://agentyzer.test/jobs/remote-1/dtvp-binding").mock(
        return_value=httpx.Response(200, json=proof)
    )
    path = url(project, f"/analysis-jobs/{identity}")
    viewed = analyst.get(path)
    assert viewed.status_code == 200 and "reconcile" in viewed.json()["capabilities"]
    body = {"request_id": "explicit-reconciliation", "remote_id": "remote-1"}
    first = analyst.post(path + "/reconcile", json=body)
    assert first.status_code == 200, first.text
    assert (
        first.json()["status"] == "queued" and not first.json()["requires_explicit_reconciliation"]
    )
    assert remote.call_count == 1
    again = analyst.post(path + "/reconcile", json=body)
    assert again.status_code == 200 and remote.call_count == 1
    nonce = proof["binding"]["nonce"]
    assert nonce not in first.text + viewed.text
    for file in app.state.knowledge.objects.root.rglob("*"):
        if file.is_file():
            assert nonce.encode() not in file.read_bytes()


@respx.mock
def test_foreign_actor_cancel_and_private_echo_fail_closed(analyst, app, bom):
    project, identity, proof = pending(analyst, app, bom)
    path = url(project, f"/analysis-jobs/{identity}")
    body = {"request_id": "explicit-reconciliation", "remote_id": "remote-1"}
    login(analyst, "administrator")
    assert analyst.post(path + "/reconcile", json=body).status_code == 403
    login(analyst, "analyst")
    proof["report"]["unexpected"] = {"dtvp_binding": proof["binding"]}
    route = respx.get("http://agentyzer.test/jobs/remote-1/dtvp-binding").mock(
        return_value=httpx.Response(200, json=proof)
    )
    failed = analyst.post(path + "/reconcile", json=body)
    assert failed.status_code == 502 and proof["binding"]["nonce"] not in failed.text
    assert analyst.get(path).json()["status"] == "submission_unknown"
    assert analyst.post(path + "/cancel", json={}).json()["status"] == "cancelled"
    assert analyst.post(path + "/reconcile", json=body).status_code == 409
    assert route.call_count == 1
