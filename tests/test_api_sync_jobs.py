"""Current authorization governs policies and retained automatic proposal bytes."""

from sqlalchemy import select

from dtvp.jobs import work_once
from dtvp.models import Job
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def prepared(client, bom):
    project = product(client)
    for version in ("7.1.1", "7.1.2"):
        imported(client, project, version, body(bom, request_id=version))
    return project, f"/api/v3/projects/{project}"


def configuration():
    return {
        "request_id": "sync-policy",
        "expected_policy": None,
        "relationships": [
            {"relationship_id": "next", "source_version": "7.1.1", "target_version": "7.1.2"}
        ],
    }


def test_policy_authority_worker_dispatch_and_frozen_proposal(analyst, app, bom):
    project, path = prepared(analyst, bom)
    response = analyst.put(path + "/synchronization-policy", json=configuration())
    assert response.status_code == 404, response.text
    login(analyst, "administrator")
    response = analyst.put(path + "/synchronization-policy", json=configuration())
    assert response.status_code == 200, response.text
    head = app.state.knowledge.head()
    value = analyst.get(path + "/synchronization-policy").json()
    assert value["state"]
    assert "credential_id" not in value
    # Force the production worker rescan independent of previous tests' throttle.
    from dtvp.jobs import _work_once

    _work_once.last_sync_scan = 0
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    assert app.state.knowledge.head() == head
    page = analyst.get(path + "/synchronization-jobs").json()
    assert len(page["items"]) == 1
    job = page["items"][0]
    assert job["status"] == "succeeded", job
    report = analyst.get(path + f"/synchronization-jobs/{job['id']}/proposal")
    assert report.status_code == 200, report.text
    assert report.json()["automatic_proposal"] and not report.json()["stale"]
    assert report.json()["source"] == job["inputs"]["source"]
    assert not work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    login(analyst, "viewer")
    assert analyst.get(path + f"/synchronization-jobs/{job['id']}/proposal").status_code == 200
    assert analyst.post(path + f"/synchronization-jobs/{job['id']}/retry").status_code == 404


def test_owner_retry_preserves_pins_and_failed_jobs_are_not_implicitly_retried(analyst, app, bom):
    project, path = prepared(analyst, bom)
    login(analyst, "administrator")
    response = analyst.put(path + "/synchronization-policy", json=configuration())
    assert response.status_code == 200, response.text
    from dtvp.knowledge.sync_jobs import KIND, reconcile

    reconcile(app.state.sessions, app.state.knowledge)
    with app.state.sessions.begin() as db:
        job = db.scalar(select(Job).where(Job.kind == KIND, Job.project_id == project))
        identity, payload = job.id, dict(job.payload)
        job.status, job.error = "failed", "simulated interruption"
    assert reconcile(app.state.sessions, app.state.knowledge) == 0
    response = analyst.post(path + f"/synchronization-jobs/{identity}/retry")
    assert response.status_code == 200, response.text
    assert response.json()["inputs"] == payload["inputs"]
    assert response.json()["status"] == "queued"
    assert (
        analyst.post(path + f"/synchronization-jobs/{identity}/cancel").json()["status"]
        == "cancelled"
    )
    assert reconcile(app.state.sessions, app.state.knowledge) == 0
    assert (
        analyst.get(path + "/synchronization-jobs/00000000-0000-0000-0000-000000000000").status_code
        == 404
    )
