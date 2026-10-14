from datetime import timedelta

import httpx
import respx
from sqlalchemy import select

from dtvp.jobs import claim, work_once
from dtvp.models import Job, now


@respx.mock
def test_matching_job_coverage_failure_and_lease_recovery(analyst, release_id):
    app = analyst.app
    app.state.settings.providers_enabled = ["osv"]
    route = respx.post("https://api.osv.dev/v1/query").mock(
        return_value=httpx.Response(200, json={"vulns": []})
    )
    response = analyst.post(
        "/api/v2/jobs", json={"kind": "match", "release_id": release_id, "provider": "osv"}
    )
    assert response.status_code == 202
    first = claim(app.state.sessions)
    assert first
    assert claim(app.state.sessions) is None
    with app.state.sessions.begin() as db:
        db.get(Job, first[0]).lease_until = now() - timedelta(seconds=1)
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    with app.state.sessions() as db:
        job = db.get(Job, first[0])
        assert job.status == "succeeded"
        assert job.attempts == 2
        assert all(c["status"] == "checked" for c in job.result["coverage"])
    # No match does not convert imported findings to not-affected or remove them.
    assert len(analyst.get("/api/v2/findings").json()["items"]) == 2
    route.mock(return_value=httpx.Response(503))
    response = analyst.post(
        "/api/v2/jobs", json={"kind": "match", "release_id": release_id, "provider": "osv"}
    )
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    with app.state.sessions() as db:
        job = db.get(Job, response.json()["id"])
        assert job.status == "failed"
        assert not job.result
    assert analyst.post(f"/api/v2/jobs/{response.json()['id']}/retry").status_code == 202


def test_disabled_providers_no_network(analyst, release_id):
    assert (
        analyst.post(
            "/api/v2/jobs", json={"kind": "match", "release_id": release_id, "provider": "osv"}
        ).status_code
        == 422
    )
    assert analyst.get("/api/v2/jobs").json() == []


def test_cancelled_job_cannot_publish(analyst, release_id):
    app = analyst.app
    app.state.settings.providers_enabled = ["osv"]
    response = analyst.post(
        "/api/v2/jobs", json={"kind": "match", "release_id": release_id, "provider": "osv"}
    )
    job_id = response.json()["id"]
    assert analyst.post(f"/api/v2/jobs/{job_id}/cancel").json()["status"] == "cancelled"
    assert not work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    with app.state.sessions() as db:
        assert db.scalar(select(Job).where(Job.id == job_id)).status == "cancelled"
