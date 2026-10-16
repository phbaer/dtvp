"""Scheduling remains explicit; the existing worker performs pinned authorized collection."""

import httpx
import respx
from sqlalchemy import select

from dtvp.jobs import _work_once, work_once
from dtvp.models import AdvisoryProviderThrottle, Job, Membership, User
from tests.conftest import login
from tests.test_api_knowledge_advisory_jobs import configured, response
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import url

app = knowledge_app


def prepare(client, app, bom):
    project, identifier, intake = configured(client, app, bom)
    body = {
        "request_id": "automatic-known-id",
        "expected_policy": None,
        "providers": [
            {
                "provider": "nvd",
                "versions": list(intake["expected_versions"]),
                "interval_seconds": 3600,
                "batch_size": 1,
            }
        ],
    }
    return project, identifier, intake, body


def scan(app):
    _work_once.last_advisory_scan = 0
    return work_once(app.state.sessions, app.state.artifacts, app.state.settings)


@respx.mock
def test_authorized_policy_worker_capture_and_empty_policy_disable(analyst, app, bom):
    project, identifier, _, data = prepare(analyst, app, bom)
    path = url(project, "/advisory-schedule")
    assert analyst.put(path, json=data).status_code == 404
    login(analyst, "administrator")
    before = app.state.knowledge.head()
    published = analyst.put(path, json=data)
    assert published.status_code == 200, published.text
    assert published.json()["committed"] is True
    policy = analyst.get(path).json()
    assert policy["state"] and policy["capabilities"] == ["configure"]
    assert "credential_id" not in policy
    assert app.state.knowledge.head() != before
    remote = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        side_effect=lambda request: httpx.Response(
            200, json=response("nvd", request.url.params["cveId"])
        )
    )
    assert scan(app)
    jobs = analyst.get(url(project, "/advisory-jobs")).json()["items"]
    assert len(jobs) == 1 and jobs[0]["status"] == "succeeded", jobs
    assert remote.call_count == 1
    assert not scan(app)
    stopped = analyst.put(
        path,
        json=data | {"request_id": "stop", "expected_policy": policy["state"], "providers": []},
    )
    assert stopped.status_code == 200
    assert not scan(app)
    login(analyst, "viewer")
    assert analyst.get(path).json()["capabilities"] == []
    assert analyst.put(path, json=data).status_code == 404


@respx.mock
def test_worker_rechecks_current_policy_author_permission_before_outbound(analyst, app, bom):
    from dtvp.knowledge.advisory_schedule import reconcile

    project, identifier, _, data = prepare(analyst, app, bom)
    login(analyst, "administrator")
    assert analyst.put(url(project, "/advisory-schedule"), json=data).status_code == 200
    assert reconcile(app.state.sessions, app.state.knowledge, app.state.settings) == 1
    with app.state.sessions.begin() as db:
        author = db.scalar(select(User).where(User.subject == "administrator"))
        for membership in db.scalars(select(Membership).where(Membership.user_id == author.id)):
            membership.roles = ["viewer"]
    remote = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(200, json=response("nvd", identifier))
    )
    assert scan(app)
    assert remote.call_count == 0
    with app.state.sessions() as db:
        job = db.scalar(
            select(Job).where(Job.project_id == project, Job.kind == "refresh-advisories-native")
        )
        assert job.status == "failed"


@respx.mock
def test_429_retains_shared_cooldown_and_manual_job_cannot_bypass_it(analyst, app, bom):
    project, identifier, intake, _ = prepare(analyst, app, bom)
    remote = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "120"})
    )
    path = url(project, "/advisory-jobs")
    assert analyst.post(path, json=intake).status_code == 202
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    assert remote.call_count == 1
    login(analyst, "administrator")
    cpe = analyst.post(
        url(project, "/cpe/sources/refresh"),
        json={
            "request_id": "shared-cpe-quota",
            "expected": None,
            "keyword": "library",
            "reason": "Check shared provider cooldown",
        },
    )
    assert cpe.status_code == 422 and "30 seconds" in cpe.text
    assert remote.call_count == 1
    assert analyst.post(path, json=intake | {"request_id": "second-request"}).status_code == 202
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    assert remote.call_count == 1
    with app.state.sessions() as db:
        assert db.get(AdvisoryProviderThrottle, "nvd").cooldown_until is not None
    outcomes = analyst.get(path).json()["items"]
    assert len(outcomes) == 2 and all(job["status"] == "failed" for job in outcomes)
    assert any("30 seconds" in job["error"] for job in outcomes)


def test_disabled_provider_rejected_without_policy_publication(analyst, app, bom):
    project, _, _, data = prepare(analyst, app, bom)
    login(analyst, "administrator")
    app.state.settings.providers_enabled = []
    before = app.state.knowledge.head()
    assert analyst.put(url(project, "/advisory-schedule"), json=data).status_code == 422
    assert app.state.knowledge.head() == before
