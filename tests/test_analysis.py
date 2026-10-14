from datetime import timedelta

import httpx
import pytest
import respx

from dtvp.analysis import normalize
from dtvp.jobs import claim, work_once
from dtvp.models import Job, now
from tests.conftest import login


def submit(client, finding, **fields):
    return client.post(
        f"/api/v2/findings/{finding['id']}/analyses",
        json={"expected_version": finding["state_version"], **fields},
    )


def run_worker(client):
    app = client.app
    return work_once(app.state.sessions, app.state.artifacts, app.state.settings)


def make_available(client, job_id):
    with client.app.state.sessions.begin() as db:
        job = db.get(Job, job_id)
        job.available_at = now() - timedelta(seconds=1)
        if job.status == "running":
            job.lease_until = now() - timedelta(seconds=1)


def external(client, release_id):
    settings = client.app.state.settings
    settings.agentyzer_enabled = True
    settings.agentyzer_url = "http://agentyzer.test"
    project_id = client.get("/api/v2/projects").json()[0]["id"]
    finding = next(
        row
        for row in client.get("/api/v2/findings").json()["items"]
        if row["identifier"] == "CVE-2099-20001"
    )
    assert submit(client, finding).status_code == 422
    login(client, "administrator")
    assert (
        client.put(
            f"/api/v2/projects/{project_id}/connectors/agentyzer",
            json={"component_name": "gateway-repository"},
        ).status_code
        == 200
    )
    login(client)
    return finding


def report(**changes):
    return {
        "assessment": {
            "application_eligible": True,
            "rescoring_eligible": False,
            "affected": True,
            "analysis": "EXPLOITABLE",
            "verdict": "Affected",
            "summary": "Reachable dependency",
            "reasoning": "Repository evidence",
            "version_analysis": {
                "detected_version": "1.2.0",
                "comparison_inputs": {"component_name": "demo-http"},
            },
            **changes,
        },
        "steps": [],
    }


@respx.mock
def test_remote_analysis_poll_recovery_dedup_followup_and_report_scope(analyst, release_id):
    finding = external(analyst, release_id)
    posted = respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "remote-one"})
    )
    status = respx.get("http://agentyzer.test/jobs/remote-one").mock(
        return_value=httpx.Response(200, json={"status": "running"})
    )
    respx.get("http://agentyzer.test/jobs/remote-one/result").mock(
        return_value=httpx.Response(200, json=report())
    )
    job_id = submit(analyst, finding).json()["id"]
    assert submit(analyst, finding).json()["id"] == job_id
    assert run_worker(analyst)
    assert posted.call_count == 1
    assert posted.calls[0].request.read().find(b'"component_name":"gateway-repository"') >= 0
    # Recover an expired polling lease using the persisted remote job ID.
    make_available(analyst, job_id)
    claimed = claim(analyst.app.state.sessions)
    assert claimed[0] == job_id
    make_available(analyst, job_id)
    status.mock(return_value=httpx.Response(200, json={"status": "completed"}))
    assert run_worker(analyst)
    assert posted.call_count == 1
    current = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert current["decisions"] == [] and current["approval"] is None
    history = analyst.get(f"/api/v2/findings/{finding['id']}/analyses").json()["items"]
    assert history[0]["current"] and history[0]["result"]["proposal_state"] == "affected"
    assert analyst.get(f"/api/v2/analyses/{job_id}/report").json() == report()
    follow = respx.post("http://agentyzer.test/jobs/remote-one/follow-up").mock(
        return_value=httpx.Response(200, json={"job_id": "remote-two"})
    )
    respx.get("http://agentyzer.test/jobs/remote-two").mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    respx.get("http://agentyzer.test/jobs/remote-two/result").mock(
        return_value=httpx.Response(
            200, json=report(affected=False, analysis="IN_TRIAGE", application_eligible=False)
        )
    )
    assert (
        submit(
            analyst, current, parent_job_id=job_id, question="What about the worker?"
        ).status_code
        == 202
    )
    assert run_worker(analyst) and follow.call_count == 1
    newest = analyst.get(f"/api/v2/findings/{finding['id']}/analyses?limit=1").json()
    assert newest["items"][0]["result"]["proposal_state"] is None
    assert newest["next_cursor"]
    older = analyst.get(
        f"/api/v2/findings/{finding['id']}/analyses", params={"cursor": newest["next_cursor"]}
    ).json()["items"]
    assert older[0]["id"] == job_id and not older[0]["current"]
    latest = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert submit(analyst, latest, parent_job_id=job_id, question="Old context?").status_code == 409
    login(analyst, "operations")
    assert analyst.get(f"/api/v2/analyses/{job_id}/report").status_code == 404


@respx.mock
def test_ambiguous_submission_never_replayed_and_stale_evidence_never_published(
    analyst, release_id
):
    finding = external(analyst, release_id)
    post = respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "remote-stale"})
    )
    status = respx.get("http://agentyzer.test/jobs/remote-stale").mock(
        return_value=httpx.Response(200, json={"status": "running"})
    )
    first = submit(analyst, finding).json()["id"]
    with analyst.app.state.sessions.begin() as db:
        job = db.get(Job, first)
        job.payload = {**job.payload, "submission_started": True}
    assert run_worker(analyst)
    assert post.call_count == 0
    assert analyst.get("/api/v2/jobs").json()[0]["status"] == "failed"
    assert analyst.post(f"/api/v2/jobs/{first}/retry").status_code == 409
    second = submit(analyst, finding).json()["id"]
    assert run_worker(analyst) and post.call_count == 1
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/evidence",
            json={
                "source": "pipeline",
                "external_id": "new",
                "assertion": {"kind": "code-analysis", "summary": "New source evidence"},
            },
        ).status_code
        == 201
    )
    make_available(analyst, second)
    assert run_worker(analyst)
    assert status.call_count == 1
    jobs = analyst.get("/api/v2/jobs").json()
    assert all(job["status"] == "failed" for job in jobs)
    assert not any(
        e["source"] == "agentyzer"
        for e in analyst.get(f"/api/v2/findings/{finding['id']}").json()["evidence"]
    )


def test_synthetic_analysis_preserves_manual_decisions_and_cancellation(analyst):
    finding = analyst.get("/api/v2/findings").json()["items"][0]
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/decisions",
            json={
                "expected_version": finding["state_version"],
                "state": "affected",
                "rationale": "Human decision",
            },
        ).status_code
        == 201
    )
    finding = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    cancelled = submit(analyst, finding).json()["id"]
    assert analyst.post(f"/api/v2/jobs/{cancelled}/cancel").status_code == 200
    assert not run_worker(analyst)
    assert submit(analyst, finding, demo_outcome="inconclusive").status_code == 202
    assert run_worker(analyst)
    current = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert current["decisions"][0]["rationale"] == "Human decision"
    assert current["approval"] is None and current["lifecycle"] == "needs_revalidation"
    assert current["original_score"] == finding["original_score"]
    assert current["evidence"][0]["proposal_state"] is None
    assert submit(analyst, finding).status_code == 409
    login(analyst, "viewer")
    assert submit(analyst, current).status_code == 404


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, "affected"),
        ({"application_eligible": "true"}, None),
        ({"affected": False, "analysis": "NOT_AFFECTED"}, None),
        (
            {
                "affected": False,
                "analysis": "NOT_AFFECTED",
                "code_coverage": {"permits_exclusion": True},
            },
            "not_affected",
        ),
        (
            {
                "affected": False,
                "analysis": "IN_TRIAGE",
                "code_coverage": {"permits_exclusion": True},
            },
            None,
        ),
        ({"affected": None}, None),
        (
            {
                "version_analysis": {
                    "detected_version": "9.0.0",
                    "comparison_inputs": {"component_name": "demo-http"},
                }
            },
            None,
        ),
        (
            {
                "version_analysis": {
                    "detected_version": "1.2.0",
                    "comparison_inputs": {"component_name": "other-package"},
                }
            },
            None,
        ),
    ],
)
def test_proposals_require_explicit_eligibility_and_exclusion_coverage(changes, expected):
    assert (
        normalize(report(**changes), {"package_name": "demo-http", "version": "1.2.0"})[
            "proposal_state"
        ]
        == expected
    )


@respx.mock
def test_cancellation_during_remote_completion_blocks_publication(analyst, release_id):
    finding = external(analyst, release_id)
    respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "remote-cancel"})
    )
    respx.get("http://agentyzer.test/jobs/remote-cancel").mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    job_id = submit(analyst, finding).json()["id"]

    def cancel_before_result(request):
        assert analyst.post(f"/api/v2/jobs/{job_id}/cancel").status_code == 200
        return httpx.Response(200, json=report())

    respx.get("http://agentyzer.test/jobs/remote-cancel/result").mock(
        side_effect=cancel_before_result
    )
    assert run_worker(analyst)
    assert analyst.get("/api/v2/jobs").json()[0]["status"] == "cancelled"
    assert analyst.get(f"/api/v2/findings/{finding['id']}").json()["evidence"] == []


@respx.mock
def test_revoked_credential_cannot_start_remote_analysis(analyst, release_id):
    from dtvp.models import Credential

    finding = external(analyst, release_id)
    posted = respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "should-not-start"})
    )
    job_id = submit(analyst, finding).json()["id"]
    with analyst.app.state.sessions.begin() as db:
        job = db.get(Job, job_id)
        db.get(Credential, job.payload["credential_id"]).revoked = True
    assert run_worker(analyst)
    assert not posted.called
    login(analyst)
    assert analyst.get("/api/v2/jobs").json()[0]["status"] == "failed"


def test_same_advisory_on_different_components_is_not_deduplicated(analyst):
    from sqlalchemy import select

    from dtvp.models import Component, Finding

    original = analyst.get("/api/v2/findings").json()["items"][0]
    with analyst.app.state.sessions.begin() as db:
        other = db.scalar(
            select(Component).where(
                Component.release_id == original["release_id"],
                Component.id != original["component_id"],
            )
        )
        finding = Finding(
            release_id=original["release_id"],
            component_id=other.id,
            identifier=original["identifier"],
        )
        db.add(finding)
        db.flush()
        other_id = finding.id
    first = submit(analyst, original).json()["id"]
    second = submit(analyst, {"id": other_id, "state_version": 1}).json()["id"]
    assert first != second
