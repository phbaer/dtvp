import json
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


SOURCE_COMMIT = "a" * 40


def bound_target():
    return {
        "package_name": "demo-http",
        "version": "1.2.0",
        "source_binding": {
            "status": "known",
            "source_commit": SOURCE_COMMIT,
        },
    }


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
    from dtvp.domain import current_observations
    from dtvp.models import Revision

    with client.app.state.sessions.begin() as db:
        for observation in current_observations(db, finding["release_id"]):
            if observation.finding_id == finding["id"]:
                revision = db.get(Revision, observation.revision_id)
                revision.context = {
                    **revision.context,
                    "analysis_source": {
                        "component_name": "gateway-repository",
                        "source_commit": SOURCE_COMMIT,
                    },
                }
    return finding


def report(**changes):
    return {
        "source_input": {
            "binding": "verified_git_commit",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": SOURCE_COMMIT,
            "artifact_verified": False,
        },
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
    assert json.loads(posted.calls[0].request.content)["source_commit"] == SOURCE_COMMIT
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
    assert json.loads(follow.calls[0].request.content)["source_commit"] == SOURCE_COMMIT
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
    assert normalize(report(**changes), bound_target())["proposal_state"] == expected


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


@pytest.mark.parametrize(
    "source",
    [
        None,
        {},
        {
            "binding": "observed_git_head",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": SOURCE_COMMIT,
        },
        {
            "binding": "verified_git_commit",
            "requested_commit": "b" * 40,
            "resolved_commit": SOURCE_COMMIT,
        },
        {
            "binding": "verified_git_commit",
            "requested_commit": SOURCE_COMMIT,
            "resolved_commit": "b" * 40,
        },
        {"binding": "verified_git_commit", "requested_commit": SOURCE_COMMIT},
    ],
)
def test_source_provenance_must_match_both_requested_and_resolved_commit(source):
    data = report(rescoring_eligible=True)
    if source is None:
        data.pop("source_input")
    else:
        data["source_input"] = source
    normalized = normalize(data, bound_target())
    assert normalized["source_verified"] is False
    assert normalized["application_eligible"] is False
    assert normalized["rescoring_eligible"] is False
    assert normalized["proposal_state"] is None
    assert normalized["ineligibility_reasons"]


def test_provider_cannot_invent_requested_binding_or_claim_artifact_equivalence():
    target = bound_target()
    target["source_binding"] = {
        "status": "unknown",
        "source_commit": None,
        "reason": "No qualified source",
    }
    result = normalize(report(), target)
    assert not result["source_verified"] and not result["application_eligible"]
    known = normalize(report(), bound_target())
    assert known["source_verified"] and known["application_eligible"]
    assert "artifact_verified" not in known or known["artifact_verified"] is not True


def test_synthetic_eligibility_remains_explicitly_unverified():
    from dtvp.analysis import synthetic_report

    target = {"package_name": "demo-http", "version": "1.2.0"}
    data = synthetic_report("eligible", target)
    result = normalize(data, target, synthetic=True)
    assert result["application_eligible"] is True
    assert result["source_verified"] is False
    assert result["source_binding"]["status"] == "synthetic_unverified"
    # The report's self-description cannot bypass the external boundary.
    assert normalize(data, target)["application_eligible"] is False


@respx.mock
def test_legacy_report_retained_but_missing_source_binding_is_ineligible(analyst, release_id):
    finding = external(analyst, release_id)
    legacy = report(rescoring_eligible=True)
    legacy.pop("source_input")
    respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "legacy"})
    )
    respx.get("http://agentyzer.test/jobs/legacy").mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    respx.get("http://agentyzer.test/jobs/legacy/result").mock(
        return_value=httpx.Response(200, json=legacy)
    )
    job_id = submit(analyst, finding).json()["id"]
    assert run_worker(analyst)
    job = analyst.get(f"/api/v2/findings/{finding['id']}/analyses").json()["items"][0]
    assert job["status"] == "succeeded"
    assert job["result"]["application_eligible"] is False
    assert job["result"]["rescoring_eligible"] is False
    assert job["result"]["ineligibility_reasons"]
    assert analyst.get(f"/api/v2/analyses/{job_id}/report").json() == legacy


@pytest.mark.parametrize(
    "context",
    [
        {"commit": SOURCE_COMMIT},
        {"source_revision": SOURCE_COMMIT},
        {
            "analysis_source": {
                "component_name": "another-repository",
                "source_commit": SOURCE_COMMIT,
            }
        },
        {"analysis_source": {"component_name": "gateway-repository", "source_commit": "main"}},
    ],
)
def test_unqualified_or_wrong_repository_context_cannot_pin_source(analyst, release_id, context):
    from dtvp.analysis import source_binding
    from dtvp.domain import current_observations
    from dtvp.models import Finding, Revision

    finding = external(analyst, release_id)
    with analyst.app.state.sessions.begin() as db:
        stored = db.get(Finding, finding["id"])
        for observation in current_observations(db, stored.release_id):
            if observation.finding_id == stored.id:
                db.get(Revision, observation.revision_id).context = context
        result = source_binding(db, stored, "gateway-repository")
    assert result["status"] == "unknown" and result["source_commit"] is None
    job_id = submit(analyst, finding).json()["id"]
    with analyst.app.state.sessions() as db:
        assert "source_commit" not in db.get(Job, job_id).payload["request"]


def reimport(analyst, finding, bom, commit, source="pipeline:demo"):
    from dtvp.domain import current_observations
    from dtvp.models import Revision

    context = {}
    with analyst.app.state.sessions() as db:
        for observation in current_observations(db, finding["release_id"]):
            if observation.finding_id == finding["id"]:
                revision = db.get(Revision, observation.revision_id)
                if revision.source == source:
                    context = dict(revision.context)
    context["analysis_source"] = {"component_name": "gateway-repository", "source_commit": commit}
    return analyst.post(
        f"/api/v2/releases/{finding['release_id']}/ingestions",
        json={
            "source": source,
            "event_id": "qualified-source-update",
            "occurred_at": now().isoformat(),
            "completeness": "complete",
            "sbom": bom,
            "context": context,
        },
    )


def test_contradictory_current_import_sources_remain_unbound(analyst, release_id, bom):
    from dtvp.analysis import source_binding
    from dtvp.models import Finding

    finding = external(analyst, release_id)
    assert reimport(analyst, finding, bom, "b" * 40, source="other-source").status_code == 201
    with analyst.app.state.sessions() as db:
        result = source_binding(db, db.get(Finding, finding["id"]), "gateway-repository")
    assert result["status"] == "conflicting" and result["source_commit"] is None


@respx.mock
def test_source_context_change_blocks_inflight_submission_even_without_revision_counter(
    analyst, release_id
):
    from dtvp.domain import current_observations
    from dtvp.models import Revision

    finding = external(analyst, release_id)
    job_id = submit(analyst, finding).json()["id"]
    post = respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "never"})
    )
    with analyst.app.state.sessions.begin() as db:
        for observation in current_observations(db, finding["release_id"]):
            if observation.finding_id == finding["id"]:
                revision = db.get(Revision, observation.revision_id)
                revision.context = {
                    "analysis_source": {
                        "component_name": "gateway-repository",
                        "source_commit": "b" * 40,
                    }
                }
    assert run_worker(analyst)
    assert not post.called
    with analyst.app.state.sessions() as db:
        assert db.get(Job, job_id).status == "failed"


@respx.mock
def test_reimport_of_changed_qualified_source_invalidates_completed_analysis(
    analyst, release_id, bom
):
    finding = external(analyst, release_id)
    respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "completed-source"})
    )
    respx.get("http://agentyzer.test/jobs/completed-source").mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    respx.get("http://agentyzer.test/jobs/completed-source/result").mock(
        return_value=httpx.Response(200, json=report())
    )
    job_id = submit(analyst, finding).json()["id"]
    assert run_worker(analyst)
    before = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    history = analyst.get(f"/api/v2/findings/{finding['id']}/analyses").json()["items"]
    assert history[0]["current"] and history[0]["result"]["source_verified"]
    assert reimport(analyst, finding, bom, "b" * 40).status_code == 201
    after = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert after["evidence_revision"] > before["evidence_revision"]
    history = analyst.get(f"/api/v2/findings/{finding['id']}/analyses").json()["items"]
    assert not history[0]["current"]
    assert (
        submit(analyst, after, parent_job_id=job_id, question="Reuse old source?").status_code
        == 409
    )


def test_stored_old_external_eligibility_is_not_exposed_as_current_proof():
    from types import SimpleNamespace

    from dtvp.api_analysis import representation

    job = SimpleNamespace(
        id="old",
        kind="analyse",
        status="succeeded",
        error="",
        created_at=now(),
        payload={"mode": "external"},
        result={
            "application_eligible": True,
            "rescoring_eligible": True,
            "proposal_state": "affected",
            "evidence_revision": 1,
        },
    )
    result = representation(job, SimpleNamespace(evidence_revision=1))["result"]
    assert not result["application_eligible"] and not result["rescoring_eligible"]
    assert result["proposal_state"] is None and result["ineligibility_reasons"]
    assert job.result["application_eligible"] is True  # Historical record is retained unchanged.
