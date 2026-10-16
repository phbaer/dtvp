"""Parent-bound child analyses never repeat an unknown remote write."""

import copy
from datetime import timedelta

import httpx
import pytest
import respx
from pydantic import ValidationError

from dtvp.knowledge.analysis_followups import FollowUpInput, enqueue_followup, parent_material
from dtvp.knowledge.analysis_jobs import retry_analysis
from dtvp.knowledge.analysis_reconciliation import ReconcileInput, reconcile_analysis
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Credential, Job, now
from tests.test_knowledge_agentyzer import VERSION
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_analysis_jobs import BASE, actor, complete_routes, enqueue, job, run
from tests.test_knowledge_analysis_jobs import env as source_env

env = source_env
TOKEN = "private-followup-service-" + "x" * 32


def completed_parent(env):
    env.settings.agentyzer_token = TOKEN
    env.settings.agentyzer_reconciliation_enabled = True
    parent_id = enqueue(env)
    complete_routes(env)
    run(env, parent_id)
    selected = job(env, parent_id)
    assert selected.status == "succeeded"
    with env.factory() as db:
        _, pins, scope = parent_material(
            db,
            env.journal,
            env.settings,
            project_id="product",
            version=VERSION,
            parent_id=parent_id,
            report_sha=selected.payload["report_sha256"],
        )
    proof = {"format": "agentyzer.dtvp-follow-up-parent/1", "parent": pins, "scope": scope}
    preflight = respx.get(BASE + "/jobs/remote-1/dtvp-follow-up-parent").mock(
        return_value=httpx.Response(200, json=proof)
    )
    data = FollowUpInput(
        request_id="follow-up-1",
        expected=selected.result["state"],
        parent_report_sha256=selected.payload["report_sha256"],
        question="Check whether the configured parser entry point is reachable",
    )
    return parent_id, data, preflight


def child(env, parent_id, data):
    with env.factory.begin() as db:
        return enqueue_followup(
            db,
            env.journal,
            env.settings,
            project_id="product",
            version=VERSION,
            parent_id=parent_id,
            actor=actor(db),
            data=data,
        ).id


def child_proof(env, identity, remote="child-remote"):
    payload = job(env, identity).payload
    follow = payload["follow_up"]
    return {
        "format": "agentyzer.dtvp-follow-up-binding/1",
        "job_id": remote,
        "status": "completed",
        "binding": {
            "format": "dtvp.follow-up-binding/1",
            "parent": follow["parent"],
            "correlation": payload["correlation"],
        },
        "parent": follow["parent"],
        "submission": follow["wire_request"],
        "request": payload["request"]
        | {"user_guidance": "Provider-compiled parent context and analyst question"},
        "report": report(env.derived)["report"],
    }


def routes(env, identity):
    sent = respx.post(BASE + "/jobs/remote-1/follow-up").mock(
        return_value=httpx.Response(200, json={"job_id": "child-remote"})
    )
    respx.get(BASE + "/jobs/child-remote").mock(
        return_value=httpx.Response(200, json={"job_id": "child-remote", "status": "completed"})
    )
    proof = child_proof(env, identity)
    fetched = respx.get(BASE + "/jobs/child-remote/dtvp-follow-up-binding").mock(
        return_value=httpx.Response(200, json=proof)
    )
    return sent, fetched, proof


@respx.mock
def test_exact_parent_child_is_separate_durable_evidence_without_human_approval(env):
    parent_id, data, preflight = completed_parent(env)
    original = copy.deepcopy(job(env, parent_id).payload)
    identity = child(env, parent_id, data)
    assert child(env, parent_id, data) == identity and preflight.call_count == 1
    stored = job(env, identity)
    assert stored.payload["receipt"] == original["receipt"]
    sent, fetched, proof = routes(env, identity)
    run(env, identity)
    updated = job(env, identity)
    assert updated.status == "succeeded" and sent.call_count == fetched.call_count == 1
    assert preflight.call_count == 2
    assert job(env, parent_id).payload == original
    sections = load_sections(env.journal, updated.result["state"])
    assert sections["assessments"] == sections["reviews"] == {}
    assert all(
        value.get("format") == "dtvp.scoring-proposal/1" for value in sections["scoring"].values()
    )
    retained = env.journal.load(updated.payload["report_sha256"])
    assert retained["follow_up"]["parent_job_id"] == parent_id
    assert retained["job"]["request"] == proof["request"]
    for file in env.journal.objects.root.rglob("*"):
        if file.is_file():
            raw = file.read_bytes()
            assert stored.payload["correlation"]["nonce"].encode() not in raw
            assert original["correlation"]["nonce"].encode() not in raw


@respx.mock
def test_parent_age_does_not_expire_completed_evidence_but_child_has_fresh_timeout(env):
    parent_id, data, _ = completed_parent(env)
    with env.factory.begin() as db:
        db.get(Job, parent_id).created_at = now() - timedelta(days=30)
    identity = child(env, parent_id, data)
    routes(env, identity)
    run(env, identity)
    assert job(env, identity).status == "succeeded"


@respx.mock
def test_unsupported_remote_parent_proof_prevents_child_sql_enqueue(env):
    parent_id, data, preflight = completed_parent(env)
    preflight.mock(return_value=httpx.Response(404))
    with pytest.raises(httpx.HTTPStatusError):
        child(env, parent_id, data)
    with env.factory() as db:
        assert len(list(db.query(Job))) == 1


@respx.mock
def test_whitespace_scope_override_and_parent_hash_changes_fail_before_preflight(env):
    parent_id, data, preflight = completed_parent(env)
    with pytest.raises(ValidationError):
        FollowUpInput.model_validate(data.model_dump() | {"question": " \t "})
    with pytest.raises(ValidationError):
        FollowUpInput.model_validate(data.model_dump() | {"component_name": "other"})
    with pytest.raises(ValueError, match="meaningful"):
        child(env, parent_id, data.model_copy(update={"question": " \n "}))
    with pytest.raises(Conflict):
        child(env, parent_id, data.model_copy(update={"parent_report_sha256": "0" * 64}))
    assert preflight.call_count == 0


@respx.mock
def test_ambiguous_followup_post_never_repeats_and_explicit_reconciliation_imports_exact_child(env):
    parent_id, data, _ = completed_parent(env)
    identity = child(env, parent_id, data)
    sent = respx.post(BASE + "/jobs/remote-1/follow-up").mock(
        side_effect=httpx.ReadTimeout("unknown")
    )
    run(env, identity)
    assert job(env, identity).status == "submission_unknown" and sent.call_count == 1
    assert child(env, parent_id, data) == identity
    with env.factory.begin() as db:
        with pytest.raises(Conflict):
            retry_analysis(
                db,
                env.journal,
                env.settings,
                project_id="product",
                job_id=identity,
                actor=actor(db),
            )
    proof = child_proof(env, identity)
    fetched = respx.get(BASE + "/jobs/child-remote/dtvp-follow-up-binding").mock(
        return_value=httpx.Response(200, json=proof)
    )
    reconciled = reconcile_analysis(
        env.factory,
        env.journal,
        env.settings,
        project_id="product",
        job_id=identity,
        actor_id="author",
        credential_id="credential",
        data=ReconcileInput(request_id="reconcile-child", remote_id="child-remote"),
    )
    assert reconciled.status == "queued" and fetched.call_count == 1
    run(env, identity)
    assert job(env, identity).status == "succeeded" and sent.call_count == 1


@respx.mock
def test_preflight_failure_before_post_can_retry_only_safe_preparation(env):
    parent_id, data, preflight = completed_parent(env)
    identity = child(env, parent_id, data)
    good = copy.deepcopy(preflight.calls[0].response.json())
    preflight.mock(return_value=httpx.Response(404))
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "failed" and not stored.payload["submission_started"]
    with env.factory.begin() as db:
        retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
    preflight.mock(return_value=httpx.Response(200, json=good))
    sent, _, _ = routes(env, identity)
    run(env, identity)
    assert job(env, identity).status == "succeeded" and sent.call_count == 1


@respx.mock
def test_revoked_current_credential_prevents_followup_enqueue_and_replay(env):
    parent_id, data, preflight = completed_parent(env)
    identity = child(env, parent_id, data)
    with env.factory.begin() as db:
        db.get(Credential, "credential").revoked = True
    with pytest.raises(PermissionError, match="revoked"):
        child(env, parent_id, data)
    assert preflight.call_count == 1 and job(env, identity).status == "queued"


@pytest.mark.parametrize("change", ["parent", "wire", "source", "child_nonce", "parent_nonce"])
@respx.mock
def test_wrong_authenticated_child_proof_never_becomes_retained_evidence(env, change):
    parent_id, data, _ = completed_parent(env)
    identity = child(env, parent_id, data)
    sent, fetched, proof = routes(env, identity)
    if change == "parent":
        proof["parent"]["report_sha256"] = "0" * 64
    elif change == "wire":
        proof["submission"]["question"] = "Different question"
    elif change == "source":
        proof["request"]["source_commit"] = "b" * 40
    else:
        selected = job(env, identity if change == "child_nonce" else parent_id)
        proof["report"]["assessment"]["summary"] = selected.payload["correlation"]["nonce"]
    fetched.mock(return_value=httpx.Response(200, json=proof))
    before = env.journal.head()
    with pytest.raises(ValueError):
        run(env, identity)
    assert sent.call_count == 1 and env.journal.head() == before
    assert "report_sha256" not in job(env, identity).payload


@respx.mock
def test_credential_revoked_during_enqueue_preflight_leaves_no_child(env):
    parent_id, data, preflight = completed_parent(env)
    valid = preflight.return_value.json()

    def revoked(request):
        with env.factory.begin() as db:
            db.get(Credential, "credential").revoked = True
        return httpx.Response(200, json=valid)

    preflight.mock(side_effect=revoked)
    with pytest.raises(PermissionError, match="revoked"):
        child(env, parent_id, data)
    with env.factory() as db:
        assert len(list(db.query(Job))) == 1


@respx.mock
def test_revoked_worker_credential_after_parent_get_never_posts_child(env):
    parent_id, data, preflight = completed_parent(env)
    identity = child(env, parent_id, data)
    valid = preflight.calls[0].response.json()

    def revoked(request):
        with env.factory.begin() as db:
            db.get(Credential, "credential").revoked = True
        return httpx.Response(200, json=valid)

    preflight.mock(side_effect=revoked)
    posted = respx.post(BASE + "/jobs/remote-1/follow-up").mock(
        return_value=httpx.Response(200, json={"job_id": "forbidden"})
    )
    run(env, identity)
    assert posted.call_count == 0
    assert (
        job(env, identity).status == "failed"
        and not job(env, identity).payload["submission_started"]
    )


@respx.mock
def test_child_uncertain_publication_replays_receipt_without_new_remote_io(env, monkeypatch):
    import dtvp.knowledge.analysis_jobs as module

    parent_id, data, _ = completed_parent(env)
    identity = child(env, parent_id, data)
    sent, fetched, _ = routes(env, identity)
    original = module.import_agentyzer_result

    def uncertain(*args, **kwargs):
        receipt = original(*args, **kwargs)
        raise CommitUncertain(receipt[0])

    monkeypatch.setattr(module, "import_agentyzer_result", uncertain)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    state = env.journal.head()
    monkeypatch.setattr(module, "import_agentyzer_result", original)
    with env.factory.begin() as db:
        retried = retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
        assert retried.status == "succeeded"
    assert env.journal.head() == state and sent.call_count == fetched.call_count == 1


@respx.mock
def test_child_material_drift_retains_exact_report_as_stale_proposal(env):
    from dtvp.knowledge.agentyzer_results import list_agentyzer_results
    from tests.test_knowledge_analysis_jobs import imported, qualified

    parent_id, data, _ = completed_parent(env)
    identity = child(env, parent_id, data)
    sent, fetched, proof = routes(env, identity)

    def drift(request):
        changed = {
            **env.bom,
            "components": [
                dict(value) | ({"version": "2.0.0"} if value["bom-ref"] == "http" else {})
                for value in env.bom["components"]
            ],
        }
        imported(env.journal, changed, context=qualified(), expected=data.expected, build_number=2)
        return httpx.Response(200, json=proof)

    fetched.mock(side_effect=drift)
    run(env, identity)
    selected = job(env, identity)
    assert selected.status == "succeeded" and sent.call_count == 1
    sections = load_sections(env.journal, selected.result["state"])
    receipt = env.derived["receipt"]
    rows = list_agentyzer_results(
        env.journal, sections, VERSION, receipt["context_id"], receipt["vulnerability_id"]
    )
    assert rows and all(not row["current"] and not row["application_eligible"] for row in rows)
    assert env.journal.load(selected.payload["report_sha256"])["report"] == proof["report"]
    assert sections["assessments"] == sections["reviews"] == {}
