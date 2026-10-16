"""Leased provider jobs never repeat frozen lookups or silently repin CAS inputs."""

from datetime import timedelta

import httpx
import pytest
import respx
from fastapi import HTTPException

from dtvp.jobs import claim
from dtvp.knowledge.advisory_jobs import (
    advisory_job_view,
    enqueue_advisory_refresh,
    execute_advisory_refresh,
    retry_advisory_refresh,
)
from dtvp.knowledge.advisory_sources import AdvisoryRefreshInput
from dtvp.knowledge.evidence import current_evidence
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.models import Credential, Job, Membership, now
from tests.test_knowledge_advisory_documents import heads
from tests.test_knowledge_advisory_sources import FIRST, SECOND, route, upstream
from tests.test_knowledge_analysis_jobs import actor
from tests.test_knowledge_analysis_jobs import env as analysis_env

source_env = analysis_env


@pytest.fixture
def env(source_env):
    value = source_env
    value.settings.providers_enabled = ["nvd", "circl"]
    value.data = AdvisoryRefreshInput(
        request_id="refresh",
        provider="nvd",
        identifiers=[FIRST, SECOND],
        expected_evidence=None,
        expected_versions=heads(value.journal),
        revision=1,
    )
    return value


def enqueue(env, data=None):
    with env.factory.begin() as db:
        return enqueue_advisory_refresh(
            db,
            env.journal,
            env.settings,
            project_id="product",
            actor=actor(db),
            data=data or env.data,
        ).id


def job(env, identity):
    with env.factory() as db:
        return db.get(Job, identity)


def run(env, identity):
    claimed = claim(env.factory)
    assert claimed and claimed[0] == identity
    execute_advisory_refresh(env.factory, env.journal, env.settings, *claimed)


def retry(env, identity):
    with env.factory.begin() as db:
        return retry_advisory_refresh(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        ).id


@respx.mock
def test_success_checkpoint_then_atomic_evidence_and_idempotent_enqueue(env):
    route(FIRST)
    route(SECOND)
    identity = enqueue(env)
    assert enqueue(env) == identity
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded" and len(respx.calls) == 2
    assert stored.payload["capture_sha256"] == stored.result["capture_sha256"]
    state = current_evidence(env.journal, "product")[0]
    assert stored.result["evidence_state"] == state
    assert stored.payload["capture_sha256"] in env.journal.verify_state(state).artifacts
    assert advisory_job_view(stored)["expected_versions"] == env.data.expected_versions
    with pytest.raises(Conflict):
        enqueue(env, env.data.model_copy(update={"revision": 2}))


@pytest.mark.parametrize("change", ["credential", "roles", "provider"])
@respx.mock
def test_reauthorization_and_provider_enablement_precede_any_get(env, change):
    first = route(FIRST)
    route(SECOND)
    identity = enqueue(env)
    if change == "provider":
        env.settings.providers_enabled = []
    else:
        with env.factory.begin() as db:
            if change == "credential":
                db.get(Credential, "credential").revoked = True
            else:
                db.get(Membership, ("team", "author")).roles = ["viewer"]
    with pytest.raises((HTTPException, ValueError)):
        run(env, identity)
    assert not first.called and not respx.calls


@respx.mock
def test_revocation_between_gets_blocks_next_request_and_checkpoint(env):
    first = route(FIRST)
    second = route(SECOND)
    identity = enqueue(env)

    def revoke(request):
        with env.factory.begin() as db:
            db.get(Credential, "credential").revoked = True
        return httpx.Response(200, json=upstream(FIRST))

    first.mock(side_effect=revoke)
    before = env.journal.head()
    with pytest.raises(ValueError, match="revoked"):
        run(env, identity)
    assert first.call_count == 1 and not second.called
    assert not job(env, identity).payload.get("capture_sha256")
    assert env.journal.head() == before


@respx.mock
def test_uncertainty_retries_exact_frozen_body_without_refetch(env, monkeypatch):
    import dtvp.knowledge.advisory_jobs as module

    route(FIRST)
    route(SECOND)
    identity = enqueue(env)
    native = module.publish_advisories

    def uncertain(*args, **kwargs):
        receipt = native(*args, **kwargs)
        raise CommitUncertain(receipt[0])

    monkeypatch.setattr(module, "publish_advisories", uncertain)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "import_pending"
    capture_sha, input_data = stored.payload["capture_sha256"], stored.payload["intake"]
    before, calls = env.journal.head(), len(respx.calls)
    retry(env, identity)
    monkeypatch.setattr(module, "publish_advisories", native)
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert job(env, identity).payload["capture_sha256"] == capture_sha
    assert job(env, identity).payload["intake"] == input_data
    assert env.journal.head() == before and len(respx.calls) == calls


@respx.mock
def test_stale_branch_after_checkpoint_keeps_capture_and_never_repins_or_refetches(
    env, monkeypatch
):
    import dtvp.knowledge.advisory_jobs as module
    from tests.test_knowledge_agentyzer import imported, qualified

    route(FIRST)
    route(SECOND)
    identity = enqueue(env)
    native = module.publish_advisories
    raced = []

    def race(*args, **kwargs):
        if not raced:
            raced.append(True)
            imported(env.journal, env.bom, expected=env.state, build_number=2, context=qualified())
        return native(*args, **kwargs)

    monkeypatch.setattr(module, "publish_advisories", race)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "import_pending"
    assert stored.payload["capture_sha256"]
    calls = len(respx.calls)
    retry(env, identity)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    assert job(env, identity).payload["intake"] == env.data.model_dump(mode="json")
    assert len(respx.calls) == calls
    assert current_evidence(env.journal, "product")[0] is None


@respx.mock
def test_sql_completion_crash_recovers_durable_capture_and_receipt(env, monkeypatch):
    import dtvp.knowledge.advisory_jobs as module

    route(FIRST)
    route(SECOND)
    identity = enqueue(env)
    native = module.publish_advisories

    def crash(*args, **kwargs):
        native(*args, **kwargs)
        raise OSError("SQL completion uncertainty")

    monkeypatch.setattr(module, "publish_advisories", crash)
    with pytest.raises(OSError):
        run(env, identity)
    before, calls = env.journal.head(), len(respx.calls)
    with env.factory.begin() as db:
        stored = db.get(Job, identity)
        assert stored.payload["capture_sha256"]
        stored.lease_until = now() - timedelta(seconds=1)
    monkeypatch.setattr(module, "publish_advisories", native)
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert env.journal.head() == before and len(respx.calls) == calls


@respx.mock
def test_incomplete_lookup_cannot_publish_and_explicit_retry_may_refetch(env):
    first = route(FIRST)
    second = route(SECOND)
    second.mock(return_value=httpx.Response(503, text="Unavailable"))
    identity = enqueue(env)
    before = env.journal.head()
    with pytest.raises(httpx.HTTPStatusError):
        run(env, identity)
    assert env.journal.head() == before and not job(env, identity).payload.get("capture_sha256")
    with env.factory.begin() as db:
        db.get(Job, identity).status = "failed"
    second.mock(return_value=httpx.Response(200, json=upstream(SECOND)))
    retry(env, identity)
    run(env, identity)
    assert job(env, identity).status == "succeeded" and first.call_count == 2


def test_only_baseline_ids_and_complete_pinned_heads_can_enqueue(env):
    with pytest.raises(ValueError, match="baseline"):
        enqueue(env, env.data.model_copy(update={"identifiers": ["CVE-2099-99999"]}))
    with pytest.raises(Conflict, match="versions"):
        enqueue(env, env.data.model_copy(update={"expected_versions": {}}))


@respx.mock
def test_cancellation_between_gets_cannot_checkpoint_or_publish(env):
    first = route(FIRST)
    second = route(SECOND)
    identity = enqueue(env)

    def cancel(request):
        with env.factory.begin() as db:
            db.get(Job, identity).status = "cancelled"
        return httpx.Response(200, json=upstream(FIRST))

    first.mock(side_effect=cancel)
    before = env.journal.head()
    with pytest.raises(ValueError, match="cancelled"):
        run(env, identity)
    assert not second.called and job(env, identity).status == "cancelled"
    assert not job(env, identity).payload.get("capture_sha256")
    assert env.journal.head() == before
