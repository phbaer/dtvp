"""Matching workers checkpoint queries, honor live authority and never repin frozen captures."""

import json
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest

from dtvp.jobs import claim
from dtvp.knowledge import osv_jobs as module
from dtvp.knowledge.evidence import current_evidence
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.osv_matching import MatchingInput, selection
from dtvp.models import Credential, Job
from tests.test_knowledge_advisory_documents import heads
from tests.test_knowledge_analysis_jobs import actor
from tests.test_knowledge_analysis_jobs import env as analysis_env
from tests.test_knowledge_osv_matching import upstream

source_env = analysis_env


@pytest.fixture
def env(source_env):
    value = source_env
    value.settings.providers_enabled = ["osv"]
    value.data = MatchingInput(
        request_id="matching-job",
        expected_versions=heads(value.journal),
        expected_evidence=None,
        purls=sorted(selection(value.journal, "product", heads(value.journal))["packages"])[:2],
        revision=0,
    )
    return value


def enqueue(env):
    with env.factory.begin() as db:
        return module.enqueue_matching(
            db, env.journal, env.settings, project_id="product", actor=actor(db), data=env.data
        ).id


def job(env, identity):
    with env.factory() as db:
        return db.get(Job, identity)


def run(env, identity):
    selected = claim(env.factory)
    assert selected and selected[0] == identity
    return module.execute_matching(env.factory, env.journal, env.settings, *selected)


def retry(env, identity):
    with env.factory.begin() as db:
        return module.retry_matching(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        ).id


def install_transport(monkeypatch, callback):
    @contextmanager
    def client():
        with httpx.Client(transport=httpx.MockTransport(callback)) as transport:
            yield transport

    monkeypatch.setattr(module, "client", client)


def test_completed_query_checkpoint_precedes_next_post_and_final_capture_is_retained(
    env, monkeypatch
):
    identity = enqueue(env)
    calls = []

    def transport(request):
        calls.append(json.loads(request.content))
        assert request.headers["accept-encoding"] == "identity"
        if len(calls) == 2:
            stored = job(env, identity)
            assert stored.result["completed_queries"] == 1
            assert stored.payload["progress_sha256"]
            frozen = env.journal.load(stored.payload["progress_sha256"])
            assert frozen["queries"][0]["purl"] == env.data.purls[0]
            assert env.journal.objects.read(stored.result["raw_artifact_shas"][0])
        return httpx.Response(200, json={"vulns": [upstream()]})

    install_transport(monkeypatch, transport)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded" and len(calls) == 2
    evidence = current_evidence(env.journal, "product")[0]
    assert stored.payload["capture_sha256"] in env.journal.state(evidence).artifacts


def test_partial_failure_resumes_without_refetching_checkpointed_query(env, monkeypatch):
    identity = enqueue(env)
    calls = []

    def failing(request):
        purl = json.loads(request.content)["package"]["purl"]
        calls.append(purl)
        if purl == env.data.purls[1]:
            raise httpx.ReadTimeout("synthetic failure")
        return httpx.Response(200, json={})

    install_transport(monkeypatch, failing)
    with pytest.raises(httpx.ReadTimeout):
        run(env, identity)
    assert current_evidence(env.journal, "product")[0] is None
    assert job(env, identity).result["completed_queries"] == 1
    with env.factory.begin() as db:
        db.get(Job, identity).status = "failed"
    retry(env, identity)
    install_transport(
        monkeypatch,
        lambda request: (
            calls.append(json.loads(request.content)["package"]["purl"])
            or httpx.Response(200, json={})
        ),
    )
    run(env, identity)
    assert calls.count(env.data.purls[0]) == 1 and calls.count(env.data.purls[1]) == 2
    assert job(env, identity).status == "succeeded"


def test_pending_capture_retry_never_refetches_or_silently_repins(env, monkeypatch):
    identity = enqueue(env)
    original = module.publish_matches
    monkeypatch.setattr(
        module,
        "publish_matches",
        lambda *args, **kwargs: (_ for _ in ()).throw(Conflict("synthetic CAS")),
    )
    install_transport(monkeypatch, lambda _: httpx.Response(200, json={}))
    run(env, identity)
    frozen = job(env, identity)
    assert frozen.status == "import_pending" and frozen.payload["capture_sha256"]
    monkeypatch.setattr(module, "publish_matches", original)
    retry(env, identity)
    monkeypatch.setattr(
        module, "client", lambda: pytest.fail("Frozen capture retry must not contact provider")
    )
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert job(env, identity).payload["capture_sha256"] == frozen.payload["capture_sha256"]


def test_authority_revoked_before_first_query_blocks_network(env, monkeypatch):
    identity = enqueue(env)
    with env.factory.begin() as db:
        db.get(Credential, "credential").revoked = True
    monkeypatch.setattr(module, "client", lambda: pytest.fail("Revoked actor must not contact OSV"))
    with pytest.raises(ValueError, match="revoked"):
        run(env, identity)
    assert current_evidence(env.journal, "product")[0] is None


def test_dribbling_stream_reauthorizes_and_blocks_revocation_without_query_publication(
    env, monkeypatch
):
    identity = enqueue(env)
    moment = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: moment[0]))

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"vulns":'
            with env.factory.begin() as db:
                db.get(Credential, "credential").revoked = True
            moment[0] += 11
            yield b"[]}"

    install_transport(monkeypatch, lambda _: httpx.Response(200, stream=Stream()))
    with pytest.raises(ValueError, match="revoked"):
        run(env, identity)
    assert not job(env, identity).payload.get("progress_sha256")
    assert current_evidence(env.journal, "product")[0] is None


def test_stream_monotonic_budget_prevents_late_publication_even_if_wall_clock_stalls(
    env, monkeypatch
):
    identity = enqueue(env)
    moment = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: moment[0]))

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"vulns":'
            moment[0] += 901
            yield b"[]}"

    install_transport(monkeypatch, lambda _: httpx.Response(200, stream=Stream()))
    with pytest.raises(ValueError, match="observation interval"):
        run(env, identity)
    assert current_evidence(env.journal, "product")[0] is None


@pytest.mark.parametrize("loss", ["token", "expiry"])
def test_chunk_heartbeat_renews_lease_and_forced_end_check_rejects_lost_lease(
    env, monkeypatch, loss
):
    identity = enqueue(env)
    moment = [0.0]
    original_now = module.now
    baseline = original_now()
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: moment[0]))
    monkeypatch.setattr(module, "now", lambda: baseline + timedelta(seconds=moment[0]))

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"vulns":'
            moment[0] += 11
            yield b"[]}"
            assert job(env, identity).lease_until.replace(
                tzinfo=baseline.tzinfo
            ) >= baseline + timedelta(seconds=100)
            with env.factory.begin() as db:
                if loss == "token":
                    db.get(Job, identity).lease_token = "another-worker"
                else:
                    db.get(Job, identity).lease_until = module.now() - timedelta(seconds=1)

    install_transport(monkeypatch, lambda _: httpx.Response(200, stream=Stream()))
    with pytest.raises(ValueError, match="lease"):
        run(env, identity)
    assert current_evidence(env.journal, "product")[0] is None
