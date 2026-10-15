"""Native DT jobs freeze complete read-only captures before exact-input publication."""

from datetime import timedelta

import httpx
import pytest
import respx
from fastapi import HTTPException

from dtvp.jobs import claim
from dtvp.knowledge.journal import CommitUncertain, Conflict, Ref
from dtvp.knowledge.service import part_ref
from dtvp.knowledge.source_jobs import (
    SourceJobInput,
    enqueue_source,
    execute_source,
    retry_source,
    source_job_view,
)
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Credential, Job, Membership, Project, now
from tests.test_knowledge_analysis_jobs import actor
from tests.test_knowledge_analysis_jobs import env as source_env
from tests.test_knowledge_dependency_track import BASE, EXTERNAL, OTHER, routes

analysis_env = source_env
SOURCE_VERSION = "7.2.0"


@pytest.fixture
def env(analysis_env):
    value = analysis_env
    value.settings.dt_url, value.settings.dt_api_key = BASE, "private-read-only-key"
    with value.factory.begin() as db:
        db.get(Project, "product").metadata_json = {
            "connectors": {
                "dependency-track": {"versions": {SOURCE_VERSION: {"project_id": EXTERNAL}}}
            }
        }
    value.data = SourceJobInput(
        request_id="dt-job-1", expected=None, build_number=1, occurred_at="2026-10-15T06:00:00Z"
    )
    return value


def enqueue(env, data=None, version=SOURCE_VERSION):
    with env.factory.begin() as db:
        return enqueue_source(
            db,
            env.journal,
            env.settings,
            project_id="product",
            version=version,
            actor=actor(db),
            data=data or env.data,
        ).id


def job(env, identity):
    with env.factory() as db:
        return db.get(Job, identity)


def run(env, identity):
    claimed = claim(env.factory)
    assert claimed and claimed[0] == identity
    execute_source(env.factory, env.journal, env.settings, *claimed)


def retry(env, identity):
    with env.factory.begin() as db:
        return retry_source(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        ).id


def test_version_binding_is_mandatory_without_legacy_global_fallback_and_enqueue_idempotent(env):
    identity = enqueue(env)
    assert enqueue(env) == identity
    stored = job(env, identity)
    assert stored.payload["version"] == SOURCE_VERSION
    assert stored.payload["external_project_id"] == EXTERNAL
    assert "release_id" not in stored.payload
    assert "private-read-only-key" not in str(stored.payload) + str(source_job_view(stored))
    with pytest.raises(Conflict):
        enqueue(env, env.data.model_copy(update={"build_number": 2}))
    with env.factory.begin() as db:
        db.get(Project, "product").metadata_json = {
            "connectors": {"dependency-track": {"project_id": EXTERNAL}}
        }
    with pytest.raises(ValueError, match="version"):
        enqueue(env, env.data.model_copy(update={"request_id": "global-not-allowed"}))


@respx.mock
def test_success_freezes_raw_capture_and_publishes_composition_without_dt_writes_or_approvals(env):
    export, page, detail, raw = routes(env.bom)
    identity = enqueue(env)
    original_source = load_sections(env.journal, env.state)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded"
    assert export.call_count == page.call_count == detail.call_count == 1
    assert all(call.request.method == "GET" for call in respx.calls)
    capture = env.journal.load(stored.payload["capture_sha256"])
    assert capture["format"] == "dtvp.dependency-track-capture/1"
    assert stored.payload["raw_artifact_shas"] == capture["raw_artifact_shas"]
    assert raw in [env.journal.objects.read(sha) for sha in capture["raw_artifact_shas"]]
    state = stored.result["state"]
    env.journal.verify_state(state)
    after = load_sections(env.journal, state)
    assert (
        after["inventory"]["baseline"]["source_provenance"]["remote_snapshot_consistent"] is False
    )
    assert after["assessments"] == after["reviews"] == after["scoring"] == {}
    assert load_sections(env.journal, env.state) == original_source


@respx.mock
def test_explicit_part_target_publishes_only_its_source_ref(env):
    routes(env.bom)
    identity = enqueue(env, env.data.model_copy(update={"part_id": "container"}))
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded"
    assert (
        env.journal.resolve(part_ref("product", SOURCE_VERSION, "container"))
        == stored.result["state"]
    )
    assert env.journal.resolve(Ref(project_id="product", name=SOURCE_VERSION)) is None
    assert (
        load_sections(env.journal, stored.result["state"])["inventory"]["baseline"]["part_id"]
        == "container"
    )


@pytest.mark.parametrize("change", ["credential", "permissions", "binding", "endpoint"])
@respx.mock
def test_reauthorize_and_pin_config_before_every_source_read(env, change):
    export, _, _, _ = routes(env.bom)
    identity = enqueue(env)
    if change == "endpoint":
        env.settings.dt_url = "https://another.example.invalid"
    else:
        with env.factory.begin() as db:
            if change == "credential":
                db.get(Credential, "credential").revoked = True
            elif change == "permissions":
                db.get(Membership, ("team", "author")).roles = ["viewer"]
            else:
                db.get(Project, "product").metadata_json = {
                    "connectors": {
                        "dependency-track": {"versions": {SOURCE_VERSION: {"project_id": OTHER}}}
                    }
                }
    with pytest.raises((ValueError, PermissionError, HTTPException)):
        run(env, identity)
    assert not export.called and not respx.calls


@respx.mock
def test_permission_revocation_between_export_and_finding_page_prevents_next_get(env):
    export, page, _, raw = routes(env.bom)
    identity = enqueue(env)

    def revoke(request):
        with env.factory.begin() as db:
            db.get(Credential, "credential").revoked = True
        return httpx.Response(200, content=raw)

    export.mock(side_effect=revoke)
    before = env.journal.head()
    with pytest.raises(ValueError, match="revoked"):
        run(env, identity)
    assert export.call_count == 1 and not page.called
    assert env.journal.head() == before and not job(env, identity).payload.get("capture_sha256")


@respx.mock
def test_uncertain_publication_retries_same_frozen_capture_without_refetch(env, monkeypatch):
    import dtvp.knowledge.source_jobs as module

    routes(env.bom)
    identity = enqueue(env)
    native = module.publish_dependency_track

    def uncertain(*args, **kwargs):
        receipt = native(*args, **kwargs)
        raise CommitUncertain(receipt[0])

    monkeypatch.setattr(module, "publish_dependency_track", uncertain)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "import_pending"
    capture_sha, expected = stored.payload["capture_sha256"], stored.payload["intake"]["expected"]
    calls, committed = len(respx.calls), env.journal.head()
    retry(env, identity)
    monkeypatch.setattr(module, "publish_dependency_track", native)
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert job(env, identity).payload["capture_sha256"] == capture_sha
    assert job(env, identity).payload["intake"]["expected"] == expected
    assert len(respx.calls) == calls and env.journal.head() == committed


@respx.mock
def test_crash_between_journal_publish_and_sql_success_replays_checkpoint(env, monkeypatch):
    import dtvp.knowledge.source_jobs as module

    routes(env.bom)
    identity = enqueue(env)
    native = module.publish_dependency_track

    def crash(*args, **kwargs):
        native(*args, **kwargs)
        raise OSError("Simulated SQL completion loss")

    monkeypatch.setattr(module, "publish_dependency_track", crash)
    with pytest.raises(OSError):
        run(env, identity)
    committed, calls = env.journal.head(), len(respx.calls)
    with env.factory.begin() as db:
        stored = db.get(Job, identity)
        assert stored.payload["capture_sha256"]
        stored.lease_until = now() - timedelta(seconds=1)
    monkeypatch.setattr(module, "publish_dependency_track", native)
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert env.journal.head() == committed and len(respx.calls) == calls


@respx.mock
def test_capture_cas_conflict_never_repins_expected_or_refetches(env, monkeypatch):
    import dtvp.knowledge.source_jobs as module

    routes(env.bom)
    identity = enqueue(env)
    native = module.publish_dependency_track
    raced = []

    def race(*args, **kwargs):
        if not raced:
            other = dict(
                kwargs, data=kwargs["data"].model_copy(update={"request_id": "competing-intake"})
            )
            raced.append(native(*args, **other))
        return native(*args, **kwargs)

    monkeypatch.setattr(module, "publish_dependency_track", race)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    calls, expected = len(respx.calls), job(env, identity).payload["intake"]["expected"]
    retry(env, identity)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    assert job(env, identity).payload["intake"]["expected"] == expected
    assert len(respx.calls) == calls


@respx.mock
def test_failed_incomplete_read_does_not_checkpoint_or_publish_and_explicit_retry_can_refetch(env):
    export, _, detail, _ = routes(env.bom)
    detail.mock(return_value=httpx.Response(503, text="Upstream unavailable"))
    identity = enqueue(env)
    before = env.journal.head()
    with pytest.raises(httpx.HTTPStatusError):
        run(env, identity)
    assert not job(env, identity).payload.get("capture_sha256") and env.journal.head() == before
    with env.factory.begin() as db:
        stored = db.get(Job, identity)
        stored.status, stored.lease_until = "failed", None  # Normal outer worker failure handling.
        stored.payload = {
            **stored.payload,
            "collection_started_at": (now() - timedelta(hours=1)).isoformat(),
        }
    detail.mock(
        return_value=httpx.Response(
            200, json={"analysis": {"analysisState": "IN_TRIAGE"}, "comments": []}
        )
    )
    retry(env, identity)
    run(env, identity)
    assert job(env, identity).status == "succeeded" and export.call_count == 2


@respx.mock
def test_cancellation_between_reads_stops_collection_and_never_publishes(env):
    export, page, _, raw = routes(env.bom)
    identity = enqueue(env)

    def cancel(request):
        with env.factory.begin() as db:
            db.get(Job, identity).status = "cancelled"
        return httpx.Response(200, content=raw)

    export.mock(side_effect=cancel)
    before = env.journal.head()
    with pytest.raises(ValueError, match="cancelled"):
        run(env, identity)
    assert not page.called and env.journal.head() == before
    assert job(env, identity).status == "cancelled"


def test_existing_other_source_authority_and_wrong_head_are_rejected_before_collection(env):
    from tests.test_knowledge_agentyzer import VERSION

    with env.factory.begin() as db:
        db.get(Project, "product").metadata_json = {
            "connectors": {"dependency-track": {"versions": {VERSION: {"project_id": EXTERNAL}}}}
        }
    with pytest.raises(Conflict, match="source authority"):
        enqueue(env, env.data.model_copy(update={"expected": env.state}), version=VERSION)
    with pytest.raises(Conflict, match="head changed"):
        enqueue(env, env.data.model_copy(update={"expected": "f" * 64}), version=VERSION)
