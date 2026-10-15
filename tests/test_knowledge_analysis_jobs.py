"""Operational leases never repeat unknown remote writes or grant human approvals."""

from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi import HTTPException

from dtvp.auth import Actor, capabilities
from dtvp.config import Settings
from dtvp.db import engine_for, migrate, sessions
from dtvp.jobs import claim
from dtvp.knowledge.analysis_jobs import (
    AnalysisJobInput,
    enqueue_analysis,
    execute_analysis,
    job_view,
    retry_analysis,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Journal
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Credential, Job, Membership, Project, User, Workspace, now
from tests.test_knowledge_agentyzer import VERSION, derive, imported, qualified
from tests.test_knowledge_agentyzer_results import report

BASE = "https://agentyzer.example.invalid"


@pytest.fixture
def env(tmp_path, bom):
    engine = engine_for("sqlite:///:memory:")
    migrate(engine)
    factory = sessions(engine)
    with factory.begin() as db:
        db.add(Workspace(id="team", name="Team"))
        db.add(User(id="author", issuer="test", subject="author", name="Author"))
        db.flush()
        db.add(
            Project(
                id="product",
                workspace_id="team",
                name="Product",
                metadata_json={"connectors": {"agentyzer": {"component_name": "gateway"}}},
            )
        )
        db.add(Membership(workspace_id="team", user_id="author", roles=["analyst"]))
        db.add(
            Credential(
                id="credential",
                user_id="author",
                token_hash="a" * 64,
                kind="session",
                expires_at=now() + timedelta(hours=2),
            )
        )
    journal = Journal(tmp_path / "journal")
    state = imported(journal, bom, context=qualified())
    derived = derive(journal, state)
    settings = Settings(
        _env_file=None,
        playground=True,
        database_url="sqlite:///:memory:",
        agentyzer_enabled=True,
        agentyzer_url=BASE,
        agentyzer_token="private-server-token",
    )
    value = SimpleNamespace(
        factory=factory, journal=journal, settings=settings, derived=derived, state=state, bom=bom
    )
    value.data = AnalysisJobInput(
        request_id="analysis-1",
        expected=state,
        context_id=derived["receipt"]["context_id"],
        vulnerability_id=derived["receipt"]["vulnerability_id"],
    )
    yield value
    engine.dispose()


def actor(db):
    return Actor(
        db.get(User, "author"),
        db.get(Credential, "credential"),
        {"team": capabilities(["analyst"])},
    )


def enqueue(env, data=None):
    with env.factory.begin() as db:
        result = enqueue_analysis(
            db,
            env.journal,
            env.settings,
            project_id="product",
            version=VERSION,
            actor=actor(db),
            data=data or env.data,
        )
        return result.id


def job(env, identity):
    with env.factory() as db:
        return db.get(Job, identity)


def run(env, identity):
    claimed = claim(env.factory)
    assert claimed and claimed[0] == identity
    execute_analysis(env.factory, env.journal, env.settings, *claimed)


def ready(env, identity):
    with env.factory.begin() as db:
        db.get(Job, identity).available_at = now() - timedelta(seconds=1)


def complete_routes(env):
    envelope = report(env.derived)
    envelope["job"]["job_id"] = "remote-1"
    posted = respx.post(BASE + "/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "remote-1", "status": "pending"})
    )
    polled = respx.get(BASE + "/jobs/remote-1").mock(
        return_value=httpx.Response(200, json=envelope["job"])
    )
    fetched = respx.get(BASE + "/jobs/remote-1/result").mock(
        return_value=httpx.Response(200, json=envelope["report"])
    )
    return posted, polled, fetched


def test_enqueue_is_idempotent_pinned_native_and_requires_authorized_repository(env):
    identity = enqueue(env)
    assert enqueue(env) == identity
    stored = job(env, identity)
    assert "release_id" not in stored.payload
    assert stored.payload["receipt"] == env.derived["receipt"]
    assert stored.payload["request"] == env.derived["request"]
    assert stored.payload["version"] == VERSION
    assert "private-server-token" not in str(stored.payload) + str(job_view(stored))
    with pytest.raises(Conflict):
        enqueue(env, env.data.model_copy(update={"user_guidance": "Different request"}))
    with env.factory.begin() as db:
        db.get(Project, "product").metadata_json = {
            "connectors": {"agentyzer": {"component_name": "another-repo"}}
        }
    with pytest.raises(PermissionError):
        enqueue(env, env.data.model_copy(update={"request_id": "another"}))


@respx.mock
def test_completed_remote_envelope_is_imported_without_human_or_source_changes(env):
    identity = enqueue(env)
    posted, polled, fetched = complete_routes(env)
    before = load_sections(env.journal, env.state)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded"
    assert posted.call_count == polled.call_count == fetched.call_count == 1
    assert posted.calls[0].request.headers["Authorization"] == "Bearer private-server-token"
    after = load_sections(env.journal, stored.result["state"])
    for section in ("inventory", "ownership", "vulnerabilities", "assessments", "reviews"):
        assert after[section] == before[section]
    assert any(key.startswith("code-analysis:") for key in after["history"])
    assert not any(key.startswith("published:") for key in after["scoring"])
    assert env.journal.load(stored.payload["report_sha256"])["job"]["job_id"] == "remote-1"


@respx.mock
def test_pending_poll_and_recovered_lease_reuse_known_remote_id_without_post(env):
    identity = enqueue(env)
    posted, polled, fetched = complete_routes(env)
    completed = report(env.derived)["job"] | {"job_id": "remote-1"}
    polled.mock(return_value=httpx.Response(200, json={"job_id": "remote-1", "status": "running"}))
    run(env, identity)
    assert job(env, identity).status == "queued" and not fetched.called
    ready(env, identity)
    claimed = claim(env.factory)
    with env.factory.begin() as db:
        db.get(Job, identity).lease_until = now() - timedelta(seconds=1)
    polled.mock(return_value=httpx.Response(200, json=completed))
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert job(env, identity).attempts == 3
    assert posted.call_count == 1
    execute_analysis(env.factory, env.journal, env.settings, *claimed)  # Old lease cannot publish.
    assert posted.call_count == 1


@respx.mock
def test_ambiguous_post_is_terminal_and_cannot_be_blindly_retried(env):
    identity = enqueue(env)
    posted = respx.post(BASE + "/assess").mock(
        side_effect=httpx.ReadTimeout("secret provider body")
    )
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "submission_unknown" and stored.payload["submission_started"]
    assert "secret provider body" not in str(job_view(stored))
    assert claim(env.factory) is None
    with env.factory.begin() as db, pytest.raises(Conflict, match="unknown submissions"):
        retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
    assert posted.call_count == 1


@respx.mock
def test_crash_after_durable_submit_marker_never_posts_on_lease_recovery(env):
    identity = enqueue(env)
    claimed = claim(env.factory)
    with env.factory.begin() as db:
        stored = db.get(Job, identity)
        stored.payload = {**stored.payload, "submission_started": True}
        stored.lease_until = now() - timedelta(seconds=1)
    run(env, identity)
    assert job(env, identity).status == "submission_unknown"
    assert not respx.calls
    execute_analysis(env.factory, env.journal, env.settings, *claimed)
    assert not respx.calls


@pytest.mark.parametrize(
    "change", ["credential", "permissions", "repository", "endpoint", "source"]
)
@respx.mock
def test_revocation_or_changed_bindings_prevent_every_outbound_step(env, change):
    identity = enqueue(env)
    complete_routes(env)
    with env.factory.begin() as db:
        if change == "credential":
            db.get(Credential, "credential").revoked = True
        elif change == "permissions":
            db.get(Membership, ("team", "author")).roles = ["viewer"]
        elif change == "repository":
            db.get(Project, "product").metadata_json = {}
    if change == "endpoint":
        env.settings.agentyzer_url = "https://another.example.invalid"
    elif change == "source":
        changed = dict(env.bom)
        changed["components"] = [
            dict(value) | ({"version": "changed"} if value["bom-ref"] == "http" else {})
            for value in env.bom["components"]
        ]
        imported(env.journal, changed, context=qualified(), expected=env.state, build_number=2)
    with pytest.raises((ValueError, PermissionError, HTTPException)):
        run(env, identity)
    assert not respx.calls


@respx.mock
def test_safe_poll_timeout_can_retry_without_duplicate_submission(env):
    identity = enqueue(env)
    posted, polled, _ = complete_routes(env)
    polled.mock(side_effect=httpx.ReadTimeout("temporary"))
    run(env, identity)
    assert job(env, identity).status == "queued"
    ready(env, identity)
    polled.mock(
        return_value=httpx.Response(200, json=report(env.derived)["job"] | {"job_id": "remote-1"})
    )
    run(env, identity)
    assert job(env, identity).status == "succeeded" and posted.call_count == 1


@respx.mock
def test_journal_uncertain_commit_replays_deterministically_after_recovery(env, monkeypatch):
    import dtvp.knowledge.analysis_jobs as module

    identity = enqueue(env)
    posted, _, _ = complete_routes(env)
    native = module.import_agentyzer_result

    def uncertain(*args, **kwargs):
        receipt = native(*args, **kwargs)
        raise CommitUncertain(receipt[0])

    monkeypatch.setattr(module, "import_agentyzer_result", uncertain)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    committed = env.journal.head()
    monkeypatch.setattr(module, "import_agentyzer_result", native)
    with env.factory.begin() as db:
        retried = retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
        assert retried.status == "succeeded"
    assert env.journal.head() == committed and posted.call_count == 1


@respx.mock
def test_material_drift_during_remote_run_retains_completed_but_stale_evidence(env):
    from dtvp.knowledge.agentyzer_results import list_agentyzer_results

    identity = enqueue(env)
    posted, _, fetched = complete_routes(env)
    envelope = report(env.derived)

    def complete_after_drift(request):
        changed = {
            **env.bom,
            "components": [
                dict(value) | ({"version": "2.0.0"} if value["bom-ref"] == "http" else {})
                for value in env.bom["components"]
            ],
        }
        imported(env.journal, changed, context=qualified(), expected=env.state, build_number=2)
        return httpx.Response(200, json=envelope["report"])

    fetched.mock(side_effect=complete_after_drift)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded" and posted.call_count == 1
    receipt = env.derived["receipt"]
    sections = load_sections(env.journal, stored.result["state"])
    rows = list_agentyzer_results(
        env.journal, sections, VERSION, receipt["context_id"], receipt["vulnerability_id"]
    )
    assert len(rows) == 1 and not rows[0]["current"] and not rows[0]["application_eligible"]
    assert "source_evidence_changed" in rows[0]["ineligibility_reasons"]
    assert env.journal.load(stored.payload["report_sha256"])["report"] == envelope["report"]
    assert sections["assessments"] == sections["reviews"] == {}


@respx.mock
def test_publication_cas_race_retains_report_then_explicit_retry_repins_current_head(
    env, monkeypatch
):
    import dtvp.knowledge.analysis_jobs as module

    identity = enqueue(env)
    posted, _, fetched = complete_routes(env)
    native = module.import_agentyzer_result
    raced = []

    def race(*args, **kwargs):
        if not raced:
            raced.append(True)
            imported(env.journal, env.bom, context=qualified(), expected=env.state, build_number=2)
        return native(*args, **kwargs)

    monkeypatch.setattr(module, "import_agentyzer_result", race)
    run(env, identity)
    assert job(env, identity).status == "import_pending"
    assert job(env, identity).payload["report_sha256"]
    with env.factory.begin() as db:
        retried = retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
        assert retried.status == "queued"
    run(env, identity)
    assert job(env, identity).status == "succeeded"
    assert posted.call_count == fetched.call_count == 1


@respx.mock
def test_crash_after_journal_publish_recovers_from_durable_exact_import_input(env, monkeypatch):
    import dtvp.knowledge.analysis_jobs as module

    identity = enqueue(env)
    posted, _, _ = complete_routes(env)
    native = module.import_agentyzer_result

    def crash(*args, **kwargs):
        native(*args, **kwargs)
        raise OSError("Simulated crash before SQL completion")

    monkeypatch.setattr(module, "import_agentyzer_result", crash)
    with pytest.raises(OSError):
        run(env, identity)
    committed = env.journal.head()
    with env.factory.begin() as db:
        stored = db.get(Job, identity)
        assert stored.payload["report_sha256"] and stored.status == "running"
        stored.lease_until = now() - timedelta(seconds=1)
    monkeypatch.setattr(module, "import_agentyzer_result", native)
    run(env, identity)
    assert job(env, identity).status == "succeeded" and env.journal.head() == committed
    assert posted.call_count == 1


@respx.mock
def test_actor_revoked_between_status_and_result_is_rechecked_before_next_request(env):
    identity = enqueue(env)
    _, polled, fetched = complete_routes(env)

    def revoke(request):
        with env.factory.begin() as db:
            db.get(Credential, "credential").revoked = True
        return httpx.Response(200, json=report(env.derived)["job"] | {"job_id": "remote-1"})

    polled.mock(side_effect=revoke)
    with pytest.raises(ValueError, match="revoked"):
        run(env, identity)
    assert not fetched.called


@respx.mock
def test_uncertain_explicit_retry_never_repins_an_already_published_import(env, monkeypatch):
    import dtvp.knowledge.analysis_jobs as module

    identity = enqueue(env)
    complete_routes(env)
    native = module.import_agentyzer_result
    calls = []

    def uncertain(*args, **kwargs):
        calls.append(kwargs["data"].expected)
        if len(calls) == 1:
            raise CommitUncertain("f" * 64)  # First publication did not replace HEAD.
        receipt = native(*args, **kwargs)
        raise CommitUncertain(receipt[0])  # Explicit retry did replace HEAD.

    monkeypatch.setattr(module, "import_agentyzer_result", uncertain)
    run(env, identity)
    original_expected = job(env, identity).payload["import_expected"]
    with env.factory.begin() as db:
        retried = retry_analysis(
            db, env.journal, env.settings, project_id="product", job_id=identity, actor=actor(db)
        )
        assert retried.status == "import_pending"
        assert retried.payload["import_expected"] == original_expected
    committed = env.journal.head()
    monkeypatch.setattr(module, "import_agentyzer_result", native)
    with env.factory.begin() as db:
        assert (
            retry_analysis(
                db,
                env.journal,
                env.settings,
                project_id="product",
                job_id=identity,
                actor=actor(db),
            ).status
            == "succeeded"
        )
    assert calls == [original_expected, original_expected]
    assert env.journal.head() == committed
