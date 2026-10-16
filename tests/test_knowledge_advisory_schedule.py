"""Bounded scheduling uses exact existing job contracts and durable provider pacing."""

from datetime import timedelta
from email.utils import format_datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from dtvp.auth import Actor, capabilities
from dtvp.jobs import claim
from dtvp.knowledge import advisory_schedule as module
from dtvp.knowledge.advisory_jobs import KIND
from dtvp.knowledge.journal import Conflict
from dtvp.models import AdvisoryProviderThrottle, Credential, Job, Membership, Project, User, now
from tests.test_knowledge_analysis_jobs import env as analysis_env

source_env = analysis_env


@pytest.fixture
def env(source_env):
    with source_env.factory.begin() as db:
        db.get(Membership, ("team", "author")).roles = ["admin"]
    source_env.settings.providers_enabled = ["nvd", "circl"]
    return source_env


def actor(db):
    return Actor(
        db.get(User, "author"), db.get(Credential, "credential"), {"team": capabilities(["admin"])}
    )


def configured(env, **changes):
    versions = list(module.product_heads(env.journal.references(), "product"))
    data = module.AdvisoryScheduleInput.model_validate(
        {
            "request_id": "configure-schedule",
            "expected_policy": None,
            "providers": [
                {"provider": "nvd", "versions": versions, "interval_seconds": 3600, "batch_size": 1}
            ],
        }
        | changes
    )
    with env.factory() as db:
        return module.configure(
            env.journal, env.settings, project_id="product", actor=actor(db), data=data
        )


def jobs(env):
    with env.factory() as db:
        return list(
            db.scalars(select(Job).where(Job.kind == KIND).order_by(Job.created_at, Job.id))
        )


def test_policy_is_opt_in_versioned_and_cas_replayable(env):
    assert module.reconcile(env.factory, env.journal, env.settings) == 0
    assert module.policy(env.journal, "product") == (None, {"providers": []})
    configured(env)
    before = env.journal.head()
    configured(env)
    assert env.journal.head() == before
    with pytest.raises(Conflict):
        configured(env, request_id="other")
    assert module.policy(env.journal, "product")[1]["credential_id"] == "credential"


@pytest.mark.parametrize(
    "changes",
    [
        {"versions": []},
        {"versions": ["same", "same"]},
        {"interval_seconds": 3599},
        {"batch_size": 21},
    ],
)
def test_schedule_bounds(changes):
    with pytest.raises(ValidationError):
        module.ProviderSchedule.model_validate({"provider": "nvd", "versions": ["one"]} | changes)


def test_enqueue_gap_recovery_pins_heads_and_never_publishes_knowledge(env):
    configured(env)
    before = env.journal.head()
    assert module.reconcile(env.factory, env.journal, env.settings) == 1
    assert module.reconcile(env.factory, env.journal, env.settings) == 0
    job = jobs(env)[0]
    assert job.payload["intake"]["expected_versions"] == module.product_heads(
        env.journal.references(), "product"
    )
    assert len(job.payload["intake"]["identifiers"]) == 1
    assert job.payload["schedule"]["policy"] == module.policy(env.journal, "product")[0]
    assert env.journal.head() == before


def test_due_batches_rotate_and_unresolved_publication_blocks_new_cycles(env):
    configured(env)
    module.reconcile(env.factory, env.journal, env.settings)
    original = jobs(env)[0]
    with env.factory.begin() as db:
        previous = db.get(Job, original.id)
        previous.created_at = now() - timedelta(hours=2)
        previous.status = "import_pending"
    assert module.reconcile(env.factory, env.journal, env.settings) == 0
    with env.factory.begin() as db:
        db.get(Job, original.id).status = "failed"
    assert module.reconcile(env.factory, env.journal, env.settings) == 1
    current = next(job for job in jobs(env) if job.id != original.id)
    assert current.payload["intake"]["identifiers"] != original.payload["intake"]["identifiers"]
    assert current.payload["intake"]["expected_evidence"] is None


@pytest.mark.parametrize("change", ["credential", "membership", "provider"])
def test_revoked_authority_or_disabled_provider_stops_scheduling(env, change):
    configured(env)
    if change == "provider":
        env.settings.providers_enabled = []
    else:
        with env.factory.begin() as db:
            if change == "credential":
                db.get(Credential, "credential").revoked = True
            else:
                db.get(Membership, ("team", "author")).roles = ["viewer"]
    assert module.reconcile(env.factory, env.journal, env.settings) == 0
    assert jobs(env) == []


def test_missing_configured_version_waits_and_empty_policy_stops_future_work(env):
    configured(env, providers=[{"provider": "nvd", "versions": ["not-imported"]}])
    assert module.reconcile(env.factory, env.journal, env.settings) == 0
    pin = module.policy(env.journal, "product")[0]
    configured(env, request_id="stop", expected_policy=pin, providers=[])
    assert module.reconcile(env.factory, env.journal, env.settings) == 0


class Clock:
    def __init__(self):
        self.tick, self.waits = now(), []

    def now(self):
        return self.tick

    def sleep(self, delay):
        self.waits.append(delay)
        self.tick += timedelta(seconds=delay)


def running(env):
    configured(env)
    module.reconcile(env.factory, env.journal, env.settings)
    identity, _ = claim(env.factory)
    return identity


def test_manual_and_scheduled_requests_share_durable_provider_gap(env):
    identity = running(env)
    clock = Clock()
    module.wait_for_provider_slot(env.factory, identity, clock=clock.now, sleep=clock.sleep)
    module.wait_for_provider_slot(env.factory, identity, clock=clock.now, sleep=clock.sleep)
    assert clock.waits == [6.0]
    with env.factory() as db:
        assert len(list(db.scalars(select(AdvisoryProviderThrottle)))) == 1
        assert len(list(db.scalars(select(Job)))) == 1
        assert db.get(AdvisoryProviderThrottle, "nvd").last_dispatch_at is not None


@pytest.mark.parametrize("date", [False, True])
def test_retry_after_is_shared_and_long_cooldown_fails_before_request(env, date):
    identity = running(env)
    clock = Clock()
    until = clock.now() + timedelta(seconds=120)
    header = format_datetime(until, usegmt=True) if date else "120"
    module.record_retry_after(env.factory, identity, header, clock=clock.now)
    with pytest.raises(ValueError, match="30 seconds"):
        module.wait_for_provider_slot(env.factory, identity, clock=clock.now, sleep=clock.sleep)
    assert clock.waits == []
    with env.factory() as db:
        marker = db.get(AdvisoryProviderThrottle, "nvd")
        assert marker.last_dispatch_at is None
        assert module.aware(marker.cooldown_until).replace(microsecond=0) == until.replace(
            microsecond=0
        )


def test_short_retry_after_waits_once_and_rechecks_cancellation(env):
    identity = running(env)
    clock = Clock()
    module.record_retry_after(env.factory, identity, "10", clock=clock.now)

    def cancel(delay):
        clock.sleep(delay)
        with env.factory.begin() as db:
            db.get(Job, identity).status = "cancelled"

    with pytest.raises(ValueError, match="no longer running"):
        module.wait_for_provider_slot(env.factory, identity, clock=clock.now, sleep=cancel)
    assert clock.waits == [10]
    with env.factory() as db:
        assert db.get(AdvisoryProviderThrottle, "nvd").last_dispatch_at is None


def test_providers_are_independent_and_marker_has_no_project_owner(env):
    identity = running(env)
    clock = Clock()
    module.wait_for_provider_slot(env.factory, identity, clock=clock.now, sleep=clock.sleep)
    with env.factory.begin() as db:
        other = Job(
            project_id="product",
            actor_id="author",
            kind=KIND,
            status="running",
            payload={"intake": {"provider": "circl"}},
        )
        db.add(other)
        db.flush()
        other_id = other.id
    module.wait_for_provider_slot(env.factory, other_id, clock=clock.now, sleep=clock.sleep)
    assert clock.waits == []


def test_selected_input_bounds_fail_without_truncation(env, monkeypatch):
    heads = module.product_heads(env.journal.references(), "product")
    monkeypatch.setattr(module, "MAX_SELECTED_BYTES", 1)
    with pytest.raises(ValueError, match="64 MiB"):
        module.selected_identifiers(env.journal, "product", heads)
    monkeypatch.undo()
    monkeypatch.setattr(module, "MAX_SELECTED_RECORDS", 1)
    with pytest.raises(ValueError, match="100,000"):
        module.selected_identifiers(env.journal, "product", heads)


def test_replaced_policy_stops_fresh_collection_before_any_get(env):
    from dtvp.knowledge.advisory_jobs import execute_advisory_refresh

    identity = running(env)
    with env.factory() as db:
        token = db.get(Job, identity).lease_token
    pin = module.policy(env.journal, "product")[0]
    configured(env, request_id="stop-fresh-collection", expected_policy=pin, providers=[])
    with pytest.raises(Conflict, match="schedule changed"):
        execute_advisory_refresh(env.factory, env.journal, env.settings, identity, token)


def test_invalid_retry_after_has_bounded_conservative_cooldown(env):
    identity = running(env)
    clock = Clock()
    module.record_retry_after(env.factory, identity, "unparseable", clock=clock.now)
    with env.factory() as db:
        assert module.aware(
            db.get(AdvisoryProviderThrottle, "nvd").cooldown_until
        ) == clock.now() + timedelta(seconds=60)


def test_bad_first_policy_does_not_starve_a_healthy_project(env, monkeypatch, caplog):
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.knowledge.workspace import load_sections

    configured(env)
    version, source = next(iter(module.product_heads(env.journal.references(), "product").items()))
    with env.factory.begin() as db:
        db.add(Project(id="z-healthy", name="Healthy", workspace_id="team"))
    state = env.journal.snapshot(
        project_id="z-healthy",
        version=version,
        actor_id="author",
        reason="Synthetic scheduler fixture",
        sections=load_sections(env.journal, source),
        artifacts=env.journal.state(source).artifacts,
    )
    env.journal.publish(
        request_id="healthy-baseline",
        fingerprint="1" * 64,
        updates=[
            Update(ref=Ref(project_id="z-healthy", name=version), expected=None, target=state)
        ],
    )
    with env.factory() as db:
        module.configure(
            env.journal,
            env.settings,
            project_id="z-healthy",
            actor=actor(db),
            data=module.AdvisoryScheduleInput(
                request_id="healthy-schedule",
                expected_policy=None,
                providers=[module.ProviderSchedule(provider="nvd", versions=[version])],
            ),
        )
    original = module.selected_identifiers

    def bounded(journal, project, heads):
        if project == "product":
            raise ValueError("confidential diagnostic must not be logged")
        return original(journal, project, heads)

    monkeypatch.setattr(module, "selected_identifiers", bounded)
    monkeypatch.setattr(module.reconcile, "cursor", "", raising=False)
    assert module.reconcile(env.factory, env.journal, env.settings) == 1
    assert jobs(env)[0].project_id == "z-healthy"
    assert module.reconcile.cursor == "z-healthy"
    assert "skipped bounded or stale" in caplog.text
    assert "confidential diagnostic" not in caplog.text
