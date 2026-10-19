"""Native worker leases never execute or mutate retained legacy jobs."""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from dtvp.db import engine_for, migrate, sessions
from dtvp.jobs import claim, execute, work_once
from dtvp.models import Job, Project, User, Workspace, now
from dtvp.storage import Artifacts


@pytest.fixture
def worker(tmp_path):
    engine = engine_for("sqlite:///:memory:")
    migrate(engine)
    factory = sessions(engine)
    with factory.begin() as db:
        db.add(Workspace(id="team", name="Team"))
        db.add(User(id="author", issuer="test", subject="author", name="Author"))
        db.flush()
        db.add(Project(id="product", workspace_id="team", name="Product"))
    yield factory, Artifacts(tmp_path / "artifacts"), SimpleNamespace()
    engine.dispose()


def add(factory, identifier, kind="propose-sync-native", **changes):
    with factory.begin() as db:
        db.add(
            Job(
                id=identifier,
                project_id="product",
                actor_id="author",
                kind=kind,
                payload={"preserved": True},
                **changes,
            )
        )


@pytest.mark.parametrize("status", ["queued", "running"])
def test_retained_jobs_do_not_starve_native_jobs_or_mutate_history(worker, status):
    factory, _, _ = worker
    add(
        factory,
        "old",
        "match",
        status=status,
        lease_until=now() - timedelta(seconds=1),
        created_at=now() - timedelta(days=1),
        result={"retained": True},
    )
    add(factory, "native")
    identifier, token = claim(factory)
    assert identifier == "native" and token
    assert claim(factory) is None
    with factory() as db:
        old = db.get(Job, "old")
        assert (old.status, old.attempts, old.payload, old.result) == (
            status,
            0,
            {"preserved": True},
            {"retained": True},
        )


def test_native_expired_lease_can_be_recovered(worker):
    factory, _, _ = worker
    add(factory, "native")
    first = claim(factory)
    with factory.begin() as db:
        db.get(Job, "native").lease_until = now() - timedelta(seconds=1)
    second = claim(factory)
    assert first[0] == second[0] and first[1] != second[1]
    with factory() as db:
        assert db.get(Job, "native").attempts == 2


def test_cancelled_and_future_jobs_are_not_claimed(worker):
    factory, _, _ = worker
    add(factory, "cancelled", status="cancelled")
    add(factory, "future", available_at=now() + timedelta(days=1))
    assert claim(factory) is None


def test_worker_dispatches_native_job_and_updates_projection(worker, monkeypatch):
    from dtvp.knowledge import sync_jobs

    factory, artifacts, settings = worker
    add(factory, "native")
    calls = []

    def complete(factory, journal, settings, identifier, token):
        calls.append((identifier, token))
        with factory.begin() as db:
            job = db.get(Job, identifier)
            assert job.lease_token == token
            job.status = "succeeded"
            job.result = {"publication": "retained"}

    monkeypatch.setattr(sync_jobs, "execute", complete)
    assert work_once(factory, artifacts, settings)
    with factory() as db:
        job = db.get(Job, "native")
        assert job.result == {"publication": "retained", "projection": "current"}
        assert calls == [(job.id, job.lease_token)]


def test_legacy_direct_execution_rejected_without_mutation(worker):
    factory, artifacts, settings = worker
    add(factory, "old", "import-dt")
    with pytest.raises(ValueError, match="only native"):
        execute(factory, artifacts, settings, "old", "unused")
    with factory() as db:
        assert db.get(Job, "old").status == "queued"
