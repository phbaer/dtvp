"""Offline collection protects live history/checkpoints and retains recovery bytes."""

import os
from pathlib import Path
from time import time

import pytest
from sqlalchemy import insert

from dtvp.db import engine_for, migrate
from dtvp.knowledge.journal import SECTIONS, Journal, Ref, Update
from dtvp.knowledge.maintenance_lock import MaintenanceBusy, RuntimeLease
from dtvp.knowledge.offline_cleanup import apply_cleanup, plan_cleanup
from dtvp.knowledge.projection import catch_up
from dtvp.models import Job, Project, User, Workspace
from dtvp.storage import digest


@pytest.fixture(params=["sqlite"] + (["postgresql"] if os.getenv("DTVP_TEST_DATABASE_URL") else []))
def installation(tmp_path, request):
    journal = Journal(tmp_path / "artifacts" / "knowledge")
    url = "sqlite:///:memory:"
    if request.param == "postgresql":
        from sqlalchemy import text
        from sqlalchemy.engine import make_url

        url = os.environ["DTVP_TEST_DATABASE_URL"]
        assert make_url(url).database.endswith("_test")
        clean = engine_for(url)
        with clean.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        clean.dispose()
    engine = engine_for(url)
    migrate(engine)
    yield journal, engine
    engine.dispose()


def old_object(journal, raw=b"unreferenced staged bytes"):
    sha = journal.objects.put(raw)
    os.utime(journal.objects.path(sha), (time() - 40 * 86400,) * 2)
    return sha


def test_plan_apply_retains_history_and_exact_recovery_copies(installation, tmp_path):
    journal, engine = installation
    retained = old_object(journal, b"retained source")
    state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="test",
        reason="Retained",
        sections={name: {} for name in SECTIONS},
        artifacts=[retained],
    )
    journal.publish(
        request_id="initial",
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    catch_up(engine, journal)
    orphan = old_object(journal)
    head = journal.head()
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    assert [item["sha256"] for item in plan["objects"]] == [orphan]
    assert plan["operational_references_complete"]
    assert not (tmp_path / "recovery").exists()
    receipt = apply_cleanup(journal.root, engine, plan, recovery_dir=tmp_path / "recovery")
    assert receipt["removed"] == [orphan]
    assert not journal.objects.path(orphan).exists()
    assert (tmp_path / "recovery" / orphan).read_bytes() == b"unreferenced staged bytes"
    assert journal.head() == head
    assert journal.objects.read(retained) == b"retained source"
    journal.verify_state(state)


@pytest.mark.parametrize("status", ["queued", "failed", "cancelled", "succeeded"])
def test_all_job_statuses_protect_unpublished_checkpoint_graph(installation, status):
    journal, engine = installation
    raw = old_object(journal)
    capture = journal.store({"raw_artifact_shas": [raw]})
    os.utime(journal.objects.path(capture), (time() - 40 * 86400,) * 2)
    with engine.begin() as connection:
        connection.execute(insert(Workspace).values(id="team", name="Team"))
        connection.execute(
            insert(User).values(id="actor", issuer="test", subject="test", name="Actor")
        )
        connection.execute(
            insert(Project).values(id="product", workspace_id="team", name="Product")
        )
        connection.execute(
            insert(Job).values(
                id="job",
                project_id="product",
                actor_id="actor",
                kind="match-osv-native",
                status=status,
                payload={"capture_sha256": capture},
            )
        )
    result = plan_cleanup(journal.root, engine, min_age_days=30)
    assert result["objects"] == []
    assert raw in result["database"]["roots"] or capture in result["database"]["roots"]


def test_active_runtime_blocks_plan_and_apply(installation, tmp_path):
    journal, engine = installation
    old_object(journal)
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    lease = RuntimeLease(journal.root)
    try:
        with pytest.raises(MaintenanceBusy):
            plan_cleanup(journal.root, engine, min_age_days=30)
        with pytest.raises(MaintenanceBusy):
            apply_cleanup(journal.root, engine, plan, recovery_dir=tmp_path / "recovery")
    finally:
        lease.close()


@pytest.mark.parametrize("change", ["database", "storage", "plan"])
def test_stale_or_modified_plans_delete_nothing(installation, tmp_path, change):
    journal, engine = installation
    orphan = old_object(journal)
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    if change == "database":
        with engine.begin() as connection:
            connection.execute(insert(Workspace).values(id="new", name="New"))
    elif change == "storage":
        journal.objects.put(b"new concurrent object")
    else:
        plan["objects"] = []
    with pytest.raises(ValueError):
        apply_cleanup(journal.root, engine, plan, recovery_dir=tmp_path / "recovery")
    assert journal.objects.read(orphan)
    assert not (tmp_path / "recovery").exists()


def test_recovery_failure_prevents_first_delete_and_existing_directory_is_preserved(
    installation, tmp_path
):
    journal, engine = installation
    orphan = old_object(journal)
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    recovery = tmp_path / "recovery"
    recovery.mkdir()
    (recovery / "keep").write_text("untouched")
    with pytest.raises(FileExistsError):
        apply_cleanup(journal.root, engine, plan, recovery_dir=recovery)
    assert journal.objects.read(orphan)
    assert (recovery / "keep").read_text() == "untouched"
    with pytest.raises(ValueError, match="outside"):
        apply_cleanup(journal.root, engine, plan, recovery_dir=journal.root.parent / "backup")


def test_partial_unlink_failure_has_all_verified_recovery_bytes(
    installation, tmp_path, monkeypatch
):
    journal, engine = installation
    shas = [old_object(journal, value) for value in (b"one", b"two")]
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    original = Path.unlink
    failed = journal.objects.path(plan["objects"][1]["sha256"])

    def interrupted(path, *args, **kwargs):
        if path == failed:
            raise OSError("Simulated unlink interruption")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", interrupted)
    with pytest.raises(OSError):
        apply_cleanup(journal.root, engine, plan, recovery_dir=tmp_path / "recovery")
    assert (tmp_path / "recovery" / "recovery-ready.json").is_file()
    for sha in shas:
        assert digest((tmp_path / "recovery" / sha).read_bytes()) == sha


@pytest.mark.parametrize("failure", ["copy", "recovery-ready.json"])
def test_recovery_write_or_sync_failure_never_deletes_original(
    installation, tmp_path, monkeypatch, failure
):
    from dtvp.knowledge import offline_cleanup as module

    journal, engine = installation
    orphan = old_object(journal)
    plan = plan_cleanup(journal.root, engine, min_age_days=30)
    original = module._write_new

    def interrupted(path, value):
        if path.name == (orphan if failure == "copy" else failure):
            raise OSError("Simulated recovery write/fsync failure")
        return original(path, value)

    monkeypatch.setattr(module, "_write_new", interrupted)
    with pytest.raises(OSError):
        apply_cleanup(journal.root, engine, plan, recovery_dir=tmp_path / "recovery")
    assert journal.objects.read(orphan)


def test_postgres_maintenance_transaction_blocks_external_dml(installation):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from dtvp.knowledge.offline_cleanup import _offline

    journal, engine = installation
    if engine.dialect.name != "postgresql":
        pytest.skip("Actual PostgreSQL table-lock qualification")
    with _offline(journal.root, engine):
        with engine.connect() as other:
            other.execute(text("SET LOCAL lock_timeout = '100ms'"))
            with pytest.raises(DBAPIError):
                other.execute(insert(Workspace).values(id="blocked", name="Blocked"))
            other.rollback()
