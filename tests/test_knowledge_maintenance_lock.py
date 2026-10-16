"""Stopped-writer exclusion and runtime lease lifecycle."""

import asyncio
import gc
import subprocess
import sys
from types import SimpleNamespace

import pytest

from dtvp.knowledge.maintenance_lock import MaintenanceBusy, RuntimeLease, maintenance_exclusive


def probe(root, *, exclusive=True):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; "
            "from dtvp.knowledge.maintenance_lock import RuntimeLease; "
            "import sys; "
            "RuntimeLease(Path(sys.argv[1]), exclusive=sys.argv[2] == 'True')",
            str(root),
            str(exclusive),
        ],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


def test_shared_runtime_and_exclusive_processes(tmp_path):
    root = tmp_path / "absent" / "knowledge"
    assert not root.exists()
    with RuntimeLease(root):
        assert probe(root, exclusive=False)
        assert not probe(root)
        with pytest.raises(MaintenanceBusy):
            maintenance_exclusive(root)
    with maintenance_exclusive(root):
        assert not probe(root, exclusive=False)
        assert not probe(root)
    assert probe(root)
    assert not root.exists()
    assert (root.parent / ".knowledge-maintenance.lock").exists()


def test_close_idempotent_and_bad_lock_rejected(tmp_path):
    root = tmp_path / "knowledge"
    lease = RuntimeLease(root)
    lease.close()
    lease.close()
    (tmp_path / ".knowledge-maintenance.lock").unlink()
    (tmp_path / ".knowledge-maintenance.lock").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        RuntimeLease(root)


def settings(tmp_path):
    from dtvp.config import Settings

    return Settings(
        playground=True,
        database_url="sqlite://",
        artifact_dir=tmp_path / "artifacts",
        frontend_dir=tmp_path / "no-frontend",
    )


def test_api_unstarted_app_holds_lease_until_collected(tmp_path):
    from dtvp.main import create_app

    config = settings(tmp_path)
    app = create_app(config)
    assert not probe(config.artifact_dir / "knowledge")
    del app
    gc.collect()
    assert probe(config.artifact_dir / "knowledge")


def test_api_init_failure_releases_lease(tmp_path, monkeypatch):
    import dtvp.main as main

    config = settings(tmp_path)

    def fail(*_):
        raise RuntimeError("init failure")

    monkeypatch.setattr(main, "engine_for", fail)
    with pytest.raises(RuntimeError, match="init failure"):
        main.create_app(config)
    assert probe(config.artifact_dir / "knowledge")


@pytest.mark.parametrize("fail_startup", [True, False])
def test_api_lifespan_releases_on_failure_and_shutdown(tmp_path, monkeypatch, fail_startup):
    import dtvp.main as main

    config = settings(tmp_path)
    app = main.create_app(config)

    def migrate(*_):
        assert not probe(config.artifact_dir / "knowledge")
        if fail_startup:
            raise RuntimeError("startup failure")

    monkeypatch.setattr(main, "migrate", migrate)
    monkeypatch.setattr(main, "catch_up", lambda *_: None)
    monkeypatch.setattr(main, "seed", lambda *_: None)

    async def exercise():
        async with app.router.lifespan_context(app):
            assert not probe(config.artifact_dir / "knowledge")

    if fail_startup:
        with pytest.raises(RuntimeError, match="startup failure"):
            asyncio.run(exercise())
    else:
        asyncio.run(exercise())
        asyncio.run(exercise())
        with maintenance_exclusive(config.artifact_dir / "knowledge"):
            with pytest.raises(MaintenanceBusy):
                asyncio.run(exercise())
    assert probe(config.artifact_dir / "knowledge")


def test_api_refuses_maintenance_before_initialization(tmp_path, monkeypatch):
    import dtvp.main as main

    config = settings(tmp_path)
    monkeypatch.setattr(main, "engine_for", lambda *_: pytest.fail("initialized during maintenance"))
    with maintenance_exclusive(config.artifact_dir / "knowledge"):
        with pytest.raises(MaintenanceBusy):
            main.create_app(config)


def test_worker_run_and_once_hold_and_release(tmp_path, monkeypatch):
    import dtvp.jobs as jobs

    artifacts = SimpleNamespace(root=tmp_path)

    def claim(*_):
        assert not probe(tmp_path / "knowledge")
        raise RuntimeError("worker stopped")

    monkeypatch.setattr(jobs, "claim", claim)
    for worker in (jobs.work_once, jobs.run):
        with pytest.raises(RuntimeError, match="worker stopped"):
            worker(None, artifacts, None)
        assert probe(tmp_path / "knowledge")
        with maintenance_exclusive(tmp_path / "knowledge"):
            with pytest.raises(MaintenanceBusy):
                worker(None, artifacts, None)


@pytest.mark.parametrize("command", ["worker", "migrate", "rebuild-knowledge"])
def test_cli_excludes_maintenance_before_migration(tmp_path, monkeypatch, command):
    import dtvp.cli as cli

    config = settings(tmp_path)
    monkeypatch.setattr(sys, "argv", ["dtvp", command])
    monkeypatch.setattr(cli, "Settings", lambda: config)
    monkeypatch.setattr(cli, "engine_for", lambda *_: pytest.fail("SQL touched during maintenance"))
    with maintenance_exclusive(config.artifact_dir / "knowledge"):
        with pytest.raises(MaintenanceBusy):
            cli.main()


def test_cli_lease_covers_local_startup_failure(tmp_path, monkeypatch):
    import dtvp.cli as cli

    config = settings(tmp_path)
    monkeypatch.setattr(sys, "argv", ["dtvp", "worker"])
    monkeypatch.setattr(cli, "Settings", lambda: config)

    def fail(*_):
        assert not probe(config.artifact_dir / "knowledge")
        raise RuntimeError("migration initialization failed")

    monkeypatch.setattr(cli, "engine_for", fail)
    with pytest.raises(RuntimeError, match="migration initialization failed"):
        cli.main()
    assert probe(config.artifact_dir / "knowledge")
