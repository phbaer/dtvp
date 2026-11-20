"""Scheduled dumps in the backend, pruning, and the status."""

import asyncio
import os
import shutil
import zipfile

import pytest

from dtvp.backup import schedule
from dtvp.backup.__main__ import main
from dtvp.backup.export import export_dump
from dtvp.backup.restore import restore_dump
from dtvp.instance_stores import (
    resolve_instance_stores,
    try_lock_exclusive,
    unlock,
    write_instance_registry,
)
from tests.backup_instance import configure_instance, populate
from tests.dump_helpers import build_dump


@pytest.fixture
def instance(tmp_path, monkeypatch):
    configured = configure_instance(monkeypatch, tmp_path / "instance")
    populate(configured)
    schedule.reset_backup_status()
    yield configured
    schedule.reset_backup_status()


def test_interval_is_off_by_default_and_has_a_floor(monkeypatch):
    monkeypatch.delenv("DTVP_BACKUP_INTERVAL_SECONDS", raising=False)
    assert schedule.get_backup_interval_seconds() == 0
    monkeypatch.setenv("DTVP_BACKUP_INTERVAL_SECONDS", "60")
    assert schedule.get_backup_interval_seconds() == 3600
    monkeypatch.setenv("DTVP_BACKUP_INTERVAL_SECONDS", "86400")
    assert schedule.get_backup_interval_seconds() == 86400
    monkeypatch.setenv("DTVP_BACKUP_RETENTION_COUNT", "0")
    assert schedule.get_backup_retention_count() == 1


async def test_the_loop_does_nothing_when_off(monkeypatch):
    monkeypatch.setenv("DTVP_BACKUP_INTERVAL_SECONDS", "0")
    calls = []
    monkeypatch.setattr(schedule, "run_scheduled_backup_once", lambda: calls.append(1))
    await asyncio.wait_for(schedule.run_backup_loop(), timeout=1)
    assert calls == []
    assert schedule.get_backup_status()["enabled"] is False


async def test_the_loop_runs_after_each_interval(monkeypatch):
    monkeypatch.setenv("DTVP_BACKUP_INTERVAL_SECONDS", "3600")
    calls = []
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(schedule.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(schedule, "run_scheduled_backup_once", lambda: calls.append(1))
    with pytest.raises(asyncio.CancelledError):
        await schedule.run_backup_loop()
    assert sleeps == [3600, 3600, 3600]
    assert len(calls) == 2


def test_a_run_writes_verifies_and_prunes(instance, monkeypatch):
    monkeypatch.setenv("DTVP_BACKUP_RETENTION_COUNT", "2")
    monkeypatch.setenv("DTVP_BACKUP_LABEL", "nightly")
    verified = []
    original = schedule.verify_dump
    monkeypatch.setattr(schedule, "verify_dump", lambda path: verified.append(path) or original(path))
    outcomes = [schedule.run_scheduled_backup_once() for _ in range(3)]
    backups = instance.root / "backups"
    dumps = sorted(path.name for path in backups.glob("*.dtvp-dump.zip"))
    assert len(dumps) == 2 and all(name.startswith("nightly-") for name in dumps)
    assert len(list(backups.glob("*.sha256"))) == 2
    assert len(verified) == 3
    assert outcomes[2]["pruned"]
    with zipfile.ZipFile(backups / dumps[0]) as archive:
        assert b'"reason": "scheduled"' in archive.read("manifest.json")
        assert b'"created_by": "scheduler"' in archive.read("manifest.json")
    status = schedule.get_backup_status()
    assert status["last_file"] == outcomes[2]["file"]
    assert status["last_bytes"] > 0
    assert status["last_error"] is None
    assert "/" not in status["last_file"]


def test_retention_follows_created_at_not_file_times(instance, tmp_path):
    directory = tmp_path / "keep"
    directory.mkdir()
    paths = []
    for day in ("01", "02", "03"):
        def stamp(manifest, day=day):
            manifest["created_at"] = f"2026-11-{day}T00:00:00+00:00"

        path = build_dump(directory / f"dtvp-202611{day}T000000Z.dtvp-dump.zip", change_manifest=stamp)
        (directory / (path.name + ".sha256")).write_text("x")
        paths.append(path)
    # File times in the opposite order: the oldest dump looks newest.
    for index, path in enumerate(paths):
        os.utime(path, (1_000_000 - index * 1000, 1_000_000 - index * 1000))
    (directory / "dtvp-notes.dtvp-dump.zip").write_bytes(b"not a dump")
    (directory / "readme.txt").write_text("keep me")
    (directory / "other-20261101T000000Z.dtvp-dump.zip").write_bytes(
        (paths[0]).read_bytes()
    )
    removed = schedule.prune_dumps(str(directory), 2)
    assert [os.path.basename(path) for path in removed] == [paths[0].name]
    remaining = sorted(path.name for path in directory.iterdir())
    assert paths[0].name not in remaining
    assert paths[0].name + ".sha256" not in remaining
    assert {"dtvp-notes.dtvp-dump.zip", "readme.txt", "other-20261101T000000Z.dtvp-dump.zip"} <= set(remaining)


def test_prune_command(instance, capsys, tmp_path):
    directory = tmp_path / "cli"
    directory.mkdir()
    for day in ("01", "02"):
        build_dump(
            directory / f"site-202611{day}T000000Z.dtvp-dump.zip",
            change_manifest=lambda m, day=day: m.update(created_at=f"2026-11-{day}T00:00:00+00:00"),
        )
    assert main(["prune", str(directory), "--keep", "1", "--label", "site"]) == 0
    assert "site-20261101" in capsys.readouterr().out
    assert main(["prune", str(directory), "--keep", "0"]) == 2


def test_a_failure_shows_in_the_status(instance, monkeypatch):
    (instance.root / "data" / "team_mapping.json").write_bytes(b"{broken")
    assert schedule.run_scheduled_backup_once() is None
    status = schedule.get_backup_status()
    assert "E3" in status["last_error"]
    assert status["last_error_at"]
    assert "/" not in status["last_error"]
    assert "team_mapping.json" in status["last_error"]


def test_the_performance_status_has_a_backup_block(instance):
    from dtvp import main as app

    block = app.get_performance_status()["backup"]
    assert set(block) == {
        "enabled",
        "interval_seconds",
        "last_success_at",
        "last_file",
        "last_bytes",
        "last_duration_seconds",
        "last_error",
        "last_error_at",
    }


def test_a_held_export_lock_skips_the_run(instance):
    descriptor = try_lock_exclusive(resolve_instance_stores().export_lock_path)
    try:
        assert schedule.run_scheduled_backup_once() is None
    finally:
        unlock(descriptor)
    status = schedule.get_backup_status()
    assert status["last_error"] is None and status["last_success_at"] is None
    assert not (instance.root / "backups").exists() or not list(
        (instance.root / "backups").glob("*.zip")
    )


def test_the_backup_directory_is_never_part_of_a_dump(instance, tmp_path, monkeypatch):
    # Backups inside the data directory, as by default in Compose.
    monkeypatch.setenv("DTVP_BACKUP_PATH", str(instance.root / "data" / "backups"))
    first = export_dump()
    second = export_dump()
    with zipfile.ZipFile(second.path) as archive:
        names = archive.namelist()
    assert not any("backups" in name or name.endswith(".zip") for name in names)
    assert os.path.getsize(second.path) < os.path.getsize(first.path) * 1.5
    # A target whose data directory holds only backups is empty.
    target = configure_instance(monkeypatch, tmp_path / "target")
    backups = target.root / "data" / "backups"
    backups.mkdir(parents=True)
    shutil.copy(first.path, backups)
    write_instance_registry(resolve_instance_stores())
    report = restore_dump(str(backups / os.path.basename(first.path)), dry_run=True)
    assert not [finding for finding in report.refusals if finding.code == "T3"]


def test_prune_keeps_dumps_whose_label_only_starts_with_the_label(instance, tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir()

    def dump(name, day):
        path = build_dump(
            directory / name,
            change_manifest=lambda m: m.update(created_at=f"2026-11-{day}T00:00:00+00:00"),
        )
        (directory / (name + ".sha256")).write_text("x")
        return path.name

    safety = dump("dtvp-before-upgrade-20261101T000000Z.dtvp-dump.zip", "01")
    staging = dump("dtvp-staging-20261102T000000Z-with-credentials.dtvp-dump.zip", "02")
    oldest = dump("dtvp-20261103T000000Z-with-credentials-2.dtvp-dump.zip", "03")
    newer = dump("dtvp-20261104T000000Z.dtvp-dump.zip", "04")
    newest = dump("dtvp-20261105T000000Z-2.dtvp-dump.zip", "05")
    removed = schedule.prune_dumps(str(directory), 2, label="dtvp")
    assert [os.path.basename(path) for path in removed] == [oldest]
    remaining = {path.name for path in directory.iterdir()}
    assert {safety, staging, newer, newest} <= remaining
    assert {safety + ".sha256", staging + ".sha256"} <= remaining
    assert schedule.prune_dumps(str(directory), 1, label="dtvp-before-upgrade") == []
