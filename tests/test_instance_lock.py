"""One DTVP process per data directory, and none while a restore is open."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dtvp import instance_stores
from dtvp.dt_cache import CacheManager
from dtvp.instance_stores import (
    InstanceBusyError,
    RestoreInProgressError,
    claim_instance,
    release_instance,
    resolve_instance_stores,
    try_lock_exclusive,
    unlock,
)


@pytest.fixture
def instance_dir(tmp_path, monkeypatch):
    directory = tmp_path / "instance" / "dt_cache"
    directory.mkdir(parents=True)
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(directory))
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_PATH", str(directory / "dtvp.sqlite3"))
    return directory


def test_second_exclusive_descriptor_is_refused(instance_dir):
    path = str(instance_dir / ".dtvp-instance.lock")
    first = try_lock_exclusive(path)
    assert first is not None
    try:
        assert try_lock_exclusive(path) is None
    finally:
        unlock(first)
    second = try_lock_exclusive(path)
    assert second is not None
    unlock(second)


def test_claim_is_counted_and_idempotent(instance_dir):
    lock_path = str(instance_dir / ".dtvp-instance.lock")
    key = claim_instance(str(instance_dir))
    assert claim_instance(str(instance_dir)) == key
    release_instance(key)
    # Still held by the first claim.
    assert try_lock_exclusive(lock_path) is None
    release_instance(key)
    descriptor = try_lock_exclusive(lock_path)
    assert descriptor is not None
    unlock(descriptor)
    # Releasing more often than claimed is harmless.
    release_instance(key)
    release_instance(None)


def test_claim_writes_the_registry(instance_dir):
    key = claim_instance(str(instance_dir))
    try:
        document = json.loads((instance_dir / ".dtvp-instance.json").read_text())
    finally:
        release_instance(key)
    assert document["pid"] == os.getpid()
    assert document["stores"] == resolve_instance_stores(str(instance_dir)).as_comparable()
    assert document["written_at"]
    assert oct((instance_dir / ".dtvp-instance.json").stat().st_mode & 0o777) == "0o600"


def test_cache_manager_cannot_open_a_locked_instance(instance_dir):
    descriptor = try_lock_exclusive(str(instance_dir / ".dtvp-instance.lock"))
    try:
        with pytest.raises(InstanceBusyError, match="another DTVP process or a restore"):
            CacheManager(base_path=str(instance_dir))
    finally:
        unlock(descriptor)
    # No database was created while the lock was held.
    assert not (instance_dir / "dtvp.sqlite3").exists()


def test_cache_manager_refuses_while_a_restore_journal_exists(instance_dir):
    journal = instance_dir / ".dtvp-restore-1234.json"
    journal.write_text("{}")
    with pytest.raises(RestoreInProgressError, match="recover --resume"):
        CacheManager(base_path=str(instance_dir))
    assert not (instance_dir / "dtvp.sqlite3").exists()
    # The failed claim released the lock.
    descriptor = try_lock_exclusive(str(instance_dir / ".dtvp-instance.lock"))
    assert descriptor is not None
    unlock(descriptor)


async def test_cache_manager_holds_the_lock_until_closed(instance_dir):
    manager = CacheManager(base_path=str(instance_dir))
    lock_path = str(instance_dir / ".dtvp-instance.lock")
    assert try_lock_exclusive(lock_path) is None
    # A second manager on the same directory in the same process shares it.
    other = CacheManager(base_path=str(instance_dir))
    await other.close()
    assert try_lock_exclusive(lock_path) is None
    await manager.close()
    descriptor = try_lock_exclusive(lock_path)
    assert descriptor is not None
    unlock(descriptor)


def test_reset_moves_the_claim(instance_dir, tmp_path, monkeypatch):
    manager = CacheManager(base_path=str(instance_dir))
    other_dir = tmp_path / "other"
    # Paths that live in the old directory (the access tokens, the SSVC cache
    # derived from DTVP_DT_CACHE_PATH) move along; otherwise their directory,
    # the old one, would rightly stay locked.
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(other_dir))
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_PATH", str(other_dir / "dtvp.sqlite3"))
    manager.reset(str(other_dir))
    try:
        descriptor = try_lock_exclusive(str(instance_dir / ".dtvp-instance.lock"))
        assert descriptor is not None
        unlock(descriptor)
        assert try_lock_exclusive(str(other_dir / ".dtvp-instance.lock")) is None
    finally:
        manager._release_instance()
        manager.store.close()


def test_claims_are_tracked_per_resolved_directory(instance_dir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(instance_dir)
    key = claim_instance(str(instance_dir))
    try:
        assert claim_instance(str(link)) == key
        release_instance(key)
    finally:
        release_instance(key)
    assert key not in instance_stores._claims


def test_claim_locks_every_record_and_cache_directory(instance_dir, tmp_path, monkeypatch):
    results = tmp_path / "shared" / "code_analysis_results.sqlite"
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", str(results))
    stores = resolve_instance_stores(str(instance_dir))
    shared_lock = str(results.parent / ".dtvp-instance.lock")
    assert stores.instance_lock_paths()[0] == stores.lock_path
    assert shared_lock in stores.instance_lock_paths()
    key = claim_instance(str(instance_dir))
    try:
        assert try_lock_exclusive(shared_lock) is None
        # A backend of another dt_cache sharing the results directory cannot
        # start; its failed claim leaves nothing held.
        other = tmp_path / "other" / "dt_cache"
        script = (
            "import sys\n"
            "from dtvp.instance_stores import InstanceBusyError, claim_instance\n"
            "try:\n"
            "    claim_instance(sys.argv[1])\n"
            "except InstanceBusyError as exc:\n"
            "    print(exc)\n"
            "    sys.exit(3)\n"
        )
        outcome = subprocess.run(
            [sys.executable, "-c", script, str(other)],
            capture_output=True,
            text=True,
            env={**os.environ, "DTVP_DT_CACHE_PATH": str(other)},
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        assert outcome.returncode == 3, outcome.stderr
        assert ".dtvp-instance.lock is held" in outcome.stdout
        descriptor = try_lock_exclusive(str(other / ".dtvp-instance.lock"))
        assert descriptor is not None
        unlock(descriptor)
    finally:
        release_instance(key)
    descriptor = try_lock_exclusive(shared_lock)
    assert descriptor is not None
    unlock(descriptor)
