"""Reusing verified bytes keeps publication durability barriers and corruption failures."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from dtvp.knowledge.journal import Journal
from dtvp.knowledge.service import import_inventory
from dtvp.storage import Artifacts, canonical, digest


def test_duplicate_verifies_existing_data_without_new_temp_or_file_fsync(tmp_path, monkeypatch):
    store = Artifacts(tmp_path / "artifacts")
    raw = b"unchanged captured source\n"
    sha = store.put(raw)
    original_fsync = os.fsync
    barriers = []

    def fsync(fd):
        assert stat.S_ISDIR(os.fstat(fd).st_mode), "Duplicate must not fsync a new file"
        info = os.fstat(fd)
        barriers.append((info.st_dev, info.st_ino))
        return original_fsync(fd)

    def unexpected_temp(*args, **kwargs):
        raise AssertionError("An existing verified object needs no new temporary file")

    monkeypatch.setattr("dtvp.storage.tempfile.mkstemp", unexpected_temp)
    monkeypatch.setattr("dtvp.storage.os.fsync", fsync)
    assert store.put(raw) == sha
    expected = [store.root.stat(), store.path(sha).parent.stat()]
    assert barriers == [(item.st_dev, item.st_ino) for item in expected]
    assert store.read(sha) == raw


def test_corrupt_or_unreadable_existing_target_fails_without_overwrite(tmp_path, monkeypatch):
    store = Artifacts(tmp_path / "artifacts")
    raw = b"original content"
    sha = store.put(raw)
    store.path(sha).write_bytes(b"corrupt existing bytes")
    with pytest.raises(ValueError, match="integrity"):
        store.put(raw)
    assert store.path(sha).read_bytes() == b"corrupt existing bytes"

    def denied(sha):
        raise PermissionError("Existing object is unreadable")

    monkeypatch.setattr(store, "read", denied)
    with pytest.raises(PermissionError, match="unreadable"):
        store.put(raw)
    assert store.path(sha).read_bytes() == b"corrupt existing bytes"


@pytest.mark.parametrize("barrier", ["root", "shard"])
def test_reuse_directory_barrier_failure_prevents_native_head_advance(
    tmp_path, monkeypatch, barrier
):
    journal = Journal(tmp_path / "journal")
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"bom-ref": "library", "type": "library", "name": "Library"}],
    }
    args = dict(
        project_id="project",
        version="1",
        actor_id="pipeline",
        source="pipeline",
        occurred_at="2026-10-16T10:00:00Z",
        sbom=bom,
    )
    _, receipt = import_inventory(
        journal, **args, request_id="first", expected=None, build_number=1
    )
    head = journal.head()
    raw_sha = digest(canonical(bom))
    selected = journal.objects.root if barrier == "root" else journal.objects.path(raw_sha).parent
    expected = selected.stat()
    original_fsync = os.fsync

    def fail(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
            raise OSError("Simulated directory durability failure")
        return original_fsync(fd)

    monkeypatch.setattr("dtvp.storage.os.fsync", fail)
    with pytest.raises(OSError, match="durability"):
        import_inventory(
            journal, **args, request_id="next", expected=receipt.updates[0].target, build_number=2
        )
    assert journal.head() == head
    assert journal.objects.read(raw_sha) == canonical(bom)


def test_concurrent_new_and_duplicate_writers_publish_only_exact_bytes(tmp_path):
    directory = tmp_path / "artifacts"
    raw = b"concurrent immutable object\n" * 100

    def write(_):
        store = Artifacts(directory)
        sha = store.put(raw)
        assert store.read(sha) == raw
        return sha

    with ThreadPoolExecutor(max_workers=8) as pool:
        result = list(pool.map(write, range(32)))
    assert set(result) == {digest(raw)}
    assert [path for path in directory.glob("*/*") if path.is_file()] == [
        Artifacts(directory).path(result[0])
    ]


def test_reuse_completes_barriers_when_creator_is_interrupted_after_link(tmp_path, monkeypatch):
    store = Artifacts(tmp_path / "artifacts")
    raw = b"file data must be durable before the target link"
    linked, release = Event(), Event()
    original_link = os.link

    def interrupted(source, target):
        original_link(source, target)
        linked.set()
        assert release.wait(5), "Duplicate writer did not finish while creator was paused"
        raise OSError("Creator interrupted after linking its target")

    monkeypatch.setattr("dtvp.storage.os.link", interrupted)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.put, raw)
        try:
            assert linked.wait(5)
            assert store.put(raw) == digest(raw)
            assert store.read(digest(raw)) == raw
        finally:
            release.set()
        with pytest.raises(OSError, match="Creator interrupted"):
            future.result(timeout=5)
    assert store.read(digest(raw)) == raw
