import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from dtvp.runtime_coordination import ProcessLease
from dtvp.storage_health import (
    StatePath,
    backup_health,
    durable_storage_health,
    inspect_state_path,
)


def test_process_lease_rejects_a_second_runtime_and_is_owner_only(tmp_path):
    path = tmp_path / "runtime.lock"
    first = ProcessLease(str(path), "DTVP")
    second = ProcessLease(str(path), "DTVP")

    first.acquire()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert f"pid={os.getpid()}" in path.read_text(encoding="utf-8")
        with pytest.raises(RuntimeError, match="Multiple workers"):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()


def test_process_lease_refuses_a_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "runtime.lock"
    link.symlink_to(target)

    with pytest.raises(OSError):
        ProcessLease(str(link), "DTVP").acquire()
    assert target.read_text(encoding="utf-8") == "do not overwrite"


def test_process_lease_refuses_a_non_regular_file():
    with pytest.raises(RuntimeError, match="regular file"):
        ProcessLease("/dev/null", "DTVP").acquire()


def test_storage_health_checks_sqlite_json_and_free_space(tmp_path, monkeypatch):
    database = tmp_path / "state.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY)")
        connection.commit()
    document = tmp_path / "state.json"
    document.write_text('{"valid": true}', encoding="utf-8")

    monkeypatch.setenv("DTVP_STORAGE_MIN_FREE_BYTES", "1")
    health = durable_storage_health(
        [
            StatePath("database", str(database), "sqlite"),
            StatePath("document", str(document), "json"),
        ]
    )

    assert health["healthy"] is True
    assert health["stores"]["database"]["integrity"] == "ok"
    assert health["stores"]["document"]["integrity"] == "ok"

    document.write_text("not-json", encoding="utf-8")
    damaged = inspect_state_path(
        StatePath("document", str(document), "json"),
        min_free_bytes=1,
    )
    assert damaged["healthy"] is False
    assert "JSONDecodeError" in damaged["error"]


def test_storage_health_reports_low_disk_without_writing(tmp_path):
    target = StatePath("future", str(tmp_path / "future.json"), "json")
    health = inspect_state_path(target, min_free_bytes=2**63)

    assert health["exists"] is False
    assert health["healthy"] is False
    assert not (tmp_path / "future.json").exists()


def test_storage_health_rejects_wrong_path_type(tmp_path):
    expected_database = tmp_path / "database.sqlite"
    expected_database.mkdir()

    health = inspect_state_path(
        StatePath("database", str(expected_database), "sqlite"),
        min_free_bytes=1,
    )

    assert health["healthy"] is False
    assert health["error"] == "Expected a regular file"


def test_backup_health_enforces_configured_freshness(tmp_path, monkeypatch):
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    status_path = tmp_path / "backup_status.json"
    status_path.write_text(
        json.dumps({"completed_at": (now - timedelta(minutes=5)).isoformat()}),
        encoding="utf-8",
    )
    monkeypatch.setenv("DTVP_BACKUP_STATUS_PATH", str(status_path))
    monkeypatch.setenv("DTVP_BACKUP_MAX_AGE_SECONDS", "600")

    assert backup_health(now=now)["healthy"] is True
    monkeypatch.setenv("DTVP_BACKUP_MAX_AGE_SECONDS", "60")
    assert backup_health(now=now)["healthy"] is False

    status_path.write_text(
        json.dumps({"completed_at": (now + timedelta(hours=1)).isoformat()}),
        encoding="utf-8",
    )
    future = backup_health(now=now)
    assert future["healthy"] is False
    assert "future" in future["error"]


def test_stale_backup_does_not_make_the_state_stores_unavailable(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("DTVP_BACKUP_STATUS_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("DTVP_BACKUP_MAX_AGE_SECONDS", "60")
    monkeypatch.setenv("DTVP_STORAGE_MIN_FREE_BYTES", "1")

    health = durable_storage_health(
        [StatePath("future", str(tmp_path / "future.sqlite"), "sqlite")]
    )

    assert health["stores_healthy"] is True
    assert health["backup"]["healthy"] is False
    assert health["healthy"] is False
