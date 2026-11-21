"""Online export of an instance dump."""

import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import zipfile
from contextlib import closing

import pytest

from dtvp.backup import container, export, schemas, sqlite_source
from dtvp.backup.errors import DumpError
from dtvp.backup.export import export_dump
from dtvp.backup.manifest import sanitize_dependency_track_url
from dtvp.backup.verify import verify_dump
from dtvp.instance_stores import resolve_instance_stores, try_lock_exclusive, unlock
from tests.backup_instance import P1, P2, configure_instance, populate


@pytest.fixture
def instance(tmp_path, monkeypatch):
    configured = configure_instance(monkeypatch, tmp_path / "instance")
    configured.keys = populate(configured)
    return configured


def _members(path):
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _records(members, entity):
    data = b"".join(
        content
        for name, content in sorted(members.items())
        if name.startswith(f"records/{entity}/")
    )
    return [json.loads(line) for line in data.splitlines()]


def _key(record):
    key = record["key"]
    return (key["project_uuid"], key["component_uuid"], key["vulnerability_uuid"])


def _by_key(records):
    return {_key(record): record for record in records}


def test_every_record_and_the_manifest_validate(instance):
    result = export_dump()
    members = _members(result.path)
    manifest = json.loads(members["manifest.json"])
    assert schemas.errors("manifest", manifest) == []
    assert list(members)[-1] == "manifest.json"
    for entity in schemas.ENTITY_ORDER:
        for record in _records(members, entity):
            assert schemas.errors(entity, record) == [], (entity, record)
    assert manifest["required_features"] == []
    assert manifest["contains_credentials"] is False
    assert manifest["excluded"] == ["access_tokens"]
    assert manifest["reason"] == "manual"
    assert result.records["assessment"] == 7
    assert os.path.basename(result.path).startswith("dtvp-")
    assert result.path.endswith(".dtvp-dump.zip")
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o600
    sidecar = open(result.sidecar).read()
    assert sidecar.endswith(f"  {os.path.basename(result.path)}\n")
    assert stat.S_IMODE(os.stat(result.sidecar).st_mode) == 0o600


def test_gone_findings_and_session_versions_are_records(instance):
    members = _members(export_dump().path)
    presence = {
        record["key"]["component_uuid"]: record
        for record in _records(members, "finding_presence")
    }
    assert presence["c-old"]["gone_reason"] == "replaced"
    assert presence["c-old"]["successor_component_uuid"] == "c-new"
    assert presence["c-old"]["carry_over"] == "carried"
    assert (presence["c-old"]["acknowledged_by"], presence["c-old"]["acknowledged_at"]) == (
        "rita", "2026-11-19T09:00:00+00:00",
    )
    assert presence["c-new"]["status"] == "reported"
    # Fields of an acknowledgement only where there is one.
    assert "acknowledged_by" not in presence["c-new"]
    [read] = _records(members, "finding_read")
    assert (read["project_uuid"], read["went"], read["carried_over"]) == (
        "p-lifecycle", {"replaced": 1}, 1,
    )
    # Not a credential: dumped even without --include-access-tokens.
    [session] = _records(members, "session_version")
    assert (session["username"], session["version"]) == ("alice", 2)


def test_storage_details_are_resolved(instance):
    members = _members(export_dump().path)
    assessments = _by_key(_records(members, "assessment"))
    keys = instance.keys
    # Inactive and cancelled assessments are records too.
    statuses = {record["sync"]["status"] for record in assessments.values()}
    assert statuses == {"synced", "pending", "error", "inactive", "cancelled"}
    # base_same with base_details NULL: the base is the record's own text.
    imported = assessments[keys["imported"]]
    assert imported["sync"]["base"]["details"] == imported["value"]["details"]
    assert imported["sync"]["remote"] == {
        "state": "IN_TRIAGE",
        "details": "They say otherwise.",
        "suppressed": True,
    }
    assert imported["sync"]["export_rejections"] == 3
    # The transient row: base_same = 1 but base_details still set. The base
    # is base_details, not the new text.
    transient = assessments[keys["transient"]]
    assert transient["sync"]["base"]["details"] == "the text the base had"
    assert transient["value"]["details"] != "the text the base had"
    # text_in_record: the history entry carries the record's text.
    revisions = _records(members, "revision")
    entry = next(r for r in revisions if _key(r) == keys["imported"])
    assert entry["value"]["details"] == imported["value"]["details"]
    assert entry["origin"] == "import"
    assert any(r["origin"] == "wf-1a2b3c4d" for r in revisions)
    # Storage columns do not leak.
    raw = b"".join(members.values())
    assert b"base_same" not in raw
    assert b"text_in_record" not in raw
    outbox = _by_key(_records(members, "outbox_entry"))
    assert outbox[keys["error"]]["payload_raw"] == "{broken"
    assert outbox[keys["pending"]]["payload"]["state"] == "EXPLOITABLE"
    manifest = json.loads(members["manifest.json"])
    assert any("payload_raw" in warning for warning in manifest["warnings"])


def test_ids_and_sequences_are_kept(instance):
    with instance.sql() as connection, connection:
        connection.execute(
            "INSERT INTO assessment_revisions (project_uuid, component_uuid, "
            "vulnerability_uuid, revision, analysis_state, analysis_details, "
            "suppressed, origin, author, created_at) VALUES "
            "('x', 'y', 'z', 1, 'NOT_SET', '', 0, 'user', NULL, 't')"
        )
        connection.execute("DELETE FROM assessment_revisions WHERE project_uuid = 'x'")
        sequence = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'assessment_revisions'"
        ).fetchone()[0]
        stored = [
            row[0]
            for row in connection.execute(
                "SELECT revision_id FROM assessment_revisions ORDER BY revision_id"
            )
        ]
    members = _members(export_dump().path)
    revisions = _records(members, "revision")
    assert [record["revision_id"] for record in revisions] == stored
    audit = _records(members, "token_audit")
    assert [record["audit_id"] for record in audit] == [1, 2]
    assert audit[0]["target"] == {"project": "Imaging"}
    manifest = json.loads(members["manifest.json"])
    assert manifest["cut_point"] == {
        "sequences": {"assessment_revisions": sequence, "access_token_audit": 2},
        "event_log_high_water_mark": None,
    }
    assert sequence > max(stored)


def test_source_timestamps_and_counts_are_kept(instance):
    members = _members(export_dump().path)
    snapshots = _records(members, "source_snapshot")
    with instance.sql() as connection:
        stored = connection.execute(
            "SELECT kind, project_uuid, item_count, updated_at FROM source_snapshots "
            "ORDER BY kind, project_uuid"
        ).fetchall()
        boms = connection.execute("SELECT project_uuid, updated_at FROM source_boms").fetchall()
    assert [
        (r["kind"], r["project_uuid"], r["item_count"], r["updated_at"]) for r in snapshots
    ] == stored
    raw = next(r for r in snapshots if r["form"] == "raw")
    assert (raw["kind"], raw["project_uuid"], raw["raw"]) == ("project_vulnerabilities", P2, None)
    assert [(r["project_uuid"], r["updated_at"]) for r in _records(members, "source_bom")] == boms
    known = {r["project_uuid"] for r in _records(members, "known_project")}
    listed = {r["payload"]["uuid"] for r in _records(members, "source_project")}
    assert listed == {P1, P2}
    assert len(known - listed) == 1
    assert _records(members, "instance_metadata") == [
        {"key": "active_projects", "value": {P1: 1763280000.25}}
    ]


def test_two_dumps_of_the_same_data_are_identical(instance):
    first = _members(export_dump().path)
    second = _members(export_dump().path)
    first.pop("manifest.json")
    second.pop("manifest.json")
    assert first == second
    assert "config/team_mapping.json" in first
    assert first["config/team_mapping.json"] == b'{"lib-1": "Core"}\n'
    assert "config/user_roles.json" not in first


def test_token_digests_are_left_out_by_default(instance, monkeypatch):
    copies = []
    original = sqlite_source.snapshot_store

    def inspecting(store, tmp_dir, **kwargs):
        snapshot = original(store, tmp_dir, **kwargs)
        if snapshot.path and "access_tokens" in snapshot.namespaces:
            with closing(sqlite3.connect(snapshot.path)) as connection:
                copies.append(
                    connection.execute("SELECT COUNT(*) FROM access_tokens").fetchone()[0]
                )
            assert stat.S_IMODE(os.stat(snapshot.path).st_mode) == 0o600
        return snapshot

    monkeypatch.setattr(export, "snapshot_store", inspecting)
    result = export_dump()
    assert copies == [0]
    members = _members(result.path)
    assert _records(members, "access_token") == []
    with instance.sql() as connection:
        digest = connection.execute("SELECT token_hash FROM access_tokens").fetchone()[0]
    assert digest.encode() not in b"".join(members.values())

    copies.clear()
    with_tokens = export_dump(include_access_tokens=True)
    assert copies == [1]
    assert "-with-credentials" in os.path.basename(with_tokens.path)
    members = _members(with_tokens.path)
    manifest = json.loads(members["manifest.json"])
    assert manifest["required_features"] == ["credentials"]
    assert manifest["contains_credentials"] is True
    assert manifest["excluded"] == []
    tokens = _records(members, "access_token")
    assert [(t["token_hash"], t["scopes"]) for t in tokens] == [(digest, ["read", "write"])]


def test_without_source(instance):
    members = _members(export_dump(include_source=False).path)
    manifest = json.loads(members["manifest.json"])
    assert manifest["excluded"] == ["source", "access_tokens"]
    for entity in ("source_snapshot", "source_project", "source_finding", "source_bom", "source_analysis"):
        assert manifest["entities"][entity]["records"] == 0
    assert manifest["entities"]["known_project"]["records"] == 3


def test_parts_are_cut_by_count_and_size(instance, monkeypatch):
    monkeypatch.setattr(container, "PART_MAX_RECORDS", 3)
    members = _members(export_dump().path)
    manifest = json.loads(members["manifest.json"])
    parts = manifest["entities"]["assessment"]["parts"]
    assert [part["path"] for part in parts] == [
        "records/assessment/assessment-0001.jsonl",
        "records/assessment/assessment-0002.jsonl",
        "records/assessment/assessment-0003.jsonl",
    ]
    assert [part["records"] for part in parts] == [3, 3, 1]
    monkeypatch.setattr(container, "PART_MAX_RECORDS", 100_000)
    monkeypatch.setattr(container, "PART_MAX_BYTES", 400)
    manifest = json.loads(_members(export_dump().path)["manifest.json"])
    assert len(manifest["entities"]["assessment"]["parts"]) == 7


def test_dependency_track_url_is_sanitized(instance):
    manifest = json.loads(_members(export_dump().path)["manifest.json"])
    assert manifest["source"] == {"dependency_track_url": "https://dtrack.example.test:8443/api/"}
    assert sanitize_dependency_track_url("http://u:p@[::1]:81/x?y#z") == "http://[::1]:81/x"
    assert sanitize_dependency_track_url("not a url") is None
    assert sanitize_dependency_track_url("") is None


def test_export_to_standard_output(instance):
    sink = io.BytesIO()
    result = export_dump(out="-", stdout=sink)
    assert result.path is None and result.sidecar is None
    with zipfile.ZipFile(io.BytesIO(sink.getvalue())) as archive:
        assert archive.namelist()[-1] == "manifest.json"


def test_taken_names_get_a_suffix(instance, monkeypatch):
    class Frozen(export.datetime):
        @classmethod
        def now(cls, tz=None):
            return export.datetime(2026, 11, 20, 12, 0, 0, tzinfo=tz)

    monkeypatch.setattr(export, "datetime", Frozen)
    first = export_dump(label="nightly")
    second = export_dump(label="nightly")
    assert os.path.basename(first.path) == "nightly-20261120T120000Z.dtvp-dump.zip"
    assert os.path.basename(second.path) == "nightly-20261120T120000Z-2.dtvp-dump.zip"


def test_a_name_another_export_reserved_is_not_taken(instance, monkeypatch):
    """Two instances (or a scheduled and a manual export) writing into one
    directory with the same label in the same second get different names:
    a name is reserved exclusively before the dump is written."""

    class Frozen(export.datetime):
        @classmethod
        def now(cls, tz=None):
            return export.datetime(2026, 11, 20, 12, 0, 0, tzinfo=tz)

    monkeypatch.setattr(export, "datetime", Frozen)
    backups = instance.root / "backups"
    backups.mkdir(exist_ok=True)
    # Another export has reserved the first name and is still writing.
    reserved = backups / "nightly-20261120T120000Z.dtvp-dump.zip"
    reserved.write_bytes(b"")
    result = export_dump(label="nightly", directory=str(backups))
    assert os.path.basename(result.path) == "nightly-20261120T120000Z-2.dtvp-dump.zip"
    assert reserved.read_bytes() == b""  # left to its owner


def test_choosing_a_name_reserves_it(tmp_path):
    # Two exports choosing a name before either has written its dump.
    first = export._free_name(str(tmp_path), "nightly-20261120T120000Z")
    second = export._free_name(str(tmp_path), "nightly-20261120T120000Z")
    assert first != second
    assert os.path.exists(first) and os.path.exists(second)


def test_a_failed_export_releases_its_reserved_name(instance, monkeypatch):
    backups = instance.root / "backups"
    backups.mkdir(exist_ok=True)

    def fail(*_args, **_kwargs):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(export, "write_dump", fail)
    with pytest.raises(RuntimeError):
        export_dump(label="nightly", directory=str(backups))
    assert [name for name in os.listdir(backups) if name.endswith(".zip")] == []


def test_snapshot_directories_are_private_and_removed(instance, monkeypatch, tmp_path):
    backups = instance.root / "backups"
    backups.mkdir()
    stale = backups / (export.snapshot_dir_prefix(resolve_instance_stores()) + "stale")
    stale.mkdir()
    (stale / "main.sqlite").write_bytes(b"old")
    # Another instance's directory (or one of an older version) is not ours.
    foreign = backups / ".dtvp-dump-tmp-0123456789abcdef-live"
    foreign.mkdir()
    seen = []
    original = sqlite_source.snapshot_store

    def recording(store, tmp_dir, **kwargs):
        seen.append((tmp_dir, stat.S_IMODE(os.stat(tmp_dir).st_mode)))
        return original(store, tmp_dir, **kwargs)

    monkeypatch.setattr(export, "snapshot_store", recording)
    export_dump()
    assert not stale.exists()
    assert seen and all(mode == 0o700 for _directory, mode in seen)
    assert all(not os.path.exists(directory) for directory, _mode in seen)

    def failing(store, tmp_dir, **kwargs):
        seen.append((tmp_dir, 0))
        raise RuntimeError("disk error")

    monkeypatch.setattr(export, "snapshot_store", failing)
    with pytest.raises(RuntimeError):
        export_dump()
    assert not os.path.exists(seen[-1][0])
    assert [path.name for path in backups.iterdir() if path.name.startswith(".")] == [foreign.name]


def test_an_export_leaves_the_snapshots_of_another_instance_alone(instance, tmp_path, monkeypatch):
    first = resolve_instance_stores()
    other = configure_instance(monkeypatch, tmp_path / "other")
    populate(other)
    second = resolve_instance_stores()
    shared = tmp_path / "shared"
    real = export.open_snapshot_source
    seen = {}

    def overlapping(stores, tmp_dir, **kwargs):
        if stores is first and "other" not in seen:
            # The other instance's export runs while this one has made its
            # snapshot directory and not yet filled it.
            seen["other"] = export_dump(directory=str(shared), label="staging", stores=second)
            seen["mine"] = os.path.exists(tmp_dir)
        return real(stores, tmp_dir, **kwargs)

    monkeypatch.setattr(export, "open_snapshot_source", overlapping)
    result = export_dump(directory=str(shared), stores=first)
    assert seen["mine"] is True
    assert seen["other"].path != result.path
    assert verify_dump(result.path).errors == []
    assert export.snapshot_dir_prefix(first) != export.snapshot_dir_prefix(second)


def _writer(path, statements, stop, errors, latencies, wal):
    with closing(sqlite3.connect(path, timeout=5)) as connection:
        if wal:
            connection.execute("PRAGMA journal_mode=WAL")
        for statement in statements:
            if stop.is_set():
                break
            started = time.monotonic()
            try:
                with connection:
                    connection.execute(statement)
            except sqlite3.Error as exc:
                errors.append(exc)
            latencies.append(time.monotonic() - started)
            time.sleep(0.02)


@pytest.mark.parametrize("store", ["main", "code_analysis_results"])
def test_export_runs_while_another_connection_commits(instance, monkeypatch, store):
    if store == "main":
        path = instance.database
        statements = [
            f"INSERT INTO known_projects VALUES ('extra-{index}', 'n', 'v', 't', 't')"
            for index in range(25)
        ]
    else:
        path = instance.code_analysis_results
        with closing(sqlite3.connect(path)) as connection, connection:
            for index in range(300):
                connection.execute(
                    "INSERT INTO code_analysis_results (analysis_run_id, payload_json) "
                    "VALUES (?, ?)",
                    (f"bulk-{index:04d}", json.dumps({"analysis_run_id": f"bulk-{index:04d}", "pad": "x" * 2000})),
                )
        statements = [
            "INSERT INTO code_analysis_results (analysis_run_id, payload_json) "
            f"VALUES ('late-{index}', '{{}}')"
            for index in range(25)
        ]
        # Many small steps, so that the copy and the writer interleave.
        monkeypatch.setattr(sqlite_source, "BACKUP_PAGES_PER_STEP", 4)
    stop = threading.Event()
    errors, latencies = [], []
    thread = threading.Thread(
        target=_writer, args=(path, statements, stop, errors, latencies, store == "main")
    )
    thread.start()
    try:
        result = export_dump()
    finally:
        stop.set()
        thread.join()
    assert errors == []
    assert max(latencies) < 5
    manifest = result.manifest
    methods = {item["name"]: item["snapshot_method"] for item in manifest["stores"]}
    assert methods == {"main": "vacuum-into", "code_analysis_results": "backup-api"}
    if store == "code_analysis_results":
        assert manifest["entities"]["code_analysis_result"]["records"] >= 301


def test_snapshot_deadline(instance, monkeypatch):
    monkeypatch.setattr(sqlite_source, "BACKUP_PAGES_PER_STEP", 1)
    monkeypatch.setattr(sqlite_source, "SNAPSHOT_TIMEOUT_SECONDS", -1)
    with pytest.raises(DumpError) as raised:
        export_dump()
    assert raised.value.code == "E8"


# -- refusals E1-E7 --------------------------------------------------------------


def _refused(code, **kwargs):
    with pytest.raises(DumpError) as raised:
        export_dump(**kwargs)
    assert raised.value.code == code, raised.value
    return raised.value


def test_e1_migration_state_differs(instance):
    with instance.sql() as connection, connection:
        connection.execute(
            "UPDATE schema_migrations SET checksum = 'x' WHERE namespace = 'local_store' AND version = 2"
        )
    assert "different migration state" in _refused("E1").message


def test_e1_newer_database(instance):
    with instance.sql() as connection, connection:
        connection.execute(
            "INSERT INTO schema_migrations VALUES ('assessment_outbox', 99, 'future', 'x', 't')"
        )
    _refused("E1")


def test_e2_file_changes_between_reads(instance, monkeypatch):
    counter = iter(range(100))
    monkeypatch.setattr(export, "_read_file", lambda path: f'{{"n": {next(counter)}}}'.encode())
    monkeypatch.setattr(export, "READ_RETRY_SECONDS", 0)
    _refused("E2")


@pytest.mark.parametrize("file", ["team_mapping.json", "tmrescore_proposals.json"])
def test_e3_file_is_not_json(instance, file):
    (instance.root / "data" / file).write_bytes(b"{nope")
    _refused("E3")


def test_e3_proposals_must_be_an_object(instance):
    (instance.root / "data" / "tmrescore_proposals.json").write_bytes(b"[]")
    _refused("E3")


def test_e4_record_over_the_maximum(instance, monkeypatch):
    monkeypatch.setattr(container, "MAX_RECORD_BYTES", 300)
    error = _refused("E4")
    assert "assessment" in error.message


def test_e5_export_lock_held(instance):
    stores = instance.stores()
    descriptor = try_lock_exclusive(stores.export_lock_path)
    try:
        _refused("E5")
    finally:
        unlock(descriptor)


def test_e6_restore_journal_present(instance):
    (instance.dt_cache / ".dtvp-restore-x.json").write_text("{}")
    _refused("E6")


def test_e7_not_enough_space(instance, monkeypatch):
    monkeypatch.setattr(export, "free_bytes", lambda _path: 0)
    _refused("E7")
    assert not list((instance.root / "backups").glob("*.zip"))


def test_failed_export_leaves_no_file(instance, monkeypatch):
    monkeypatch.setattr(container, "MAX_RECORD_BYTES", 300)
    _refused("E4")
    assert list((instance.root / "backups").iterdir()) == []


def test_the_package_does_not_open_the_running_instance():
    code = (
        "import dtvp.backup.__main__, sys; "
        "assert not {'dtvp.main', 'dtvp.dt_cache', 'dtvp.boot', 'dtvp.app_wiring'} "
        "& set(sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
