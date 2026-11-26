"""Offline restore of an instance dump, recovery, and verify --deep.

Every test works on separate temporary instances, never on the conftest
instance, whose directory this test process holds the instance lock on."""

import copy
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from dtvp.assessment_outbox_services import AssessmentOutboxStore
from dtvp.backup import restore, schemas, sqlite_target
from dtvp.backup.errors import DumpError
from dtvp.backup.export import export_dump
from dtvp.backup.restore import RestoreOptions, recover, restore_dump, verify_deep
from dtvp.instance_stores import (
    RestoreInProgressError,
    claim_instance,
    release_instance,
    resolve_instance_stores,
    try_lock_exclusive,
    unlock,
    write_instance_registry,
)
from dtvp.local_store import LocalStore
from tests.backup_instance import all_files, configure_instance, populate
from tests.dump_helpers import FIXTURE_V1, build_dump, fixture_records, pack_tree

MIGRATION_0007 = (
    Path(__file__).resolve().parent.parent
    / "dtvp/migrations/assessment_outbox/0007_store_each_text_once.sql"
)


def _members(path):
    with zipfile.ZipFile(path) as archive:
        return {
            name: archive.read(name) for name in archive.namelist() if name != "manifest.json"
        }


SESSION_MEMBER = "records/session_version/session_version-0001.jsonl"


def _assert_restored_members(restored, dumped):
    """Equal apart from session versions, which a restore raises by one."""
    restored, dumped = dict(restored), dict(dumped)
    after = [json.loads(line) for line in restored.pop(SESSION_MEMBER, b"").splitlines()]
    before = [json.loads(line) for line in dumped.pop(SESSION_MEMBER, b"").splitlines()]
    assert restored == dumped
    assert [{**r, "version": r["version"] + 1} for r in before] == after


def _manifest(path):
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read("manifest.json"))


def _fresh(monkeypatch, root):
    """An empty target on which a backend has run (the registry exists)."""
    target = configure_instance(monkeypatch, root)
    write_instance_registry(resolve_instance_stores())
    return target


@pytest.fixture
def source_dump(tmp_path, monkeypatch):
    """A dump of a populated instance, with tokens."""
    source = configure_instance(monkeypatch, tmp_path / "source")
    source.keys = populate(source)
    result = export_dump(include_access_tokens=True)
    with source.sql() as connection:
        source.fields = (
            connection.execute("SELECT * FROM assessment_fields ORDER BY 1, 2, 3").fetchall(),
            connection.execute("SELECT * FROM assessment_team_fields ORDER BY 1, 2, 3, 4").fetchall(),
        )
        source.history = connection.execute(
            "SELECT * FROM assessment_revisions ORDER BY revision_id"
        ).fetchall()
    source.dump = result.path
    return source


def _fields(instance):
    with instance.sql() as connection:
        return (
            connection.execute("SELECT * FROM assessment_fields ORDER BY 1, 2, 3").fetchall(),
            connection.execute("SELECT * FROM assessment_team_fields ORDER BY 1, 2, 3, 4").fetchall(),
        )


def test_round_trip_gives_identical_records(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    result = restore_dump(source_dump.dump)
    assert result.ok
    again = export_dump(include_access_tokens=True)
    session_member = "records/session_version/session_version-0001.jsonl"
    restored, dumped = _members(again.path), _members(source_dump.dump)
    # Session versions come back one higher (every restored user signs in
    # again); everything else is identical.
    sessions_before = [json.loads(line) for line in dumped.pop(session_member).splitlines()]
    sessions_after = [json.loads(line) for line in restored.pop(session_member).splitlines()]
    assert restored == dumped
    assert [(r["username"], r["version"] + 1) for r in sessions_before] == [
        (r["username"], r["version"]) for r in sessions_after
    ]
    assert sessions_before and all(r["version"] >= 1 for r in sessions_before)
    before, after = _manifest(source_dump.dump), _manifest(again.path)
    assert after["cut_point"] == before["cut_point"]
    assert after["config"] == before["config"]
    # Agent code evidence is record data: both entries, the withdrawn one
    # included, and its application survive the round trip.
    assert before["entities"]["code_evidence"]["records"] == 2
    assert before["entities"]["code_evidence_application"]["records"] == 1
    # What happened to findings survives as well.
    assert before["entities"]["finding_presence"]["records"] == 3
    assert before["entities"]["finding_read"]["records"] == 1
    # The history is written as dumped (the trigger never fires), including
    # the compacted storage: text_in_record and base_same are back.
    with target.sql() as connection:
        history = connection.execute(
            "SELECT * FROM assessment_revisions ORDER BY revision_id"
        ).fetchall()
        compacted = connection.execute(
            "SELECT COUNT(*) FROM assessment_revisions WHERE text_in_record = 1"
        ).fetchone()[0]
        same = connection.execute(
            "SELECT COUNT(*) FROM assessment_state WHERE base_same = 1"
        ).fetchone()[0]
    assert history == source_dump.history
    assert compacted == 1
    assert same >= 2
    assert _fields(target) == source_dump.fields
    # Absent settings stay absent; the registry is written; no journal.
    assert not (target.root / "data" / "user_roles.json").exists()
    assert (target.dt_cache / ".dtvp-instance.json").exists()
    assert not list(target.dt_cache.glob(".dtvp-restore-*"))
    assert not list((target.root / "data").rglob("*.restore-*"))


def test_a_restore_ends_restored_sessions_and_revives_no_revoked_one(
    source_dump, tmp_path, monkeypatch
):
    target = _fresh(monkeypatch, tmp_path / "target")
    assert restore_dump(source_dump.dump).ok
    tokens = target.tokens()
    # alice logged out twice before the dump (version 2): a cookie issued at
    # 0, 1 or 2 is not valid on the restored instance.
    assert tokens.session_version("alice") == 3
    # The gone findings and the last read are back as they were.
    from dtvp.assessment_outbox_services import get_assessment_outbox_path
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    lifecycle = FindingLifecycleStore(get_assessment_outbox_path(str(target.dt_cache)))
    old = lifecycle.presence("p-lifecycle")[("c-old", "v-l")]
    assert (old["status"], old["gone_reason"], old["successor_component_uuid"]) == (
        "gone", "replaced", "c-new",
    )
    assert lifecycle.last_read("p-lifecycle")["went"] == {"replaced": 1}


def test_saved_views_and_defaults_come_back(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    assert restore_dump(source_dump.dump).ok
    from dtvp.saved_view_services import SavedViewStore

    views = SavedViewStore(target.database)
    # Every view's code still resolves.
    assert {view.name for view in views.list_for("alice", "Imaging Suite")} == {"My open", "Release 7.1"}
    defaults = views.defaults_for("alice", "ANALYST", "Imaging Suite")
    assert defaults["effective"]["source"] == "user"
    assert defaults["effective"]["query"] == "cutoff=2026-11-01&lifecycle=OPEN"
    assert views.defaults_for("carl", "ANALYST", "Other")["effective"]["name"] == "Release 7.1"


def test_a_dump_of_format_minor_0_restores_without_saved_views(tmp_path, monkeypatch):
    # The frozen fixture predates saved views: it does not list them.
    manifest = json.loads((FIXTURE_V1 / "manifest.json").read_text())
    assert manifest["format_minor"] == 0
    assert "saved_view" not in manifest["entities"]
    dump = build_dump(tmp_path / "minor0.zip")
    target = _fresh(monkeypatch, tmp_path / "target")
    assert restore_dump(dump, options=RestoreOptions(accept_dt_url_change=True)).ok
    with target.sql() as connection:
        assert connection.execute("SELECT COUNT(*) FROM saved_views").fetchone()[0] == 0


def test_a_new_revision_gets_an_id_above_the_sequence(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    restore_dump(source_dump.dump)
    sequence = _manifest(source_dump.dump)["cut_point"]["sequences"]["assessment_revisions"]
    outbox = target.outbox()
    key = source_dump.keys["synced"]
    revision = outbox.get_revision(key)
    outbox.enqueue_many(
        [{"project_uuid": key[0], "component_uuid": key[1], "vulnerability_uuid": key[2],
          "state": "RESOLVED", "details": "new", "suppressed": False}],
        expected_revisions={key: revision},
    )
    with target.sql() as connection:
        newest = connection.execute("SELECT MAX(revision_id) FROM assessment_revisions").fetchone()[0]
    assert newest == sequence + 1


def test_backend_style_open_changes_no_restored_data(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    # Legacy inputs left in place must not be imported again.
    (target.dt_cache / "projects.json").write_text(json.dumps([{"uuid": "legacy", "name": "L"}]))
    (target.dt_cache / "pending_updates.json").write_text(
        json.dumps([{"payload": {"project_uuid": "a", "component_uuid": "b",
                                  "vulnerability_uuid": "c", "state": "EXPLOITABLE"}}])
    )
    with closing(sqlite3.connect(target.dt_cache / "assessment_outbox.sqlite")) as legacy:
        legacy.execute("CREATE TABLE assessment_state (x)")
    (target.root / "data" / "code_analysis_results.json").write_text(
        json.dumps({"records": [{"analysis_run_id": "legacy-run"}]})
    )
    restore_dump(source_dump.dump)
    first = _members(export_dump(include_access_tokens=True).path)
    store = LocalStore(target.database)
    assert store.import_legacy_json_cache(str(target.dt_cache)) is None
    store.close()
    outbox = target.outbox()
    outbox._ensure_initialized()
    assert outbox.import_legacy([{"payload": {"project_uuid": "a", "component_uuid": "b",
                                              "vulnerability_uuid": "c"}}]) == 0
    results = target.code_analysis()
    with results._lock:
        results._ensure_loaded()
    assert _members(export_dump(include_access_tokens=True).path) == first


def test_replace_moves_records_settings_and_caches_aside(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    populate(target)
    write_instance_registry(resolve_instance_stores())
    data = target.root / "data"
    caches = [
        data / "grouped_vuln_summary_index.sqlite",
        target.dt_cache / "ssvc_enrichment.sqlite3",
        data / "code_analysis_results.sqlite.diagnostics.sqlite",
    ]
    for cache in caches:
        cache.write_bytes(b"cache")
    (data / "user_roles.json").write_bytes(b'{"x": "REVIEWER"}')
    with pytest.raises(DumpError) as raised:
        restore_dump(source_dump.dump)
    assert raised.value.code == "T3"
    result = restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    run_id = result.run_id
    assert run_id.startswith(result.dump_id + "-")
    for cache in caches:
        assert not cache.exists()
        assert Path(f"{cache}.pre-restore-{run_id}").read_bytes() == b"cache"
    # Absent in the dump: the target's file is moved aside, not kept.
    assert not (data / "user_roles.json").exists()
    assert (data / f"user_roles.json.pre-restore-{run_id}").exists()
    assert Path(f"{target.database}.pre-restore-{run_id}").exists()
    _assert_restored_members(_members(export_dump(include_access_tokens=True).path), _members(source_dump.dump))


def _run_ids(monkeypatch, *names):
    """Give successive restore runs fixed names (a real run is named by its
    start second)."""
    queue = list(names)
    monkeypatch.setattr(restore, "restore_run_id", lambda dump_id, _started=None: f"{dump_id}-{queue.pop(0)}")


def _tables(path):
    with closing(sqlite3.connect(path)) as connection:
        return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_restoring_the_same_dump_again_keeps_the_current_data(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    populate(target)
    write_instance_registry(resolve_instance_stores())
    _run_ids(monkeypatch, "first", "second")
    first = restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    # A week of work in the restored instance.
    with target.sql() as connection, connection:
        connection.execute("CREATE TABLE week_of_work (x)")
    second = restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    assert first.dump_id == second.dump_id and first.run_id != second.run_id
    assert "week_of_work" in _tables(f"{target.database}.pre-restore-{second.run_id}")
    assert "week_of_work" not in _tables(f"{target.database}.pre-restore-{first.run_id}")
    assert "week_of_work" not in _tables(target.database)


def test_t9_files_of_an_earlier_restore_in_the_way(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    populate(target)
    write_instance_registry(resolve_instance_stores())
    _run_ids(monkeypatch, "same", "same", "same")
    restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    with target.sql() as connection, connection:
        connection.execute("CREATE TABLE week_of_work (x)")
    before = _snapshot(target.root)
    error = _refused("T9", source_dump.dump, replace=True)
    assert f"dtvp.sqlite3.pre-restore-{source_dump_id(source_dump)}-same" in error.message
    assert _snapshot(target.root) == before
    report = restore_dump(source_dump.dump, options=RestoreOptions(replace=True), dry_run=True)
    assert [finding.code for finding in report.refusals] == ["T9"]


def source_dump_id(source):
    return _manifest(source.dump)["dump_id"]


def test_moved_aside_side_files_stay_with_their_database(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    populate(target)
    write_instance_registry(resolve_instance_stores())
    # A backend killed after a commit that is only in the WAL.
    script = (
        "import os, sqlite3, sys\n"
        "c = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
        "c.execute('PRAGMA journal_mode=WAL')\n"
        "c.execute('PRAGMA wal_autocheckpoint=0')\n"
        "c.execute('CREATE TABLE only_in_wal (x)')\n"
        "c.execute(\"INSERT INTO only_in_wal VALUES ('committed')\")\n"
        "os._exit(0)\n"
    )
    subprocess.run([sys.executable, "-c", script, target.database], check=True)
    assert Path(target.database + "-wal").stat().st_size > 0
    result = restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    aside = f"{target.database}.pre-restore-{result.run_id}"
    assert Path(aside + "-wal").exists()
    assert not Path(target.database + "-wal").exists()
    with closing(sqlite3.connect(aside)) as connection:
        assert connection.execute("SELECT x FROM only_in_wal").fetchall() == [("committed",)]


# -- the frozen fixture, upcasters, verify --deep -------------------------------------


def test_the_frozen_fixture_restores_and_round_trips(tmp_path, monkeypatch):
    fixture = pack_tree(FIXTURE_V1, tmp_path / "fixture.zip")
    _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_DT_API_URL", "https://dtrack.example.test/api")
    result = restore_dump(str(fixture))
    assert result.ok
    again = export_dump(include_access_tokens=True)
    _assert_restored_members(_members(again.path), _members(fixture))
    assert _manifest(again.path)["cut_point"] == _manifest(fixture)["cut_point"]


def test_upcaster_chain_on_restore(tmp_path, monkeypatch):
    from dtvp.backup import upcasters

    def upcast(record):
        record = dict(record)
        record["project_uuid"] = record.pop("uuid")
        return record

    monkeypatch.setitem(upcasters.UPCASTERS, ("known_project", 0), (1, upcast))
    old = []
    for record in fixture_records("known_project"):
        record = dict(record)
        record["uuid"] = record.pop("project_uuid")
        old.append(record)

    def version_0(manifest):
        manifest["entities"]["known_project"]["schema"] = "dtvp.dump.known_project/0"

    dump = build_dump(tmp_path / "old.zip", records={"known_project": old}, change_manifest=version_0)
    target = _fresh(monkeypatch, tmp_path / "target")
    restore_dump(str(dump), options=RestoreOptions(accept_dt_url_change=True))
    with target.sql() as connection:
        assert connection.execute("SELECT COUNT(*) FROM known_projects").fetchone()[0] == 2

    def version_9(manifest):
        manifest["entities"]["known_project"]["schema"] = "dtvp.dump.known_project/9"

    newer = build_dump(tmp_path / "new.zip", change_manifest=version_9)
    with pytest.raises(DumpError) as raised:
        verify_deep(str(newer))
    assert raised.value.code == "F7"
    monkeypatch.delitem(upcasters.UPCASTERS, ("known_project", 0))
    with pytest.raises(DumpError) as raised:
        verify_deep(str(dump))
    assert raised.value.code == "F8"


def test_verify_deep(tmp_path, monkeypatch):
    fixture = pack_tree(FIXTURE_V1, tmp_path / "fixture.zip")
    outcome = verify_deep(str(fixture))
    assert outcome["records"]["assessment"] == 5

    original = sqlite_target.SqliteDumpTarget._write_known_project
    monkeypatch.setattr(
        sqlite_target.SqliteDumpTarget,
        "_write_known_project",
        lambda self, record: None if record["name"] == "Retired Viewer" else original(self, record),
    )
    with pytest.raises(DumpError) as raised:
        verify_deep(str(fixture))
    assert raised.value.code == "P2"


def test_the_compaction_statements_are_those_of_migration_0007():
    sql = MIGRATION_0007.read_text()
    for statement in sqlite_target.COMPACTION_SQL:
        assert statement.rstrip(";") in sql
        assert "SET analysis_details" not in statement.split("assessment_revisions")[0]


# -- target rules T1-T8 -------------------------------------------------------------


def _refused(code, path, **options):
    with pytest.raises(DumpError) as raised:
        restore_dump(str(path), options=RestoreOptions(**options))
    assert raised.value.code == code, raised.value
    return raised.value


def test_t1_backend_running(source_dump, tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")
    stores = resolve_instance_stores()
    descriptor = try_lock_exclusive(stores.lock_path)
    try:
        _refused("T1", source_dump.dump)
        # The dry run takes no lock and reports it.
        report = restore_dump(source_dump.dump, dry_run=True)
        assert report.lock_held is True
    finally:
        unlock(descriptor)
    descriptor = try_lock_exclusive(stores.export_lock_path)
    try:
        _refused("T1", source_dump.dump)
    finally:
        unlock(descriptor)


def test_t2_journal_exists(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    (target.dt_cache / ".dtvp-restore-x.json").write_text("{}")
    _refused("T2", source_dump.dump)


def test_t4_dependency_track_differs(source_dump, tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_DT_API_URL", "https://other.example.test/api")
    _refused("T4", source_dump.dump)
    assert restore_dump(source_dump.dump, options=RestoreOptions(accept_dt_url_change=True)).ok


def test_t5_pruning(source_dump, tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS", "1")
    fixture = build_dump(
        tmp_path / "two.zip",
        records={
            "code_analysis_result": fixture_records("code_analysis_result")
            + [{"analysis_run_id": "run-0002", "payload": {"analysis_run_id": "run-0002"}}]
        },
    )
    monkeypatch.setenv("DTVP_DT_API_URL", "https://dtrack.example.test/api")
    _refused("T5", fixture)
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS", "10")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS", "1")
    _refused("T5", fixture)
    assert restore_dump(str(fixture), options=RestoreOptions(accept_pruning=True)).ok


def test_t6_paths_differ(source_dump, tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("USER_ROLES_PATH", str(target.root / "elsewhere.json"))
    error = _refused("T6", source_dump.dump)
    assert "config:user_roles" in error.message
    assert restore_dump(source_dump.dump, options=RestoreOptions(accept_path_change=True)).ok


def test_t7_no_backend_ran_here(source_dump, tmp_path, monkeypatch):
    configure_instance(monkeypatch, tmp_path / "target")
    _refused("T7", source_dump.dump)
    result = restore_dump(source_dump.dump, options=RestoreOptions(new_instance=True))
    assert any(warning.code == "T7" for warning in result.warnings)


def test_t8_no_room_for_the_staged_copies(source_dump, tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")

    class Usage:
        free = 0

    monkeypatch.setattr(restore.shutil, "disk_usage", lambda _path: Usage)
    _refused("T8", source_dump.dump)


def test_dry_run_reports_and_changes_nothing(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_DT_API_URL", "https://other.example.test/")
    before = all_files(target.root)
    report = restore_dump(source_dump.dump, dry_run=True)
    assert all_files(target.root) == before
    assert {finding.code for finding in report.refusals} == {"T4", "T7"}
    assert report.lock_held is False
    assert any(
        action["target"] == target.database and action["staged"] for action in report.actions
    )
    assert all(os.path.isabs(action["target"]) for action in report.actions)


# -- verification through restore: S, R, W and F6 ---------------------------------------


def test_restore_refuses_what_verify_refuses(tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_DT_API_URL", "https://dtrack.example.test/api")
    cases = {
        "S1": {"known_project": [{"project_uuid": 1}]},
        "R1": {"known_project": fixture_records("known_project") * 2},
        "R3": {"assessment": fixture_records("assessment")[:-1]},
        "R4": {"code_analysis_result": []},
    }
    for code, records in cases.items():
        dump = build_dump(tmp_path / f"{code}.zip", records=records)
        _refused(code, dump)
    assert not list((tmp_path / "target").rglob("*.restore-*"))
    # Warnings do not stop a restore.
    outbox = copy.deepcopy(fixture_records("outbox_entry"))
    outbox[0]["update_id"] = "differs"
    result = restore_dump(str(build_dump(tmp_path / "w.zip", records={"outbox_entry": outbox})))
    assert {"W1", "W8"} <= {warning.code for warning in result.warnings}


def test_f6_newer_minor_needs_allow_unknown(tmp_path, monkeypatch):
    target = _fresh(monkeypatch, tmp_path / "target")
    monkeypatch.setenv("DTVP_DT_API_URL", "https://dtrack.example.test/api")
    records = copy.deepcopy(fixture_records("known_project"))
    records[0]["future_field"] = 1

    def newer(manifest):
        manifest["format_minor"] = schemas.FORMAT_MINOR + 1

    dump = build_dump(tmp_path / "newer.zip", records={"known_project": records}, change_manifest=newer)
    _refused("F6", dump)
    result = restore_dump(str(dump), options=RestoreOptions(allow_unknown=True))
    assert any(warning.code == "F6" for warning in result.warnings)
    with target.sql() as connection:
        assert connection.execute("SELECT COUNT(*) FROM known_projects").fetchone()[0] == 2


# -- staging rules P1-P3 ----------------------------------------------------------------


def _untouched(target, before):
    assert all_files(target.root) == before


@pytest.mark.parametrize("rule", ["P1", "P2", "P3"])
def test_staging_failures_leave_the_target_untouched(source_dump, tmp_path, monkeypatch, rule):
    target = _fresh(monkeypatch, tmp_path / "target")
    stores = resolve_instance_stores()
    for path in (*stores.instance_lock_paths(), stores.export_lock_path):
        Path(path).touch()
    before = all_files(target.root)
    if rule == "P1":
        monkeypatch.setattr(sqlite_target, "integrity_problems", lambda _c: ["page 3: damaged"])
    elif rule == "P2":
        monkeypatch.setattr(sqlite_target.SqliteDumpTarget, "_write_token_audit", lambda self, r: None)
    else:
        original_finish = sqlite_target.SqliteDumpTarget.finish

        def finish(self):
            for path in self.staged.values():
                Path(path + "-wal").write_bytes(b"")
            # The check runs after the connections are closed.
            return original_finish(self)

        monkeypatch.setattr(sqlite_target.SqliteDumpTarget, "finish", finish)
    with pytest.raises(DumpError) as raised:
        restore_dump(source_dump.dump)
    assert raised.value.code == rule
    _untouched(target, before)


# -- crashes during the swap ------------------------------------------------------------


def _crash_after(monkeypatch, count):
    calls = {"n": 0}
    real = restore._replace

    def crashing(source, target):
        if calls["n"] >= count:
            raise OSError("simulated crash")
        calls["n"] += 1
        real(source, target)

    monkeypatch.setattr(restore, "_replace", crashing)
    return calls


def _snapshot(root):
    return {
        name: data
        for name, data in all_files(root).items()
        if ".restore-" not in name and not name.endswith((".lock",))
    }


def test_crash_at_every_rename_then_resume_or_abort(source_dump, tmp_path, monkeypatch):
    # Count the renames of a complete swap over a populated target.
    probe = configure_instance(monkeypatch, tmp_path / "probe")
    populate(probe)
    (probe.root / "data" / "grouped_vuln_summary_index.sqlite").write_bytes(b"c")
    write_instance_registry(resolve_instance_stores())
    calls = _crash_after(monkeypatch, 10**6)
    restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    total = calls["n"]
    assert total >= 8
    expected = _members(source_dump.dump)

    for count in range(total):
        for mode in ("resume", "abort"):
            root = tmp_path / f"t{count}{mode}"
            target = configure_instance(monkeypatch, root)
            populate(target)
            (root / "data" / "grouped_vuln_summary_index.sqlite").write_bytes(b"c")
            write_instance_registry(resolve_instance_stores())
            original = _snapshot(root)
            _crash_after(monkeypatch, count)
            with pytest.raises(OSError, match="simulated crash"):
                restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
            monkeypatch.setattr(restore, "_replace", os.replace)
            assert list(target.dt_cache.glob(".dtvp-restore-*.json"))
            with pytest.raises(RestoreInProgressError):
                claim_instance(str(target.dt_cache))
            recover(mode)
            assert not list(target.dt_cache.glob(".dtvp-restore-*.json"))
            if mode == "resume":
                _assert_restored_members(_members(export_dump(include_access_tokens=True).path), expected)
            else:
                current = _snapshot(root)
                assert current == original, sorted(
                    set(current) ^ set(original)
                    | {k for k in current if current.get(k) != original.get(k)}
                )
                key = claim_instance(str(target.dt_cache))
                release_instance(key)


def test_recover_without_a_journal(tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path / "target")
    with pytest.raises(DumpError) as raised:
        recover("resume")
    assert raised.value.code == "T2"


def test_recover_stops_on_files_changed_outside(source_dump, tmp_path, monkeypatch):
    target = configure_instance(monkeypatch, tmp_path / "target")
    populate(target)
    write_instance_registry(resolve_instance_stores())
    _crash_after(monkeypatch, 3)
    with pytest.raises(OSError):
        restore_dump(source_dump.dump, options=RestoreOptions(replace=True))
    monkeypatch.setattr(restore, "_replace", os.replace)
    journal = json.loads(next(target.dt_cache.glob(".dtvp-restore-*.json")).read_text())
    database = next(a for a in journal["actions"] if a["kind"] == "database" and a["staged"])
    # Something outside DTVP put a file where the moved original was.
    Path(database["target"]).write_bytes(b"intruder")
    if not Path(database["aside"]).exists():
        Path(database["aside"]).write_bytes(b"x")
    if not Path(database["staged"]).exists():
        Path(database["staged"]).write_bytes(b"y")
    with pytest.raises(DumpError, match="changed outside DTVP"):
        recover("abort")


def test_the_store_resolves_the_base_like_the_dump():
    row = {
        "base_state": "IN_TRIAGE",
        "base_details": "old",
        "base_suppressed": 0,
        "analysis_details": "new",
    }
    assert AssessmentOutboxStore.resolve_base_value(row)["details"] == "old"
    assert AssessmentOutboxStore.resolve_base_value({**row, "base_details": None})["details"] == "new"
    assert AssessmentOutboxStore.resolve_base_value({**row, "base_state": None}) is None


def test_a_restore_cannot_swap_files_of_a_backend_on_another_dt_cache(tmp_path, monkeypatch):
    # Production runs; its results and proposals resolve from the shared
    # working directory, its dt_cache is its own.
    production = configure_instance(monkeypatch, tmp_path / "production")
    populate(production)
    dump = export_dump(include_access_tokens=True).path
    key = claim_instance(str(production.dt_cache))
    try:
        results = Path(production.code_analysis_results)
        inode = results.stat().st_ino
        # A practice restore with a scratch dt_cache and scratch settings
        # paths, but the results and proposals paths left at their defaults.
        scratch = tmp_path / "scratch"
        monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(scratch / "dt_cache"))
        for variable in ("TEAM_MAPPING_PATH", "TEAM_GROUPS_PATH", "USER_ROLES_PATH",
                         "RESCORE_RULES_PATH", "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"):
            monkeypatch.setenv(variable, str(scratch / f"{variable.lower()}.json"))
        for replace in (False, True):
            error = _refused("T1", dump, new_instance=True, replace=replace)
            assert str(production.root / "data" / ".dtvp-instance.lock") in error.message
        assert restore_dump(dump, options=RestoreOptions(new_instance=True), dry_run=True).lock_held
        assert results.stat().st_ino == inode
        assert not list((production.root / "data").glob("*.pre-restore-*"))
    finally:
        release_instance(key)
