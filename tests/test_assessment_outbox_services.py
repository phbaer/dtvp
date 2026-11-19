import pytest

from dtvp.assessment_outbox_services import (
    AssessmentOutboxConflictError,
    AssessmentOutboxStore,
    AssessmentRevisionConflictError,
)


def _payload(state: str = "IN_TRIAGE", details: str = "Reviewing") -> dict:
    return {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "state": state,
        "details": details,
        "suppressed": False,
    }


def test_outbox_enqueue_is_persistent_and_exposes_overlay(tmp_path):
    path = str(tmp_path / "assessment_outbox.sqlite")
    store = AssessmentOutboxStore(path)

    records = store.enqueue_many([_payload()])

    assert len(records) == 1
    assert records[0]["revision"] == 1
    assert store.pending_count() == 1
    assert store.get_overlay(("project", "component", "vulnerability")) == {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "revision": 1,
        "analysisState": "IN_TRIAGE",
        "analysisDetails": "Reviewing",
        "isSuppressed": False,
        "sync_status": "pending",
        "update_id": records[0]["id"],
        "last_error": None,
        "updated_at": records[0]["updated_at"],
        "export_rejections": 0,
        "base": None,
        "remote": None,
    }

    reloaded = AssessmentOutboxStore(path)
    assert reloaded.list_pending() == records
    assert reloaded.get_revision(("project", "component", "vulnerability")) == 1


def test_outbox_coalesces_newer_finding_update(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    first = store.enqueue_many([_payload()])[0]
    second = store.enqueue_many(
        [_payload("NOT_AFFECTED", "New conclusion")],
        replace=True,
    )[0]

    assert second["id"] != first["id"]
    assert second["revision"] == 2
    assert second["created_at"] == first["created_at"]
    assert store.pending_count() == 1
    assert store.list_pending()[0]["payload"]["details"] == "New conclusion"


def test_outbox_rejects_duplicate_without_replace(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    store.enqueue_many([_payload()])

    with pytest.raises(AssessmentOutboxConflictError):
        store.enqueue_many([_payload()], replace=False)


def test_outbox_revision_compare_and_swap_is_atomic(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    store.enqueue_many([_payload()])
    key = ("project", "component", "vulnerability")

    with pytest.raises(AssessmentRevisionConflictError) as conflict:
        store.enqueue_many(
            [_payload("NOT_AFFECTED")],
            expected_revisions={key: 0},
        )

    assert conflict.value.current_revision == 1
    assert store.list_pending()[0]["revision"] == 1


def test_outbox_only_marks_matching_revision_synced(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    key = ("project", "component", "vulnerability")
    first = store.enqueue_many([_payload()])[0]
    second = store.enqueue_many([_payload("NOT_AFFECTED")])[0]

    assert store.mark_synced(key, first["revision"]) is False
    assert store.pending_count() == 1
    assert store.mark_synced(key, second["revision"]) is True
    assert store.pending_count() == 0
    assert store.get_overlay(key)["sync_status"] == "synced"


def test_outbox_retains_retry_error(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    key = ("project", "component", "vulnerability")
    record = store.enqueue_many([_payload()])[0]

    assert store.mark_failed(
        key,
        record["revision"],
        "DT unavailable",
        next_attempt_at="2026-07-30T18:00:00+00:00",
    )

    pending = store.list_pending()[0]
    assert pending["attempts"] == 1
    assert pending["last_error"] == "DT unavailable"
    assert pending["next_attempt_at"] == "2026-07-30T18:00:00+00:00"
    assert store.get_overlay(key)["sync_status"] == "error"


def test_outbox_stops_exporting_to_a_missing_finding_but_keeps_its_assessment(
    tmp_path,
):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    key = ("project", "component", "vulnerability")
    record = store.enqueue_many([_payload()])[0]

    assert store.drop_missing_finding(key, record["revision"]) is True
    assert store.pending_count() == 0
    kept = store.get_overlay(key)
    assert kept["sync_status"] == "inactive"
    assert kept["analysisDetails"] == "Reviewing"
    assert AssessmentOutboxStore(store.path).get_overlay(key) == kept


def test_outbox_does_not_drop_newer_revision_for_stale_missing_response(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    key = ("project", "component", "vulnerability")
    first = store.enqueue_many([_payload()])[0]
    second = store.enqueue_many([_payload("NOT_AFFECTED")])[0]

    assert store.drop_missing_finding(key, first["revision"]) is False
    assert store.list_pending() == [second]
    assert store.get_overlay(key)["revision"] == second["revision"]


def test_outbox_filters_future_retries_and_discards_by_id(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    record = store.enqueue_many([_payload()])[0]
    key = ("project", "component", "vulnerability")
    store.mark_failed(
        key,
        record["revision"],
        "DT unavailable",
        next_attempt_at="2999-01-01T00:00:00+00:00",
    )

    assert store.list_due() == []
    assert store.discard(record["id"]) is True
    assert store.pending_count() == 0
    assert store.get_overlay(key)["sync_status"] == "cancelled"


def test_outbox_imports_legacy_pending_updates_once(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "assessment_outbox.sqlite"))
    entries = [{"id": "legacy", "payload": _payload()}]

    assert store.import_legacy(entries) == 1
    assert store.import_legacy(entries) == 0
    assert store.pending_count() == 1


# -- joining the one local database ----------------------------------------


def test_outbox_shares_the_local_database_by_default(monkeypatch):
    from dtvp.access_token_services import get_access_tokens_path
    from dtvp.assessment_outbox_services import (
        get_assessment_outbox_path,
        get_legacy_assessment_outbox_path,
    )

    for name in (
        "DTVP_ASSESSMENT_OUTBOX_PATH",
        "DTVP_DATABASE_PATH",
        "DTVP_ACCESS_TOKENS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", "data/x")

    assert get_assessment_outbox_path("data/x") == "data/x/dtvp.sqlite3"
    assert get_access_tokens_path() == "data/x/dtvp.sqlite3"
    assert get_legacy_assessment_outbox_path("data/x") == "data/x/assessment_outbox.sqlite"

    monkeypatch.setenv("DTVP_DATABASE_PATH", "/db/main.sqlite3")
    assert get_assessment_outbox_path("data/x") == "/db/main.sqlite3"
    assert get_access_tokens_path() == "/db/main.sqlite3"

    monkeypatch.setenv("DTVP_ASSESSMENT_OUTBOX_PATH", "/elsewhere/outbox.sqlite")
    assert get_assessment_outbox_path("data/x") == "/elsewhere/outbox.sqlite"


def test_a_former_outbox_file_is_copied_once_with_its_pending_exports(tmp_path):
    key = ("project", "component", "vulnerability")
    legacy_path = str(tmp_path / "assessment_outbox.sqlite")
    legacy = AssessmentOutboxStore(legacy_path)
    legacy.import_legacy([])  # the pending_updates.json marker travels too
    pending = legacy.enqueue_many([_payload(details="Waiting for export")])
    other = {**_payload(details="Already exported"), "component_uuid": "other"}
    synced = legacy.enqueue_many([other])
    legacy.mark_synced(("project", "other", "vulnerability"), synced[0]["revision"])

    database = str(tmp_path / "dtvp.sqlite3")
    store = AssessmentOutboxStore(database, legacy_path=legacy_path)

    assert store.list_pending() == pending
    assert store.get_overlay(key)["analysisDetails"] == "Waiting for export"
    assert store.get_overlay(key)["sync_status"] == "pending"
    exported = store.get_overlay(("project", "other", "vulnerability"))
    assert exported["sync_status"] == "synced" and exported["revision"] == 1
    assert "1 pending exports" in store.legacy_import_report
    # The earlier JSON import is not repeated against the new database.
    assert store.import_legacy([{"payload": _payload(details="stale json")}]) == 0

    # Work continues in the database; the old file is never read again.
    store.mark_synced(key, pending[0]["revision"])
    legacy.enqueue_many([_payload(details="Written to the old file later")])
    reopened = AssessmentOutboxStore(database, legacy_path=legacy_path)
    assert reopened.list_pending() == []
    assert reopened.get_overlay(key)["analysisDetails"] == "Waiting for export"
    assert reopened.legacy_import_report is None


def test_missing_or_empty_former_outbox_file_is_harmless(tmp_path):
    database = str(tmp_path / "dtvp.sqlite3")
    assert AssessmentOutboxStore(
        database, legacy_path=str(tmp_path / "absent.sqlite")
    ).list_pending() == []

    empty = tmp_path / "assessment_outbox.sqlite"
    import sqlite3

    sqlite3.connect(empty).close()
    store = AssessmentOutboxStore(database, legacy_path=str(empty))
    assert store.list_pending() == []
    store.enqueue_many([_payload()])
    assert AssessmentOutboxStore(database, legacy_path=str(empty)).pending_count() == 1


# -- merging values read from the source -----------------------------------

import sqlite3  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402

KEY = ("project", "component", "vulnerability")


def _remote(state="IN_TRIAGE", details="Reviewing", suppressed=False):
    return {KEY: {"state": state, "details": details, "suppressed": suppressed}}


def _later():
    return datetime.now(UTC) + timedelta(seconds=5)


def _store(tmp_path):
    return AssessmentOutboxStore(str(tmp_path / "dtvp.sqlite3"))


def _synced(store, **payload):
    record = store.enqueue_many([_payload(**payload)], author="alice")[0]
    assert store.mark_synced(KEY, record["revision"])
    return record


BASE = {"state": "NOT_SET", "details": "", "suppressed": False}


def test_unchanged_source_leaves_a_synced_assessment_alone(tmp_path):
    store = _store(tmp_path)
    _synced(store)
    before = store.get_overlay(KEY)

    outcomes = store.reconcile_remote(
        _remote(details="  Reviewing\n"), fetched_at=_later()
    )

    assert not any(outcomes.values())
    assert store.get_overlay(KEY) == before


def test_a_local_only_change_stays_queued(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload()], bases={KEY: BASE})

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert not any(outcomes.values())
    assert store.get_overlay(KEY)["sync_status"] == "pending"
    assert len(store.list_due()) == 1


def test_pending_export_is_dropped_when_the_source_already_has_the_value(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})

    outcomes = store.reconcile_remote(_remote("IN_TRIAGE", "Mine"), fetched_at=_later())

    assert outcomes["settled"] == [KEY]
    assert store.pending_count() == 0
    assert store.get_overlay(KEY)["sync_status"] == "synced"


def test_pending_export_with_unknown_base_is_exported_as_before(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")])  # no base known

    outcomes = store.reconcile_remote(
        _remote("EXPLOITABLE", "Theirs"), fetched_at=_later()
    )

    assert not any(outcomes.values())
    assert len(store.list_due()) == 1


def test_an_assessment_the_source_lost_is_sent_again(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Carefully written")

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["requeued"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert overlay["analysisDetails"] == "Carefully written"
    assert overlay["sync_status"] == "pending"
    assert overlay["revision"] == 1
    due = store.list_due()
    assert [(d["revision"], d["payload"]["details"]) for d in due] == [
        (1, "Carefully written")
    ]
    assert store.mark_synced(KEY, 1)
    assert store.get_overlay(KEY)["sync_status"] == "synced"


def test_a_read_that_started_before_a_local_change_cannot_undo_it(tmp_path):
    store = _store(tmp_path)
    read_started = datetime.now(UTC) - timedelta(seconds=5)
    _synced(store, details="Exported while the read was in flight")

    outcomes = store.reconcile_remote(
        _remote("NOT_SET", "Older source value"), fetched_at=read_started
    )

    assert not any(outcomes.values())
    assert store.get_overlay(KEY)["analysisDetails"] == (
        "Exported while the read was in flight"
    )


def test_an_existing_database_gains_base_values_for_synced_assessments(tmp_path):
    import sqlite3

    from dtvp.assessment_outbox_services import get_assessment_outbox_migrations_path

    import shutil

    from dtvp.sqlite_migration_services import run_sqlite_migrations

    # A database as the previous release left it: the first two migrations.
    earlier = tmp_path / "earlier_migrations"
    earlier.mkdir()
    for name in ("0001_initial.sql", "0002_metadata.sql"):
        shutil.copy(get_assessment_outbox_migrations_path() / name, earlier / name)
    path = str(tmp_path / "old.sqlite")
    connection = sqlite3.connect(path)
    run_sqlite_migrations(
        connection, namespace="assessment_outbox", migrations_path=earlier
    )
    row = "INSERT INTO assessment_state VALUES (?, ?, ?, 3, ?, ?, 0, ?, NULL, NULL, ?)"
    connection.execute(row, ("p", "c1", "v", "NOT_AFFECTED", "done", "synced", "2026-01-01T00:00:00+00:00"))
    connection.execute(row, ("p", "c2", "v", "IN_TRIAGE", "wip", "pending", "2026-01-01T00:00:00+00:00"))
    connection.commit()
    connection.close()

    store = AssessmentOutboxStore(path)

    assert store.get_overlay(("p", "c1", "v"))["base"] == {
        "state": "NOT_AFFECTED",
        "details": "done",
        "suppressed": False,
    }
    assert store.get_overlay(("p", "c2", "v"))["base"] is None
    # Each earlier assessment gets one history entry, so its value is still
    # on record after the first change that replaces it.
    history = store.list_revisions(("p", "c1", "v"))
    assert [(h["revision"], h["analysisDetails"], h["origin"]) for h in history] == [
        (3, "done", "before-history")
    ]
    assert len(AssessmentOutboxStore(path).list_revisions(("p", "c1", "v"))) == 1


# -- findings the source no longer reports ---------------------------------


def test_assessments_of_vanished_findings_are_kept_as_inactive(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Kept")
    other = ("project", "still-there", "vulnerability")
    record = store.enqueue_many([{**_payload(), "component_uuid": "still-there"}])[0]
    store.mark_synced(other, record["revision"])
    waiting = ("project", "waiting", "vulnerability")
    store.enqueue_many([{**_payload(), "component_uuid": "waiting"}])
    elsewhere = ("other-project", "component", "vulnerability")
    record = store.enqueue_many([{**_payload(), "project_uuid": "other-project"}])[0]
    store.mark_synced(elsewhere, record["revision"])

    marked = store.mark_inactive("project", {other}, fetched_at=_later())

    assert marked == [KEY]
    assert store.get_overlay(KEY)["sync_status"] == "inactive"
    assert store.get_overlay(KEY)["analysisDetails"] == "Kept"
    assert store.get_overlay(other)["sync_status"] == "synced"
    assert store.get_overlay(waiting)["sync_status"] == "pending"
    assert store.get_overlay(elsewhere)["sync_status"] == "synced"
    # A read that started before the last change proves nothing.
    assert store.mark_inactive(
        "project", set(), fetched_at=datetime.now(UTC) - timedelta(minutes=1)
    ) == []


def test_a_returning_finding_gets_its_assessment_back(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Kept")
    store.mark_inactive("project", set(), fetched_at=_later())

    # The source reports the finding again, without an assessment.
    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["requeued"] == [KEY]
    assert store.get_overlay(KEY)["sync_status"] == "pending"
    assert [d["payload"]["details"] for d in store.list_due()] == ["Kept"]


def test_a_returning_finding_with_its_assessment_is_simply_active_again(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Kept")
    store.mark_inactive("project", set(), fetched_at=_later())

    outcomes = store.reconcile_remote(
        _remote("IN_TRIAGE", "Kept"), fetched_at=_later()
    )

    assert outcomes["settled"] == [KEY]
    assert store.get_overlay(KEY)["sync_status"] == "synced"
    assert store.pending_count() == 0


# -- regressions from the independent review (2026-11-17) -------------------


def test_an_empty_source_never_conflicts_with_a_pending_change(tmp_path):
    store = _store(tmp_path)
    old = {"state": "IN_TRIAGE", "details": "Old text we had stored", "suppressed": False}
    store.enqueue_many([_payload(details="Mine")], bases={KEY: old})

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert not any(outcomes.values())
    assert store.get_overlay(KEY)["sync_status"] == "pending"
    assert len(store.list_due()) == 1


def test_an_unexported_edit_survives_its_finding_vanishing_and_returning(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="A")
    edit = store.enqueue_many([_payload(details="B")])[0]
    assert store.drop_missing_finding(KEY, edit["revision"])
    assert store.get_overlay(KEY)["sync_status"] == "inactive"

    # The finding is back, still holding the value from before the edit.
    outcomes = store.reconcile_remote(_remote("IN_TRIAGE", "A"), fetched_at=_later())

    assert outcomes["requeued"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert (overlay["analysisDetails"], overlay["sync_status"]) == ("B", "pending")
    assert [d["payload"]["details"] for d in store.list_due()] == ["B"]


def test_a_discarded_edit_is_not_revived_through_inactivity(tmp_path):
    store = _store(tmp_path)
    # Queued before bases were recorded: discarding cannot revert, only cancel.
    record = store.enqueue_many([_payload(details="Discarded")])[0]
    store.discard(record["id"])

    assert store.mark_inactive("project", set(), fetched_at=_later()) == []
    store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert store.pending_count() == 0
    assert store.get_overlay(KEY)["analysisDetails"] == ""


def test_migrations_apply_schema_changes_atomically(tmp_path):
    import sqlite3

    from dtvp.sqlite_migration_services import run_sqlite_migrations

    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001_first.sql").write_text(
        "CREATE TABLE things (id INTEGER PRIMARY KEY);\n"
        "ALTER TABLE things ADD COLUMN name TEXT;\n"
        "ALTER TABLE missing ADD COLUMN broken TEXT;\n"
    )
    connection = sqlite3.connect(tmp_path / "db.sqlite")

    with pytest.raises(sqlite3.OperationalError):
        run_sqlite_migrations(connection, namespace="t", migrations_path=migrations)

    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "things" not in tables  # nothing half applied; a retry can succeed
    (migrations / "0001_first.sql").write_text(
        "CREATE TABLE things (id INTEGER PRIMARY KEY);\n"
        "ALTER TABLE things ADD COLUMN name TEXT;\n"
    )
    assert run_sqlite_migrations(
        connection, namespace="t", migrations_path=migrations
    ) == [1]


# -- discarding queued exports -----------------------------------------------


def test_discarding_an_export_returns_to_the_value_the_source_holds(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Agreed")
    change = store.enqueue_many([_payload(details="Never to be sent")], author="alice")[0]

    assert store.discard_many([change["id"], "unknown-id"], author="rita") == [KEY]

    overlay = store.get_overlay(KEY)
    assert (overlay["analysisDetails"], overlay["sync_status"]) == ("Agreed", "synced")
    assert overlay["revision"] == 3
    assert store.pending_count() == 0
    assert [(h["analysisDetails"], h["origin"], h["author"]) for h in store.list_revisions(KEY)][:2] == [
        ("Agreed", "export-discarded", "rita"),
        ("Never to be sent", "user", "alice"),
    ]
    # Nothing to merge on the next import: both sides agree.
    assert not any(
        store.reconcile_remote(_remote("IN_TRIAGE", "Agreed"), fetched_at=_later()).values()
    )
    assert AssessmentOutboxStore(store.path).get_overlay(KEY) == overlay


def test_discarding_an_export_without_a_known_base_keeps_the_text_as_cancelled(tmp_path):
    store = _store(tmp_path)
    change = store.enqueue_many([_payload(details="Queued before bases existed")])[0]
    store.mark_failed(KEY, change["revision"], "404", next_attempt_at="2999-01-01T00:00:00+00:00")

    assert store.discard(change["id"], author="rita") is True

    overlay = store.get_overlay(KEY)
    assert overlay["sync_status"] == "cancelled"
    assert overlay["analysisDetails"] == "Queued before bases existed"
    assert overlay["last_error"] is None
    assert store.pending_count() == 0 and store.list_due() == []
    assert store.discard(change["id"]) is False


# -- the local database is the record ---------------------------------------


def test_a_source_assessment_without_a_local_record_is_adopted_once(tmp_path):
    store = _store(tmp_path)

    outcomes = store.reconcile_remote(
        _remote("NOT_AFFECTED", "From Dependency-Track", True), fetched_at=_later()
    )

    assert outcomes["adopted"] == [KEY]
    record = store.get_overlay(KEY)
    assert (record["revision"], record["sync_status"]) == (0, "synced")
    assert record["analysisDetails"] == "From Dependency-Track"
    assert record["isSuppressed"] is True
    assert store.pending_count() == 0
    assert [(h["revision"], h["origin"]) for h in store.list_revisions(KEY)] == [
        (0, "import")
    ]
    # A second import of the same value does nothing.
    again = store.reconcile_remote(
        _remote("NOT_AFFECTED", "From Dependency-Track", True), fetched_at=_later()
    )
    assert not any(again.values())
    # Survives a restart.
    assert AssessmentOutboxStore(store.path).get_overlay(KEY) == record


def test_a_blank_source_assessment_creates_no_record(tmp_path):
    store = _store(tmp_path)
    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())
    assert not any(outcomes.values())
    assert store.get_overlay(KEY) is None


def test_a_view_loaded_before_the_adoption_can_still_save(tmp_path):
    store = _store(tmp_path)
    store.reconcile_remote(_remote("IN_TRIAGE", "Theirs"), fetched_at=_later())

    # The client saw no local record, that is revision 0.
    record = store.enqueue_many(
        [_payload(details="Mine")], expected_revisions={KEY: 0}, author="alice"
    )[0]

    assert record["revision"] == 1
    assert store.get_overlay(KEY)["base"] == {
        "state": "IN_TRIAGE", "details": "Theirs", "suppressed": False,
    }


def test_the_source_never_changes_a_local_assessment(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Decided in DTVP")

    outcomes = store.reconcile_remote(
        _remote("EXPLOITABLE", "Changed in Dependency-Track"), fetched_at=_later()
    )

    assert outcomes["requeued"] == [KEY]
    record = store.get_overlay(KEY)
    assert record["analysisDetails"] == "Decided in DTVP"
    assert (record["revision"], record["sync_status"]) == (1, "pending")
    # What the source holds is kept for display only.
    assert record["remote"]["details"] == "Changed in Dependency-Track"
    due = store.list_due()
    assert [item["payload"]["details"] for item in due] == ["Decided in DTVP"]


def test_an_adopted_assessment_the_source_lost_is_sent_back(tmp_path):
    store = _store(tmp_path)
    store.reconcile_remote(_remote("NOT_AFFECTED", "Assessed"), fetched_at=_later())

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["requeued"] == [KEY]
    assert [item["payload"]["details"] for item in store.list_due()] == ["Assessed"]


def test_a_pending_change_is_exported_whatever_the_source_holds(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})

    outcomes = store.reconcile_remote(
        _remote("EXPLOITABLE", "Theirs"), fetched_at=_later()
    )

    assert not any(outcomes.values())
    record = store.get_overlay(KEY)
    assert record["sync_status"] == "pending"
    assert record["remote"]["details"] == "Theirs"
    assert len(store.list_due()) == 1


def test_a_source_that_keeps_dropping_an_export_is_reported_not_hammered(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="Mine")
    delays = []

    def delay(repetition):
        delays.append(repetition)
        return 600

    def import_and_export():
        outcomes = store.reconcile_remote(
            _remote("NOT_SET", ""), fetched_at=_later(), retry_delay=delay
        )
        assert outcomes["requeued"] == [KEY]
        pending = store.list_pending()[0]
        state = store.get_overlay(KEY)
        store.mark_synced(KEY, pending["revision"])
        return pending, state

    first, state = import_and_export()
    # The first time it is simply sent again.
    assert (first["attempts"], state["sync_status"]) == (0, "pending")
    assert store.list_due() == []  # exported by the helper

    second, state = import_and_export()
    assert second["attempts"] == 1 and delays == [1]
    assert state["sync_status"] == "error"
    assert "did not keep the exported assessment" in state["last_error"]

    third, _state = import_and_export()
    assert third["attempts"] == 2 and delays == [1, 2]

    # Waiting for its retry time, it is not due.
    store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later(), retry_delay=delay)
    assert store.list_due() == []

    # Once the source holds the value, the count starts over.
    settled = store.reconcile_remote(_remote(details="Mine"), fetched_at=_later())
    assert settled["settled"] == [KEY]
    record = store.get_overlay(KEY)
    assert (record["sync_status"], record["export_rejections"]) == ("synced", 0)
    assert store.pending_count() == 0


def test_a_discarded_export_with_unknown_previous_value_takes_the_source_value(tmp_path):
    store = _store(tmp_path)
    # Queued before bases were recorded: discarding cannot revert, only cancel.
    record = store.enqueue_many([_payload(details="Discarded")])[0]
    assert store.discard(record["id"])

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["replaced"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert (overlay["analysisDetails"], overlay["sync_status"]) == ("", "synced")


def test_former_conflicts_become_ordinary_pending_exports(tmp_path):
    path = str(tmp_path / "dtvp.sqlite3")
    store = AssessmentOutboxStore(path)
    store.enqueue_many([_payload(details="Mine")])
    # Rewind to the schema before this version, with a held conflict.
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM assessment_outbox")
        connection.execute(
            "UPDATE assessment_state SET sync_status = 'diverged', update_id = NULL"
        )
        connection.execute("ALTER TABLE assessment_state DROP COLUMN export_rejections")
        connection.execute(
            "DELETE FROM schema_migrations WHERE version = 4 AND namespace = 'assessment_outbox'"
        )

    upgraded = AssessmentOutboxStore(path)

    record = upgraded.get_overlay(KEY)
    assert record["sync_status"] == "pending" and record["update_id"]
    due = upgraded.list_due()
    assert [item["payload"] for item in due] == [_payload(details="Mine")]
    assert due[0]["id"] == record["update_id"]



# -- atomic fields -----------------------------------------------------------

DTVP_TEXT = (
    "[Rescored: 2.5] [Rescored Vector: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N]"
    "\n\n[Status: Pending Review]\n\n"
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
    "[Reviewed By: rita] [Justification: CODE_NOT_REACHABLE] ---\n"
    "The parser is never called.\n\n"
    "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
    "[Date: 1794561289026] [Justification: CODE_NOT_REACHABLE] "
    "[Assigned: carol, dave] [Evidence Reviewed: yes] "
    "[Version Coverage: yes] [Ticket: EXP-1001] ---\n"
    "See global assessment. Tracked in EXP-1001."
)


def test_an_adopted_assessment_is_stored_as_atomic_fields(tmp_path):
    store = _store(tmp_path)
    assert store.get_fields(KEY) is None

    store.reconcile_remote(
        _remote("NOT_AFFECTED", DTVP_TEXT, True), fetched_at=_later()
    )

    fields = store.get_fields(KEY)
    teams = fields.pop("teams")
    assert fields == {
        "revision": 0,
        "state": "NOT_AFFECTED",
        "suppressed": True,
        "pending_review": True,
        "rescored_score": 2.5,
        "rescored_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "free_text": "",
        "form": "structured",
    }
    assert [
        (t["team"], t["state"], t["justification"], t["assessed_by"],
         t["reviewed_by"], t["assessed_at_ms"], t["assigned"], t["details"])
        for t in teams
    ] == [
        ("General", "NOT_AFFECTED", "CODE_NOT_REACHABLE", "alice", "rita", None,
         [], "The parser is never called."),
        ("Core", "NOT_AFFECTED", "CODE_NOT_REACHABLE", "bob", None,
         1794561289026, ["carol", "dave"],
         "See global assessment. Tracked in EXP-1001."),
    ]
    assert [
        (t["ticket"], t["evidence_reviewed"], t["version_coverage"]) for t in teams
    ] == [(None, None, None), ("EXP-1001", "yes", "yes")]
    # Stored in the database, not derived on reading.
    assert AssessmentOutboxStore(store.path).get_fields(KEY) == {**fields, "teams": teams}


def test_fields_follow_every_change_of_the_assessment(tmp_path):
    store = _store(tmp_path)
    store.reconcile_remote(_remote("NOT_AFFECTED", DTVP_TEXT), fetched_at=_later())

    record = store.enqueue_many([_payload("EXPLOITABLE", "Plain note")])[0]
    fields = store.get_fields(KEY)
    assert (fields["revision"], fields["state"], fields["form"]) == (1, "EXPLOITABLE", "text")
    assert fields["free_text"] == "Plain note" and fields["teams"] == []
    assert fields["pending_review"] is False and fields["rescored_score"] is None

    # Discarding the export goes back to the adopted value, fields included.
    store.discard_many([record["id"]])
    fields = store.get_fields(KEY)
    assert fields["state"] == "NOT_AFFECTED"
    assert [team["team"] for team in fields["teams"]] == ["General", "Core"]


def test_existing_assessments_get_their_fields_on_startup(tmp_path):
    path = str(tmp_path / "dtvp.sqlite3")
    store = AssessmentOutboxStore(path)
    store.enqueue_many([_payload("NOT_AFFECTED", DTVP_TEXT)])
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM assessment_team_fields")
        connection.execute("DELETE FROM assessment_fields")

    fields = AssessmentOutboxStore(path).get_fields(KEY)

    assert fields["form"] == "structured" and len(fields["teams"]) == 2


def test_an_empty_assessment_has_empty_fields(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload("NOT_SET", "")])
    fields = store.get_fields(KEY)
    assert (fields["form"], fields["free_text"], fields["teams"]) == ("empty", "", [])


def test_free_text_outside_the_team_blocks_is_kept_as_written(tmp_path):
    store = _store(tmp_path)
    note = "Agreed with the supplier on 2026-03-01.\nSee ticket EXP-7 (second line)."
    text = (
        "[Rescored: 2.5]\n\n" + note + "\n\n"
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNot used."
    )
    store.enqueue_many([_payload("NOT_AFFECTED", text)])

    fields = store.get_fields(KEY)

    assert fields["free_text"] == note
    assert fields["rescored_score"] == 2.5
    assert [team["details"] for team in fields["teams"]] == ["Not used."]
    # The text as it was saved is kept as well, in the record and its history.
    assert store.get_overlay(KEY)["analysisDetails"] == text
    assert store.list_revisions(KEY)[0]["analysisDetails"] == text


def test_reading_existing_assessments_into_fields_is_reported(tmp_path, capsys, monkeypatch):
    from dtvp import assessment_outbox_services as services
    from dtvp.startup_progress import clear_startup_progress, current_startup_progress

    path = str(tmp_path / "dtvp.sqlite3")
    store = AssessmentOutboxStore(path)
    payloads = [
        {**_payload(details=f"Note {index}"), "component_uuid": f"component-{index}"}
        for index in range(5)
    ]
    store.enqueue_many(payloads)
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM assessment_fields")
    monkeypatch.setattr(services, "FIELD_MIGRATION_REPORT_EVERY", 2)
    clear_startup_progress()
    capsys.readouterr()

    AssessmentOutboxStore(path).pending_count()

    printed = capsys.readouterr().out
    assert "[startup] Data migration: reading 5 assessments into fields" in printed
    assert "[startup] Data migration: 2 of 5 assessments read into fields" in printed
    assert "5 assessments read into fields in" in printed
    # Finished: the start page shows its own messages again.
    assert current_startup_progress() is None

    # Nothing to do the next time: nothing is reported.
    clear_startup_progress()
    AssessmentOutboxStore(path).pending_count()
    assert current_startup_progress() is None


# -- each text is stored once -------------------------------------------------


def _raw(store, sql):
    with sqlite3.connect(store.path) as connection:
        return connection.execute(sql).fetchall()


def test_an_adopted_assessment_stores_its_text_once(tmp_path):
    store = _store(tmp_path)
    store.reconcile_remote(_remote("NOT_AFFECTED", DTVP_TEXT), fetched_at=_later())

    assert _raw(store, "SELECT base_details, base_same FROM assessment_state") == [(None, 1)]
    assert _raw(
        store, "SELECT analysis_details, text_in_record FROM assessment_revisions"
    ) == [("", 1)]
    # Readers still see the text in both places.
    assert store.get_overlay(KEY)["base"]["details"] == DTVP_TEXT
    assert store.list_revisions(KEY)[0]["analysisDetails"] == DTVP_TEXT
    assert AssessmentOutboxStore(store.path).get_overlay(KEY)["base"]["details"] == DTVP_TEXT


def test_changing_the_record_keeps_the_text_it_replaces(tmp_path):
    store = _store(tmp_path)
    store.reconcile_remote(_remote("NOT_AFFECTED", DTVP_TEXT), fetched_at=_later())

    record = store.enqueue_many([_payload("EXPLOITABLE", "Changed here")], author="alice")[0]

    # The value last agreed with the source, and the adoption's history entry.
    assert store.get_overlay(KEY)["base"]["details"] == DTVP_TEXT
    history = store.list_revisions(KEY)
    assert [(h["revision"], h["analysisDetails"]) for h in history] == [
        (1, "Changed here"), (0, DTVP_TEXT),
    ]
    assert _raw(
        store, "SELECT text_in_record FROM assessment_revisions ORDER BY revision"
    ) == [(0,), (0,)]

    # Once the source holds the new value, that is stored once again.
    assert store.mark_synced(KEY, record["revision"])
    assert _raw(store, "SELECT base_details, base_same FROM assessment_state") == [(None, 1)]
    assert store.get_overlay(KEY)["base"]["details"] == "Changed here"
    # And the next change keeps it in turn.
    store.enqueue_many([_payload("NOT_AFFECTED", "Changed again")])
    assert store.get_overlay(KEY)["base"]["details"] == "Changed here"
    assert AssessmentOutboxStore(store.path).get_overlay(KEY)["base"]["details"] == "Changed here"


def test_a_differing_agreed_value_is_stored_as_before(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    assert _raw(store, "SELECT base_details, base_same FROM assessment_state") == [("", 0)]
    assert store.get_overlay(KEY)["base"] == BASE

    unknown = _store(tmp_path / "other")
    unknown.enqueue_many([_payload(details="Mine")])
    assert unknown.get_overlay(KEY)["base"] is None


def test_an_existing_database_is_reduced_to_one_copy_of_each_text(tmp_path):
    path = str(tmp_path / "dtvp.sqlite3")
    store = AssessmentOutboxStore(path)
    store.reconcile_remote(_remote("NOT_AFFECTED", DTVP_TEXT), fetched_at=_later())
    other = ("project", "component-2", "vulnerability")
    edited = {**_payload("EXPLOITABLE", "Edited"), "component_uuid": "component-2"}
    store.reconcile_remote(
        {other: {"state": "IN_TRIAGE", "details": "Adopted", "suppressed": False}},
        fetched_at=_later(),
    )
    store.enqueue_many([edited])
    before = {key: (store.get_overlay(key), store.list_revisions(key)) for key in (KEY, other)}
    # Rewind to the layout before this version: every copy written out.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER assessment_state_keep_replaced_text")
        connection.execute(
            "UPDATE assessment_state SET base_details = analysis_details WHERE base_same = 1"
        )
        connection.execute(
            """
            UPDATE assessment_revisions SET analysis_details = (
                SELECT analysis_details FROM assessment_state s
                WHERE s.project_uuid = assessment_revisions.project_uuid
                  AND s.component_uuid = assessment_revisions.component_uuid
                  AND s.vulnerability_uuid = assessment_revisions.vulnerability_uuid
            ) WHERE text_in_record = 1
            """
        )
        connection.execute("ALTER TABLE assessment_state DROP COLUMN base_same")
        connection.execute("ALTER TABLE assessment_revisions DROP COLUMN text_in_record")
        connection.execute(
            "DELETE FROM schema_migrations WHERE version = 7 AND namespace = 'assessment_outbox'"
        )

    upgraded = AssessmentOutboxStore(path)

    assert {
        key: (upgraded.get_overlay(key), upgraded.list_revisions(key)) for key in (KEY, other)
    } == before
    # The unchanged adoption is stored once; the edited record keeps the
    # texts that differ from it.
    rows = dict(_raw(upgraded, "SELECT component_uuid, base_same FROM assessment_state"))
    assert rows == {"component": 1, "component-2": 0}
    kept = _raw(
        upgraded,
        "SELECT component_uuid, revision, analysis_details, text_in_record "
        "FROM assessment_revisions ORDER BY component_uuid, revision",
    )
    assert kept == [
        ("component", 0, "", 1),
        ("component-2", 0, "Adopted", 0),
        ("component-2", 1, "Edited", 0),
    ]



def test_ticket_histories_list_every_version_of_assessments_that_named_a_ticket(tmp_path):
    store = _store(tmp_path)
    ticketed = "--- [Team: A] [State: IN_TRIAGE] [Assessed By: alice] [Ticket: VP-1] ---\nText"
    store.enqueue_many([_payload(details=ticketed)], author="alice")
    store.enqueue_many([_payload(details="Rewritten")], origin="bulk-workflow")
    store.enqueue_many([{**_payload(details="Never a ticket"), "component_uuid": "other"}])

    histories = store.list_ticket_histories()

    assert list(histories) == [KEY]
    assert [(h["origin"], h["analysisDetails"]) for h in histories[KEY]][-2:] == [
        ("user", histories[KEY][-2]["analysisDetails"]),
        ("bulk-workflow", histories[KEY][-1]["analysisDetails"]),
    ]
    assert "[Ticket: VP-1]" in histories[KEY][-2]["analysisDetails"]
    assert "Rewritten" in histories[KEY][-1]["analysisDetails"]
    assert all(h["created_at"] for h in histories[KEY])
