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


def test_findings_without_a_local_assessment_are_not_touched(tmp_path):
    store = _store(tmp_path)
    assert store.reconcile_remote(_remote(), fetched_at=_later()) == {
        "fast_forwarded": [],
        "diverged": [],
        "settled": [],
        "requeued": [],
    }
    assert store.get_overlay(KEY) is None


def test_unchanged_source_leaves_a_synced_assessment_alone(tmp_path):
    store = _store(tmp_path)
    _synced(store)
    before = store.get_overlay(KEY)

    outcomes = store.reconcile_remote(
        _remote(details="  Reviewing\n"), fetched_at=_later()
    )

    assert not any(outcomes.values())
    assert store.get_overlay(KEY) == before


def test_a_source_only_change_becomes_a_new_local_revision(tmp_path):
    store = _store(tmp_path)
    _synced(store)

    outcomes = store.reconcile_remote(
        _remote("NOT_AFFECTED", "Decided in Dependency-Track", True),
        fetched_at=_later(),
    )

    assert outcomes["fast_forwarded"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert overlay["revision"] == 2
    assert overlay["analysisState"] == "NOT_AFFECTED"
    assert overlay["analysisDetails"] == "Decided in Dependency-Track"
    assert overlay["isSuppressed"] is True
    assert overlay["sync_status"] == "synced"
    assert store.pending_count() == 0
    history = store.list_revisions(KEY)
    assert [(h["revision"], h["origin"], h["author"]) for h in history] == [
        (2, "import", None),
        (1, "user", "alice"),
    ]
    # Survives a restart.
    assert AssessmentOutboxStore(store.path).get_overlay(KEY) == overlay


def test_a_local_only_change_stays_queued(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload()], bases={KEY: BASE})

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert not any(outcomes.values())
    assert store.get_overlay(KEY)["sync_status"] == "pending"
    assert len(store.list_due()) == 1


def test_changes_on_both_sides_diverge_and_hold_the_export(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})

    outcomes = store.reconcile_remote(
        _remote("EXPLOITABLE", "Theirs"), fetched_at=_later()
    )

    assert outcomes["diverged"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert overlay["sync_status"] == "diverged"
    assert overlay["analysisDetails"] == "Mine"  # nothing overwritten
    assert overlay["revision"] == 1
    assert overlay["remote"] == {
        "state": "EXPLOITABLE",
        "details": "Theirs",
        "suppressed": False,
    }
    assert store.pending_count() == 1  # still recorded ...
    assert store.list_due() == []  # ... but not exported
    assert [s["analysisDetails"] for s in store.list_diverged()] == ["Mine"]
    reopened = AssessmentOutboxStore(store.path)
    assert reopened.get_overlay(KEY) == overlay
    assert reopened.list_due() == []


def test_a_further_local_edit_does_not_settle_a_conflict(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    store.enqueue_many([_payload(details="Mine, edited")])

    overlay = store.get_overlay(KEY)
    assert overlay["sync_status"] == "diverged"
    assert overlay["remote"]["details"] == "Theirs"
    assert store.list_due() == []


def test_resolving_for_the_local_value_exports_it(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    resolved = store.resolve(KEY, "local", author="rita")

    assert resolved["sync_status"] == "pending"
    assert resolved["remote"] is None
    assert resolved["base"]["details"] == "Theirs"
    due = store.list_due()
    assert [entry["payload"]["details"] for entry in due] == ["Mine"]
    # The source still shows its own value until the export lands: no new conflict.
    assert not any(
        store.reconcile_remote(
            _remote("EXPLOITABLE", "Theirs"), fetched_at=_later()
        ).values()
    )
    assert store.mark_synced(KEY, due[0]["revision"])
    assert store.get_overlay(KEY)["sync_status"] == "synced"


def test_resolving_for_the_source_value_adopts_it(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE}, author="alice")
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    resolved = store.resolve(KEY, "remote", author="rita")

    assert resolved["sync_status"] == "synced"
    assert resolved["analysisDetails"] == "Theirs"
    assert resolved["analysisState"] == "EXPLOITABLE"
    assert resolved["revision"] == 2
    assert store.pending_count() == 0
    # The replaced local value stays in the history.
    assert [(h["analysisDetails"], h["origin"], h["author"]) for h in store.list_revisions(KEY)] == [
        ("Theirs", "conflict-resolution", "rita"),
        ("Mine", "user", "alice"),
    ]


def test_resolution_needs_an_open_conflict(tmp_path):
    from dtvp.assessment_outbox_services import AssessmentNotDivergedError

    store = _store(tmp_path)
    with pytest.raises(AssessmentNotDivergedError):
        store.resolve(KEY, "local")
    _synced(store)
    with pytest.raises(AssessmentNotDivergedError):
        store.resolve(KEY, "remote")
    with pytest.raises(ValueError):
        store.resolve(KEY, "both")


def test_conflict_settles_itself_when_the_sides_meet(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    # Someone entered the local value in the source.
    outcomes = store.reconcile_remote(
        _remote("IN_TRIAGE", "Mine"), fetched_at=_later()
    )
    assert outcomes["settled"] == [KEY]
    assert store.get_overlay(KEY)["sync_status"] == "synced"
    assert store.pending_count() == 0


def test_conflict_reopens_the_export_when_the_source_reverts(tmp_path):
    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["settled"] == [KEY]
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


def test_a_cancelled_local_edit_gives_way_to_the_source(tmp_path):
    store = _store(tmp_path)
    # Queued before bases were recorded: discarding cannot revert, only cancel.
    record = store.enqueue_many([_payload(details="Discarded")])[0]
    assert store.discard(record["id"])

    outcomes = store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert outcomes["fast_forwarded"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert (overlay["analysisDetails"], overlay["sync_status"]) == ("", "synced")


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


def test_a_source_change_that_empties_the_details_is_adopted_not_overwritten(tmp_path):
    """Only a source with nothing at all counts as having lost the assessment."""
    store = _store(tmp_path)
    _synced(store, details="Mine")

    outcomes = store.reconcile_remote(_remote("EXPLOITABLE", ""), fetched_at=_later())

    assert outcomes["fast_forwarded"] == [KEY]
    assert store.get_overlay(KEY)["analysisState"] == "EXPLOITABLE"
    assert store.pending_count() == 0

    suppressed = store.reconcile_remote(
        _remote("NOT_SET", "", suppressed=True), fetched_at=_later()
    )
    assert suppressed["fast_forwarded"] == [KEY]


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


def test_an_unexported_edit_conflicts_if_its_returning_finding_changed(tmp_path):
    store = _store(tmp_path)
    _synced(store, details="A")
    edit = store.enqueue_many([_payload(details="B")])[0]
    store.drop_missing_finding(KEY, edit["revision"])

    outcomes = store.reconcile_remote(_remote("EXPLOITABLE", "C"), fetched_at=_later())

    assert outcomes["diverged"] == [KEY]
    overlay = store.get_overlay(KEY)
    assert (overlay["analysisDetails"], overlay["sync_status"]) == ("B", "diverged")
    assert store.pending_count() == 1 and store.list_due() == []


def test_a_discarded_edit_is_not_revived_through_inactivity(tmp_path):
    store = _store(tmp_path)
    # Queued before bases were recorded: discarding cannot revert, only cancel.
    record = store.enqueue_many([_payload(details="Discarded")])[0]
    store.discard(record["id"])

    assert store.mark_inactive("project", set(), fetched_at=_later()) == []
    store.reconcile_remote(_remote("NOT_SET", ""), fetched_at=_later())

    assert store.pending_count() == 0
    assert store.get_overlay(KEY)["analysisDetails"] == ""


def test_a_failed_write_does_not_turn_a_conflict_back_into_a_retry(tmp_path):
    store = _store(tmp_path)
    record = store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})[0]
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    store.mark_failed(KEY, record["revision"], "timeout")

    assert store.get_overlay(KEY)["sync_status"] == "diverged"
    assert store.list_due() == []
    assert AssessmentOutboxStore(store.path).get_overlay(KEY)["sync_status"] == "diverged"


def test_resolving_several_findings_is_all_or_nothing(tmp_path):
    from dtvp.assessment_outbox_services import AssessmentNotDivergedError

    store = _store(tmp_path)
    store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())
    other = ("project", "other", "vulnerability")
    store.enqueue_many([{**_payload(), "component_uuid": "other"}])

    with pytest.raises(AssessmentNotDivergedError):
        store.resolve_many([KEY, other], "remote")
    assert store.get_overlay(KEY)["sync_status"] == "diverged"
    assert store.get_overlay(KEY)["analysisDetails"] == "Mine"

    # The same finding named twice is one resolution, not a failure.
    resolved = store.resolve_many([KEY, KEY], "remote")
    assert [r["analysisDetails"] for r in resolved] == ["Theirs"]


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


def test_a_review_marker_dtvp_added_to_its_copy_is_not_a_source_change(tmp_path):
    store = _store(tmp_path)
    shown = {
        "state": "IN_TRIAGE",
        "details": "Source text\n\n[Status: Pending Review]",
        "suppressed": False,
    }
    store.enqueue_many([_payload(details="Mine")], bases={KEY: shown})

    outcomes = store.reconcile_remote(
        _remote("IN_TRIAGE", "Source text"), fetched_at=_later()
    )

    assert not any(outcomes.values())
    assert len(store.list_due()) == 1

    # A real difference in the text is still a conflict.
    changed = store.reconcile_remote(
        _remote("IN_TRIAGE", "Source text, edited"), fetched_at=_later()
    )
    assert changed["diverged"] == [KEY]


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


def test_discarding_a_conflicting_export_takes_the_last_agreed_value(tmp_path):
    store = _store(tmp_path)
    change = store.enqueue_many([_payload(details="Mine")], bases={KEY: BASE})[0]
    store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())

    store.discard_many([change["id"]])

    overlay = store.get_overlay(KEY)
    assert overlay["sync_status"] == "synced" and overlay["remote"] is None
    assert store.list_diverged() == []
    # The source's newer value arrives with the next import.
    outcomes = store.reconcile_remote(_remote("EXPLOITABLE", "Theirs"), fetched_at=_later())
    assert outcomes["fast_forwarded"] == [KEY]
