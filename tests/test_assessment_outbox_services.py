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
