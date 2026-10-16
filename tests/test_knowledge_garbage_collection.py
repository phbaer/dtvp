"""Global orphan diagnostics never authorize physical deletion."""

import os
from datetime import UTC, datetime, timedelta

import pytest

from dtvp.knowledge.garbage_collection import preview_unreferenced_objects
from dtvp.knowledge.journal import SECTIONS, CorruptJournal, Journal, Ref, Update
from dtvp.storage import digest
from tests.test_knowledge_journal import publish, state


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def old(journal, sha, days=30):
    when = (datetime.now(UTC) - timedelta(days=days)).timestamp()
    os.utime(journal.objects.path(sha), (when, when))


def test_empty_default_has_no_policy_or_execution(journal):
    orphan = journal.objects.put(b"unpublished")
    old(journal, orphan)
    report = preview_unreferenced_objects(journal)
    assert report["items"][0]["sha256"] == orphan
    assert not report["items"][0]["age_matches_policy"]
    assert not report["items"][0]["eligible_for_deletion"]
    assert not report["execution_supported"]
    assert not report["operational_references_complete"]
    assert report["statistics"]["eligible_for_deletion"] == 0
    assert len(report["blockers"]) == 3
    assert journal.objects.read(orphan) == b"unpublished"


def test_all_publications_ancestry_sources_and_opaque_record_links_protected(journal):
    original = journal.objects.put(b"original source bytes")
    issued = journal.objects.put(b"frozen issued bytes")
    nested = journal.store({"files": {"issued": {"sha256": issued}}})
    sections = {key: {} for key in SECTIONS}
    sections["history"]["opaque-reference"] = {"bucket": nested}
    parent = journal.snapshot(
        project_id="product",
        version="7.1.1",
        actor_id="fixture",
        reason="parent",
        sections=sections,
        artifacts=[original],
    )
    first = state(journal, parent=parent)
    first_receipt = publish(journal, first)
    latest = state(journal, parent=first)
    publish(journal, latest, expected=first, request_id="replace")
    orphan = journal.objects.put(b"unused crash residue")
    old(journal, orphan)
    report = preview_unreferenced_objects(journal, min_age_days=7)
    assert [item["sha256"] for item in report["items"]] == [orphan]
    assert report["items"][0]["age_matches_policy"]
    assert report["statistics"]["eligible_for_deletion"] == 0
    assert journal.receipt("first", first_receipt[1].fingerprint) == first_receipt


def test_supplemental_job_root_preserves_transitive_capture_but_not_completeness(journal):
    raw = journal.objects.put(b"pending provider page")
    capture = journal.store({"queries": [{"pages": [{"sha256": raw}]}]})
    assert preview_unreferenced_objects(journal)["total"] == 2
    report = preview_unreferenced_objects(journal, operational_roots=[capture])
    assert report["total"] == 0
    assert report["statistics"]["protected_objects"] == 2
    assert not report["operational_references_complete"]
    assert not report["execution_supported"]


def test_global_refs_tags_and_issued_evidence_remain_readable_without_writes(journal):
    first = state(journal)
    publish(journal, first)
    for project_id, kind in (("product", "tag"), ("other-product", "evidence")):
        raw = journal.objects.put((project_id + kind).encode())
        revision = journal.snapshot(
            project_id=project_id,
            version="released-or-issued",
            actor_id="fixture",
            reason="retained publication",
            sections={key: {} for key in SECTIONS},
            artifacts=[raw],
        )
        journal.publish(
            request_id=project_id + kind,
            fingerprint=digest((project_id + kind).encode()),
            updates=[
                Update(
                    ref=Ref(project_id=project_id, name="retained", kind=kind),
                    expected=None,
                    target=revision,
                )
            ],
        )
    before = {
        path.relative_to(journal.root): path.read_bytes()
        for path in journal.root.rglob("*")
        if path.is_file()
    }
    assert preview_unreferenced_objects(journal, min_age_days=1)["total"] == 0
    assert before == {
        path.relative_to(journal.root): path.read_bytes()
        for path in journal.root.rglob("*")
        if path.is_file()
    }


def test_snapshot_digest_pins_global_history_and_storage_not_pagination(journal):
    for value in (b"orphan1", b"orphan2"):
        journal.objects.put(value)
    now = datetime.now(UTC)
    first = preview_unreferenced_objects(journal, now=now, limit=1)
    second = preview_unreferenced_objects(journal, now=now, offset=1, limit=1)
    assert first["plan_hash"] == second["plan_hash"]
    assert first["next_offset"] == 1 and second["next_offset"] is None
    assert first["items"] != second["items"]
    assert (
        preview_unreferenced_objects(journal, now=now, min_age_days=7)["plan_hash"]
        != first["plan_hash"]
    )
    publish(journal, state(journal))
    assert preview_unreferenced_objects(journal, now=now)["plan_hash"] != first["plan_hash"]


@pytest.mark.parametrize("damage", ["artifact", "record", "orphan", "missing_hint"])
def test_missing_or_corrupt_objects_fail_closed(journal, damage):
    artifact = journal.objects.put(b"retained artifact")
    sections = {key: {} for key in SECTIONS}
    sections["inventory"]["component"] = {"name": "fixture"}
    revision = journal.snapshot(
        project_id="product",
        version="7.1.1",
        actor_id="fixture",
        reason="seed",
        sections=sections,
        artifacts=[artifact],
    )
    publish(journal, revision)
    if damage == "artifact":
        journal.objects.path(artifact).unlink()
    elif damage == "record":
        sha = journal.records(revision, "inventory")["component"]
        journal.objects.path(sha).write_bytes(b"corrupt")
    elif damage == "orphan":
        sha = journal.objects.put(b"orphan")
        journal.objects.path(sha).write_bytes(b"corrupt")
    with pytest.raises(CorruptJournal):
        preview_unreferenced_objects(
            journal, operational_roots=["a" * 64] if damage == "missing_hint" else []
        )


def test_staging_files_not_classified_as_garbage_and_symlinks_rejected(journal, tmp_path):
    sha = journal.objects.put(b"orphan")
    temporary = journal.objects.path(sha).parent / "tmp-stage"
    temporary.write_bytes(b"in-flight bytes")
    report = preview_unreferenced_objects(journal)
    assert report["statistics"]["ignored_staging_files"] == 1
    assert report["total"] == 1
    temporary.unlink()
    temporary.symlink_to(tmp_path / "outside")
    with pytest.raises(CorruptJournal):
        preview_unreferenced_objects(journal)


def test_concurrent_staging_invalidates_audit(journal, monkeypatch):
    first = journal.objects.put(b"first")
    original = journal.objects.read
    changed = False

    def read(sha):
        nonlocal changed
        raw = original(sha)
        if sha == first and not changed:
            changed = True
            journal.objects.put(b"newly staged")
        return raw

    monkeypatch.setattr(journal.objects, "read", read)
    with pytest.raises(ValueError, match="changed during audit"):
        preview_unreferenced_objects(journal)


def test_bounds_and_policy_validation(journal):
    journal.objects.put(b"too large")
    with pytest.raises(ValueError, match="storage bounds"):
        preview_unreferenced_objects(journal, max_bytes=2)
    for kwargs in (
        {"min_age_days": 0},
        {"min_age_days": True},
        {"limit": 201},
        {"offset": -1},
        {"now": datetime(2026, 1, 1)},
        {"operational_roots": ["invalid"]},
    ):
        with pytest.raises(ValueError):
            preview_unreferenced_objects(journal, **kwargs)
