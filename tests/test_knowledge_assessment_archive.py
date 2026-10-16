"""Logical retirement preserves exact historical authority without future reuse."""

import pytest

import dtvp.knowledge.assessment_archive as archive
from dtvp.knowledge.assessment_archive import (
    ArchiveInput,
    apply_archive,
    get_archived,
    preview_archive,
)
from dtvp.knowledge.exports import export_bytes
from dtvp.knowledge.journal import CommitUncertain, Conflict, Journal, Ref, Update
from dtvp.knowledge.service import create_tag
from dtvp.storage import digest
from tests.test_knowledge_assessments import assessment, current, head, review, save, seed, target


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def absent(sections):
    sections["vulnerabilities"] = {}


def retire_input(journal, **changes):
    plan = preview_archive(journal, "project")
    return ArchiveInput(
        request_id="retire",
        plan_hash=plan["plan_hash"],
        project_refs=plan["project_refs"],
        assessment_ids=["decision"],
        reason="Absent from every maintained version; retain historical evidence.",
        **changes,
    )


def apply(journal, data):
    return apply_archive(journal, project_id="project", actor_id="manager", data=data)


def orphan(journal, *, approve=True):
    seed(journal)
    save(journal, assessment(journal))
    if approve:
        review(journal)
    prior = head(journal)
    seed(journal, parent=prior, modify=absent)
    return prior


def test_archive_retains_exact_history_exports_and_other_sections_and_receipt(journal):
    prior = orphan(journal)
    historical = export_bytes(journal, prior)
    before = current(journal)
    raw = {sha: journal.objects.read(sha) for sha in journal.state(prior).artifacts}
    data = retire_input(journal)
    result = apply(journal, data)
    after = current(journal)
    assert after["assessments"] == after["reviews"] == {}
    for section in ("inventory", "ownership", "vulnerabilities", "scoring"):
        assert after[section] == before[section]
    retained = get_archived(journal, "project", "decision")
    assert retained["current_approval"] is False
    assert retained["assessments"][0]["payload"]["author_id"] == "analyst"
    assert any(row["record"].get("status") == "approved" for row in retained["records"])
    assert export_bytes(journal, prior) == historical
    assert all(journal.objects.read(sha) == value for sha, value in raw.items())
    assert apply(journal, data) == result
    assert len(journal.records(journal.resolve(archive.archive_ref("project")), "history")) == 1
    pointer = archive.list_archived(journal, "project")["items"][0]
    assert "occurrences" not in pointer and "manifest_sha" in pointer


def test_reappearance_is_unassessed_retired_id_cannot_reuse_but_old_receipt_replays(journal):
    seed(journal)
    original = assessment(journal)
    saved = save(journal, original)
    seed(journal, parent=head(journal), modify=absent)
    apply(journal, retire_input(journal))

    def reappear(sections):
        sections["vulnerabilities"] = {
            "claim": {
                "identifier": "CVE-2026-0001",
                "ref": "lib",
                "source": "supplier",
                "advisory": {"description": "A defect"},
            }
        }

    seed(journal, parent=head(journal), modify=reappear)
    assert not current(journal)["assessments"] and not current(journal)["reviews"]
    with pytest.raises(Conflict, match="retired"):
        save(journal, assessment(journal, request_id="reused"))
    assert save(journal, original) == saved
    save(journal, assessment(journal, request_id="new"), assessment_id="new-logical")


def test_all_historical_revisions_and_shared_versions_protect_logical_id(journal):
    seed(journal)
    seed(journal, "7.1.2")
    save(journal, assessment(journal, targets=[target(journal), target(journal, "7.1.2")]))
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(journal, assessment(journal, request_id="narrow", expected_revision=revision))
    seed(journal, parent=head(journal), modify=absent)
    plan = preview_archive(journal, "project")
    assert plan["revision_total"] == 2 and plan["assessments"][0]["status"] == "active"
    with pytest.raises(Conflict, match="candidate"):
        apply(journal, retire_input(journal))
    seed(journal, "7.1.2", parent=head(journal, "7.1.2"), modify=absent)
    assert preview_archive(journal, "project")["assessments"][0]["candidate"]


def test_exact_tag_protection_and_unknown_past_scope_block(journal):
    prior = orphan(journal)
    create_tag(
        journal,
        project_id="project",
        actor_id="manager",
        name="released",
        state=prior,
        request_id="tag",
    )
    assert preview_archive(journal, "project")["assessments"][0]["status"] == "tag_protected"
    with pytest.raises(Conflict):
        apply(journal, retire_input(journal))


def test_new_tag_and_other_ref_publication_races_fail_atomic(journal, monkeypatch):
    prior = orphan(journal)
    data = retire_input(journal)
    before = head(journal)
    publish = journal.publish
    raced = False

    def racing(**kwargs):
        nonlocal raced
        if kwargs.get("project_refs") and not raced:
            raced = True
            create_tag(
                journal,
                project_id="project",
                actor_id="manager",
                name="new-release",
                state=prior,
                request_id="racing-tag",
            )
        return publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing)
    with pytest.raises(Conflict, match="references"):
        apply(journal, data)
    assert head(journal) == before and current(journal)["reviews"]
    assert journal.resolve(archive.archive_ref("project")) is None


def test_post_head_uncertainty_replays_exact_after_new_inventory(journal, monkeypatch):
    orphan(journal)
    data = retire_input(journal)
    replace = journal._replace_head

    def uncertain(sha):
        replace(sha)
        raise OSError("durability result unknown")

    monkeypatch.setattr(journal, "_replace_head", uncertain)
    with pytest.raises(CommitUncertain):
        apply(journal, data)
    retired = head(journal)
    monkeypatch.setattr(journal, "_replace_head", replace)
    seed(journal, parent=retired, modify=absent)
    newest = head(journal)
    assert apply(journal, data)[1].updates[0].ref == archive.archive_ref("project")
    assert head(journal) == newest
    with pytest.raises(Conflict, match="different input"):
        apply(journal, data.model_copy(update={"reason": "Changed reason"}))


def test_preview_is_pure_stable_paged_and_finite_budget_checks_before_decode(journal, monkeypatch):
    orphan(journal)
    before = journal.head(), set(journal.objects.root.rglob("*"))
    first = preview_archive(journal, "project", limit=1)
    assert first["plan_hash"] == preview_archive(journal, "project", offset=1, limit=1)["plan_hash"]
    assert before == (journal.head(), set(journal.objects.root.rglob("*")))
    monkeypatch.setattr(archive, "MAX_SCAN_BYTES", 1)
    selected_state = head(journal)
    original = journal.load

    def guarded(sha, model=None):
        if sha == selected_state:
            pytest.fail("Oversized state decoded before scan-budget admission")
        return original(sha, model)

    # Calling head() itself decodes only the publication, not the state.
    monkeypatch.setattr(journal, "load", guarded)
    with pytest.raises(ValueError, match="budget"):
        preview_archive(journal, "project")


def test_reason_and_selection_must_be_explicit(journal):
    orphan(journal)
    with pytest.raises(ValueError):
        retire_input(journal).model_validate({**retire_input(journal).model_dump(), "reason": "  "})
    with pytest.raises(ValueError):
        ArchiveInput.model_validate(
            {**retire_input(journal).model_dump(), "assessment_ids": ["decision", "decision"]}
        )


def test_unknown_replaced_historical_revision_still_blocks_logical_archive(journal):
    from tests.test_knowledge_maintenance import publish_sections

    seed(journal)
    save(journal, assessment(journal))
    sections = current(journal)
    record = sections["assessments"]["assessment:decision"]
    record["payload"]["targets"] = []
    revision = journal.store(record["payload"])
    record["revision"] = revision
    publish_sections(journal, sections)
    save(journal, assessment(journal, request_id="repaired-current", expected_revision=revision))
    seed(journal, parent=head(journal), modify=absent)
    plan = preview_archive(journal, "project")
    assert plan["assessments"][0]["status"] == "unknown_scope"
    with pytest.raises(Conflict):
        apply(journal, retire_input(journal))


def test_current_effective_score_defensively_blocks_and_stale_score_is_retained(
    journal, monkeypatch
):
    orphan(journal)
    monkeypatch.setattr(archive, "published_score", lambda *args: {"current": True})
    assert (
        preview_archive(journal, "project")["assessments"][0]["status"]
        == "current_scoring_reference"
    )
    with pytest.raises(Conflict):
        apply(journal, retire_input(journal))


def test_new_source_reference_publication_race_blocks_archival(journal, monkeypatch):
    orphan(journal, approve=False)
    data = retire_input(journal)
    publish = journal.publish
    raced = False

    def racing(**kwargs):
        nonlocal raced
        if kwargs.get("project_refs") and not raced:
            raced = True
            parent = head(journal)
            sections = current(journal)
            state = journal.snapshot(
                project_id="project",
                version="7.1.1",
                actor_id="pipeline",
                reason="Concurrent revision",
                sections=sections,
                parents=[parent],
            )
            publish(
                request_id="racing-new-ref",
                fingerprint=digest(state.encode()),
                updates=[
                    Update(
                        ref=Ref(kind="source", project_id="project", name="new-source"),
                        expected=None,
                        target=state,
                    )
                ],
            )
        return publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing)
    with pytest.raises(Conflict, match="references"):
        apply(journal, data)
    assert journal.resolve(archive.archive_ref("project")) is None


def test_registry_only_retirement_race_blocks_logical_id_reuse_without_branch_change(
    journal, monkeypatch
):
    seed(journal)
    save(journal, assessment(journal))

    def replace_with_other_vuln(sections):
        sections["assessments"] = {}
        sections["vulnerabilities"]["claim"]["identifier"] = "CVE-2026-9999"

    seed(journal, parent=head(journal), modify=replace_with_other_vuln)
    data = retire_input(journal)
    before = head(journal)
    new_target = target(journal).model_copy(update={"vulnerability_id": "CVE-2026-9999"})
    new_assessment = assessment(journal, targets=[new_target], request_id="reuse-racing")
    publish, raced = journal.publish, False

    def racing(**kwargs):
        nonlocal raced
        if kwargs.get("checks") and not raced:
            raced = True
            result = apply(journal, data)
            assert len(result[1].updates) == 1  # Registry only, no branch CAS can catch this race.
            assert head(journal) == before
        return publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing)
    with pytest.raises(Conflict, match="Referenced policy"):
        save(journal, new_assessment)
    assert not current(journal)["assessments"]


def test_old_state_fork_retains_history_without_cross_version_approval_or_editable_id(journal):
    from dtvp.knowledge.assessments import coverage_status, load_sections

    prior = orphan(journal)
    apply(journal, retire_input(journal))
    sections = load_sections(journal, prior)
    fork = journal.snapshot(
        project_id="project",
        version="7.1.2",
        actor_id="manager",
        reason="Explicit old state fork",
        sections=sections,
        parents=[prior],
    )
    journal.publish(
        request_id="fork",
        fingerprint=digest(fork.encode()),
        updates=[Update(ref=Ref(project_id="project", name="7.1.2"), expected=None, target=fork)],
    )
    row = target(journal, "7.1.2")
    assert coverage_status(journal, sections, **row.model_dump())["status"] != "approved"
    assert sections["assessments"] and sections["reviews"]
    with pytest.raises(Conflict, match="retired"):
        save(
            journal,
            assessment(
                journal,
                targets=[row],
                request_id="edit-retired-fork",
                expected_revision=sections["assessments"]["assessment:decision"]["revision"],
            ),
        )


def test_missing_or_corrupted_historical_objects_fail_closed_without_publication(journal):
    from dtvp.knowledge.journal import CorruptJournal

    prior = orphan(journal)
    before = journal.head()
    path = journal.objects.path(prior)
    original = path.read_bytes()
    path.write_bytes(b"{}")
    with pytest.raises(CorruptJournal):
        preview_archive(journal, "project")
    assert journal.head() == before
    path.write_bytes(original)
    path.unlink()
    with pytest.raises(CorruptJournal, match="Missing archival scan object"):
        preview_archive(journal, "project")
    assert journal.head() == before


def test_history_state_cap_refuses_before_loading_any_state(journal, monkeypatch):
    orphan(journal)
    monkeypatch.setattr(archive, "MAX_STATES", 0)
    selected_state = head(journal)
    native = journal.load

    def guarded(sha, model=None):
        if sha == selected_state:
            pytest.fail("State decoded before finite state-cap admission")
        return native(sha, model)

    monkeypatch.setattr(journal, "load", guarded)
    with pytest.raises(ValueError, match="state cap"):
        preview_archive(journal, "project")
