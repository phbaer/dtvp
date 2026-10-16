"""Bulk units are exact targets; one decision never grants implicit extra reviews."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from dtvp.knowledge.bulk_reviews import (
    BulkApply,
    BulkInput,
    Item,
    apply_bulk_review,
    item_id,
    preview_bulk_review,
)
from dtvp.knowledge.journal import Conflict, Journal
from tests.test_knowledge_assessments import (
    assessment,
    coverage,
    current,
    head,
    review,
    save,
    seed,
    target,
)


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def allow(team, capability):
    assert team in {"A", "B"} and capability == "approve"


def data(journal, versions=("7.1.1", "7.1.2"), **changes):
    return BulkInput(
        **(
            dict(
                request_id=str(uuid4()),
                expected_versions={version: head(journal, version) for version in versions},
                items=[
                    Item(
                        target=target(journal, version),
                        assessment_id="decision",
                        assessment_revision=current(journal, version)["assessments"][
                            "assessment:decision"
                        ]["revision"],
                    )
                    for version in versions
                ],
                action="approve",
                rationale="Independently inspected exact submitted revisions",
            )
            | changes
        )
    )


def ready(journal):
    seed(journal)
    seed(journal, "7.1.2")
    save(journal, assessment(journal, [target(journal), target(journal, "7.1.2")]))
    return data(journal)


def preview(journal, intake, actor="reviewer", authorize=allow, **kwargs):
    return preview_bulk_review(journal, "project", actor, intake, authorize, **kwargs)


def apply(journal, intake, selected=None, *, authorize=allow):
    result = preview(journal, intake, authorize=authorize)
    selected = (
        selected
        if selected is not None
        else [row["item_id"] for row in result["items"] if row["ready"]]
    )
    body = BulkApply(
        **intake.model_dump(), selected=selected, preview_digest=result["preview_digest"]
    )
    return apply_bulk_review(journal, "project", "reviewer", body, authorize), body


def test_preview_deterministic_full_counts_no_writes_and_atomic_selected_versions(journal):
    intake = ready(journal)
    before = journal.head()
    objects = set(journal.objects.root.rglob("*"))
    result = preview(journal, intake, limit=1)
    assert result["statistics"] == {
        "total": 2,
        "ready": 2,
        "excluded": 0,
        "by_reason": {"ready": 2},
    }
    assert len(result["items"]) == 1 and result["next_offset"] == 1
    assert preview(journal, intake)["preview_digest"] == result["preview_digest"]
    assert journal.head() == before and set(journal.objects.root.rglob("*")) == objects
    untouched = head(journal, "7.1.2")
    receipt, body = apply(journal, intake, selected=[item_id(intake.items[0])])
    assert len(receipt[1].updates) == 1 and head(journal, "7.1.2") == untouched
    assert (
        coverage(journal)["approved"]
        and not coverage(journal, target(journal, "7.1.2"))["approved"]
    )
    assert apply_bulk_review(journal, "project", "reviewer", body, allow) == receipt
    with pytest.raises(Conflict, match="different input"):
        apply_bulk_review(
            journal, "project", "reviewer", body.model_copy(update={"rationale": "changed"}), allow
        )


def test_all_selected_versions_one_publication_common_timestamp_and_no_scoring(journal):
    intake = ready(journal)
    receipt, _ = apply(journal, intake)
    assert len(receipt[1].updates) == 2
    reviews = [
        next(iter(current(journal, version)["reviews"].values()))
        for version in intake.expected_versions
    ]
    assert len({record["created_at"] for record in reviews}) == 1
    for version in intake.expected_versions:
        assert current(journal, version)["scoring"] == {}
        assert coverage(journal, target(journal, version))["approved"]


def test_exclusions_and_pending_new_submitted_revision(journal):
    intake = ready(journal)
    assert preview(journal, intake, actor="analyst")["statistics"]["by_reason"] == {
        "self_authored": 2
    }

    def deny(team, capability):
        raise PermissionError("No approval role")

    assert preview(journal, intake, authorize=deny)["statistics"]["by_reason"] == {
        "missing_authority": 2
    }
    review(journal, [target(journal), target(journal, "7.1.2")])
    again = data(journal)
    assert preview(journal, again)["statistics"]["by_reason"] == {"already_reviewed_current": 2}
    old = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            [target(journal), target(journal, "7.1.2")],
            request_id="new-revision",
            expected_revision=old,
            rationale="New submitted revision",
        ),
    )
    new = data(journal)
    assert preview(journal, new)["statistics"]["ready"] == 2
    assert coverage(journal)["assessment_revision"] == old
    apply(journal, new)
    assert coverage(journal)["assessment_revision"] != old


def test_draft_stale_missing_and_invalid_scope_are_never_auto_selected(journal):
    intake = ready(journal)
    old = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            [target(journal), target(journal, "7.1.2")],
            request_id="draft",
            expected_revision=old,
        ),
        submit=False,
    )
    assert preview(journal, data(journal))["statistics"]["by_reason"] == {"draft": 2}
    stale = data(journal)
    bad = stale.model_copy(
        update={
            "items": [
                stale.items[0].model_copy(update={"assessment_id": "missing"}),
                stale.items[1],
            ]
        }
    )
    assert preview(journal, bad)["statistics"]["by_reason"] == {"draft": 1, "missing_assessment": 1}
    with pytest.raises(ValidationError):
        data(journal, items=[intake.items[0], intake.items[0]])
    with pytest.raises(ValidationError):
        data(journal, expected_versions={"7.1.1": head(journal)})


def test_excluded_or_unknown_selected_item_aborts_without_publication(journal):
    intake = ready(journal)
    first = item_id(intake.items[0])
    result = preview(journal, intake)
    body = BulkApply(
        **intake.model_dump(), selected=[first, "f" * 64], preview_digest=result["preview_digest"]
    )
    before = journal.head()
    with pytest.raises(Conflict, match="excluded or unknown"):
        apply_bulk_review(journal, "project", "reviewer", body, allow)
    assert journal.head() == before and not current(journal)["reviews"]


def test_racing_unmutated_candidate_version_blocks_selected_publication(journal, monkeypatch):
    intake = ready(journal)
    result = preview(journal, intake)
    body = BulkApply(
        **intake.model_dump(),
        selected=[item_id(intake.items[0])],
        preview_digest=result["preview_digest"],
    )
    native = Journal.publish
    raced = []

    def race(self, **kwargs):
        if not raced:
            raced.append(True)
            seed(journal, "7.1.2", parent=head(journal, "7.1.2"))
        return native(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    with pytest.raises(Conflict, match="Referenced policy changed"):
        apply_bulk_review(journal, "project", "reviewer", body, allow)
    assert not current(journal)["reviews"]


def test_request_changes_applies_only_new_submissions_not_approved_revocation(journal):
    intake = ready(journal).model_copy(update={"action": "request_changes"})
    apply(journal, intake)
    again = data(journal, action="request_changes")
    assert preview(journal, again)["statistics"]["by_reason"] == {"already_reviewed_current": 2}
    assert all(
        coverage(journal, target(journal, version))["status"] == "reassessment_needed"
        for version in intake.expected_versions
    )


def test_materially_stale_candidate_is_excluded_while_ready_other_version_can_be_selected(journal):
    ready(journal)
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"]["component:lib"].update(version="2"),
    )
    intake = data(journal)
    result = preview(journal, intake)
    assert result["statistics"]["by_reason"] == {"ready": 1, "stale_evidence": 1}
    ready_row = next(row for row in result["items"] if row["ready"])
    unchanged = head(journal)
    apply(journal, intake, selected=[ready_row["item_id"]])
    assert head(journal) == unchanged
    assert not current(journal)["reviews"]
    assert coverage(journal, target(journal, "7.1.2"))["approved"]
