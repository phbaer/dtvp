"""Retention plans are globally scoped read-only proposals, never garbage collection."""

from datetime import UTC, datetime, timedelta

import pytest

from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.maintenance import preview_retention
from dtvp.knowledge.service import create_tag
from dtvp.storage import digest
from tests.test_knowledge_assessments import assessment, current, head, save, seed, target


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def preview(journal, **kwargs):
    return preview_retention(journal, "project", **kwargs)


def absent(sections):
    sections["vulnerabilities"] = {}


def publish_sections(journal, sections):
    parent = head(journal)
    state = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="fixture",
        reason="Fixture",
        sections=sections,
        parents=[parent],
    )
    journal.publish(
        request_id="custom-" + state,
        fingerprint=digest(state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.1"), expected=parent, target=state)
        ],
    )


def test_active_shared_revision_never_candidates_one_absent_version(journal):
    seed(journal)
    seed(journal, "7.1.2")
    save(journal, assessment(journal, targets=[target(journal), target(journal, "7.1.2")]))
    seed(journal, parent=head(journal), modify=absent)
    plan = preview(journal)
    assert plan["total"] == 1
    item = plan["items"][0]
    assert item["status"] == "active" and not item["candidate"]
    assert item["active_targets"][0]["version"] == "7.1.2"
    assert item["current_branches"] == ["7.1.1", "7.1.2"]
    seed(journal, "7.1.2", parent=head(journal, "7.1.2"), modify=absent)
    assert preview(journal)["items"][0]["candidate"]


def test_tag_protection_and_logical_vs_revision_candidates(journal):
    seed(journal)
    save(journal, assessment(journal))
    first = preview(journal)["items"][0]["revision"]
    create_tag(
        journal,
        project_id="project",
        actor_id="manager",
        name="release",
        state=head(journal),
        request_id="tag",
    )
    save(
        journal,
        assessment(
            journal,
            expected_revision=first,
            request_id="edit",
            rationale="Additional explicit evidence",
        ),
    )
    seed(journal, parent=head(journal), modify=absent)
    plan = preview(journal)
    assert plan["statistics"]["revision_statuses"] == {"tag_protected": 1, "retention_candidate": 1}
    assert plan["assessments"][0]["status"] == "tag_protected"
    assert not plan["assessments"][0]["candidate"]
    assert next(item for item in plan["items"] if item["revision"] == first)[
        "tagged_references"
    ] == ["release"]


def test_unknown_scope_and_age_never_auto_candidates(journal):
    seed(journal)
    sections = current(journal)
    sections["assessments"]["assessment:unknown"] = {
        "revision": "a" * 64,
        "payload": {"targets": [{"version": "7.1.1"}], "created_at": "not a date"},
    }
    publish_sections(journal, sections)
    plan = preview(journal)
    assert plan["items"][0]["status"] == "unknown_scope"
    assert not plan["items"][0]["candidate"]
    assert plan["statistics"]["unknown_age"] == 1


def test_stable_paged_full_plan_and_no_publication_or_objects_written(journal):
    seed(journal)
    save(journal, assessment(journal))
    save(journal, assessment(journal, request_id="second"), assessment_id="second")
    seed(journal, parent=head(journal), modify=absent)
    before_head = journal.head()
    before_files = sorted(path.relative_to(journal.root) for path in journal.root.rglob("*"))
    now = datetime.now(UTC)
    first = preview(journal, limit=1, now=now)
    second = preview(journal, offset=1, limit=1, now=now + timedelta(days=5))
    assert first["plan_hash"] == second["plan_hash"]
    assert first["next_offset"] == 1 and first["total"] == 2
    assert first["statistics"]["logical_assessments"] == 2
    assert first["statistics"]["revision_statuses"] == {"retention_candidate": 2}
    assert second["items"][0]["retained_age_days"] == 5
    assert journal.head() == before_head
    assert (
        sorted(path.relative_to(journal.root) for path in journal.root.rglob("*")) == before_files
    )
    seed(journal, "7.2.0")
    assert preview(journal)["plan_hash"] != first["plan_hash"]


def test_invalid_page_or_naive_preview_time(journal):
    with pytest.raises(ValueError):
        preview(journal, limit=201)
    with pytest.raises(ValueError):
        preview(journal, now=datetime(2026, 1, 1))


def test_retained_review_revision_candidate_does_not_candidate_active_logical_assessment(journal):
    from tests.test_knowledge_assessments import review

    seed(journal)
    seed(journal, "7.1.2")
    save(journal, assessment(journal))
    review(journal)
    previous = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            targets=[target(journal), target(journal, "7.1.2")],
            expected_revision=previous,
            request_id="extension",
        ),
    )
    seed(journal, parent=head(journal), modify=absent)
    plan = preview(journal)
    assert plan["total"] == 2
    assert next(item for item in plan["items"] if item["revision"] == previous)["candidate"]
    assert plan["assessments"][0]["status"] == "active"
    assert not plan["assessments"][0]["candidate"]
    assert current(journal)["reviews"]  # Preview never withdraws the retained approval.


def test_unknown_age_is_distinct_from_unknown_scope(journal):
    seed(journal)
    save(journal, assessment(journal))
    authored = current(journal)["assessments"]["assessment:decision"]["payload"]["created_at"]
    seed(journal, parent=head(journal), modify=absent)
    plan = preview(journal, now=datetime.fromisoformat(authored) - timedelta(days=1))
    assert plan["items"][0]["candidate"]
    assert plan["items"][0]["retained_age_days"] is None
    assert plan["statistics"]["unknown_age"] == 1
