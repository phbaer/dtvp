"""Synchronization only extends explicit draft coverage, guarded atomically."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.assessments import (
    ReviewInput,
    Target,
    coverage_status,
    create_review,
    save_assessment,
)
from dtvp.knowledge.journal import Conflict, Journal, Ref
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.knowledge.service import create_tag
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.knowledge.synchronization_apply import (
    SynchronizationApplyInput,
    apply_synchronization,
)
from tests.test_knowledge_assessments import (
    allow,
    assessment,
    current,
    head,
    review,
    save,
    seed,
    target,
)
from tests.test_knowledge_synchronization import (
    SOURCE,
    TARGET,
    parallel,
    preview,
    publish,
)
from tests.test_knowledge_synchronization import journal as source_journal

journal = source_journal


def application(journal, *, source=None, destination=None, **changes):
    result = preview(journal, source, destination)
    row = result["items"][0]
    return SynchronizationApplyInput(
        **(
            {
                "request_id": "synchronize",
                "source": result["source"],
                "target": result["target"],
                "preview_digest": result["preview_digest"],
                "source_context_id": row["source_context_id"],
                "target_context_id": row["target_context_id"],
                "vulnerability_id": row["vulnerability_id"],
                "source_assessment_revision": row["source"]["assessment_revision"],
                "conditions": "Target uses the same unreachable parser configuration.",
                "reason": "Source analysis is relevant to this parallel maintenance version.",
            }
            | changes
        )
    )


def apply(journal, data=None, *, actor="analyst", authorize=allow):
    return apply_synchronization(
        journal,
        project_id="project",
        actor_id=actor,
        data=data or application(journal),
        authorize=authorize,
    )


def coverage(journal, version=TARGET):
    return coverage_status(
        journal, current(journal, version), **target(journal, version).model_dump()
    )


def test_apply_extends_same_id_to_target_draft_only_and_preserves_source_approval(journal):
    parallel(journal)
    data = application(journal)
    source_head = head(journal)
    source_sections = copy.deepcopy(current(journal))
    original = copy.deepcopy(current(journal, TARGET))
    receipt = apply(journal, data)
    assert len(receipt[1].updates) == 1
    assert receipt[1].updates[0].ref.name == TARGET
    assert head(journal) == source_head and current(journal) == source_sections
    updated = current(journal, TARGET)
    for section in original:
        if section != "assessments":
            assert updated[section] == original[section]
    record = updated["assessments"]["assessment:decision"]
    payload = record["payload"]
    assert record["stage"] == "draft"
    assert payload["previous"] == data.source_assessment_revision
    assert payload["assessment_id"] == "decision" and payload["author_id"] == "analyst"
    assert payload["conditions"] == data.conditions
    assert (
        payload["rationale"]
        == source_sections["assessments"]["assessment:decision"]["payload"]["rationale"]
    )
    assert payload["targets"][0]["version"] == TARGET and len(payload["targets"]) == 1
    evidence = payload["evidence"][-1]
    assert evidence["source"] == data.source and evidence["target"] == data.target
    assert evidence["preview_digest"] == data.preview_digest
    assert evidence["source_assessment_revision"] == data.source_assessment_revision
    assert evidence["reason"] == data.reason
    assert evidence["requires_new_target_review"] and not evidence["software_integration_verified"]
    assert coverage(journal)["status"] == "draft" and not coverage(journal)["approved"]
    assert coverage(journal, SOURCE)["status"] == "approved"
    # The new target draft must follow the existing explicit submit/review path.
    review_data = assessment(
        journal,
        [target(journal, TARGET)],
        request_id="submit-target",
        expected_revision=record["revision"],
        conditions=data.conditions,
    )
    save(journal, review_data)
    review(journal, [target(journal, TARGET)], request_id="review-target")
    assert coverage(journal)["status"] == "approved"
    assert coverage(journal, SOURCE)["status"] == "approved"


def test_pending_source_and_material_changes_remain_review_required_drafts(journal):
    parallel(journal, approved=False)
    sections = current(journal, TARGET)
    sections["vulnerabilities"]["claim"]["advisory"]["description"] = "Different source evidence"
    publish(journal, sections)
    assert preview(journal)["items"][0]["category"] == "needs_review"
    apply(journal)
    result = coverage(journal)
    assert result["status"] == "draft"
    authored = result["assessment"]["payload"]["targets"][0]
    assert authored["fingerprint"] == result["fingerprint"]
    assert not result["approved"] and not result["submitted"]


def test_unrelated_valid_target_approval_and_archived_scores_are_preserved(journal):
    parallel(journal)
    sections = current(journal, TARGET)
    sections["inventory"]["component:other"] = {
        "bom-ref": "other",
        "name": "other",
        "version": "1",
        "purl": "pkg:generic/other@1",
    }
    sections["inventory"]["dependencies"]["edges"][0]["dependsOn"].append("other")
    sections["inventory"]["dependencies"]["edges"].append({"ref": "other", "dependsOn": []})
    sections["vulnerabilities"]["other"] = {
        "identifier": "CVE-2026-0002",
        "ref": "other",
        "advisory": {"description": "Another finding"},
    }
    resolve_ownership(
        sections,
        version=TARGET,
        config={"rules": [{"selector": "*", "team_id": "A"}], "context_roots": {}},
    )
    publish(journal, sections)
    context = next(
        item
        for key, item in current(journal, TARGET)["ownership"].items()
        if key.startswith("context:") and item["component_ref"] == "other"
    )
    selected = Target(version=TARGET, context_id=context["id"], vulnerability_id="CVE-2026-0002")
    save(journal, assessment(journal, [selected], request_id="other"), assessment_id="other")
    revision = current(journal, TARGET)["assessments"]["assessment:other"]["revision"]
    create_review(
        journal,
        project_id="project",
        actor_id="reviewer",
        authorize=allow,
        data=ReviewInput(
            request_id="approve-other",
            expected_versions={TARGET: head(journal, TARGET)},
            assessment_id="other",
            assessment_revision=revision,
            targets=[selected],
            action="approve",
            rationale="Independently checked other finding",
        ),
    )
    sections = current(journal, TARGET)
    sections["scoring"]["archived"] = {"format": "historical-test-score", "value": 2}
    publish(journal, sections)
    reviews = copy.deepcopy(current(journal, TARGET)["reviews"])
    apply(journal)
    updated = current(journal, TARGET)
    assert updated["reviews"] == reviews
    assert updated["scoring"] == {"archived": {"format": "historical-test-score", "value": 2}}
    assert coverage_status(journal, updated, **selected.model_dump())["approved"]


@pytest.mark.parametrize("field", ["conditions", "reason"])
def test_target_conditions_and_action_reason_must_be_explicit(journal, field):
    parallel(journal)
    with pytest.raises(ValidationError):
        application(journal, **{field: " \t "})


def test_only_source_author_can_extend_assessment_and_target_authorization_is_enforced(journal):
    parallel(journal)
    before = journal.head()
    with pytest.raises(PermissionError, match="author"):
        apply(journal, actor="another-analyst")

    def deny(team, capability):
        assert team == "A" and capability == "assess"
        raise PermissionError("No target team access")

    with pytest.raises(PermissionError, match="target team"):
        apply(journal, authorize=deny)
    assert journal.head() == before


@pytest.mark.parametrize("recorded_state", ["same", "stale"])
def test_any_recorded_target_content_is_preserved_even_another_id_or_stale(journal, recorded_state):
    parallel(journal)
    save(
        journal,
        assessment(journal, [target(journal, TARGET)], request_id="target-existing"),
        submit=False,
        assessment_id="independent-target",
    )
    if recorded_state == "stale":
        sections = current(journal, TARGET)
        sections["vulnerabilities"]["claim"]["advisory"]["description"] = "Changed evidence"
        publish(journal, sections)
    data = application(journal)
    before = journal.head()
    with pytest.raises(Conflict, match="recorded assessment"):
        apply(journal, data)
    assert journal.head() == before


@pytest.mark.parametrize("field", ["preview_digest", "source_assessment_revision"])
def test_mismatched_preview_or_source_revision_never_publishes(journal, field):
    parallel(journal)
    data = application(journal, **{field: "f" * 64})
    before = journal.head()
    with pytest.raises(Conflict, match="differs"):
        apply(journal, data)
    assert journal.head() == before


def test_exact_current_heads_required_and_tagged_past_is_never_applied(journal):
    parallel(journal)
    data = application(journal)
    create_tag(
        journal,
        project_id="project",
        name="release",
        state=data.source,
        actor_id="release",
        request_id="tag",
    )
    sections = current(journal)
    sections["history"]["note"] = {"text": "Later nightly"}
    publish(journal, sections, version=SOURCE)
    before = journal.head()
    with pytest.raises(Conflict, match="current product-version branch head"):
        apply(journal, data)
    assert journal.head() == before


def test_target_advance_refuses_old_preview(journal):
    parallel(journal)
    data = application(journal)
    publish(journal, current(journal, TARGET))
    before = journal.head()
    with pytest.raises(Conflict, match="Target product version changed"):
        apply(journal, data)
    assert journal.head() == before


def test_durable_replay_precedes_head_checks_and_changed_request_cannot_reuse_id(journal):
    parallel(journal)
    data = application(journal)
    receipt = apply(journal, data)
    publish(journal, current(journal), version=SOURCE)
    publish(journal, current(journal, TARGET))
    before = journal.head()
    assert apply(journal, data) == receipt
    assert journal.head() == before
    with pytest.raises(Conflict, match="Request ID"):
        apply(journal, data.model_copy(update={"reason": "A different action"}))


def test_source_head_guard_is_atomic_without_writing_source_branch(journal, monkeypatch):
    parallel(journal)
    data = application(journal)
    old_target = head(journal, TARGET)
    native_publish = Journal.publish
    invoked = []

    def race(self, **kwargs):
        if kwargs.get("checks"):
            invoked.append(kwargs["checks"])
            publish(journal, current(journal), version=SOURCE)
        return native_publish(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    with pytest.raises(Conflict, match="Referenced policy changed"):
        apply(journal, data)
    assert invoked == [((Ref(project_id="project", name=SOURCE), data.source),)]
    assert head(journal, TARGET) == old_target
    assert head(journal) != data.source


def test_new_branch_race_is_rejected_by_native_global_head_guard(journal, monkeypatch):
    parallel(journal)
    data = application(journal)
    old_target = head(journal, TARGET)
    native_publish = Journal.publish

    def race(self, **kwargs):
        if kwargs.get("checks"):
            seed(journal, version="7.2.0")
        return native_publish(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    with pytest.raises(Conflict, match="Product versions changed"):
        apply(journal, data)
    assert head(journal, TARGET) == old_target


def test_optional_native_checks_are_part_of_receipt_identity_and_old_calls_unchanged(journal):
    parallel(journal)
    selected = target(journal, TARGET)
    data = assessment(
        journal,
        [selected],
        request_id="direct-guarded-save",
        expected_revision=current(journal)["assessments"]["assessment:decision"]["revision"],
        conditions="Explicit cross-version conditions",
    )
    ref = Ref(project_id="project", name=SOURCE)
    args = dict(
        project_id="project",
        actor_id="analyst",
        assessment_id="decision",
        data=data,
        submit=False,
        authorize=allow,
    )
    receipt = save_assessment(journal, **args, publication_checks=[(ref, head(journal))])
    assert save_assessment(journal, **args, publication_checks=[(ref, head(journal))]) == receipt
    with pytest.raises(Conflict, match="Request ID"):
        save_assessment(journal, **args, publication_checks=[(ref, "f" * 64)])


def test_unresolved_lineage_is_not_eligible_for_draft_extension(journal):
    parallel(journal)
    sections = current(journal, TARGET)
    sections["inventory"]["component:lib"]["purl"] = "pkg:generic/another@1"
    publish(journal, sections)
    assert preview(journal)["items"][0]["category"] == "unresolved"
    before = journal.head()
    with pytest.raises(Conflict, match="not eligible"):
        apply(journal)
    assert journal.head() == before


def test_internal_selected_row_preserves_full_digest_counts_and_pagination(journal):
    parallel(journal)
    original = preview(journal)
    row = original["items"][0]
    selected = synchronization_preview(
        journal,
        "project",
        head(journal),
        head(journal, TARGET),
        offset=1,
        limit=1,
        row_id=row["id"],
    )
    assert selected["items"] == [] and selected["total"] == original["total"]
    assert selected["summary"] == original["summary"]
    assert selected["preview_digest"] == original["preview_digest"]
    assert selected["selected_row"] == row


def test_explicit_common_basis_is_pinned_in_applied_draft(journal):
    basis = parallel(journal)
    result = preview(journal, basis=basis)
    data = application(journal, basis=basis, preview_digest=result["preview_digest"])
    apply(journal, data)
    assert coverage(journal)["assessment"]["payload"]["evidence"][-1]["basis"] == basis
