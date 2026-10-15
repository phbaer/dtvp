"""Pinned synchronization previews never copy inventory, reviews or scores."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.assessments import ReviewInput, create_review, load_sections
from dtvp.knowledge.journal import Ref, Update
from dtvp.knowledge.service import create_tag
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.storage import digest
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
from tests.test_knowledge_assessments import (
    journal as source_journal,
)

journal = source_journal
SOURCE = "7.1.1"
TARGET = "7.1.2"


def preview(journal, source=None, destination=None, **kwargs):
    return synchronization_preview(
        journal, "project", source or head(journal), destination or head(journal, TARGET), **kwargs
    )


def branch(journal, predecessor):
    state = journal.snapshot(
        project_id="project",
        version=TARGET,
        actor_id="pipeline",
        reason="Branch",
        sections=load_sections(journal, predecessor),
        parents=[predecessor],
        artifacts=journal.state(predecessor).artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[Update(ref=Ref(project_id="project", name=TARGET), expected=None, target=state)],
    )
    return state


def parallel(journal, *, approved=True):
    basis = seed(journal)
    branch(journal, basis)
    save(journal, assessment(journal))
    if approved:
        review(journal)
    return basis


def publish(journal, sections, version=TARGET):
    parent = head(journal, version)
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="test",
        reason="Change",
        sections=sections,
        parents=[parent],
        artifacts=journal.state(parent).artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name=version), expected=parent, target=state)
        ],
    )
    return state


def test_matching_parallel_context_offers_content_without_invented_merge_or_target_review(journal):
    parallel(journal)
    before = journal.head()
    sections = copy.deepcopy(current(journal, TARGET))
    result = preview(journal)
    assert journal.head() == before
    assert current(journal, TARGET) == sections
    assert result["mode"] == "two_state" and result["basis"] is None
    assert result["provenance"]["software_integration_verified"] is False
    assert not result["apply_supported"]
    row = result["items"][0]
    assert row["category"] == "reusable_content"
    assert row["requires_new_target_review"]
    assert row["source"]["approved"]
    assert not row["target"]["approved"]
    assert row["source"]["assessment_revision"]
    assert row["source"]["fingerprint"] == row["target"]["fingerprint"]
    assert result["summary"]["by_category"] == {"reusable_content": 1}


def test_explicit_basis_requires_real_common_knowledge_ancestry(journal):
    basis = parallel(journal)
    result = preview(journal, basis=basis)
    assert result["mode"] == "three_way"
    assert result["items"][0]["category"] == "reusable_content"
    with pytest.raises(ValueError, match="ancestor of both"):
        preview(journal, basis=head(journal))
    with pytest.raises(ValueError, match="ancestor of both"):
        preview(journal, basis="f" * 64)


def test_pending_source_content_needs_review_and_keeps_approved_pin_separate(journal):
    parallel(journal)
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            request_id="pending-source",
            expected_revision=revision,
            rationale="New source explanation pending review",
        ),
        submit=False,
    )
    row = preview(journal)["items"][0]
    assert row["category"] == "needs_review"
    assert "pending" in row["reasons"][0]
    assert not row["source"]["approved"]
    assert row["source"]["assessment_revision"] != row["source"]["approved_revision"]


def test_target_independent_conclusion_is_conflicting_and_never_overwritten(journal):
    parallel(journal)
    selected = target(journal, TARGET)
    save(
        journal,
        assessment(
            journal,
            [selected],
            request_id="target-decision",
            state="affected",
            rationale="Target configuration exposes the vulnerable function",
        ),
        submit=False,
        assessment_id="target-decision",
    )
    before = copy.deepcopy(current(journal, TARGET))
    row = preview(journal)["items"][0]
    assert row["category"] == "conflicting"
    assert row["target"]["assessment"]["payload"]["state"] == "affected"
    assert current(journal, TARGET) == before


def test_independent_text_edits_since_an_empty_basis_are_three_way_conflicts(journal):
    basis = parallel(journal)
    save(
        journal,
        assessment(
            journal,
            [target(journal, TARGET)],
            request_id="target-text",
            rationale="Independent target rationale",
        ),
        submit=False,
        assessment_id="target-decision",
    )
    assert preview(journal)["items"][0]["category"] == "needs_review"
    assert preview(journal, basis=basis)["items"][0]["category"] == "conflicting"


def test_existing_independently_reviewed_target_content_is_already_covered(journal):
    parallel(journal)
    selected = target(journal, TARGET)
    save(
        journal,
        assessment(journal, [selected], request_id="target-assessment"),
        assessment_id="target-decision",
    )
    create_review(
        journal,
        project_id="project",
        actor_id="reviewer",
        authorize=allow,
        data=ReviewInput(
            request_id="target-review",
            expected_versions={TARGET: head(journal, TARGET)},
            assessment_id="target-decision",
            assessment_revision=current(journal, TARGET)["assessments"][
                "assessment:target-decision"
            ]["revision"],
            targets=[selected],
            action="approve",
            rationale="Independent target approval",
        ),
    )
    result = preview(journal)
    assert result["items"][0]["category"] == "already_covered"
    assert not result["items"][0]["requires_new_target_review"]


def test_changed_target_material_requires_review_and_missing_claims_do_not_prove_remediation(
    journal,
):
    parallel(journal)
    changed = current(journal, TARGET)
    changed["vulnerabilities"]["claim"]["advisory"]["description"] = "Changed target advisory"
    publish(journal, changed)
    assert preview(journal)["items"][0]["category"] == "needs_review"
    changed["vulnerabilities"] = {}
    publish(journal, changed)
    result = preview(journal)
    assert result["items"][0]["category"] == "not_applicable"
    assert "not_remediation_proof" in result["items"][0]["reasons"][0]


def test_context_mapping_is_explicit_and_cannot_establish_material_equivalence(journal):
    parallel(journal)

    def rename_root(sections):
        sections["inventory"]["root"]["bom-ref"] = "different-app"
        sections["inventory"]["dependencies"]["edges"][0]["ref"] = "different-app"

    seed(journal, TARGET, parent=head(journal, TARGET), modify=rename_root)
    assert preview(journal)["items"][0]["category"] == "unresolved"
    source_id, target_id = target(journal).context_id, target(journal, TARGET).context_id
    result = preview(journal, context_mapping={source_id: target_id})
    assert result["items"][0]["category"] == "needs_review"
    assert result["items"][0]["context_mapping"] == "explicit"
    with pytest.raises(ValueError, match="existing source and target"):
        preview(journal, context_mapping={source_id: "f" * 64})


def test_explicit_mapping_cannot_collapse_another_unmapped_context(journal):
    parallel(journal)
    contexts = [
        value for key, value in current(journal)["ownership"].items() if key.startswith("context:")
    ]
    root = next(context for context in contexts if context["component_ref"] == "app")
    lib = next(context for context in contexts if context["component_ref"] == "lib")
    with pytest.raises(ValueError, match="collapse several"):
        preview(journal, context_mapping={lib["id"]: root["id"]})


def test_delayed_nightly_does_not_change_existing_pinned_preview_or_release_tag(journal):
    basis = parallel(journal)
    source, destination = head(journal), head(journal, TARGET)
    create_tag(
        journal,
        project_id="project",
        actor_id="release",
        name="released",
        state=source,
        request_id="tag",
    )
    frozen = preview(journal, source, destination, basis=basis)

    def newer_build(sections):
        sections["inventory"]["baseline"]["build_number"] = 200
        sections["inventory"]["baseline"]["collection"]["pipeline_run"] = "delayed-nightly"

    seed(journal, TARGET, parent=destination, modify=newer_build)
    assert preview(journal, source, destination, basis=basis) == frozen
    latest = preview(journal, source, basis=basis)
    assert latest["preview_digest"] != frozen["preview_digest"]
    assert latest["items"][0]["category"] == "reusable_content"
    assert journal.resolve(Ref(kind="tag", project_id="project", name="released")) == source


def test_preview_pages_share_full_counts_and_digest_with_unknown_scope_retained(journal):
    parallel(journal)
    source = current(journal)
    source["assessments"]["legacy"] = {"reason": "Unknown historical scope"}
    publish(journal, source, SOURCE)
    first = preview(journal, limit=1)
    second = preview(journal, limit=1, offset=first["next_offset"])
    assert first["total"] == second["total"] == 2
    assert (
        first["summary"]
        == second["summary"]
        == {"by_category": {"unresolved": 1, "reusable_content": 1}}
    )
    assert first["preview_digest"] == second["preview_digest"]
    assert {first["items"][0]["category"], second["items"][0]["category"]} == {
        "unresolved",
        "reusable_content",
    }


def test_branching_after_approval_never_credits_copied_source_review(journal):
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    branch(journal, head(journal))
    result = preview(journal)
    assert not result["items"][0]["target"]["approved"]
    assert result["items"][0]["category"] == "reusable_content"


def test_cross_product_and_uncommitted_states_are_rejected(journal):
    parallel(journal)
    sections = current(journal)
    foreign = journal.snapshot(
        project_id="foreign", version=TARGET, actor_id="test", reason="Foreign", sections=sections
    )
    uncommitted = journal.snapshot(
        project_id="project",
        version=TARGET,
        actor_id="test",
        reason="Unpublished",
        sections=sections,
    )
    for state in (foreign, uncommitted, "e" * 64):
        with pytest.raises(ValueError, match="committed states"):
            preview(journal, destination=state)


@pytest.mark.parametrize("mapping", [[], "not a map", {"source": []}])
def test_malformed_context_mappings_fail_with_validation_error(journal, mapping):
    parallel(journal)
    with pytest.raises(ValueError, match="context mappings"):
        preview(journal, context_mapping=mapping)


def test_source_assessment_with_changed_material_requires_revalidation(journal):
    parallel(journal)
    changed = current(journal)
    changed["vulnerabilities"]["claim"]["advisory"]["description"] = "Changed source advisory"
    publish(journal, changed, SOURCE)
    row = preview(journal)["items"][0]
    assert row["category"] == "needs_review"
    assert row["reasons"] == ["source_assessment_requires_revalidation"]


def test_owner_change_keeps_content_candidate_but_never_grants_target_approval(journal):
    parallel(journal)
    seed(journal, TARGET, parent=head(journal, TARGET), team="B")
    row = preview(journal)["items"][0]
    assert row["category"] == "reusable_content"
    assert row["requires_new_target_review"]
    assert not row["target"]["approved"]
