"""Correspondence permits a new adopted draft, never lineage or approval transfer."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.correspondence_drafts import (
    CorrespondenceDraftInput,
    CorrespondenceDraftPreview,
    apply_correspondence_draft,
    preview_correspondence_draft,
)
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.reconciliation import (
    Pair,
    ReconciliationInput,
    RetractionInput,
    confirm_reconciliation,
    correspondence_key,
    preview_reconciliation,
    retract_reconciliation,
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
from tests.test_knowledge_assessments import journal as source_journal
from tests.test_knowledge_reconciliation import renamed, update

journal = source_journal


def prepared(journal, *, pairs="both", evidence=None):
    initial = seed(journal)
    update(journal, initial, lambda sections: sections["inventory"]["component:lib"].pop("purl"))
    source_context = target(journal).context_id
    save(journal, assessment(journal, evidence=evidence or []))
    review(journal)
    source = head(journal)
    source_revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    destination = update(journal, source, renamed)
    target_context = next(
        value["id"]
        for key, value in current(journal)["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "new-lib"
    )
    selected = [
        Pair(kind="component", source_id="lib", target_id="new-lib"),
        Pair(kind="context", source_id=source_context, target_id=target_context),
    ]
    selected = selected if pairs == "both" else [pair for pair in selected if pair.kind == pairs]
    preview = preview_reconciliation(journal, "project", source, destination, selected)
    confirm_reconciliation(
        journal,
        "project",
        "7.1.1",
        "curator",
        "mapping",
        ReconciliationInput(
            request_id=str(uuid4()),
            source=source,
            expected=destination,
            expected_revision=None,
            preview_digest=preview["preview_digest"],
            pairs=selected,
            rationale="Reviewed renamed occurrence and its consuming context",
        ),
        lambda capability: None,
    )
    destination = head(journal)
    record = current(journal)["history"][correspondence_key("mapping")]
    return CorrespondenceDraftPreview(
        source=source,
        target=destination,
        source_context_id=source_context,
        target_context_id=target_context,
        vulnerability_id="CVE-2026-0001",
        source_assessment_revision=source_revision,
        assertions={"mapping": record["revision"]},
        expected_policy=None,
    )


def preview(journal, data):
    return preview_correspondence_draft(journal, project_id="project", data=data)


def application(journal, data):
    result = preview(journal, data)
    return CorrespondenceDraftInput(
        **data.model_dump(),
        request_id=str(uuid4()),
        preview_digest=result["preview_digest"],
        assessment_id="adopted-new-context",
        conditions="Adopted only for the explicitly reviewed target configuration.",
        reason="New team independently takes responsibility for this target analysis.",
    )


def apply(journal, data, *, authorize=allow):
    return apply_correspondence_draft(
        journal, project_id="project", actor_id="new-analyst", data=data, authorize=authorize
    )


def test_historical_same_version_source_creates_new_target_author_draft_and_preserves_source(
    journal,
):
    data = prepared(journal)
    original_source = copy.deepcopy(journal.state(data.source))
    before = copy.deepcopy(current(journal))
    result = preview(journal, data)
    assert result["category"] == "needs_review" and result["requires_new_target_review"]
    assert result["source_author_id"] == "analyst"
    receipt = apply(journal, application(journal, data))
    assert len(receipt[1].updates) == 1
    updated = current(journal)
    for section in before:
        if section != "assessments":
            assert updated[section] == before[section]
    assert (
        updated["assessments"]["assessment:decision"]
        == before["assessments"]["assessment:decision"]
    )
    record = updated["assessments"]["assessment:adopted-new-context"]
    payload = record["payload"]
    assert payload["author_id"] == "new-analyst" and payload["previous"] is None
    assert record["stage"] == "draft"
    evidence = payload["evidence"][-1]
    assert evidence["source_author_id"] == "analyst"
    assert evidence["source_assessment_revision"] == data.source_assessment_revision
    assert evidence["assertions"] == data.assertions
    assert evidence["requires_new_target_review"] and not evidence["software_integration_verified"]
    assert journal.state(data.source) == original_source
    from dtvp.knowledge.assessments import coverage_status

    coverage = coverage_status(
        journal,
        updated,
        version="7.1.1",
        context_id=data.target_context_id,
        vulnerability_id=data.vulnerability_id,
    )
    assert coverage["status"] == "draft" and not coverage["approved"]


@pytest.mark.parametrize("pairs", ["component", "context"])
def test_both_component_and_context_assertions_required(journal, pairs):
    data = prepared(journal, pairs=pairs)
    with pytest.raises(Conflict, match="both required"):
        preview(journal, data)


def test_replay_after_target_advancement_is_exact_but_still_requires_authorization(journal):
    data = application(journal, prepared(journal))
    receipt = apply(journal, data)
    update(
        journal,
        head(journal),
        lambda sections: sections["history"].update(note={"text": "Later unrelated edit"}),
    )
    later = head(journal)
    assert apply(journal, data) == receipt and head(journal) == later

    def deny(team, capability):
        raise PermissionError("Target permission revoked")

    with pytest.raises(PermissionError, match="revoked"):
        apply(journal, data, authorize=deny)
    with pytest.raises(Conflict):
        apply(journal, data.model_copy(update={"reason": "Changed under the same request"}))
    assert head(journal) == later


def test_changed_captured_material_requires_new_confirmation(journal):
    data = prepared(journal)
    destination = update(
        journal,
        head(journal),
        lambda sections: sections["inventory"]["component:new-lib"].update(version="2"),
    )
    data = data.model_copy(update={"target": destination})
    with pytest.raises(Conflict, match="material changed"):
        preview(journal, data)


def test_retracted_assertion_and_stale_target_fail_without_publication(journal):
    data = prepared(journal)
    retract_reconciliation(
        journal,
        "project",
        "7.1.1",
        "curator",
        "mapping",
        RetractionInput(
            request_id=str(uuid4()),
            expected=data.target,
            expected_revision=data.assertions["mapping"],
            reason="Mapping withdrawn",
        ),
        lambda capability: None,
    )
    before = journal.head()
    with pytest.raises(Conflict, match="Target product version changed"):
        preview(journal, data)
    with pytest.raises(Conflict, match="retracted"):
        preview(journal, data.model_copy(update={"target": head(journal)}))
    assert journal.head() == before


def test_existing_target_content_is_never_overwritten(journal):
    data = prepared(journal)
    apply(journal, application(journal, data))
    data = data.model_copy(update={"target": head(journal)})
    with pytest.raises(Conflict, match="preserve its decision"):
        preview(journal, data)


def test_arbitrary_state_and_wrong_source_revision_rejected(journal):
    data = prepared(journal)
    with pytest.raises(ValueError, match="committed states"):
        preview(journal, data.model_copy(update={"source": "0" * 64}))
    with pytest.raises(Conflict, match="independent approval"):
        preview(journal, data.model_copy(update={"source_assessment_revision": "0" * 64}))


def test_conflicting_unselected_active_mapping_blocks_adoption(journal):
    data = prepared(journal)
    pairs = [Pair(kind="component", source_id="lib", target_id="app")]
    result = preview_reconciliation(journal, "project", data.source, data.target, pairs)
    confirm_reconciliation(
        journal,
        "project",
        "7.1.1",
        "curator",
        "alternative",
        ReconciliationInput(
            request_id=str(uuid4()),
            source=data.source,
            expected=data.target,
            expected_revision=None,
            preview_digest=result["preview_digest"],
            pairs=pairs,
            rationale="Competing explicit mapping",
        ),
        lambda capability: None,
    )
    with pytest.raises(Conflict, match="conflicting mappings"):
        preview(journal, data.model_copy(update={"target": head(journal)}))


def test_atomic_policy_change_does_not_publish_adopted_target(journal, monkeypatch):
    from dtvp.knowledge.journal import Journal, Update
    from dtvp.knowledge.ownership import policy_ref
    from dtvp.storage import digest

    data = application(journal, prepared(journal))
    original_target = head(journal)
    publish = Journal.publish
    raced = []

    def race(self, **kwargs):
        if kwargs.get("checks") and not raced:
            raced.append(True)
            publish(
                self,
                request_id=str(uuid4()),
                fingerprint=digest(b"policy-race"),
                updates=[Update(ref=policy_ref("project"), expected=None, target=data.target)],
            )
        return publish(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    with pytest.raises(Conflict, match="policy changed"):
        apply(journal, data)
    assert raced and head(journal) == original_target
    assert "assessment:adopted-new-context" not in current(journal)["assessments"]


def test_uncertain_publication_replays_exact_committed_new_draft(journal, monkeypatch):
    from dtvp.knowledge.journal import CommitUncertain

    data = application(journal, prepared(journal))
    replace = journal._replace_head

    def uncertain(sha):
        replace(sha)
        raise OSError("Durability result unknown")

    monkeypatch.setattr(journal, "_replace_head", uncertain)
    with pytest.raises(CommitUncertain):
        apply(journal, data)
    updated = head(journal)
    monkeypatch.setattr(journal, "_replace_head", replace)
    receipt = apply(journal, data)
    assert receipt[1].updates[0].target == updated and head(journal) == updated


def test_new_logical_identifier_is_required_and_wrong_policy_is_stale(journal):
    data = application(journal, prepared(journal))
    before = journal.head()
    with pytest.raises(Conflict, match="new logical"):
        apply(journal, data.model_copy(update={"assessment_id": "decision"}))
    with pytest.raises(Conflict, match="Ownership policy changed"):
        preview(journal, data.model_copy(update={"expected_policy": "0" * 64}))
    assert journal.head() == before


@pytest.mark.parametrize("field", ["conditions", "reason"])
def test_whitespace_only_adoption_fields_are_rejected(journal, field):
    from pydantic import ValidationError

    data = application(journal, prepared(journal))
    with pytest.raises(ValidationError):
        CorrespondenceDraftInput.model_validate(data.model_dump() | {field: " \t \n "})


def test_full_source_evidence_is_retained_by_exact_revision_without_truncation(journal):
    from dtvp.storage import canonical, digest

    evidence = [
        {"artifact": f"original-{index}", "details": "Original source context"}
        for index in range(100)
    ]
    data = application(journal, prepared(journal, evidence=evidence))
    apply(journal, data)
    payload = current(journal)["assessments"]["assessment:adopted-new-context"]["payload"]
    assert len(payload["evidence"]) == 1
    reference = payload["evidence"][0]
    assert reference["source_assessment_revision"] == data.source_assessment_revision
    assert reference["source_evidence"] == {
        "count": 100,
        "sha256": digest(canonical(evidence)),
        "location": "source_assessment_revision.payload.evidence",
    }
    assert journal.load(data.source_assessment_revision)["evidence"] == evidence
    assert reference["source_author_id"] == "analyst" and payload["author_id"] == "new-analyst"


def tagged_copy(journal, source, *, connected):
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.knowledge.workspace import load_sections
    from dtvp.storage import digest

    revision = journal.state(source)
    state = journal.snapshot(
        project_id="project",
        version=revision.version,
        actor_id="fixture",
        reason="Independent root" if not connected else "Related source bookkeeping",
        sections=load_sections(journal, source),
        parents=[source] if connected else [],
        artifacts=revision.artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[
            Update(
                ref=Ref(kind="tag", project_id="project", name=str(uuid4())),
                expected=None,
                target=state,
            )
        ],
    )
    return state


def test_equal_looking_unrelated_source_history_is_not_correspondence_authority(journal):
    data = prepared(journal)
    unrelated = tagged_copy(journal, data.source, connected=False)
    with pytest.raises(Conflict, match="unrelated"):
        preview(journal, data.model_copy(update={"source": unrelated}))


def test_connected_source_history_can_reuse_mapping_only_with_unchanged_material(journal):
    data = prepared(journal)
    related = tagged_copy(journal, data.source, connected=True)
    result = preview(journal, data.model_copy(update={"source": related}))
    assert result["category"] == "needs_review"


def test_copied_assertion_on_unrelated_target_root_is_not_authority(journal):
    import shutil

    from dtvp.knowledge.journal import Journal, Ref, Update
    from dtvp.knowledge.workspace import load_sections
    from dtvp.storage import digest

    data = prepared(journal)
    state = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="fixture",
        reason="New unrelated target root with copied history",
        sections=load_sections(journal, data.target),
        parents=[],
    )
    # An established branch cannot discard its parent. A freshly assembled
    # installation can still contain valid objects and copied assertion history.
    replacement = Journal(journal.root.parent / "independent-journal")
    shutil.copytree(journal.objects.root, replacement.objects.root, dirs_exist_ok=True)
    replacement.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.1"), expected=None, target=state),
            Update(
                ref=Ref(kind="tag", project_id="project", name="old-source"),
                expected=None,
                target=data.source,
            ),
        ],
    )
    with pytest.raises(Conflict, match="unrelated"):
        preview(replacement, data.model_copy(update={"target": state}))


def test_candidate_summaries_are_historical_bounded_and_do_not_copy_evidence(journal):
    from dtvp.knowledge.correspondence_drafts import correspondence_draft_candidates

    data = prepared(journal, evidence=[{"private_evidence": "Original file retained"}])
    first = correspondence_draft_candidates(
        journal, project_id="project", state=data.source, limit=1
    )
    second = correspondence_draft_candidates(
        journal, project_id="project", state=data.source, offset=1, limit=1
    )
    assert first["total"] == second["total"] == 1 and second["items"] == []
    assert first["candidates_digest"] == second["candidates_digest"]
    item = first["items"][0]
    assert item["approved_assessment"]["revision"] == data.source_assessment_revision
    assert "evidence" not in item["approved_assessment"]["payload"]
    assert item["summary_only"] and first["state"] != head(journal)
    assert (
        correspondence_draft_candidates(
            journal, project_id="project", state=data.source, q="not-a-match"
        )["total"]
        == 0
    )
    with pytest.raises(ValueError, match="committed product history"):
        correspondence_draft_candidates(journal, project_id="project", state="0" * 64)


def test_unapproved_source_is_not_a_candidate(journal):
    from dtvp.knowledge.correspondence_drafts import correspondence_draft_candidates

    seed(journal)
    save(journal, assessment(journal))
    result = correspondence_draft_candidates(journal, project_id="project", state=head(journal))
    assert result["items"] == [] and result["total"] == 0
