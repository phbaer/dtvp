"""Human license decisions remain exact, independent and separate from source facts."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.license_reviews import (
    LicenseInput,
    LicenseReviewInput,
    inventory_fingerprint,
    license_status,
    list_license_reviews,
    review_license,
    save_license,
)
from tests.test_knowledge_assessments import current, head, seed


@pytest.fixture
def journal(tmp_path):
    value = Journal(tmp_path / "journal")
    seed(value)
    return value


def data(journal, **changes):
    return LicenseInput(
        **(
            {
                "request_id": "license",
                "expected": head(journal),
                "expected_revision": None,
                "component_ref": "lib",
                "concluded_expression": "LicenseRef-Reviewed-Terms",
                "disposition": "restricted",
                "obligations": ["Include attribution"],
                "distribution": "Binary distribution to customers",
                "modification": "Unmodified",
                "linking": "Dynamically linked",
                "rationale": "Supplier terms and the actual distribution were reviewed.",
                "evidence": [{"reference": "legal-review:123"}],
                "provenance": {"source": "license-specialist"},
            }
            | changes
        )
    )


def save(journal, payload=None, *, submit=True, actor="author", authorize=lambda capability: None):
    return save_license(
        journal,
        project_id="project",
        version="7.1.1",
        actor_id=actor,
        data=payload or data(journal),
        submit=submit,
        authorize=authorize,
    )


def status(journal, version="7.1.1"):
    return license_status(journal, current(journal, version), version, "lib")


def review(journal, *, actor="reviewer", action="approve", **changes):
    payload = LicenseReviewInput(
        **(
            {
                "request_id": "review",
                "expected": head(journal),
                "component_ref": "lib",
                "revision": status(journal)["assessment"]["revision"],
                "action": action,
                "rationale": "Independently reviewed the exact terms and distribution context.",
            }
            | changes
        )
    )
    return review_license(
        journal,
        project_id="project",
        version="7.1.1",
        actor_id=actor,
        data=payload,
        authorize=lambda capability: None,
    )


def test_draft_submit_independent_approval_and_original_facts_untouched(journal):
    source = copy.deepcopy(current(journal)["inventory"])
    save(journal, submit=False)
    assert status(journal)["status"] == "draft"
    with pytest.raises(Conflict, match="submitted"):
        review(journal)
    revision = status(journal)["assessment"]["revision"]
    save(journal, data(journal, request_id="submit", expected_revision=revision))
    assert status(journal)["status"] == "submitted"
    with pytest.raises(PermissionError, match="independent"):
        review(journal, actor="author")
    review(journal)
    assert status(journal)["status"] == "approved"
    assert (
        status(journal)["approved_assessment"]["payload"]["concluded_expression"]
        == "LicenseRef-Reviewed-Terms"
    )
    assert current(journal)["inventory"] == source
    assert status(journal)["assessment"]["revision"] in journal.state(head(journal)).artifacts


def test_pending_draft_retains_exact_approved_pin(journal):
    save(journal)
    review(journal)
    approved = status(journal)["approved_assessment"]["revision"]
    save(
        journal,
        data(journal, request_id="edit", expected_revision=approved, disposition="prohibited"),
        submit=False,
    )
    result = status(journal)
    assert result["approved"] and result["pending"]
    assert result["approved_assessment"]["revision"] == approved
    assert result["assessment"]["payload"]["disposition"] == "prohibited"
    assert result["approved_assessment"]["payload"]["disposition"] == "restricted"


def test_changed_other_component_or_dependency_context_invalidates_approval(journal):
    save(journal)
    review(journal)
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"]["root"].update(version="2"),
    )
    assert status(journal)["status"] == "stale"
    with pytest.raises(Conflict, match="context changed"):
        review(journal, request_id="retry-review")


def test_identical_nightly_and_team_reassignment_preserve_approval(journal):
    save(journal)
    review(journal)
    before = inventory_fingerprint(current(journal))

    def bookkeeping(sections):
        sections["inventory"]["baseline"].update(
            build_number=200, artifact_sha="new", occurred_at="later"
        )
        sections["inventory"]["baseline"]["collection"]["pipeline_run"] = "new"
        sections["inventory"]["component:lib"]["dtvp_origin"]["state"] = "new-import"

    seed(journal, parent=head(journal), team="B", modify=bookkeeping)
    assert inventory_fingerprint(current(journal)) == before
    assert status(journal)["approved"]


def test_new_version_removed_component_and_reappearance(journal):
    save(journal)
    review(journal)
    original = head(journal)
    seed(journal, "7.1.2", parent=None)
    # Simulate normal retained history inherited along the product branch lineage.
    seed(
        journal,
        "7.1.2",
        parent=head(journal, "7.1.2"),
        modify=lambda sections: sections["history"].update(
            copy.deepcopy(current(journal)["history"])
        ),
    )
    assert status(journal, "7.1.2")["status"] == "out_of_scope"
    inventory = copy.deepcopy(current(journal)["inventory"])

    def remove_component(sections):
        sections["inventory"].pop("component:lib")
        sections["inventory"]["dependencies"]["edges"] = [{"ref": "app", "dependsOn": []}]

    seed(journal, parent=original, modify=remove_component)
    assert status(journal)["status"] == "absent"
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"].update(inventory),
    )
    assert status(journal)["approved"]


def test_receipt_cas_authority_and_explicit_input(journal):
    payload = data(journal)
    first = save(journal, payload)
    assert save(journal, payload) == first
    with pytest.raises(Conflict):
        save(journal, payload.model_copy(update={"request_id": "stale"}))

    def deny(capability):
        assert capability == "license_assess"
        raise PermissionError("No role")

    with pytest.raises(PermissionError):
        save(journal, payload, authorize=deny)
    with pytest.raises(ValidationError):
        data(journal, concluded_expression=" ")
    with pytest.raises(ValidationError):
        data(journal, disposition="automatic")


def test_request_changes_and_full_count_list(journal):
    save(journal)
    review(journal, action="request_changes")
    assert status(journal)["status"] == "changes_requested"
    assert not status(journal)["approved"]
    listing = list_license_reviews(journal, current(journal), "7.1.1", limit=1)
    assert listing["total"] == 1 and listing["by_status"] == {"changes_requested": 1}
    with pytest.raises(ValueError):
        list_license_reviews(journal, current(journal), "7.1.1", limit=201)


def test_source_license_change_and_immutable_tag_retain_prior_decision(journal):
    from dtvp.knowledge.assessments import load_sections
    from dtvp.knowledge.service import create_tag

    save(journal)
    review(journal)
    pinned = head(journal)
    create_tag(
        journal,
        project_id="project",
        actor_id="manager",
        name="release",
        state=pinned,
        request_id="tag",
    )
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"]["component:lib"].update(
            licenses=[{"expression": "LicenseRef-Changed-Supplier-Terms"}]
        ),
    )
    assert status(journal)["status"] == "stale"
    historical = license_status(journal, load_sections(journal, pinned), "7.1.1", "lib")
    assert historical["approved"]
    assert (
        historical["approved_assessment"]["payload"]["concluded_expression"]
        == "LicenseRef-Reviewed-Terms"
    )


def test_current_curated_usage_changes_license_context_but_recording_rationale_does_not(journal):
    from dtvp.knowledge.metadata import get_metadata, save_metadata
    from tests.test_knowledge_metadata import data as metadata_data

    save(journal)
    review(journal)
    assert status(journal)["approved"]
    save_metadata(
        journal,
        project_id="project",
        version="7.1.1",
        actor_id="manager",
        data=metadata_data(journal),
    )
    assert status(journal)["status"] == "stale"
    fingerprint = inventory_fingerprint(current(journal), "7.1.1")
    old = get_metadata(journal, current(journal), "7.1.1", "lib")
    updated = metadata_data(
        journal,
        request_id="recording-only",
        expected_revision=old["revision"],
        rationale="Corrected recording rationale only.",
    )
    save_metadata(journal, project_id="project", version="7.1.1", actor_id="manager", data=updated)
    assert inventory_fingerprint(current(journal), "7.1.1") == fingerprint


def test_assembly_integration_build_labels_are_bookkeeping_not_license_changes(journal):
    original = current(journal)
    original["inventory"]["assembly"] = {
        "coherence": {
            "status": "producer_declared",
            "build_id": "integration-1",
            "rationale": "Selected together",
        },
        "parts": [],
    }
    changed = copy.deepcopy(original)
    changed["inventory"]["assembly"]["coherence"].update(
        build_id="integration-2", rationale="Next identical integration"
    )
    assert inventory_fingerprint(original, "7.1.1") == inventory_fingerprint(changed, "7.1.1")
    changed["inventory"]["assembly"]["coherence"]["status"] = "unverified"
    assert inventory_fingerprint(original, "7.1.1") != inventory_fingerprint(changed, "7.1.1")
