"""Curated annotations stay separate, explicit, version-scoped and recoverable."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.metadata import (
    MetadataInput,
    get_metadata,
    identity_fingerprint,
    list_metadata,
    save_metadata,
)
from dtvp.knowledge.service import create_tag
from tests.test_knowledge_assessments import current, head, load_sections, seed


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def data(journal, **changes):
    return MetadataInput(
        **(
            {
                "request_id": "metadata-1",
                "expected": head(journal),
                "expected_revision": None,
                "component_ref": "lib",
                "annotations": {
                    "cybersecurity": {
                        "criticality": "high",
                        "exposure": "internal",
                        "mitigations": ["The wrapper validates input."],
                    },
                    "deployment": {
                        "usage": "Parses internally generated reports.",
                        "environment": "Private service network",
                    },
                    "support": {
                        "supplier": "Example maintainer",
                        "status": "supported",
                        "support_until": "2028-12-31",
                    },
                    "notes": "Review again when deployment changes.",
                    "properties": {"tracking": "ISSUE-42"},
                },
                "provenance": {
                    "source": "Component owner",
                    "reference": "DESIGN-42",
                    "observed_at": "2026-10-15T08:00:00Z",
                },
                "rationale": "Recorded the verified inventory and maintenance context.",
            }
            | changes
        )
    )


def save(journal, value, version="7.1.1", actor="manager"):
    return save_metadata(journal, project_id="project", version=version, actor_id=actor, data=value)


def read(journal, version="7.1.1", ref="lib"):
    return get_metadata(journal, current(journal, version), version, ref)


def test_metadata_is_journal_owned_and_imported_component_stays_unchanged(journal):
    seed(journal)
    before = copy.deepcopy(current(journal))
    save(journal, data(journal))
    result = read(journal)
    assert result["status"] == "current" and result["applicable"]
    assert result["payload"]["annotations"]["cybersecurity"]["criticality"] == "high"
    assert result["payload"]["provenance"]["reference"] == "DESIGN-42"
    assert result["payload"]["actor_id"] == "manager"
    assert current(journal)["inventory"] == before["inventory"]
    for section in ("assessments", "reviews", "scoring", "vulnerabilities"):
        assert current(journal)[section] == before[section]
    assert result["revision"] in journal.verify_state(head(journal)).artifacts
    assert "approved" not in result["payload"]


def test_reimport_bookkeeping_and_nonidentity_descriptions_preserve_annotation(journal):
    seed(journal)
    save(journal, data(journal))
    revision = read(journal)["revision"]

    def reimport(sections):
        sections["inventory"]["component:lib"]["dtvp_origin"]["state"] = "next-build"
        sections["inventory"]["component:lib"]["description"] = "More detailed upstream description"
        sections["inventory"]["baseline"]["build_number"] = 2

    seed(journal, parent=head(journal), modify=reimport)
    assert read(journal)["status"] == "current"
    assert read(journal)["revision"] == revision


@pytest.mark.parametrize(
    "change",
    [
        {"version": "2"},
        {"purl": "pkg:generic/another@1"},
        {"name": "different package"},
        {"hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
    ],
)
def test_reused_ref_with_changed_identity_is_stale_not_automatically_rebound(journal, change):
    seed(journal)
    save(journal, data(journal))
    before = read(journal)
    seed(
        journal,
        parent=head(journal),
        modify=lambda s: s["inventory"]["component:lib"].update(change),
    )
    after = read(journal)
    assert after["status"] == "stale" and not after["applicable"]
    assert after["revision"] == before["revision"] and after["payload"] == before["payload"]


def test_removal_retains_absent_metadata_and_matching_reappearance_recovers_status(journal):
    seed(journal)
    save(journal, data(journal))
    previous = copy.deepcopy(current(journal)["inventory"])
    revision = read(journal)["revision"]

    def remove(sections):
        sections["inventory"].pop("component:lib")
        sections["inventory"]["dependencies"]["edges"] = [{"ref": "app", "dependsOn": []}]
        sections["vulnerabilities"] = {}

    seed(journal, parent=head(journal), modify=remove)
    assert read(journal)["status"] == "absent"
    assert list_metadata(journal, current(journal), "7.1.1")["by_status"] == {"absent": 1}
    seed(journal, parent=head(journal), modify=lambda s: s.update(inventory=previous))
    assert read(journal)["status"] == "current" and read(journal)["revision"] == revision


def test_tagged_metadata_stays_immutable_when_explicitly_revised(journal):
    seed(journal)
    save(journal, data(journal))
    tagged = head(journal)
    previous = read(journal)
    create_tag(
        journal,
        project_id="project",
        actor_id="manager",
        name="released",
        state=tagged,
        request_id="tag",
    )
    replacement = data(
        journal,
        request_id="metadata-2",
        expected_revision=previous["revision"],
        annotations={"notes": "Replaced explicitly after owner review."},
    )
    save(journal, replacement, actor="another-manager")
    latest = read(journal)
    assert latest["revision"] != previous["revision"]
    assert latest["payload"]["previous"] == previous["revision"]
    assert latest["payload"]["actor_id"] == "another-manager"
    assert get_metadata(journal, load_sections(journal, tagged), "7.1.1", "lib") == previous


def test_retry_and_expected_head_or_metadata_revision_conflicts_do_not_republish(journal):
    seed(journal)
    value = data(journal)
    receipt = save(journal, value)
    before = journal.head()
    assert save(journal, value) == receipt and journal.head() == before
    with pytest.raises(Conflict, match="different input"):
        save(journal, value.model_copy(update={"rationale": "Changed"}))
    with pytest.raises(Conflict, match="Product version changed"):
        save(journal, value.model_copy(update={"request_id": "old-head"}))
    with pytest.raises(Conflict, match="metadata revision changed"):
        save(journal, data(journal, request_id="old-record"))
    assert journal.head() == before


def test_metadata_is_not_automatically_extended_to_another_version(journal):
    seed(journal)
    save(journal, data(journal))
    old = head(journal)
    inherited = current(journal)
    # A predecessor-style branch explicitly retains the complete older knowledge.
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.storage import digest

    branched = journal.snapshot(
        project_id="project",
        version="7.1.2",
        actor_id="pipeline",
        reason="Next product version",
        sections=inherited,
        parents=[old],
        artifacts=journal.state(old).artifacts,
    )
    journal.publish(
        request_id="branch",
        fingerprint=digest(b"branch"),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.2"), expected=None, target=branched)
        ],
    )
    assert read(journal, "7.1.2")["status"] == "out_of_scope"
    previous = read(journal, "7.1.2")["revision"]
    save(
        journal,
        data(
            journal, request_id="extend-explicitly", expected=branched, expected_revision=previous
        ),
        version="7.1.2",
    )
    assert read(journal, "7.1.2")["status"] == "current"
    assert read(journal)["revision"] == previous


def test_typed_annotations_and_timezone_are_validated_and_hash_order_is_semantic(journal):
    seed(journal)
    with pytest.raises(ValidationError):
        data(journal, annotations={"approved_license": True})
    with pytest.raises(ValidationError, match="timezone"):
        data(journal, provenance={"source": "Owner", "observed_at": "2026-10-15T08:00:00"})
    hashes = [{"alg": "SHA-256", "content": "a"}, {"alg": "SHA-512", "content": "b"}]
    assert identity_fingerprint({"name": "lib", "hashes": hashes}) == identity_fingerprint(
        {"name": "lib", "hashes": list(reversed(hashes))}
    )
    with pytest.raises(ValueError, match="bounds"):
        list_metadata(journal, current(journal), "7.1.1", limit=201)
    assert get_metadata(journal, current(journal), "7.1.1", "lib") is None


def test_real_inventory_import_keeps_curated_revision_separate_from_replaced_source(journal):
    from dtvp.knowledge.service import import_inventory

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "app", "version": "1", "bom-ref": "app"}
        },
        "components": [
            {
                "type": "library",
                "name": "lib",
                "version": "1",
                "purl": "pkg:generic/lib@1",
                "bom-ref": "lib",
            }
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["lib"]}, {"ref": "lib", "dependsOn": []}],
    }
    fields = {
        "project_id": "project",
        "version": "7.1.1",
        "actor_id": "pipeline",
        "source": "pipeline",
        "occurred_at": "2026-10-15T08:00:00Z",
        "sbom": document,
    }
    import_inventory(journal, **fields, request_id="real-1", expected=None, build_number=1)
    save(journal, data(journal))
    metadata = read(journal)
    parent = head(journal)
    import_inventory(journal, **fields, request_id="real-2", expected=parent, build_number=2)
    assert read(journal)["status"] == "current"
    assert read(journal)["revision"] == metadata["revision"]
    assert metadata["revision"] in journal.verify_state(head(journal)).artifacts
    assert "annotations" not in current(journal)["inventory"]["component:ref:lib"]
