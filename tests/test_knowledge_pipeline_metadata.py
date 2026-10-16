"""CI declarations permit legacy same-build inputs without guessing their identity."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.observation_graph import propose_observation
from dtvp.knowledge.pipeline_metadata import SubjectDeclaration
from tests.test_knowledge_observation_graph import inventory


def legacy_inputs():
    authority, observation = inventory(), inventory("other-")
    for document, artifact in ((authority, "a" * 64), (observation, "b" * 64)):
        document["baseline"]["artifact_sha"] = artifact
        document["baseline"]["product_version"] = "7.1.2"
        document["baseline"]["collection"].pop("subject_digest")
    declaration = {
        "product_id": "product",
        "version": "7.1.2",
        "part_id": "runtime",
        "subject_id": "processing-engine",
        "build_id": "1842",
        "authority_sbom_sha256": "a" * 64,
        "observation_sbom_sha256": "b" * 64,
    }
    return authority, observation, declaration


def test_ci_metadata_binds_legacy_inputs_with_visible_assurance_and_no_mutation():
    authority, observation, declaration = legacy_inputs()
    original = deepcopy([authority, observation, declaration])
    assert propose_observation(authority, observation)["status"] == "blocked"
    report = propose_observation(authority, observation, subject_declaration=declaration)
    assert report["status"] == "proposals_only"
    assert report["subject_assurance"] == "producer_declared"
    assert report["summary"]["matched_occurrences"] == 2
    assert report["subject_declaration"]["build_id"] == "1842"
    assert report == propose_observation(authority, observation, subject_declaration=declaration)
    assert [authority, observation, declaration] == original


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("authority_sbom_sha256", "c" * 64, "subject_declaration_sbom_changed"),
        ("observation_sbom_sha256", "c" * 64, "subject_declaration_sbom_changed"),
        ("part_id", "other", "subject_declaration_part_changed"),
        ("version", "7.2.0", "subject_declaration_version_changed"),
    ],
)
def test_declaration_cannot_follow_changed_file_or_known_scope(field, value, reason):
    authority, observation, declaration = legacy_inputs()
    declaration[field] = value
    report = propose_observation(authority, observation, subject_declaration=declaration)
    assert report["status"] == "blocked"
    assert reason in report["blocked_reasons"]
    assert report["mapping"] == []


def test_declared_build_never_overrides_conflicting_artifact_digests_or_collection_scope():
    authority, observation, declaration = legacy_inputs()
    authority["baseline"]["collection"]["subject_digest"] = "sha256:" + "c" * 64
    observation["baseline"]["collection"]["subject_digest"] = "sha256:" + "d" * 64
    observation["baseline"]["collection"]["configuration"] = "different"
    report = propose_observation(authority, observation, subject_declaration=declaration)
    assert report["status"] == "blocked"
    assert {"subject_digest_changed", "collection_scope_changed"} <= set(report["blocked_reasons"])


def test_one_known_artifact_digest_remains_declared_until_both_inputs_identify_it():
    authority, observation, declaration = legacy_inputs()
    authority["baseline"]["collection"]["subject_digest"] = "sha256:" + "c" * 64
    first = propose_observation(authority, observation, subject_declaration=declaration)
    assert first["subject_assurance"] == "producer_declared"
    observation["baseline"]["collection"]["subject_digest"] = "sha256:" + "c" * 64
    second = propose_observation(authority, observation, subject_declaration=declaration)
    assert second["subject_assurance"] == "digest_bound"
    assert second["report_digest"] != first["report_digest"]


def test_even_digest_bound_inputs_do_not_ignore_a_stale_declaration():
    authority, observation, declaration = legacy_inputs()
    for document in (authority, observation):
        document["baseline"]["collection"]["subject_digest"] = "sha256:" + "c" * 64
    declaration["authority_sbom_sha256"] = "d" * 64
    report = propose_observation(authority, observation, subject_declaration=declaration)
    assert report["status"] == "blocked"
    assert report["subject_assurance"] == "unresolved"


@pytest.mark.parametrize("field", ["product_id", "version", "part_id", "subject_id", "build_id"])
def test_blank_declaration_identifiers_are_rejected(field):
    _, _, declaration = legacy_inputs()
    declaration[field] = " "
    with pytest.raises(ValidationError):
        SubjectDeclaration.model_validate(declaration)


def test_declarations_cannot_self_grant_authorization_or_assert_verification():
    authority, observation, declaration = legacy_inputs()
    declaration["approved"] = True
    with pytest.raises(ValidationError):
        propose_observation(authority, observation, subject_declaration=declaration)
