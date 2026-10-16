"""Explicit DTVP subset profiles reject unsupported semantics without certification."""

import copy

import pytest

from dtvp.knowledge.evidence import EvidenceInput
from dtvp.knowledge.evidence_conformance import bounded_tree, conformance
from dtvp.knowledge.vex import parse_evidence, preview_evidence
from dtvp.storage import canonical, digest
from tests.test_knowledge_vex import cdx, csaf, inventory, openvex

OPEN = "dtvp-openvex-0.2.0-exact/1"
CSAF = "dtvp-csaf-2.0-vex-exact/1"
CDX = "dtvp-cyclonedx-1.6-exact/1"


@pytest.mark.parametrize("factory,profile", [(cdx, CDX), (openvex, OPEN), (csaf, CSAF)])
def test_declared_supported_profiles_remain_unverified_evidence(factory, profile):
    document = factory()
    parsed = parse_evidence(canonical(document), validation_profile=profile)
    assert parsed["conformance"]["valid"]
    assert parsed["schema_validation"] == "dtvp_supported_subset_only"
    assert parsed["signature_verification"] == "not_performed"
    sections = inventory()
    result = preview_evidence(
        sections, {"artifact_sha": digest(canonical(document)), "document": parsed}
    )
    assert result["application"]["matched"] == 1
    assert sections["assessments"] == {"human": {"state": "affected", "author_id": "analyst"}}
    assert sections["reviews"] == {"human": {"reviewer_id": "reviewer"}}


@pytest.mark.parametrize(
    "factory,profile,mutate",
    [
        (openvex, OPEN, lambda d: d.update({"@context": "https://openvex.dev/ns/v0.2.9"})),
        (openvex, OPEN, lambda d: d.update(version=True)),
        (openvex, OPEN, lambda d: d.update(timestamp="2026-10-16T12:00:00")),
        (openvex, OPEN, lambda d: d["statements"][0].update(status=["not_affected"])),
        (
            openvex,
            OPEN,
            lambda d: d["statements"][0]["products"][0].update({"@id": "pkg:generic/library"}),
        ),
        (
            openvex,
            OPEN,
            lambda d: d["statements"][0]["products"][0].update(
                subcomponents=[{"@id": "pkg:generic/other@1"}]
            ),
        ),
        (cdx, CDX, lambda d: d.update(specVersion="1.7")),
        (cdx, CDX, lambda d: d["components"].append(copy.deepcopy(d["components"][0]))),
        (
            cdx,
            CDX,
            lambda d: d["vulnerabilities"][0]["affects"][0].update(
                versions=[{"range": "vers:npm/<2"}]
            ),
        ),
        (
            cdx,
            CDX,
            lambda d: d["vulnerabilities"][0]["affects"][0].update(ref="urn:cdx:external/one"),
        ),
        (csaf, CSAF, lambda d: d["document"].update(csaf_version="2.1")),
        (csaf, CSAF, lambda d: d["product_tree"].update(relationships=[{}])),
        (csaf, CSAF, lambda d: d["product_tree"].update(product_groups=[{}])),
        (
            csaf,
            CSAF,
            lambda d: d["vulnerabilities"][0]["product_status"].update(fixed=["product-1"]),
        ),
    ],
)
def test_declared_profile_rejects_bad_shape_version_or_scope(factory, profile, mutate):
    document = factory()
    mutate(document)
    report = conformance(document, profile)
    assert not report["valid"] and report["diagnostics"]
    assert all(set(item) == {"path", "code"} for item in report["diagnostics"])
    with pytest.raises(ValueError, match="profile rejected"):
        parse_evidence(canonical(document), validation_profile=profile)


def test_default_dto_and_legacy_fingerprint_inputs_are_unchanged():
    document = openvex()
    data = dict(
        request_id="old",
        expected_evidence=None,
        expected_versions={},
        source="supplier",
        revision=1,
        document=document,
    )
    assert EvidenceInput.model_validate(data).model_dump(mode="json") == data
    assert (
        EvidenceInput.model_validate({**data, "validation_profile": None}).model_dump(mode="json")
        == data
    )
    parsed = parse_evidence(canonical(document))
    assert (
        "conformance" not in parsed and parsed["schema_validation"] == "supported_semantic_subset"
    )
    # Legacy acceptance is not silently upgraded to a stricter contract.
    document["@context"] = "https://openvex.dev/ns/v0.2.9"
    assert parse_evidence(canonical(document))["format"] == "openvex-0.2"


def test_signature_presence_is_reported_but_never_verified_or_trusted():
    document = openvex()
    document["signature"] = {"value": "not-real"}
    report = conformance(document, OPEN)
    assert report["valid"] and report["warnings"] == [
        {"path": "/", "code": "signature_present_not_verified"}
    ]
    assert (
        parse_evidence(canonical(document), validation_profile=OPEN)["signature_verification"]
        == "not_performed"
    )


def test_csaf_nested_branch_identity_is_exact_without_relationship_expansion():
    document = csaf()
    product = document["product_tree"].pop("full_product_names")[0]
    document["product_tree"]["branches"] = [
        {
            "category": "vendor",
            "name": "Supplier",
            "branches": [{"category": "product_name", "name": "Library", "product": product}],
        }
    ]
    parsed = parse_evidence(canonical(document), validation_profile=CSAF)
    result = preview_evidence(
        inventory(), {"artifact_sha": digest(canonical(document)), "document": parsed}
    )
    assert result["application"]["matched"] == 1
    document["product_tree"]["full_product_names"] = [product]
    assert not conformance(document, CSAF)["valid"]
    legacy = parse_evidence(canonical(document))
    result = preview_evidence(
        inventory(), {"artifact_sha": digest(canonical(document)), "document": legacy}
    )
    assert result["application"]["matched"] == 0


def test_tree_admission_checks_width_before_iterating_and_bounds_diagnostics():
    class GuardedList(list):
        def __iter__(self):
            raise AssertionError("Must reject before enqueue iteration")

    with pytest.raises(ValueError, match="budget"):
        bounded_tree(GuardedList([None] * 100_001))
    document = openvex()
    document["statements"] = [{} for _ in range(100)]
    assert len(conformance(document, OPEN)["diagnostics"]) == 64


@pytest.mark.parametrize(
    "field,value", [("label", []), ("product_ids", "product-1"), ("group_ids", ["group-1"])]
)
def test_malformed_csaf_reason_never_raises_type_errors_or_becomes_valid(field, value):
    document = csaf()
    document["vulnerabilities"][0]["flags"] = [
        {"label": "component_not_present", "product_ids": ["product-1"], field: value}
    ]
    assert not conformance(document, CSAF)["valid"]
    with pytest.raises(ValueError):
        parse_evidence(canonical(document), validation_profile=CSAF)
