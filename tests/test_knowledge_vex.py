"""Imported product-scoped claims are evidence, never internal approvals."""

import copy
import json

import pytest

from dtvp.knowledge.journal import SECTIONS
from dtvp.knowledge.vex import parse_evidence, preview_evidence, reconcile_evidence
from dtvp.storage import canonical, digest

PURL = "pkg:generic/example/library@1.0?arch=amd64"
OTHER = "pkg:generic/example/library@2.0?arch=amd64"
VULN = "CVE-2026-0001"


def inventory():
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {
        "component:one": {"bom-ref": "one", "name": "library", "purl": PURL},
        "component:other": {"bom-ref": "other", "name": "library", "purl": OTHER},
        "baseline": {"artifact_sha": "0" * 64},
    }
    sections["assessments"] = {"human": {"state": "affected", "author_id": "analyst"}}
    sections["reviews"] = {"human": {"reviewer_id": "reviewer"}}
    return sections


def openvex(status="not_affected", product=PURL, **changes):
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:example:advisory",
        "version": 1,
        "author": "Supplier",
        "timestamp": "2026-10-15T08:00:00Z",
        "statements": [
            {
                "vulnerability": {"name": VULN},
                "products": [{"@id": product}],
                "status": status,
                "justification": "vulnerable_code_not_in_execute_path",
                **changes,
            }
        ],
    }


def cdx(status="not_affected", components=True, **changes):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:fixture",
        "version": 1,
        "components": [{"bom-ref": "one", "name": "library", "purl": PURL}] if components else [],
        "vulnerabilities": [
            {
                "id": VULN,
                "analysis": {
                    "state": status,
                    "justification": "code_not_reachable",
                    "detail": "Unreachable in this configuration",
                },
                "affects": [{"ref": "one"}],
                **changes,
            }
        ],
    }


def csaf(status="known_not_affected"):
    return {
        "document": {
            "csaf_version": "2.0",
            "category": "csaf_vex",
            "publisher": {"name": "Supplier", "namespace": "https://example.org"},
            "tracking": {"id": "ADVISORY-1", "version": "1.0.0"},
        },
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "product-1",
                    "name": "Library",
                    "product_identification_helper": {"purl": PURL},
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": VULN,
                "product_status": {status: ["product-1"]},
                "threats": [
                    {
                        "category": "impact",
                        "details": "The vulnerable code is unreachable.",
                        "product_ids": ["product-1"],
                    }
                ],
            }
        ],
    }


def record(document, **changes):
    raw = canonical(document)
    return {
        "document": parse_evidence(raw),
        "artifact_sha": digest(raw),
        "source": "supplier-upload",
        **changes,
    }


def install(sections, item):
    sections["vulnerabilities"]["evidence-document:" + item["artifact_sha"]] = item
    return reconcile_evidence(sections)


def claims(sections):
    return [
        item
        for key, item in sections["vulnerabilities"].items()
        if key.startswith("external-evidence:")
    ]


@pytest.mark.parametrize("factory", [openvex, cdx, csaf])
def test_supported_formats_apply_only_exact_product_and_keep_human_state(factory):
    sections = inventory()
    before = copy.deepcopy(sections)
    item = record(factory())
    preview = preview_evidence(sections, item)
    assert sections == before
    assert len(preview["would_apply"]) == 1
    assert preview["would_apply"][0]["ref"] == "one"
    assert preview["unmatched"] == []
    install(sections, item)
    assert len(claims(sections)) == 1
    claim = claims(sections)[0]
    assert claim["advisory"]["normalized_status"] == "not_affected"
    assert claim["trust"] == "unverified"
    assert sections["inventory"] == before["inventory"]
    assert sections["assessments"] == before["assessments"]
    assert sections["reviews"] == before["reviews"]
    assert item["document"]["raw"] == factory()
    assert item["document"]["schema_validation"] == "supported_semantic_subset"


@pytest.mark.parametrize(
    "document",
    [
        {"bomFormat": "CycloneDX", "specVersion": "1.7"},
        {"@context": "https://openvex.dev/ns/v0.3.0", "statements": []},
        {"document": {"csaf_version": "2.1", "category": "csaf_vex"}},
        {"document": {"csaf_version": "2.0", "category": "csaf_security_advisory"}},
    ],
)
def test_unsupported_declared_versions_and_profiles_rejected(document):
    with pytest.raises(ValueError, match="Supported"):
        parse_evidence(canonical(document))


def test_no_global_vulnerability_or_versionless_package_application():
    sections = inventory()
    item = record(openvex(product="pkg:generic/example/library"))
    install(sections, item)
    assert not claims(sections)
    assert item["application"]["unresolved"] == 1
    assert "unresolved_product_id" in item["application"]["statements"][0]["unresolved"][0]


def test_document_local_ref_cannot_bind_unrelated_sbom_without_component_identity():
    sections = inventory()
    item = record(cdx(components=False))
    install(sections, item)
    assert not claims(sections)
    assert item["application"]["unresolved"] == 1
    # An original CDX baseline can use its own document-local ref, even without
    # a package URL: the exact original content hash establishes that namespace.
    sections["inventory"]["baseline"]["artifact_sha"] = item["artifact_sha"]
    reconcile_evidence(sections)
    assert [item["ref"] for item in claims(sections)] == ["one"]


def test_evidence_received_before_inventory_reconciles_and_removed_component_does_not_delete_document():
    sections = {name: {} for name in SECTIONS}
    item = record(openvex())
    install(sections, item)
    assert not claims(sections) and item["application"]["unresolved"] == 1
    sections["inventory"] = inventory()["inventory"]
    reconcile_evidence(sections)
    assert len(claims(sections)) == 1
    before = copy.deepcopy(sections)
    reconcile_evidence(sections)
    assert sections == before
    sections["inventory"] = {}
    reconcile_evidence(sections)
    assert not claims(sections)
    assert item["document"]["raw"] == openvex()


@pytest.mark.parametrize("factory", [openvex, cdx, csaf])
def test_missing_not_affected_reason_stays_unresolved(factory):
    document = factory()
    if factory is openvex:
        document["statements"][0].pop("justification")
        document["statements"][0]["action_statement"] = "Upgrade later"
    elif factory is cdx:
        document["vulnerabilities"][0]["analysis"] = {"state": "not_affected"}
    else:
        document["vulnerabilities"][0].pop("threats")
    sections = inventory()
    item = record(document)
    install(sections, item)
    assert not claims(sections)
    assert "missing_not_affected_reason" in item["application"]["statements"][0]["unresolved"]


def test_external_conflicting_claims_remain_attributed_and_visible():
    sections = inventory()
    first = record(openvex())
    install(sections, first)
    second = record(openvex(status="affected", action_statement="Upgrade"))
    preview = preview_evidence(sections, second)
    assert preview["contradictions"] == [
        {"vulnerability_id": VULN, "ref": "one", "statuses": ["affected", "not_affected"]}
    ]
    install(sections, second)
    assert len(claims(sections)) == 2
    assert sections["assessments"]["human"]["state"] == "affected"


def test_cdx_vdr_without_analysis_keeps_advisory_without_inventing_status():
    document = cdx()
    document["vulnerabilities"][0].pop("analysis")
    document["vulnerabilities"][0]["description"] = "Supplier disclosure"
    sections = inventory()
    install(sections, record(document))
    assert len(claims(sections)) == 1
    assert claims(sections)[0]["advisory"]["normalized_status"] is None
    assert claims(sections)[0]["advisory"]["description"] == "Supplier disclosure"
    assert claims(sections)[0]["statement"]["raw"]["description"] == "Supplier disclosure"


@pytest.mark.parametrize(
    "modify",
    [
        lambda d: d["vulnerabilities"][0]["affects"][0].update(
            versions=[{"range": "vers:generic/<2", "status": "affected"}]
        ),
        lambda d: d["components"].append(copy.deepcopy(d["components"][0])),
    ],
)
def test_unsupported_or_ambiguous_cdx_scope_is_not_applied(modify):
    document = cdx()
    modify(document)
    sections = inventory()
    item = record(document)
    install(sections, item)
    assert not claims(sections)
    assert item["application"]["unresolved"] == 1


def test_openvex_subcomponent_product_context_is_not_flattened():
    document = openvex()
    document["statements"][0]["products"][0]["subcomponents"] = [{"@id": OTHER}]
    sections = inventory()
    install(sections, record(document))
    assert not claims(sections)


def test_csaf_group_impact_cannot_be_misapplied_to_other_product():
    document = csaf()
    document["vulnerabilities"][0]["threats"][0]["product_ids"] = ["different-product"]
    document["vulnerabilities"][0]["threats"][0]["group_ids"] = ["group-1"]
    sections = inventory()
    install(sections, record(document))
    assert not claims(sections)


def test_input_structure_and_duplicate_keys_rejected():
    for raw in [
        b"[]",
        b"not json",
        b'{"bomFormat":"CycloneDX","bomFormat":"other"}',
        b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":"bad"}',
    ]:
        with pytest.raises(ValueError):
            parse_evidence(raw)
    document = openvex()
    document["statements"][0]["products"] = ["bad"]
    with pytest.raises(ValueError):
        parse_evidence(json.dumps(document).encode())


def test_explicit_inactive_selection_preserves_original_but_removes_derived_claims():
    sections = inventory()
    item = record(openvex())
    install(sections, item)
    assert len(claims(sections)) == 1
    original = copy.deepcopy(item["document"])
    item["active"] = False
    reconcile_evidence(sections)
    assert not claims(sections)
    assert item["application"] == {
        "selection": "inactive",
        "matched": 0,
        "unresolved": 0,
        "statements": [],
    }
    assert item["document"] == original
    item["active"] = True
    reconcile_evidence(sections)
    assert len(claims(sections)) == 1


def test_non_utf8_and_nonfinite_numbers_are_rejected():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_evidence(json.dumps(openvex()).encode("utf-16"))
    with pytest.raises(ValueError, match="UTF-8"):
        parse_evidence(json.dumps(openvex()).replace('"version": 1', '"version": NaN').encode())
