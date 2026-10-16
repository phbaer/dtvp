"""Official schema validation remains optional and distinct from evidence application."""

import copy
import json

import pytest
from referencing.exceptions import NoSuchResource

from dtvp.knowledge.schema_validation import PROFILES, ROOT, _resources, validate_schema
from dtvp.storage import canonical, digest


def document(profile):
    if profile.startswith("cyclonedx"):
        return {"bomFormat": "CycloneDX", "specVersion": profile.split("-")[1], "version": 1}
    if profile.startswith("openvex"):
        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.test/vex/1",
            "author": "Producer",
            "timestamp": "2026-10-16T12:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2026-1234"},
                    "products": [{"@id": "pkg:generic/example@1"}],
                    "status": "fixed",
                }
            ],
        }
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Supplier report",
            "publisher": {
                "category": "vendor",
                "name": "Producer",
                "namespace": "https://example.test",
            },
            "tracking": {
                "current_release_date": "2026-10-16T12:00:00Z",
                "id": "supplier-1",
                "initial_release_date": "2026-10-16T12:00:00Z",
                "status": "final",
                "version": "1",
                "revision_history": [
                    {"date": "2026-10-16T12:00:00Z", "number": "1", "summary": "Initial"}
                ],
            },
        }
    }


@pytest.mark.parametrize("profile", PROFILES)
def test_official_schemas_validate_versioned_documents_and_retain_exact_closure(profile):
    source = document(profile)
    before = copy.deepcopy(source)
    report = validate_schema(source, profile)
    assert report["valid"], report["diagnostics"]
    assert source == before
    assert not report["committed"]
    assert report["signature_verification"] == report["semantic_validation"] == "not_performed"
    assert len(report["schema_resources"]) == 10
    assert report["schema_resources_digest"] == digest(canonical(report["schema_resources"]))
    assert report["report_digest"] == digest(
        canonical({key: value for key, value in report.items() if key != "report_digest"})
    )
    assert all(len(row["sha256"]) == 64 for row in report["schema_resources"])


@pytest.mark.parametrize("profile", PROFILES)
def test_full_schema_rejects_missing_required_fields_with_paths_not_untrusted_values(profile):
    source = document(profile)
    source.pop(
        "document"
        if profile.startswith("csaf")
        else "@id"
        if profile.startswith("openvex")
        else "bomFormat"
    )
    source["private"] = "Never echo this secret evidence value"
    report = validate_schema(source, profile)
    assert not report["valid"]
    assert any(row["code"] == "required" for row in report["diagnostics"])
    assert "Never echo" not in json.dumps(report)
    assert report["schema_validation"] == "pinned_official_json_schema_only"


def test_csaf_cvss_reference_uses_vendored_first_schema():
    source = document("csaf-2.0-json-schema/1")
    source["vulnerabilities"] = [
        {
            "cve": "CVE-2026-1234",
            "scores": [
                {
                    "products": ["pkg-1"],
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ],
        }
    ]
    report = validate_schema(source, "csaf-2.0-json-schema/1")
    assert report["valid"], report["diagnostics"]
    source["vulnerabilities"][0]["scores"][0]["cvss_v3"]["baseScore"] = 11
    assert not validate_schema(source, "csaf-2.0-json-schema/1")["valid"]


def test_cdx_license_and_structured_signature_resolve_locally_without_verifying_signatures():
    source = document("cyclonedx-1.6-json-schema/1")
    source["components"] = [
        {"type": "library", "name": "library", "licenses": [{"license": {"id": "MIT"}}]}
    ]
    source["signature"] = {"algorithm": "HS256", "value": "ZmFrZQ"}
    report = validate_schema(source, "cyclonedx-1.6-json-schema/1")
    assert report["valid"], report["diagnostics"]
    assert report["signatures_present"] is True
    assert report["signature_verification"] == "not_performed"
    source["components"][0]["licenses"][0]["license"]["id"] = "Not-A-Real-SPDX-License"
    assert not validate_schema(source, "cyclonedx-1.6-json-schema/1")["valid"]


def test_registry_cannot_retrieve_remote_or_local_unregistered_references():
    _, _, registry = _resources()
    for uri in ("https://attacker.invalid/schema", "file:///etc/passwd"):
        with pytest.raises(NoSuchResource):
            registry.get_or_retrieve(uri)


def test_bundled_schema_hash_mismatch_fails_closed(tmp_path, monkeypatch):
    import dtvp.knowledge.schema_validation as module

    manifest = json.loads((ROOT / "sources.json").read_bytes())
    (tmp_path / "sources.json").write_text(json.dumps(manifest))
    (tmp_path / manifest["resources"][0]["file"]).write_text("{}")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    _resources.cache_clear()
    try:
        with pytest.raises(ValueError, match="pinned digest"):
            validate_schema({}, "csaf-2.0-json-schema/1")
    finally:
        _resources.cache_clear()


@pytest.mark.parametrize("kind", ["deep", "nodes", "string", "profile"])
def test_schema_validation_budgets_and_profiles_are_explicit(kind):
    source = document("cyclonedx-1.6-json-schema/1")
    profile = "cyclonedx-1.6-json-schema/1"
    if kind == "deep":
        item = source
        for _ in range(65):
            item["nested"] = {}
            item = item["nested"]
    elif kind == "nodes":
        source["too_many"] = [None] * 100_001
    elif kind == "string":
        source["too_long"] = "x" * 65537
    else:
        profile = "arbitrary-remote-schema"
    with pytest.raises(ValueError):
        validate_schema(source, profile)


def test_many_failures_cap_diagnostics_explicitly_without_changing_invalid_result():
    source = document("cyclonedx-1.6-json-schema/1")
    source["components"] = [{"type": "not-a-type", "name": "library"} for _ in range(100)]
    report = validate_schema(source, "cyclonedx-1.6-json-schema/1")
    assert not report["valid"]
    assert len(report["diagnostics"]) == 64 and report["diagnostics_truncated"]


def test_readonly_schema_endpoint_keeps_publications_and_intake_profiles_unchanged(analyst, app):
    from dtvp.knowledge.evidence_conformance import PROFILES as consumed_profiles

    before = app.state.knowledge.references()
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    response = analyst.post(
        f"/api/v3/projects/{project}/evidence/schema-validation",
        json={
            "document": document("cyclonedx-1.6-json-schema/1"),
            "validation_profile": "cyclonedx-1.6-json-schema/1",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["valid"] and response.json()["committed"] is False
    assert app.state.knowledge.references() == before
    assert not set(PROFILES) & set(consumed_profiles)
    assert (
        analyst.post(
            f"/api/v3/projects/{project}/evidence/conformance",
            json={
                "document": document("cyclonedx-1.6-json-schema/1"),
                "validation_profile": "cyclonedx-1.6-json-schema/1",
            },
        ).status_code
        == 422
    )
