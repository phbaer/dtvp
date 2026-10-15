"""License declarations never silently become clearance or known completeness."""

import json

import pytest

from dtvp.knowledge.licenses import component_licenses, license_worklist
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace


def spdx(**facts):
    return {"properties": [{"name": "dtvp:spdx-source", "value": json.dumps(facts)}]}


def test_spdx_declared_and_concluded_remain_distinct_source_claims():
    evidence = component_licenses(
        spdx(
            licenseDeclared="MIT OR Apache-2.0",
            licenseConcluded="NOASSERTION",
            licenseInfoFromFiles=["LicenseRef-Custom"],
        ),
        {"format": "spdx-2.3-json"},
    )
    assert evidence["status"] == "reported"
    assert [(item["source_field"], item["status"]) for item in evidence["facts"]] == [
        ("licenseDeclared", "reported"),
        ("licenseConcluded", "unknown"),
        ("licenseInfoFromFiles", "reported"),
    ]
    assert evidence["facts"][0]["value"] == "MIT OR Apache-2.0"


def test_none_noassertion_and_absent_have_different_meanings():
    baseline = {"format": "spdx-2.3-json"}
    assert component_licenses(spdx(licenseDeclared="NONE"), baseline)["status"] == "explicit_none"
    assert component_licenses(spdx(licenseDeclared="NOASSERTION"), baseline)["status"] == "unknown"
    assert component_licenses(spdx(), baseline)["status"] == "not_reported"
    assert component_licenses({}, baseline)["status"] == "malformed"


def test_lookalike_spdx_property_does_not_override_cyclonedx_license_evidence():
    component = spdx(licenseConcluded="MIT")
    component["licenses"] = [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}]
    result = component_licenses(component, {"format": "cyclonedx-json"})
    assert result["facts"][0]["value"] == component["licenses"][0]
    assert len(result["facts"]) == 1


@pytest.mark.parametrize("licenses", [None, [], "MIT", [None], [{"license": {}}]])
def test_missing_or_malformed_cyclonedx_licenses_stay_explicit(licenses):
    result = component_licenses({"licenses": licenses}, {"format": "cyclonedx-json"})
    assert result["status"] == ("not_reported" if licenses in (None, []) else "malformed")


def test_pinned_worklist_counts_before_paging_and_does_not_clear_components(workspace):
    journal, sections = workspace
    sections["inventory"]["component:shared"]["licenses"] = [{"license": {"id": "MIT"}}]
    journal, state = snapshot(workspace)
    page = license_worklist(journal, state, limit=1)
    full = license_worklist(journal, state, limit=200)
    assert page["total"] == len(full["items"]) > 1
    assert page["statistics"] == full["statistics"]
    assert page["statistics"]["by_evidence_status"]["reported"] == 1
    assert all(item["clearance"] == "not_assessed" for item in full["items"])
    assert full["limitations"]
    before = full
    sections["inventory"]["component:shared"]["licenses"] = [{"license": {"name": "Proprietary"}}]
    snapshot(workspace)
    assert license_worklist(journal, state, limit=200) == before


def test_multipart_uses_pinned_constituent_format_and_coverage(workspace):
    journal, sections = workspace
    sections["inventory"]["component:shared"].update(spdx(licenseDeclared="BSD-3-Clause"))
    sections["inventory"]["component:shared"]["dtvp_origin"] = {
        "part_id": "supplier",
        "ref": "shared",
        "state": "a" * 64,
    }
    sections["inventory"]["assembly"] = {
        "parts": [
            {
                "part_id": "supplier",
                "baseline": {
                    "format": "spdx-2.3-json",
                    "artifact_sha": "b" * 64,
                    "collection": {"license_coverage": "partial"},
                },
            }
        ]
    }
    journal, state = snapshot(workspace)
    row = next(
        item
        for item in license_worklist(journal, state)["items"]
        if item["component_ref"] == "shared"
    )
    assert row["evidence"]["facts"][0]["value"] == "BSD-3-Clause"
    assert row["source"]["format"] == "spdx-2.3-json"
    assert row["declared_license_coverage"] == "partial"
    assert row["clearance"] == "not_assessed"
