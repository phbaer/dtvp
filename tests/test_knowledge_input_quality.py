"""Input observations stay pinned, attributed and distinct from correctness claims."""

import json

from dtvp.knowledge.input_quality import input_quality
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace


def test_full_statistics_and_digest_ignore_pagination_and_search_without_writes(workspace):
    journal, sections = workspace
    sections["inventory"]["component:shared"].pop("version")
    sections["inventory"]["component:shared"].pop("purl")
    _, state = snapshot(workspace)
    before = journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))
    full = input_quality(journal, state, limit=200)
    page = input_quality(journal, state, code="version_not_reported", q="shared", limit=1)
    assert page["statistics"] == full["statistics"]
    assert page["report_digest"] == full["report_digest"]
    assert page["total"] == 1 and len(page["items"]) == 1
    assert page["items"][0]["component_ref"] == "shared"
    assert full["statistics"]["occurrences"] == 5
    assert full["statistics"]["by_role"] == {"inventory_component": 4, "metadata_root": 1}
    assert full["statistics"]["inventory_components"]["components"] == 4
    assert (journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))) == before
    sections["inventory"]["component:shared"]["version"] = "new"
    snapshot(workspace)
    assert input_quality(journal, state, limit=200) == full


def test_pinned_constituent_formats_keep_noassertion_none_missing_and_malformed_distinct(workspace):
    journal, sections = workspace
    inventory = sections["inventory"]
    inventory["assembly"] = {
        "readiness": "unverified",
        "parts": [
            {
                "part_id": "supplier",
                "state": "a" * 64,
                "availability": "selected",
                "required": True,
                "baseline": {
                    "format": "spdx-2.3-json",
                    "source": "supplier-build",
                    "dependency_graph": "not_reported",
                    "collection": {
                        "package_coverage": "reported_complete",
                        "license_coverage": "partial",
                    },
                },
            }
        ],
    }
    for ref, license in zip(
        ("app-a", "app-b", "shared", "other"), ("NOASSERTION", "NONE", "MIT", None), strict=True
    ):
        component = inventory["component:" + ref]
        component["dtvp_origin"] = {"part_id": "supplier", "state": "a" * 64, "ref": ref}
        if license:
            component["properties"] = [
                {"name": "dtvp:spdx-source", "value": json.dumps({"licenseDeclared": license})}
            ]
    _, state = snapshot(workspace)
    report = input_quality(journal, state, limit=200)
    counts = report["statistics"]["inventory_components"]
    assert {
        key: counts[key]
        for key in (
            "license_unknown",
            "license_explicit_none",
            "license_reported",
            "license_malformed",
        )
    } == dict(license_unknown=1, license_explicit_none=1, license_reported=1, license_malformed=1)
    claims = [item for item in report["items"] if item["code"] == "license_noassertion_reported"]
    assert claims[0]["source_id"] == "part:supplier"
    source = report["sources"][0]
    assert source["state"] == "a" * 64 and source["coverage_verification"] == "not_verified"
    assert source["collection"]["package_coverage"] == "reported_complete"
    assert source["collection"]["license_coverage"] == "partial"
    assert report["statistics"]["by_code"]["assembly_not_declared_ready"] == 1
    # No matching current source pointer is consulted or required by this pure report.
    assert input_quality(journal, state, limit=200) == report


def test_unresolved_relationships_are_not_promoted_to_dependencies(workspace):
    journal, sections = workspace
    inventory = sections["inventory"]
    inventory["dependencies"] = {
        "edges": [
            {"ref": "shared", "dependsOn": ["missing"]},
            {"ref": "unknown-empty", "dependsOn": []},
        ]
    }
    inventory["relationships"] = {
        "items": [
            {"from": "shared", "to": "external-document", "kind": "CONTAINS", "origin": "spdx"}
        ]
    }
    _, state = snapshot(workspace)
    result = input_quality(journal, state, limit=200)
    assert result["statistics"]["unique_dependency_edges"] == 1
    assert result["statistics"]["unresolved_dependency_refs"] == 2
    assert result["statistics"]["by_code"]["relationship_reference_external_or_unresolved"] == 1
    assert all(
        item["source_id"] == "baseline" for item in result["items"] if "reference" in item["code"]
    )


def test_empty_withdrawn_and_incomplete_assemblies_never_look_like_clean_zero(workspace):
    journal, sections = workspace
    sections["inventory"] = {"baseline": {"withdrawn": True}}
    _, state = snapshot(workspace)
    report = input_quality(journal, state)
    assert report["baseline_status"] == "withdrawn"
    assert report["statistics"]["occurrences"] == 0
    assert report["statistics"]["by_code"]["baseline_withdrawn"] == 1
    assert report["statistics"]["by_code"]["no_inventory_occurrences_reported"] == 1
    sections["inventory"] = {
        "baseline": {"kind": "assembly"},
        "assembly": {
            "readiness": "incomplete",
            "parts": [
                {
                    "part_id": "required",
                    "required": True,
                    "state": None,
                    "availability": "unavailable",
                }
            ],
        },
    }
    _, state = snapshot(workspace)
    report = input_quality(journal, state)
    assert report["statistics"]["by_code"]["required_part_unavailable"] == 1
    assert report["statistics"]["by_code"]["assembly_not_declared_ready"] == 1


def test_same_root_component_ref_has_explicit_roles_without_double_counting_occurrence(workspace):
    journal, sections = workspace
    sections["inventory"]["root"] = sections["inventory"]["component:app-a"]
    sections["inventory"]["component:app-a"]["purl"] = "pkg:generic/app-a@2"
    _, state = snapshot(workspace)
    report = input_quality(journal, state, limit=200)
    assert report["statistics"]["occurrences"] == 4
    assert report["statistics"]["by_role"]["metadata_root"] == 1
    assert report["statistics"]["inventory_components"]["components"] == 4
    issue = next(
        item for item in report["items"] if item["code"] == "declared_version_conflicts_with_purl"
    )
    assert issue["roles"] == ["inventory_component", "metadata_root"]
