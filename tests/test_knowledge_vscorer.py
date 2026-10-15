"""Focused VScorer files preserve tree context and require original Base choices."""

import copy

import pytest

from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.storage import canonical, digest
from tests.test_knowledge_workspace import snapshot, source
from tests.test_knowledge_workspace import workspace as source_workspace
from tests.test_rescoring import BASE, VECTOR

workspace = source_workspace


def prepare(workspace):
    sections = workspace[1]
    sections["vulnerabilities"] = {
        "one": source("shared", "CVE-2099-10001", 9.8, "Description", "DT", vector=BASE),
        "two": source("other", "CVE-2099-10002", 9.8, "Another component", "DT", vector=BASE),
        "non-cve": source(
            "shared", "GHSA-example", 9.8, "Non-CVE evidence", "supplier", vector=BASE
        ),
    }
    sections["inventory"]["component:shared"]["properties"] = [
        {"name": "vscorer:threat-model-element-ids", "value": "API"}
    ]
    journal, state = snapshot(workspace)
    context = next(
        value
        for value in sections["ownership"].values()
        if value.get("component_ref") == "shared" and value["root_ref"] == "app-a"
    )
    return journal, state, context


def test_derived_files_have_full_tree_but_exact_component_cve_focus(workspace):
    journal, state, context = prepare(workspace)
    result = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    assert result["eligible"]
    sbom = result["sbom"]
    assert sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["bom-ref"] == "app-a"
    assert {component["bom-ref"] for component in sbom["components"]} == {"shared", "other"}
    assert next(component for component in sbom["components"] if component["bom-ref"] == "shared")[
        "properties"
    ] == [{"name": "vscorer:threat-model-element-ids", "value": "API"}]
    assert "vulnerabilities" not in sbom
    assert result["cves"]["cves"][0]["component_refs"] == ["shared"]
    assert len(result["cves"]["cves"]) == 1
    receipt = result["dtvp_source"]
    assert receipt["format"] == "dtvp.vscorer-source/1"
    assert receipt["state"] == state
    assert receipt["artifacts"] == {
        "sbom_sha256": digest(canonical(sbom)),
        "cves_sha256": digest(canonical(result["cves"])),
    }
    assert result["coverage"]["excluded"] == [
        {"vulnerability_id": "GHSA-example", "reason": "non_cve_identifier"}
    ]
    assert not result["coverage"]["all_context_vulnerabilities_included"]
    assert (
        derive_context_inputs(journal, state, context["id"], "shared", {"CVE-2099-10001": BASE})
        == result
    )


def test_unselected_original_base_never_implicitly_chosen(workspace):
    journal, state, context = prepare(workspace)
    result = derive_context_inputs(journal, state, context["id"], "shared", {})
    assert not result["eligible"]
    assert result["dtvp_source"] is None
    assert result["cves"] == {"cves": []}
    assert {entry["reason"] for entry in result["coverage"]["excluded"]} == {
        "non_cve_identifier",
        "explicit_base_selection_required",
    }


@pytest.mark.parametrize("selection", [VECTOR, BASE.replace("AV:N", "AV:P")])
def test_environmental_or_unasserted_base_rejected(workspace, selection):
    journal, state, context = prepare(workspace)
    with pytest.raises(ValueError, match="original source assertion"):
        derive_context_inputs(
            journal, state, context["id"], "shared", {"CVE-2099-10001": selection}
        )


def test_scope_mismatches_and_missing_topology_fail_closed(workspace):
    journal, state, context = prepare(workspace)
    with pytest.raises(ValueError, match="exact selected component"):
        derive_context_inputs(journal, state, context["id"], "other", {})
    with pytest.raises(ValueError, match="outside the selected context"):
        derive_context_inputs(journal, state, context["id"], "shared", {"CVE-2099-10002": BASE})
    for value in workspace[1]["ownership"].values():
        if value.get("id") == context["id"]:
            value["dependency_graph"] = "not_reported"
    journal, changed = snapshot(workspace)
    with pytest.raises(ValueError, match="reported dependency topology"):
        derive_context_inputs(journal, changed, context["id"], "shared", {})


def test_qualified_source_origins_are_not_invalid_cyclonedx_extensions(workspace):
    prepare(workspace)
    component = workspace[1]["inventory"]["component:shared"]
    component["dtvp_origin"] = {"part_id": "service", "ref": "old", "state": "f" * 64}
    component["components"] = [copy.deepcopy(workspace[1]["inventory"]["component:other"])]
    journal, state = snapshot(workspace)
    context = next(
        value
        for value in workspace[1]["ownership"].values()
        if value.get("component_ref") == "shared" and value["root_ref"] == "app-a"
    )
    result = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    shared = next(
        component for component in result["sbom"]["components"] if component["bom-ref"] == "shared"
    )
    assert "dtvp_origin" not in shared and "components" not in shared
    assert {entry["field"] for entry in result["coverage"]["conversions"]} == {
        "dtvp_origin",
        "components",
    }
