"""The editable 5000-advisory fixture stays deterministic and within real loader bounds."""

import json
from collections import Counter
from pathlib import Path

from dtvp.knowledge.demo_scenarios import DemoScenario
from dtvp.knowledge.journal import SECTIONS
from dtvp.knowledge.ownership import resolve_ownership
from scripts.generate_scale_scenario import PARTITIONS, ROOTS, VERSION, VULNERABILITIES, scenario

FIXTURE = Path(__file__).resolve().parents[1] / "playground/scenarios/scale-5000.json"


def loaded():
    return DemoScenario.model_validate_json(FIXTURE.read_bytes())


def test_checked_in_payload_is_complete_deterministic_editable_data():
    generated = scenario()
    assert FIXTURE.read_text() == json.dumps(generated, indent=2, ensure_ascii=False) + "\n"
    data = loaded()
    assert data.synthetic and data.fixture_id == "native-scale-5000/1"
    assert data.selected_version == VERSION
    assert len(data.baselines) == 1 and not data.updates
    assert not data.assessments and not data.tags and not data.licenses
    assert not data.vscorer_proposals and not data.code_analysis
    assert len(data.baselines[0].sbom["components"]) == 402
    context = data.baselines[0].context
    assert {context.package_coverage, context.dependency_coverage, context.license_coverage} == {
        "unknown"
    }
    assert context.limitations


def test_5000_distinct_ids_have_real_refs_and_valid_source_base_claims():
    from dtvp.rescoring import base_fact

    sbom = loaded().baselines[0].sbom
    refs = {item["bom-ref"] for item in sbom["components"]}
    findings = sbom["vulnerabilities"]
    assert len(findings) == VULNERABILITIES == 5000
    assert len({item["id"] for item in findings}) == 5000
    assert all(item["id"].startswith("CVE-2099-") for item in findings)
    assert all(item["source"]["name"] == "DTVP synthetic scale fixture" for item in findings)
    assert all(len(item["affects"]) == 1 and item["affects"][0]["ref"] in refs for item in findings)
    ratings = {
        (rating["vector"], rating["score"]) for item in findings for rating in item["ratings"]
    }
    assert len(ratings) == 4 and all(base_fact(vector, score) for vector, score in ratings)
    per_library = Counter(item["affects"][0]["ref"] for item in findings)
    assert len(per_library) == 400 and set(per_library.values()) == {12, 13}


def test_branching_shared_dependencies_and_delegation_produce_6000_review_targets():
    data = loaded()
    sbom = data.baselines[0].sbom
    graph = {item["ref"]: item["dependsOn"] for item in sbom["dependencies"]}
    refs = {item["bom-ref"] for item in sbom["components"]} | {"product"}
    assert set(graph) == refs
    assert all(child in refs for children in graph.values() for child in children)
    assert graph[ROOTS[0]] == ["platform-000", "shared-000"]
    assert graph[ROOTS[1]] == ["operations-000", "shared-000"]
    for prefix, count in PARTITIONS:
        assert graph[prefix + "-000"] == [prefix + "-001", prefix + "-002"]
        assert not graph[f"{prefix}-{count - 1:03}"]
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {
        "baseline": {"dependency_graph": "reported"},
        "root": sbom["metadata"]["component"],
        "dependencies": {"edges": sbom["dependencies"]},
        **{"component:" + component["bom-ref"]: component for component in sbom["components"]},
    }
    resolve_ownership(
        sections,
        version=VERSION,
        config={
            "rules": [
                {"selector": rule.selector, "team_id": rule.team} for rule in data.ownership.rules
            ],
            "context_roots": data.ownership.context_roots,
        },
    )
    contexts = [item for key, item in sections["ownership"].items() if key.startswith("context:")]
    assert len(contexts) == 482
    assert {item["root_ref"] for item in contexts} == set(ROOTS)
    assert all(item["status"] == "resolved" for item in contexts)
    delegated = next(item for item in contexts if item["component_ref"] == "platform-001")
    assert delegated["root_ref"] == ROOTS[0] and delegated["team_id"] == "Operations"
    occurrences = Counter(item["component_ref"] for item in contexts)
    review_targets = sum(occurrences[item["affects"][0]["ref"]] for item in sbom["vulnerabilities"])
    assert review_targets == 6000
