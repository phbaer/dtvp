"""Same-artifact observations enrich proposals without changing authority or reviews."""

from copy import deepcopy

import pytest

from dtvp.knowledge import observation_graph as module


def component(ref, *, name="library", version="1", purl=True, **metadata):
    return {
        "bom-ref": ref,
        "type": "library",
        "name": name,
        "version": version,
        **({"purl": f"pkg:pypi/{name}@{version}"} if purl else {}),
        **metadata,
    }


def inventory(prefix="", *, part_id="runtime", collection=None):
    root = component(prefix + "root", name="application")
    library = component(prefix + "library")
    return {
        "baseline": {
            "part_id": part_id,
            "artifact_sha": prefix + "raw",
            "collection": collection
            or {
                "subject_kind": "container",
                "target": "image",
                "subject_digest": "sha256:" + "a" * 64,
            },
        },
        "root": root,
        "component:library": library,
        "relationships": {
            "items": [
                {
                    "from": root["bom-ref"],
                    "to": library["bom-ref"],
                    "kind": "DEPENDS_ON",
                    "origin": "synthetic",
                }
            ]
        },
        "dependencies": {"edges": [{"ref": root["bom-ref"], "dependsOn": [library["bom-ref"]]}]},
    }


def test_unique_same_subject_matches_and_typed_edges_retain_support_without_mutating():
    authority, observation = inventory(), inventory("other-")
    originals = deepcopy([authority, observation])
    result = module.propose_observation(authority, observation)
    assert result["status"] == "proposals_only"
    assert {row["observation_ref"]: row["authority_ref"] for row in result["mapping"]} == {
        "other-library": "library",
        "other-root": "root",
    }
    assert result["summary"]["authority_typed_edges"] == 1
    assert len(result["edge_support"]) == 1
    assert len(result["edge_support"][0]["authority_support"]) == 2
    assert len(result["edge_support"][0]["observation_support"]) == 2
    assert result["topology_proposals"] == []
    assert result["component_proposals"] == []
    assert result == module.propose_observation(deepcopy(authority), deepcopy(observation))
    assert [authority, observation] == originals


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("unknown", "subject_digest_unknown"),
        ("digest", "subject_digest_changed"),
        ("scope", "collection_scope_changed"),
        ("part", "delivery_part_changed"),
        ("assembly", "individual_delivery_part_required"),
    ],
)
def test_unknown_or_changed_subject_and_scope_block(change, reason):
    authority, observation = inventory(), inventory("other-")
    baseline = observation["baseline"]
    if change == "unknown":
        baseline["collection"].pop("subject_digest")
    elif change == "digest":
        baseline["collection"]["subject_digest"] = "sha256:" + "b" * 64
    elif change == "scope":
        baseline["collection"]["configuration"] = "different-build"
    elif change == "part":
        baseline["part_id"] = "another-part"
    else:
        baseline["kind"] = "assembly"
    result = module.propose_observation(authority, observation)
    assert result["status"] == "blocked"
    assert reason in result["blocked_reasons"]
    assert result["mapping"] == result["edge_support"] == []


def test_metadata_is_attributed_including_conflicts_and_missing_fields():
    authority, observation = inventory(), inventory("other-")
    authority["component:library"]["description"] = "Authority description"
    observation["component:library"].update(
        description="Different description", licenses=[{"license": {"id": "MIT"}}]
    )
    result = module.propose_observation(authority, observation)
    assertions = {row["field"]: row for row in result["supplemental_assertions"]}
    assert assertions["description"]["status"] == "conflict"
    assert assertions["description"]["authority_value"] == "Authority description"
    assert assertions["licenses"]["status"] == "additional_information"
    assert "licenses" not in authority["component:library"]
    assert result["summary"]["field_conflicts"] == 1


def test_added_components_topology_and_missing_edges_do_not_modify_baseline():
    authority, observation = inventory(), inventory("other-")
    observation["component:extra"] = component("extra", name="extra")
    observation["relationships"]["items"] = [
        {"from": "other-library", "to": "other-root", "kind": "DEPENDS_ON"},
        {"from": "other-root", "to": "other-library", "kind": "CONTAINS"},
        {"from": "other-root", "to": "extra", "kind": "DEPENDS_ON"},
    ]
    observation["dependencies"]["edges"] = []
    result = module.propose_observation(authority, observation)
    assert result["component_proposals"] == [
        {"observation_ref": "extra", "reason": "unresolved_occurrence_identity"}
    ]
    assert {item["reason"] for item in result["topology_proposals"]} == {
        "additional_topology",
        "relationship_kind_differs",
        "unresolved_endpoint",
    }
    assert result["summary"]["authority_edges_without_observation_support"] == 1
    assert "component:extra" not in authority


@pytest.mark.parametrize("change", ["version", "digest", "name_only", "duplicate", "role"])
def test_identity_conflicts_missing_markers_and_duplicate_occurrences_stay_distinct(change):
    authority, observation = inventory(), inventory("other-")
    if change == "version":
        observation["component:library"] = component("other-library", version="2")
    elif change == "digest":
        authority["component:library"]["hashes"] = [{"alg": "SHA-256", "content": "b" * 64}]
        observation["component:library"]["hashes"] = [{"alg": "SHA-256", "content": "c" * 64}]
    elif change == "name_only":
        authority["component:library"].pop("purl")
        observation["component:library"].pop("purl")
    elif change == "duplicate":
        observation["component:duplicate"] = component("other-copy")
    else:
        observation["root"] = component("other-root")
        observation.pop("component:library")
    result = module.propose_observation(authority, observation)
    assert all(item["authority_ref"] != "library" for item in result["mapping"])
    assert result["component_proposals"]


@pytest.mark.parametrize("location_field", ["install_path", "instance_id", "occurrences"])
def test_installation_contexts_require_agreement(location_field):
    authority, observation = inventory(), inventory("other-")
    if location_field == "occurrences":
        authority["component:library"]["evidence"] = {"occurrences": [{"location": "/one"}]}
        observation["component:library"]["evidence"] = {"occurrences": [{"location": "/two"}]}
    else:
        authority["component:library"][location_field] = "/one"
        observation["component:library"][location_field] = "/two"
    result = module.propose_observation(authority, observation)
    assert result["summary"]["matched_occurrences"] == 1
    observation["component:library"] = {
        **observation["component:library"],
        **{
            key: deepcopy(authority["component:library"][key])
            for key in ("evidence", location_field)
            if key in authority["component:library"]
        },
    }
    assert module.propose_observation(authority, observation)["summary"]["matched_occurrences"] == 2


def test_scoped_artifact_digest_without_purl_can_establish_match():
    authority, observation = inventory(), inventory("other-")
    for value in (authority, observation):
        value["component:library"].pop("purl")
        value["component:library"]["hashes"] = [{"alg": "SHA-256", "content": "c" * 64}]
    result = module.propose_observation(authority, observation)
    assert (
        next(item for item in result["mapping"] if item["observation_ref"] == "other-library")[
            "basis"
        ]
        == "scoped_strong_digest"
    )


def test_diagnostics_are_bounded_but_counts_complete():
    authority, observation = inventory(), inventory("other-")
    for index in range(250):
        observation[f"component:{index}"] = component(
            f"missing-{index}", name=f"missing-{index}", purl=False
        )
    result = module.propose_observation(authority, observation)
    assert len(result["diagnostics"]) == 200
    assert result["diagnostics_truncated"]
    assert result["summary"]["unresolved_occurrences"] == 250
    assert len(result["component_proposals"]) == 250


def test_bounds_and_invalid_topology_fail_closed(monkeypatch):
    authority, observation = inventory(), inventory("other-")
    monkeypatch.setattr(module, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="bound"):
        module.propose_observation(authority, observation)
    monkeypatch.setattr(module, "MAX_ENTRIES", 100_000)
    observation["relationships"]["items"][0]["to"] = None
    with pytest.raises(ValueError, match="typed observation"):
        module.propose_observation(authority, observation)


@pytest.mark.parametrize(
    "field", ["baseline", "root", "dependencies", "relationships", "evidence", "dtvp_origin"]
)
def test_malformed_optional_documents_are_rejected(field):
    authority, observation = inventory(), inventory("other-")
    if field in {"evidence", "dtvp_origin"}:
        observation["component:library"][field] = []
    else:
        observation[field] = []
    with pytest.raises(ValueError, match="Invalid observation"):
        module.propose_observation(authority, observation)


def test_unresolved_authority_endpoint_rejected_and_report_bytes_bounded(monkeypatch):
    authority, observation = inventory(), inventory("other-")
    authority["relationships"]["items"][0]["to"] = "missing"
    with pytest.raises(ValueError, match="Authority topology"):
        module.propose_observation(authority, observation)
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValueError, match="report byte bound"):
        module.propose_observation(inventory(), observation)


def test_report_assertion_values_are_detached_from_original_inputs():
    authority, observation = inventory(), inventory("other-")
    observation["component:library"]["licenses"] = [{"license": {"id": "MIT"}}]
    report = module.propose_observation(authority, observation)
    report["supplemental_assertions"][0]["observation_value"][0]["license"]["id"] = "changed"
    assert observation["component:library"]["licenses"][0]["license"]["id"] == "MIT"
