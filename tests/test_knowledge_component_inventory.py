"""Inventory counts occurrences separately from consuming contexts and findings."""

from copy import deepcopy

from dtvp.knowledge.component_inventory import inventory_page


def test_context_recurrence_delegation_and_exact_source_identity_survive_filters():
    sections = {
        "inventory": {
            "root": {"bom-ref": "root", "name": "App"},
            "component:a": {"bom-ref": "a", "name": "Shared", "purl": "pkg:generic/shared@1"},
            "component:b": {"bom-ref": "b", "name": "Shared", "purl": "pkg:generic/shared@1"},
            "part-root:part": {"bom-ref": "part", "name": "Constituent"},
            "dependencies": {"edges": [{"ref": "root", "dependsOn": ["a", "a", "missing"]}]},
        },
        "ownership": {
            "context:first": {
                "id": "first",
                "component_ref": "a",
                "status": "resolved",
                "team_scope": {"A": True},
                "delegated": True,
            },
            "context:second": {
                "id": "second",
                "component_ref": "a",
                "status": "resolved",
                "team_scope": {"A": True},
                "delegated": False,
            },
            "context:third": {
                "id": "third",
                "component_ref": "b",
                "status": "topology_unknown",
                "team_scope": {"B": True},
                "delegated": False,
            },
        },
    }
    before = deepcopy(sections)
    page = inventory_page(sections, q="SHARED", limit=1)
    assert page["statistics"] == {
        "component_occurrences": 2,
        "consuming_contexts": 3,
        "all_component_occurrences": 4,
    }
    assert page["next_offset"] == 1
    assert page["items"][0]["component_ref"] == "a"
    assert page["items"][0]["incoming_declared"] == 1
    assert inventory_page(sections, q="shared", offset=1)["items"][0]["component_ref"] == "b"
    delegated = inventory_page(sections, ownership="delegated", team_id="A")
    assert delegated["statistics"]["component_occurrences"] == 1
    assert delegated["items"][0]["context_count"] == 2
    assert (
        inventory_page(sections, ownership="no_context")["statistics"]["component_occurrences"] == 2
    )
    assert sections == before


def test_core_pagination_bounds_and_limitations_do_not_leak_mutability():
    import pytest

    sections = {"inventory": {}, "ownership": {}}
    for offset, limit in [(-1, 1), (0, 0), (0, 201)]:
        with pytest.raises(ValueError):
            inventory_page(sections, offset=offset, limit=limit)
    first = inventory_page(sections)
    first["limitations"].clear()
    assert inventory_page(sections)["limitations"]
