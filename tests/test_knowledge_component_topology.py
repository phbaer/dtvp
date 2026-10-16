"""Paging never drops unresolved references or invents semantic edges."""

import pytest

from dtvp.knowledge.component_topology import neighbor_page


def test_stable_deduplicated_pages_and_search_preserve_unknown_references():
    inventory = {
        "root": {"bom-ref": "app", "name": "Application"},
        "component:library": {"bom-ref": "library", "name": "Library", "version": "2"},
        "dependencies": {
            "edges": [
                {"ref": "app", "dependsOn": ["missing", "library", "library"]},
                {"ref": "app", "dependsOn": ["library"]},
                {"ref": "library", "dependsOn": ["app"]},
            ]
        },
        "relationships": {"items": [{"from": "app", "to": "contained", "type": "CONTAINS"}]},
    }
    first = neighbor_page(inventory, "app", "outgoing", limit=1)
    assert first["total"] == first["declared_total"] == 2
    assert first["items"][0]["ref"] == "library" and first["next_offset"] == 1
    second = neighbor_page(inventory, "app", "outgoing", offset=1, limit=1)
    assert second["items"] == [{"ref": "missing", "name": "", "version": "", "resolved": False}]
    assert second["next_offset"] is None
    selected = neighbor_page(inventory, "app", "outgoing", q=" LIBRARY ")
    assert selected["total"] == 1 and selected["declared_total"] == 2
    assert neighbor_page(inventory, "app", "incoming")["items"][0]["ref"] == "library"
    assert first["dependency_graph"] == "unknown"
    assert not neighbor_page(inventory, "app", "outgoing", offset=99)["items"]


@pytest.mark.parametrize("options", [{"limit": 0}, {"limit": 201}, {"offset": -1}])
def test_invalid_page_is_rejected(options):
    with pytest.raises(ValueError):
        neighbor_page({}, "app", "outgoing", **options)


def test_direction_and_missing_graph_are_explicit():
    with pytest.raises(ValueError):
        neighbor_page({}, "app", "transitive")
    page = neighbor_page({"baseline": {"dependency_graph": "not_reported"}}, "app", "incoming")
    assert page["total"] == 0 and page["dependency_graph"] == "not_reported"
    assert "non-use" in page["limitations"][0]
