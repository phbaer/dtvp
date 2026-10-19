"""Dependency display preserves graph references without exponential unfolding."""

from dtvp.knowledge.dependency_tree import dependency_tree


def graph():
    return {
        "inventory": {
            "root": {"bom-ref": "root", "name": "Application"},
            **{
                f"component:{ref}": {"bom-ref": ref, "name": ref}
                for ref in ("a", "b", "shared", "island")
            },
            "dependencies": {
                "edges": [
                    {"ref": "root", "dependsOn": ["b", "a", "a", "missing"]},
                    {"ref": "a", "dependsOn": ["shared"]},
                    {"ref": "b", "dependsOn": ["shared"]},
                    {"ref": "shared", "dependsOn": ["a"]},
                    {"ref": "island", "dependsOn": ["island"]},
                ]
            },
        },
        "vulnerabilities": {
            "first": {"ref": "shared", "identifier": "CVE-2099-10000"},
            "duplicate": {"ref": "shared", "identifier": "CVE-2099-10000"},
            "second": {"ref": "shared", "identifier": "CVE-2099-10001"},
        },
    }


def test_cycles_shared_missing_and_disconnected_components_remain_distinct():
    result = dependency_tree(graph(), max_depth=10)
    rows = result["items"]
    assert [row["component_ref"] for row in rows if row["depth"] == 0] == ["root", "island"]
    assert any(row["cycle"] and row["component_ref"] == "a" for row in rows)
    assert any(row["shared"] and row["component_ref"] == "shared" for row in rows)
    assert any(row["missing"] and row["component_ref"] == "missing" for row in rows)
    assert all(row["vulnerability_count"] == 2 for row in rows if row["component_ref"] == "shared")
    assert result["component_count"] == 5
    assert not result["truncated"]


def test_depth_does_not_turn_hidden_dependencies_into_disconnected_roots():
    result = dependency_tree(graph(), max_depth=0)
    assert [row["component_ref"] for row in result["items"]] == ["root", "island"]
    assert result["depth_limited"]
    subtree = dependency_tree(graph(), root_ref="b", max_depth=2)
    assert [row["component_ref"] for row in subtree["items"]] == ["b", "shared", "a"]
    assert subtree["items"][-1]["path"] == ["b", "shared", "a"]


def test_pagination_is_stable_and_hard_cap_is_explicit(monkeypatch):
    whole = dependency_tree(graph(), max_depth=10)
    pages = [
        dependency_tree(graph(), max_depth=10, offset=i, limit=1) for i in range(whole["total"])
    ]
    assert [page["items"][0] for page in pages] == whole["items"]
    assert pages[-1]["next_offset"] is None
    monkeypatch.setattr("dtvp.knowledge.dependency_tree.MAX_ROWS", 3)
    limited = dependency_tree(graph(), max_depth=10)
    assert limited["total"] == 3 and limited["truncated"] and limited["row_limit"] == 3


def test_empty_inventory_has_no_invented_root():
    result = dependency_tree({"inventory": {}, "vulnerabilities": {}})
    assert result["items"] == [] and result["total"] == 0


def test_shortest_paths_keep_both_shared_routes_and_ignore_cycles():
    from dtvp.knowledge.dependency_tree import dependency_paths

    result = dependency_paths(graph(), component_ref="shared", root_ref="root")
    assert [[node["component_ref"] for node in path] for path in result["paths"]] == [
        ["root", "a", "shared"],
        ["root", "b", "shared"],
    ]
    assert result["paths"][0][0]["component"]["name"] == "Application"
    assert not result["truncated"]
    focused = dependency_paths(graph(), component_ref="shared", root_ref="b")
    assert [[node["component_ref"] for node in path] for path in focused["paths"]] == [
        ["b", "shared"],
    ]
    assert dependency_paths(graph(), component_ref="island")["paths"] == []
    assert dependency_paths(graph(), component_ref="island", root_ref="root")["paths"] == []


def test_paths_limits_missing_metadata_and_root_component():
    import pytest

    from dtvp.knowledge.dependency_tree import dependency_paths

    result = dependency_paths(graph(), component_ref="shared", root_ref="root", limit=1)
    assert len(result["paths"]) == 1 and result["truncated"]
    assert dependency_paths(graph(), component_ref="missing")["paths"][0][-1]["missing"]
    root = dependency_paths(graph(), component_ref="root", root_ref="root")
    assert len(root["paths"]) == 1 and len(root["paths"][0]) == 1
    with pytest.raises(KeyError):
        dependency_paths(graph(), component_ref="absent")
    with pytest.raises(KeyError):
        dependency_paths(graph(), component_ref="a", root_ref="absent")
    with pytest.raises(ValueError):
        dependency_paths(graph(), component_ref="a", limit=51)


def test_path_search_is_bounded_and_does_not_unfold_longer_alternatives(monkeypatch):
    from dtvp.knowledge.dependency_tree import dependency_paths

    sections = graph()
    sections["inventory"]["dependencies"]["edges"].append({"ref": "root", "dependsOn": ["shared"]})
    result = dependency_paths(sections, component_ref="shared", root_ref="root")
    assert [[node["component_ref"] for node in path] for path in result["paths"]] == [
        ["root", "shared"]
    ]
    monkeypatch.setattr("dtvp.knowledge.dependency_tree.MAX_ROWS", 2)
    result = dependency_paths(graph(), component_ref="shared", root_ref="root")
    assert result["truncated"] and result["visited_count"] <= 2
    assert result["paths"] == []


def test_path_search_handles_depth_beyond_tree_pages_but_reports_its_own_cap():
    from dtvp.knowledge.dependency_tree import dependency_paths

    sections = {
        "inventory": {
            "dependencies": {
                "edges": [{"ref": f"n{i}", "dependsOn": [f"n{i + 1}"]} for i in range(102)]
            }
        },
        "vulnerabilities": {},
    }
    result = dependency_paths(sections, component_ref="n40", root_ref="n0")
    assert len(result["paths"][0]) == 41 and not result["truncated"]
    result = dependency_paths(sections, component_ref="n102", root_ref="n0")
    assert result["paths"] == [] and result["truncated"]
    assert result["visited_count"] == 101 and result["depth_limit"] == 100
