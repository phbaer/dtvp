"""Context graph regressions, including bounded owner propagation on long chains."""

import random

from dtvp.knowledge.ownership import (
    boundary_masks,
    reachable,
    resolve_ownership,
    selected_boundaries,
    source_roots,
)


def resolve(edges, owners, *, roots=None, declared=None):
    refs = set(edges) | {child for children in edges.values() for child in children}
    sections = {
        "inventory": {
            "baseline": {"dependency_graph": "reported"},
            "dependencies": {
                "edges": [{"ref": ref, "dependsOn": children} for ref, children in edges.items()]
            },
            **{f"component:{ref}": {"bom-ref": ref, "name": ref} for ref in refs},
            **({"root": {"bom-ref": declared, "name": declared}} if declared else {}),
        }
    }
    config = {
        "rules": [{"selector": ref, "team_id": team} for ref, team in owners.items()],
        "context_roots": {"1": roots} if roots is not None else {},
    }
    resolve_ownership(sections, version="1", config=config)
    ownership = sections["ownership"]
    contexts = {
        (value["root_ref"], value["component_ref"]): value
        for key, value in ownership.items()
        if key.startswith("context:")
    }
    return contexts, ownership["summary"]


def test_inferred_roots_each_keep_shared_dependency_context():
    contexts, summary = resolve({"a": ["x"], "b": ["x"]}, {"a": "A", "b": "B"})
    assert contexts["a", "x"]["team_id"] == "A"
    assert contexts["b", "x"]["team_id"] == "B"
    assert summary["contexts"] == 4


def test_declared_root_does_not_remove_shared_subject_from_disconnected_tree():
    contexts, _ = resolve(
        {"p": ["x"], "d": ["x"]}, {"p": "P", "d": "D"}, declared="p"
    )
    assert contexts["p", "x"]["team_id"] == "P"
    assert contexts["d", "x"]["team_id"] == "D"


def test_configured_roots_exclude_aggregate_but_retain_disconnected_data():
    contexts, summary = resolve(
        {"product": ["a", "b"], "a": ["x"], "b": ["x"], "other": []},
        {"a": "A", "b": "B"},
        roots=["a", "b"],
        declared="product",
    )
    assert set(summary["roots"]) == {"a", "b", "other"}
    assert summary["outside_selected_roots"] == ["product"]
    assert contexts["a", "x"]["team_id"] == "A"
    assert contexts["b", "x"]["team_id"] == "B"


def test_descendant_owner_shadows_ancestor_across_bypass():
    contexts, _ = resolve(
        {"b": ["a", "x"], "a": ["x"]}, {"b": "B", "a": "A"}
    )
    assert contexts["b", "x"]["owner_boundaries"] == ["a"]
    assert contexts["b", "x"]["team_id"] == "A"


def test_sibling_owners_conflict_within_one_context():
    contexts, _ = resolve(
        {"root": ["a", "b"], "a": ["x"], "b": ["x"]}, {"a": "A", "b": "B"}
    )
    context = contexts["root", "x"]
    assert context["status"] == "conflict"
    assert context["owner_boundaries"] == ["a", "b"]
    assert context["candidate_teams"] == ["A", "B"]
    assert context["team_id"] is None


def test_mutually_reachable_boundaries_do_not_shadow_each_other():
    contexts, _ = resolve(
        {"root": ["a"], "a": ["b"], "b": ["a", "x"]},
        {"root": "Root", "a": "A", "b": "B"},
    )
    for ref in ("a", "b", "x"):
        assert contexts["root", ref]["status"] == "conflict"
        assert contexts["root", ref]["owner_boundaries"] == ["a", "b"]


def test_rootless_cycle_remains_visible_with_topology_unknown():
    contexts, summary = resolve({"a": ["b"], "b": ["a"]}, {"a": "A", "b": "B"})
    assert summary["roots"] == {"a": "cycle_without_declared_root"}
    assert len(contexts) == 2
    assert all(context["status"] == "topology_unknown" for context in contexts.values())
    assert all(context["candidate_teams"] == ["A", "B"] for context in contexts.values())


def test_thousand_owned_components_keep_nearest_owner_without_recursion():
    refs = [f"node-{index:04d}" for index in range(1000)]
    edges = {ref: refs[index + 1 : index + 2] for index, ref in enumerate(refs)}
    contexts, summary = resolve(edges, {ref: f"team-{ref}" for ref in refs})
    assert summary["contexts"] == len(refs)
    for ref in refs:
        assert contexts[refs[0], ref]["owner_boundaries"] == [ref]
        assert contexts[refs[0], ref]["team_id"] == f"team-{ref}"


def test_boundary_masks_match_reachability_oracle_on_directed_graphs():
    generator = random.Random(42)
    for _ in range(30):
        nodes = [f"n{index}" for index in range(10)]
        graph = {
            node: {child for child in nodes if generator.random() < 0.12} for node in nodes
        }
        owners = {node: True for node in nodes if generator.random() < 0.7}
        _, _, membership, parents = source_roots(graph)
        boundaries, bits, upstream, shadowed = boundary_masks(owners, membership, parents)
        descendants = {node: reachable(graph, node) for node in nodes}
        for root in nodes:
            subjects = descendants[root]
            root_bits = sum(bits[node] for node in subjects & owners.keys())
            for subject in subjects:
                candidates = {
                    node for node in subjects & owners.keys() if subject in descendants[node]
                }
                expected = sorted(
                    a
                    for a in candidates
                    if not any(
                        b in descendants[a] and a not in descendants[b] for b in candidates
                    )
                )
                group = membership[subject]
                assert selected_boundaries(
                    upstream[group] & root_bits & ~shadowed[group], boundaries
                ) == expected
