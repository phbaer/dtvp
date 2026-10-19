"""Bounded, pinned dependency traversal shared by presentation clients."""

from collections import Counter, defaultdict

MAX_ROWS = 10_000
LIMITATIONS = [
    "Declared dependencies do not establish runtime reachability or complete discovery.",
    "Shared components and cycles are references, not duplicated component identities.",
    "Vulnerability counts are distinct imported identifiers per component, not approved assessments.",
]


def dependency_tree(sections, *, root_ref=None, max_depth=3, offset=0, limit=100):
    if not 0 <= max_depth <= 20 or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Tree requires depth 0..20, nonnegative offset and limit 1..200")
    inventory = sections["inventory"]
    components = {
        value["bom-ref"]: value
        for key, value in inventory.items()
        if (key == "root" or key.startswith(("component:", "part-root:")))
        and isinstance(value, dict)
        and value.get("bom-ref")
    }
    children = defaultdict(set)
    for edge in inventory.get("dependencies", {}).get("edges", []):
        children[edge["ref"]].update(edge.get("dependsOn", []))
    refs = set(components) | set(children)
    incoming = Counter()
    for values in children.values():
        refs.update(values)
        incoming.update(values)

    def order(ref):
        component = components.get(ref, {})
        return (component.get("name", ref).casefold(), component.get("version", ""), ref)

    if root_ref is not None and root_ref not in refs:
        raise KeyError(root_ref)
    if root_ref is not None:
        roots = [root_ref]
    else:
        primary = inventory.get("root", {}).get("bom-ref")
        roots = ([primary] if primary in refs else []) + sorted(
            (ref for ref in refs if not incoming[ref] and ref != primary), key=order
        )
        # Discover disconnected cyclic groups independently of display depth.
        covered = set()

        def cover(ref):
            pending = [ref]
            while pending:
                current = pending.pop()
                if current not in covered:
                    covered.add(current)
                    pending.extend(children[current] - covered)

        selected = []
        for ref in [*roots, *sorted(refs, key=order)]:
            if ref not in covered:
                selected.append(ref)
                cover(ref)
        roots = selected

    vulnerabilities = defaultdict(set)
    for record in sections["vulnerabilities"].values():
        if record.get("ref") and record.get("identifier"):
            vulnerabilities[record["ref"]].add(record["identifier"])
    rows, seen = [], set()
    pending = [(ref, []) for ref in reversed(roots)]
    depth_limited = False
    while pending and len(rows) < MAX_ROWS:
        ref, ancestors = pending.pop()
        cycle = ref in ancestors
        shared = ref in seen and not cycle
        path = [*ancestors, ref]
        component = components.get(ref)
        rows.append(
            {
                "component_ref": ref,
                "parent_ref": ancestors[-1] if ancestors else None,
                "path": path,
                "depth": len(ancestors),
                "component": {
                    key: component[key]
                    for key in ("name", "group", "version", "purl", "type")
                    if component and key in component
                },
                "child_count": len(children[ref]),
                "vulnerability_count": len(vulnerabilities[ref]),
                "cycle": cycle,
                "shared": shared,
                "missing": component is None,
            }
        )
        seen.add(ref)
        if children[ref] and not cycle and not shared:
            if len(ancestors) < max_depth:
                pending.extend(
                    (child, path) for child in sorted(children[ref], key=order, reverse=True)
                )
            else:
                depth_limited = True
    return {
        "root_ref": root_ref,
        "offset": offset,
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
        "max_depth": max_depth,
        "depth_limited": depth_limited,
        "truncated": bool(pending),
        "row_limit": MAX_ROWS,
        "component_count": len(components),
        "dependency_graph": inventory.get("baseline", {}).get("dependency_graph", "unknown"),
        "limitations": list(LIMITATIONS),
    }
