"""Bounded, pinned dependency traversal shared by presentation clients."""

from collections import Counter, defaultdict

MAX_ROWS = 10_000
LIMITATIONS = [
    "Declared dependencies do not establish runtime reachability or complete discovery.",
    "Shared components and cycles are references, not duplicated component identities.",
    "Vulnerability counts are distinct imported identifiers per component, not approved assessments.",
]


def _tree_index(sections):
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

    return components, children, refs, incoming, order


def _tree_roots(inventory, children, refs, incoming, order):
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
    return selected


def dependency_tree(sections, *, root_ref=None, max_depth=3, offset=0, limit=100):
    if not 0 <= max_depth <= 20 or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Tree requires depth 0..20, nonnegative offset and limit 1..200")
    inventory = sections["inventory"]
    components, children, refs, incoming, order = _tree_index(sections)
    if root_ref is not None and root_ref not in refs:
        raise KeyError(root_ref)
    roots = (
        [root_ref]
        if root_ref is not None
        else _tree_roots(inventory, children, refs, incoming, order)
    )

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


def dependency_paths(sections, *, component_ref, root_ref=None, limit=20):
    """Shortest declared paths, using reverse BFS rather than unfolding the graph."""
    from collections import deque

    if not 1 <= limit <= 50:
        raise ValueError("Path limit must be between 1 and 50")
    inventory = sections["inventory"]
    components = {
        value["bom-ref"]: value
        for key, value in inventory.items()
        if (key == "root" or key.startswith(("component:", "part-root:")))
        and isinstance(value, dict)
        and value.get("bom-ref")
    }
    children, parents = defaultdict(set), defaultdict(set)
    refs = set(components)
    for edge in inventory.get("dependencies", {}).get("edges", []):
        parent = edge["ref"]
        refs.add(parent)
        for child in edge.get("dependsOn", []):
            refs.add(child)
            children[parent].add(child)
            parents[child].add(parent)
    if component_ref not in refs or (root_ref is not None and root_ref not in refs):
        raise KeyError(component_ref)

    def order(ref):
        component = components.get(ref, {})
        return (component.get("name", ref).casefold(), component.get("version", ""), ref)

    distances = {component_ref: 0}
    pending = deque([component_ref])
    search_truncated = False
    while pending:
        current = pending.popleft()
        # A supplied consuming root bounds the search; ancestors above it are irrelevant.
        if current == root_ref:
            break
        for parent in sorted(parents[current], key=order):
            if parent in distances:
                continue
            if distances[current] >= 100 or len(distances) >= MAX_ROWS:
                search_truncated = True
                continue
            distances[parent] = distances[current] + 1
            pending.append(parent)
    primary = inventory.get("root", {}).get("bom-ref")
    roots = (
        [root_ref]
        if root_ref
        else sorted((ref for ref in distances if not parents[ref] or ref == primary), key=order)
    )
    pending_paths = [(root, [root]) for root in reversed(roots) if root in distances]
    paths = []
    while pending_paths and len(paths) < limit:
        current, path = pending_paths.pop()
        if current == component_ref:
            paths.append(
                [
                    {
                        "component_ref": ref,
                        "component": {
                            key: components[ref][key]
                            for key in ("name", "group", "version", "purl", "type")
                            if ref in components and key in components[ref]
                        },
                        "missing": ref not in components,
                    }
                    for ref in path
                ]
            )
        else:
            pending_paths.extend(
                (child, [*path, child])
                for child in sorted(children[current], key=order, reverse=True)
                if distances.get(child) == distances[current] - 1
            )
    return {
        "component_ref": component_ref,
        "root_ref": root_ref,
        "paths": paths,
        "truncated": search_truncated or bool(pending_paths),
        "limit": limit,
        "visited_count": len(distances),
        "node_limit": MAX_ROWS,
        "depth_limit": 100,
        "dependency_graph": inventory.get("baseline", {}).get("dependency_graph", "unknown"),
        "limitations": [
            "Shows shortest declared paths per root; longer alternative routes are omitted.",
            "Declared dependencies do not establish runtime reachability or complete discovery.",
            "Disconnected cycles without a declared root have no product-root path.",
        ],
    }


def dependency_children(sections, *, parent_ref=None, root_ref=None, path=(), offset=0, limit=100):
    """Page only immediate siblings; expanded branches never compete for page slots."""
    if offset < 0 or not 1 <= limit <= 200 or len(path) > 100:
        raise ValueError("Children require nonnegative offset, limit 1..200 and path depth <=100")
    if any(
        not isinstance(ref, str)
        or not ref
        or len(ref) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in ref)
        for ref in path
    ):
        raise ValueError("Invalid ancestor path reference")
    inventory = sections["inventory"]
    components, children, refs, incoming, order = _tree_index(sections)
    if any(ref not in refs for ref in (parent_ref, root_ref) if ref is not None):
        raise KeyError(parent_ref or root_ref)
    ancestors = list(path)
    if parent_ref is None:
        if ancestors:
            raise ValueError("Root listings cannot have an ancestor path")
        siblings = (
            [root_ref]
            if root_ref is not None
            else _tree_roots(inventory, children, refs, incoming, order)
        )
    else:
        ancestors = ancestors or [parent_ref]
        if (
            ancestors[-1] != parent_ref
            or len(set(ancestors)) != len(ancestors)
            or (root_ref is not None and ancestors[0] != root_ref)
            or any(child not in children[parent] for parent, child in zip(ancestors, ancestors[1:]))
        ):
            raise ValueError("Ancestor path must follow declared dependencies to the parent")
        siblings = sorted(children[parent_ref], key=order)
    vulnerabilities = defaultdict(set)
    for record in sections.get("vulnerabilities", {}).values():
        if record.get("ref") and record.get("identifier"):
            vulnerabilities[record["ref"]].add(record["identifier"])
    items = []
    for ref in siblings[offset : offset + limit]:
        component = components.get(ref, {})
        items.append(
            {
                "component_ref": ref,
                "parent_ref": parent_ref,
                "path": [*ancestors, ref],
                "depth": len(ancestors),
                "component": {
                    key: component[key]
                    for key in ("name", "group", "version", "purl", "type")
                    if key in component
                },
                "child_count": len(children[ref]),
                "vulnerability_count": len(vulnerabilities[ref]),
                "cycle": ref in ancestors,
                "shared": incoming[ref] > 1,
                "missing": ref not in components,
            }
        )
    return {
        "root_ref": root_ref,
        "parent_ref": parent_ref,
        "ancestor_path": ancestors,
        "items": items,
        "offset": offset,
        "total": len(siblings),
        "next_offset": offset + limit if offset + limit < len(siblings) else None,
        "component_count": len(components),
        "dependency_graph": inventory.get("baseline", {}).get("dependency_graph", "unknown"),
        "limitations": list(LIMITATIONS),
    }
