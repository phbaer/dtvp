"""Imported direct edges only; never inferred runtime or cross-part topology."""

LIMITATIONS = [
    "Only imported direct dependency edges are shown; unknown or absent edges do not establish non-use or complete discovery.",
    "Edges do not establish runtime reachability, deployment topology or architecture approval; assembly adds no cross-part edges.",
]


def neighborhood(inventory, component_ref):
    graph = {}
    for edge in inventory.get("dependencies", {}).get("edges", []):
        graph.setdefault(edge["ref"], set()).update(edge.get("dependsOn", []))
    components = {
        value["bom-ref"]: value
        for key, value in inventory.items()
        if (key == "root" or key.startswith(("component:", "part-root:"))) and value.get("bom-ref")
    }

    def rows(refs):
        return [
            {
                "ref": ref,
                "name": components.get(ref, {}).get("name", ""),
                "version": components.get(ref, {}).get("version", ""),
                "resolved": ref in components,
            }
            for ref in sorted(refs)
        ]

    return {
        "incoming": rows(ref for ref, children in graph.items() if component_ref in children),
        "outgoing": rows(graph.get(component_ref, ())),
    }


def neighbor_page(inventory, component_ref, direction, *, q="", offset=0, limit=50):
    if direction not in ("incoming", "outgoing"):
        raise ValueError("Direction must be incoming or outgoing")
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Neighbors require nonnegative offset and limit 1..200")
    rows = neighborhood(inventory, component_ref)[direction]
    query = q.strip().casefold()
    selected = [
        row
        for row in rows
        if not query
        or query in " ".join(str(row[key]) for key in ("ref", "name", "version")).casefold()
    ]
    return {
        "component_ref": component_ref,
        "direction": direction,
        "items": selected[offset : offset + limit],
        "total": len(selected),
        "declared_total": len(rows),
        "next_offset": offset + limit if offset + limit < len(selected) else None,
        "dependency_graph": inventory.get("baseline", {}).get("dependency_graph", "unknown"),
        "limitations": list(LIMITATIONS),
    }
