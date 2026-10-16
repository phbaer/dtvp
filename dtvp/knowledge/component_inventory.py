"""Pinned component occurrences, including those without vulnerability observations."""

from collections import Counter, defaultdict

LIMITATIONS = [
    "Rows are source-local component occurrences; matching names or PURLs do not merge identities.",
    "Ownership is the pinned resolver output, not an access grant, approval or completeness claim.",
    "Declared dependency edges do not establish runtime reachability or license/security clearance.",
]


def component_rows(sections):
    inventory = sections["inventory"]
    components = {}
    for key, value in inventory.items():
        if key == "root" or key.startswith(("component:", "part-root:")):
            if value.get("bom-ref"):
                components[value["bom-ref"]] = value
    contexts = defaultdict(list)
    for key, value in sections["ownership"].items():
        if key.startswith("context:"):
            contexts[value["component_ref"]].append(value)
    incoming, outgoing = Counter(), defaultdict(set)
    for edge in inventory.get("dependencies", {}).get("edges", []):
        outgoing[edge["ref"]].update(edge.get("dependsOn", []))
    for children in outgoing.values():
        incoming.update(children)
    rows = []
    for ref, component in components.items():
        values = contexts[ref]
        rows.append(
            {
                "component_ref": ref,
                "component": {
                    key: component[key]
                    for key in ("type", "name", "group", "version", "purl", "cpe", "dtvp_origin")
                    if key in component
                },
                "context_count": len(values),
                "team_ids": sorted(
                    {team for value in values for team in value.get("team_scope", {})}
                ),
                "ownership_statuses": sorted({value["status"] for value in values})
                or ["no_context"],
                "delegated_contexts": sum(bool(value.get("delegated")) for value in values),
                "incoming_declared": incoming[ref],
                "outgoing_declared": len(outgoing[ref]),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["component"].get("name", "").casefold(),
            row["component"].get("version", ""),
            row["component_ref"],
        ),
    )


def inventory_page(sections, *, q="", team_id=None, ownership=None, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Component inventory requires nonnegative offset and limit 1..200")
    rows = component_rows(sections)
    query = q.casefold().strip()
    selected = [
        row
        for row in rows
        if (
            not query
            or query
            in " ".join(
                str(row["component"].get(key, ""))
                for key in ("name", "group", "version", "purl", "cpe")
            ).casefold()
            or query in row["component_ref"].casefold()
        )
        and (not team_id or team_id in row["team_ids"])
        and (
            not ownership
            or ownership in row["ownership_statuses"]
            or (ownership == "delegated" and row["delegated_contexts"])
        )
    ]
    return {
        "items": selected[offset : offset + limit],
        "next_offset": offset + limit if offset + limit < len(selected) else None,
        "statistics": {
            "component_occurrences": len(selected),
            "consuming_contexts": sum(row["context_count"] for row in selected),
            "all_component_occurrences": len(rows),
        },
        "limitations": list(LIMITATIONS),
    }
