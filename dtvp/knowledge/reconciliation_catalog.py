"""Bounded exact occurrence selectors; no identity matching or correspondence inference."""

from dtvp.knowledge.comparison import components, page, product_state, reachable_states
from dtvp.knowledge.workspace import load_sections

FIELDS = ("bom-ref", "type", "name", "group", "version", "purl", "hashes")


def occurrence_catalog(journal, project_id, state, kind, q="", offset=0, limit=50):
    page([], offset, limit)
    if kind not in {"component", "context"}:
        raise ValueError("Occurrence kind must be component or context")
    node = product_state(journal, state, project_id)
    if state not in reachable_states(journal, project_id):
        raise ValueError("Occurrence selectors require committed product history")
    sections = load_sections(journal, state)
    inventory = components(sections["inventory"])

    def facts(ref):
        value = inventory.get(ref)
        return {key: value[key] for key in FIELDS if key in value} if value else None

    rows = []
    if kind == "component":
        rows = [
            {
                "id": ref,
                "kind": kind,
                "component_ref": ref,
                "root_ref": None,
                "component": facts(ref),
                "root": None,
                "team_id": None,
                "ownership_status": None,
            }
            for ref in inventory
        ]
    else:
        for key, context in sections["ownership"].items():
            if not key.startswith("context:"):
                continue
            rows.append(
                {
                    "id": context["id"],
                    "kind": kind,
                    "component_ref": context["component_ref"],
                    "root_ref": context["root_ref"],
                    "component": facts(context["component_ref"]),
                    "root": facts(context["root_ref"]),
                    "team_id": context.get("team_id"),
                    "ownership_status": context.get("status"),
                }
            )
    query = q.casefold()
    rows = [
        row
        for row in rows
        if not query
        or any(
            query in str(value).casefold()
            for value in (
                row["id"],
                row["component_ref"],
                row["root_ref"],
                row["team_id"],
                *(row["component"] or {}).values(),
                *(row["root"] or {}).values(),
            )
        )
    ]
    rows.sort(key=lambda row: (row["component_ref"], row["root_ref"] or "", row["id"]))
    return {
        "project_id": project_id,
        "state": state,
        "version": node.version,
        "kind": kind,
        **page(rows, offset, limit),
    }
