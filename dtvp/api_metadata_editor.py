"""Scoped presentation data for existing versioned component metadata writes."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import require_state
from dtvp.knowledge.journal import Ref, Sha
from dtvp.knowledge.metadata import LIMITATIONS, Annotations, component_at, get_metadata
from dtvp.knowledge.workspace import load_sections

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/states/{state}/component-context")
def component_context(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    component_ref: str = Query(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$"),
    context_id: Sha | None = None,
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    revision = require_state(journal, state, project_id)
    sections = load_sections(journal, state)
    component = component_at(sections, component_ref)
    if component is None:
        raise HTTPException(404, "Component is absent from the selected state")
    context = sections["ownership"].get("context:" + context_id) if context_id else None
    if context_id and (not context or context.get("component_ref") != component_ref):
        raise HTTPException(404, "Consuming context does not describe this component occurrence")
    head = journal.resolve(Ref(project_id=project_id, name=revision.version))
    reasons = []
    if head != state:
        reasons.append("selected_state_is_not_current_head")
    if not actor.allowed(db, project, "manage"):
        reasons.append("component_metadata_requires_management_permission")
    if revision.version.startswith("@"):
        reasons.append("reserved_version")
    inventory = sections["inventory"]
    graph = {}
    for edge in inventory.get("dependencies", {}).get("edges", []):
        graph.setdefault(edge["ref"], set()).update(edge.get("dependsOn", []))
    incoming = sorted(ref for ref, children in graph.items() if component_ref in children)
    outgoing = sorted(graph.get(component_ref, ()))
    components = {
        value["bom-ref"]: value
        for key, value in inventory.items()
        if key.startswith(("component:", "part-root:")) and value.get("bom-ref")
    }
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        components.setdefault(root["bom-ref"], root)

    def neighbors(refs):
        return [
            {
                "ref": ref,
                "name": components.get(ref, {}).get("name", ""),
                "version": components.get(ref, {}).get("version", ""),
                "resolved": ref in components,
            }
            for ref in refs[:50]
        ]

    return {
        "state": state,
        "head": head,
        "version": revision.version,
        "component_ref": component_ref,
        "component": component,
        "metadata": get_metadata(journal, sections, revision.version, component_ref),
        "defaults": Annotations().model_dump(mode="json"),
        "capabilities": [] if reasons else ["curate"],
        "blocked_reasons": reasons,
        "topology": {
            "dependency_graph": (context or {}).get(
                "dependency_graph", inventory.get("baseline", {}).get("dependency_graph", "unknown")
            ),
            "consuming_root": (context or {}).get("root_ref"),
            "incoming": neighbors(incoming),
            "outgoing": neighbors(outgoing),
            "incoming_total": len(incoming),
            "outgoing_total": len(outgoing),
            "neighbor_limit": 50,
            "limitations": [
                "Only imported direct dependency edges are shown; unknown or absent edges do not establish non-use or complete discovery.",
                "Edges do not establish runtime reachability, deployment topology or architecture approval; assembly adds no cross-part edges.",
            ],
        },
        "limitations": list(LIMITATIONS),
    }
