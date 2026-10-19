"""Scoped presentation data for existing versioned component metadata writes."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import require_state
from dtvp.knowledge.component_topology import LIMITATIONS as TOPOLOGY_LIMITATIONS
from dtvp.knowledge.component_topology import neighbor_page, neighborhood
from dtvp.knowledge.journal import Ref, Sha
from dtvp.knowledge.metadata import LIMITATIONS, Annotations, component_at, get_metadata
from dtvp.knowledge.workspace import load_sections

router = APIRouter(prefix=API_PREFIX)


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
    adjacent = neighborhood(inventory, component_ref)

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
            "incoming": adjacent["incoming"][:50],
            "outgoing": adjacent["outgoing"][:50],
            "incoming_total": len(adjacent["incoming"]),
            "outgoing_total": len(adjacent["outgoing"]),
            "neighbor_limit": 50,
            "limitations": list(TOPOLOGY_LIMITATIONS),
        },
        "limitations": list(LIMITATIONS),
    }


@router.get("/projects/{project_id}/states/{state}/component-neighbors")
def component_neighbors(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    component_ref: str = Query(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$"),
    direction: Literal["incoming", "outgoing"] = "outgoing",
    q: str = Query(default="", max_length=500),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    sections = load_sections(journal, state)
    if component_at(sections, component_ref) is None:
        raise HTTPException(404, "Component is absent from the selected state")
    return {
        "state": state,
        **neighbor_page(
            sections["inventory"], component_ref, direction, q=q, offset=offset, limit=limit
        ),
    }
