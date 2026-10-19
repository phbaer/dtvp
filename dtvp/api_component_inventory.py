"""Read-only source-local inventory independent of the vulnerability queue."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import require_state
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.component_inventory import inventory_page
from dtvp.knowledge.journal import Name, Ref, Sha
from dtvp.knowledge.metadata import component_at
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Workspace

router = APIRouter(prefix=API_PREFIX)


def pinned(request, project_id, state):
    journal = request.app.state.knowledge
    if state not in reachable_states(journal, project_id):
        raise HTTPException(404, "Committed state unavailable in this product line")
    return journal, require_state(journal, state, project_id), load_sections(journal, state)


@router.get("/projects/{project_id}/states/{state}/components")
def components(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=500),
    team_id: Name | None = None,
    ownership: Literal[
        "resolved", "unassigned", "conflict", "topology_unknown", "no_context", "delegated"
    ]
    | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal, revision, sections = pinned(request, project_id, state)
    result = inventory_page(
        sections, q=q, team_id=team_id, ownership=ownership, offset=offset, limit=limit
    )
    ids = {
        team
        for value in sections["ownership"].values()
        if isinstance(value, dict)
        for team in value.get("team_scope", {})
    }
    names = {
        item.id: item.name for item in db.scalars(select(Workspace).where(Workspace.id.in_(ids)))
    }
    labels = [{"id": team, "name": names.get(team, team)} for team in sorted(ids)]
    return {
        **result,
        "state": state,
        "version": revision.version,
        "head": journal.resolve(Ref(project_id=project_id, name=revision.version)),
        "teams": labels,
    }


@router.get("/projects/{project_id}/states/{state}/components/contexts")
def contexts(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    component_ref: str = Query(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    _, _, sections = pinned(request, project_id, state)
    if component_at(sections, component_ref) is None:
        raise HTTPException(404, "Component absent from selected state")
    values = sorted(
        [
            value
            for key, value in sections["ownership"].items()
            if key.startswith("context:") and value["component_ref"] == component_ref
        ],
        key=lambda value: (value["root_ref"], value["id"]),
    )
    return {
        "state": state,
        "component_ref": component_ref,
        "items": values[offset : offset + limit],
        "total": len(values),
        "next_offset": offset + limit if offset + limit < len(values) else None,
    }
