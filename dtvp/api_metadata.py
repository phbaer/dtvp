"""Versioned authored metadata, kept separate from imported component facts."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha
from dtvp.knowledge.metadata import MetadataInput, get_metadata, list_metadata, save_metadata
from dtvp.knowledge.workspace import load_sections

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/states/{state}/metadata")
def metadata(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    component_ref: str | None = Query(None, min_length=1, max_length=4096),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    revision = require_state(journal, state, project_id)
    sections = load_sections(journal, state)
    if component_ref is not None:
        return {
            "state": state,
            "metadata": get_metadata(journal, sections, revision.version, component_ref),
        }
    return {"state": state, **list_metadata(journal, sections, revision.version, offset, limit)}


@router.put("/projects/{project_id}/versions/{version}/metadata", status_code=201)
def curate(
    project_id: str, version: Name, data: MetadataInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "manage")
    try:
        receipt = save_metadata(
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
