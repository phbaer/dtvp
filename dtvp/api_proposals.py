"""Explicit external proposal intake; publication stays a coordinator workflow."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name
from dtvp.knowledge.proposals import VScorerProposalInput, import_vscorer_proposal

router = APIRouter(prefix="/api/v3")


@router.post("/projects/{project_id}/versions/{version}/proposals/vscorer", status_code=201)
def vscorer_proposal(
    project_id: str,
    version: Name,
    data: VScorerProposalInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    project_for(db, actor, project_id, "write")
    try:
        receipt = import_vscorer_proposal(
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
