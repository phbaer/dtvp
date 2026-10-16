"""Explicit external proposal intake; publication stays a coordinator workflow."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name
from dtvp.knowledge.proposals import VScorerProposalInput, import_vscorer_proposal
from dtvp.knowledge.vscorer_minimal import MinimalMappingSelection, VScorerMinimalProposalInput

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


@router.post("/projects/{project_id}/versions/{version}/proposals/vscorer-minimal", status_code=201)
def vscorer_minimal_proposal(
    project_id: str,
    version: Name,
    data: VScorerMinimalProposalInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    """Operator-bound native minimal REST result; no fabricated consumer receipt."""
    project_for(db, actor, project_id, "write")
    from dtvp.knowledge.vscorer_minimal import import_minimal_proposal

    try:
        receipt = import_minimal_proposal(
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


@router.post("/projects/{project_id}/vscorer-minimal-mapping")
def minimal_mapping(
    project_id: str, data: MinimalMappingSelection, request: Request, db: DB, actor: Auth
):
    """Read-only canonical items.csv conversion of exact issued model declarations."""
    project_for(db, actor, project_id)
    from dtvp.knowledge.vscorer_minimal import derive_minimal_mapping

    return derive_minimal_mapping(request.app.state.knowledge, project_id=project_id, data=data)
