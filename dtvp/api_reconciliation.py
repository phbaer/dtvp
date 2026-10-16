"""Explicit occurrence correspondence without identity merging or approval transfer."""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import Field

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha
from dtvp.knowledge.reconciliation import (
    Pair,
    ReconciliationInput,
    RetractionInput,
    confirm_reconciliation,
    list_reconciliations,
    preview_reconciliation,
    retract_reconciliation,
)
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")


class PreviewInput(RequestModel):
    source: Sha
    target: Sha
    pairs: list[Pair] = Field(min_length=1, max_length=100)


@router.post("/projects/{project_id}/reconciliation/preview")
def preview(project_id: str, data: PreviewInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, data.source, project_id)
    require_state(journal, data.target, project_id)
    try:
        return preview_reconciliation(journal, project_id, data.source, data.target, data.pairs)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


def mutate(project_id, version, reconciliation_id, data, request, db, actor, *, retract):
    project_for(db, actor, project_id)
    project_for(db, actor, project_id, "write")
    journal = request.app.state.knowledge
    require_state(journal, data.expected, project_id)
    if not retract:
        require_state(journal, data.source, project_id)
    try:
        operation = retract_reconciliation if retract else confirm_reconciliation
        receipt = operation(
            journal,
            project_id,
            version,
            actor.user.id,
            reconciliation_id,
            data,
            lambda capability: project_for(db, actor, project_id, capability),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post(
    "/projects/{project_id}/versions/{version}/reconciliations/{reconciliation_id}/confirm",
    status_code=201,
)
def confirm(
    project_id: str,
    version: Name,
    reconciliation_id: Name,
    data: ReconciliationInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    return mutate(project_id, version, reconciliation_id, data, request, db, actor, retract=False)


@router.post(
    "/projects/{project_id}/versions/{version}/reconciliations/{reconciliation_id}/retract",
    status_code=201,
)
def retract(
    project_id: str,
    version: Name,
    reconciliation_id: Name,
    data: RetractionInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    return mutate(project_id, version, reconciliation_id, data, request, db, actor, retract=True)


@router.get("/projects/{project_id}/states/{state}/reconciliations")
def registry(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    if state not in reachable_states(journal, project_id):
        raise HTTPException(404, "Correspondence registry requires committed product history")
    return {
        "state": state,
        "capabilities": ["write"] if actor.allowed(db, project, "write") else [],
        **list_reconciliations(journal, state, offset, limit),
    }
