"""Presentation adapter for pinned, explicit, independently authorized bulk reviews."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.bulk_reviews import BulkApply, BulkInput, apply_bulk_review, preview_bulk_review
from dtvp.knowledge.journal import CommitUncertain, Conflict

router = APIRouter(prefix="/api/v3")


def authorize(db, actor, project):
    def check(team_id, capability):
        if not actor.allowed(db, project, capability) or not actor.workspace(team_id, capability):
            raise PermissionError("Review requires the responsible team's current approval role")

    return check


@router.post("/projects/{project_id}/reviews/bulk/preview")
def preview(
    project_id: str,
    data: BulkInput,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    try:
        return preview_bulk_review(
            request.app.state.knowledge,
            project_id,
            actor.user.id,
            data,
            authorize(db, actor, project),
            offset,
            limit,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/reviews/bulk/apply", status_code=201)
def apply(project_id: str, data: BulkApply, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id, "approve")
    try:
        receipt = apply_bulk_review(
            request.app.state.knowledge,
            project_id,
            actor.user.id,
            data,
            authorize(db, actor, project),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
