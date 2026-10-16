"""Managed logical archival with project-readable retained evidence; no physical deletion."""

import json

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.assessment_archive import (
    ArchiveInput,
    apply_archive,
    get_archived,
    list_archived,
    preview_archive,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict

router = APIRouter(prefix="/api/v3")


@router.post("/projects/{project_id}/maintenance/assessment-archive/preview")
def preview(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id, "manage")
    return preview_archive(request.app.state.knowledge, project_id, offset=offset, limit=limit)


@router.post("/projects/{project_id}/maintenance/assessment-archive/apply", status_code=201)
async def apply(project_id: str, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id, "manage")
    if not actor.allowed(db, project, "write"):
        raise HTTPException(403, "Archival also requires current product write permission")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 2 * 1024 * 1024:
            raise HTTPException(413, "Assessment archive request exceeds 2 MiB")
        raw.extend(chunk)
    try:
        data = ArchiveInput.model_validate(json.loads(raw))
    except (ValueError, RecursionError) as error:
        raise HTTPException(422, "Invalid bounded assessment archive input") from error
    try:
        receipt = apply_archive(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/maintenance/assessment-archive")
def listing(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return list_archived(request.app.state.knowledge, project_id, offset=offset, limit=limit)


@router.get("/projects/{project_id}/maintenance/assessment-archive/{assessment_id}")
def detail(
    project_id: str,
    assessment_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    try:
        return get_archived(
            request.app.state.knowledge, project_id, assessment_id, offset=offset, limit=limit
        )
    except KeyError as error:
        raise HTTPException(404, "Archived logical assessment unavailable") from error
