"""Authorized raw ZIP publication; upload and disclosure are explicit operator choices."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.auth import authenticate
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name
from dtvp.knowledge.legacy_archive import MAX_COMPRESSED, strict_json
from dtvp.knowledge.legacy_archive_migration import (
    MAX_HEADER,
    LegacyArchiveMigrationApply,
    LegacyArchiveMigrationInput,
    apply_migration,
    preview_migration,
)

router = APIRouter(prefix="/api/v3")


def authorize(db, actor, project_id):
    project = project_for(db, actor, project_id, "manage")
    actor.require(db, project, "write")
    actor.require(db, project, "read")


async def capture(project_id, request, db, actor, model):
    authorize(db, actor, project_id)
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/zip"
    ):
        raise HTTPException(415, "Expected application/zip raw request body")
    header = request.headers.get("x-dtvp-migration", "")
    if not header or not header.isascii() or len(header.encode("ascii")) > MAX_HEADER:
        raise HTTPException(422, "Expected bounded ASCII JSON X-DTVP-Migration metadata")
    try:
        data = model.model_validate(strict_json(header.encode("ascii")))
    except (ValueError, ValidationError) as error:
        raise HTTPException(422, "Invalid publication metadata") from error
    maximum = min(MAX_COMPRESSED, request.app.state.settings.max_upload_bytes)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > maximum:
            raise HTTPException(413, "Legacy archive exceeds configured compressed upload bound")
        raw.extend(chunk)
    # A long upload must not keep a revoked cached credential/membership alive.
    db.rollback()
    db.expire_all()
    refreshed = authenticate(request, db)
    authorize(db, refreshed, project_id)
    return data, bytes(raw), refreshed


@router.post("/projects/{project_id}/versions/{version}/migration/v1-archive/preview")
async def preview(project_id: str, version: Name, request: Request, db: DB, actor: Auth):
    data, raw, actor = await capture(project_id, request, db, actor, LegacyArchiveMigrationInput)
    try:
        return await run_in_threadpool(
            preview_migration,
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
            raw=raw,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post(
    "/projects/{project_id}/versions/{version}/migration/v1-archive/apply", status_code=201
)
async def apply(project_id: str, version: Name, request: Request, db: DB, actor: Auth):
    data, raw, actor = await capture(project_id, request, db, actor, LegacyArchiveMigrationApply)
    try:
        receipt = await run_in_threadpool(
            apply_migration,
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
            raw=raw,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
