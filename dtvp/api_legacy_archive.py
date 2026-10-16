"""Bounded raw ZIP dry run. Authorization precedes consuming the upload stream."""

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.legacy_archive import MAX_COMPRESSED, preview_archive

router = APIRouter(prefix="/api/v3")


@router.post("/projects/{project_id}/migration/v1-archive/preview")
async def preview(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
):
    project_for(db, actor, project_id, "manage")
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/zip"
    ):
        raise HTTPException(415, "Expected application/zip raw request body")
    maximum = min(MAX_COMPRESSED, request.app.state.settings.max_upload_bytes)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > maximum:
            raise HTTPException(413, "Legacy archive exceeds configured compressed upload bound")
        raw.extend(chunk)
    return await run_in_threadpool(preview_archive, bytes(raw), offset=offset, limit=limit)
