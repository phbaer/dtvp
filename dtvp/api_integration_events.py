"""Bounded integration evidence intake; authority precedes uploads and receipt replay."""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.auth import authenticate
from dtvp.knowledge.git_ancestry import MAX_OBJECTS
from dtvp.knowledge.integration_events import (
    MAX_REQUEST_BYTES,
    IntegrationInput,
    IntegrationPreviewInput,
    event_identity,
    integration_event,
    integration_events,
    integration_synchronization_preview,
    record_integration,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Sha
from dtvp.knowledge.legacy_archive import strict_json

router = APIRouter(prefix=API_PREFIX)


async def capture(request, db, actor, project_id, model, capability):
    project_for(db, actor, project_id)
    project_for(db, actor, project_id, capability)
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Expected application/json")
    maximum = min(MAX_REQUEST_BYTES, request.app.state.settings.max_upload_bytes)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > maximum:
            raise HTTPException(413, "Integration request exceeds its intake bound")
        raw.extend(chunk)
    try:
        value = strict_json(bytes(raw))
        if not isinstance(value, dict):
            raise ValueError("Expected an integration request object")
        objects = value.get("git_commit_objects", {})
        if not isinstance(objects, dict) or len(objects) > MAX_OBJECTS:
            raise ValueError("Git proof exceeds the commit-object limit")
        data = model.model_validate(value)
    except ValueError, ValidationError:
        raise HTTPException(422, "Invalid bounded integration request") from None
    db.rollback()
    db.expire_all()
    current = authenticate(request, db)
    project_for(db, current, project_id)
    project_for(db, current, project_id, capability)
    return data, current


@router.post("/projects/{project_id}/integration-events", status_code=201)
async def record(project_id: str, request: Request, db: DB, actor: Auth):
    data, actor = await capture(request, db, actor, project_id, IntegrationInput, "evidence")
    try:
        receipt = await run_in_threadpool(
            record_integration,
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return {
        **projected_response(request, receipt),
        "event_id": event_identity(project_id, actor.user.id, data)[0],
    }


@router.get("/projects/{project_id}/states/{state}/integration-events")
def list_events(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return integration_events(request.app.state.knowledge, project_id, state, offset, limit)


@router.get("/projects/{project_id}/states/{state}/integration-events/{event_id}")
def selected_event(
    project_id: str, state: Sha, event_id: Sha, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id)
    return integration_event(request.app.state.knowledge, project_id, state, event_id)


@router.post("/projects/{project_id}/integration-events/{event_id}/synchronization-preview")
async def preview(
    project_id: str,
    event_id: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    data, _ = await capture(request, db, actor, project_id, IntegrationPreviewInput, "read")
    try:
        return await run_in_threadpool(
            integration_synchronization_preview,
            request.app.state.knowledge,
            project_id=project_id,
            event_id=event_id,
            data=data,
            offset=offset,
            limit=limit,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
