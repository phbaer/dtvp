"""Explicit bounded offline CPE source intake; all access uses current project authority."""

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import Field, ValidationError
from starlette.concurrency import run_in_threadpool

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.auth import authenticate
from dtvp.knowledge.cpe_sources import (
    MAX_BODY,
    MAX_BYTES,
    CpeSourceApply,
    CpeSourceInput,
    apply_source,
    preview_source,
    rank_retained,
    retained_policy,
    source_report,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Sha
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.schemas import RequestModel
from dtvp.storage import digest

router = APIRouter(prefix="/api/v3")


async def capture(project_id, request, db, actor, model):
    project_for(db, actor, project_id, "manage")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > min(MAX_BODY, request.app.state.settings.max_upload_bytes):
            raise HTTPException(413, "CPE source metadata and encoded bytes exceed 3 MiB")
        raw.extend(chunk)
    try:
        data = model.model_validate(strict_json(bytes(raw)))
    except (ValueError, ValidationError) as error:
        raise HTTPException(422, "Invalid bounded CPE source input") from error
    db.rollback()
    db.expire_all()
    actor = authenticate(request, db)
    project_for(db, actor, project_id, "manage")
    return data, actor


@router.post("/projects/{project_id}/cpe/sources/preview")
async def preview(project_id: str, request: Request, db: DB, actor: Auth):
    data, actor = await capture(project_id, request, db, actor, CpeSourceInput)
    try:
        return await run_in_threadpool(
            preview_source,
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/cpe/sources/apply", status_code=201)
async def apply(project_id: str, request: Request, db: DB, actor: Auth):
    data, actor = await capture(project_id, request, db, actor, CpeSourceApply)
    try:
        receipt = await run_in_threadpool(
            apply_source,
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/cpe/sources/{policy}/{kind}")
def report(
    project_id: str,
    policy: Sha,
    kind: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return source_report(
        request.app.state.knowledge,
        project_id=project_id,
        policy=policy,
        kind=kind,
        offset=offset,
        limit=limit,
    )


@router.get("/projects/{project_id}/cpe/sources/{policy}/{kind}/artifact")
def artifact(project_id: str, policy: Sha, kind: str, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    config = retained_policy(journal, project_id, policy)
    metadata = config.get("offline_sources", {}).get(kind)
    if not metadata:
        raise HTTPException(404, "Offline source unavailable")
    sha = metadata["artifact_sha256"]
    if (
        sha not in journal.state(policy).artifacts
        or journal.objects.path(sha).stat().st_size > MAX_BYTES
    ):
        raise HTTPException(409, "Retained offline source artifact is inconsistent")
    raw = journal.objects.read(sha)
    if digest(raw) != sha:
        raise HTTPException(409, "Retained offline source artifact digest differs")
    return Response(
        raw,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="cpe-offline-source"',
            "X-Content-SHA256": sha,
        },
    )


class RetainedRankingInput(RequestModel):
    component_ref: str = Field(min_length=1, max_length=4096)
    policy: Sha
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=200)


@router.post("/projects/{project_id}/states/{state}/cpe/rank-retained")
def rank(
    project_id: str, state: Sha, data: RetainedRankingInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    component = None
    for key, value in journal.records(state, "inventory").items():
        if key == "root" or key.startswith(("component:", "part-root:")):
            candidate = journal.load(value)
            if candidate.get("bom-ref") == data.component_ref:
                component = candidate
                break
    if component is None:
        raise HTTPException(404, "Component unavailable in this product state")
    return {
        "inventory_state": state,
        **rank_retained(
            journal,
            project_id=project_id,
            policy=data.policy,
            component=component,
            offset=data.offset,
            limit=data.limit,
        ),
    }
