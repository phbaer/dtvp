"""Explicit policy configuration and authorized frozen automatic sync proposals."""

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.knowledge.sync_jobs import KIND, SynchronizationInput, configure, job_view, policy
from dtvp.models import Job

router = APIRouter(prefix=API_PREFIX)


def selected(db, actor, project_id, job_id, capability="read", *, lock=False):
    project_for(db, actor, project_id, capability)
    query = select(Job).where(Job.id == job_id, Job.project_id == project_id, Job.kind == KIND)
    job = db.scalar(query.with_for_update() if lock else query)
    if job is None:
        raise HTTPException(404, "Synchronization proposal unavailable")
    return job


def view(db, actor, job, journal):
    project = project_for(db, actor, job.project_id)
    actions = []
    if actor.user.id == job.actor_id and actor.allowed(db, project, "manage"):
        if job.status == "failed":
            actions.append("retry")
        if job.status in {"queued", "running"}:
            actions.append("cancel")
    return {**job_view(job, journal), "capabilities": actions}


@router.get("/projects/{project_id}/synchronization-policy")
def get_policy(project_id: str, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    state, config = policy(request.app.state.knowledge, project_id)
    return {
        "state": state,
        "relationships": config["relationships"],
        "actor_id": config.get("actor_id"),
        "capabilities": ["configure"] if actor.allowed(db, project, "manage") else [],
        "limitations": [
            "Latest committed heads are coalesced after downtime; intermediate heads are not individually scheduled.",
            "Policy author credential and manage permission must remain current; expired credentials require explicit policy reauthorization.",
            "Proposals never change target inventory, assessments, approvals or scores.",
        ],
    }


@router.put("/projects/{project_id}/synchronization-policy")
def put_policy(project_id: str, data: SynchronizationInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    try:
        receipt = configure(
            request.app.state.knowledge, project_id=project_id, actor=actor, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/synchronization-jobs")
def list_jobs(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    rows = list(
        db.scalars(
            select(Job)
            .where(Job.project_id == project_id, Job.kind == KIND)
            .order_by(Job.created_at.desc(), Job.id)
            .offset(offset)
            .limit(limit + 1)
        )
    )
    return {
        "items": [view(db, actor, row, request.app.state.knowledge) for row in rows[:limit]],
        "next_offset": offset + limit if len(rows) > limit else None,
    }


@router.get("/projects/{project_id}/synchronization-jobs/{job_id}")
def get_job(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    return view(db, actor, selected(db, actor, project_id, job_id), request.app.state.knowledge)


@router.get("/projects/{project_id}/synchronization-jobs/{job_id}/proposal")
def proposal(
    project_id: str,
    job_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    job = selected(db, actor, project_id, job_id)
    if job.status != "succeeded":
        raise HTTPException(409, "Synchronization proposal is not available yet")
    report = request.app.state.knowledge.load(job.result["artifact_sha"])
    rows = report.pop("items")
    return {
        **report,
        "items": rows[offset : offset + limit],
        "next_offset": offset + limit if offset + limit < len(rows) else None,
        "stale": job_view(job, request.app.state.knowledge)["stale"],
        "job_id": job.id,
    }


@router.post("/projects/{project_id}/synchronization-jobs/{job_id}/{action}")
def action(project_id: str, job_id: str, action: str, request: Request, db: DB, actor: Auth):
    if action not in {"retry", "cancel"}:
        raise HTTPException(404, "Unknown synchronization action")
    job = selected(db, actor, project_id, job_id, "manage", lock=True)
    if job.actor_id != actor.user.id:
        raise HTTPException(403, "Only the policy author can retry or cancel its proposal")
    if action == "retry":
        if job.status != "failed":
            # An uncertain retry may already have queued/completed this exact job.
            return view(db, actor, job, request.app.state.knowledge)
        # Explicit retry preserves every knowledge pin, reauthorizing only execution.
        job.payload = {**job.payload, "credential_id": actor.credential.id}
        job.status, job.error, job.lease_until = "queued", "", None
    elif job.status in {"queued", "running"}:
        job.status, job.lease_until = "cancelled", None
    return view(db, actor, job, request.app.state.knowledge)
