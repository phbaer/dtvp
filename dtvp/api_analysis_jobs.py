"""Explicit native analysis jobs; operational state stays separate from knowledge."""

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_analysis import AnalysisBinding, bind
from dtvp.api_knowledge import require_state
from dtvp.knowledge.analysis_followups import FollowUpInput, enqueue_followup
from dtvp.knowledge.analysis_jobs import (
    KIND,
    AnalysisJobInput,
    enqueue_analysis,
    job_view,
    retry_analysis,
)
from dtvp.knowledge.analysis_reconciliation import ReconcileInput, configured, reconcile_analysis
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha
from dtvp.models import Job

router = APIRouter(prefix="/api/v3")


@router.put("/projects/{project_id}/connectors/agentyzer")
def repository_binding(project_id: str, data: AnalysisBinding, db: DB, actor: Auth):
    return bind(project_id, data, db, actor)


def selected_job(db, actor, project_id, job_id, capability="read", *, lock=False):
    project_for(db, actor, project_id, capability)
    query = select(Job).where(Job.id == job_id, Job.project_id == project_id, Job.kind == KIND)
    job = db.scalar(query.with_for_update() if lock else query)
    if not job:
        raise HTTPException(404, "Native analysis job unavailable")
    return job


def allowed_actions(db, actor, project):
    return all(actor.allowed(db, project, cap) for cap in ("read", "snapshot", "evidence"))


def view(db, actor, selected, settings=None):
    project = project_for(db, actor, selected.project_id)
    actions = []
    if selected.actor_id == actor.user.id and allowed_actions(db, actor, project):
        if selected.status in {"queued", "running", "submission_unknown"}:
            actions.append("cancel")
        if selected.status in {"failed", "import_pending"} and (
            selected.payload.get("remote_id")
            or selected.payload.get("report_sha256")
            or (
                selected.payload.get("follow_up") and not selected.payload.get("submission_started")
            )
        ):
            actions.append("retry")
        if (
            selected.status == "submission_unknown"
            and selected.payload.get("correlation")
            and settings
            and configured(settings)
        ):
            actions.append("reconcile")
    if (
        selected.status == "succeeded"
        and selected.payload.get("report_sha256")
        and selected.payload.get("correlation")
        and settings
        and configured(settings)
        and allowed_actions(db, actor, project)
    ):
        actions.append("follow_up")
    return {**job_view(selected), "capabilities": actions}


@router.post("/projects/{project_id}/versions/{version}/analysis-jobs", status_code=202)
def enqueue(
    project_id: str, version: Name, data: AnalysisJobInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "evidence")
    project_for(db, actor, project_id, "snapshot")
    project_for(db, actor, project_id)
    require_state(request.app.state.knowledge, data.expected, project_id)
    try:
        return view(
            db,
            actor,
            enqueue_analysis(
                db,
                request.app.state.knowledge,
                request.app.state.settings,
                project_id=project_id,
                version=version,
                actor=actor,
                data=data,
            ),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        raise HTTPException(
            503, "Input issuance uncertain; retry the identical analysis request"
        ) from error


@router.get("/projects/{project_id}/versions/{version}/analysis-jobs")
def jobs(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    context_id: Sha | None = None,
    vulnerability_id: Name | None = None,
):
    project = project_for(db, actor, project_id)
    # Version is an exact native payload field; SQL pagination must follow filtering.
    query = (
        select(Job)
        .where(
            Job.project_id == project_id,
            Job.kind == KIND,
            Job.payload["version"].as_string() == version,
        )
        .order_by(Job.created_at.desc(), Job.id)
    )
    if context_id:
        query = query.where(Job.payload["receipt"]["context_id"].as_string() == context_id)
    if vulnerability_id:
        query = query.where(
            Job.payload["receipt"]["vulnerability_id"].as_string() == vulnerability_id
        )
    rows = list(db.scalars(query.offset(offset).limit(limit + 1)))
    return {
        "items": [view(db, actor, job, request.app.state.settings) for job in rows[:limit]],
        "next_offset": offset + limit if len(rows) > limit else None,
        "capabilities": ["submit"] if allowed_actions(db, actor, project) else [],
    }


@router.get("/projects/{project_id}/analysis-jobs/{job_id}")
def job(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    return view(db, actor, selected_job(db, actor, project_id, job_id), request.app.state.settings)


@router.post("/projects/{project_id}/analysis-jobs/{job_id}/retry", status_code=202)
def retry(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    selected_job(db, actor, project_id, job_id, "evidence", lock=True)
    try:
        return view(
            db,
            actor,
            retry_analysis(
                db,
                request.app.state.knowledge,
                request.app.state.settings,
                project_id=project_id,
                job_id=job_id,
                actor=actor,
            ),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error


@router.post("/projects/{project_id}/analysis-jobs/{job_id}/cancel")
def cancel(project_id: str, job_id: str, db: DB, actor: Auth):
    selected = selected_job(db, actor, project_id, job_id, "evidence", lock=True)
    if selected.actor_id != actor.user.id:
        raise HTTPException(403, "Only the submitting user can cancel this analysis")
    if selected.status in {"queued", "running", "submission_unknown"}:
        selected.status = "cancelled"
        selected.lease_until = None
    return view(db, actor, selected)


@router.post("/projects/{project_id}/analysis-jobs/{job_id}/reconcile")
def reconcile(
    project_id: str, job_id: str, data: ReconcileInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "evidence")
    try:
        selected = reconcile_analysis(
            request.app.state.sessions,
            request.app.state.knowledge,
            request.app.state.settings,
            project_id=project_id,
            job_id=job_id,
            actor_id=actor.user.id,
            credential_id=actor.credential.id,
            data=data,
        )
        return view(db, actor, selected, request.app.state.settings)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except httpx.HTTPError, ValueError, TypeError:
        raise HTTPException(
            502,
            "Authenticated remote observation unavailable or inconsistent; nothing was attached",
        ) from None


@router.post(
    "/projects/{project_id}/versions/{version}/analysis-jobs/{parent_id}/follow-up", status_code=202
)
def follow_up(
    project_id: str,
    version: Name,
    parent_id: str,
    data: FollowUpInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    project_for(db, actor, project_id, "evidence")
    project_for(db, actor, project_id, "snapshot")
    project_for(db, actor, project_id)
    try:
        return view(
            db,
            actor,
            enqueue_followup(
                db,
                request.app.state.knowledge,
                request.app.state.settings,
                project_id=project_id,
                version=version,
                parent_id=parent_id,
                actor=actor,
                data=data,
            ),
            request.app.state.settings,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except httpx.HTTPError, ValueError, TypeError:
        raise HTTPException(
            502, "Authenticated parent evidence unavailable or inconsistent; no child was enqueued"
        ) from None
