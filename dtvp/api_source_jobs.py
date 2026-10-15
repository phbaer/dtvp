"""Explicit version-bound read-only source collection jobs."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.domain import audit
from dtvp.knowledge.journal import Conflict, Name
from dtvp.knowledge.source_jobs import (
    KIND,
    SourceJobInput,
    enqueue_source,
    retry_source,
    source_job_view,
)
from dtvp.models import Job, Project
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")


class BindingInput(RequestModel):
    external_project_id: UUID
    expected_external_project_id: UUID | None


@router.get("/projects/{project_id}/versions/{version}/connectors/dependency-track")
def binding(project_id: str, version: Name, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    config = project.metadata_json.get("connectors", {}).get("dependency-track", {})
    settings = request.app.state.settings
    return {
        **config.get("versions", {}).get(version, {"project_id": None}),
        "configured": bool(settings.dt_url and settings.dt_api_key),
        "capabilities": [
            action
            for action, capability in (("bind", "manage"), ("import", "write"))
            if actor.allowed(db, project, capability)
        ],
    }


@router.put("/projects/{project_id}/versions/{version}/connectors/dependency-track")
def bind(project_id: str, version: Name, data: BindingInput, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    project = db.scalar(
        select(Project)
        .where(Project.id == project_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    metadata = project.metadata_json
    connectors = metadata.get("connectors", {})
    config = connectors.get("dependency-track", {})
    versions = config.get("versions", {})
    existing = versions.get(version, {}).get("project_id")
    expected = str(data.expected_external_project_id) if data.expected_external_project_id else None
    if existing != expected:
        raise HTTPException(409, "DT version binding changed; reload before replacing it")
    value = {"project_id": str(data.external_project_id)}
    project.metadata_json = {
        **metadata,
        "connectors": {
            **connectors,
            "dependency-track": {
                **config,
                "versions": {**versions, version: value},
            },
        },
    }
    audit(
        db,
        actor.user.id,
        "connector.bind",
        project_id,
        project_id,
        {
            "provider": "dependency-track",
            "version": version,
            **value,
        },
    )
    return value


def selected(db, actor, project_id, job_id, capability="read", *, lock=False):
    project_for(db, actor, project_id, capability)
    query = select(Job).where(Job.id == job_id, Job.project_id == project_id, Job.kind == KIND)
    job = db.scalar(query.with_for_update() if lock else query)
    if not job:
        raise HTTPException(404, "Native source job unavailable")
    return job


def view(db, actor, job):
    project = project_for(db, actor, job.project_id)
    actions = []
    if job.actor_id == actor.user.id and actor.allowed(db, project, "write"):
        if job.status in {"queued", "running"}:
            actions.append("cancel")
        if job.status in {"failed", "import_pending"}:
            actions.append("retry")
    return {**source_job_view(job), "capabilities": actions}


@router.post(
    "/projects/{project_id}/versions/{version}/imports/dependency-track/jobs", status_code=202
)
def enqueue(
    project_id: str, version: Name, data: SourceJobInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "write")
    try:
        return view(
            db,
            actor,
            enqueue_source(
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


@router.get("/projects/{project_id}/versions/{version}/source-jobs")
def jobs(
    project_id: str,
    version: Name,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    query = (
        select(Job)
        .where(
            Job.project_id == project_id,
            Job.kind == KIND,
            Job.payload["version"].as_string() == version,
        )
        .order_by(Job.created_at.desc(), Job.id)
    )
    rows = list(db.scalars(query.offset(offset).limit(limit + 1)))
    return {
        "items": [view(db, actor, job) for job in rows[:limit]],
        "next_offset": offset + limit if len(rows) > limit else None,
    }


@router.get("/projects/{project_id}/source-jobs/{job_id}")
def job(project_id: str, job_id: str, db: DB, actor: Auth):
    return view(db, actor, selected(db, actor, project_id, job_id))


@router.post("/projects/{project_id}/source-jobs/{job_id}/retry", status_code=202)
def retry(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    selected(db, actor, project_id, job_id, "write", lock=True)
    try:
        return view(
            db,
            actor,
            retry_source(
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


@router.post("/projects/{project_id}/source-jobs/{job_id}/cancel")
def cancel(project_id: str, job_id: str, db: DB, actor: Auth):
    job = selected(db, actor, project_id, job_id, "write", lock=True)
    if job.actor_id != actor.user.id:
        raise HTTPException(403, "Only the submitting user can cancel this source job")
    if job.status in {"queued", "running"}:
        job.status, job.lease_until = "cancelled", None
    return view(db, actor, job)
