"""Explicit native OSV matching jobs; source claims remain separate from assessments."""

from fastapi import APIRouter, HTTPException, Query, Request, Response
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.journal import Conflict, Sha
from dtvp.knowledge.osv_jobs import KIND, enqueue_matching, job_view, retry_matching
from dtvp.knowledge.osv_matching import LIMITATIONS, MAX_CAPTURE, MatchingInput, selection
from dtvp.knowledge.ownership import product_heads
from dtvp.models import Job
from dtvp.storage import canonical, digest

router = APIRouter(prefix=API_PREFIX)


def selected(db, actor, project_id, job_id, *, lock=False):
    project_for(db, actor, project_id)
    query = select(Job).where(Job.id == job_id, Job.project_id == project_id, Job.kind == KIND)
    job = db.scalar(query.with_for_update() if lock else query)
    if job is None:
        raise HTTPException(404, "Native OSV matching job unavailable")
    return job


def view(db, actor, job):
    project = project_for(db, actor, job.project_id)
    actions = []
    if job.actor_id == actor.user.id and actor.allowed(db, project, "evidence"):
        if job.status in {"queued", "running"}:
            actions.append("cancel")
        if job.status in {"failed", "import_pending"}:
            actions.append("retry")
    return {**job_view(job), "capabilities": actions}


@router.get("/projects/{project_id}/osv-matching")
def inputs(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    refs = journal.references()
    versions = product_heads(refs, project_id)
    evidence = refs.get(evidence_ref(project_id).key)
    coverage = (
        selection(journal, project_id, versions, current=False)
        if versions
        else {
            "packages": {},
            "unsupported_occurrences": {},
            "eligible_purls": 0,
            "eligible_occurrences": 0,
            "unqueried_coverage": "unknown",
        }
    )
    revisions = []
    if evidence:
        for key, sha in journal.records(evidence, "vulnerabilities").items():
            if key.startswith("evidence-document:"):
                record = journal.load(sha)
                if record.get("source") == "connector:osv-matching":
                    revisions.append(record["source_revision"])
    packages = sorted(coverage.pop("packages"))
    configured = "osv" in request.app.state.settings.providers_enabled
    return {
        "expected_versions": versions,
        "expected_evidence": evidence,
        "provider": "osv",
        "enabled": configured,
        "next_revision": max(revisions, default=-1) + 1,
        "purls": packages[offset : offset + limit],
        "total": len(packages),
        "next_offset": offset + limit if offset + limit < len(packages) else None,
        "coverage": coverage,
        "selection_digest": digest(canonical([versions, evidence, packages, coverage])),
        "capabilities": ["query"] if configured and actor.allowed(db, project, "evidence") else [],
        "limitations": LIMITATIONS,
    }


@router.post("/projects/{project_id}/osv-jobs", status_code=202)
def enqueue(project_id: str, data: MatchingInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    try:
        return view(
            db,
            actor,
            enqueue_matching(
                db,
                request.app.state.knowledge,
                request.app.state.settings,
                project_id=project_id,
                actor=actor,
                data=data,
            ),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.get("/projects/{project_id}/osv-jobs")
def jobs(
    project_id: str,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    query = (
        select(Job)
        .where(Job.project_id == project_id, Job.kind == KIND)
        .order_by(Job.created_at.desc(), Job.id)
    )
    rows = list(db.scalars(query.offset(offset).limit(limit + 1)))
    return {
        "items": [view(db, actor, job) for job in rows[:limit]],
        "next_offset": offset + limit if len(rows) > limit else None,
        "capabilities": ["query"] if actor.allowed(db, project, "evidence") else [],
    }


@router.get("/projects/{project_id}/osv-jobs/{job_id}")
def detail(project_id: str, job_id: str, db: DB, actor: Auth):
    return view(db, actor, selected(db, actor, project_id, job_id))


@router.post("/projects/{project_id}/osv-jobs/{job_id}/retry", status_code=202)
def retry(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    selected(db, actor, project_id, job_id, lock=True)
    try:
        return view(
            db,
            actor,
            retry_matching(
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


@router.post("/projects/{project_id}/osv-jobs/{job_id}/cancel")
def cancel(project_id: str, job_id: str, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    job = selected(db, actor, project_id, job_id, lock=True)
    if job.actor_id != actor.user.id:
        raise HTTPException(403, "Only the submitting actor may cancel matching")
    if job.status in {"queued", "running"}:
        job.status, job.lease_until = "cancelled", None
    return view(db, actor, job)


@router.get("/projects/{project_id}/osv-jobs/{job_id}/artifacts/{sha}")
def artifact(project_id: str, job_id: str, sha: Sha, request: Request, db: DB, actor: Auth):
    job = selected(db, actor, project_id, job_id)
    allowed = {
        *job.result.get("raw_artifact_shas", []),
        *[
            job.payload[key]
            for key in ("progress_sha256", "capture_sha256")
            if job.payload.get(key)
        ],
    }
    if sha not in allowed:
        raise HTTPException(404, "Matching artifact unavailable in this job")
    objects = request.app.state.knowledge.objects
    if objects.path(sha).stat().st_size > MAX_CAPTURE * 3:
        raise HTTPException(409, "Matching artifact exceeds supported bound")
    raw = objects.read(sha)
    if digest(raw) != sha:
        raise HTTPException(409, "Matching artifact digest differs")
    return Response(raw, media_type="application/json", headers={"X-Content-SHA256": sha})
