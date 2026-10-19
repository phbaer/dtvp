"""Explicit, baseline-known advisory refresh jobs; no package matching or approvals."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.advisory_jobs import (
    KIND,
    AdvisoryRefreshInput,
    advisory_job_view,
    enqueue_advisory_refresh,
    retry_advisory_refresh,
)
from dtvp.knowledge.advisory_sources import PUBLISHERS, baseline_identifiers
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.ownership import product_heads
from dtvp.models import Job
from dtvp.non_us_advisories import IDENTIFIER_FORMATS, supports_identifier

router = APIRouter(prefix=API_PREFIX)


def selected(db, actor, project_id, job_id, capability="read", *, lock=False):
    project_for(db, actor, project_id, capability)
    query = select(Job).where(Job.id == job_id, Job.project_id == project_id, Job.kind == KIND)
    value = db.scalar(query.with_for_update() if lock else query)
    if value is None:
        raise HTTPException(404, "Native advisory job unavailable")
    return value


def view(db, actor, job):
    project = project_for(db, actor, job.project_id)
    actions = []
    if job.actor_id == actor.user.id and actor.allowed(db, project, "evidence"):
        if job.status in {"queued", "running"}:
            actions.append("cancel")
        if job.status in {"failed", "import_pending"}:
            actions.append("retry")
    return {**advisory_job_view(job), "capabilities": actions}


@router.get("/projects/{project_id}/advisory-refresh")
def refresh_inputs(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    provider: Literal["nvd", "circl", "euvd", "jvn"] | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    references = journal.references()
    versions = product_heads(references, project_id)
    evidence = references.get(evidence_ref(project_id).key)
    records = journal.records(evidence, "vulnerabilities") if evidence else {}
    documents = [
        journal.load(sha) for key, sha in records.items() if key.startswith("evidence-document:")
    ]
    identifiers = sorted(
        value
        for value in baseline_identifiers(journal, project_id, versions, require_current=False)
        if any(supports_identifier(provider, value) for provider in PUBLISHERS)
        and q.casefold() in value.casefold()
    )
    unsupported_total = (
        sum(not supports_identifier(provider, value) for value in identifiers) if provider else 0
    )
    if provider:
        identifiers = [value for value in identifiers if supports_identifier(provider, value)]
    providers = []
    selected_provider = provider
    for provider, publisher in PUBLISHERS.items():
        revisions = [
            record["source_revision"]
            for record in documents
            if record.get("source") == "connector:" + provider
            and record["document"].get("document_id") == "dtvp-provider-catalog:" + provider
            and record["document"].get("publisher") == publisher
        ]
        providers.append(
            {
                "id": provider,
                "publisher": publisher,
                "identifier_formats": IDENTIFIER_FORMATS[provider],
                "enabled": provider in request.app.state.settings.providers_enabled,
                "next_revision": max(revisions, default=-1) + 1,
            }
        )
    return {
        "expected_versions": versions,
        "expected_evidence": evidence,
        "providers": providers,
        "identifiers": identifiers[offset : offset + limit],
        "total": len(identifiers),
        "unsupported_total": unsupported_total,
        "selected_provider": selected_provider,
        "next_offset": offset + limit if offset + limit < len(identifiers) else None,
        "capabilities": ["refresh"] if actor.allowed(db, project, "evidence") else [],
        "limitations": [
            "Only exact IDs claimed by baseline observations or active exact package-matching sources can be enriched; this refresh performs no package matching or approval.",
            "Provider not-found never proves remediation; source and publisher attribution remain distinct.",
        ],
    }


@router.post("/projects/{project_id}/advisory-jobs", status_code=202)
def enqueue(project_id: str, data: AdvisoryRefreshInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    try:
        return view(
            db,
            actor,
            enqueue_advisory_refresh(
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
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error


@router.get("/projects/{project_id}/advisory-jobs")
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
        "items": [view(db, actor, value) for value in rows[:limit]],
        "next_offset": offset + limit if len(rows) > limit else None,
        "capabilities": ["refresh"] if actor.allowed(db, project, "evidence") else [],
    }


@router.get("/projects/{project_id}/advisory-jobs/{job_id}")
def job(project_id: str, job_id: str, db: DB, actor: Auth):
    return view(db, actor, selected(db, actor, project_id, job_id))


@router.post("/projects/{project_id}/advisory-jobs/{job_id}/retry", status_code=202)
def retry(project_id: str, job_id: str, request: Request, db: DB, actor: Auth):
    selected(db, actor, project_id, job_id, "evidence", lock=True)
    try:
        return view(
            db,
            actor,
            retry_advisory_refresh(
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


@router.post("/projects/{project_id}/advisory-jobs/{job_id}/cancel")
def cancel(project_id: str, job_id: str, db: DB, actor: Auth):
    value = selected(db, actor, project_id, job_id, "evidence", lock=True)
    if value.actor_id != actor.user.id:
        raise HTTPException(403, "Only the submitting user can cancel this advisory refresh")
    if value.status in {"queued", "running"}:
        value.status, value.lease_until = "cancelled", None
    return view(db, actor, value)
