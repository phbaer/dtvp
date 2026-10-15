"""DTVP-side analysis operations. Agentyzer remains separately deployed."""

import json
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import Field
from sqlalchemy import select

from dtvp.analysis import enabled, mode, source_binding
from dtvp.api import DB, Auth, finding_for, project_for
from dtvp.domain import audit, lock_release
from dtvp.jobs import enqueue
from dtvp.models import Component, Job, Project
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v2")


class AnalysisBinding(RequestModel):
    component_name: str = Field(min_length=1, max_length=200)


class AnalysisInput(RequestModel):
    expected_version: int = Field(ge=1)
    guidance: str = Field(default="", max_length=6000)
    parent_job_id: str | None = None
    question: str = Field(default="", max_length=6000)
    demo_outcome: str = Field(default="eligible", pattern="^(eligible|inconclusive|failure)$")


@router.put("/projects/{project_id}/connectors/agentyzer")
def bind(project_id: str, data: AnalysisBinding, db: DB, actor: Auth):
    project = project_for(db, actor, project_id, "manage")
    db.refresh(project, with_for_update=True)
    if not data.component_name.strip():
        raise HTTPException(422, "Repository name must not be empty")
    project.metadata_json = {
        **project.metadata_json,
        "connectors": {
            **project.metadata_json.get("connectors", {}),
            "agentyzer": {"component_name": data.component_name.strip()},
        },
    }
    audit(db, actor.user.id, "connector.bind", project.id, project.id, {"provider": "agentyzer"})
    return project.metadata_json["connectors"]["agentyzer"]


@router.post("/findings/{finding_id}/analyses", status_code=202)
def submit(finding_id: str, data: AnalysisInput, db: DB, actor: Auth, request: Request):
    finding = finding_for(db, actor, finding_id, "evidence")
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    if finding.state_version != data.expected_version or not finding.active:
        raise HTTPException(409, "Finding changed; reload before analysis")
    settings = request.app.state.settings
    if not enabled(settings):
        raise HTTPException(422, "Agentyzer is not enabled by deployment configuration")
    project = db.get(Project, release.project_id)
    binding = project.metadata_json.get("connectors", {}).get("agentyzer", {}).get("component_name")
    if mode(settings) == "external" and not binding:
        raise HTTPException(
            422, "An administrator must bind this product to an Agentyzer repository name"
        )
    component = db.get(Component, finding.component_id)
    from packageurl import PackageURL

    package = PackageURL.from_string(component.purl) if component.purl else None
    package_name = (
        f"{package.namespace}/{package.name}"
        if package and package.namespace
        else package.name
        if package
        else component.name
    )
    target = {
        "component_id": component.id,
        "package_name": package_name,
        "version": component.version,
        "purl": component.purl,
    }
    outbound = {
        "component_name": binding or project.name,
        "vuln_id": finding.identifier,
        "project_name": project.name,
        "project_versions": [release.version],
        "assessment_scope": "repository",
        "user_guidance": data.guidance,
    }
    qualified_source = source_binding(db, finding, binding)
    target["source_binding"] = qualified_source
    if mode(settings) == "external" and qualified_source["status"] == "known":
        outbound["source_commit"] = qualified_source["source_commit"]
    parent_remote_id = None
    if data.parent_job_id:
        parent = db.get(Job, data.parent_job_id)
        if (
            not parent
            or parent.kind != "analyse"
            or parent.payload.get("finding_id") != finding.id
            or parent.status != "succeeded"
        ):
            raise HTTPException(422, "Follow-up requires a completed analysis of this finding")
        if (
            parent.result.get("evidence_revision") != finding.evidence_revision
            or parent.payload.get("endpoint_digest") != digest(settings.agentyzer_url.encode())
            or parent.payload.get("mode") != mode(settings)
            or parent.payload["request"]["component_name"] != outbound["component_name"]
            or parent.payload["target"].get("source_binding") != qualified_source
        ):
            raise HTTPException(409, "Parent analysis is stale; start a new analysis")
        if not data.question.strip():
            raise HTTPException(422, "A follow-up question is required")
        parent_remote_id = parent.payload["remote_id"]
    elif data.question:
        raise HTTPException(422, "A follow-up question requires a parent analysis")
    fingerprint = digest(
        canonical(
            [
                outbound,
                finding.id,
                target,
                finding.evidence_revision,
                data.parent_job_id,
                data.question,
                data.demo_outcome,
                mode(settings),
                settings.agentyzer_url,
            ]
        )
    )
    pending = db.scalar(
        select(Job).where(
            Job.project_id == project.id,
            Job.kind == "analyse",
            Job.status.in_(["queued", "running"]),
            Job.payload["fingerprint"].as_string() == fingerprint,
        )
    )
    if pending:
        return {"id": pending.id, "status": pending.status, "deduplicated": True}
    payload = {
        "finding_id": finding.id,
        "target": target,
        "evidence_revision": finding.evidence_revision,
        "request": outbound,
        "mode": mode(settings),
        "endpoint_digest": digest(settings.agentyzer_url.encode()),
        "fingerprint": fingerprint,
        "parent_remote_id": parent_remote_id,
        "parent_job_id": data.parent_job_id,
        "question": data.question,
        "demo_outcome": data.demo_outcome,
    }
    job = enqueue(db, actor, release, "analyse", payload)
    audit(db, actor.user.id, "analysis.enqueue", job.id, project.id, {"finding_id": finding.id})
    return {"id": job.id, "status": job.status}


def representation(job, finding):
    result = dict(job.result)
    if (
        job.status == "succeeded"
        and job.payload.get("mode") == "external"
        and result.get("source_verified") is not True
    ):
        result.update(
            application_eligible=False,
            rescoring_eligible=False,
            proposal_state=None,
            ineligibility_reasons=result.get("ineligibility_reasons")
            or ["Historical external report has no verified analysis source binding"],
        )
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "error": job.error,
        "result": result,
        "created_at": job.created_at.isoformat(),
        "parent_job_id": job.payload.get("parent_job_id"),
        "current": job.result.get("evidence_revision") == finding.evidence_revision,
    }


@router.get("/findings/{finding_id}/analyses")
def history(
    finding_id: str, db: DB, actor: Auth, cursor: str = "", limit: int = Query(20, ge=1, le=100)
):
    from dtvp.catalog import after_cursor, page_cursor

    finding = finding_for(db, actor, finding_id)
    scope = ["analyses", finding_id]
    query = select(Job).where(
        Job.kind == "analyse", Job.payload["finding_id"].as_string() == finding.id
    )
    query = after_cursor(
        query,
        Job.created_at,
        Job.id,
        cursor,
        scope,
        descending=True,
        value_parser=datetime.fromisoformat,
    )
    rows = list(db.scalars(query.order_by(Job.created_at.desc(), Job.id.desc()).limit(limit + 1)))
    return {
        "items": [representation(job, finding) for job in rows[:limit]],
        "next_cursor": page_cursor(
            rows[limit - 1].created_at.isoformat(), rows[limit - 1].id, scope
        )
        if len(rows) > limit
        else None,
    }


@router.get("/analyses/{job_id}/report")
def report(job_id: str, db: DB, actor: Auth, request: Request):
    job = db.get(Job, job_id)
    if not job or job.kind != "analyse":
        raise HTTPException(404, "Analysis unavailable")
    finding_for(db, actor, job.payload["finding_id"])
    if job.status != "succeeded":
        raise HTTPException(409, "Analysis report is not ready")
    return json.loads(request.app.state.artifacts.read(job.result["report_sha256"]))
