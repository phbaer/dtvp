"""Release context, dependency graph, and explicit consumer exports."""

import copy
import json
from uuid import UUID

from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select

from dtvp.api import DB, Auth, bounded_metadata, project_for, release_for, snapshot_for
from dtvp.domain import audit, inventory, lock_release
from dtvp.models import Finding, now
from dtvp.schemas import MetadataInput, RequestModel

router = APIRouter(prefix="/api/v2")


class DTBinding(RequestModel):
    external_project_id: UUID


@router.put("/projects/{project_id}/connectors/dependency-track")
def bind_dt(project_id: str, data: DTBinding, db: DB, actor: Auth):
    project = project_for(db, actor, project_id, "manage")
    connectors = {
        **project.metadata_json.get("connectors", {}),
        "dependency-track": {"project_id": str(data.external_project_id)},
    }
    project.metadata_json = {**project.metadata_json, "connectors": connectors}
    audit(
        db,
        actor.user.id,
        "connector.bind",
        project.id,
        project.id,
        {"provider": "dependency-track", "external_project_id": str(data.external_project_id)},
    )
    return connectors["dependency-track"]


@router.get("/releases/{release_id}/dependencies")
def dependencies(release_id: str, db: DB, actor: Auth):
    release = release_for(db, actor, release_id)
    effective, _, _ = inventory(db, release)
    return [
        {
            "revision_id": r.id,
            "source": r.source,
            "component_ids": r.document["component_ids"],
            "dependencies": r.document["bom"].get("dependencies", []),
            "completeness": r.completeness,
        }
        for r in effective
    ]


@router.put("/releases/{release_id}/metadata")
def release_metadata(release_id: str, data: MetadataInput, db: DB, actor: Auth):
    release_for(db, actor, release_id, "write")
    release = lock_release(db, release_id)
    if release.metadata_version != data.expected_version:
        raise HTTPException(409, "Release context changed; reload first")
    bounded_metadata(data.metadata)
    attachments = release.metadata_json.get("attachments", [])
    release.metadata_json = {**data.metadata, "attachments": attachments}
    release.metadata_version += 1
    release.generation += 1
    for finding in db.scalars(select(Finding).where(Finding.release_id == release.id)):
        finding.evidence_revision += 1
        finding.state_version += 1
    audit(db, actor.user.id, "release.context", release.id, release.project_id)
    return {"metadata": release.metadata_json, "metadata_version": release.metadata_version}


@router.post("/releases/{release_id}/attachments", status_code=201)
def upload_attachment(
    release_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    file: UploadFile = File(),
    kind: str = Form("threat_model"),
):
    release_for(db, actor, release_id, "write")
    if kind not in {"threat_model", "evidence", "attestation"}:
        raise HTTPException(422, "Unsupported attachment kind")
    release = lock_release(db, release_id)
    raw = file.file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(413, "Attachment too large")
    sha = request.app.state.artifacts.put(raw)
    attachments = release.metadata_json.get("attachments", [])
    if not any(a["sha256"] == sha and a["kind"] == kind for a in attachments):
        attachments = [
            *attachments,
            {
                "sha256": sha,
                "kind": kind,
                "filename": file.filename,
                "author_id": actor.user.id,
                "created_at": now().isoformat(),
            },
        ]
        release.metadata_json = {**release.metadata_json, "attachments": attachments}
        release.metadata_version += 1
        release.generation += 1
        for finding in db.scalars(select(Finding).where(Finding.release_id == release.id)):
            finding.evidence_revision += 1
            finding.state_version += 1
        audit(db, actor.user.id, "attachment.import", sha, release.project_id, {"kind": kind})
    return {"sha256": sha, "kind": kind}


@router.get("/releases/{release_id}/attachments/{sha}")
def attachment(release_id: str, sha: str, request: Request, db: DB, actor: Auth):
    release = release_for(db, actor, release_id)
    if not any(a["sha256"] == sha for a in release.metadata_json.get("attachments", [])):
        raise HTTPException(404, "Attachment unavailable")
    return Response(
        request.app.state.artifacts.read(sha),
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="release-attachment"'},
    )


@router.get("/snapshots/{snapshot_id}/exports/vex")
def vex_export(snapshot_id: str, db: DB, actor: Auth, request: Request):
    stored = snapshot_for(db, actor, snapshot_id)
    payload = json.loads(request.app.state.artifacts.read(stored.sha))
    bom = copy.deepcopy(payload["sbom"])
    refs = {c["id"]: c["refs"] for c in payload["components"]}
    statements = []
    for finding in payload["findings"]:
        if finding["lifecycle"] != "approved" or not refs.get(finding["component_id"]):
            continue
        decision = finding["decisions"][0]
        statements.append(
            {
                "bom-ref": finding["id"],
                "id": finding["identifier"],
                "source": {"name": "DTVP human review"},
                "affects": [{"ref": ref} for ref in refs[finding["component_id"]]],
                "analysis": {"state": decision["state"], "detail": decision["rationale"]},
                "properties": [
                    {"name": "dtvp:snapshot", "value": snapshot_id},
                    {"name": "dtvp:decision", "value": decision["id"]},
                ],
            }
        )
    bom["vulnerabilities"] = statements
    return JSONResponse(
        bom, headers={"Content-Disposition": 'attachment; filename="reviewed-vex.cdx.json"'}
    )
