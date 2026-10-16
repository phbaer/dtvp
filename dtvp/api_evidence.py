"""Explicit VDR/VEX selection and pinned original evidence downloads."""

import json

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, Response, UploadFile

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.evidence import (
    EvidenceInput,
    WithdrawalInput,
    current_evidence,
    evidence_ref,
    import_evidence,
    resolve_evidence_artifact,
    withdraw_evidence,
)
from dtvp.knowledge.journal import SECTIONS, CommitUncertain, Conflict, Sha
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.vex import parse_evidence, preview_evidence
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/evidence/artifacts/{artifact}")
def retained_evidence_artifact(
    project_id: str,
    artifact: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    expected_evidence: Sha | None = None,
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    selected = expected_evidence or journal.resolve(evidence_ref(project_id))
    pinned = (
        resolve_evidence_artifact(journal, project_id, selected, artifact) if selected else None
    )
    if pinned is None:
        raise HTTPException(404, "Artifact is not retained in this evidence selection")
    return Response(
        journal.objects.read(artifact),
        media_type="application/octet-stream",
        headers={
            "X-Content-SHA256": artifact,
            "X-Knowledge-State": pinned,
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": 'attachment; filename="dtvp-evidence-artifact"',
        },
    )


@router.get("/projects/{project_id}/evidence")
def documents(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    state = journal.resolve(evidence_ref(project_id))
    records = journal.records(state, "vulnerabilities") if state else {}
    keys = sorted(key for key in records if key.startswith("evidence-document:"))
    summaries = []
    for key in keys[offset : offset + limit]:
        record = journal.load(records[key])
        document = record["document"]
        summaries.append(
            {
                "id": key,
                **{key: value for key, value in record.items() if key != "document"},
                "document": {
                    key: document.get(key)
                    for key in ("format", "document_id", "publisher", "revision", "losses")
                },
            }
        )
    return {
        "evidence_state": state,
        "versions": product_heads(journal.references(), project_id),
        "documents": summaries,
        "next_offset": offset + limit if offset + limit < len(keys) else None,
    }


def apply_document(project_id, data, request, db, actor, raw=None):
    project_for(db, actor, project_id, "evidence")
    try:
        receipt = import_evidence(
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            data=data,
            raw=raw,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/evidence/imports", status_code=201)
def import_document(project_id: str, data: EvidenceInput, request: Request, db: DB, actor: Auth):
    return apply_document(project_id, data, request, db, actor)


@router.post("/projects/{project_id}/evidence/files", status_code=201)
def import_document_file(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    file: UploadFile = File(),
    metadata: str = Form(max_length=65536),
):
    project_for(db, actor, project_id, "evidence")
    raw = file.file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(413, "Evidence file exceeds upload limit")
    # The adapter validates exact bytes, duplicate keys and the supported format.
    parse_evidence(raw)
    fields = json.loads(metadata)
    if not isinstance(fields, dict) or "document" in fields:
        raise ValueError("File metadata must contain import fields without document")
    data = EvidenceInput.model_validate({**fields, "document": json.loads(raw)})
    return apply_document(project_id, data, request, db, actor, raw=raw)


@router.post("/projects/{project_id}/evidence/preview")
def preview(project_id: str, data: EvidenceInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    journal = request.app.state.knowledge
    state, _ = current_evidence(journal, project_id)
    if (
        state != data.expected_evidence
        or product_heads(journal.references(), project_id) != data.expected_versions
    ):
        raise HTTPException(409, "Evidence or versions changed; refresh the preview")
    raw = canonical(data.document)
    record = {"document": parse_evidence(raw), "source": data.source, "artifact_sha": digest(raw)}
    previews = {
        version: preview_evidence(load_sections(journal, sha), record)
        for version, sha in data.expected_versions.items()
    }
    if not previews:
        previews["unassigned"] = preview_evidence({name: {} for name in SECTIONS}, record)
    return {
        "committed": False,
        "application": previews,
        "trust": "unverified_publisher_and_signature",
        "artifact_sha": digest(raw),
    }


@router.post("/projects/{project_id}/evidence/withdrawals", status_code=201)
def withdraw(project_id: str, data: WithdrawalInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "evidence")
    try:
        receipt = withdraw_evidence(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/evidence/{artifact}/source")
def original(project_id: str, artifact: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    state = journal.resolve(evidence_ref(project_id))
    records = journal.records(state, "vulnerabilities") if state else {}
    if "evidence-document:" + artifact not in records:
        raise HTTPException(404, "Evidence document unavailable")
    return Response(
        journal.objects.read(artifact),
        media_type="application/json",
        headers={
            "X-Content-SHA256": artifact,
            "Content-Disposition": 'attachment; filename="evidence.json"',
        },
    )
