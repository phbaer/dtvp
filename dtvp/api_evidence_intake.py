"""Exact-byte semantic previews; source-order and publication remain separate checks."""

import json

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.evidence import EvidenceInput, evidence_ref
from dtvp.knowledge.journal import SECTIONS, Name, Sha
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.vex import parse_evidence, preview_evidence
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v3")
LIMITATIONS = [
    "Semantic scope preview only: matching, unresolved scope and contradictions are not an exact simulation of source supersession or ordinal ordering.",
    "Import separately validates producer revision ordering and all current evidence/version pins; preview never publishes or approves anything.",
    "Publisher/signature and consuming-context applicability are unverified. Unsupported fields remain explicit losses; JSON semantic subsets only.",
]


class EvidencePins(RequestModel):
    expected_evidence: Sha | None
    expected_versions: dict[Name, Sha]


def checked_refs(journal, project_id, data):
    references = journal.references()
    if (
        references.get(evidence_ref(project_id).key) != data.expected_evidence
        or product_heads(references, project_id) != data.expected_versions
    ):
        raise HTTPException(409, "Evidence or product versions changed; refresh explicitly")


def describe_preview(journal, data, record):
    applications = {
        version: preview_evidence(load_sections(journal, state), record)
        for version, state in data.expected_versions.items()
    }
    if not applications:
        applications["unassigned"] = preview_evidence({name: {} for name in SECTIONS}, record)
    document = record["document"]
    content = {
        "committed": False,
        "expected_evidence": data.expected_evidence,
        "expected_versions": data.expected_versions,
        "artifact_sha": record["artifact_sha"],
        "source": record["source"],
        "source_revision": record.get("source_revision"),
        "active": record.get("active", True),
        "document": {
            key: document.get(key)
            for key in ("format", "document_id", "publisher", "revision", "losses")
        },
        "application": applications,
        "trust": "unverified_publisher_and_signature",
        "limitations": LIMITATIONS,
    }
    if "conformance" in document:
        content["conformance"] = document["conformance"]
    return {**content, "preview_digest": digest(canonical(content))}


@router.post("/projects/{project_id}/evidence/files/preview")
def file_preview(
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
    fields = json.loads(metadata)
    if not isinstance(fields, dict) or "document" in fields:
        raise ValueError("File metadata must contain import fields without document")
    normalized = parse_evidence(raw, validation_profile=fields.get("validation_profile"))
    data = EvidenceInput.model_validate({**fields, "document": normalized["raw"]})
    journal = request.app.state.knowledge
    checked_refs(journal, project_id, data)
    return describe_preview(
        journal,
        data,
        {
            "document": normalized,
            "artifact_sha": digest(raw),
            "source": data.source,
            "source_revision": data.revision,
        },
    )


@router.post("/projects/{project_id}/evidence/{artifact}/preview")
def retained_preview(
    project_id: str, artifact: Sha, data: EvidencePins, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    checked_refs(journal, project_id, data)
    records = (
        journal.records(data.expected_evidence, "vulnerabilities") if data.expected_evidence else {}
    )
    sha = records.get("evidence-document:" + artifact)
    if sha is None:
        raise HTTPException(404, "Artifact is not a document in the selected evidence collection")
    return describe_preview(journal, data, journal.load(sha))


class ConformanceInput(RequestModel):
    document: dict
    validation_profile: str


@router.post("/projects/{project_id}/evidence/conformance")
def inspect_conformance(project_id: str, data: ConformanceInput, db: DB, actor: Auth):
    """Read-only validation; no source, policy or publication claims."""
    project_for(db, actor, project_id, "evidence")
    from dtvp.knowledge.evidence_conformance import conformance

    raw = canonical(data.document)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("Evidence exceeds the 32 MiB validation limit")
    report = conformance(data.document, data.validation_profile)
    if report["valid"]:
        try:
            parse_evidence(raw, validation_profile=data.validation_profile)
        except ValueError:
            report["valid"] = False
            report["diagnostics"] = [{"path": "/", "code": "unsupported_statement_semantics"}]
    return report


class SchemaValidationInput(RequestModel):
    document: dict
    validation_profile: str


@router.post("/projects/{project_id}/evidence/schema-validation")
def inspect_schema(project_id: str, data: SchemaValidationInput, db: DB, actor: Auth):
    """Opt-in read-only official schema check; never changes the intake contract."""
    project_for(db, actor, project_id, "evidence")
    from dtvp.knowledge.schema_validation import validate_schema

    return validate_schema(data.document, data.validation_profile)
