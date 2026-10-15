"""Product-wide evidence selection, independently durable before any inventory."""

import copy
from datetime import UTC, datetime

from pydantic import Field

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.vex import parse_evidence, reconcile_evidence
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class EvidenceInput(RequestModel):
    request_id: Name
    expected_evidence: Sha | None
    expected_versions: dict[Name, Sha]
    source: Name
    revision: int = Field(ge=0, strict=True)
    document: dict


class WithdrawalInput(RequestModel):
    request_id: Name
    expected_evidence: Sha | None
    expected_versions: dict[Name, Sha]
    artifact_sha: Sha
    reason: str = Field(min_length=1, max_length=6000)


def evidence_ref(project_id):
    return Ref(kind="evidence", project_id=project_id, name="documents")


def current_evidence(journal, project_id):
    state = journal.resolve(evidence_ref(project_id))
    records = journal.records(state, "vulnerabilities") if state else {}
    return state, {
        key: journal.load(sha)
        for key, sha in records.items()
        if key.startswith("evidence-document:")
    }


def merge_documents(sections, documents):
    """Replace only the product evidence view; preserve baseline observations."""
    records = sections["vulnerabilities"]
    for key in list(records):
        if key.startswith(("evidence-document:", "external-evidence:")):
            del records[key]
    records.update(copy.deepcopy(documents))
    reconcile_evidence(sections)


def apply_current_evidence(journal, sections, project_id):
    state, documents = current_evidence(journal, project_id)
    merge_documents(sections, documents)
    return state


def prepare(journal, project_id, actor_id, operation, data, raw=None):
    fingerprint = digest(
        canonical(
            [
                operation,
                project_id,
                actor_id,
                data.model_dump(mode="json"),
                digest(raw) if raw is not None else None,
            ]
        )
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    return request_id, fingerprint, receipt


def expected_documents(journal, project_id, expected_evidence, expected_versions):
    refs = journal.references()
    if refs.get(evidence_ref(project_id).key) != expected_evidence:
        raise Conflict("Product evidence changed; reload before updating")
    if product_heads(refs, project_id) != expected_versions:
        raise Conflict("Product versions changed; reload before updating evidence")
    if not expected_evidence:
        return {}
    return {
        key: journal.load(sha)
        for key, sha in journal.records(expected_evidence, "vulnerabilities").items()
        if key.startswith("evidence-document:")
    }


def publish_documents(
    journal, *, project_id, actor_id, data, documents, request_id, fingerprint, reason
):
    sections = {name: {} for name in SECTIONS}
    sections["vulnerabilities"] = documents
    artifacts = sorted({record["artifact_sha"] for record in documents.values()})
    evidence_state = journal.snapshot(
        project_id=project_id,
        version="@evidence",
        actor_id=actor_id,
        reason=reason,
        sections=sections,
        parents=[data.expected_evidence] if data.expected_evidence else [],
        artifacts=artifacts,
    )
    updates = [
        Update(ref=evidence_ref(project_id), expected=data.expected_evidence, target=evidence_state)
    ]
    for version, parent in sorted(data.expected_versions.items()):
        previous = journal.state(parent)
        if previous.project_id != project_id or previous.version != version:
            raise Conflict("Expected branch state belongs to another product version")
        sections = {
            name: {key: journal.load(sha) for key, sha in journal.records(parent, name).items()}
            for name in SECTIONS
        }
        merge_documents(sections, documents)
        state = journal.snapshot(
            project_id=project_id,
            version=version,
            actor_id=actor_id,
            reason=reason,
            sections=sections,
            parents=[parent, evidence_state],
            artifacts=sorted(set(previous.artifacts) | set(artifacts)),
        )
        updates.append(
            Update(ref=Ref(project_id=project_id, name=version), expected=parent, target=state)
        )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=updates,
        branch_heads={project_id: data.expected_versions},
    )


def import_evidence(journal, *, project_id, actor_id, data, raw=None):
    """Select a producer-ordered revision, never infer ordering from arrival time.

    JSON requests retain canonical bytes; an optional original file must describe
    exactly the same JSON document. Ordinals are explicit per publisher/source/
    document identity. Missing document IDs use content identity and cannot imply
    supersession of other documents.
    """
    original_file = raw is not None
    raw = canonical(data.document) if raw is None else raw
    request_id, fingerprint, receipt = prepare(
        journal, project_id, actor_id, "evidence.import/1", data, raw
    )
    if receipt:
        return receipt
    documents = expected_documents(
        journal, project_id, data.expected_evidence, data.expected_versions
    )
    normalized = parse_evidence(raw)
    if canonical(normalized["raw"]) != canonical(data.document):
        raise ValueError("Original evidence bytes do not match the declared document")
    sha = normalized["original_sha"]
    identity = normalized.get("document_id") or "sha256:" + sha
    binding = digest(canonical([data.source, normalized.get("publisher"), identity]))
    related = [record for record in documents.values() if record.get("binding") == binding]
    if related and data.revision <= max(record["source_revision"] for record in related):
        raise Conflict("Evidence source revision must increase for this document binding")
    key = "evidence-document:" + sha
    if key in documents and documents[key].get("binding") != binding:
        # One content object cannot be rebound to a different publisher/source
        # while silently replacing the first attribution. Same-binding ordinal
        # advancement is explicit; prior selection metadata stays in the journal.
        raise Conflict("These exact evidence bytes already belong to another source binding")
    for record in related:
        record.update(active=False, superseded_by=sha)
    original = journal.objects.put(raw)
    documents[key] = {
        "document": normalized,
        "artifact_sha": original,
        "source": data.source,
        "source_revision": data.revision,
        "binding": binding,
        "identity_basis": "publisher_source_document_id"
        if normalized.get("document_id")
        else "content_digest",
        "active": True,
        "actor_id": actor_id,
        "imported_at": datetime.now(UTC).isoformat(),
        "representation": "original_bytes" if original_file else "canonical_json",
    }
    return publish_documents(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        data=data,
        documents=documents,
        request_id=request_id,
        fingerprint=fingerprint,
        reason="Import product vulnerability evidence",
    )


def withdraw_evidence(journal, *, project_id, actor_id, data):
    request_id, fingerprint, receipt = prepare(
        journal, project_id, actor_id, "evidence.withdraw/1", data
    )
    if receipt:
        return receipt
    documents = expected_documents(
        journal, project_id, data.expected_evidence, data.expected_versions
    )
    record = documents.get("evidence-document:" + data.artifact_sha)
    if not record:
        raise ValueError("Evidence document does not belong to this product")
    if not record.get("active", True):
        raise Conflict("Evidence document is already inactive")
    record.update(
        active=False,
        withdrawal={
            "reason": data.reason,
            "actor_id": actor_id,
            "withdrawn_at": datetime.now(UTC).isoformat(),
        },
    )
    return publish_documents(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        data=data,
        documents=documents,
        request_id=request_id,
        fingerprint=fingerprint,
        reason="Withdraw product vulnerability evidence",
    )
