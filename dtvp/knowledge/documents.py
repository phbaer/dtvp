"""Controlled generated artifacts; approval covers exact bytes and pinned inputs only."""

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator

from dtvp.knowledge.comparison import product_state
from dtvp.knowledge.issued_exports import (
    MATERIAL_FORMAT,
    material_fingerprint,
    resolve_issued_export,
)
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.controlled-document/1"
MAX_BYTES = 32 * 1024 * 1024
LIMITATIONS = [
    "Approval covers one exact generated artifact and its issued input bundle, not architecture correctness or regulatory compliance.",
    "Document approval does not approve cybersecurity assessments, license dispositions or a current release.",
    "Renderer identity and configuration are attributed declarations, not verified execution provenance.",
]


class Renderer(RequestModel):
    name: Name
    version: Name
    source_revision: str | None = Field(default=None, min_length=1, max_length=1000)


class DocumentInput(RequestModel):
    request_id: Name
    expected: Sha
    expected_revision: Sha | None
    document_id: Name
    issued_receipt_sha: Sha
    renderer: Renderer
    configuration: dict
    title: str = Field(min_length=1, max_length=1000)
    purpose: Literal["architecture", "soup", "license", "combined"]
    rationale: str = Field(min_length=1, max_length=6000)
    filename: str = Field(min_length=1, max_length=255, pattern=r"^[^/\\\x00-\x1f\x7f]+$")
    media_type: str = Field(
        min_length=3, max_length=127, pattern=r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$"
    )

    @field_validator("title", "rationale", "filename")
    @classmethod
    def nonblank(cls, value):
        if not value.strip() or value in {".", ".."}:
            raise ValueError("Document fields must contain meaningful text")
        return value


class DocumentReviewInput(RequestModel):
    request_id: Name
    expected: Sha
    document_id: Name
    revision: Sha
    action: Literal["approve", "request_changes"]
    rationale: str = Field(min_length=1, max_length=6000)
    acknowledge_historical: bool = False

    @field_validator("rationale")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Review rationale must contain meaningful text")
        return value


def keys(document_id):
    suffix = digest(canonical(document_id))
    return "document:" + suffix, "document-review:" + suffix


def _verify(journal, record):
    if record.get("format") != FORMAT or journal.load(record["revision"]) != record["payload"]:
        raise ValueError("Controlled document differs from its immutable revision")
    return record["payload"]


def _status(journal, sections, project_id, version, document_id, current_fingerprint):
    key, review_key = keys(document_id)
    current = sections["history"].get(key)
    if current is None:
        return None
    payload = _verify(journal, current)
    if payload["document_id"] != document_id:
        raise ValueError("Controlled document identifier differs from record key")
    review = sections["history"].get(review_key)
    approved = None
    historical_review = None
    if review:
        if journal.load(review["review_revision"]) != {
            k: v for k, v in review.items() if k != "review_revision"
        }:
            raise ValueError("Document review differs from its immutable revision")
        pinned = {
            "format": FORMAT,
            "revision": review["revision"],
            "payload": review["payload"],
            "stage": "submitted",
        }
        _verify(journal, pinned)
        review_payload = review["payload"]
        if (
            review_payload["project_id"] != project_id
            or review_payload["version"] != version
            or review_payload["document_id"] != document_id
        ):
            historical_review, review = review, None
        elif review["action"] == "approve":
            approved = pinned
    in_scope = payload["project_id"] == project_id and payload["version"] == version
    source_current = (
        in_scope
        and payload["material_fingerprint_id"] == MATERIAL_FORMAT
        and payload["material_fingerprint"] == current_fingerprint
    )
    status = (
        "out_of_scope"
        if not in_scope
        else "approved"
        if approved
        else "changes_requested"
        if review
        and review["action"] == "request_changes"
        and review["revision"] == current["revision"]
        else current["stage"]
    )
    return {
        "document_id": document_id,
        "status": status,
        "document": current,
        "review": review,
        "historical_review": historical_review,
        "approved_document": approved,
        "source_current": source_current,
        "approved_source_current": bool(
            approved
            and approved["payload"]["material_fingerprint_id"] == MATERIAL_FORMAT
            and approved["payload"]["version"] == version
            and approved["payload"]["material_fingerprint"] == current_fingerprint
        ),
        "pending": bool(approved and approved["revision"] != current["revision"]),
        "limitations": list(LIMITATIONS),
    }


def document_status(journal, state, document_id):
    revision = journal.state(state)
    product_state(journal, state, revision.project_id)
    return _status(
        journal,
        load_sections(journal, state),
        revision.project_id,
        revision.version,
        document_id,
        material_fingerprint(journal, state),
    )


def list_documents(journal, state, offset=0, limit=50, *, paginate=True):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid document page bounds")
    revision = journal.state(state)
    product_state(journal, state, revision.project_id)
    sections = load_sections(journal, state)
    fingerprint = material_fingerprint(journal, state)
    records = [
        value for key, value in sorted(sections["history"].items()) if key.startswith("document:")
    ]
    items = [
        _status(
            journal,
            sections,
            revision.project_id,
            revision.version,
            value["payload"]["document_id"],
            fingerprint,
        )
        for value in records
    ]
    return {
        "items": items[offset : offset + limit] if paginate else items,
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit if paginate and offset + limit < len(items) else None,
        "by_status": dict(Counter(item["status"] for item in items)),
    }


def _prepare(journal, project_id, version, actor_id, data, operation, extra=None):
    fingerprint = digest(
        canonical(
            [
                "document." + operation,
                project_id,
                version,
                actor_id,
                data.model_dump(mode="json"),
                extra,
            ]
        )
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt, None, None, request_id, fingerprint
    if journal.resolve(Ref(project_id=project_id, name=version)) != data.expected:
        raise Conflict("Product version changed; reload before editing documents")
    previous = product_state(journal, data.expected, project_id)
    if previous.version != version:
        raise ValueError("Document requires the selected product version")
    return None, load_sections(journal, data.expected), previous, request_id, fingerprint


def _publish(
    journal,
    project_id,
    version,
    actor_id,
    data,
    sections,
    previous,
    request_id,
    fingerprint,
    artifacts,
    parents=(),
):
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Record controlled generated document",
        sections=sections,
        parents=list(dict.fromkeys([data.expected, *parents])),
        artifacts=sorted(set(previous.artifacts) | set(artifacts)),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[
            Update(
                ref=Ref(project_id=project_id, name=version), expected=data.expected, target=state
            )
        ],
    )


def register_document(journal, project_id, version, actor_id, data, raw, *, submit, authorize):
    authorize("documentary_assess")
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ValueError("Document artifact must contain 1 byte to 32 MiB")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, data, "submit" if submit else "draft", digest(raw)
    )
    if receipt:
        return receipt
    key, _ = keys(data.document_id)
    current = sections["history"].get(key)
    if (current["revision"] if current else None) != data.expected_revision:
        raise Conflict("Controlled document revision changed")
    if current and _verify(journal, current)["actor_id"] != actor_id:
        raise PermissionError("Only the document author may revise its logical document")
    issued = resolve_issued_export(journal, project_id, data.issued_receipt_sha)
    if not issued or issued["kind"] != "knowledge-bundle" or issued["version"] != version:
        raise ValueError(
            "Document requires an issued knowledge bundle for the same product version"
        )
    configuration = canonical(data.configuration)
    if len(configuration) > 1024 * 1024:
        raise ValueError("Renderer configuration exceeds 1 MiB")
    artifact_sha, config_sha = journal.objects.put(raw), journal.objects.put(configuration)
    payload = {
        "format": FORMAT,
        "project_id": project_id,
        "version": version,
        "actor_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        **data.model_dump(
            mode="json", exclude={"request_id", "expected", "expected_revision", "configuration"}
        ),
        "artifact_sha256": artifact_sha,
        "artifact_bytes": len(raw),
        "configuration_sha256": config_sha,
        "issued_state": issued["issuance_state"],
        "source_state": issued["source_state"],
        "bundle_sha256": issued["files"]["bundle.json"]["sha256"],
        "material_fingerprint_id": issued["material_fingerprint_id"],
        "material_fingerprint": issued["material_fingerprint"],
        "serializer_id": issued["serializer_id"],
    }
    revision = journal.store(payload)
    sections["history"][key] = {
        "format": FORMAT,
        "revision": revision,
        "payload": payload,
        "stage": "submitted" if submit else "draft",
    }
    return _publish(
        journal,
        project_id,
        version,
        actor_id,
        data,
        sections,
        previous,
        request_id,
        fingerprint,
        [revision, artifact_sha, config_sha],
        parents=[issued["issuance_state"]],
    )


def review_document(journal, project_id, version, actor_id, data, *, authorize):
    authorize("documentary_approve")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, data, "review"
    )
    if receipt:
        return receipt
    key, review_key = keys(data.document_id)
    current = sections["history"].get(key)
    if not current or current["revision"] != data.revision or current["stage"] != "submitted":
        raise Conflict("Review requires the exact current submitted document revision")
    payload = _verify(journal, current)
    if payload["actor_id"] == actor_id:
        raise PermissionError("Document review requires an independent actor")
    if payload["version"] != version:
        raise Conflict("Document belongs to another product version")
    source_current = payload["material_fingerprint_id"] == MATERIAL_FORMAT and payload[
        "material_fingerprint"
    ] == material_fingerprint(journal, data.expected)
    if not source_current and not data.acknowledge_historical:
        raise Conflict("Historical document review requires explicit acknowledgement")
    review = {
        "format": "dtvp.document-review/1",
        "revision": data.revision,
        "payload": payload,
        "action": data.action,
        "reviewer_id": actor_id,
        "rationale": data.rationale,
        "created_at": datetime.now(UTC).isoformat(),
        "source_current_at_review": source_current,
        "acknowledge_historical": data.acknowledge_historical,
    }
    review_sha = journal.store(review)
    sections["history"][review_key] = {**review, "review_revision": review_sha}
    return _publish(
        journal,
        project_id,
        version,
        actor_id,
        data,
        sections,
        previous,
        request_id,
        fingerprint,
        [data.revision, review_sha],
    )
