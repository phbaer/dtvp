"""Explicit human license dispositions; no inferred legal/compliance conclusions."""

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, model_validator

from dtvp.knowledge.assessments import collection_scope, load_sections, semantic
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.metadata import Provenance, component_at
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.license-disposition/1"
LIMITATIONS = [
    "Dispositions are attributed human judgments for explicit usage assumptions, not automated legal advice or compatibility validation.",
    "Concluded expressions are preserved verbatim; DTVP does not infer SPDX validity or permission to distribute.",
    "Approval covers one exact component occurrence, product version and material product inventory context.",
]


class LicenseInput(RequestModel):
    request_id: Name
    expected: Sha
    expected_revision: Sha | None
    component_ref: str = Field(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")
    concluded_expression: str = Field(min_length=1, max_length=6000)
    disposition: Literal["allowed", "restricted", "prohibited", "unresolved"]
    obligations: list[str] = Field(default_factory=list, max_length=100)
    conditions: str = Field(default="", max_length=6000)
    evidence: list[dict] = Field(default_factory=list, max_length=100)
    distribution: str = Field(min_length=1, max_length=6000)
    modification: str = Field(min_length=1, max_length=6000)
    linking: str = Field(min_length=1, max_length=6000)
    rationale: str = Field(min_length=1, max_length=6000)
    provenance: Provenance

    @model_validator(mode="after")
    def meaningful_text(self):
        for name in (
            "concluded_expression",
            "distribution",
            "modification",
            "linking",
            "rationale",
        ):
            if not getattr(self, name).strip():
                raise ValueError(name + " must contain explicit human input")
        if any(not value.strip() or len(value) > 6000 for value in self.obligations):
            raise ValueError("Obligations must be nonempty bounded text")
        return self


class LicenseReviewInput(RequestModel):
    request_id: Name
    expected: Sha
    component_ref: str = Field(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")
    revision: Sha
    action: Literal["approve", "request_changes"]
    rationale: str = Field(min_length=1, max_length=6000)


def keys(component_ref):
    suffix = digest(canonical(component_ref))
    return "license-disposition:" + suffix, "license-review:" + suffix


def inventory_fingerprint(sections, version=None):
    """Whole product source context; nightly pointers and ownership are not facts."""
    source = sections["inventory"]
    inventory = {
        key: semantic(value) for key, value in source.items() if key not in {"baseline", "assembly"}
    }
    inventory["baseline"] = collection_scope(source.get("baseline", {}))
    if "assembly" in source:
        assembly = source["assembly"]
        inventory["assembly"] = {
            key: semantic(assembly[key])
            for key in (
                "format",
                "coverage_verification",
                "readiness",
                "missing_required_parts",
                "selected_part_count",
                "withdrawn_parts",
            )
            if key in assembly
        }
        inventory["assembly"]["coherence"] = {"status": assembly.get("coherence", {}).get("status")}
        inventory["assembly"]["parts"] = [
            {
                key: semantic(value)
                for key, value in part.items()
                if key not in {"state", "baseline", "artifact_sha"}
            }
            | {"scope": collection_scope(part.get("baseline", {}))}
            for part in assembly.get("parts", [])
        ]
    from dtvp.knowledge.metadata import FORMAT as METADATA_FORMAT
    from dtvp.knowledge.metadata import identity_fingerprint

    curated = {}
    for key, record in sections["history"].items():
        if not key.startswith("metadata:") or record.get("format") != METADATA_FORMAT:
            continue
        payload = record["payload"]
        component = component_at(sections, payload["component_ref"])
        if (
            (version is None or payload.get("version") == version)
            and component is not None
            and payload.get("identity_fingerprint") == identity_fingerprint(component)
        ):
            curated[payload["component_ref"]] = {
                key: payload[key] for key in ("annotations", "provenance")
            }
    if curated:
        inventory["curated_context"] = curated
    return digest(canonical(inventory))


def license_status(journal, sections, version, component_ref, *, source_fingerprint=None):
    key, review_key = keys(component_ref)
    current, review = sections["history"].get(key), sections["history"].get(review_key)
    source_fingerprint = source_fingerprint or inventory_fingerprint(sections, version)
    present = component_at(sections, component_ref) is not None

    def matching(record):
        payload = record["payload"]
        if journal.load(record["revision"]) != payload:
            raise ValueError("License disposition differs from immutable revision")
        return (
            payload.get("version") == version
            and payload.get("component_ref") == component_ref
            and payload.get("source_fingerprint") == source_fingerprint
        )

    current_valid = bool(current) and matching(current)
    approved = None
    if review and review.get("action") == "approve":
        pinned = {
            "revision": review["revision"],
            "payload": review["payload"],
            "stage": "submitted",
        }
        if present and matching(pinned):
            approved = pinned
    status = (
        "unassessed"
        if not current and not review
        else "absent"
        if not present
        else "approved"
        if approved
        else "out_of_scope"
        if current and current["payload"].get("version") != version
        else "stale"
        if current and not current_valid
        else "changes_requested"
        if review
        and review.get("action") == "request_changes"
        and current
        and review["revision"] == current["revision"]
        else current["stage"]
        if current
        else "stale"
    )
    return {
        "status": status,
        "recorded": bool(current),
        "submitted": bool(current_valid and current["stage"] == "submitted"),
        "approved": bool(approved),
        "assessment": current,
        "approved_assessment": approved,
        "review": review,
        "source_fingerprint": source_fingerprint,
        "pending": bool(current and approved and current["revision"] != approved["revision"]),
        "limitations": list(LIMITATIONS),
    }


def list_license_reviews(journal, sections, version, *, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid license disposition page bounds")
    fingerprint = inventory_fingerprint(sections, version)
    items = [
        {
            "component_ref": value["payload"]["component_ref"],
            **license_status(
                journal,
                sections,
                version,
                value["payload"]["component_ref"],
                source_fingerprint=fingerprint,
            ),
        }
        for key, value in sorted(sections["history"].items())
        if key.startswith("license-disposition:")
    ]
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "by_status": dict(Counter(item["status"] for item in items)),
        "next_offset": offset + limit if offset + limit < len(items) else None,
    }


def _prepare(journal, project_id, version, actor_id, data, operation):
    fingerprint = digest(
        canonical(
            ["license." + operation, project_id, version, actor_id, data.model_dump(mode="json")]
        )
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt, None, None, request_id, fingerprint
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Product version changed; reload before editing license disposition")
    previous = journal.state(data.expected)
    if previous.project_id != project_id or previous.version != version:
        raise ValueError("License disposition requires selected product version")
    sections = load_sections(journal, data.expected)
    if component_at(sections, data.component_ref) is None:
        raise Conflict("Component is absent from selected product version")
    return None, sections, previous, request_id, fingerprint


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
    revision,
):
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Record human license disposition",
        sections=sections,
        parents=[data.expected],
        artifacts=sorted(set(previous.artifacts) | {revision}),
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


def save_license(journal, *, project_id, version, actor_id, data, submit, authorize):
    authorize("license_assess")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, data, "submit" if submit else "draft"
    )
    if receipt:
        return receipt
    key, _ = keys(data.component_ref)
    current = sections["history"].get(key)
    if (current["revision"] if current else None) != data.expected_revision:
        raise Conflict("License disposition revision changed")
    payload = {
        "format": FORMAT,
        "project_id": project_id,
        "version": version,
        "actor_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        "source_fingerprint": inventory_fingerprint(sections, version),
        **data.model_dump(mode="json", exclude={"request_id", "expected", "expected_revision"}),
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
        revision,
    )


def review_license(journal, *, project_id, version, actor_id, data, authorize):
    authorize("license_approve")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, data, "review"
    )
    if receipt:
        return receipt
    key, review_key = keys(data.component_ref)
    current = sections["history"].get(key)
    if not current or current["revision"] != data.revision or current["stage"] != "submitted":
        raise Conflict("Review requires the exact current submitted revision")
    payload = current["payload"]
    if journal.load(data.revision) != payload:
        raise ValueError("License disposition differs from immutable revision")
    if payload["actor_id"] == actor_id:
        raise PermissionError("License review requires an independent actor")
    if payload["version"] != version or payload["source_fingerprint"] != inventory_fingerprint(
        sections, version
    ):
        raise Conflict("License source context changed; submit a fresh disposition")
    sections["history"][review_key] = {
        "format": "dtvp.license-review/1",
        "revision": data.revision,
        "payload": payload,
        "action": data.action,
        "reviewer_id": actor_id,
        "rationale": data.rationale,
        "created_at": datetime.now(UTC).isoformat(),
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
        data.revision,
    )
