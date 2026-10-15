"""Version-scoped curated component annotations, separate from imported facts."""

from collections import Counter
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

Text = Annotated[str, Field(min_length=1, max_length=6000)]
FORMAT = "dtvp.component-metadata/1"
LIMITATIONS = [
    "Annotations apply only to the explicitly saved product version and source-local component occurrence.",
    "Annotations are authored metadata, not applicability assessments, license clearance, architecture approval or published scores.",
    "Identity equality does not verify build completeness, deployment conditions or source authenticity.",
]


class CybersecurityAnnotations(RequestModel):
    criticality: Literal["unknown", "low", "moderate", "high", "critical"] = "unknown"
    exposure: Literal["unknown", "not_exposed", "internal", "external"] = "unknown"
    mitigations: list[Text] = Field(default_factory=list, max_length=100)
    testing_evidence: list[Text] = Field(default_factory=list, max_length=100)


class DeploymentAnnotations(RequestModel):
    environment: str = Field(default="", max_length=6000)
    usage: str = Field(default="", max_length=6000)
    configuration: str = Field(default="", max_length=6000)


class SupportAnnotations(RequestModel):
    status: Literal["unknown", "supported", "unsupported", "internally_maintained"] = "unknown"
    supplier: str = Field(default="", max_length=1000)
    support_until: date | None = None
    end_of_life: date | None = None
    references: list[Text] = Field(default_factory=list, max_length=100)


class Annotations(RequestModel):
    cybersecurity: CybersecurityAnnotations = Field(default_factory=CybersecurityAnnotations)
    deployment: DeploymentAnnotations = Field(default_factory=DeploymentAnnotations)
    support: SupportAnnotations = Field(default_factory=SupportAnnotations)
    notes: str = Field(default="", max_length=12000)
    properties: dict[Name, Text] = Field(default_factory=dict, max_length=100)


class Provenance(RequestModel):
    source: Name
    reference: str = Field(default="", max_length=3000)
    observed_at: datetime | None = None

    @field_validator("observed_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Provenance observation time must include a timezone")
        return value


class MetadataInput(RequestModel):
    request_id: Name
    expected: Sha
    expected_revision: Sha | None
    component_ref: str = Field(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")
    annotations: Annotations
    provenance: Provenance
    rationale: str = Field(min_length=1, max_length=6000)


def metadata_key(component_ref):
    return "metadata:" + digest(canonical(component_ref))


def component_at(sections, component_ref):
    inventory = sections["inventory"]
    root = inventory.get("root", {})
    if root.get("bom-ref") == component_ref:
        return root
    return next(
        (
            value
            for key, value in inventory.items()
            if key.startswith(("component:", "part-root:"))
            and value.get("bom-ref") == component_ref
        ),
        None,
    )


def identity_fingerprint(component):
    """Exact occurrence identity facts; unrelated source annotations stay separate."""
    if component is None:
        return None
    identity = {
        key: component[key]
        for key in ("type", "name", "group", "version", "purl", "cpe")
        if key in component
    }
    identity["hashes"] = sorted(component.get("hashes", []), key=canonical)
    return digest(canonical(identity))


def get_metadata(journal, sections, version, component_ref):
    record = sections["history"].get(metadata_key(component_ref))
    if not record:
        return None
    if record.get("format") != FORMAT:
        raise ValueError("Unsupported component metadata record")
    payload = record["payload"]
    if payload["component_ref"] != component_ref:
        raise ValueError("Component metadata scope disagrees with its record key")
    # The payload is retained inside the complete state as well as by its hash.
    # Verify the pinned object rather than deriving history from mutable records.
    if journal.load(record["revision"]) != payload:
        raise ValueError("Component metadata payload differs from its revision")
    fingerprint = identity_fingerprint(component_at(sections, component_ref))
    status = (
        "absent"
        if fingerprint is None
        else "out_of_scope"
        if payload["version"] != version
        else "current"
        if fingerprint == payload["identity_fingerprint"]
        else "stale"
    )
    return {
        **record,
        "status": status,
        "applicable": status == "current",
        "current_identity_fingerprint": fingerprint,
        "scope": "component_occurrence",
        "limitations": list(LIMITATIONS),
    }


def list_metadata(journal, sections, version, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid component metadata page bounds")
    records = [
        get_metadata(journal, sections, version, value["payload"]["component_ref"])
        for key, value in sorted(sections["history"].items())
        if key.startswith("metadata:")
    ]
    return {
        "items": records[offset : offset + limit],
        "total": len(records),
        "by_status": dict(Counter(item["status"] for item in records)),
        "next_offset": offset + limit if offset + limit < len(records) else None,
    }


def save_metadata(journal, *, project_id, version, actor_id, data):
    """Authorized callers explicitly replace annotations; imported facts are untouched."""
    fingerprint = digest(
        canonical(
            [
                "component-metadata.save/1",
                project_id,
                version,
                actor_id,
                data.model_dump(mode="json"),
            ]
        )
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Product version changed; reload before editing metadata")
    previous = journal.state(data.expected)
    if previous.project_id != project_id or previous.version != version:
        raise ValueError("Metadata must belong to the selected product version")
    sections = {
        name: {key: journal.load(sha) for key, sha in journal.records(data.expected, name).items()}
        for name in SECTIONS
    }
    component = component_at(sections, data.component_ref)
    if component is None:
        raise Conflict("Component is absent from the selected product version")
    key = metadata_key(data.component_ref)
    current = sections["history"].get(key)
    if (current.get("revision") if current else None) != data.expected_revision:
        raise Conflict("Component metadata revision changed; reload before editing")
    payload = {
        "format": FORMAT,
        "project_id": project_id,
        "version": version,
        "component_ref": data.component_ref,
        "identity_fingerprint": identity_fingerprint(component),
        "actor_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        **data.model_dump(mode="json", include={"annotations", "provenance", "rationale"}),
    }
    revision = journal.store(payload)
    sections["history"][key] = {"format": FORMAT, "revision": revision, "payload": payload}
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Curate component metadata",
        sections=sections,
        parents=[data.expected],
        artifacts=sorted(set(previous.artifacts) | {revision}),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
    )
