"""Explicit, source-author-only draft extension of a pinned assessment."""

from pydantic import Field

from dtvp.knowledge.assessments import (
    AssessmentInput,
    Target,
    coverage_status,
    load_sections,
    prepare,
    save_assessment,
)
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class SynchronizationApplyInput(RequestModel):
    request_id: Name
    source: Sha
    target: Sha
    basis: Sha | None = None
    preview_digest: Sha
    source_context_id: Sha
    target_context_id: Sha
    vulnerability_id: Name
    source_assessment_revision: Sha
    context_mapping: dict[Sha, Sha] = Field(default_factory=dict, max_length=1000)
    conditions: str = Field(min_length=1, max_length=6000)
    reason: str = Field(min_length=1, max_length=6000)


def _recorded(sections, target):
    """Retain even stale target decisions, including those under another ID."""
    identity = target.model_dump()
    for record in sections["assessments"].values():
        for item in record.get("payload", {}).get("targets", []):
            if all(item.get(key) == value for key, value in identity.items()):
                return True
    return any(
        all(review.get("target", {}).get(key) == value for key, value in identity.items())
        for review in sections["reviews"].values()
    )


def apply_synchronization(journal, *, project_id, actor_id, data, authorize):
    """Copy content into one new draft; never copy source approval or inventory."""
    source_revision, target_revision = (
        journal.verify_state(data.source),
        journal.verify_state(data.target),
    )
    if any(item.project_id != project_id for item in (source_revision, target_revision)):
        raise ValueError("Synchronization states must belong to the selected product line")
    if source_revision.version == target_revision.version:
        raise ValueError("Synchronization requires two distinct product versions")
    sections = load_sections(journal, data.source)
    coverage = coverage_status(
        journal, sections, source_revision.version, data.source_context_id, data.vulnerability_id
    )
    record = coverage.get("assessment") or coverage.get("approved_assessment")
    if not record or record["revision"] != data.source_assessment_revision:
        raise Conflict("Selected source assessment revision differs from the pinned source state")
    payload = record["payload"]
    assessment_id = payload["assessment_id"]
    evidence = [
        *payload.get("evidence", []),
        {
            "format": "dtvp.synchronization-draft/1",
            **data.model_dump(mode="json", exclude={"request_id", "conditions", "reason"}),
            "reason": data.reason,
            "source_conditions": payload.get("conditions", ""),
            "software_integration_verified": False,
            "requires_new_target_review": True,
        },
    ]
    target = Target(
        version=target_revision.version,
        context_id=data.target_context_id,
        vulnerability_id=data.vulnerability_id,
    )
    assessment = AssessmentInput(
        request_id=data.request_id,
        expected_versions={target_revision.version: data.target},
        expected_revision=data.source_assessment_revision,
        targets=[target],
        state=payload["state"],
        justification=payload.get("justification"),
        rationale=payload["rationale"],
        conditions=data.conditions,
        evidence=evidence,
    )
    source_ref = Ref(project_id=project_id, name=source_revision.version)
    checks = ((source_ref, data.source),)
    # Use the native save identity, including guarded references, so a durable
    # publication can replay even after either branch has subsequently advanced.
    operation = {
        **assessment.model_dump(mode="json"),
        "assessment_id": assessment_id,
        "submit": False,
        "publication_checks": [
            {"ref": source_ref.model_dump(mode="json"), "expected": data.source}
        ],
    }
    _, _, receipt = prepare(journal, project_id, actor_id, "assessment.save/1", operation)
    if receipt:
        return receipt
    if journal.resolve(source_ref) != data.source:
        raise Conflict("Source must still be the current product-version branch head")
    if journal.resolve(Ref(project_id=project_id, name=target.version)) != data.target:
        raise Conflict("Target product version changed; reload the synchronization preview")
    row_id = digest(
        canonical([data.source_context_id, data.vulnerability_id, data.target_context_id])
    )
    preview = synchronization_preview(
        journal,
        project_id,
        data.source,
        data.target,
        basis=data.basis,
        context_mapping=data.context_mapping,
        row_id=row_id,
    )
    if preview["preview_digest"] != data.preview_digest:
        raise Conflict("Synchronization preview digest differs; reload before applying")
    row = preview["selected_row"]
    if not row or row["category"] not in {
        "reusable_content",
        "needs_review",
    }:
        raise Conflict("Selected synchronization content is not eligible for a target draft")
    if _recorded(load_sections(journal, data.target), target):
        raise Conflict("Target already has recorded assessment content; preserve its decision")
    return save_assessment(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        assessment_id=assessment_id,
        data=assessment,
        submit=False,
        authorize=authorize,
        publication_checks=checks,
    )
