"""Explicit, independently authorized review targets; one atomic publication."""

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from dtvp.knowledge.assessments import (
    ReviewInput,
    Target,
    prepare,
    publish,
    review_for_target,
    selected_sections,
    target_key,
)
from dtvp.knowledge.comparison import page
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class Item(RequestModel):
    target: Target
    assessment_id: Name
    assessment_revision: Sha


def item_id(item):
    return digest(canonical(item.model_dump(mode="json")))


class BulkInput(RequestModel):
    request_id: Name
    expected_versions: dict[Name, Sha] = Field(min_length=1, max_length=100)
    items: list[Item] = Field(min_length=1, max_length=100)
    action: Literal["approve", "request_changes"]
    rationale: str = Field(min_length=1, max_length=6000)

    @model_validator(mode="after")
    def exact_scope(self):
        targets = {canonical(item.target.model_dump()) for item in self.items}
        if len(targets) != len(self.items):
            raise ValueError("Bulk review requires distinct exact targets")
        if {item.target.version for item in self.items} != self.expected_versions.keys():
            raise ValueError("Expected versions must match all explicit candidate targets exactly")
        return self

    @field_validator("rationale")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Bulk review rationale must contain meaningful human input")
        return value


class BulkApply(BulkInput):
    preview_digest: Sha
    selected: list[Sha] = Field(min_length=1, max_length=100)

    @field_validator("selected")
    @classmethod
    def distinct_selection(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Select each bulk review item once")
        return values


def _review_input(data, item):
    return ReviewInput(
        request_id=data.request_id,
        expected_versions={item.target.version: data.expected_versions[item.target.version]},
        assessment_id=item.assessment_id,
        assessment_revision=item.assessment_revision,
        targets=[item.target],
        action=data.action,
        rationale=data.rationale,
    )


def _reason(section, item, error):
    record = section["assessments"].get("assessment:" + item.assessment_id)
    if not record:
        return "missing_assessment"
    if record["revision"] != item.assessment_revision:
        return "assessment_revision_changed"
    if record["stage"] != "submitted":
        return "draft"
    messages = {
        "An assessment requires an independent reviewer": "self_authored",
        "Assessment requires resolved ownership and dependency topology": "unresolved_ownership_or_topology",
        "The selected vulnerability is absent from this consuming context": "missing_target",
        "Assessment evidence changed; submit a fresh revision": "stale_evidence",
    }
    return messages.get(
        str(error), "missing_authority" if isinstance(error, PermissionError) else "not_reviewable"
    )


def _plan(journal, project_id, actor_id, data, authorize):
    sections = selected_sections(journal, project_id, data.expected_versions)
    rows, records = [], {}
    for item in sorted(data.items, key=item_id):
        identity = item_id(item)
        section = sections[item.target.version]
        row = {"item_id": identity, **item.model_dump(mode="json"), "ready": False}
        try:
            review = review_for_target(
                journal,
                section,
                actor_id=actor_id,
                data=_review_input(data, item),
                target=item.target,
                authorize=authorize,
                created_at="preview",
            )
        except (Conflict, PermissionError) as error:
            row.update(reason=_reason(section, item, error), detail=str(error))
        else:
            prior = section["reviews"].get("review:" + target_key(item.target))
            if (
                prior
                and prior.get("assessment_id") == item.assessment_id
                and prior.get("assessment_revision") == item.assessment_revision
                and prior.get("target") == review["target"]
                and prior.get("status") in {"approved", "changes_requested"}
            ):
                row.update(
                    reason="already_reviewed_current",
                    detail="This exact current submitted revision already has an independent review",
                )
            else:
                row.update(
                    ready=True,
                    reason="ready",
                    team_id=review["reviewer_team_id"],
                    fingerprint=review["target"]["fingerprint"],
                )
                records[identity] = review
        rows.append(row)
    content = {
        "format": "dtvp.bulk-review-preview/1",
        "project_id": project_id,
        "reviewer_id": actor_id,
        "input": data.model_dump(mode="json"),
        "items": rows,
    }
    result = {
        "preview_digest": digest(canonical(content)),
        "items": rows,
        "statistics": {
            "total": len(rows),
            "ready": len(records),
            "excluded": len(rows) - len(records),
            "by_reason": dict(sorted(Counter(row["reason"] for row in rows).items())),
        },
        "expected_versions": data.expected_versions,
        "limitations": [
            "Only explicitly selected eligible targets are reviewed; shared assessment scope never adds implicit approvals.",
            "Approvals do not publish contextual scores or alter imported source information.",
        ],
    }
    return result, sections, records


def preview_bulk_review(journal, project_id, actor_id, data, authorize, offset=0, limit=50):
    result, _, _ = _plan(journal, project_id, actor_id, data, authorize)
    return {**result, **page(result["items"], offset, limit)}


def apply_bulk_review(journal, project_id, actor_id, data, authorize):
    request_id, fingerprint, receipt = prepare(
        journal, project_id, actor_id, "assessment.bulk-review/1", data.model_dump(mode="json")
    )
    if receipt:
        return receipt
    intake = BulkInput.model_validate(data.model_dump(exclude={"preview_digest", "selected"}))
    result, sections, _ = _plan(journal, project_id, actor_id, intake, authorize)
    if result["preview_digest"] != data.preview_digest:
        raise Conflict("Bulk review preview changed; review the exact current selection again")
    rows = {row["item_id"]: row for row in result["items"]}
    if any(identity not in rows or not rows[identity]["ready"] for identity in data.selected):
        raise Conflict("Bulk review selection contains excluded or unknown targets")
    chosen = {item_id(item): item for item in data.items}
    updated, artifacts = {}, set()
    created_at = datetime.now(UTC).isoformat()
    for identity in data.selected:
        item = chosen[identity]
        section = sections[item.target.version]
        # Reauthorize each actual target; no preview permission is a grant.
        record = review_for_target(
            journal,
            section,
            actor_id=actor_id,
            data=_review_input(intake, item),
            target=item.target,
            authorize=authorize,
            created_at=created_at,
        )
        section["reviews"]["review:" + target_key(item.target)] = record
        updated[item.target.version] = section
        artifacts.add(item.assessment_revision)
    expected = {version: data.expected_versions[version] for version in updated}
    return publish(
        journal,
        project_id,
        actor_id,
        expected,
        updated,
        request_id,
        fingerprint,
        "Review explicitly selected contextual assessments",
        artifacts=sorted(artifacts),
        publication_checks=[
            (Ref(project_id=project_id, name=version), state)
            for version, state in sorted(data.expected_versions.items())
        ],
    )
