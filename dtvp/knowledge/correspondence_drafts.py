"""Explicit adopted drafts from approved historical evidence and human correspondence."""

from pydantic import Field, field_validator

from dtvp.knowledge.assessments import (
    AssessmentInput,
    Target,
    checked_target,
    coverage_status,
    prepare,
    save_assessment,
)
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha
from dtvp.knowledge.ownership import policy_ref
from dtvp.knowledge.reconciliation import (
    FORMAT,
    Pair,
    correspondence_key,
    preview_reconciliation,
)
from dtvp.knowledge.synchronization import _ancestors, _scopes
from dtvp.knowledge.synchronization_apply import _recorded
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class CorrespondenceDraftPreview(RequestModel):
    source: Sha
    target: Sha
    source_context_id: Sha
    target_context_id: Sha
    vulnerability_id: Name
    source_assessment_revision: Sha
    assertions: dict[Name, Sha] = Field(min_length=1, max_length=100)
    expected_policy: Sha | None


class CorrespondenceDraftInput(CorrespondenceDraftPreview):
    request_id: Name
    preview_digest: Sha
    assessment_id: Name = Field(max_length=189)
    conditions: str = Field(min_length=1, max_length=6000)
    reason: str = Field(min_length=1, max_length=6000)

    @field_validator("conditions", "reason")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Adoption requires meaningful target conditions and reason")
        return value


def _states(journal, project_id, data):
    reachable = reachable_states(journal, project_id)
    if data.source not in reachable or data.target not in reachable:
        raise ValueError("Draft inputs must be committed states in the selected product line")
    return load_sections(journal, data.source), load_sections(journal, data.target), reachable


def _selection(journal, project_id, data, source, target, revisions):
    source_version = journal.state(data.source).version
    target_version = journal.state(data.target).version
    contexts = [
        sections["ownership"].get("context:" + context_id)
        for sections, context_id in (
            (source, data.source_context_id),
            (target, data.target_context_id),
        )
    ]
    if not all(contexts):
        raise Conflict("Both consuming contexts must exist in the selected states")
    required = {
        ("component", contexts[0]["component_ref"], contexts[1]["component_ref"]),
        ("context", data.source_context_id, data.target_context_id),
    }
    selected, active = [], []
    for key, record in sorted(target["history"].items()):
        if not key.startswith("reconciliation:"):
            continue
        payload = record["payload"]
        if (
            journal.load(record["revision"]) != payload
            or payload.get("format") != FORMAT
            or record.get("format") != FORMAT
        ):
            raise ValueError("Correspondence differs from its immutable revision")
        if (
            payload["stage"] != "active"
            or payload["project_id"] != project_id
            or payload["version"] != target_version
            or payload["preview"]["source_version"] != source_version
        ):
            continue
        active.extend(payload["preview"]["items"])
        identifier = payload["reconciliation_id"]
        if identifier not in data.assertions:
            continue
        if (
            key != correspondence_key(identifier)
            or record["revision"] != data.assertions[identifier]
        ):
            raise Conflict("Selected correspondence revision changed")
        captured_source, captured_target = payload["source"], payload["target"]
        if (
            captured_source not in revisions
            or captured_target not in revisions
            or revisions[captured_source].version != source_version
            or revisions[captured_target].version != target_version
            or captured_target not in _ancestors(data.target, revisions)
            or not (
                captured_source in _ancestors(data.source, revisions)
                or data.source in _ancestors(captured_source, revisions)
            )
        ):
            raise Conflict("Selected states are unrelated to the captured correspondence history")
        selected.append(record)
    if len(selected) != len(data.assertions):
        raise Conflict("Selected correspondence is missing, retracted or outside version scope")
    rows = [row for record in selected for row in record["payload"]["preview"]["items"]]
    identities = {(row["kind"], row["source_id"], row["target_id"]) for row in rows}
    if not required <= identities:
        raise Conflict("Explicit component and consuming-context correspondence are both required")
    for kind, old, new in required:
        if any(
            row["kind"] == kind
            and (
                (row["source_id"] == old and row["target_id"] != new)
                or (row["target_id"] == new and row["source_id"] != old)
            )
            for row in active
        ):
            raise Conflict("Active correspondence assertions contain conflicting mappings")
    # Recompute only the selected required pairs, not incidental rows in a larger assertion.
    pairs = [Pair(kind=kind, source_id=old, target_id=new) for kind, old, new in sorted(required)]
    current = preview_reconciliation(journal, project_id, data.source, data.target, pairs)
    if not current["eligible"]:
        raise Conflict("Correspondence has conflicting or missing current material")
    for row in current["items"]:
        previous = [
            item
            for item in rows
            if (item["kind"], item["source_id"], item["target_id"])
            == (row["kind"], row["source_id"], row["target_id"])
        ]
        if any(
            canonical([item["source_facts"], item["target_facts"]])
            != canonical([row["source_facts"], row["target_facts"]])
            for item in previous
        ):
            raise Conflict("Captured correspondence material changed; confirm a fresh assertion")
    return selected


def preview_correspondence_draft(journal, *, project_id, data):
    source, target, revisions = _states(journal, project_id, data)
    version = journal.state(data.target).version
    if journal.resolve(Ref(project_id=project_id, name=version)) != data.target:
        raise Conflict("Target product version changed")
    if journal.resolve(policy_ref(project_id)) != data.expected_policy:
        raise Conflict("Ownership policy changed")
    records = _selection(journal, project_id, data, source, target, revisions)
    source_target = Target(
        version=journal.state(data.source).version,
        context_id=data.source_context_id,
        vulnerability_id=data.vulnerability_id,
    )
    coverage = coverage_status(journal, source, **source_target.model_dump())
    record = coverage.get("approved_assessment")
    if (
        not coverage.get("approved")
        or not record
        or record["revision"] != data.source_assessment_revision
    ):
        raise Conflict(
            "Selected source revision lacks current independent approval in the pinned state"
        )
    target_scope = Target(
        version=version, context_id=data.target_context_id, vulnerability_id=data.vulnerability_id
    )
    checked = checked_target(target, target_scope)
    if _recorded(target, target_scope):
        raise Conflict("Target already has recorded assessment content; preserve its decision")
    result = {
        "format": "dtvp.correspondence-draft-preview/1",
        "project_id": project_id,
        **data.model_dump(mode="json"),
        "target_version": version,
        "source_version": source_target.version,
        "source_assessment": record,
        "source_author_id": record["payload"]["author_id"],
        "target": data.target,
        "target_scope": checked,
        "assertions": {
            record["payload"]["reconciliation_id"]: record["revision"] for record in records
        },
        "category": "needs_review",
        "requires_new_target_review": True,
        "software_integration_verified": False,
        "limitations": [
            "Human correspondence is not identity, artifact equivalence or applicability proof.",
            "A new target-author draft is proposed; source approval and scores are never copied.",
            "Historical source evidence is pinned, not asserted to be the latest source state.",
            "Complete source evidence is retained by immutable assessment revision reference, not copied or truncated.",
        ],
    }
    result["preview_digest"] = digest(canonical(result))
    return result


def apply_correspondence_draft(journal, *, project_id, actor_id, data, authorize):
    # Current authorization precedes replay. Original pinned scope remains available
    # after a successful publication; replay never silently rebinds to a new head.
    source, target, revisions = _states(journal, project_id, data)
    scope = Target(
        version=journal.state(data.target).version,
        context_id=data.target_context_id,
        vulnerability_id=data.vulnerability_id,
    )
    checked = checked_target(target, scope)
    authorize(checked["team_id"], "assess")
    source_coverage = coverage_status(
        journal,
        source,
        version=journal.state(data.source).version,
        context_id=data.source_context_id,
        vulnerability_id=data.vulnerability_id,
    )
    source_record = source_coverage.get("approved_assessment")
    if not source_record or source_record["revision"] != data.source_assessment_revision:
        raise Conflict("Source approval revision differs from the pinned state")
    payload = source_record["payload"]
    if data.assessment_id == payload["assessment_id"]:
        raise Conflict("Adoption requires a new logical assessment identifier")
    assessment = AssessmentInput(
        request_id=data.request_id,
        expected_versions={scope.version: data.target},
        expected_revision=None,
        targets=[scope],
        state=payload["state"],
        justification=payload.get("justification"),
        rationale=payload["rationale"],
        conditions=data.conditions,
        evidence=[
            {
                "format": "dtvp.correspondence-draft/1",
                **data.model_dump(mode="json", exclude={"request_id", "conditions", "reason"}),
                "source_author_id": payload["author_id"],
                "source_evidence": {
                    "location": "source_assessment_revision.payload.evidence",
                    "count": len(payload.get("evidence", [])),
                    "sha256": digest(canonical(payload.get("evidence", []))),
                },
                "target_author_id": actor_id,
                "reason": data.reason,
                "requires_new_target_review": True,
                "software_integration_verified": False,
            },
        ],
    )
    checks = ((policy_ref(project_id), data.expected_policy),)
    operation = {
        **assessment.model_dump(
            mode="json", exclude={"ssvc"} if assessment.ssvc is None else set()
        ),
        "assessment_id": data.assessment_id,
        "submit": False,
        "publication_checks": [
            {"ref": ref.model_dump(mode="json"), "expected": expected} for ref, expected in checks
        ],
    }
    _, _, receipt = prepare(journal, project_id, actor_id, "assessment.save/1", operation)
    if receipt:
        return receipt
    preview_data = CorrespondenceDraftPreview.model_validate(
        data.model_dump(include=set(CorrespondenceDraftPreview.model_fields))
    )
    preview = preview_correspondence_draft(journal, project_id=project_id, data=preview_data)
    if preview["preview_digest"] != data.preview_digest:
        raise Conflict("Correspondence draft preview changed")
    return save_assessment(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        assessment_id=data.assessment_id,
        data=assessment,
        submit=False,
        authorize=authorize,
        publication_checks=checks,
    )


def correspondence_draft_candidates(journal, *, project_id, state, q="", offset=0, limit=50):
    """Bounded approved-source summaries; selected preview provides exact content."""
    from dtvp.knowledge.comparison import page
    from dtvp.knowledge.target_fingerprints import TargetFingerprintBuilder

    page([], offset, limit)
    revisions = reachable_states(journal, project_id)
    if state not in revisions:
        raise ValueError("Draft candidates require committed product history")
    version = revisions[state].version
    sections = load_sections(journal, state)
    resolver = TargetFingerprintBuilder(sections, version).fingerprint
    scopes, _ = _scopes(sections, version)
    components = {
        item["bom-ref"]: item
        for key, item in sections["inventory"].items()
        if key.startswith(("component:", "part-root:")) and item.get("bom-ref")
    }
    root = sections["inventory"].get("root", {})
    if root.get("bom-ref"):
        components.setdefault(root["bom-ref"], root)
    rows = []
    query = q.casefold()
    for context_id, identifier in scopes:
        coverage = coverage_status(
            journal, sections, version, context_id, identifier, fingerprint_resolver=resolver
        )
        record = coverage.get("approved_assessment")
        if not coverage.get("approved") or not record:
            continue
        context = sections["ownership"].get("context:" + context_id, {})
        ref = context.get("component_ref", "")
        component = components.get(ref, {})
        if query and not any(
            query in str(value).casefold()
            for value in (identifier, ref, component.get("name"), component.get("version"))
        ):
            continue
        payload = record["payload"]
        rows.append(
            {
                "context_id": context_id,
                "vulnerability_id": identifier,
                "component_ref": ref if len(ref) <= 4096 else None,
                "component": {
                    key: str(component.get(key) or "")[:500] for key in ("name", "version")
                },
                "team_id": context.get("team_id"),
                "approved_assessment": {
                    "revision": record["revision"],
                    "payload": {
                        "author_id": payload["author_id"],
                        "state": payload["state"],
                        "justification": payload.get("justification"),
                        "rationale": payload["rationale"][:1000],
                    },
                },
                "summary_only": True,
                "rationale_truncated": len(payload["rationale"]) > 1000,
            }
        )
    result = {
        "format": "dtvp.correspondence-draft-candidates/1",
        "project_id": project_id,
        "state": state,
        "version": version,
        "current_policy": journal.resolve(policy_ref(project_id)),
        "limitations": [
            "Approved source summaries are pinned historical evidence, not target coverage or automatic reuse.",
            "Only selected preview includes exact rationale and evidence; candidate summaries are bounded.",
        ],
    }
    result["candidates_digest"] = digest(canonical([result, rows]))
    return {**result, **page(rows, offset, limit)}
