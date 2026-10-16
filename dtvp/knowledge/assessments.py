"""Explicit contextual decisions and independent, revision-pinned reviews."""

from datetime import UTC, datetime
from typing import Literal

from packageurl import PackageURL
from pydantic import Field, model_validator

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.schemas import DecisionInput, RequestModel
from dtvp.storage import canonical, digest


class Target(RequestModel):
    version: Name
    context_id: Sha
    vulnerability_id: Name


class AssessmentInput(RequestModel):
    request_id: Name
    expected_versions: dict[Name, Sha]
    expected_revision: Sha | None
    targets: list[Target] = Field(min_length=1, max_length=1000)
    state: Literal["affected", "not_affected", "fixed", "under_investigation"]
    justification: DecisionInput.model_fields["justification"].annotation = None
    rationale: str = Field(min_length=1, max_length=6000)
    conditions: str = Field(default="", max_length=6000)
    evidence: list[dict] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def distinct_targets(self):
        validate_targets(self)
        return self


class ReviewInput(RequestModel):
    request_id: Name
    expected_versions: dict[Name, Sha]
    assessment_id: Name
    assessment_revision: Sha
    targets: list[Target] = Field(min_length=1, max_length=1000)
    action: Literal["approve", "request_changes"]
    rationale: str = Field(min_length=1, max_length=6000)

    @model_validator(mode="after")
    def distinct_targets(self):
        validate_targets(self)
        return self


def target_key(target):
    return digest(canonical([target.context_id, target.vulnerability_id]))


def validate_targets(data):
    identities = [(t.version, t.context_id, t.vulnerability_id) for t in data.targets]
    if len(identities) != len(set(identities)):
        raise ValueError("Assessment targets must be distinct")
    if len({t.vulnerability_id for t in data.targets}) != 1:
        raise ValueError("A shared assessment must cover one vulnerability identifier")
    if set(data.expected_versions) != {t.version for t in data.targets}:
        raise ValueError("Expected versions must exactly match the selected target versions")


def load_sections(journal, state):
    return {
        name: {key: journal.load(sha) for key, sha in journal.records(state, name).items()}
        for name in SECTIONS
    }


def semantic(value):
    """Drop only origin state pointers, never human or source claim fields."""
    if isinstance(value, list):
        return [semantic(item) for item in value]
    if isinstance(value, dict):
        return {
            key: semantic({k: v for k, v in item.items() if k != "state"})
            if key == "dtvp_origin" and isinstance(item, dict)
            else semantic(item)
            for key, item in value.items()
        }
    return value


def collection_scope(baseline):
    return {
        key: value
        for key, value in baseline.items()
        if key
        in {
            "normalizer",
            "parser",
            "format",
            "losses",
            "snapshot_completeness",
            "dependency_graph",
            "coverage_verification",
        }
    } | {
        "collection": {
            key: value
            for key, value in baseline.get("collection", {}).items()
            if key != "pipeline_run"
        }
    }


def target_fingerprint(sections, version, context_id, vulnerability_id):
    """Conservative assessment-target/1 equality; no cross-request caching."""
    from dtvp.knowledge.target_fingerprints import TargetFingerprintBuilder

    return TargetFingerprintBuilder(sections, version).fingerprint(context_id, vulnerability_id)


def component_lineage(sections, context):
    component = next(
        (
            item
            for key, item in sections["inventory"].items()
            if key.startswith("component:") and item.get("bom-ref") == context["component_ref"]
        ),
        sections["inventory"].get("root", {}),
    )
    if component.get("purl"):
        package = PackageURL.from_string(component["purl"])
        coordinate = PackageURL(
            type=package.type,
            namespace=package.namespace,
            name=package.name,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
        ).to_string()
        return {"basis": "purl_coordinates", "coordinate": coordinate}
    return {
        "basis": "source_local_refs",
        "root_ref": context["root_ref"],
        "component_ref": context["component_ref"],
    }


def checked_target(sections, target):
    context = sections["ownership"].get("context:" + target.context_id)
    if not context or context.get("status") != "resolved" or not context.get("team_id"):
        raise Conflict("Assessment requires resolved ownership and dependency topology")
    fingerprint = target_fingerprint(sections, **target.model_dump())
    if fingerprint is None:
        raise Conflict("The selected vulnerability is absent from this consuming context")
    return {
        **target.model_dump(),
        "fingerprint": fingerprint,
        "team_id": context["team_id"],
        "lineage": component_lineage(sections, context),
    }


def prepare(journal, project_id, actor_id, operation, data):
    fingerprint = digest(canonical([operation, project_id, actor_id, data]))
    request_id = digest(canonical([project_id, actor_id, data["request_id"]]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    return request_id, fingerprint, receipt


def selected_sections(journal, project_id, expected):
    result = {}
    for version, state in expected.items():
        if journal.resolve(Ref(project_id=project_id, name=version)) != state:
            raise Conflict("Product version changed; reload before assessing")
        revision = journal.state(state)
        if revision.project_id != project_id or revision.version != version:
            raise Conflict("Expected state does not belong to this product version")
        result[version] = load_sections(journal, state)
    return result


def publish(
    journal,
    project_id,
    actor_id,
    expected,
    sections,
    request_id,
    fingerprint,
    reason,
    *,
    branch_heads=None,
    artifacts=(),
    publication_checks=(),
):
    updates = []
    for version, parent in sorted(expected.items()):
        state = journal.snapshot(
            project_id=project_id,
            version=version,
            actor_id=actor_id,
            reason=reason,
            sections=sections[version],
            parents=[parent],
            artifacts=sorted(set(journal.state(parent).artifacts) | set(artifacts)),
        )
        updates.append(
            Update(ref=Ref(project_id=project_id, name=version), expected=parent, target=state)
        )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=updates,
        checks=publication_checks,
        branch_heads={project_id: branch_heads} if branch_heads is not None else None,
    )


def save_assessment(
    journal,
    *,
    project_id,
    actor_id,
    assessment_id,
    data,
    submit,
    authorize,
    publication_checks=(),
):
    """Save a draft or explicitly submit; never create a human approval."""
    publication_checks = tuple(publication_checks)
    operation = {**data.model_dump(mode="json"), "assessment_id": assessment_id, "submit": submit}
    if publication_checks:
        operation["publication_checks"] = [
            {"ref": ref.model_dump(mode="json"), "expected": expected}
            for ref, expected in publication_checks
        ]
    request_id, fingerprint, receipt = prepare(
        journal,
        project_id,
        actor_id,
        "assessment.save/1",
        operation,
    )
    if receipt:
        return receipt
    from dtvp.knowledge.assessment_archive import archive_ref, is_retired

    refs = journal.references()
    retirement_ref = archive_ref(project_id)
    retirement_state = refs.get(retirement_ref.key)
    if is_retired(journal, retirement_state, assessment_id):
        raise Conflict(
            "Assessment identifier is retired; use a new identifier or an explicit future restore"
        )
    publication_checks = (*publication_checks, (retirement_ref, retirement_state))
    project_heads = {
        ref.name: state
        for ref_key, state in refs.items()
        if (ref := Ref.model_validate_json(ref_key)).project_id == project_id
        and ref.kind == "branch"
    }
    sections = selected_sections(journal, project_id, data.expected_versions)
    key = "assessment:" + assessment_id
    if len(key) > 200:
        raise ValueError("Assessment identifier must be at most 189 characters")
    existing = [s["assessments"].get(key) for s in sections.values()]
    # The same logical assessment can be extended into a previously uncovered
    # branch; existing pointers in selected branches must match the supplied CAS.
    for record in existing:
        if record and record["revision"] != data.expected_revision:
            raise Conflict("Assessment revision changed; reload before editing")
    known = []
    for ref_key, state in refs.items():
        ref = Ref.model_validate_json(ref_key)
        if ref.project_id == project_id and ref.kind == "branch":
            record_sha = journal.records(state, "assessments").get(key)
            if record_sha:
                known.append(journal.load(record_sha))
    if not data.expected_revision and known:
        raise Conflict("Assessment already exists; supply its revision to extend coverage")
    prior = None
    if data.expected_revision:
        if not any(record["revision"] == data.expected_revision for record in known):
            raise Conflict("Expected assessment revision is not a current published assessment")
        prior = journal.load(data.expected_revision)
        if (
            prior.get("format") != "dtvp.assessment/1"
            or prior.get("assessment_id") != assessment_id
            or prior.get("project_id") != project_id
        ):
            raise Conflict("Expected assessment revision belongs to another assessment")
        if prior["author_id"] != actor_id:
            raise PermissionError("Only the assessment author may revise this assessment")
    elif any(existing):
        raise Conflict("Assessment already exists")
    if submit and data.state == "not_affected" and not data.justification:
        raise ValueError("Not-affected submission requires a specific justification")
    targets = []
    for target in data.targets:
        checked = checked_target(sections[target.version], target)
        authorize(checked["team_id"], "assess")
        targets.append(checked)
    all_targets = targets + (prior.get("targets", []) if prior else [])
    if len({item["vulnerability_id"] for item in all_targets}) != 1:
        raise ValueError("A shared assessment must retain its vulnerability identifier")
    lineages = {canonical(item["lineage"]) for item in all_targets}
    if len(lineages) != 1:
        raise ValueError("Selected targets do not establish a compatible component lineage")
    if (
        targets[0]["lineage"]["basis"] == "source_local_refs"
        and len(all_targets) > 1
        and not data.conditions
    ):
        raise ValueError("Weak source-local lineage requires explicit supporting conditions")
    payload = {
        "format": "dtvp.assessment/1",
        "project_id": project_id,
        "assessment_id": assessment_id,
        "author_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        "targets": targets,
        **data.model_dump(
            mode="json", include={"state", "justification", "rationale", "conditions", "evidence"}
        ),
    }
    revision = journal.store(payload)
    for section in sections.values():
        section["assessments"][key] = {
            "revision": revision,
            "stage": "submitted" if submit else "draft",
            "payload": payload,
        }
    return publish(
        journal,
        project_id,
        actor_id,
        data.expected_versions,
        sections,
        request_id,
        fingerprint,
        "Submit contextual assessment" if submit else "Save contextual assessment draft",
        branch_heads=project_heads,
        artifacts=[revision],
        publication_checks=publication_checks,
    )


def review_for_target(journal, section, *, actor_id, data, target, authorize, created_at=None):
    """Build one exact review without mutating sections or publishing anything."""
    record = section["assessments"].get("assessment:" + data.assessment_id)
    if (
        not record
        or record["revision"] != data.assessment_revision
        or record["stage"] != "submitted"
    ):
        raise Conflict("Review requires the exact current submitted assessment revision")
    payload = journal.load(data.assessment_revision)
    if payload["author_id"] == actor_id:
        raise PermissionError("An assessment requires an independent reviewer")
    checked = checked_target(section, target)
    authored = next(
        (
            item
            for item in payload["targets"]
            if all(item[key] == value for key, value in target.model_dump().items())
        ),
        None,
    )
    if not authored or authored["fingerprint"] != checked["fingerprint"]:
        raise Conflict("Assessment evidence changed; submit a fresh revision")
    authorize(checked["team_id"], "approve")
    return {
        "format": "dtvp.review/1",
        "assessment_id": data.assessment_id,
        "assessment_revision": data.assessment_revision,
        "assessment": payload,
        "target": authored,
        "status": "approved" if data.action == "approve" else "changes_requested",
        "reviewer_id": actor_id,
        "reviewer_team_id": checked["team_id"],
        "rationale": data.rationale,
        "created_at": created_at or datetime.now(UTC).isoformat(),
    }


def create_review(journal, *, project_id, actor_id, data, authorize):
    request_id, fingerprint, receipt = prepare(
        journal, project_id, actor_id, "assessment.review/1", data.model_dump(mode="json")
    )
    if receipt:
        return receipt
    sections = selected_sections(journal, project_id, data.expected_versions)
    for target in data.targets:
        section = sections[target.version]
        section["reviews"]["review:" + target_key(target)] = review_for_target(
            journal, section, actor_id=actor_id, data=data, target=target, authorize=authorize
        )
    return publish(
        journal,
        project_id,
        actor_id,
        data.expected_versions,
        sections,
        request_id,
        fingerprint,
        "Review contextual assessment",
        artifacts=[data.assessment_revision],
    )


def coverage_status(
    journal,
    sections,
    version,
    context_id,
    vulnerability_id,
    *,
    fingerprint_resolver=None,
    continuity_resolver=None,
):
    target = Target(version=version, context_id=context_id, vulnerability_id=vulnerability_id)
    fingerprint = (
        fingerprint_resolver(context_id, vulnerability_id)
        if fingerprint_resolver
        else target_fingerprint(sections, version, context_id, vulnerability_id)
    )
    context = sections["ownership"].get("context:" + context_id)
    result = {
        "status": "unassessed",
        "recorded": False,
        "submitted": False,
        "approved": False,
        "fingerprint": fingerprint,
        "context": context,
        "team_id": context.get("team_id") if context else None,
    }
    review = sections["reviews"].get("review:" + target_key(target))
    if review and any(
        review.get("target", {}).get(key) != value for key, value in target.model_dump().items()
    ):
        # Branch ancestry retains history; it does not extend reviewed coverage.
        review = None
    candidates = []
    for record in sections["assessments"].values():
        payload = record.get("payload", {})
        for covered in payload.get("targets", []):
            if all(covered.get(key) == value for key, value in target.model_dump().items()):
                candidates.append((record, covered))
    latest = (
        max(candidates, key=lambda item: item[0]["payload"]["created_at"])[0]
        if candidates
        else None
    )
    result["assessment"] = latest
    if not fingerprint:
        if review or candidates:
            result.update(status="historically_absent", recorded=True)
        return result
    resolved = context and context.get("status") == "resolved"
    if (
        review
        and review.get("status") == "approved"
        and review["target"]["fingerprint"] == fingerprint
        and resolved
    ):
        approved_payload = review["assessment"]
        pending_changes = []
        if latest and latest["revision"] != review["assessment_revision"]:
            for field in ("state", "justification", "rationale", "conditions", "evidence"):
                if latest["payload"].get(field) != approved_payload.get(field):
                    pending_changes.append(field)
            fields = ("version", "context_id", "vulnerability_id")
            old_scope = {
                tuple(item[field] for field in fields) for item in approved_payload["targets"]
            }
            new_scope = {
                tuple(item[field] for field in fields) for item in latest["payload"]["targets"]
            }
            if old_scope != new_scope:
                pending_changes.append("scope")
        return {
            **result,
            "status": "approved",
            "pending_revision": bool(
                latest and latest["revision"] != review["assessment_revision"]
            ),
            "pending_changes": pending_changes,
            "recorded": True,
            "submitted": True,
            "approved": True,
            "assessment_id": review["assessment_id"],
            "assessment_revision": review["assessment_revision"],
            "historical_team_id": review["target"]["team_id"],
            "review": review,
            "approved_assessment": {
                "revision": review["assessment_revision"],
                "stage": "submitted",
                "payload": review["assessment"],
            },
        }
    # A reference rename changes /1 target bytes. Prove equivalence against the
    # retained reviewed source; never rewrite its target or extend its version.
    from dtvp.knowledge.assessment_continuity import approval_bridge

    bridge = (
        (
            continuity_resolver(context_id, vulnerability_id)
            if continuity_resolver
            else approval_bridge(journal, sections, version, context_id, vulnerability_id)
        )
        if resolved and (not review or review.get("status") == "approved")
        else None
    )
    if bridge:
        historical = bridge["review"]
        # A new authored revision is surfaced for explicit review rather than
        # being masked by a historical bridge.
        if not latest or latest["revision"] == historical["assessment_revision"]:
            return {
                **result,
                "status": "approved",
                "recorded": True,
                "submitted": True,
                "approved": True,
                "pending_revision": False,
                "pending_changes": [],
                "assessment_id": historical["assessment_id"],
                "assessment_revision": historical["assessment_revision"],
                "historical_team_id": historical["target"]["team_id"],
                "review": historical,
                "continuity": {key: value for key, value in bridge.items() if key != "review"},
                "approved_assessment": {
                    "revision": historical["assessment_revision"],
                    "stage": "submitted",
                    "payload": historical["assessment"],
                },
            }
    matching = [
        (record, covered) for record, covered in candidates if covered["fingerprint"] == fingerprint
    ]
    if matching and resolved:
        record, covered = max(matching, key=lambda item: item[0]["payload"]["created_at"])
        changes_requested = (
            review
            and review.get("status") == "changes_requested"
            and review.get("assessment_revision") == record["revision"]
        )
        return {
            **result,
            "status": "reassessment_needed" if changes_requested else record["stage"],
            "recorded": True,
            "submitted": record["stage"] == "submitted" and not changes_requested,
            "assessment_id": record["payload"]["assessment_id"],
            "assessment_revision": record["revision"],
            "assessment": record,
            "review": review,
        }
    if review or candidates:
        result.update(status="reassessment_needed", recorded=True, review=review)
    return result
