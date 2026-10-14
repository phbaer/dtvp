"""Inventory publication and decisions. All mutations share the release lock."""

from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select

from dtvp.auth import aware
from dtvp.legacy_dt import from_advisory as decode_legacy
from dtvp.models import (
    Approval,
    Audit,
    Component,
    Decision,
    Evidence,
    Finding,
    Observation,
    Project,
    Release,
    Revision,
    User,
    now,
)
from dtvp.parsers import identity, parse
from dtvp.storage import canonical, digest


def lock_release(db, release_id):
    release = db.scalar(select(Release).where(Release.id == release_id).with_for_update())
    if not release:
        raise HTTPException(404, "Release unavailable")
    return release


def audit(db, actor_id, action, subject_id, project_id=None, details=None):
    db.add(
        Audit(
            actor_id=actor_id,
            action=action,
            subject_id=subject_id,
            project_id=project_id,
            details=details or {},
        )
    )


def revisions(db, release_id):
    return list(
        db.scalars(
            select(Revision)
            .where(Revision.release_id == release_id)
            .order_by(Revision.occurred_at, Revision.created_at, Revision.id)
        )
    )


def effective_revisions(db, release_id):
    by_source = defaultdict(list)
    for revision in revisions(db, release_id):
        if revision.completeness == "complete":
            by_source[revision.source] = [revision]
        else:
            by_source[revision.source].append(revision)
    return [revision for values in by_source.values() for revision in values]


def current_observations(db, release_id):
    effective = effective_revisions(db, release_id)
    by_pair = {}
    for revision in effective:
        for observation in db.scalars(
            select(Observation).where(Observation.revision_id == revision.id)
        ):
            by_pair[(observation.finding_id, observation.source)] = observation
    return list(by_pair.values())


def import_sbom(
    db, artifacts, release, raw, *, source, event_id, occurred_at, completeness, context, actor_id
):
    document = parse(raw)
    release = lock_release(db, release.id)
    checksum = digest(raw)
    existing = db.scalar(
        select(Revision).where(
            Revision.release_id == release.id,
            Revision.source == source,
            Revision.event_id == event_id,
        )
    )
    if existing:
        if (
            existing.artifact_sha != checksum
            or existing.context != context
            or (existing.completeness != completeness or aware(existing.occurred_at) != occurred_at)
        ):
            raise HTTPException(409, "Event ID already belongs to different input")
        return existing
    before = {(o.finding_id, o.source): o.fingerprint for o in current_observations(db, release.id)}
    revision = Revision(
        release_id=release.id,
        source=source,
        event_id=event_id,
        occurred_at=occurred_at,
        completeness=completeness,
        context=context,
        artifact_sha=artifacts.put(raw),
        format=document["format"],
        document={},
    )
    db.add(revision)
    db.flush()
    refs = {}
    counts = Counter(identity(component, source) for component in document["components"])
    for component in document["components"]:
        key = identity(component, source)
        if counts[key] > 1:
            key += ":occurrence:" + digest(canonical([source, component["bom-ref"]]))
        stored = db.scalar(
            select(Component).where(Component.release_id == release.id, Component.identity == key)
        )
        if not stored:
            stored = Component(
                release_id=release.id,
                identity=key,
                name=component["name"],
                version=component.get("version", ""),
                purl=component.get("purl", ""),
            )
            db.add(stored)
            db.flush()
        refs[component["bom-ref"]] = stored.id
    document["component_ids"] = refs
    revision.document = document
    for item in document["findings"]:
        component_id = refs[item["ref"]]
        finding = db.scalar(
            select(Finding).where(
                Finding.release_id == release.id,
                Finding.component_id == component_id,
                Finding.identifier == item["identifier"],
            )
        )
        if not finding:
            finding = Finding(
                release_id=release.id, component_id=component_id, identifier=item["identifier"]
            )
            db.add(finding)
            db.flush()
        assertion = {
            "advisory": item["advisory"],
            "match": item["match"],
            "component_ref": item["ref"],
            "method": "source-supplied",
        }
        assertion["scope"] = {
            key: context[key]
            for key in ("commit", "branch", "artifact_digest", "environment", "detector_version")
            if key in context
        }
        legacy = decode_legacy(item["advisory"])
        if legacy:
            assertion["imported_assessment"] = legacy
        fingerprint = digest(canonical(assertion))
        duplicate = db.scalar(
            select(Observation).where(
                Observation.finding_id == finding.id,
                Observation.revision_id == revision.id,
                Observation.source == source,
                Observation.fingerprint == fingerprint,
            )
        )
        if not duplicate:
            db.add(
                Observation(
                    finding_id=finding.id,
                    revision_id=revision.id,
                    source=source,
                    fingerprint=fingerprint,
                    assertion=assertion,
                )
            )
            db.flush()
    after = {(o.finding_id, o.source): o.fingerprint for o in current_observations(db, release.id)}
    changed = {key[0] for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    active = {key[0] for key in after}
    for finding in db.scalars(select(Finding).where(Finding.release_id == release.id)):
        has_match = any(
            e.assertion.get("kind") == "match"
            for e in db.scalars(select(Evidence).where(Evidence.finding_id == finding.id))
        )
        finding.active = finding.id in active or has_match
        if finding.id in changed and any(key[0] == finding.id for key in before):
            finding.evidence_revision += 1
            finding.state_version += 1
    release.generation += 1
    audit(
        db,
        actor_id,
        "sbom.import",
        revision.id,
        release.project_id,
        {"source": source, "event_id": event_id, "sha256": checksum},
    )
    db.flush()
    return revision


def inventory(db, release):
    effective = effective_revisions(db, release.id)
    active_ids = {
        component_id for r in effective for component_id in r.document["component_ids"].values()
    }
    components = {
        c.id: c for c in db.scalars(select(Component).where(Component.release_id == release.id))
    }
    return effective, components, active_ids


def finding_detail(db, finding, *, observations=None, prepared=None):
    component = (
        prepared["components"][finding.component_id]
        if prepared
        else db.get(Component, finding.component_id)
    )
    observations = (
        observations if observations is not None else current_observations(db, finding.release_id)
    )
    observations = [o for o in observations if o.finding_id == finding.id]
    evidence = (
        prepared["evidence"].get(finding.id, [])
        if prepared
        else list(
            db.scalars(
                select(Evidence)
                .where(Evidence.finding_id == finding.id)
                .order_by(Evidence.created_at, Evidence.id)
            )
        )
    )
    decisions = (
        prepared["decisions"].get(finding.id, [])
        if prepared
        else list(
            db.scalars(
                select(Decision)
                .where(Decision.finding_id == finding.id)
                .order_by(Decision.created_at.desc(), Decision.id.desc())
            )
        )
    )
    decision = decisions[0] if decisions else None
    approval = (
        (
            prepared["approvals"].get(decision.id)
            if prepared
            else db.scalar(select(Approval).where(Approval.decision_id == decision.id))
        )
        if decision
        else None
    )
    lifecycle = "open"
    if decision:
        lifecycle = (
            "needs_revalidation"
            if decision.evidence_revision != finding.evidence_revision
            else (
                "approved"
                if approval
                else "ready"
                if decision.status == "submitted"
                else "changes_requested"
            )
        )
    imported = [
        {
            "source": observation.source,
            "revision_id": observation.revision_id,
            **observation.assertion["imported_assessment"],
        }
        for observation in observations
        if observation.assertion.get("imported_assessment")
    ]
    if not decision and imported:
        imported_states = {entry.get("state") for entry in imported if entry.get("state")}
        lifecycle = (
            "legacy_conflicting"
            if any(entry["conflicting"] for entry in imported) or len(imported_states) > 1
            else (
                "legacy_pending"
                if any(entry["pending_review"] for entry in imported)
                else "legacy_assessed"
                if any(entry["assessed"] for entry in imported)
                else "legacy_documented"
            )
        )
    advisory_assertions = [o.assertion["advisory"] for o in observations]
    effective_evidence = {}
    for record in evidence:
        key = (
            record.source,
            record.assertion.get("kind"),
            record.assertion.get("advisory", {}).get("id", finding.identifier),
        )
        effective_evidence[key] = record
    advisory_assertions += [e.assertion.get("advisory", {}) for e in effective_evidence.values()]
    ratings = [
        rating for assertion in advisory_assertions for rating in assertion.get("ratings", [])
    ]
    scores = [
        float(rating["score"])
        for rating in ratings
        if isinstance(rating.get("score"), (int, float))
    ]
    vectors = {rating.get("vector") for rating in ratings if rating.get("vector")}
    from dtvp.rescoring import original_vectors

    originals = original_vectors(advisory_assertions)
    proposed_rescoring = decision.details.get("rescoring") if decision else None
    if not isinstance(proposed_rescoring, dict) or not all(
        key in proposed_rescoring for key in ("score", "vector", "base_vector", "kind", "rationale")
    ):
        proposed_rescoring = None
    adopted_rescoring = (
        proposed_rescoring
        if lifecycle == "approved" and approval.policy.get("rescoring_verified") is True
        else None
    )
    stale = any(aware(o.created_at) < now() - timedelta(days=30) for o in observations)
    return {
        "id": finding.id,
        "identifier": finding.identifier,
        "kind": finding.kind,
        "release_id": finding.release_id,
        "component_id": component.id,
        "component": component.name,
        "component_version": component.version,
        "purl": component.purl,
        "owner": component.metadata_json.get("owner", "Unassigned"),
        "active": finding.active,
        "lifecycle": lifecycle,
        "state_version": finding.state_version,
        "evidence_revision": finding.evidence_revision,
        "original_score": max(scores) if scores else None,
        "original_vectors": originals,
        "proposed_rescoring": proposed_rescoring,
        "adopted_rescoring": adopted_rescoring,
        "effective_score": adopted_rescoring["score"]
        if adopted_rescoring
        else max(scores)
        if scores
        else None,
        "effective_vector": adopted_rescoring["vector"] if adopted_rescoring else None,
        "conflicting_scores": len(vectors) > 1,
        "stale_evidence": stale,
        "imported_assessments": imported,
        "description": next(
            (a.get("description") for a in advisory_assertions if a.get("description")), ""
        ),
        "observations": [
            {
                **o.assertion,
                "id": o.id,
                "source": o.source,
                "revision_id": o.revision_id,
                "created_at": o.created_at.isoformat(),
            }
            for o in observations
        ],
        "evidence": [
            {
                **e.assertion,
                "id": e.id,
                "source": e.source,
                "snapshot_id": e.snapshot_id,
                "created_at": e.created_at.isoformat(),
                "input_evidence_revision": e.input_revision,
                "published_evidence_revision": e.published_revision,
            }
            for e in evidence
        ],
        "decisions": [
            {
                "id": d.id,
                "state": d.state,
                "rationale": d.rationale,
                "author_id": d.author_id,
                "author_name": (
                    prepared["users"].get(d.author_id, "Unknown")
                    if prepared
                    else db.get(User, d.author_id).name
                ),
                "workspace_id": d.workspace_id,
                "evidence_revision": d.evidence_revision,
                "status": d.status,
                "created_at": d.created_at.isoformat(),
                "details": d.details,
            }
            for d in decisions
        ],
        "approval": {
            "id": approval.id,
            "reviewer_id": approval.reviewer_id,
            "created_at": approval.created_at.isoformat(),
            "policy": approval.policy,
        }
        if approval
        else None,
    }


def check_version(finding, expected):
    if finding.state_version != expected:
        raise HTTPException(409, "Finding changed; reload and review the new evidence")


def submit_decision(db, actor, finding, expected, state, rationale, details):
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    check_version(finding, expected)
    project = actor.require(db, db.get(Project, release.project_id), "assess")
    workspace_id = actor.decision_workspace(db, project)
    if not rationale.strip():
        raise HTTPException(422, "Explain the decision")
    decision = Decision(
        finding_id=finding.id,
        author_id=actor.user.id,
        workspace_id=workspace_id,
        evidence_revision=finding.evidence_revision,
        state=state,
        rationale=rationale,
        details=details,
    )
    db.add(decision)
    finding.state_version += 1
    db.flush()
    audit(db, actor.user.id, "decision.submit", decision.id, project.id)
    return decision


def approve_decision(db, actor, finding, expected, decision_id, *, request_changes=False):
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    check_version(finding, expected)
    project = actor.require(db, db.get(Project, release.project_id), "approve")
    decision = db.scalar(
        select(Decision)
        .where(Decision.finding_id == finding.id)
        .order_by(Decision.created_at.desc(), Decision.id.desc())
    )
    if not decision or decision.id != decision_id or decision.status != "submitted":
        raise HTTPException(409, "Decision is no longer pending")
    if decision.evidence_revision != finding.evidence_revision:
        raise HTTPException(409, "Evidence changed; submit a new decision")
    if decision.author_id == actor.user.id:
        raise HTTPException(403, "A different reviewer must approve")
    if db.scalar(select(Approval).where(Approval.decision_id == decision.id)):
        raise HTTPException(409, "Already approved")
    if decision.details.get("rescoring") and not request_changes:
        from dtvp.rescoring import calculate, policy

        rescoring = decision.details["rescoring"]
        detail = finding_detail(db, finding)
        if rescoring.get("base_vector") not in {
            entry["vector"] for entry in detail["original_vectors"]
        }:
            raise HTTPException(409, "Original Base evidence changed")
        validated = calculate(rescoring["base_vector"], rescoring["vector"])
        if validated["score"] != rescoring.get("score"):
            raise HTTPException(409, "Rescoring calculation is inconsistent")
        if (
            rescoring.get("kind") == "rule"
            and rescoring.get("policy_digest") != policy(db, project.id)["digest"]
        ):
            raise HTTPException(409, "Rescoring policy changed; submit a new proposal")
    if request_changes:
        decision.status = "changes_requested"
    else:
        db.add(
            Approval(
                decision_id=decision.id,
                reviewer_id=actor.user.id,
                evidence_revision=finding.evidence_revision,
                policy={
                    "version": "four-eyes/1",
                    "scope": "component-release",
                    "decision_workspace": decision.workspace_id,
                    "rescoring_verified": bool(decision.details.get("rescoring")),
                },
            )
        )
    finding.state_version += 1
    audit(
        db,
        actor.user.id,
        "decision.request_changes" if request_changes else "decision.approve",
        decision.id,
        project.id,
    )


def import_evidence(db, actor_id, finding, *, source, external_id, assertion, snapshot_id=None):
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    fingerprint = digest(canonical(assertion))
    existing = db.scalar(
        select(Evidence).where(
            Evidence.finding_id == finding.id,
            Evidence.source == source,
            Evidence.external_id == external_id,
        )
    )
    if existing:
        if existing.fingerprint != fingerprint or existing.snapshot_id != snapshot_id:
            raise HTTPException(409, "Evidence ID already belongs to different content")
        return existing
    evidence = Evidence(
        finding_id=finding.id,
        source=source,
        external_id=external_id,
        assertion=assertion,
        snapshot_id=snapshot_id,
        fingerprint=fingerprint,
        input_revision=finding.evidence_revision,
    )
    prior = db.scalar(
        select(Evidence)
        .where(
            Evidence.finding_id == finding.id,
            Evidence.source == source,
            Evidence.assertion["kind"].as_string() == assertion.get("kind"),
        )
        .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        .limit(1)
    )
    substantive = {key: value for key, value in assertion.items() if key != "checked_at"}
    prior_substantive = (
        {key: value for key, value in prior.assertion.items() if key != "checked_at"}
        if prior
        else None
    )
    db.add(evidence)
    if prior_substantive != substantive or (prior and prior.snapshot_id != snapshot_id):
        finding.evidence_revision += 1
        finding.state_version += 1
    evidence.published_revision = finding.evidence_revision
    audit(
        db,
        actor_id,
        "evidence.import",
        finding.id,
        release.project_id,
        {"source": source, "external_id": external_id, "snapshot_id": snapshot_id},
    )
    db.flush()
    return evidence


def finding_details(db, findings, observation_cache=None):
    """Batch-load review facts; the same semantics serve details, queues and statistics."""
    if not findings:
        return []
    observation_cache = observation_cache if observation_cache is not None else {}
    ids = [finding.id for finding in findings]
    prepared = {
        "components": {
            c.id: c
            for c in db.scalars(
                select(Component).where(Component.id.in_([f.component_id for f in findings]))
            )
        },
        "evidence": defaultdict(list),
        "decisions": defaultdict(list),
        "approvals": {},
    }
    for record in db.scalars(
        select(Evidence)
        .where(Evidence.finding_id.in_(ids))
        .order_by(Evidence.created_at, Evidence.id)
    ):
        prepared["evidence"][record.finding_id].append(record)
    for decision in db.scalars(
        select(Decision)
        .where(Decision.finding_id.in_(ids))
        .order_by(Decision.created_at.desc(), Decision.id.desc())
    ):
        prepared["decisions"][decision.finding_id].append(decision)
    decision_ids = [records[0].id for records in prepared["decisions"].values() if records]
    prepared["approvals"] = {
        a.decision_id: a
        for a in db.scalars(select(Approval).where(Approval.decision_id.in_(decision_ids)))
    }
    author_ids = {d.author_id for records in prepared["decisions"].values() for d in records}
    prepared["users"] = {
        u.id: u.name for u in db.scalars(select(User).where(User.id.in_(author_ids)))
    }
    for release_id in {f.release_id for f in findings}:
        if release_id not in observation_cache:
            grouped = defaultdict(list)
            for observation in current_observations(db, release_id):
                grouped[observation.finding_id].append(observation)
            observation_cache[release_id] = grouped
    return [
        finding_detail(
            db,
            finding,
            observations=observation_cache[finding.release_id].get(finding.id, []),
            prepared=prepared,
        )
        for finding in findings
    ]
