"""Explicit contextual score preview and DTVP-owned versioned rule policies."""

import importlib
import json

from fastapi import APIRouter, HTTPException
from pydantic import Field
from sqlalchemy import select

from dtvp.api import DB, Auth, bounded_metadata, finding_for, project_for
from dtvp.domain import audit, check_version, finding_detail, lock_release
from dtvp.models import (
    Evidence,
    FinalRescoring,
    Grant,
    Project,
    Release,
    RescorePolicy,
    ReviewScope,
    Workspace,
)
from dtvp.rescoring import (
    BASE,
    DEFAULT_PATH,
    evidence_candidate,
    policy,
    prepare,
    preview_digest,
    validate_policy,
)
from dtvp.schemas import RequestModel, RescoreInput
from dtvp.team_reviews import require_ready

router = APIRouter(prefix="/api/v2")


class Preview(RequestModel):
    expected_version: int = Field(ge=1)
    state: str | None = Field(
        default=None, pattern="^(affected|not_affected|fixed|under_investigation)$"
    )
    rescoring: RescoreInput


class PolicyInput(RequestModel):
    expected_version: int = Field(ge=0)
    config: dict


@router.get("/cvss/metrics/{version}")
def metric_catalog(version: str, actor: Auth):
    if version not in BASE:
        raise HTTPException(422, "Unsupported CVSS version")
    constants = importlib.import_module(f"cvss.constants{version[0]}")
    return {
        "version": version,
        "metrics": [
            {
                "key": key,
                "name": name,
                "base": key in BASE[version],
                "values": [
                    {"value": value, "name": label}
                    for value, label in constants.METRICS_VALUE_NAMES[key].items()
                ],
            }
            for key, name in constants.METRICS_ABBREVIATIONS.items()
        ],
    }


@router.get("/projects/{project_id}/rescore-policy")
def get_policy(project_id: str, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    return {**policy(db, project_id), "default_config": json.loads(DEFAULT_PATH.read_text())}


@router.put("/projects/{project_id}/rescore-policy")
def save_policy(project_id: str, data: PolicyInput, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    project = db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    current = policy(db, project.id)
    if data.expected_version != current["version"]:
        raise HTTPException(409, "Rescoring rules changed; reload before editing")
    bounded_metadata(data.config)
    try:
        validate_policy(data.config)
    except TypeError, AttributeError, KeyError:
        raise HTTPException(422, "Invalid rule configuration structure") from None
    if current["config"] == data.config:
        return current
    releases = list(
        db.scalars(select(Release).where(Release.project_id == project_id).order_by(Release.id))
    )
    for release in releases:
        lock_release(db, release.id)
    row = db.get(RescorePolicy, project_id)
    if row is None:
        row = RescorePolicy(project_id=project_id, version=1, config=data.config)
        db.add(row)
    else:
        row.version += 1
        row.config = data.config
    if current["config"] != data.config:
        from dtvp.models import Finding

        for finding in db.scalars(
            select(Finding).where(Finding.release_id.in_([r.id for r in releases]))
        ):
            score = db.scalar(
                select(FinalRescoring)
                .where(FinalRescoring.finding_id == finding.id)
                .order_by(FinalRescoring.created_at.desc(), FinalRescoring.id.desc())
            )
            if score and score.proposal.get("kind") == "rule":
                finding.state_version += 1
    audit(
        db,
        actor.user.id,
        "rescore-policy.update",
        project_id,
        project_id,
        {"version": row.version, "config": data.config},
    )
    db.flush()
    return policy(db, project_id)


@router.post("/findings/{finding_id}/rescoring/preview")
def preview(finding_id: str, data: Preview, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "rescore")
    lock_release(db, finding.release_id)
    db.refresh(finding)
    if finding.state_version != data.expected_version:
        raise HTTPException(409, "Finding changed; reload before calculating")
    detail = finding_detail(db, finding)
    require_ready(detail)
    state = detail["review_coverage"]["state"]
    if data.state and data.state != state:
        raise HTTPException(422, "Use the consolidated team applicability state")
    result = prepare(db, finding, detail, data.rescoring.model_dump(), state)
    return {
        "proposal": result,
        "state_version": finding.state_version,
        "preview_digest": preview_digest(finding, state, result),
    }


@router.get("/findings/{finding_id}/rescoring/proposals")
def proposals(finding_id: str, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id)
    detail = finding_detail(db, finding)
    records = list(
        db.scalars(
            select(Evidence)
            .where(Evidence.finding_id == finding.id, Evidence.source.in_(["vscorer", "agentyzer"]))
            .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        )
    )
    # Return the newest result of each provider; older results remain in history.
    latest = {}
    for record in records:
        latest.setdefault(record.source, record)
    release = db.get(Release, finding.release_id)
    return {
        "original_vectors": detail["original_vectors"],
        "policy_digest": policy(db, release.project_id)["digest"],
        "items": [evidence_candidate(db, finding, record.id, detail) for record in latest.values()],
    }


class ReviewTeamsInput(RequestModel):
    expected_version: int = Field(ge=1)
    workspace_ids: list[str] = Field(min_length=1, max_length=100)


@router.get("/findings/{finding_id}/review-teams")
def review_teams(finding_id: str, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "manage")
    project = db.get(Project, db.get(Release, finding.release_id).project_id)
    grants = list(db.scalars(select(Grant).where(Grant.project_id == project.id)))
    eligible = {project.workspace_id} | {
        g.workspace_id for g in grants if {"read", "assess", "approve"}.issubset(g.capabilities)
    }
    return {
        "items": [
            {"id": w.id, "name": w.name}
            for w in db.scalars(
                select(Workspace).where(Workspace.id.in_(eligible)).order_by(Workspace.name)
            )
        ]
    }


@router.put("/findings/{finding_id}/review-teams")
def set_review_teams(finding_id: str, data: ReviewTeamsInput, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "manage")
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    check_version(finding, data.expected_version)
    project = db.get(Project, release.project_id)
    teams = sorted(set(data.workspace_ids))
    for team in teams:
        grant = db.get(Grant, (project.id, team))
        if not db.get(Workspace, team) or (
            team != project.workspace_id
            and (not grant or not {"read", "assess", "approve"}.issubset(grant.capabilities))
        ):
            raise HTTPException(
                422, "Required teams need explicit read, assessment and approval access"
            )
    scope = db.get(ReviewScope, finding.id)
    current = sorted(scope.workspace_ids) if scope else [project.workspace_id]
    if current != teams:
        if scope:
            scope.workspace_ids = teams
        else:
            db.add(ReviewScope(finding_id=finding.id, workspace_ids=teams))
        # Even changing a team list back cannot resurrect a previously published score.
        finding.evidence_revision += 1
        finding.state_version += 1
        audit(
            db,
            actor.user.id,
            "review-teams.update",
            finding.id,
            project.id,
            {"workspace_ids": teams},
        )
    db.flush()
    return finding_detail(db, finding)["review_coverage"]


@router.post("/findings/{finding_id}/rescoring", status_code=201)
def publish_rescoring(finding_id: str, data: Preview, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "rescore")
    release = lock_release(db, finding.release_id)
    db.refresh(finding)
    check_version(finding, data.expected_version)
    detail = finding_detail(db, finding)
    require_ready(detail)
    state = detail["review_coverage"]["state"]
    if data.state and data.state != state:
        raise HTTPException(422, "Use the consolidated team applicability state")
    proposal = prepare(db, finding, detail, data.rescoring.model_dump(), state)
    if data.rescoring.preview_digest != preview_digest(finding, state, proposal):
        raise HTTPException(409, "Preview the current contextual score before publishing")
    score = FinalRescoring(
        finding_id=finding.id,
        coordinator_id=actor.user.id,
        evidence_revision=finding.evidence_revision,
        review_digest=detail["review_coverage"]["digest"],
        proposal=proposal,
    )
    db.add(score)
    finding.state_version += 1
    db.flush()
    audit(
        db,
        actor.user.id,
        "rescoring.publish",
        score.id,
        release.project_id,
        {"review_digest": score.review_digest},
    )
    return {"id": score.id, "state_version": finding.state_version}
