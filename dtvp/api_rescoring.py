"""Explicit contextual score preview and DTVP-owned versioned rule policies."""

import importlib
import json

from fastapi import APIRouter, HTTPException
from pydantic import Field
from sqlalchemy import select

from dtvp.api import DB, Auth, bounded_metadata, finding_for, project_for
from dtvp.domain import audit, finding_detail, lock_release
from dtvp.models import Decision, Evidence, Project, Release, RescorePolicy
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

router = APIRouter(prefix="/api/v2")


class Preview(RequestModel):
    expected_version: int = Field(ge=1)
    state: str = Field(pattern="^(affected|not_affected|fixed|under_investigation)$")
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
        # Only findings whose latest decision uses a rule depend on this policy.
        from dtvp.models import Finding

        for finding in db.scalars(
            select(Finding).where(Finding.release_id.in_([r.id for r in releases]))
        ):
            decision = db.scalar(
                select(Decision)
                .where(Decision.finding_id == finding.id)
                .order_by(Decision.created_at.desc(), Decision.id.desc())
                .limit(1)
            )
            if decision and decision.details.get("rescoring", {}).get("kind") == "rule":
                finding.evidence_revision += 1
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
    finding = finding_for(db, actor, finding_id, "assess")
    lock_release(db, finding.release_id)
    db.refresh(finding)
    if finding.state_version != data.expected_version:
        raise HTTPException(409, "Finding changed; reload before calculating")
    result = prepare(
        db, finding, finding_detail(db, finding), data.rescoring.model_dump(), data.state
    )
    return {
        "proposal": result,
        "state_version": finding.state_version,
        "preview_digest": preview_digest(finding, data.state, result),
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
