"""Required team reviews are distinct from project sharing and scoring."""

from fastapi import HTTPException
from sqlalchemy import select

from dtvp.models import Approval, Grant, Project, Release, ReviewScope, Workspace
from dtvp.storage import canonical, digest


def coverage(db, finding, decisions, prepared=None):
    scope = prepared["scopes"].get(finding.id) if prepared else db.get(ReviewScope, finding.id)
    project = (
        prepared["projects"][finding.release_id]
        if prepared
        else db.get(Project, db.get(Release, finding.release_id).project_id)
    )
    teams = scope.workspace_ids if scope else [project.workspace_id]
    latest = {}
    for decision in decisions:
        latest.setdefault(decision.workspace_id, decision)
    reviews = []
    for team in sorted(teams):
        decision = latest.get(team)
        approval = (
            prepared["approvals"].get(decision.id)
            if prepared and decision
            else db.scalar(select(Approval).where(Approval.decision_id == decision.id))
            if decision
            else None
        )
        grant = (
            prepared["grants"].get((project.id, team))
            if prepared
            else db.get(Grant, (project.id, team))
        )
        accessible = team == project.workspace_id or bool(
            grant and {"read", "assess", "approve"}.issubset(grant.capabilities)
        )
        status = (
            "blocked_access"
            if not accessible
            else "open"
            if not decision
            else "needs_revalidation"
            if decision.evidence_revision != finding.evidence_revision
            else "approved"
            if approval
            else "ready"
            if decision.status == "submitted"
            else "changes_requested"
        )
        name = (
            prepared["workspaces"].get(team, "Unknown")
            if prepared
            else db.get(Workspace, team).name
        )
        reviews.append(
            {
                "workspace_id": team,
                "team": name,
                "status": status,
                "decision_id": decision.id if decision else None,
                "approval_id": approval.id if approval else None,
                "state": decision.state if decision else None,
            }
        )
    ready = bool(reviews) and all(r["status"] == "approved" for r in reviews)
    states = {r["state"] for r in reviews}
    # Mixed outcomes cannot establish a blanket not-affected/fixed assertion.
    state = (
        "affected"
        if "affected" in states
        else next(iter(states))
        if len(states) == 1 and None not in states
        else "under_investigation"
    )
    return {
        "teams": reviews,
        "ready": ready,
        "state": state,
        "digest": digest(
            canonical({"evidence_revision": finding.evidence_revision, "reviews": reviews})
        ),
    }


def require_ready(detail):
    if not detail["review_coverage"]["ready"] or not detail["active"]:
        raise HTTPException(
            409,
            "Every required team must approve the current vulnerability evidence before rescoring",
        )


def select_team(db, actor, project, detail, workspace_id=None):
    """Select only an authorized review team; never substitute another team's decision."""
    for review in detail["review_coverage"]["teams"]:
        team = review["workspace_id"]
        if workspace_id and team != workspace_id:
            continue
        grant = db.get(Grant, (project.id, team))
        if team == project.workspace_id or grant:
            for cap in ("assess", "approve"):
                if actor.workspace(team, cap) and (
                    team == project.workspace_id or cap in grant.capabilities
                ):
                    return team
    if workspace_id:
        raise HTTPException(404, "Review team unavailable in your scope")
    return None


def actor_detail(db, actor, project, detail, workspace_id=None):
    team = select_team(db, actor, project, detail, workspace_id)
    decision = next((d for d in detail["decisions"] if d["workspace_id"] == team), None)
    review = next(
        (r for r in detail["review_coverage"]["teams"] if r["workspace_id"] == team), None
    )
    if "capabilities" in detail:
        detail["capabilities"] = [
            c for c in detail["capabilities"] if c not in {"assess", "approve"}
        ]
        if team:
            grant = db.get(Grant, (project.id, team))
            detail["capabilities"] += [
                c
                for c in ("assess", "approve")
                if actor.workspace(team, c)
                and (team == project.workspace_id or grant and c in grant.capabilities)
            ]
    detail.update(
        review_workspace_id=team,
        latest_decision=decision,
        review_lifecycle=review["status"] if review else None,
    )
    return detail
