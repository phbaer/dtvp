"""Full-scope statistics: no pagination cap, no duplicate counts through sharing."""

from collections import Counter, defaultdict
from itertools import islice

from fastapi import APIRouter, Query, Request
from sqlalchemy import func, or_, select, text

from dtvp.api import project_for, release_for, visible_project_query
from dtvp.auth import authenticate
from dtvp.domain import finding_details
from dtvp.models import Component, Finding, Project, Release, Workspace, now

router = APIRouter(prefix="/api/v2")


def severity(score):
    if score is None:
        return "unknown"
    return (
        "critical"
        if score >= 9
        else "high"
        if score >= 7
        else "medium"
        if score >= 4
        else "low"
        if score > 0
        else "none"
    )


def aggregate(
    db,
    actor,
    *,
    project_id="",
    release_id="",
    workspace_id="",
    owner="",
    owner_match="contains",
    q="",
    lifecycle="",
):
    scope = visible_project_query(actor)
    if project_id:
        project_for(db, actor, project_id)
        scope = scope.where(Project.id == project_id)
    if release_id:
        release = release_for(db, actor, release_id)
        scope = scope.where(Project.id == release.project_id)
    if workspace_id:
        scope = scope.where(Project.workspace_id == workspace_id)
    projects = {p.id: p for p in db.scalars(scope)}
    releases = {
        r.id: r for r in db.scalars(select(Release).where(Release.project_id.in_(projects)))
    }
    teams = {
        w.id: w.name
        for w in db.scalars(
            select(Workspace).where(Workspace.id.in_({p.workspace_id for p in projects.values()}))
        )
    }
    query = (
        select(Finding)
        .join(Component, Finding.component_id == Component.id)
        .join(Release, Finding.release_id == Release.id)
        .join(Project, Release.project_id == Project.id)
        .where(Project.id.in_(projects), Finding.active.is_(True))
    )
    if release_id:
        query = query.where(Finding.release_id == release_id)
    if owner:
        column = Component.metadata_json["owner"].as_string()
        query = query.where(
            or_(column.is_(None), func.trim(column).in_(["", "Unassigned"]))
            if owner == "Unassigned"
            else column == owner
            if owner_match == "exact"
            else column.icontains(owner, autoescape=True)
        )
    if q:
        query = query.where(
            or_(
                Finding.identifier.icontains(q, autoescape=True),
                Component.name.icontains(q, autoescape=True),
                Component.purl.icontains(q, autoescape=True),
                Project.name.icontains(q, autoescape=True),
                Release.version.icontains(q, autoescape=True),
            )
        )
    workflow, applicability, base_severity, effective_severity = (
        Counter(),
        Counter(),
        Counter(),
        Counter(),
    )
    by_project = {
        p.id: {
            "id": p.id,
            "name": p.name,
            "workspace_id": p.workspace_id,
            "workspace": teams[p.workspace_id],
            "total": 0,
            "states": Counter(),
        }
        for p in projects.values()
    }
    by_team = {
        key: {"id": key, "name": name, "total": 0, "states": Counter()}
        for key, name in teams.items()
    }
    owners = defaultdict(lambda: {"total": 0, "states": Counter()})
    unique = defaultdict(lambda: {"states": set(), "score": None})
    total = changed = conflicts = stale = adopted = 0
    iterator = iter(
        db.scalars(query.order_by(Finding.release_id, Finding.id).execution_options(yield_per=250))
    )
    observation_cache = {}
    while batch := list(islice(iterator, 250)):
        for finding in finding_details(db, batch, observation_cache):
            if lifecycle and finding["lifecycle"] != lifecycle:
                continue
            total += 1
            status = finding["lifecycle"]
            state = "unassessed"
            if finding["decisions"]:
                state = (
                    finding["decisions"][0]["state"]
                    if status != "needs_revalidation"
                    else "needs_revalidation"
                )
            elif finding["imported_assessments"]:
                imported = {
                    entry["state"]
                    for entry in finding["imported_assessments"]
                    if entry.get("state")
                }
                state = (
                    "legacy:" + next(iter(imported))
                    if len(imported) == 1
                    else "legacy:conflicting"
                    if len(imported) > 1
                    else "legacy:documented"
                )
            workflow[status] += 1
            applicability[state] += 1
            base_severity[severity(finding["original_score"])] += 1
            effective_severity[
                severity(finding.get("effective_score", finding["original_score"]))
            ] += 1
            changed += status == "needs_revalidation"
            conflicts += finding["conflicting_scores"]
            stale += finding["stale_evidence"]
            adopted += bool(finding.get("adopted_rescoring"))
            project = projects[releases[finding["release_id"]].project_id]
            for group in (by_project[project.id], by_team[project.workspace_id]):
                group["total"] += 1
                group["states"][status] += 1
            owner_name = (
                finding["owner"]
                if isinstance(finding["owner"], str) and finding["owner"].strip()
                else "Unassigned"
            )
            owners[owner_name]["total"] += 1
            owners[owner_name]["states"][status] += 1
            group = unique[finding["identifier"]]
            group["states"].add(state)
            if finding["original_score"] is not None:
                group["score"] = max(group["score"] or 0, finding["original_score"])
        last_release = batch[-1].release_id
        observation_cache = {last_release: observation_cache[last_release]}
    unique_states, unique_severity = Counter(), Counter()
    for occurrences in unique.values():
        states = occurrences["states"]
        status = (
            "inconsistent"
            if len(states - {"unassessed"}) > 1
            else "incomplete"
            if "unassessed" in states and len(states) > 1
            else next(iter(states))
        )
        unique_states[status] += 1
        unique_severity[severity(occurrences["score"])] += 1
    return {
        "as_of": now().isoformat(),
        "totals": {
            "findings": total,
            "unique_vulnerabilities": len(unique),
            "projects": len(projects),
            "projects_with_findings": sum(p["total"] > 0 for p in by_project.values()),
            "releases": int(release_id in releases) if release_id else len(releases),
            "needs_revalidation": changed,
            "conflicting_scores": conflicts,
            "stale_evidence": stale,
            "adopted_rescoring": adopted,
        },
        "workflow": workflow,
        "applicability": applicability,
        "base_severity": base_severity,
        "effective_severity": effective_severity,
        "unique_states": unique_states,
        "unique_base_severity": unique_severity,
        "teams": sorted(by_team.values(), key=lambda row: row["name"]),
        "owners": [{"name": name, **values} for name, values in sorted(owners.items())],
        "projects": sorted(by_project.values(), key=lambda row: (row["name"], row["id"])),
    }


@router.get("/statistics")
def statistics(
    request: Request,
    project_id: str = "",
    release_id: str = "",
    workspace_id: str = "",
    owner: str = "",
    owner_match: str = Query("contains", pattern="^(contains|exact)$"),
    q: str = "",
    lifecycle: str = "",
    project_cursor: int = Query(0, ge=0),
    project_limit: int = Query(25, ge=1, le=100),
):
    # Statistics and authorization share one consistent database snapshot.
    engine = request.app.state.engine
    with engine.connect() as connection:
        if engine.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        with request.app.state.sessions(bind=connection) as db:
            if engine.dialect.name == "postgresql":
                db.execute(text("SET TRANSACTION READ ONLY"))
            actor = authenticate(request, db)
            result = aggregate(
                db,
                actor,
                project_id=project_id,
                release_id=release_id,
                workspace_id=workspace_id,
                owner=owner,
                owner_match=owner_match,
                q=q,
                lifecycle=lifecycle,
            )
            projects = result.pop("projects")
            result["project_page"] = {
                "items": projects[project_cursor : project_cursor + project_limit],
                "next_cursor": project_cursor + project_limit
                if project_cursor + project_limit < len(projects)
                else None,
            }
            return result
