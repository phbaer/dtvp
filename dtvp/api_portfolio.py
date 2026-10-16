"""Authorized project statistics over a single immutable selection of version heads."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for, visible_project_query
from dtvp.api_workflow import team_labels
from dtvp.knowledge.filters import KnowledgeFilters
from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.organization_portfolio import MAX_PROJECTS, organization_portfolio
from dtvp.knowledge.portfolio import load_portfolio

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/portfolio")
def portfolio(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    version: list[Name] | None = Query(None, max_length=200),
    team_id: Name | None = None,
    q: str = Query("", max_length=500),
    lifecycle: str = Query("", max_length=100),
    expected_heads: Sha | None = None,
    source_severity: str = "",
    contextual_severity: str = "",
    applicability: str = "",
    scoring_status: str = "",
    team_review: str = "",
    provider: str = "",
    cvss_version: str = "",
    dependency: str = "",
    source_conflict: str = "",
    component: str = "",
    criticality: str = "",
    exposure: str = "",
    support_status: str = "",
    metadata_status: str = "",
):
    project_for(db, actor, project_id)
    filters = KnowledgeFilters(
        source_severity=source_severity,
        contextual_severity=contextual_severity,
        applicability=applicability,
        scoring_status=scoring_status,
        team_review=team_review,
        provider=provider,
        cvss_version=cvss_version,
        dependency=dependency,
        source_conflict=source_conflict,
        component=component,
        criticality=criticality,
        exposure=exposure,
        support_status=support_status,
        metadata_status=metadata_status,
    )
    result = load_portfolio(
        request.app.state.knowledge,
        project_id,
        versions=version,
        team_id=team_id,
        q=q,
        lifecycle=lifecycle,
        filters=filters,
    )
    if expected_heads is not None and expected_heads != result["heads_digest"]:
        raise HTTPException(409, "Portfolio version heads changed; refresh the selected statistics")
    result["team_labels"] = team_labels(db, {"by_team": result["by_team"]})
    return result


@router.get("/portfolio")
def organization_statistics(
    request: Request,
    db: DB,
    actor: Auth,
    filters: KnowledgeFilters = Depends(),
    project: list[Name] | None = Query(default=None, max_length=100),
    team_id: Name | None = None,
    q: str = Query(default="", max_length=500),
    lifecycle: str = Query(default="", max_length=100),
    expected_heads: Sha | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
):
    if project is not None:
        if len(project) != len(set(project)):
            raise HTTPException(422, "Portfolio project selection must be distinct")
        selected = [project_for(db, actor, identifier) for identifier in project]
    else:
        selected = list(db.scalars(visible_project_query(actor).limit(MAX_PROJECTS + 1)))
        if len(selected) > MAX_PROJECTS:
            raise HTTPException(422, "Portfolio exceeds 100 projects; select projects explicitly")
        for item in selected:
            project_for(db, actor, item.id)
    result = organization_portfolio(
        request.app.state.knowledge,
        [{"id": item.id, "name": item.name} for item in selected],
        team_id=team_id,
        q=q,
        lifecycle=lifecycle,
        filters=filters,
        offset=offset,
        limit=limit,
    )
    if expected_heads is not None and expected_heads != result["heads_digest"]:
        raise HTTPException(
            409, "Portfolio project/version heads changed; refresh the full selection"
        )
    result["team_labels"] = team_labels(db, result)
    return result
