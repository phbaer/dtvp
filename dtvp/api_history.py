"""Authorized historical read models; no live-state or projection mutations."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.comparison import compare_states, list_product_history, list_product_refs
from dtvp.knowledge.journal import Name, Sha

router = APIRouter(prefix=API_PREFIX)


@router.get("/projects/{project_id}/refs")
def references(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return list_product_refs(request.app.state.knowledge, project_id, offset, limit)


@router.get("/projects/{project_id}/history")
def history(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    version: Name | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return list_product_history(request.app.state.knowledge, project_id, version, offset, limit)


@router.get("/projects/{project_id}/compare/details")
def comparison(
    project_id: str,
    before: Sha,
    after: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return compare_states(request.app.state.knowledge, project_id, before, after, offset, limit)


@router.get("/projects/{project_id}/states/{state}/retained-assessments")
def retained(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    absent_only: bool = True,
    team_id: Name | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
):
    from dtvp.api_knowledge import require_state
    from dtvp.knowledge.retained import retained_assessments

    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    return retained_assessments(
        journal, state, absent_only=absent_only, team_id=team_id, offset=offset, limit=limit
    )


@router.get("/projects/{project_id}/maintenance/retention-preview")
def retention(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    expected: Sha | None = None,
):
    from dtvp.knowledge.maintenance import preview_retention

    project_for(db, actor, project_id, "manage")
    result = preview_retention(request.app.state.knowledge, project_id, offset=offset, limit=limit)
    if expected is not None and expected != result["plan_hash"]:
        raise HTTPException(409, "Product references changed; restart retention preview")
    return result
