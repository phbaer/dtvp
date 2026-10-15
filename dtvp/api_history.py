"""Authorized historical read models; no live-state or projection mutations."""

from fastapi import APIRouter, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.comparison import compare_states, list_product_history, list_product_refs
from dtvp.knowledge.journal import Name, Sha

router = APIRouter(prefix="/api/v3")


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
