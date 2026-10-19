"""Authorized pinned occurrence catalogs for explicit human correspondence."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import require_state
from dtvp.knowledge.journal import Sha
from dtvp.knowledge.reconciliation_catalog import occurrence_catalog

router = APIRouter(prefix=API_PREFIX)


@router.get("/projects/{project_id}/states/{state}/reconciliation-candidates")
def candidates(
    project_id: str,
    state: Sha,
    kind: Literal["component", "context"],
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    try:
        return occurrence_catalog(journal, project_id, state, kind, q, offset, limit)
    except ValueError as error:
        raise HTTPException(
            404, "Occurrence selectors require committed product inventory"
        ) from error
