"""Authorized immutable advisory comparison; no evidence application or provider calls."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.intelligence_comparison import IntelligenceInput, compare_intelligence
from dtvp.knowledge.journal import Conflict

router = APIRouter(prefix=API_PREFIX)


@router.post("/projects/{project_id}/compare/intelligence")
def compare(
    project_id: str,
    data: IntelligenceInput,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    try:
        return compare_intelligence(
            request.app.state.knowledge, project_id, data, offset=offset, limit=limit
        )
    except KeyError as error:
        raise HTTPException(404, "Selected input unavailable in this product line") from error
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
