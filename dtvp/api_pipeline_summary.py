"""Authorized pinned pipeline evidence counts; never an automatic release verdict."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.journal import Sha
from dtvp.knowledge.pipeline_summary import pipeline_summary

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/states/{state}/evidence-summary")
def summary(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    if state not in reachable_states(journal, project_id):
        raise HTTPException(404, "Committed product state unavailable in this product line")
    return pipeline_summary(journal, state)
