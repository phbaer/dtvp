"""Current-authority configuration of optional known-ID advisory scheduling."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.advisory_schedule import MIN_INTERVAL, AdvisoryScheduleInput, configure, policy
from dtvp.knowledge.journal import CommitUncertain, Conflict

router = APIRouter(prefix=API_PREFIX)


@router.get("/projects/{project_id}/advisory-schedule")
def get_schedule(project_id: str, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    state, config = policy(request.app.state.knowledge, project_id)
    return {
        "state": state,
        "providers": config["providers"],
        "actor_id": config.get("actor_id"),
        "capabilities": ["configure"]
        if actor.allowed(db, project, "manage") and actor.allowed(db, project, "evidence")
        else [],
        "provider_minimum_seconds": MIN_INTERVAL,
        "limitations": [
            "Only configured versions provide known exact identifiers; each batch pins all current product heads and product-wide evidence selection.",
            "At most one queued/running/pending-publication refresh per product/provider; overdue intermediate cycles are coalesced.",
            "Each interval collects at most the configured batch size, rotating known identifiers; this is not an all-identifiers-per-interval guarantee.",
            "Credential expiry, provider disablement or lost management/evidence permission stops new work; configure again to reauthorize.",
            "Provider catalogs are product-scoped; no package matching, human approval or score adoption is performed.",
        ],
    }


@router.put("/projects/{project_id}/advisory-schedule")
def put_schedule(
    project_id: str, data: AdvisoryScheduleInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "manage")
    project_for(db, actor, project_id, "evidence")
    try:
        receipt = configure(
            request.app.state.knowledge,
            request.app.state.settings,
            project_id=project_id,
            actor=actor,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
