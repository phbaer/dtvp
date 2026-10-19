"""Project-scoped rule policies and explicit coordinator scoring."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.knowledge.rule_scoring import (
    PolicyInput,
    RuleInput,
    RulePublication,
    configure_policy,
    current_policy,
    prepare_rule_score,
    publish_rule_score,
)

router = APIRouter(prefix=API_PREFIX)


@router.get("/projects/{project_id}/scoring-policy")
def get_policy(project_id: str, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    return current_policy(request.app.state.knowledge, project_id)


@router.put("/projects/{project_id}/scoring-policy")
def put_policy(project_id: str, data: PolicyInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    try:
        receipt = configure_policy(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/scoring/rules/preview")
def preview_rules(project_id: str, data: RuleInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "rescore")
    try:
        return prepare_rule_score(request.app.state.knowledge, project_id=project_id, data=data)[0]
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/scoring/rules/publish", status_code=201)
def publish_rules(project_id: str, data: RulePublication, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "rescore")
    try:
        receipt = publish_rule_score(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
