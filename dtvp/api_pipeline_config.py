"""Current authority guards immutable user/CI pipeline metadata."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Sha
from dtvp.knowledge.pipeline_config import (
    PipelineConfigInput,
    configure,
    current_config,
    current_heads,
    resolve_context,
    retained_config,
)

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/pipeline-config")
def read(project_id: str, request: Request, db: DB, actor: Auth, configuration: Sha | None = None):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    if configuration:
        state, config = configuration, retained_config(journal, project_id, configuration)
    else:
        state, config = current_config(journal, project_id)
    return {
        "configuration_state": state,
        "expected_versions": current_heads(journal, project_id),
        "configuration": config,
        "capabilities": ["configure"] if actor.allowed(db, project, "manage") else [],
        "assurance": "user_or_ci_declared",
    }


@router.put("/projects/{project_id}/pipeline-config", status_code=201)
def write(project_id: str, data: PipelineConfigInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    try:
        receipt = configure(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/states/{state}/pipeline-context")
def context(
    project_id: str,
    state: Sha,
    configuration: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return resolve_context(
        request.app.state.knowledge,
        project_id=project_id,
        state=state,
        configuration=configuration,
        offset=offset,
        limit=limit,
    )
