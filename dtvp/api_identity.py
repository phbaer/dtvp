"""Internal offline CPE discovery and explicit context-bound analysis inputs."""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import Field

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.cpe import (
    DiscoveryInput,
    current_discovery_policy,
    import_discovery_policy,
    propose_for_component,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Sha
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/cpe")
def cpe_configuration(project_id: str, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    state, config = current_discovery_policy(request.app.state.knowledge, project_id)
    return {"policy_state": state, "configuration": config}


@router.put("/projects/{project_id}/cpe", status_code=201)
def configure_cpe(project_id: str, data: DiscoveryInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    try:
        receipt = import_discovery_policy(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/states/{state}/cpe")
def candidates(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    component_ref: str = Query(min_length=1, max_length=4096),
    policy: Sha | None = None,
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    inventory = journal.records(state, "inventory")
    component = None
    for key, value in inventory.items():
        if key.startswith("component:") or key == "root":
            data = journal.load(value)
            if data.get("bom-ref") == component_ref:
                component = data
                break
    if component is None:
        raise HTTPException(404, "Component unavailable in this state")
    if policy:
        require_state(journal, policy, project_id)
        rules = journal.records(policy, "inventory")
        if "cpe:configuration" not in rules:
            raise HTTPException(404, "CPE configuration unavailable")
        config = journal.load(rules["cpe:configuration"])
    else:
        policy, config = current_discovery_policy(journal, project_id)
    return {
        "inventory_state": state,
        "policy_state": policy,
        "proposal": propose_for_component(component, config["catalog"], config["rules"]),
    }


class VScorerInput(RequestModel):
    context_id: Sha
    component_ref: str = Field(min_length=1, max_length=4096)
    base_selections: dict[str, str] = Field(default_factory=dict, max_length=1000)


@router.post("/projects/{project_id}/states/{state}/vscorer-input")
def vscorer_inputs(
    project_id: str, state: Sha, data: VScorerInput, request: Request, db: DB, actor: Auth
):
    from dtvp.knowledge.vscorer import derive_context_inputs

    project_for(db, actor, project_id, "snapshot")
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    return derive_context_inputs(
        journal, state, data.context_id, data.component_ref, data.base_selections
    )
