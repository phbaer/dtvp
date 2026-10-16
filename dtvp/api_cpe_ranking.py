"""Explicit supplied-catalog ranking; no network acquisition or publication."""

import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field, ValidationError

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.cpe import current_discovery_policy
from dtvp.knowledge.cpe_ranking import DictionaryRecord, rank_candidates
from dtvp.knowledge.journal import Sha
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")
MAX_BODY = 2 * 1024 * 1024


class RankingInput(RequestModel):
    component_ref: str = Field(min_length=1, max_length=4096)
    records: list[DictionaryRecord] = Field(max_length=2000)
    policy: Sha | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=200)


@router.post("/projects/{project_id}/states/{state}/cpe/rank")
async def rank(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    # Stream-bound BEFORE JSON decoding; Content-Length alone is not trusted.
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_BODY:
            raise HTTPException(413, "CPE ranking body exceeds 2 MiB")
        raw.extend(chunk)
    try:
        data = RankingInput.model_validate(json.loads(raw))
    except (ValueError, RecursionError, ValidationError) as error:
        raise HTTPException(422, "Invalid bounded CPE ranking input") from error
    journal = request.app.state.knowledge
    if state not in reachable_states(journal, project_id):
        raise HTTPException(404, "Committed product inventory state unavailable")
    component = None
    for key, value in journal.records(state, "inventory").items():
        if key == "root" or key.startswith(("component:", "part-root:")):
            item = journal.load(value)
            if item.get("bom-ref") == data.component_ref:
                component = item
                break
    if component is None:
        raise HTTPException(404, "Component unavailable in this state")
    policy, config = current_discovery_policy(journal, project_id)
    if data.policy is not None:
        # Only retained states of this project's CPE policy, never arbitrary objects.
        selected, seen = policy, set()
        while selected and selected not in seen and selected != data.policy:
            seen.add(selected)
            parents = journal.state(selected).parents
            selected = parents[0] if parents else None
        if selected != data.policy:
            raise HTTPException(404, "CPE policy unavailable in this product line")
        policy = selected
        config = journal.load(journal.records(policy, "inventory")["cpe:configuration"])
    try:
        result = rank_candidates(
            component,
            [item.model_dump() for item in data.records],
            config["catalog"],
            config["rules"],
            offset=data.offset,
            limit=data.limit,
        )
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    return {
        "inventory_state": state,
        "policy_state": policy,
        "policy_selection": "explicit_retained" if data.policy else "current_configuration",
        "committed": False,
        "report": result,
    }
