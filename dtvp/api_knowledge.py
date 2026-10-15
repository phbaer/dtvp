"""Initial v3 inventory contracts; no v2 decisions are implicitly migrated."""

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Ref, Sha
from dtvp.knowledge.projection import catch_up, heads, records
from dtvp.knowledge.service import create_tag, import_inventory, validate_time
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")
logger = logging.getLogger(__name__)


class InventoryInput(RequestModel):
    request_id: Name
    expected: Sha | None
    source: Name
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    completeness: Literal["complete"]
    predecessor: Sha | None = None
    sbom: dict

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)


class TagInput(RequestModel):
    request_id: Name
    name: Name
    state: Sha


def projected_response(request, receipt):
    sha, publication = receipt
    result = {
        "committed": True,
        "publication": sha,
        "sequence": publication.sequence,
        "updates": [item.model_dump() for item in publication.updates],
    }
    try:
        position = catch_up(request.app.state.engine, request.app.state.knowledge)
    except Exception:
        # The authoritative commit succeeded. Retrying the same input/request ID
        # returns its receipt and retries projection, never a second publication.
        logger.exception("Committed knowledge publication %s awaits projection", sha)
        return JSONResponse({**result, "projection": "pending"}, status_code=202)
    return {**result, "projection": "current", "projected_sequence": position["sequence"]}


@router.post("/projects/{project_id}/versions/{version}/imports", status_code=201)
def import_version(
    project_id: str, version: str, data: InventoryInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "write")
    try:
        receipt = import_inventory(
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            **data.model_dump(exclude={"completeness"}),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/tags", status_code=201)
def tag(project_id: str, data: TagInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "snapshot")
    require_state(request.app.state.knowledge, data.state, project_id)
    try:
        receipt = create_tag(
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            **data.model_dump(),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


def uncertain_response(error, request_id):
    logger.exception("Knowledge publication %s requires a retry", error.publication)
    return JSONResponse(
        {
            "committed": None,
            "publication": error.publication,
            "request_id": request_id,
            "status": "uncertain",
            "retry": "Send the same request_id and identical input",
        },
        status_code=503,
    )


def require_state(journal, sha, project_id):
    if not journal.objects.path(sha).is_file():
        raise HTTPException(404, "State unavailable in this product line")
    state = journal.state(sha)
    if state.project_id != project_id:
        raise HTTPException(404, "State unavailable in this product line")
    return state


@router.get("/projects/{project_id}/versions/{version}/inventory")
def current_inventory(
    project_id: str,
    version: str,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    expected: Sha | None = None,
):
    project_for(db, actor, project_id)
    ref = Ref(project_id=project_id, name=version)
    # One transaction snapshot avoids mixing the head with a later projection.
    with request.app.state.engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        head = connection.execute(select(heads).where(heads.c.ref_key == ref.key)).first()
        if not head:
            raise HTTPException(404, "Version has no projected inventory")
        if expected and expected != head.state_sha:
            raise HTTPException(409, "Inventory changed; restart pagination")
        rows = connection.execute(
            select(records.c.record_key, records.c.data)
            .where(
                records.c.ref_key == ref.key,
                records.c.section == "inventory",
                records.c.record_key.startswith("component:", autoescape=True),
            )
            .order_by(records.c.record_key)
            .offset(offset)
            .limit(limit + 1)
        ).all()
        baseline = connection.execute(
            select(records.c.data).where(
                records.c.ref_key == ref.key,
                records.c.section == "inventory",
                records.c.record_key == "baseline",
            )
        ).scalar_one()
        reference_state = request.app.state.knowledge.resolve(ref)
        return {
            "state": head.state_sha,
            "reference_state": reference_state,
            "projection_current": reference_state == head.state_sha,
            "baseline": baseline,
            "items": [{"key": row.record_key, "component": row.data} for row in rows[:limit]],
            "next_offset": offset + limit if len(rows) > limit else None,
        }


@router.get("/projects/{project_id}/compare")
def compare(project_id: str, before: Sha, after: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    # Authorization covers both sides, not merely the URL's project.
    for sha in (before, after):
        require_state(journal, sha, project_id)
    return journal.diff(before, after)
