"""Authorized pinned composition observations, including pre-assembly constituents."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.input_quality import input_quality
from dtvp.knowledge.journal import Ref, Sha

router = APIRouter(prefix=API_PREFIX)


def composition_member(journal, project_id, state):
    pending = []
    for key, sha in journal.references().items():
        ref = Ref.model_validate_json(key)
        if ref.project_id == project_id and ref.kind in {"branch", "tag", "source"}:
            pending.append(sha)
    seen = set()
    while pending:
        sha = pending.pop()
        if sha in seen:
            continue
        seen.add(sha)
        revision = journal.verify_state(sha)
        if revision.project_id != project_id:
            continue
        if sha == state:
            inventory = journal.records(sha, "inventory")
            return "baseline" in inventory
        pending.extend(revision.parents)
    return False


@router.get("/projects/{project_id}/states/{state}/input-quality")
def report(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    code: str = Query("", max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    if not composition_member(journal, project_id, state):
        raise HTTPException(404, "Imported composition unavailable in this product line")
    return input_quality(journal, state, q=q, code=code, offset=offset, limit=limit)
