"""Read-only assessment synchronization diagnostics; no merge or approval action."""

from fastapi import APIRouter, Query, Request
from pydantic import Field

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.journal import Sha
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.schemas import RequestModel

router = APIRouter(prefix="/api/v3")


class SynchronizationInput(RequestModel):
    source: Sha
    target: Sha
    basis: Sha | None = None
    context_mapping: dict[Sha, Sha] = Field(default_factory=dict, max_length=1000)


@router.post("/projects/{project_id}/synchronization/preview")
def preview(
    project_id: str,
    data: SynchronizationInput,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    return synchronization_preview(
        request.app.state.knowledge,
        project_id,
        data.source,
        data.target,
        data.basis,
        data.context_mapping,
        offset,
        limit,
    )
