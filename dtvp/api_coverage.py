"""Read-only, pinned cross-version assessment candidate discovery."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import require_state
from dtvp.knowledge.coverage_candidates import coverage_candidates
from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.version_selection import VersionSelection
from dtvp.schemas import RequestModel

router = APIRouter(prefix=API_PREFIX)


class CoverageCandidatesInput(RequestModel):
    source: Sha
    context_id: Sha
    vulnerability_id: Name
    expected_preview: Sha | None = None
    version_selection: VersionSelection | None = None


def capabilities(db, actor, project, context):
    if not context or context.get("status") != "resolved" or not context.get("team_id"):
        return []
    return [
        capability
        for capability in ("assess", "approve")
        if actor.workspace(context["team_id"], capability)
        and actor.allowed(db, project, capability)
    ]


@router.post("/projects/{project_id}/coverage/candidates")
def candidates(
    project_id: str,
    data: CoverageCandidatesInput,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, data.source, project_id)
    result = coverage_candidates(
        journal,
        project_id,
        data.source,
        data.context_id,
        data.vulnerability_id,
        offset,
        limit,
        version_selection=data.version_selection,
    )
    if data.expected_preview is not None and data.expected_preview != result["preview_digest"]:
        raise HTTPException(409, "Coverage candidate heads changed; refresh the complete preview")
    result["source"]["capabilities"] = capabilities(db, actor, project, result["source"]["context"])
    for row in result["items"]:
        row["capabilities"] = capabilities(db, actor, project, row["context"])
    return result
