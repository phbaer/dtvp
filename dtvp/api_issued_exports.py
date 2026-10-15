"""Durably issued consumer bytes; read authorization never implies approval."""

import logging
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import require_state
from dtvp.knowledge.issued_exports import issue_export, resolve_issued_export
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha
from dtvp.knowledge.projection import catch_up

router = APIRouter(prefix="/api/v3")
logger = logging.getLogger(__name__)


def describe_issuance(issued):
    root = f"/api/v3/projects/{quote(issued['project_id'], safe='')}/issued-exports/{issued['receipt_sha256']}"
    return {key: value for key, value in issued.items() if key not in {"payload", "files"}} | {
        "files": {
            name: {**file, "url": root + "/files/" + quote(name, safe="")}
            for name, file in issued["files"].items()
        },
    }


def project_issuance(request, issued):
    try:
        catch_up(request.app.state.engine, request.app.state.knowledge)
        projection = "current"
    except Exception:
        logger.exception("Issued export awaits SQL projection recovery")
        projection = "pending"
    return {**describe_issuance(issued), "projection": projection}


@router.post("/projects/{project_id}/states/{state}/exports/bundle", status_code=201)
def issue_bundle(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    try:
        issued = issue_export(
            journal,
            project_id=project_id,
            actor_id=actor.user.id,
            state=state,
            kind="knowledge-bundle",
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        raise HTTPException(
            503, "Export issuance uncertain; retry the identical pinned request"
        ) from error
    return project_issuance(request, issued)


def issued_for(request, db, actor, project_id, receipt):
    project_for(db, actor, project_id)
    issued = resolve_issued_export(request.app.state.knowledge, project_id, receipt)
    if issued is None:
        raise HTTPException(404, "Issued export unavailable")
    return issued


@router.get("/projects/{project_id}/issued-exports/{receipt}")
def issuance(project_id: str, receipt: Sha, request: Request, db: DB, actor: Auth):
    return describe_issuance(issued_for(request, db, actor, project_id, receipt))


@router.get("/projects/{project_id}/issued-exports/{receipt}/files/{filename}")
def file(project_id: str, receipt: Sha, filename: Name, request: Request, db: DB, actor: Auth):
    issued = issued_for(request, db, actor, project_id, receipt)
    metadata = issued["files"].get(filename)
    if metadata is None:
        raise HTTPException(404, "Issued file unavailable")
    return Response(
        request.app.state.knowledge.objects.read(metadata["sha256"]),
        media_type=metadata["media_type"],
        headers={
            "X-Content-SHA256": metadata["sha256"],
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": 'attachment; filename="dtvp-issued-export.json"',
        },
    )
