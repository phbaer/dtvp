"""Controlled artifact registration and independent exact-revision review."""

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.documents import (
    MAX_BYTES,
    DocumentInput,
    DocumentReviewInput,
    list_documents,
    register_document,
    review_document,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha

router = APIRouter(prefix=API_PREFIX)


def authorize(db, actor, project_id):
    return lambda capability: project_for(db, actor, project_id, capability)


def register(project_id, version, metadata, file, request, db, actor, *, submit):
    project_for(db, actor, project_id, "documentary_assess")
    data = DocumentInput.model_validate_json(metadata)
    raw = file.file.read(MAX_BYTES + 1)
    try:
        receipt = register_document(
            request.app.state.knowledge,
            project_id,
            version,
            actor.user.id,
            data,
            raw,
            submit=submit,
            authorize=authorize(db, actor, project_id),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/versions/{version}/documents/draft", status_code=201)
def draft(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    metadata: str = Form(max_length=2 * 1024 * 1024),
    file: UploadFile = File(),
):
    return register(project_id, version, metadata, file, request, db, actor, submit=False)


@router.post("/projects/{project_id}/versions/{version}/documents/submit", status_code=201)
def submit(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    metadata: str = Form(max_length=2 * 1024 * 1024),
    file: UploadFile = File(),
):
    return register(project_id, version, metadata, file, request, db, actor, submit=True)


@router.post("/projects/{project_id}/versions/{version}/documents/reviews", status_code=201)
def review(
    project_id: str, version: Name, data: DocumentReviewInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "documentary_approve")
    try:
        receipt = review_document(
            request.app.state.knowledge,
            project_id,
            version,
            actor.user.id,
            data,
            authorize=authorize(db, actor, project_id),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/states/{state}/documents")
def documents(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    result = list_documents(journal, state, offset, limit)
    caps = [
        cap
        for cap in ("documentary_assess", "documentary_approve")
        if actor.allowed(db, project, cap)
    ]
    for row in result["items"]:
        record = row["document"]
        author = record["payload"]["actor_id"] == actor.user.id
        row["capabilities"] = []
        if "documentary_assess" in caps and author:
            row["capabilities"].append("revise")
        if (
            "documentary_approve" in caps
            and not author
            and record["stage"] == "submitted"
            and row["status"] != "out_of_scope"
        ):
            row["capabilities"].append("review")
    return {**result, "state": state, "capabilities": caps}
