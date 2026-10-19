"""Explicit license dispositions and independently pinned organizational review."""

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name
from dtvp.knowledge.license_reviews import (
    LicenseInput,
    LicenseReviewInput,
    review_license,
    save_license,
)

router = APIRouter(prefix=API_PREFIX)


def operation(project_id, version, data, request, db, actor, action):
    capability = "license_approve" if action == "review" else "license_assess"
    project_for(db, actor, project_id, capability)

    def authorize(required):
        project_for(db, actor, project_id, required)

    try:
        kwargs = dict(
            journal=request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
            authorize=authorize,
        )
        receipt = (
            review_license(**kwargs)
            if action == "review"
            else save_license(**kwargs, submit=action == "submit")
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/versions/{version}/licenses/draft", status_code=201)
def draft(
    project_id: str, version: Name, data: LicenseInput, request: Request, db: DB, actor: Auth
):
    return operation(project_id, version, data, request, db, actor, "draft")


@router.post("/projects/{project_id}/versions/{version}/licenses/submit", status_code=201)
def submit(
    project_id: str, version: Name, data: LicenseInput, request: Request, db: DB, actor: Auth
):
    return operation(project_id, version, data, request, db, actor, "submit")


@router.post("/projects/{project_id}/versions/{version}/licenses/reviews", status_code=201)
def review(
    project_id: str, version: Name, data: LicenseReviewInput, request: Request, db: DB, actor: Auth
):
    return operation(project_id, version, data, request, db, actor, "review")
