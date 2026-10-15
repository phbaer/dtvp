"""Pinned synchronization diagnostics and explicit draft-only content extension."""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import Field

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.api_workflow import authorize_team
from dtvp.knowledge.assessments import load_sections
from dtvp.knowledge.journal import CommitUncertain, Conflict, Ref, Sha
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.knowledge.synchronization_apply import SynchronizationApplyInput, apply_synchronization
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
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    result = synchronization_preview(
        journal,
        project_id,
        data.source,
        data.target,
        data.basis,
        data.context_mapping,
        offset,
        limit,
    )
    heads_current = (
        result["source_version"] != result["target_version"]
        and journal.resolve(Ref(project_id=project_id, name=result["source_version"]))
        == data.source
        and journal.resolve(Ref(project_id=project_id, name=result["target_version"]))
        == data.target
    )
    target_contexts = load_sections(journal, data.target)["ownership"]
    for row in result["items"]:
        source_record = (row.get("source") or {}).get("assessment") or {}
        target = row.get("target") or {}
        context = target_contexts.get("context:" + row.get("target_context_id", ""), {})
        row["draft_allowed"] = bool(
            heads_current
            and row["category"] in {"reusable_content", "needs_review"}
            and target.get("status") == "unassessed"
            and not target.get("assessment")
            and source_record.get("payload", {}).get("author_id") == actor.user.id
            and context.get("status") == "resolved"
            and context.get("team_id")
            and actor.workspace(context["team_id"], "assess")
            and actor.allowed(db, project, "assess")
        )
    result["drafts_supported"] = True
    return result


@router.post("/projects/{project_id}/synchronization/drafts", status_code=201)
def draft(project_id: str, data: SynchronizationApplyInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "assess")
    try:
        receipt = apply_synchronization(
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            data=data,
            authorize=authorize_team(db, actor, project_id),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
