"""Explicit returned Agentyzer evidence intake and pinned report retrieval."""

from fastapi import APIRouter, HTTPException, Request, Response

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.agentyzer_results import FORMAT, AgentyzerResultInput, import_agentyzer_result
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha

router = APIRouter(prefix="/api/v3")


@router.post("/projects/{project_id}/versions/{version}/proposals/agentyzer", status_code=201)
def agentyzer_result(
    project_id: str,
    version: Name,
    data: AgentyzerResultInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    project_for(db, actor, project_id, "evidence")
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, data.input_receipt.state, project_id)
    try:
        receipt = import_agentyzer_result(
            journal,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.get("/projects/{project_id}/states/{state}/proposals/agentyzer/{result_id}/report")
def original_report(
    project_id: str, state: Sha, result_id: Sha, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    revision = require_state(journal, state, project_id)
    record_sha = journal.records(state, "history").get("code-analysis:" + result_id)
    if not record_sha:
        raise HTTPException(404, "Code-analysis report unavailable in this state")
    record = journal.load(record_sha)
    if record.get("format") != FORMAT or record.get("report_sha256") not in revision.artifacts:
        raise HTTPException(404, "Code-analysis report unavailable in this state")
    return Response(
        journal.objects.read(record["report_sha256"]),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="agentyzer-report.json"',
            "X-Content-SHA256": record["report_sha256"],
            "X-DTVP-Representation": "canonical_json",
        },
    )
