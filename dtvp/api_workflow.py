"""Presentation adapters for shared journal-backed assessment workflows."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, require_state, uncertain_response
from dtvp.knowledge.assessments import AssessmentInput, ReviewInput, create_review, save_assessment
from dtvp.knowledge.exports import build_vscorer_worklist, export_bytes
from dtvp.knowledge.filters import EvidenceFilter, KnowledgeFilters
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Ref, Sha
from dtvp.knowledge.license_filters import LicenseFilters
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.scoring import (
    ScoreInput,
    ScorePublication,
    prepare_score,
    publish_score,
    published_score,
)
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.models import Workspace

router = APIRouter(prefix=API_PREFIX)


@router.get("/ssvc/models")
def ssvc_models(actor: Auth):
    from dtvp.knowledge.ssvc import models

    return {"models": list(models())}


@router.get("/projects/{project_id}/states/{state}/bundle")
def consumer_bundle(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    raw, manifest = export_bytes(journal, state)
    return Response(
        raw,
        media_type="application/json",
        headers={
            "X-Content-SHA256": manifest["bundle_sha256"],
            "Content-Disposition": 'attachment; filename="dtvp-knowledge-bundle.json"',
        },
    )


@router.get("/projects/{project_id}/states/{state}/manifest")
def consumer_manifest(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    return export_bytes(journal, state)[1]


@router.get("/projects/{project_id}/states/{state}/vscorer-worklist")
def vscorer_worklist(project_id: str, state: Sha, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    return build_vscorer_worklist(journal, state)


@router.get("/projects/{project_id}/states/{state}/license-worklist")
def licenses(
    project_id: str,
    state: Sha,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    filters: LicenseFilters = Depends(),
):
    from dtvp.knowledge.comparison import product_state
    from dtvp.knowledge.licenses import license_worklist

    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    require_state(journal, state, project_id)
    product_state(journal, state, project_id)
    result = license_worklist(journal, state, offset, limit, filters=filters)
    project = project_for(db, actor, project_id)
    result["capabilities"] = [
        cap for cap in ("license_assess", "license_approve") if actor.allowed(db, project, cap)
    ]
    return result


def authorize_team(db, actor, project_id):
    def authorize(team_id, capability):
        project_for(db, actor, project_id, capability)
        if not actor.workspace(team_id, capability):
            raise HTTPException(403, "This action requires the responsible team's role")

    return authorize


def state_for(request, project_id, version, expected=None):
    journal = request.app.state.knowledge
    state = journal.resolve(Ref(project_id=project_id, name=version))
    if not state:
        raise HTTPException(404, "Version has no accepted baseline")
    if expected and expected != state:
        raise HTTPException(409, "Workspace changed; refresh before continuing")
    return state


def team_labels(db, statistics):
    """Current display names only for teams in this authorized, complete selection."""
    identifiers = set(statistics.get("by_team", {}))
    if not identifiers:
        return {}
    return dict(
        db.execute(
            select(Workspace.id, Workspace.name)
            .where(Workspace.id.in_(identifiers))
            .order_by(Workspace.id)
        ).all()
    )


def with_capabilities(db, actor, project, row):
    context = row["context"]
    team = context.get("team_id")
    row["capabilities"] = [
        cap
        for cap in ("assess", "approve")
        if team
        and context["status"] == "resolved"
        and actor.workspace(team, cap)
        and actor.allowed(db, project, cap)
    ]
    if actor.allowed(db, project, "rescore"):
        row["capabilities"].append("rescore")
    return row


@router.get("/projects/{project_id}/versions")
def versions(
    project_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    selected = sorted(
        product_heads(request.app.state.knowledge.references(), project_id).items(), reverse=True
    )
    selected = [
        (version, state) for version, state in selected if q.casefold() in version.casefold()
    ]
    return {
        "items": [
            {"version": version, "state": state}
            for version, state in selected[offset : offset + limit]
        ],
        "next_offset": offset + limit if len(selected) > offset + limit else None,
    }


@router.get("/projects/{project_id}/versions/{version}/workspace")
def workspace(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    team_id: Name | None = None,
    q: str = Query("", max_length=500),
    lifecycle: str = Query("", max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    expected: Sha | None = None,
    source_severity: str = "",
    contextual_severity: str = "",
    applicability: str = "",
    scoring_status: str = "",
    team_review: str = "",
    provider: str = "",
    cvss_version: str = "",
    dependency: str = "",
    source_conflict: str = "",
    component: str = "",
    criticality: str = "",
    exposure: str = "",
    support_status: str = "",
    metadata_status: str = "",
    agentyzer_evidence: EvidenceFilter = "",
    vscorer_evidence: EvidenceFilter = "",
    ssvc_status: str = "",
    ssvc_action: str = "",
):
    project = project_for(db, actor, project_id)
    state = state_for(request, project_id, version, expected)
    try:
        filters = KnowledgeFilters(
            ssvc_status=ssvc_status,
            ssvc_action=ssvc_action,
            source_severity=source_severity,
            contextual_severity=contextual_severity,
            applicability=applicability,
            scoring_status=scoring_status,
            team_review=team_review,
            provider=provider,
            cvss_version=cvss_version,
            dependency=dependency,
            source_conflict=source_conflict,
            component=component,
            criticality=criticality,
            exposure=exposure,
            support_status=support_status,
            metadata_status=metadata_status,
            agentyzer_evidence=agentyzer_evidence,
            vscorer_evidence=vscorer_evidence,
        )
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    result = load_workspace(
        request.app.state.knowledge,
        state,
        team_id=team_id,
        q=q,
        lifecycle=lifecycle,
        offset=offset,
        limit=limit,
        filters=filters,
    )
    for row in result["items"]:
        with_capabilities(db, actor, project, row)
    result["team_labels"] = team_labels(db, result["statistics"])
    return result


@router.get(
    "/projects/{project_id}/versions/{version}/workspace/{context_id}/{vulnerability_id:path}"
)
def workspace_detail(
    project_id: str,
    version: Name,
    context_id: Sha,
    vulnerability_id: str,
    request: Request,
    db: DB,
    actor: Auth,
    expected: Sha | None = None,
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    state = state_for(request, project_id, version, expected)
    # The workspace read model is shared by UI, CLI and machine consumers.
    result = load_workspace(
        journal, state, context_id=context_id, vulnerability_id=vulnerability_id, limit=1
    )
    row = next(
        (
            row
            for row in result["items"]
            if row["context_id"] == context_id and row["vulnerability_id"] == vulnerability_id
        ),
        None,
    )
    if not row:
        raise HTTPException(404, "Vulnerability is unavailable in this context")
    row["published_score"] = published_score(
        journal, load_sections(journal, state), version, context_id, vulnerability_id
    )
    return {
        "state": state,
        **with_capabilities(db, actor, project, row),
        "team_labels": team_labels(db, result["statistics"]),
    }


def save(project_id, assessment_id, data, request, db, actor, *, submit):
    project_for(db, actor, project_id, "assess")
    try:
        receipt = save_assessment(
            request.app.state.knowledge,
            project_id=project_id,
            actor_id=actor.user.id,
            assessment_id=assessment_id,
            data=data,
            submit=submit,
            authorize=authorize_team(db, actor, project_id),
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except PermissionError as error:
        raise HTTPException(403, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/assessments/{assessment_id}/draft", status_code=201)
def draft(
    project_id: str,
    assessment_id: Name,
    data: AssessmentInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    return save(project_id, assessment_id, data, request, db, actor, submit=False)


@router.post("/projects/{project_id}/assessments/{assessment_id}/submit", status_code=201)
def submit(
    project_id: str,
    assessment_id: Name,
    data: AssessmentInput,
    request: Request,
    db: DB,
    actor: Auth,
):
    return save(project_id, assessment_id, data, request, db, actor, submit=True)


@router.post("/projects/{project_id}/reviews", status_code=201)
def review(project_id: str, data: ReviewInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "approve")
    try:
        receipt = create_review(
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


@router.post("/projects/{project_id}/scoring/preview")
def score_preview(project_id: str, data: ScoreInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "rescore")
    try:
        preview, _, _ = prepare_score(request.app.state.knowledge, project_id=project_id, data=data)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    return preview


@router.post("/projects/{project_id}/scoring/publish", status_code=201)
def score_publish(project_id: str, data: ScorePublication, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "rescore")
    try:
        receipt = publish_score(
            request.app.state.knowledge, project_id=project_id, actor_id=actor.user.id, data=data
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
