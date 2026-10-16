"""Authorized observation intake and explicit pinned graph selection."""

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Ref
from dtvp.knowledge.observations import (
    ObservationInput,
    ObservationMetadata,
    ObservationSelection,
    build_selection,
    import_observation,
    publish_selection,
)
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v3")


def _import(project_id, version, data, request, db, actor, raw=None):
    project_for(db, actor, project_id, "write")
    try:
        receipt = import_observation(
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            source=data.source,
            actor_id=actor.user.id,
            data=data,
            raw=raw,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)


@router.post("/projects/{project_id}/versions/{version}/observation-imports", status_code=201)
def import_json(
    project_id: str, version: Name, data: ObservationInput, request: Request, db: DB, actor: Auth
):
    return _import(project_id, version, data, request, db, actor)


@router.post("/projects/{project_id}/versions/{version}/observation-files", status_code=201)
def import_file(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    file: UploadFile = File(),
    metadata: str = Form(max_length=65536),
):
    project_for(db, actor, project_id, "write")
    data = ObservationMetadata.model_validate_json(metadata)
    raw = file.file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(413, "Observation file exceeds upload limit")
    return _import(project_id, version, data, request, db, actor, raw)


@router.get("/projects/{project_id}/versions/{version}/observation-sources")
def sources(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    rows = []
    metadata_bytes = 0
    source_count = 0
    for key, state in journal.references().items():
        ref = Ref.model_validate_json(key)
        if (
            ref.project_id != project_id
            or ref.kind != "source"
            or not ref.name.startswith("observation:")
        ):
            continue
        source_count += 1
        if source_count > 2000:
            raise HTTPException(422, "Observation source listing exceeds 2,000 retained bindings")
        pointer = journal.records(state, "history")["observation-import"]
        metadata_bytes += journal.objects.path(pointer).stat().st_size
        if metadata_bytes > 16 * 1024 * 1024:
            raise HTTPException(422, "Observation source metadata exceeds 16 MiB")
        metadata = journal.load(pointer)
        if metadata["version"] == version:
            rows.append({**metadata, "state": state})
    rows.sort(key=lambda item: (item["part_id"] or "", item["source"]))
    listing_digest = digest(canonical(rows))
    page = rows[offset : offset + limit]
    for item in page:
        pointer = journal.records(item["state"], "inventory")["baseline"]
        metadata_bytes += journal.objects.path(pointer).stat().st_size
        if metadata_bytes > 16 * 1024 * 1024:
            raise HTTPException(422, "Observation source page exceeds 16 MiB")
        item["baseline"] = journal.load(pointer)
    return {
        "items": page,
        "total": len(rows),
        "digest": listing_digest,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit if offset + limit < len(rows) else None,
        "head": journal.resolve(Ref(project_id=project_id, name=version)),
        "capabilities": ["write"] if actor.allowed(db, project, "write") else [],
    }


@router.get("/projects/{project_id}/versions/{version}/observation-selection")
def selection(project_id: str, version: Name, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    state = journal.resolve(Ref(project_id=project_id, name=version))
    if state is None:
        raise HTTPException(404, "Product version has no accepted inventory")
    return {
        "state": state,
        "selection": load_sections(journal, state)["inventory"].get("observations"),
    }


@router.post("/projects/{project_id}/versions/{version}/observation-selection/preview")
def preview(
    project_id: str,
    version: Name,
    data: ObservationSelection,
    request: Request,
    db: DB,
    actor: Auth,
):
    project_for(db, actor, project_id, "write")
    try:
        result = build_selection(
            request.app.state.knowledge, project_id=project_id, version=version, data=data
        )["preview"]
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    # Full canonical report determines the digest; presentation is bounded.
    result = dict(result)
    result["reports"] = [
        {
            **item,
            "report": {
                key: value[:20] if isinstance(value, list) else value
                for key, value in item["report"].items()
            },
            "bounded_sample": True,
        }
        for item in result["reports"]
    ]
    return result


@router.post("/projects/{project_id}/versions/{version}/observation-selection", status_code=201)
def apply(
    project_id: str,
    version: Name,
    data: ObservationSelection,
    request: Request,
    db: DB,
    actor: Auth,
):
    project_for(db, actor, project_id, "write")
    try:
        receipt = publish_selection(
            request.app.state.knowledge,
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
