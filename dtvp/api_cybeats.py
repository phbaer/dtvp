"""Version-bound CyBeats read captures and explicit supplied-export publication."""

import httpx
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import Field, field_validator
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from dtvp.api import DB, Auth, project_for
from dtvp.api_knowledge import InventoryMetadata, projected_response, uncertain_response
from dtvp.auth import authenticate
from dtvp.domain import audit
from dtvp.knowledge.cybeats import (
    FORMAT,
    LIMITATIONS,
    collect,
    connection,
    identifier,
    reject_credential_echo,
    validate_capture,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Sha
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.knowledge.service import import_inventory
from dtvp.models import Project
from dtvp.schemas import RequestModel
from dtvp.storage import digest

router = APIRouter(prefix="/api/v3")
MAX_CAPTURE = 12 * 1024 * 1024


class BindingInput(RequestModel):
    import_id: str
    expected_import_id: str | None

    @field_validator("import_id", "expected_import_id")
    @classmethod
    def valid_id(cls, value):
        return None if value is None else identifier(value)


class CaptureInput(RequestModel):
    expected_import_id: str

    @field_validator("expected_import_id")
    @classmethod
    def valid_id(cls, value):
        return identifier(value)


class ImportMetadata(InventoryMetadata):
    expected_import_id: str
    capture_sha256: Sha
    acknowledge_project_reader_disclosure: bool = Field(strict=True)


def binding(project, version):
    return (
        project.metadata_json.get("connectors", {})
        .get("cybeats", {})
        .get("versions", {})
        .get(version, {})
        .get("import_id")
    )


def require_binding(project, version, expected):
    if not expected or binding(project, version) != expected:
        raise HTTPException(409, "CyBeats version binding changed or is not configured")


@router.get("/projects/{project_id}/versions/{version}/connectors/cybeats")
def get_binding(project_id: str, version: Name, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    settings = request.app.state.settings
    return {
        "import_id": binding(project, version),
        "configured": bool(
            "cybeats" in settings.providers_enabled
            and settings.cybeats_url
            and settings.cybeats_access_key
            and settings.cybeats_secret_access_key
        ),
        "limitations": LIMITATIONS,
    }


@router.put("/projects/{project_id}/versions/{version}/connectors/cybeats")
def put_binding(project_id: str, version: Name, data: BindingInput, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    project = db.scalar(
        select(Project)
        .where(Project.id == project_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if binding(project, version) != data.expected_import_id:
        raise HTTPException(409, "CyBeats version binding changed; reload before replacing it")
    metadata = project.metadata_json
    connectors = metadata.get("connectors", {})
    config = connectors.get("cybeats", {})
    versions = config.get("versions", {})
    value = {"import_id": data.import_id}
    project.metadata_json = {
        **metadata,
        "connectors": {
            **connectors,
            "cybeats": {**config, "versions": {**versions, version: value}},
        },
    }
    audit(
        db,
        actor.user.id,
        "connector.bind",
        project_id,
        project_id,
        {"provider": "cybeats", "version": version, **value},
    )
    return value


@router.post("/projects/{project_id}/versions/{version}/sources/cybeats/capture")
async def capture(
    project_id: str, version: Name, data: CaptureInput, request: Request, db: DB, actor: Auth
):
    project = project_for(db, actor, project_id, "manage")
    require_binding(project, version, data.expected_import_id)
    settings = request.app.state.settings
    connection(settings)

    def reauthorize():
        # This callback runs on the request thread before/after network operations;
        # do not share this Session with the worker-thread HTTP client.
        db.rollback()
        db.expire_all()
        current = authenticate(request, db)
        current_project = project_for(db, current, project_id, "manage")
        require_binding(current_project, version, data.expected_import_id)
        connection(settings)
        return current

    def before_request():
        with request.app.state.sessions() as fresh_db:
            fresh_actor = authenticate(request, fresh_db)
            current_project = project_for(fresh_db, fresh_actor, project_id, "manage")
            require_binding(current_project, version, data.expected_import_id)
            connection(settings)

    reauthorize()
    try:
        result = await run_in_threadpool(
            collect, settings, data.expected_import_id, before_request=before_request
        )
    except httpx.HTTPError:
        raise HTTPException(502, "CyBeats read capture failed; no baseline was changed") from None
    reauthorize()
    return {"committed": False, "capture": result, "limitations": LIMITATIONS}


@router.post("/projects/{project_id}/versions/{version}/sources/cybeats/import", status_code=201)
def apply(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    metadata: str = Form(max_length=8192),
    file: UploadFile = File(),
    capture_file: UploadFile = File(),
):
    project = project_for(db, actor, project_id, "manage")
    project_for(db, actor, project_id, "write")
    project = db.scalar(
        select(Project)
        .where(Project.id == project_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    try:
        data = ImportMetadata.model_validate(strict_json(metadata.encode()))
    except ValueError, RecursionError:
        raise HTTPException(422, "Invalid CyBeats publication metadata") from None
    if data.source != "cybeats" or data.acknowledge_project_reader_disclosure is not True:
        raise HTTPException(
            422, "Use source cybeats and explicitly acknowledge raw capture disclosure"
        )
    raw_capture = capture_file.file.read(MAX_CAPTURE + 1)
    raw = file.file.read(min(16 * 1024 * 1024, request.app.state.settings.max_upload_bytes) + 1)
    if len(raw_capture) > MAX_CAPTURE or len(raw) > min(
        16 * 1024 * 1024, request.app.state.settings.max_upload_bytes
    ):
        raise HTTPException(413, "CyBeats capture or supplied SBOM exceeds publication limits")
    if digest(raw_capture) != data.capture_sha256:
        raise HTTPException(422, "CyBeats capture differs from its exact byte hash")
    try:
        value = strict_json(raw_capture)
        if not isinstance(value, dict):
            raise ValueError("CyBeats capture must be an object")
        originals = validate_capture(
            value, endpoint=value.get("endpoint"), import_id=data.expected_import_id
        )
        reject_credential_echo(request.app.state.settings, [raw_capture, *originals])
    except ValueError, RecursionError:
        raise HTTPException(
            422, "CyBeats capture is invalid or differs from the selected source"
        ) from None

    def authorize_new():
        require_binding(project, version, data.expected_import_id)
        if connection(request.app.state.settings) != value["endpoint"]:
            raise HTTPException(409, "CyBeats endpoint differs from the retained capture")

    journal = request.app.state.knowledge
    artifacts = [journal.objects.put(content) for content in [raw_capture, *originals]]
    # The original export remains authoritative for composition; report data is
    # retained without inventing dependency links or component-specific findings.
    try:
        receipt = import_inventory(
            journal,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            **data.model_dump(
                exclude={
                    "completeness",
                    "expected_import_id",
                    "capture_sha256",
                    "acknowledge_project_reader_disclosure",
                }
            ),
            raw=raw,
            source_provenance={
                "provider": "cybeats",
                "import_id": data.expected_import_id,
                "capture_format": FORMAT,
                "capture_sha256": data.capture_sha256,
                "capture_verification": "operator_supplied_unverified",
                "composition_binding": "operator_declared_supplied_export",
            },
            additional_artifacts=artifacts,
            authorize_new=authorize_new,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from None
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
