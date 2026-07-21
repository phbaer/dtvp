import asyncio
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Callable, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from .authorization import require_reviewer
from .dt_client import DTClient
from .project_archive_services import (
    ARCHIVE_FILE_SUFFIX,
    ProjectArchiveChecksumError,
    ProjectArchiveError,
    ProjectArchiveServiceDeps,
    ProjectArchiveValidationError,
    ProjectArchiveVersionError,
    apply_project_archive,
    export_project_archive,
    list_project_archives,
    preview_project_archive,
    resolve_archive_download_path,
    store_uploaded_archive,
)


class ProjectArchiveExportRequest(BaseModel):
    project_name: str = Field(min_length=1)
    versions: list[str] | None = None
    refresh: bool = True


class ProjectArchiveApplyRequest(BaseModel):
    mode: Literal["create_missing", "update"] = "create_missing"


@dataclass(frozen=True)
class ProjectArchiveRouteDeps:
    archive_tasks: dict[str, dict[str, Any]]
    service_deps: ProjectArchiveServiceDeps
    logger: Any
    get_user_role: Callable[[str], str]
    dt_settings_cls: Callable[[], Any]
    get_dt_client_cls: Callable[[], type[DTClient]]
    create_tracked_task: Callable[[Any], Any]
    archive_path_provider: Callable[[], str]


def _now() -> datetime:
    return datetime.now(UTC)


def _require_reviewer(
    deps: ProjectArchiveRouteDeps,
    user: str,
    detail: str = "Only reviewers can manage project archives",
) -> None:
    require_reviewer(deps.get_user_role(user), detail)


def _task_public(task: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in task.items()
        if not key.startswith("_")
    }


def _create_task(
    deps: ProjectArchiveRouteDeps,
    *,
    kind: str,
    message: str,
    user: str,
) -> dict[str, Any]:
    task_id = str(uuid.uuid4())
    now = _now()
    task = {
        "id": task_id,
        "_owner": user,
        "kind": kind,
        "status": "pending",
        "message": message,
        "progress": 0,
        "created_at": now,
        "updated_at": now,
        "result": None,
        "log": [message],
    }
    deps.archive_tasks[task_id] = task
    return task


def _task_for_user(
    deps: ProjectArchiveRouteDeps,
    task_id: str,
    user: str,
) -> dict[str, Any] | None:
    task = deps.archive_tasks.get(task_id)
    if not isinstance(task, dict) or task.get("_owner") != user:
        return None
    return task


def _update_task(
    task: dict[str, Any],
    *,
    status: str | None = None,
    message: str | None = None,
    progress: int | None = None,
    result: Any = None,
    error: str | None = None,
) -> None:
    if status is not None:
        task["status"] = status
    if message is not None:
        task["message"] = message
        task.setdefault("log", []).append(message)
    if progress is not None:
        task["progress"] = progress
    if result is not None:
        task["result"] = result
    if error is not None:
        task["error"] = error
    task["updated_at"] = _now()


def _archive_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ProjectArchiveVersionError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ProjectArchiveChecksumError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ProjectArchiveValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


def _client_context_from_request(
    deps: ProjectArchiveRouteDeps,
    request: Request,
) -> tuple[Any, str | None, dict[str, str]]:
    settings = deps.dt_settings_cls()
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
    return settings, token, dict(request.cookies)


def _register_task_routes(
    router: APIRouter,
    deps: ProjectArchiveRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/project-archives/tasks/{task_id}")
    async def get_archive_task(task_id: str, user: CurrentUser):
        _require_reviewer(deps, user)
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Archive task not found")
        return _task_public(task)

    @router.get("/project-archives/tasks/{task_id}/events")
    async def stream_archive_task_events(task_id: str, user: CurrentUser):
        _require_reviewer(deps, user)

        async def event_stream():
            last_payload = ""
            while True:
                task = _task_for_user(deps, task_id, user)
                if not task:
                    payload = {"status": "not_found"}
                else:
                    payload = _task_public(task)
                text = json.dumps(payload, default=str)
                if text != last_payload:
                    yield text + "\n"
                    last_payload = text
                status = str(payload.get("status") or "").lower()
                if status in {"completed", "failed", "not_found"}:
                    break
                await asyncio.sleep(1)

        return StreamingResponse(
            event_stream(),
            media_type="application/x-ndjson",
        )

    @router.get("/project-archives/tasks/{task_id}/download")
    async def download_archive_task(task_id: str, user: CurrentUser):
        _require_reviewer(deps, user)
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Archive task not found")
        if task.get("status") != "completed" or not task.get("_archive_path"):
            raise HTTPException(status_code=409, detail="Archive is not ready")
        archive_path = task["_archive_path"]
        if not os.path.exists(archive_path):
            raise HTTPException(status_code=404, detail="Archive file not found")
        filename = (task.get("result") or {}).get("filename") or os.path.basename(
            archive_path
        )
        return FileResponse(
            archive_path,
            media_type="application/zip",
            filename=filename,
        )


def _register_export_routes(
    router: APIRouter,
    deps: ProjectArchiveRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.post("/project-archives/exports")
    async def start_project_archive_export(
        req: ProjectArchiveExportRequest,
        request: Request,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user)
        task = _create_task(
            deps,
            kind="export",
            message=f"Queued export for {req.project_name}",
            user=user,
        )
        settings, token, cookies = _client_context_from_request(deps, request)

        async def run_export():
            _update_task(
                task,
                status="running",
                message="Collecting Dependency-Track project data...",
                progress=5,
            )
            try:
                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url,
                    api_key=settings.api_key,
                    token=token or "",
                    cookies=cookies,
                ) as client:
                    result = await export_project_archive(
                        deps.service_deps,
                        client,
                        project_name=req.project_name,
                        versions=req.versions,
                        refresh=req.refresh,
                        created_by=user,
                        reason="manual",
                    )
                task["_archive_path"] = result["archive_path"]
                _update_task(
                    task,
                    status="completed",
                    message="Project archive export completed.",
                    progress=100,
                    result={key: value for key, value in result.items() if key != "manifest"},
                )
            except Exception as exc:
                deps.logger.exception("Project archive export failed")
                _update_task(
                    task,
                    status="failed",
                    message="Project archive export failed.",
                    progress=100,
                    error=str(exc),
                )

        deps.create_tracked_task(run_export())
        return {"task_id": task["id"]}


def _register_import_routes(
    router: APIRouter,
    deps: ProjectArchiveRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.post("/project-archives/imports")
    async def upload_project_archive_import(
        file: Annotated[UploadFile, File(...)],
        request: Request,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user)
        task = _create_task(
            deps,
            kind="import_preview",
            message="Queued project archive import preview.",
            user=user,
        )
        content = await file.read()
        try:
            archive_path = await asyncio.to_thread(
                store_uploaded_archive,
                deps.archive_path_provider(),
                task["id"],
                file.filename or "archive.zip",
                content,
            )
        except ProjectArchiveError as exc:
            raise _archive_http_error(exc) from exc

        task["_archive_path"] = archive_path
        settings, token, cookies = _client_context_from_request(deps, request)

        async def run_preview():
            _update_task(
                task,
                status="running",
                message="Reading project archive...",
                progress=10,
            )
            try:
                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url,
                    api_key=settings.api_key,
                    token=token or "",
                    cookies=cookies,
                ) as client:
                    preview = await preview_project_archive(
                        deps.service_deps,
                        client,
                        archive_path=archive_path,
                    )
                _update_task(
                    task,
                    status="completed",
                    message="Project archive preview is ready.",
                    progress=100,
                    result=preview,
                )
            except Exception as exc:
                deps.logger.exception("Project archive import preview failed")
                _update_task(
                    task,
                    status="failed",
                    message="Project archive import preview failed.",
                    progress=100,
                    error=str(exc),
                )

        deps.create_tracked_task(run_preview())
        return {"task_id": task["id"]}

    @router.post("/project-archives/imports/{task_id}/apply")
    async def apply_project_archive_import(
        task_id: str,
        req: ProjectArchiveApplyRequest,
        request: Request,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user)
        task = _task_for_user(deps, task_id, user)
        if not task:
            raise HTTPException(status_code=404, detail="Archive task not found")
        if task.get("status") == "running":
            raise HTTPException(status_code=409, detail="Archive task is running")
        archive_path = task.get("_archive_path")
        if not archive_path:
            raise HTTPException(status_code=409, detail="No uploaded archive to apply")

        task["_preview_result"] = task.get("result")
        task["kind"] = "import_apply"
        task["result"] = None
        _update_task(
            task,
            status="pending",
            message=f"Queued project archive import apply ({req.mode}).",
            progress=0,
        )
        settings, token, cookies = _client_context_from_request(deps, request)

        async def run_apply():
            _update_task(
                task,
                status="running",
                message="Applying project archive to Dependency-Track...",
                progress=5,
            )
            try:
                client_cls = deps.get_dt_client_cls()
                async with client_cls(
                    settings.api_url,
                    api_key=settings.api_key,
                    token=token or "",
                    cookies=cookies,
                ) as client:
                    result = await apply_project_archive(
                        deps.service_deps,
                        client,
                        archive_path=archive_path,
                        mode=req.mode,
                    )
                _update_task(
                    task,
                    status="completed",
                    message="Project archive import completed.",
                    progress=100,
                    result=result,
                )
            except Exception as exc:
                deps.logger.exception("Project archive import apply failed")
                _update_task(
                    task,
                    status="failed",
                    message="Project archive import failed.",
                    progress=100,
                    error=str(exc),
                )

        deps.create_tracked_task(run_apply())
        return {"task_id": task["id"]}


def _register_snapshot_routes(
    router: APIRouter,
    deps: ProjectArchiveRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/project-archives/snapshots")
    async def list_archive_snapshots(user: CurrentUser):
        _require_reviewer(deps, user)
        return list_project_archives(deps.archive_path_provider())

    @router.get("/project-archives/snapshots/{filename}/download")
    async def download_archive_snapshot(filename: str, user: CurrentUser):
        _require_reviewer(deps, user)
        if not filename.endswith(ARCHIVE_FILE_SUFFIX):
            raise HTTPException(status_code=404, detail="Archive not found")
        try:
            archive_path = resolve_archive_download_path(
                deps.archive_path_provider(),
                filename,
            )
        except ProjectArchiveError as exc:
            raise _archive_http_error(exc) from exc
        return FileResponse(
            archive_path,
            media_type="application/zip",
            filename=filename,
        )


def create_project_archive_router(
    deps: ProjectArchiveRouteDeps,
    *,
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()
    _register_task_routes(router, deps, current_user_dependency)
    _register_export_routes(router, deps, current_user_dependency)
    _register_import_routes(router, deps, current_user_dependency)
    _register_snapshot_routes(router, deps, current_user_dependency)
    return router
