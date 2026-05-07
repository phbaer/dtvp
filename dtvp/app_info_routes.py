from dataclasses import dataclass
from typing import Any, Callable, Optional

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse


@dataclass(frozen=True)
class AppInfoRouteDeps:
    version: str
    build_commit: str
    load_pyproject_metadata: Callable[[], Optional[dict[str, Any]]]
    get_cache_status: Callable[[], dict[str, Any]]
    get_knowledge_store_status: Callable[[], dict[str, Any]]
    get_operational_health_summary: Callable[[], dict[str, Any]]
    load_changelog_content: Callable[[], str]
    get_sbom_path: Callable[[str], Optional[str]]
    read_text: Callable[[str], str]
    build_sbom_html: Callable[[str], str]
    backend_sbom_filename: str
    frontend_sbom_filename: str
    html_sbom_filename: str
    media_type_json: str


def create_app_info_router(
    app: FastAPI,
    deps: AppInfoRouteDeps,
    *,
    not_found_response: dict[int | str, dict[str, Any]],
) -> APIRouter:
    router = APIRouter()

    @router.get("/version")
    def get_version():
        return {"version": deps.version, "build": deps.build_commit}

    @router.get("/metadata", responses=not_found_response)
    def get_metadata():
        metadata = deps.load_pyproject_metadata()
        if not metadata:
            raise HTTPException(
                status_code=404, detail="pyproject.toml metadata not found"
            )
        return metadata

    @router.get("/cache-status")
    def get_cache_status():
        return deps.get_cache_status()

    @router.get("/knowledge-store-status")
    def get_knowledge_store_status():
        return deps.get_knowledge_store_status()

    @router.get("/operational-health")
    def get_operational_health():
        return deps.get_operational_health_summary()

    @router.get("/changelog")
    def get_changelog():
        return {"content": deps.load_changelog_content()}

    def build_sbom_response(filename: str) -> FileResponse:
        sbom_path = deps.get_sbom_path(filename)
        if sbom_path:
            return FileResponse(
                sbom_path,
                media_type=deps.media_type_json,
                filename=filename,
            )
        raise HTTPException(
            status_code=404,
            detail=f"{filename} not available.",
        )

    @router.get("/sbom", responses=not_found_response)
    def get_sbom():
        try:
            return build_sbom_response(deps.backend_sbom_filename)
        except HTTPException as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail="Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
            ) from exc

    @router.get("/sbom/backend", responses=not_found_response)
    def get_sbom_backend():
        try:
            return build_sbom_response(deps.backend_sbom_filename)
        except HTTPException as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail="Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
            ) from exc

    @router.get("/sbom/frontend", responses=not_found_response)
    def get_sbom_frontend():
        try:
            return build_sbom_response(deps.frontend_sbom_filename)
        except HTTPException as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail="Frontend SBOM not available. Generate in CI and include in container at /sbom/dtvp-frontend-cyclonedx.json.",
            ) from exc

    @router.get("/sbom/html", responses=not_found_response)
    def get_sbom_html():
        sbom_path = deps.get_sbom_path(deps.html_sbom_filename)
        if not sbom_path:
            raise HTTPException(
                status_code=404,
                detail=f"SBOM not available. Generate in CI and include in container at /sbom/{deps.html_sbom_filename}.",
            )
        return HTMLResponse(
            deps.build_sbom_html(deps.read_text(sbom_path)),
            media_type="text/html",
        )

    @router.get("/openapi.json")
    def get_open_api_endpoint():
        return get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            routes=app.routes,
        )

    return router
