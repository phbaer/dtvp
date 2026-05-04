from dataclasses import dataclass
from typing import Annotated, Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel


@dataclass(frozen=True)
class CodeAnalysisRouteDeps:
    code_analysis_settings_cls: Callable[[], Any]
    code_analysis_client_cls: type
    analysis_queue: Any
    code_analysis_not_configured_detail: str
    code_analysis_disabled_detail: str
    not_found_response: dict[int | str, dict[str, Any]]
    service_unavailable_response: dict[int | str, dict[str, Any]]


class CodeAnalysisAssessRequest(BaseModel):
    vuln_id: str
    component_name: str
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    focus_path: Optional[str] = None
    dependency_paths: Optional[list[list[str]]] = None
    debug: bool = False


class QueueSubmitRequest(BaseModel):
    vuln_id: str
    component_name: str
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None


def _register_code_analysis_routes(
    router: APIRouter,
    deps: CodeAnalysisRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.post(
        "/code-analysis/assess",
        responses=deps.service_unavailable_response,
    )
    async def code_analysis_start_assessment(
        req: CodeAnalysisAssessRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.code_analysis_disabled_detail,
            )
        async with deps.code_analysis_client_cls(settings) as client:
            return await client.start_assessment(
                vuln_id=req.vuln_id,
                component_name=req.component_name,
                cvss_vector=req.cvss_vector,
                user_guidance=req.user_guidance,
                focus_path=req.focus_path,
                dependency_paths=req.dependency_paths,
                debug=req.debug,
            )

    @router.get(
        "/code-analysis/jobs/{job_id}",
        responses=deps.service_unavailable_response,
    )
    async def code_analysis_get_job_status(
        job_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.code_analysis_not_configured_detail,
            )
        async with deps.code_analysis_client_cls(settings) as client:
            return await client.get_job_status(job_id)

    @router.get(
        "/code-analysis/jobs/{job_id}/result",
        responses=deps.service_unavailable_response,
    )
    async def code_analysis_get_job_result(
        job_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.code_analysis_not_configured_detail,
            )
        async with deps.code_analysis_client_cls(settings) as client:
            return await client.get_job_result(job_id)

    @router.get(
        "/code-analysis/health",
        responses=deps.service_unavailable_response,
    )
    async def code_analysis_health(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.code_analysis_not_configured_detail,
            )
        async with deps.code_analysis_client_cls(settings) as client:
            return await client.health()


def _register_analysis_queue_routes(
    router: APIRouter,
    deps: CodeAnalysisRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.post("/analysis-queue/submit")
    async def queue_submit(
        req: QueueSubmitRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        item = deps.analysis_queue.submit(
            vuln_id=req.vuln_id,
            component_name=req.component_name,
            submitted_by=user,
            cvss_vector=req.cvss_vector,
            user_guidance=req.user_guidance,
        )
        return item.model_dump(exclude={"result"})

    @router.get("/analysis-queue")
    async def queue_list(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        items = deps.analysis_queue.list_all()
        return [item.model_dump(exclude={"result"}) for item in items]

    @router.get("/analysis-queue/{queue_id}", responses=deps.not_found_response)
    async def queue_get(
        queue_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        item = deps.analysis_queue.get(queue_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found.")
        return item.model_dump()

    @router.delete(
        "/analysis-queue/{queue_id}",
        responses={
            404: {"description": "Not found"},
            409: {"description": "Conflict"},
        },
    )
    async def queue_cancel(
        queue_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        item = deps.analysis_queue.get(queue_id)
        if not item:
            raise HTTPException(status_code=404, detail="Queue item not found.")

        if item.status in ("queued",):
            deps.analysis_queue.cancel(queue_id)
            return {"status": "cancelled"}
        if item.status in ("completed", "failed", "cancelled"):
            deps.analysis_queue.remove_finished(queue_id)
            return {"status": "removed"}
        raise HTTPException(status_code=409, detail="Cannot cancel a running analysis.")


def create_code_analysis_router(
    deps: CodeAnalysisRouteDeps,
    *,
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()
    _register_code_analysis_routes(router, deps, current_user_dependency)
    _register_analysis_queue_routes(router, deps, current_user_dependency)
    return router
