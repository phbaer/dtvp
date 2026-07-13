import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .auto_analysis_services import (
    AutoAnalysisTarget,
    build_component_auto_analysis_guidance_block,
    get_component_auto_analysis_guidance,
)
from .code_analysis_benchmark_services import build_code_analysis_benchmark
from .code_analysis_result_services import build_follow_up_guidance


@dataclass(frozen=True)
class CodeAnalysisRouteDeps:
    code_analysis_settings_cls: Callable[[], Any]
    code_analysis_client_cls: type
    analysis_queue: Any
    result_store: Any
    load_auto_analysis_guidance: Callable[[], dict[str, Any]]
    get_auto_analysis_sweep_status: Callable[[], dict[str, Any]]
    run_auto_analysis_sweep_now: Callable[[], Awaitable[dict[str, Any]]]
    code_analysis_not_configured_detail: str
    code_analysis_disabled_detail: str
    not_found_response: dict[int | str, dict[str, Any]]
    service_unavailable_response: dict[int | str, dict[str, Any]]


class CodeAnalysisAssessRequest(BaseModel):
    vuln_id: str
    component_name: str
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    model: Optional[str] = None
    llm_backend: Optional[str] = None
    llm_provider: Optional[str] = None
    focus_path: Optional[str] = None
    dependency_paths: Optional[list[list[str]]] = None
    affected_product_versions: Optional[list[str]] = None
    debug: bool = False


class QueueSubmitRequest(BaseModel):
    vuln_id: str
    component_name: str
    project_name: Optional[str] = None
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    affected_product_versions: Optional[list[str]] = None
    model: Optional[str] = None
    llm_backend: Optional[str] = None
    llm_provider: Optional[str] = None
    source: Optional[str] = None


class CodeAnalysisBenchmarkRequest(BaseModel):
    current_team: Optional[str] = None
    current_state: Optional[str] = None
    current_justification: Optional[str] = None
    current_details: Optional[str] = None
    current_cvss_score: Optional[float | str] = None
    current_cvss_vector: Optional[str] = None


class QueueFollowUpRequest(BaseModel):
    parent_run_id: str
    question: str
    component_name: Optional[str] = None
    project_name: Optional[str] = None
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    model: Optional[str] = None
    llm_backend: Optional[str] = None
    llm_provider: Optional[str] = None
    context_mode: str = "compact"


class QueueClearRequest(BaseModel):
    statuses: list[str] = Field(
        default_factory=lambda: ["completed", "failed", "cancelled"]
    )


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _append_static_component_guidance(
    *,
    load_auto_analysis_guidance: Callable[[], dict[str, Any]],
    vuln_id: str,
    component_name: str,
    user_guidance: Optional[str],
) -> Optional[str]:
    component = str(component_name or "").strip()
    if not component:
        return user_guidance

    try:
        config = load_auto_analysis_guidance()
    except Exception:
        return user_guidance

    target = AutoAnalysisTarget(component_name=component)
    group = {
        "id": vuln_id,
        "affected_versions": [
            {
                "components": [
                    {
                        "component_name": component,
                    }
                ]
            }
        ],
    }
    component_guidance = get_component_auto_analysis_guidance(
        config,
        group,
        target,
    )
    guidance_block = build_component_auto_analysis_guidance_block(
        target,
        component_guidance,
    )
    if not guidance_block:
        return user_guidance

    existing = str(user_guidance or "").strip()
    if guidance_block in existing:
        return existing
    return "\n\n".join(part for part in (existing, guidance_block) if part) or None


def _dump_queue_item(item: Any, *, include_result: bool = False) -> dict[str, Any]:
    exclude = set() if include_result else {"result"}
    if hasattr(item, "model_dump"):
        return item.model_dump(exclude=exclude)
    data = dict(getattr(item, "__dict__", {}))
    if not include_result:
        data.pop("result", None)
    return data


def _count_by(items: list[Any], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attr, "") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _extract_error_message(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if response is not None:
        try:
            payload = response.json()
            detail = payload.get("detail") if isinstance(payload, dict) else None
            if detail:
                return str(detail)
        except Exception:
            pass
        status_code = getattr(response, "status_code", None)
        if status_code:
            return f"HTTP {status_code}: {exc}"
    return str(exc)


def _coerce_limit(value: int | None, *, default: int = 100) -> int:
    try:
        return max(1, min(int(value or default), 500))
    except (TypeError, ValueError):
        return default


def _extract_active_agents(progress: Any) -> list[dict[str, Any]]:
    if not isinstance(progress, dict):
        return []
    active_agents = progress.get("active_agents")
    if isinstance(active_agents, list) and active_agents:
        return [
            agent
            for agent in active_agents
            if isinstance(agent, dict)
        ]
    current_agent = progress.get("current_agent")
    if not current_agent:
        return []
    return [
        {
            "step": progress.get("current_step"),
            "title": progress.get("current_title"),
            "agent": current_agent,
            "activity": progress.get("current_activity"),
            "status": "running",
        }
    ]


def _find_metadata_value(value: Any, keys: tuple[str, ...]) -> Optional[str]:
    key_set = {key.lower() for key in keys}
    if isinstance(value, dict):
        for key, inner in value.items():
            if str(key).lower() in key_set and inner not in (None, ""):
                return str(inner)
        for inner in value.values():
            found = _find_metadata_value(inner, keys)
            if found:
                return found
    if isinstance(value, list):
        for inner in value:
            found = _find_metadata_value(inner, keys)
            if found:
                return found
    return None


def _find_metadata_dict(value: Any, keys: tuple[str, ...]) -> Optional[dict[str, Any]]:
    key_set = {key.lower() for key in keys}
    if isinstance(value, dict):
        for key, inner in value.items():
            if str(key).lower() in key_set and isinstance(inner, dict):
                return inner
        for inner in value.values():
            found = _find_metadata_dict(inner, keys)
            if found:
                return found
    if isinstance(value, list):
        for inner in value:
            found = _find_metadata_dict(inner, keys)
            if found:
                return found
    return None


def _first_with_source(
    candidates: list[tuple[Optional[str], str]],
) -> tuple[Optional[str], str]:
    for value, source in candidates:
        if value:
            return value, source
    return None, "not_reported"


def _settings_metadata_value(settings: Any, attrs: tuple[str, ...]) -> Optional[str]:
    for attr in attrs:
        value = getattr(settings, attr, None)
        if value not in (None, ""):
            text = str(value).strip()
            if text:
                return text
    return None


def _status_timeout_seconds(settings: Any) -> float:
    try:
        timeout = float(
            getattr(settings, "DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS", 5.0)
        )
    except (TypeError, ValueError):
        return 5.0
    return max(0.1, timeout)


async def _status_call_with_timeout(
    label: str,
    call: Awaitable[Any],
    timeout: float,
) -> Any:
    try:
        return await asyncio.wait_for(call, timeout=timeout)
    except TimeoutError:
        return TimeoutError(
            f"Timed out after {timeout:.1f}s while fetching code-analysis {label}"
        )
    except Exception as exc:
        return exc


async def _fetch_external_code_analysis_status(
    deps: CodeAnalysisRouteDeps,
    settings: Any,
) -> dict[str, Any]:
    external: dict[str, Any] = {
        "health": None,
        "health_error": None,
        "jobs": [],
        "jobs_error": None,
        "configuration": None,
        "backend": None,
        "busy": False,
        "capacity": None,
        "running_jobs": None,
        "queued_jobs": None,
        "available_slots": None,
    }
    if not settings.enabled:
        return external

    jobs_payload: Any = None
    try:
        async with deps.code_analysis_client_cls(settings) as client:
            timeout = _status_timeout_seconds(settings)
            health_result, jobs_result = await asyncio.gather(
                _status_call_with_timeout("health", client.health(), timeout),
                _status_call_with_timeout("jobs", client.list_jobs(), timeout),
            )
            if isinstance(health_result, Exception):
                external["health_error"] = _extract_error_message(health_result)
            else:
                external["health"] = health_result

            if isinstance(jobs_result, Exception):
                external["jobs_error"] = _extract_error_message(jobs_result)
            else:
                jobs_payload = jobs_result
                jobs = (
                    jobs_payload.get("jobs")
                    if isinstance(jobs_payload, dict)
                    else jobs_payload
                )
                external["jobs"] = jobs if isinstance(jobs, list) else []
    except Exception as exc:
        message = _extract_error_message(exc)
        external["health_error"] = external["health_error"] or message
        external["jobs_error"] = external["jobs_error"] or message

    running_jobs = sum(
        1
        for job in external["jobs"]
        if isinstance(job, dict) and job.get("status") == "running"
    )
    queued_jobs = sum(
        1
        for job in external["jobs"]
        if isinstance(job, dict) and job.get("status") == "pending"
    )
    external["busy"] = any(
        isinstance(job, dict) and job.get("status") in {"pending", "running"}
        for job in external["jobs"]
    )
    metadata_sources = [external.get("health"), jobs_payload, external.get("jobs")]
    external["configuration"] = _find_metadata_dict(
        metadata_sources,
        ("configuration", "config"),
    )
    external["backend"] = _find_metadata_dict(
        metadata_sources,
        ("backend", "backends"),
    )
    jobs_backend = (
        external["backend"].get("jobs")
        if isinstance(external.get("backend"), dict)
        and isinstance(external["backend"].get("jobs"), dict)
        else {}
    )

    def int_metadata(name: str, fallback: Optional[int] = None) -> Optional[int]:
        value = jobs_backend.get(name) if jobs_backend else None
        if value is None:
            return fallback
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback

    external["capacity"] = int_metadata("max_concurrent_jobs")
    external["running_jobs"] = int_metadata("running_jobs", running_jobs)
    external["queued_jobs"] = int_metadata("queued_jobs", queued_jobs)
    external["available_slots"] = int_metadata(
        "available_slots",
        (
            max(0, external["capacity"] - running_jobs)
            if isinstance(external["capacity"], int)
            else None
        ),
    )
    return external


async def build_code_analysis_dashboard_status(
    deps: CodeAnalysisRouteDeps,
) -> dict[str, Any]:
    settings = deps.code_analysis_settings_cls()
    items = deps.analysis_queue.list_all()
    running_items = [
        item for item in items if getattr(item, "status", "") == "running"
    ]
    running_item = running_items[0] if running_items else None
    queued_items = [
        item for item in items if getattr(item, "status", "") == "queued"
    ]
    capacity = (
        deps.analysis_queue.capacity()
        if hasattr(deps.analysis_queue, "capacity")
        else 1
    )
    available_slots = max(0, capacity - len(running_items))
    external = await _fetch_external_code_analysis_status(deps, settings)
    sweep_status = deps.get_auto_analysis_sweep_status()

    queue_progress_agents: list[dict[str, Any]] = []
    for item in running_items:
        queue_progress_agents.extend(
            _extract_active_agents(getattr(item, "progress", None))
        )
    external_agents: list[dict[str, Any]] = []
    for job in external["jobs"]:
        if not isinstance(job, dict) or job.get("status") not in {
            "pending",
            "running",
        }:
            continue
        external_agents.extend(_extract_active_agents(job.get("progress")))

    model, model_source = _first_with_source(
        [
            (getattr(running_item, "model", None) if running_item else None, "queue"),
            (
                _settings_metadata_value(
                    settings,
                    ("DTVP_CODE_ANALYSIS_MODEL", "DTVP_AGENYZER_MODEL"),
                ),
                "settings",
            ),
            (
                _find_metadata_value(
                    external.get("health"),
                    ("model", "llm_model"),
                ),
                "health",
            ),
            (
                _find_metadata_value(external.get("jobs"), ("model", "llm_model")),
                "jobs",
            ),
            (
                _find_metadata_value(
                    [getattr(item, "result", None) for item in items],
                    ("model", "llm_model"),
                ),
                "result",
            ),
        ]
    )
    llm_backend, llm_backend_source = _first_with_source(
        [
            (
                getattr(running_item, "llm_backend", None) if running_item else None,
                "queue",
            ),
            (
                _settings_metadata_value(
                    settings,
                    (
                        "DTVP_CODE_ANALYSIS_LLM_BACKEND",
                        "DTVP_AGENYZER_LLM_BACKEND",
                    ),
                ),
                "settings",
            ),
            (
                _find_metadata_value(
                    external.get("health"),
                    ("llm_backend", "backend", "base_url", "llm_base_url"),
                ),
                "health",
            ),
            (
                _find_metadata_value(
                    external.get("jobs"),
                    ("llm_backend", "backend", "base_url", "llm_base_url"),
                ),
                "jobs",
            ),
        ]
    )
    llm_provider, llm_provider_source = _first_with_source(
        [
            (
                getattr(running_item, "llm_provider", None) if running_item else None,
                "queue",
            ),
            (
                _settings_metadata_value(
                    settings,
                    (
                        "DTVP_CODE_ANALYSIS_LLM_PROVIDER",
                        "DTVP_AGENYZER_LLM_PROVIDER",
                    ),
                ),
                "settings",
            ),
            (
                _find_metadata_value(
                    external.get("health"),
                    ("llm_provider", "provider"),
                ),
                "health",
            ),
            (
                _find_metadata_value(
                    external.get("jobs"),
                    ("llm_provider", "provider"),
                ),
                "jobs",
            ),
        ]
    )

    if not settings.enabled:
        overall_state = "disabled"
    elif running_items:
        overall_state = "running"
    elif queued_items:
        overall_state = "queued"
    elif external.get("health_error") and not external.get("health"):
        overall_state = "unavailable"
    else:
        overall_state = "idle"

    return {
        "overall_state": overall_state,
        "updated_at": _utc_now_iso(),
        "configured": bool(settings.enabled),
        "result_cache": deps.result_store.status()
        if hasattr(deps.result_store, "status")
        else None,
        "queue": {
            "capacity": capacity,
            "running_count": len(running_items),
            "available_slots": available_slots,
            "dtvp_worker_busy": bool(running_items),
            "waiting_for_slot": bool(queued_items) and available_slots == 0,
            "counts_by_status": _count_by(items, "status"),
            "counts_by_source": _count_by(items, "source"),
            "active_item": (
                _dump_queue_item(running_item)
                if running_item
                else None
            ),
            "active_items": [_dump_queue_item(item) for item in running_items],
            "items": [_dump_queue_item(item) for item in items],
        },
        "recent_results": deps.result_store.list(limit=10, include_result=False),
        "auto_sweep": sweep_status,
        "external": external,
        "active_agents": queue_progress_agents or external_agents,
        "model": model,
        "model_source": model_source,
        "llm_backend": llm_backend,
        "llm_backend_source": llm_backend_source,
        "llm_provider": llm_provider,
        "llm_provider_source": llm_provider_source,
    }


def _register_code_analysis_routes(
    router: APIRouter,
    deps: CodeAnalysisRouteDeps,
    current_user_dependency: Callable[..., Any],
) -> None:
    @router.get("/code-analysis/status")
    async def code_analysis_dashboard_status(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        return await build_code_analysis_dashboard_status(deps)

    @router.get("/code-analysis/results")
    async def code_analysis_list_results(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
        project_name: Annotated[Optional[str], Query()] = None,
        vuln_id: Annotated[Optional[str], Query()] = None,
        component_name: Annotated[Optional[str], Query()] = None,
        source: Annotated[Optional[str], Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        include_result: Annotated[bool, Query()] = False,
    ):
        return deps.result_store.list(
            project_name=project_name,
            vuln_id=vuln_id,
            component_name=component_name,
            source=source,
            limit=_coerce_limit(limit),
            include_result=include_result,
        )

    @router.get(
        "/code-analysis/results/{run_id}",
        responses=deps.not_found_response,
    )
    async def code_analysis_get_result(
        run_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        record = deps.result_store.get(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Analysis result not found.")
        return record

    @router.delete(
        "/code-analysis/results/{run_id}",
        responses=deps.not_found_response,
    )
    async def code_analysis_delete_result(
        run_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        if not deps.result_store.delete(run_id):
            raise HTTPException(status_code=404, detail="Analysis result not found.")
        return {"status": "removed", "analysis_run_id": run_id}

    @router.post(
        "/code-analysis/results/{run_id}/compact",
        responses=deps.not_found_response,
    )
    async def code_analysis_compact_result(
        run_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        compact_context = deps.result_store.compact_context(run_id)
        if not compact_context:
            raise HTTPException(status_code=404, detail="Analysis result not found.")
        return compact_context

    @router.post(
        "/code-analysis/results/{run_id}/benchmark",
        responses=deps.not_found_response,
    )
    async def code_analysis_benchmark_result(
        run_id: str,
        req: CodeAnalysisBenchmarkRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        record = deps.result_store.get(run_id)
        if not record:
            raise HTTPException(status_code=404, detail="Analysis result not found.")
        benchmark = build_code_analysis_benchmark(record, req.model_dump())
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            return benchmark

        try:
            async with deps.code_analysis_client_cls(settings) as client:
                evaluated = await client.compare_benchmark(benchmark)
            if isinstance(evaluated, dict):
                return evaluated
        except Exception as exc:
            benchmark["evaluator"] = {
                "provider": "dtvp",
                "probabilistic": False,
                "available": False,
                "reason": f"Agentyzer benchmark comparison unavailable: {_extract_error_message(exc)}",
            }
            benchmark["comparison_method"] = "deterministic_fallback"
        return benchmark

    @router.get(
        "/projects/{project_name}/vulnerabilities/{vuln_id}/analysis-results",
    )
    async def code_analysis_list_project_vulnerability_results(
        project_name: str,
        vuln_id: str,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
        component_name: Annotated[Optional[str], Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        include_result: Annotated[bool, Query()] = False,
    ):
        return deps.result_store.list(
            project_name=project_name,
            vuln_id=vuln_id,
            component_name=component_name,
            limit=_coerce_limit(limit),
            include_result=include_result,
        )

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
            user_guidance = _append_static_component_guidance(
                load_auto_analysis_guidance=deps.load_auto_analysis_guidance,
                vuln_id=req.vuln_id,
                component_name=req.component_name,
                user_guidance=req.user_guidance,
            )
            return await client.start_assessment(
                vuln_id=req.vuln_id,
                component_name=req.component_name,
                cvss_vector=req.cvss_vector,
                user_guidance=user_guidance,
                model=req.model,
                llm_backend=req.llm_backend,
                llm_provider=req.llm_provider,
                focus_path=req.focus_path,
                dependency_paths=req.dependency_paths,
                affected_product_versions=req.affected_product_versions,
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

    @router.get(
        "/code-analysis/prompts",
        responses=deps.service_unavailable_response,
    )
    async def code_analysis_prompts(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
        include_values: Annotated[bool, Query()] = False,
        system_only: Annotated[bool, Query()] = True,
    ):
        settings = deps.code_analysis_settings_cls()
        if not settings.enabled:
            raise HTTPException(
                status_code=503,
                detail=deps.code_analysis_not_configured_detail,
            )
        async with deps.code_analysis_client_cls(settings) as client:
            if not hasattr(client, "get_prompts"):
                raise HTTPException(
                    status_code=404,
                    detail="Code analysis prompt endpoint is not available.",
                )
            return await client.get_prompts(
                include_values=include_values,
                system_only=system_only,
            )

    @router.get("/code-analysis/auto-sweep")
    async def code_analysis_auto_sweep_status(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        return deps.get_auto_analysis_sweep_status()

    @router.post("/code-analysis/auto-sweep/run")
    async def code_analysis_auto_sweep_run(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        return await deps.run_auto_analysis_sweep_now()


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
        source = (req.source or "manual").strip().lower()
        if source not in {"manual", "benchmark"}:
            raise HTTPException(
                status_code=400,
                detail="Queue source must be manual or benchmark.",
            )
        user_guidance = _append_static_component_guidance(
            load_auto_analysis_guidance=deps.load_auto_analysis_guidance,
            vuln_id=req.vuln_id,
            component_name=req.component_name,
            user_guidance=req.user_guidance,
        )
        item = deps.analysis_queue.submit(
            vuln_id=req.vuln_id,
            component_name=req.component_name,
            project_name=req.project_name,
            submitted_by=user,
            cvss_vector=req.cvss_vector,
            user_guidance=user_guidance,
            affected_product_versions=req.affected_product_versions,
            model=req.model,
            llm_backend=req.llm_backend,
            llm_provider=req.llm_provider,
            source=source,
        )
        return item.model_dump(exclude={"result"})

    @router.post(
        "/analysis-queue/follow-up",
        responses=deps.not_found_response,
    )
    async def queue_follow_up(
        req: QueueFollowUpRequest,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        parent = deps.result_store.get(req.parent_run_id)
        if not parent:
            raise HTTPException(
                status_code=404,
                detail="Parent analysis result not found.",
            )
        question = req.question.strip()
        if not question:
            raise HTTPException(
                status_code=400,
                detail="Follow-up question is required.",
            )

        user_guidance = build_follow_up_guidance(
            parent,
            question,
            extra_guidance=req.user_guidance,
        )

        item = deps.analysis_queue.submit(
            vuln_id=str(parent.get("vuln_id") or ""),
            component_name=req.component_name
            or str(parent.get("component_name") or ""),
            project_name=req.project_name
            if req.project_name is not None
            else parent.get("project_name"),
            submitted_by=user,
            cvss_vector=req.cvss_vector or parent.get("cvss_vector"),
            user_guidance=user_guidance,
            model=req.model,
            llm_backend=req.llm_backend,
            llm_provider=req.llm_provider,
            parent_run_id=parent.get("analysis_run_id"),
            parent_job_id=parent.get("job_id"),
            follow_up_question=question,
            follow_up_user_guidance=req.user_guidance,
            context_mode=req.context_mode or "compact",
            source="follow-up",
        )
        return item.model_dump(exclude={"result"})

    @router.get("/analysis-queue")
    async def queue_list(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        items = deps.analysis_queue.list_all()
        return [item.model_dump(exclude={"result"}) for item in items]

    @router.post("/analysis-queue/clear")
    async def queue_clear(
        req: QueueClearRequest | None = None,
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        statuses = set(
            (req.statuses if req else None)
            or ["completed", "failed", "cancelled"]
        )
        removed = deps.analysis_queue.remove_finished_by_statuses(statuses)
        return {"status": "cleared", "removed": removed}

    @router.post("/analysis-queue/cancel-queued")
    async def queue_cancel_queued(
        *,
        user: Annotated[str, Depends(current_user_dependency)],
    ):
        cancelled = deps.analysis_queue.cancel_all_queued()
        return {"status": "cancelled", "cancelled": cancelled}

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
        if item.status == "running":
            deps.analysis_queue.request_abort(queue_id)
            if not item.job_id:
                return {"status": "abort_requested"}

            settings = deps.code_analysis_settings_cls()
            if not settings.enabled:
                message = deps.code_analysis_not_configured_detail
                deps.analysis_queue.clear_abort(queue_id, message)
                raise HTTPException(status_code=409, detail=message)

            try:
                async with deps.code_analysis_client_cls(settings) as client:
                    await client.delete_job(item.job_id)
            except Exception as exc:
                message = _extract_error_message(exc)
                deps.analysis_queue.clear_abort(queue_id, message)
                raise HTTPException(
                    status_code=409,
                    detail=f"External code analysis job refused abort: {message}",
                ) from exc

            deps.analysis_queue.finish_running_cancelled(queue_id)
            return {"status": "cancelled"}
        raise HTTPException(status_code=409, detail="Cannot cancel this analysis.")


def create_code_analysis_router(
    deps: CodeAnalysisRouteDeps,
    *,
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()
    _register_code_analysis_routes(router, deps, current_user_dependency)
    _register_analysis_queue_routes(router, deps, current_user_dependency)
    return router
