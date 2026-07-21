import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Any, Dict

import yaml
from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from src.agents import dependency_scanner
from src.agents.dependency_scanner import RepoError
from src.agents.repository_research import repository_clone_enabled
from src.api.jobs import (
    Job,
    _now_iso,
    _recompute_job_progress,
    append_job_log,
    apply_progress_event,
    job_status_response,
)
from src.api.models import (
    ASSESS_ASYNC_REQUEST_EXAMPLE,
    ASSESS_RESPONSE_EXAMPLE,
    ASSESS_SYNC_REQUEST_EXAMPLE,
    JOB_NOT_FOUND_DETAIL,
    JOB_SUBMITTED_EXAMPLE,
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    Assessment,
    AssessRequest,
    AssessResponse,
    BenchmarkCompareRequest,
    BenchmarkCompareResponse,
    BackendInformation,
    CompactContextResponse,
    ErrorResponse,
    FollowUpRequest,
    HealthResponse,
    JobBackendInfo,
    JobListResponse,
    JobStatus,
    JobStatusResponse,
    JobSubmittedResponse,
    LlmBackendInfo,
    RepositoryBackendInfo,
    RepositoryConfigurationSummary,
    ServiceConfiguration,
    StepFindings,
)
from src.benchmark import compare_benchmark_with_llm, deterministic_benchmark_fallback
from src.llm import OllamaClient, OpenWebUIClient, create_llm_client
from src.llm.base import LLMClient
from src.llm.prompt_registry import (
    get_config_dir,
    list_prompt_bundles,
    validate_all_prompt_bundles,
)
from src.pipeline import run_pipeline
from src.security import (
    ServiceCaller,
    require_service_caller,
    validate_service_auth_configuration,
)
from src.version import VERSION

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

_CONFIG_DIR = str(get_config_dir())

_DEFAULT_REPOS_CONFIG = "components: {}\n"
_FOLLOW_UP_CONTEXT_PROMPT_LIMIT = 12_000
_DEFAULT_REPO_REFRESH_SECONDS = 900

_repos_config_path: str | None = None
_repos_config_mtime: float = 0.0


def _get_max_concurrent_jobs() -> int:
    raw_value = os.environ.get("AGENTYZER_MAX_CONCURRENT_JOBS", "1")
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        logger.warning(
            "Invalid AGENTYZER_MAX_CONCURRENT_JOBS=%r, falling back to 1",
            raw_value,
        )
        return 1


def _get_repo_refresh_seconds() -> int:
    raw_value = os.environ.get(
        "AGENTYZER_REPO_REFRESH_SECONDS",
        str(_DEFAULT_REPO_REFRESH_SECONDS),
    )
    try:
        interval = int(raw_value)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid AGENTYZER_REPO_REFRESH_SECONDS=%r, falling back to %d",
            raw_value,
            _DEFAULT_REPO_REFRESH_SECONDS,
        )
        return _DEFAULT_REPO_REFRESH_SECONDS
    if interval == 0:
        return 0
    if interval < 60:
        logger.warning(
            "AGENTYZER_REPO_REFRESH_SECONDS=%r is below the 60-second minimum; "
            "using 60",
            raw_value,
        )
        return 60
    return interval


def _repository_refresh_interval_seconds() -> int:
    try:
        return int(app.state.repository_refresh_interval_seconds)
    except (AttributeError, TypeError, ValueError):
        return _get_repo_refresh_seconds()


def _describe_llm_backend(client: object) -> str:
    return (
        f"backend={type(client).__name__} "
        f"host={getattr(client, 'host', 'n/a')} "
        f"model={getattr(client, 'model', 'n/a')}"
    )


def _llm_provider_for_client(client: object) -> str:
    configured = os.environ.get("LLM_BACKEND")
    if configured:
        return configured.lower()
    if isinstance(client, OpenWebUIClient):
        return "openwebui"
    if isinstance(client, OllamaClient):
        return "ollama"
    return type(client).__name__


def _llm_metadata(client: object, *, healthy: bool | None = None) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "provider": _llm_provider_for_client(client),
        "backend": type(client).__name__,
        "host": getattr(client, "host", None),
        "model": getattr(client, "model", None),
    }
    if healthy is not None:
        metadata["healthy"] = healthy
    last_error = getattr(client, "last_error", "")
    if last_error:
        metadata["last_error"] = str(last_error)
    return metadata


def _client_for_model(model_override: str | None = None) -> LLMClient:
    base = app.state.ollama
    model = model_override or getattr(base, "model", None)
    if isinstance(base, OpenWebUIClient):
        return OpenWebUIClient(
            host=base.host,
            model=model,
            api_key=getattr(base, "api_key", ""),
            tool_call_mode=getattr(base, "tool_call_mode", "auto"),
        )
    if isinstance(base, OllamaClient):
        return OllamaClient(host=base.host, model=model)
    return base


def _client_for_request(req: AssessRequest) -> LLMClient:
    return _client_for_model(req.model)


def load_repos_config(path: str | None = None):
    if path is None:
        path = os.path.join(_CONFIG_DIR, "repos.yaml")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(_DEFAULT_REPOS_CONFIG)
        logger.info("Created default config at %s", path)
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def _get_repos_config() -> Dict[str, Any]:
    """Return the repos config, reloading from disk if the file was modified."""
    global _repos_config_mtime
    path = _repos_config_path or os.path.join(_CONFIG_DIR, "repos.yaml")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return app.state.repos
    if mtime > _repos_config_mtime:
        app.state.repos = load_repos_config(path)
        _repos_config_mtime = mtime
        logger.info("Reloaded repos config from %s", path)
    return app.state.repos


async def _refresh_configured_repository_caches(
    repos: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Refresh each unique explicit repository URL without creating worktrees."""
    current_repos = repos if repos is not None else _get_repos_config()
    components = current_repos.get("components") or {}
    candidates: list[tuple[str, Dict[str, Any]]] = []
    seen_urls: set[str] = set()
    skipped = 0
    if isinstance(components, dict):
        for component_name, raw_config in components.items():
            if not isinstance(raw_config, dict) or not raw_config.get("url"):
                skipped += 1
                continue
            url = str(raw_config["url"])
            if url in seen_urls:
                skipped += 1
                continue
            seen_urls.add(url)
            config = dict(raw_config)
            config["url"] = url
            config.setdefault("name", str(component_name))
            candidates.append((str(component_name), config))

    if not candidates:
        logger.warning(
            "Repository cache refresh skipped: no explicit URL-backed components "
            "are configured in %s",
            _resolved_repos_config_path(),
        )
        return {
            "configured": 0,
            "refreshed": 0,
            "failed": 0,
            "skipped": skipped,
            "completed_at": _now_iso(),
        }

    logger.info(
        "Repository cache refresh cycle starting: repositories=%d interval=%ds",
        len(candidates),
        _repository_refresh_interval_seconds(),
    )
    refreshed = 0
    failures: list[str] = []
    for component_name, component_cfg in candidates:
        try:
            await dependency_scanner.refresh_repo_cache(component_cfg)
            refreshed += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failures.append(component_name)
            logger.error(
                "Repository cache refresh failed: component=%s error=%s",
                component_name,
                exc,
            )

    summary = {
        "configured": len(candidates),
        "refreshed": refreshed,
        "failed": len(failures),
        "skipped": skipped,
        "failed_components": failures,
        "completed_at": _now_iso(),
    }
    logger.info(
        "Repository cache refresh cycle complete: refreshed=%d failed=%d skipped=%d",
        refreshed,
        len(failures),
        skipped,
    )
    return summary


async def _repository_cache_refresh_loop(interval_seconds: int) -> None:
    """Continuously refresh explicit repository mappings until shutdown."""
    while True:
        try:
            app.state.repository_refresh = (
                await _refresh_configured_repository_caches()
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Repository cache refresh cycle failed: %s", exc)
            app.state.repository_refresh = {
                "configured": 0,
                "refreshed": 0,
                "failed": 1,
                "skipped": 0,
                "failed_components": [],
                "completed_at": _now_iso(),
            }
        await asyncio.sleep(interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _repos_config_path, _repos_config_mtime
    validate_service_auth_configuration()
    _repos_config_path = os.path.join(_CONFIG_DIR, "repos.yaml")
    app.state.repos = load_repos_config(_repos_config_path)
    validate_all_prompt_bundles()
    try:
        _repos_config_mtime = os.path.getmtime(_repos_config_path)
    except OSError:
        _repos_config_mtime = 0.0
    app.state.ollama = create_llm_client()
    app.state.jobs: Dict[str, Job] = {}
    app.state.job_tasks: Dict[str, asyncio.Task[Any]] = {}
    app.state.max_concurrent_jobs = _get_max_concurrent_jobs()
    app.state.job_semaphore = asyncio.Semaphore(app.state.max_concurrent_jobs)
    logger.info("Configured LLM %s", _describe_llm_backend(app.state.ollama))
    logger.info("Configured async job capacity: %s", app.state.max_concurrent_jobs)
    app.state.llm_healthy = await app.state.ollama.health_check()
    if not app.state.llm_healthy:
        logger.warning(
            "LLM backend is not reachable — requests requiring the model will fail (%s, error=%s)",
            _describe_llm_backend(app.state.ollama),
            getattr(app.state.ollama, "last_error", "unknown"),
        )
    else:
        logger.info(
            "LLM backend is reachable (%s)", _describe_llm_backend(app.state.ollama)
        )
    refresh_interval = _get_repo_refresh_seconds()
    app.state.repository_refresh_interval_seconds = refresh_interval
    app.state.repository_refresh = {
        "configured": 0,
        "refreshed": 0,
        "failed": 0,
        "skipped": 0,
        "completed_at": None,
    }
    refresh_task: asyncio.Task[Any] | None = None
    if refresh_interval:
        logger.info(
            "Periodic repository cache refresh enabled: interval=%ds",
            refresh_interval,
        )
        refresh_task = asyncio.create_task(
            _repository_cache_refresh_loop(refresh_interval),
            name="repository-cache-refresh",
        )
    else:
        logger.warning(
            "Periodic repository cache refresh disabled by "
            "AGENTYZER_REPO_REFRESH_SECONDS=0"
        )
    app.state.repository_refresh_task = refresh_task
    try:
        yield
    finally:
        if refresh_task is not None:
            refresh_task.cancel()
            with suppress(asyncio.CancelledError):
                await refresh_task


app = FastAPI(
    title="Agentic Vulnerability Analyzer",
    summary="Assess whether a component is affected by a CVE using dependency, version, and code reachability evidence.",
    description=(
        "The API runs a multi-step vulnerability assessment pipeline over a target component or repository. "
        "It can execute synchronously for immediate results or asynchronously via background jobs that can be polled later."
    ),
    version=VERSION,
    lifespan=lifespan,
    dependencies=[Depends(require_service_caller)],
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
    contact={"name": "Agentyzer Maintainers"},
    license_info={"name": "Proprietary"},
    openapi_tags=[
        {
            "name": "system",
            "description": "Service health and operational endpoints.",
        },
        {
            "name": "assessment",
            "description": "Submit vulnerability assessments and inspect pipeline output.",
        },
        {
            "name": "jobs",
            "description": "Track, inspect, and remove asynchronous assessment jobs.",
        },
        {
            "name": "benchmark",
            "description": "Compare human and automated assessment artifacts without rerunning repository analysis.",
        },
    ],
)


@app.get("/openapi.json", include_in_schema=False)
async def authenticated_openapi():
    return JSONResponse(app.openapi())


# ===================================================================== #
# Helpers                                                                #
# ===================================================================== #


def _resolved_repos_config_path() -> str:
    return _repos_config_path or os.path.join(_CONFIG_DIR, "repos.yaml")


def _jobs_visible_to(owner: str) -> Dict[str, Job]:
    jobs: Dict[str, Job] = getattr(app.state, "jobs", {})
    if owner == "*":
        return jobs
    return {job_id: job for job_id, job in jobs.items() if job.owner == owner}


def _job_for_caller(job_id: str, caller: ServiceCaller) -> Job:
    job = _jobs_visible_to(caller.owner).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=JOB_NOT_FOUND_DETAIL)
    return job


def _job_status_counts(owner: str) -> Dict[str, int]:
    counts = {status.value: 0 for status in JobStatus}
    jobs = _jobs_visible_to(owner)
    for job in jobs.values():
        key = job.status.value if isinstance(job.status, JobStatus) else str(job.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _repository_configuration_summary(
    repos: Dict[str, Any],
) -> RepositoryConfigurationSummary:
    components = repos.get("components") or {}
    aliases = repos.get("aliases") or {}
    return RepositoryConfigurationSummary(
        workspace_dir=dependency_scanner._REPOS_DIR,
        component_count=len(components),
        components=sorted(str(name) for name in components),
        aliases=sorted(str(name) for name in aliases),
        default_template_configured=bool(repos.get("defaults")),
        hot_reload=True,
    )


def _service_configuration() -> ServiceConfiguration:
    repos = _get_repos_config()
    return ServiceConfiguration(
        service_name=app.title,
        service_version=app.version,
        config_dir=_CONFIG_DIR,
        repos_config_path=_resolved_repos_config_path(),
        repositories=_repository_configuration_summary(repos),
        features={
            "async_assessments": True,
            "sync_assessments": True,
            "bounded_async_execution": True,
            "request_model_override": True,
            "debug_responses": True,
            "job_cancellation": True,
            "job_logs": True,
            "focus_path": True,
            "repository_archive_inspection": True,
            "repos_config_hot_reload": True,
            "periodic_repository_refresh": (
                _repository_refresh_interval_seconds() > 0
            ),
            "context_compaction": True,
            "follow_up_assessments": True,
            "benchmark_comparisons": True,
            "local_repository_research": repository_clone_enabled(),
            "service_bearer_authentication": True,
            "owner_scoped_jobs": True,
        },
    )


def _llm_backend_info() -> LlmBackendInfo:
    metadata = _llm_metadata(
        app.state.ollama,
        healthy=getattr(app.state, "llm_healthy", None),
    )
    supports_model_override = isinstance(
        app.state.ollama,
        (OpenWebUIClient, OllamaClient),
    )
    return LlmBackendInfo(
        provider=metadata.get("provider"),
        backend=metadata.get("backend"),
        host=metadata.get("host"),
        model=metadata.get("model"),
        healthy=metadata.get("healthy"),
        last_error=metadata.get("last_error"),
        supports_model_override=supports_model_override,
    )


def _backend_information(owner: str) -> BackendInformation:
    jobs = _jobs_visible_to(owner)
    max_concurrent_jobs = int(getattr(app.state, "max_concurrent_jobs", 1) or 1)
    status_counts = _job_status_counts(owner)
    running_jobs = status_counts.get(JobStatus.running.value, 0)
    queued_jobs = status_counts.get(JobStatus.pending.value, 0)
    refresh_interval = _repository_refresh_interval_seconds()
    update_strategy = (
        "periodic background clone/fetch every "
        f"{refresh_interval} seconds plus a locked fetch immediately before "
        "each assessment worktree"
        if refresh_interval
        else (
            "periodic background refresh is disabled; a locked fetch still runs "
            "immediately before each assessment worktree"
        )
    )
    return BackendInformation(
        llm=_llm_backend_info(),
        repositories=RepositoryBackendInfo(
            workspace_dir=dependency_scanner._REPOS_DIR,
            reuse_strategy=(
                "stable control repository per sanitized URL plus a detached "
                "worktree for each analysis"
            ),
            update_strategy=update_strategy,
            parallel_safety=(
                "execution is bounded by AGENTYZER_MAX_CONCURRENT_JOBS; different "
                "or identical configured repository URLs use isolated worktrees; "
                "focus_path concurrency remains caller-managed; raise the limit only "
                "when the LLM backend and host capacity can handle parallel scans"
            ),
        ),
        jobs=JobBackendInfo(
            job_store="in_memory",
            execution_model="bounded asyncio background tasks in this API process",
            known_jobs=len(jobs),
            max_concurrent_jobs=max_concurrent_jobs,
            running_jobs=running_jobs,
            queued_jobs=queued_jobs,
            available_slots=max(0, max_concurrent_jobs - running_jobs),
            status_counts=status_counts,
        ),
    )


def _service_info_response(owner: str) -> HealthResponse:
    metadata = _llm_metadata(
        app.state.ollama,
        healthy=getattr(app.state, "llm_healthy", None),
    )
    return HealthResponse(
        status="ok",
        model=metadata.get("model"),
        llm_backend=metadata.get("host") or metadata.get("backend"),
        llm_provider=metadata.get("provider"),
        llm=metadata,
        configuration=_service_configuration(),
        backend=_backend_information(owner),
    )


def _build_inconclusive(
    reason: str,
    *,
    vuln_id: str = "",
    component_name: str = "",
    llm_conversation: list[dict[str, Any]] | None = None,
) -> AssessResponse:
    target = component_name.strip() or "the assessed component"
    identifier = vuln_id.strip() or "The advisory"
    return AssessResponse(
        assessment=Assessment(
            affected=False,
            verdict="Inconclusive",
            confidence="Low",
            exposure="unknown",
            advisory_relevance=None,
            version_analysis=None,
            researcher_view=None,
            remediation_view=None,
            audit_view=None,
            executive_summary={
                "vulnerability": (
                    f"{identifier} · assessment target {target}: advisory processing "
                    "did not complete."
                ),
                "assessment": (
                    "Disposition: Inconclusive. Confidence: Low. Exposure: unknown. "
                    f"Basis: {reason}"
                ),
                "why": [f"Assessment conclusion: {reason}"],
            },
            summary="",
            reasoning=reason,
            analysis=AnalysisState.IN_TRIAGE,
            justification=AnalysisJustification.NOT_SET,
            response=AnalysisResponse.NOT_SET,
            details=reason,
            cvss_vector=None,
            cvss_score=None,
        ),
        steps=[],
        llm_conversation=llm_conversation or [],
    )


async def _run_assessment(
    req: AssessRequest,
    progress_callback: Any | None = None,
    llm_client: LLMClient | None = None,
) -> AssessResponse:
    """Execute the pipeline and return the structured response."""
    repos = _get_repos_config()
    repos_cfg = repos.get("components", {})
    comp = repos_cfg.get(req.component_name)

    if not comp:
        # Try resolving via defaults template + optional alias mapping
        defaults = repos.get("defaults")
        if defaults:
            aliases = repos.get("aliases") or {}
            repo_name = aliases.get(req.component_name, req.component_name)
            comp = {
                k: v.replace("{name}", repo_name) if isinstance(v, str) else v
                for k, v in defaults.items()
            }
            logger.info(
                "Component '%s' resolved via defaults template (repo_name='%s')",
                req.component_name,
                repo_name,
            )

    if not comp:
        if req.focus_path:
            # Allow ad-hoc assessments against a local path without a config entry.
            comp = {"name": req.component_name, "path": req.focus_path}
            logger.info(
                "Component '%s' not in repos.yaml — using focus_path=%s",
                req.component_name,
                req.focus_path,
            )
        else:
            logger.warning("Component '%s' not found in repos.yaml", req.component_name)
            return _build_inconclusive(
                "Component mapping not found in config/repos.yaml",
                vuln_id=req.vuln_id,
                component_name=req.component_name,
            )

    comp = dict(comp)
    if (
        "project_version_files" not in comp
        and "project_version_files" in repos
    ):
        comp["project_version_files"] = repos["project_version_files"]
    comp.setdefault("name", req.component_name)

    active_llm_client = llm_client or _client_for_request(req)

    try:
        result = await run_pipeline(
            req.vuln_id,
            comp,
            ollama=active_llm_client,
            dependency_paths=req.dependency_paths,
            affected_product_versions=(
                req.project_versions
                if req.project_versions is not None
                else req.__dict__.get("affected_product_versions")
            ),
            focus_path=req.focus_path,
            user_guidance=req.user_guidance,
            cvss_vector=req.cvss_vector,
            progress_callback=progress_callback,
            debug=req.debug,
        )
    except RepoError as exc:
        logger.error("Repository error for '%s': %s", req.component_name, exc)
        return _build_inconclusive(
            f"Repository error: {exc}",
            vuln_id=req.vuln_id,
            component_name=req.component_name,
            llm_conversation=list(
                getattr(active_llm_client, "conversation_trace", []) or []
            ),
        )
    except Exception as exc:
        logger.exception("Pipeline failed for '%s'", req.component_name)
        message = str(exc).strip() or exc.__class__.__name__
        return _build_inconclusive(
            f"Internal pipeline error: {message}",
            vuln_id=req.vuln_id,
            component_name=req.component_name,
            llm_conversation=list(
                getattr(active_llm_client, "conversation_trace", []) or []
            ),
        )
    assessment = result["assessment"]
    logger.info(
        "Pipeline complete: verdict=%s  confidence=%s",
        assessment.get("verdict"),
        assessment.get("confidence"),
    )
    return AssessResponse(
        assessment=Assessment(**assessment),
        steps=[StepFindings(**s) for s in result.get("steps", [])],
        llm_conversation=list(
            getattr(active_llm_client, "conversation_trace", []) or []
        ),
    )


async def _run_job(job: Job) -> None:
    """Background task that executes the pipeline for a job."""
    job.current_activity = "Waiting for analyzer execution slot"
    job.last_updated_at = _now_iso()
    try:
        semaphore = getattr(app.state, "job_semaphore", None)
        if semaphore is None:
            await _run_job_with_slot(job)
        else:
            async with semaphore:
                await _run_job_with_slot(job)
    except asyncio.CancelledError:
        logger.info("Job %s cancelled", job.id)
        job.status = JobStatus.cancelled
        job.active_agents.clear()
        job.current_activity = "Assessment cancelled"
        job.error = "Cancelled by request."
        append_job_log(job, "Assessment cancelled", level="warning")
    except Exception as exc:
        logger.exception("Job %s failed", job.id)
        job.status = JobStatus.failed
        message = str(exc).strip() or exc.__class__.__name__
        job.error = f"Internal pipeline error: {message}"
        append_job_log(job, job.error, level="error")
    finally:
        job.finished_at = _now_iso()


async def _run_job_with_slot(job: Job) -> None:
    job.status = JobStatus.running
    job.current_activity = "Waiting for the pipeline to start"
    job.last_updated_at = _now_iso()
    append_job_log(job, "Assessment job started")
    llm_client = _client_for_request(job.request)
    job.llm_metadata = _llm_metadata(llm_client)
    job.result = await _run_assessment(
        job.request,
        progress_callback=lambda event: apply_progress_event(job, event),
        llm_client=llm_client,
    )
    job.status = JobStatus.completed
    job.active_agents.clear()
    if not job.completed_step_names:
        job.total_steps = 1
        job.completed_steps = 1
    job.current_activity = "Assessment complete"
    append_job_log(job, "Assessment complete")
    _recompute_job_progress(job)


def _drop_job_task(job_id: str) -> None:
    tasks: Dict[str, asyncio.Task[Any]] = getattr(app.state, "job_tasks", {})
    tasks.pop(job_id, None)


def _as_model_dict(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(exclude_none=True)
        return dumped if isinstance(dumped, dict) else {}
    if isinstance(value, dict):
        return value
    return {}


def _compact_text(value: Any, limit: int = 1600) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _compact_mapping(value: Any, *, max_text: int = 800) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _compact_mapping(inner, max_text=max_text)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [_compact_mapping(inner, max_text=max_text) for inner in value[:12]]
    if isinstance(value, str):
        return _compact_text(value, max_text)
    return value


def _compact_job_context(job: Job) -> Dict[str, Any]:
    if not job.result:
        raise HTTPException(status_code=409, detail="Job result is not available.")

    result = _as_model_dict(job.result)
    assessment = _as_model_dict(result.get("assessment"))
    adjusted_cvss = _as_model_dict(assessment.get("adjusted_cvss"))
    steps = []
    for step in result.get("steps") or []:
        if not isinstance(step, dict):
            continue
        evidence = step.get("evidence") or []
        steps.append(
            {
                "step": step.get("step"),
                "title": _compact_text(step.get("title"), 240),
                "status": step.get("status"),
                "findings": _compact_mapping(step.get("findings"), max_text=500),
                "evidence": (
                    [_compact_text(entry, 600) for entry in evidence[:5]]
                    if isinstance(evidence, list)
                    else []
                ),
            }
        )

    return {
        "schema_version": "agentyzer.compact-context/v1",
        "compacted_at": _now_iso(),
        "job_id": job.id,
        "target": {
            "vuln_id": job.request.vuln_id,
            "component_name": job.request.component_name,
            "focus_path": job.request.focus_path,
            "dependency_paths": job.request.dependency_paths,
        },
        "verdict": {
            "affected": assessment.get("affected"),
            "verdict": assessment.get("verdict"),
            "confidence": assessment.get("confidence"),
            "exposure": assessment.get("exposure"),
            "analysis": assessment.get("analysis"),
            "justification": assessment.get("justification"),
            "response": assessment.get("response"),
        },
        "summary": _compact_text(assessment.get("summary"), 1600),
        "executive_summary": _compact_mapping(
            assessment.get("executive_summary"), max_text=600
        ),
        "reasoning": _compact_text(assessment.get("reasoning"), 2400),
        "details": _compact_text(assessment.get("details"), 2400),
        "cvss": {
            "original_score": adjusted_cvss.get("original_score"),
            "original_vector": adjusted_cvss.get("original_vector"),
            "adjusted_score": adjusted_cvss.get("adjusted_score"),
            "adjusted_vector": adjusted_cvss.get("adjusted_vector"),
            "summary": _compact_text(adjusted_cvss.get("summary"), 1200),
            "reasons": [
                _compact_text(reason, 400)
                for reason in (adjusted_cvss.get("reasons") or [])[:8]
            ],
        },
        "dependency_presence": _compact_mapping(assessment.get("dependency_presence")),
        "advisory_relevance": _compact_mapping(assessment.get("advisory_relevance")),
        "version_analysis": _compact_mapping(assessment.get("version_analysis")),
        "researcher_view": _compact_mapping(assessment.get("researcher_view")),
        "remediation_view": _compact_mapping(assessment.get("remediation_view")),
        "audit_view": _compact_mapping(assessment.get("audit_view")),
        "steps": steps,
    }


def _compact_context_prompt(context: Dict[str, Any]) -> str:
    return _compact_text(
        json.dumps(context, indent=2, sort_keys=True),
        _FOLLOW_UP_CONTEXT_PROMPT_LIMIT,
    )


def _build_follow_up_guidance(
    context: Dict[str, Any],
    question: str,
    extra_guidance: str | None,
) -> str:
    lines = [
        "Agentyzer follow-up assessment. Reuse the compact parent-job context below as background, and verify the answer against current code evidence.",
        "",
        "Follow-up question:",
        question.strip(),
        "",
        "Compact parent context:",
        _compact_context_prompt(context),
    ]
    if extra_guidance and extra_guidance.strip():
        lines.extend(["", "Additional reviewer guidance:", extra_guidance.strip()])
    return "\n".join(lines)


def _submit_async_job(
    req: AssessRequest,
    *,
    owner: str,
    parent_job_id: str | None = None,
    follow_up_question: str | None = None,
    compact_context: Dict[str, Any] | None = None,
) -> JobSubmittedResponse:
    job_id = uuid.uuid4().hex[:12]
    job = Job(job_id, req, owner=owner)
    job.llm_metadata = _llm_metadata(_client_for_request(req))
    job.parent_job_id = parent_job_id
    job.follow_up_question = follow_up_question
    job.compact_context = compact_context
    append_job_log(job, "Queued assessment job")
    if parent_job_id:
        append_job_log(job, f"Follow-up of job {parent_job_id}")
    app.state.jobs[job_id] = job
    task = asyncio.create_task(_run_job(job))
    app.state.job_tasks[job_id] = task
    task.add_done_callback(lambda _task: _drop_job_task(job_id))
    logger.info(
        "Job %s created for owner %s and component %s",
        job_id,
        owner,
        req.component_name,
    )
    return JobSubmittedResponse(
        job_id=job_id,
        status=job.status,
        poll_url=f"/jobs/{job_id}",
        model=job.llm_metadata.get("model"),
        llm_backend=job.llm_metadata.get("host") or job.llm_metadata.get("backend"),
        llm_provider=job.llm_metadata.get("provider"),
        llm=job.llm_metadata,
        configuration=_service_configuration(),
        backend=_backend_information(owner),
    )


# ===================================================================== #
# Endpoints                                                              #
# ===================================================================== #


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Check service health",
    description="Lightweight liveness probe that confirms the API process is accepting requests.",
)
async def health(
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    return _service_info_response(caller.owner)


@app.get(
    "/configuration",
    response_model=HealthResponse,
    tags=["system"],
    summary="Get service configuration",
    description=(
        "Return sanitized runtime configuration and backend information for API consumers. "
        "Repository credentials and raw authenticated URLs are never included."
    ),
)
async def configuration(
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    return _service_info_response(caller.owner)


@app.get(
    "/prompts",
    tags=["system"],
    summary="Inspect configured prompt bundles",
    description=(
        "Return prompt bundle metadata and, when requested, the configured system "
        "prompt text. Prompt values are omitted by default."
    ),
)
async def prompts(
    include_values: Annotated[
        bool,
        Query(description="Include prompt text values in the response."),
    ] = False,
    system_only: Annotated[
        bool,
        Query(description="Limit values to system prompts."),
    ] = True,
):
    return list_prompt_bundles(
        include_values=include_values,
        system_only=system_only,
    )


@app.post(
    "/benchmark/compare",
    response_model=BenchmarkCompareResponse,
    tags=["benchmark"],
    summary="Compare human and automated assessment artifacts",
    description=(
        "Probabilistically compare a human vulnerability assessment with an "
        "automated Agentyzer assessment result. This endpoint evaluates the "
        "assessment artifacts only; it does not run repository or source-code analysis."
    ),
)
async def benchmark_compare(req: BenchmarkCompareRequest):
    benchmark = req.benchmark or {}
    if not isinstance(benchmark, dict):
        raise HTTPException(status_code=400, detail="benchmark must be an object")

    if not getattr(app.state, "llm_healthy", False):
        return deterministic_benchmark_fallback(
            benchmark,
            reason="LLM backend is not healthy; returned deterministic fallback.",
        )

    llm_client = _client_for_model(req.model)
    return await compare_benchmark_with_llm(benchmark, llm_client)


@app.post(
    "/assess",
    response_model=AssessResponse | JobSubmittedResponse,
    tags=["assessment"],
    summary="Start a vulnerability assessment",
    description=(
        "Submit a vulnerability assessment request. By default the API enqueues a background job and returns a poll URL. "
        "Pass `sync=true` to wait for completion and receive the full assessment immediately."
    ),
    responses={
        200: {
            "description": "Assessment completed synchronously or a background job was accepted.",
            "content": {
                "application/json": {
                    "examples": {
                        "syncResult": {
                            "summary": "Completed synchronous assessment",
                            "value": ASSESS_RESPONSE_EXAMPLE,
                        },
                        "asyncJob": {
                            "summary": "Accepted asynchronous assessment job",
                            "value": JOB_SUBMITTED_EXAMPLE,
                        },
                    }
                }
            },
        }
    },
)
async def assess(
    req: Annotated[
        AssessRequest,
        Body(
            openapi_examples={
                "syncAssessment": ASSESS_SYNC_REQUEST_EXAMPLE,
                "asyncAssessment": ASSESS_ASYNC_REQUEST_EXAMPLE,
            }
        ),
    ],
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
    sync: Annotated[
        bool,
        Query(
            description="When true, block until the assessment completes and return the result instead of a job handle.",
            examples=[True],
        ),
    ] = False,
):
    """Submit a vulnerability assessment.

    By default the pipeline runs asynchronously and a job ID is returned
    for polling.  Pass ``?sync=true`` to block until the result is ready
    (original behaviour).
    """
    logger.info(
        "POST /assess  vuln_id=%s  component_name=%s  sync=%s",
        req.vuln_id,
        req.component_name,
        sync,
    )

    if sync:
        semaphore = getattr(app.state, "job_semaphore", None)
        if semaphore is None:
            return await _run_assessment(req, llm_client=_client_for_request(req))
        async with semaphore:
            return await _run_assessment(req, llm_client=_client_for_request(req))

    # Async mode — create a job and return immediately.
    return _submit_async_job(req, owner=caller.owner)


@app.get(
    "/jobs",
    response_model=JobListResponse,
    response_model_exclude_none=True,
    tags=["jobs"],
    summary="List assessment jobs",
    description="Return all in-memory background jobs known to the current API process.",
)
async def list_jobs(
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    """List all known jobs."""
    jobs = _jobs_visible_to(caller.owner)
    configuration = _service_configuration()
    backend = _backend_information(caller.owner)
    return JobListResponse(
        jobs=[
            job_status_response(j)
            for j in jobs.values()
        ],
        configuration=configuration,
        backend=backend,
    )


@app.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    tags=["jobs"],
    summary="Get job status",
    description="Retrieve the current state of a previously submitted asynchronous assessment job.",
    responses={
        404: {
            "model": ErrorResponse,
            "description": "The requested job ID does not exist.",
        }
    },
)
async def get_job_status(
    job_id: str,
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    """Poll the status of a submitted job."""
    job = _job_for_caller(job_id, caller)
    return job_status_response(
        job,
        configuration=_service_configuration(),
        backend=_backend_information(caller.owner),
    )


@app.get(
    "/jobs/{job_id}/result",
    response_model=AssessResponse,
    tags=["jobs"],
    summary="Fetch completed job result",
    description="Return the full assessment payload for a completed asynchronous job.",
    responses={
        404: {
            "model": ErrorResponse,
            "description": "The requested job ID does not exist.",
        },
        409: {"model": ErrorResponse, "description": "The job has not completed yet."},
        500: {
            "model": ErrorResponse,
            "description": "The job failed while running the pipeline.",
        },
    },
)
async def get_job_result(
    job_id: str,
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    """Retrieve the result of a completed job."""
    job = _job_for_caller(job_id, caller)
    if job.status == JobStatus.failed:
        raise HTTPException(status_code=500, detail=job.error or "Job failed")
    if job.status != JobStatus.completed:
        raise HTTPException(
            status_code=409,
            detail=f"Job is still {job.status.value}; poll /jobs/{job_id} until completed",
        )
    return job.result


@app.post(
    "/jobs/{job_id}/compact",
    response_model=CompactContextResponse,
    tags=["jobs"],
    summary="Compact a completed job for follow-up context",
    description="Return a concise structured context extracted from a completed assessment job.",
    responses={
        404: {
            "model": ErrorResponse,
            "description": "The requested job ID does not exist.",
        },
        409: {"model": ErrorResponse, "description": "The job has no result yet."},
    },
)
async def compact_job(
    job_id: str,
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    job = _job_for_caller(job_id, caller)
    context = _compact_job_context(job)
    return CompactContextResponse(
        job_id=job.id,
        compacted_at=context["compacted_at"],
        context=context,
        prompt_context=_compact_context_prompt(context),
    )


@app.post(
    "/jobs/{job_id}/follow-up",
    response_model=JobSubmittedResponse,
    tags=["jobs"],
    summary="Start a follow-up assessment from compacted parent context",
    description=(
        "Create a new asynchronous assessment job using the parent job request "
        "and compacted result context as guidance."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "The requested parent job ID does not exist.",
        },
        409: {"model": ErrorResponse, "description": "The parent job has no result yet."},
    },
)
async def follow_up_job(
    job_id: str,
    req: FollowUpRequest,
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    parent = _job_for_caller(job_id, caller)
    context = _compact_job_context(parent)
    question = req.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Follow-up question is required.")

    parent_request = parent.request
    follow_up_request = AssessRequest(
        vuln_id=req.vuln_id or parent_request.vuln_id,
        component_name=req.component_name or parent_request.component_name,
        project_name=parent_request.project_name,
        cvss_vector=req.cvss_vector or parent_request.cvss_vector,
        focus_path=(
            req.focus_path
            if req.focus_path is not None
            else parent_request.focus_path
        ),
        dependency_paths=(
            req.dependency_paths
            if req.dependency_paths is not None
            else parent_request.dependency_paths
        ),
        user_guidance=_build_follow_up_guidance(
            context,
            question,
            req.user_guidance,
        ),
        model=req.model or parent_request.model,
        llm_backend=req.llm_backend or parent_request.llm_backend,
        llm_provider=req.llm_provider or parent_request.llm_provider,
        debug=req.debug or parent_request.debug,
    )
    return _submit_async_job(
        follow_up_request,
        owner=caller.owner,
        parent_job_id=parent.id,
        follow_up_question=question,
        compact_context=context,
    )


@app.delete(
    "/jobs/{job_id}",
    status_code=204,
    tags=["jobs"],
    summary="Cancel or delete a job",
    description=(
        "Cancel a pending/running job or remove a completed, failed, or cancelled "
        "job from the in-memory job store."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "The requested job ID does not exist.",
        },
        409: {
            "model": ErrorResponse,
            "description": "The job cannot be cancelled or removed in its current state.",
        },
    },
)
async def delete_job(
    job_id: str,
    caller: Annotated[ServiceCaller, Depends(require_service_caller)],
):
    """Cancel running work or remove a finished job from memory."""
    jobs: Dict[str, Job] = app.state.jobs
    job = _job_for_caller(job_id, caller)
    if job.status in (JobStatus.pending, JobStatus.running):
        tasks: Dict[str, asyncio.Task[Any]] = getattr(app.state, "job_tasks", {})
        task = tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        job.status = JobStatus.cancelled
        job.finished_at = _now_iso()
        job.error = "Cancelled by request."
        job.active_agents.clear()
        job.current_activity = "Assessment cancelled"
        append_job_log(job, "Assessment cancelled by request.", level="warning")
        return None
    del jobs[job_id]
