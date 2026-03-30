import asyncio
import httpx
import json
import logging
import os
import shutil
import socket
import tomllib
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth import auth_settings, get_current_user
from auth import router as auth_router
from dt_client import DTClient, DTSettings, get_client
from logic import (
    BOMAnalysisCache,
    calculate_aggregated_state,
    calculate_statistics,
    get_rescore_rules_path,
    get_team_mapping_path,
    get_user_role,
    get_user_roles_path,
    group_vulnerabilities,
    load_rescore_rules,
    load_team_mapping,
    load_user_roles,
    process_assessment_details,
)
from version import BUILD_COMMIT, VERSION
from tmrescore_integration import (
    SUPPORTED_TMRESCORE_SCOPES,
    TMRescoreClient,
    TMRescoreSettings,
    build_analysis_sbom,
    build_dtvp_vulnerability_proposals,
    build_tmrescore_proposals,
    get_tmrescore_generated_at,
    is_meaningful_tmrescore_proposal,
    normalize_tmrescore_snapshot,
    sort_projects_by_version,
)

logger = logging.getLogger("dtvp")
logger.setLevel(logging.INFO)


def get_tmrescore_cache_path() -> str:
    configured_path = os.getenv("DTVP_TMRESCORE_CACHE_PATH", "").strip()
    if configured_path:
        return configured_path
    return os.path.join(os.getcwd(), "data", "tmrescore_proposals.json")


def load_tmrescore_project_cache() -> Dict[str, Dict[str, Any]]:
    cache_path = get_tmrescore_cache_path()
    if not os.path.exists(cache_path):
        return {}

    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        logger.warning("Failed to load tmrescore cache from %s: %s", cache_path, exc)
        return {}

    if not isinstance(payload, dict):
        return {}

    return {
        project_name: normalize_tmrescore_snapshot(snapshot)
        for project_name, snapshot in payload.items()
        if isinstance(snapshot, dict)
    }


def save_tmrescore_project_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    cache_path = get_tmrescore_cache_path()
    cache_dir = os.path.dirname(cache_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)

    temp_path = f"{cache_path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, sort_keys=True)
    os.replace(temp_path, cache_path)


def persist_tmrescore_project_snapshot(
    project_name: str,
    snapshot: Dict[str, Any],
) -> None:
    normalized_snapshot = normalize_tmrescore_snapshot(snapshot)
    tmrescore_project_cache[project_name] = normalized_snapshot
    save_tmrescore_project_cache(tmrescore_project_cache)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting DTVP version {VERSION} (build {BUILD_COMMIT})")
    tmrescore_project_cache.clear()
    tmrescore_project_cache.update(load_tmrescore_project_cache())
    yield


app = FastAPI(title="DTVP", version=VERSION, lifespan=lifespan)


# CORS for frontend dev
# Optionally override via environment variable (comma-separated)
cors_from_env = os.getenv("DTVP_CORS_ORIGINS")
if cors_from_env:
    origins = [o.strip() for o in cors_from_env.split(",") if o.strip()]
else:
    origins = [
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ]
    if auth_settings.FRONTEND_URL:
        frontend_url = auth_settings.FRONTEND_URL.rstrip("/")
        if frontend_url not in origins:
            origins.append(frontend_url)

    try:
        _hostname = socket.gethostname()
        for _port in ("5173", "8000"):
            _origin = f"http://{_hostname}:{_port}"
            if _origin not in origins:
                origins.append(_origin)
    except Exception:
        pass

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prefix all routes if CONTEXT_PATH is set
context_path = auth_settings.CONTEXT_PATH.rstrip("/")
if context_path and not context_path.startswith("/"):
    context_path = "/" + context_path

# Auth router
app.include_router(auth_router, prefix=context_path)

# API Router
api_router = APIRouter(prefix="/api", tags=["api"])


def load_pyproject_metadata():
    pyproject_file = os.path.join(os.getcwd(), "pyproject.toml")
    if not os.path.exists(pyproject_file):
        return {}
    with open(pyproject_file, "rb") as f:
        data = tomllib.load(f)
    project = data.get("project", {})
    return {
        "name": project.get("name"),
        "version": project.get("version"),
        "authors": project.get("authors", []),
        "urls": project.get("urls", {}),
    }


@api_router.get("/version")
def get_version():
    return {"version": VERSION, "build": BUILD_COMMIT}


@api_router.get("/metadata")
def get_metadata():
    metadata = load_pyproject_metadata()
    if not metadata:
        raise HTTPException(status_code=404, detail="pyproject.toml metadata not found")
    return metadata


@api_router.get("/changelog")
def get_changelog():
    changelog_path = os.path.join(os.getcwd(), "CHANGELOG.md")
    if os.path.exists(changelog_path):
        with open(changelog_path, "r") as f:
            return {"content": f.read()}
    return {"content": "Changelog not available."}


@api_router.get("/sbom")
def get_sbom():
    # Default SBOM for legacy compatibility. Prefer backend/frontend explicit endpoints.
    sbom_path = os.path.join(os.getcwd(), "sbom", "dtvp-backend-cyclonedx.json")
    if os.path.exists(sbom_path):
        return FileResponse(
            sbom_path,
            media_type="application/json",
            filename="dtvp-backend-cyclonedx.json",
        )

    raise HTTPException(
        status_code=404,
        detail="Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
    )


@api_router.get("/sbom/backend")
def get_sbom_backend():
    sbom_path = os.path.join(os.getcwd(), "sbom", "dtvp-backend-cyclonedx.json")
    if os.path.exists(sbom_path):
        return FileResponse(
            sbom_path,
            media_type="application/json",
            filename="dtvp-backend-cyclonedx.json",
        )

    raise HTTPException(
        status_code=404,
        detail="Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
    )


@api_router.get("/sbom/frontend")
def get_sbom_frontend():
    sbom_path = os.path.join(os.getcwd(), "sbom", "dtvp-frontend-cyclonedx.json")
    if os.path.exists(sbom_path):
        return FileResponse(
            sbom_path,
            media_type="application/json",
            filename="dtvp-frontend-cyclonedx.json",
        )

    raise HTTPException(
        status_code=404,
        detail="Frontend SBOM not available. Generate in CI and include in container at /sbom/dtvp-frontend-cyclonedx.json.",
    )


@api_router.get("/sbom/html")
def get_sbom_html():
    sbom_path = os.path.join(os.getcwd(), "sbom", "dtvp-cyclonedx.json")
    if not os.path.exists(sbom_path):
        raise HTTPException(
            status_code=404,
            detail="SBOM not available. Generate in CI and include in container at /sbom/dtvp-cyclonedx.json.",
        )

    with open(sbom_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(
        f"<html><head><title>DTVP SBOM</title></head><body><h1>DTVP CycloneDX SBOM</h1><p><a href='/api/sbom'>Download JSON</a></p><pre>{content}</pre></body></html>",
        media_type="text/html",
    )


# Models
class AssessmentRequest(BaseModel):
    instances: List[dict]  # List of instance objects from the group
    state: str
    details: str
    comment: Optional[str] = None
    justification: Optional[str] = None
    suppressed: bool = False
    team: Optional[str] = None
    original_analysis: Optional[Dict[str, Dict[str, Any]]] = None
    force: bool = False
    comparison_mode: Optional[str] = "MERGE"


class AssessmentDetailsRequest(BaseModel):
    instances: List[dict]


@api_router.get("/projects")
async def search_projects(
    name: Optional[str] = None,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    # DT API expects optional name filter. If absent, list all projects.
    try:
        return await client.get_projects(name or "")
    except Exception as e:
        logger.error("Error fetching projects from Dependency-Track: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Dependency-Track unavailable for project search. Please check DT server settings.",
        )


# Job Manager
tasks = {}
tmrescore_project_cache: Dict[str, Dict[str, Any]] = {}
tmrescore_analysis_tasks: Dict[str, Dict[str, Any]] = {}


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str
    progress: int = 0
    result: Optional[List[dict]] = None


def get_tmrescore_task_ttl_seconds() -> int:
    raw_value = os.getenv("DTVP_TMRESCORE_TASK_TTL_SECONDS", "3600")
    try:
        return max(60, int(raw_value))
    except (TypeError, ValueError):
        logger.warning(
            "Invalid DTVP_TMRESCORE_TASK_TTL_SECONDS=%r, falling back to 3600",
            raw_value,
        )
        return 3600


def touch_tmrescore_analysis_task(
    task: Dict[str, Any],
    *,
    mark_terminal: bool = False,
) -> None:
    now = datetime.now().timestamp()
    task["updated_at"] = now
    if mark_terminal:
        task["completed_at"] = now


def prune_tmrescore_analysis_tasks(now: Optional[float] = None) -> None:
    current_time = now if now is not None else datetime.now().timestamp()
    ttl_seconds = get_tmrescore_task_ttl_seconds()

    expired_session_ids = []
    for session_id, task in tmrescore_analysis_tasks.items():
        status = str(task.get("status") or "").lower()
        if status not in {"completed", "failed"}:
            continue
        completed_at = task.get("completed_at") or task.get("updated_at") or task.get("created_at")
        if completed_at is None:
            continue
        if current_time - float(completed_at) >= ttl_seconds:
            expired_session_ids.append(session_id)

    for session_id in expired_session_ids:
        tmrescore_analysis_tasks.pop(session_id, None)


def append_tmrescore_analysis_log(task: Dict[str, Any], message: str) -> None:
    if not message:
        return
    log_entries = task.setdefault("log", [])
    if not log_entries or log_entries[-1] != message:
        log_entries.append(message)
    touch_tmrescore_analysis_task(task)


def build_tmrescore_analysis_response(
    result: Dict[str, Any],
    task: Dict[str, Any],
) -> Dict[str, Any]:
    session = task["session"]
    session_id = result.get("session_id") or session.get("session_id")
    return {
        **result,
        "session": session,
        "scope": task["scope"],
        "recommended_scope": "merged_versions",
        "latest_version": task["latest_version"],
        "analyzed_versions": task["analyzed_versions"],
        "sbom_component_count": task["sbom_component_count"],
        "sbom_vulnerability_count": task["sbom_vulnerability_count"],
        "strategy_note": task["strategy_note"],
        "llm_enrichment": task["llm_enrichment"],
        "download_urls": {
            "json": f"{context_path}/api/tmrescore/sessions/{session_id}/results/json",
            "vex": f"{context_path}/api/tmrescore/sessions/{session_id}/results/vex",
        },
    }


def build_tmrescore_cached_state(
    task: Dict[str, Any],
    *,
    include_result: bool = False,
) -> Dict[str, Any]:
    status = str(task.get("status") or "running")
    return {
        "session_id": task["session_id"],
        "status": status,
        "progress": int(task.get("progress") or 0),
        "message": task.get("message") or describe_tmrescore_progress(status, int(task.get("progress") or 0)),
        "log": task.get("log") or [],
        "error": task.get("error"),
        "scope": task.get("scope"),
        "latest_version": task.get("latest_version"),
        "analyzed_versions": task.get("analyzed_versions") or [],
        "llm_enrichment": task.get("llm_enrichment") or {"enabled": False, "ollama_model": None},
        "created_at": task.get("created_at"),
        "updated_at": task.get("updated_at"),
        "completed_at": task.get("completed_at"),
        "result": task.get("result") if include_result else None,
    }


def get_latest_tmrescore_project_task(project_name: str) -> Optional[Dict[str, Any]]:
    matching_tasks = [
        task
        for task in tmrescore_analysis_tasks.values()
        if task.get("project_name") == project_name
    ]
    if not matching_tasks:
        return None
    return max(
        matching_tasks,
        key=lambda task: float(task.get("updated_at") or task.get("created_at") or 0.0),
    )


def cache_tmrescore_project_results(
    project_name: str,
    session_id: str,
    scope: str,
    latest_version: str,
    analyzed_versions: List[str],
    vex_results_document: Dict[str, Any],
    dtvp_original_proposals: Optional[Dict[str, Dict[str, Any]]] = None,
) -> None:
    generated_at = get_tmrescore_generated_at(vex_results_document)
    primary_proposals = build_tmrescore_proposals(vex_results_document)
    dtvp_original_proposals = dtvp_original_proposals or {}

    merged_proposals: Dict[str, Dict[str, Any]] = {}
    for vuln_id, proposal in primary_proposals.items():
        original_proposal = dtvp_original_proposals.get(vuln_id, {})
        merged_refs = set(original_proposal.get("affected_refs") or [])
        merged_refs.update(proposal.get("affected_refs") or [])
        merged_proposal = dict(original_proposal)
        for key, value in proposal.items():
            if key == "affected_refs":
                continue
            if value is not None:
                merged_proposal[key] = value
            elif key not in merged_proposal:
                merged_proposal[key] = value
        merged_candidate = {
            **merged_proposal,
            "affected_refs": sorted(ref for ref in merged_refs if ref),
        }
        if is_meaningful_tmrescore_proposal(merged_candidate):
            merged_proposals[vuln_id] = merged_candidate

    persist_tmrescore_project_snapshot(project_name, {
        "project_name": project_name,
        "session_id": session_id,
        "scope": scope,
        "latest_version": latest_version,
        "analyzed_versions": analyzed_versions,
        "generated_at": generated_at,
        "proposals": {
            vuln_id: {
                **proposal,
                "session_id": session_id,
                "scope": scope,
                "latest_version": latest_version,
                "analyzed_versions": analyzed_versions,
                "generated_at": generated_at,
            }
            for vuln_id, proposal in merged_proposals.items()
        },
    })


def describe_tmrescore_progress(status: str, progress: int) -> str:
    normalized_status = (status or "running").lower()
    if normalized_status == "completed":
        return "TMRescore analysis completed."
    if normalized_status == "failed":
        return "TMRescore analysis failed."
    if progress >= 95:
        return "Finalizing tmrescore outputs..."
    if progress >= 75:
        return "Rescoring vulnerabilities against the threat model..."
    if progress >= 45:
        return "Correlating threat model data with the synthetic SBOM..."
    if progress >= 20:
        return "Uploading analysis inputs to tmrescore..."
    return "Preparing tmrescore analysis session..."


async def wait_for_tmrescore_completion(
    task: Dict[str, Any],
    tmrescore_client: TMRescoreClient,
    max_wait_seconds: float,
) -> None:
    session_id = task["session_id"]
    deadline = asyncio.get_running_loop().time() + max_wait_seconds

    while True:
        progress_payload = await tmrescore_client.get_progress(session_id)
        status = str(progress_payload.get("status") or task.get("status") or "running")
        progress = int(progress_payload.get("progress") or task.get("progress") or 0)
        message = progress_payload.get("message") or describe_tmrescore_progress(status, progress)
        normalized_status = status.lower()

        task["status"] = status
        task["progress"] = max(int(task.get("progress") or 0), min(progress, 100))
        task["message"] = message
        touch_tmrescore_analysis_task(task, mark_terminal=normalized_status in {"completed", "failed"})
        append_tmrescore_analysis_log(task, message)

        if normalized_status == "completed":
            return
        if normalized_status == "failed":
            raise RuntimeError(progress_payload.get("error") or progress_payload.get("detail") or message)
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(
                f"Timed out while waiting for tmrescore analysis session {session_id} to complete"
            )
        await asyncio.sleep(1.5)


async def run_tmrescore_analysis_task(
    task: Dict[str, Any],
    settings: TMRescoreSettings,
    project_name: str,
    threatmodel_bytes: bytes,
    synthetic_sbom: Dict[str, Any],
    dtvp_original_proposals: Dict[str, Dict[str, Any]],
    items_csv_bytes: Optional[bytes],
    config_bytes: Optional[bytes],
    chain_analysis: bool,
    prioritize: bool,
    what_if: bool,
    enrich: bool,
    ollama_model: str,
) -> None:
    session_id = task["session_id"]
    max_wait_seconds = max(settings.DTVP_TMRESCORE_TIMEOUT_SECONDS * 4, 900.0)

    try:
        async with TMRescoreClient(settings) as tmrescore_client:
            task["status"] = "running"
            task["progress"] = max(int(task.get("progress") or 0), 25)
            task["message"] = "Uploading analysis inputs to tmrescore..."
            touch_tmrescore_analysis_task(task)
            append_tmrescore_analysis_log(task, task["message"])

            service_result: Optional[Dict[str, Any]] = None
            try:
                service_result = await tmrescore_client.analyze_inventory(
                    session_id,
                    threatmodel_bytes=threatmodel_bytes,
                    sbom_bytes=json.dumps(synthetic_sbom).encode("utf-8"),
                    items_csv_bytes=items_csv_bytes,
                    config_bytes=config_bytes,
                    chain_analysis=chain_analysis,
                    prioritize=prioritize,
                    what_if=what_if,
                    enrich=enrich,
                    ollama_model=ollama_model if enrich else None,
                )
            except (httpx.ReadTimeout, httpx.TimeoutException):
                task["message"] = "TMRescore is still processing remotely. Polling progress..."
                append_tmrescore_analysis_log(task, task["message"])
                await wait_for_tmrescore_completion(task, tmrescore_client, max_wait_seconds)
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code in {502, 503, 504}:
                    task["message"] = (
                        f"TMRescore returned HTTP {exc.response.status_code} while still running. Polling progress..."
                    )
                    append_tmrescore_analysis_log(task, task["message"])
                    await wait_for_tmrescore_completion(task, tmrescore_client, max_wait_seconds)
                else:
                    raise

            if service_result is not None:
                returned_status = str(service_result.get("status") or "completed")
                if returned_status.lower() == "failed":
                    raise RuntimeError(service_result.get("error") or "TMRescore analysis failed")
                if returned_status.lower() != "completed":
                    task["status"] = returned_status
                    task["progress"] = max(int(task.get("progress") or 0), int(service_result.get("progress") or 70))
                    task["message"] = service_result.get("message") or describe_tmrescore_progress(returned_status, task["progress"])
                    touch_tmrescore_analysis_task(task)
                    append_tmrescore_analysis_log(task, task["message"])
                    await wait_for_tmrescore_completion(task, tmrescore_client, max_wait_seconds)

            final_service_result = service_result or await tmrescore_client.get_results(session_id)
            vex_results = await tmrescore_client.get_results_vex(session_id)

            cache_tmrescore_project_results(
                project_name,
                session_id,
                task["scope"],
                task["latest_version"],
                task["analyzed_versions"],
                vex_results,
                dtvp_original_proposals,
            )

            final_result = build_tmrescore_analysis_response(final_service_result, task)
            task["status"] = "completed"
            task["progress"] = 100
            task["message"] = "TMRescore analysis completed."
            task["result"] = final_result
            task["error"] = None
            touch_tmrescore_analysis_task(task, mark_terminal=True)
            append_tmrescore_analysis_log(task, task["message"])
    except Exception as exc:
        logger.warning(
            "TMRescore analysis task for %s session %s failed: %s",
            project_name,
            session_id,
            exc,
        )
        task["status"] = "failed"
        task["error"] = str(exc)
        task["message"] = str(exc)
        task["progress"] = 100
        touch_tmrescore_analysis_task(task, mark_terminal=True)
        append_tmrescore_analysis_log(task, f"TMRescore analysis failed: {exc}")


def get_version_fetch_concurrency() -> int:
    raw_value = os.getenv("DTVP_VERSION_FETCH_CONCURRENCY", "4")
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        logger.warning(
            "Invalid DTVP_VERSION_FETCH_CONCURRENCY=%r, falling back to 4",
            raw_value,
        )
        return 4


def merge_vulnerability_details(
    findings: List[Dict[str, Any]],
    full_vulns: List[Dict[str, Any]],
) -> Dict[str, int]:
    vuln_map = {vuln.get("vulnId"): vuln for vuln in full_vulns}
    severity_counts: Dict[str, int] = {}

    for finding in findings:
        vuln_summary = finding.get("vulnerability", {})
        vuln_id = vuln_summary.get("vulnId")
        severity_label = (vuln_summary.get("severity") or "UNKNOWN").upper()
        severity_counts[severity_label] = severity_counts.get(severity_label, 0) + 1

        full_vuln = vuln_map.get(vuln_id)
        if not full_vuln:
            continue

        for key in [
            "cvssV4Vector",
            "cvssV4BaseScore",
            "cvssV3Vector",
            "cvssV3BaseScore",
            "cvssV2Vector",
            "cvssV2BaseScore",
            "aliases",
        ]:
            if key in full_vuln and key not in vuln_summary:
                vuln_summary[key] = full_vuln[key]

    return severity_counts


async def fetch_version_snapshot(
    client: DTClient,
    version_info: Dict[str, Any],
    cve: Optional[str],
    team_mapping: Dict[str, Any],
) -> tuple[Dict[str, Any], BOMAnalysisCache, Dict[str, int]]:
    findings_result, full_vulns_result, bom_result = await asyncio.gather(
        client.get_vulnerabilities(version_info["uuid"], cve=cve),
        client.get_project_vulnerabilities(version_info["uuid"]),
        client.get_bom(version_info["uuid"]),
        return_exceptions=True,
    )

    if isinstance(findings_result, Exception):
        raise findings_result
    if isinstance(full_vulns_result, Exception):
        raise full_vulns_result

    severity_counts = merge_vulnerability_details(findings_result, full_vulns_result)

    if isinstance(bom_result, Exception):
        bom_cache = BOMAnalysisCache({}, team_mapping)
    else:
        bom_cache = BOMAnalysisCache(bom_result or {}, team_mapping)

    return (
        {"version": version_info, "vulnerabilities": findings_result},
        bom_cache,
        severity_counts,
    )


async def collect_version_snapshots(
    versions: List[Dict[str, Any]],
    client: DTClient,
    cve: Optional[str],
    team_mapping: Dict[str, Any],
    progress_callback=None,
) -> tuple[List[Dict[str, Any]], Dict[str, BOMAnalysisCache], Dict[str, Dict[str, int]]]:
    concurrency = min(get_version_fetch_concurrency(), len(versions)) if versions else 1
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Optional[tuple[Dict[str, Any], BOMAnalysisCache, Dict[str, int]]]] = [None] * len(versions)

    async def worker(index: int, version_info: Dict[str, Any]):
        async with semaphore:
            combined_entry, bom_cache, severity_counts = await fetch_version_snapshot(
                client,
                version_info,
                cve,
                team_mapping,
            )
            return index, version_info, combined_entry, bom_cache, severity_counts

    pending = [
        asyncio.create_task(worker(index, version_info))
        for index, version_info in enumerate(versions)
    ]

    completed = 0
    try:
        for pending_task in asyncio.as_completed(pending):
            index, version_info, combined_entry, bom_cache, severity_counts = await pending_task
            results[index] = (combined_entry, bom_cache, severity_counts)
            completed += 1
            if progress_callback:
                progress_callback(completed, len(versions), version_info)
    finally:
        for pending_task in pending:
            if not pending_task.done():
                pending_task.cancel()

    combined_data = []
    bom_cache_map = {}
    version_severity_counts = {}
    for result in results:
        if result is None:
            continue
        combined_entry, bom_cache, severity_counts = result
        version_info = combined_entry["version"]
        combined_data.append(combined_entry)
        bom_cache_map[version_info["uuid"]] = bom_cache
        version_severity_counts[version_info.get("version")] = severity_counts

    return combined_data, bom_cache_map, version_severity_counts


async def fetch_version_analysis_input(
    client: DTClient,
    version_info: Dict[str, Any],
) -> Dict[str, Any]:
    findings_result, full_vulns_result, bom_result = await asyncio.gather(
        client.get_vulnerabilities(version_info["uuid"]),
        client.get_project_vulnerabilities(version_info["uuid"]),
        client.get_bom(version_info["uuid"]),
        return_exceptions=True,
    )

    if isinstance(findings_result, Exception):
        raise findings_result
    if isinstance(full_vulns_result, Exception):
        raise full_vulns_result

    merge_vulnerability_details(findings_result, full_vulns_result)

    if isinstance(bom_result, Exception):
        bom_result = {}

    return {
        "version": version_info,
        "vulnerabilities": findings_result,
        "bom": bom_result or {},
    }


async def collect_tmrescore_analysis_inputs(
    versions: List[Dict[str, Any]],
    client: DTClient,
) -> List[Dict[str, Any]]:
    if not versions:
        return []

    concurrency = min(get_version_fetch_concurrency(), len(versions))
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Optional[Dict[str, Any]]] = [None] * len(versions)

    async def worker(index: int, version_info: Dict[str, Any]):
        async with semaphore:
            return index, await fetch_version_analysis_input(client, version_info)

    pending = [
        asyncio.create_task(worker(index, version_info))
        for index, version_info in enumerate(versions)
    ]

    try:
        for pending_task in asyncio.as_completed(pending):
            index, result = await pending_task
            results[index] = result
    finally:
        for pending_task in pending:
            if not pending_task.done():
                pending_task.cancel()

    return [item for item in results if item is not None]


async def prepare_tmrescore_analysis_inventory(
    project_name: str,
    scope: str,
    client: DTClient,
) -> Dict[str, Any]:
    if scope not in SUPPORTED_TMRESCORE_SCOPES:
        raise HTTPException(status_code=400, detail="Unsupported tmrescore analysis scope")

    try:
        projects = await client.get_projects(project_name)
    except Exception as e:
        logger.error("Error fetching projects for tmrescore analysis: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Dependency-Track unavailable while preparing threat-model analysis.",
        )

    versions = [project for project in projects if project.get("name") == project_name]
    versions = sort_projects_by_version(versions)

    if not versions:
        raise HTTPException(status_code=404, detail="Project not found")

    selected_versions = versions[-1:] if scope == "latest_only" else versions
    latest_version = versions[-1].get("version", "unknown")

    analysis_inputs = await collect_tmrescore_analysis_inputs(selected_versions, client)
    synthetic_sbom = build_analysis_sbom(
        project_name,
        analysis_inputs,
        scope,
        latest_version,
    )

    analyzed_versions = [
        version.get("version", "unknown") for version in selected_versions
    ]
    strategy_note = (
        "Merged multi-version analysis keeps historical vulnerabilities attached to the versioned components they came from."
        if scope == "merged_versions"
        else "Latest-only analysis is limited to the newest version and does not account for vulnerabilities seen only in older releases."
    )

    return {
        "versions": versions,
        "selected_versions": selected_versions,
        "latest_version": latest_version,
        "dtvp_original_proposals": build_dtvp_vulnerability_proposals(analysis_inputs),
        "synthetic_sbom": synthetic_sbom,
        "analyzed_versions": analyzed_versions,
        "strategy_note": strategy_note,
    }


async def process_grouped_vulns_task(
    task_id: str, name: str, cve: Optional[str], client: DTClient
):
    try:
        tasks[task_id]["status"] = "running"
        tasks[task_id]["message"] = "Fetching projects..."
        tasks[task_id].setdefault("log", []).append("Fetching projects...")
        logger.info("Task %s started for grouped vulnerabilities", task_id)

        # 1. Get all projects matching name to find versions
        projects = await client.get_projects(name)
        if name:
            versions = [p for p in projects if p.get("name") == name]
        else:
            # If name is empty, we want ALL projects/versions
            versions = projects

        # Sort versions deterministically by version string to ensure stable processing order
        versions = sort_projects_by_version(versions)

        if not versions:
            tasks[task_id]["status"] = "completed"
            tasks[task_id]["progress"] = 100
            tasks[task_id]["result"] = []
            return

        found_msg = f"Found {len(versions)} versions. Fetching vulnerabilities..."
        tasks[task_id]["message"] = found_msg
        tasks[task_id].setdefault("log", []).append(found_msg)

        # Pre-load mapping once
        team_mapping = load_team_mapping()

        def update_progress(completed: int, total: int, version_info: Dict[str, Any]):
            tasks[task_id]["progress"] = int((completed / total) * 90)
            msg = f"Processed version {version_info.get('version')} ({completed}/{total})..."
            tasks[task_id]["message"] = msg
            tasks[task_id].setdefault("log", []).append(msg)

        combined_data, bom_cache_map, _ = await collect_version_snapshots(
            versions,
            client,
            cve,
            team_mapping,
            progress_callback=update_progress,
        )

        tasks[task_id]["message"] = "Grouping vulnerabilities..."
        tasks[task_id].setdefault("log", []).append("Grouping vulnerabilities...")

        # Pass the pre-processed BOM cache map
        result = group_vulnerabilities(
            combined_data, project_boms={}, processed_boms=bom_cache_map
        )

        tasks[task_id]["status"] = "completed"
        tasks[task_id]["progress"] = 100
        tasks[task_id]["result"] = result

    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["message"] = str(e)
        logger.exception("Task %s failed", task_id)
    finally:
        # Close the client since we created it or it was passed
        pass


@api_router.post("/tasks/group-vulns")
async def start_group_vulns_task(
    name: str,
    request: Request,
    cve: Optional[str] = None,
    # We DO NOT use Dependency Injection for the client here because it's tied to request scope.
    # We must instantiate a new client for the background task.
    user: str = Depends(get_current_user),
):
    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        "id": task_id,
        "status": "pending",
        "message": "Starting...",
        "progress": 0,
        "created_at": datetime.now(),
        "result": None,
        "log": ["Starting..."],
    }

    # Extract credentials from the request to forward to the background task
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
    cookies = dict(request.cookies)

    # Instantiate a fresh client for the background task
    async def task_wrapper():
        # Manually invoke the client context
        settings = DTSettings()
        async with DTClient(
            settings.api_url, api_key=settings.api_key, token=token, cookies=cookies
        ) as client:
            await process_grouped_vulns_task(task_id, name, cve, client)

    asyncio.create_task(task_wrapper())

    return {"task_id": task_id}


@api_router.get("/tasks/{task_id}")
async def get_task_status(task_id: str, user: str = Depends(get_current_user)):
    task = tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    return task


@api_router.get("/statistics")
async def get_statistics(
    name: Optional[str] = None,
    cve: Optional[str] = None,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    """
    Returns statistics for a project or global vulnerabilities.
    """
    # 1. Fetch data using existing logic (matching naming in search_projects/start_group_vulns_task)
    try:
        projects = await client.get_projects(name or "")
    except Exception as e:
        logger.error("Error fetching projects from Dependency-Track: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Dependency-Track unavailable when fetching statistics. Please verify DT server is reachable.",
        )

    if name:
        versions = [p for p in projects if p.get("name") == name]
    else:
        versions = projects

    if not versions:
        return {
            "severity_counts": {},
            "state_counts": {},
            "total_unique": 0,
            "total_findings": 0,
            "affected_projects_count": 0,
            "version_counts": {},
        }

    # Deterministic sort
    versions = sort_projects_by_version(versions)

    team_mapping = load_team_mapping()
    combined_data, bom_cache_map, version_severity_counts = await collect_version_snapshots(
        versions,
        client,
        cve,
        team_mapping,
    )
    version_counts = {
        entry["version"].get("version"): len(entry["vulnerabilities"])
        for entry in combined_data
    }

    # 2. Group vulnerabilities
    grouped = group_vulnerabilities(
        combined_data, project_boms={}, processed_boms=bom_cache_map
    )

    # 3. Calculate statistics
    stats = calculate_statistics(grouped)
    stats["version_counts"] = version_counts

    # Build major-version split for graphing by major version family
    major_version_counts = {}
    version_major_details = {}
    major_version_severity_counts = {}

    for v in versions:
        ver = v.get("version", "unknown")
        major = ver.split(".")[0] if isinstance(ver, str) and "." in ver else ver
        major = major or "unknown"

        major_version_counts[major] = major_version_counts.get(
            major, 0
        ) + version_counts.get(ver, 0)
        version_major_details.setdefault(major, {})[ver] = version_counts.get(ver, 0)

        # per-severity counts for this major version
        major_version_severity_counts.setdefault(major, {})
        findings = next(
            (
                cd["vulnerabilities"]
                for cd in combined_data
                if cd["version"]["uuid"] == v["uuid"]
            ),
            [],
        )
        for finding in findings:
            severity = (
                finding.get("vulnerability", {}).get("severity") or "UNKNOWN"
            ).upper()
            major_version_severity_counts[major][severity] = (
                major_version_severity_counts[major].get(severity, 0) + 1
            )

    stats["major_version_counts"] = major_version_counts
    stats["major_version_details"] = version_major_details
    stats["major_version_severity_counts"] = major_version_severity_counts
    stats["version_severity_counts"] = version_severity_counts

    return stats


@api_router.post("/assessments/details")
async def get_assessment_details(
    req: AssessmentDetailsRequest,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    logger.info(
        "Fetching assessment details for %d instances (User: %s)",
        len(req.instances),
        user,
    )
    tasks = []
    for instance in req.instances:
        tasks.append(
            client.get_analysis(
                project_uuid=instance["project_uuid"],
                component_uuid=instance["component_uuid"],
                vulnerability_uuid=instance["vulnerability_uuid"],
            )
        )

    fn_results = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i, res in enumerate(fn_results):
        inst = req.instances[i]
        result_item = {
            "finding_uuid": inst.get("finding_uuid"),
            "project_uuid": inst.get("project_uuid"),
            "component_uuid": inst.get("component_uuid"),
            "vulnerability_uuid": inst.get("vulnerability_uuid"),
            "analysis": None,
            "error": None,
        }
        if isinstance(res, Exception):
            logger.error(
                "Error fetching analysis for %s: %s",
                inst.get("finding_uuid"),
                res,
            )
            result_item["error"] = str(res)
        else:
            result_item["analysis"] = res
        results.append(result_item)

    return results


@api_router.post("/assessment")
async def update_assessment(
    req: AssessmentRequest,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    logger.info(
        "Update assessment request from %s for %d instances",
        user,
        len(req.instances),
    )
    logger.info(
        "State: %s, Suppressed: %s, Force: %s, Original Analysis Provided: %s",
        req.state,
        req.suppressed,
        req.force,
        bool(req.original_analysis),
    )

    # Conflict Check (Optimistic Locking)
    if not req.force and req.original_analysis:
        logger.debug("Checking for conflicts...")
        # Fetch current state
        tasks = []
        for instance in req.instances:
            tasks.append(
                client.get_analysis(
                    project_uuid=instance["project_uuid"],
                    component_uuid=instance["component_uuid"],
                    vulnerability_uuid=instance["vulnerability_uuid"],
                )
            )
        current_analyses = await asyncio.gather(*tasks, return_exceptions=True)

        conflicts = []
        for i, current in enumerate(current_analyses):
            instance = req.instances[i]
            finding_uuid = instance.get("finding_uuid")
            original = req.original_analysis.get(finding_uuid)

            if isinstance(current, Exception) or not current:
                continue

            # Compare relevant fields if original exists
            if original:
                # Keys in DT response: analysisState, analysisDetails, isSuppressed
                curr_state = current.get("analysisState")
                curr_details = current.get("analysisDetails")
                curr_suppressed = current.get("isSuppressed")

                orig_state = original.get("analysisState")
                orig_details = original.get("analysisDetails")
                orig_suppressed = original.get("isSuppressed")

                has_conflict = False
                if (curr_state or "") != (orig_state or ""):
                    has_conflict = True
                if (curr_details or "") != (orig_details or ""):
                    has_conflict = True
                if bool(curr_suppressed) != bool(orig_suppressed):
                    has_conflict = True

                if has_conflict:
                    logger.warning("Conflict found for %s", finding_uuid)
                    conflicts.append(
                        {
                            "finding_uuid": finding_uuid,
                            "project_name": instance.get("project_name"),
                            "project_version": instance.get("project_version"),
                            "component_name": instance.get("component_name"),
                            "component_version": instance.get("component_version"),
                            "current": current,
                            "original": original,
                            "your_change": {
                                "analysisState": req.state,
                                "analysisDetails": req.details,
                                "isSuppressed": req.suppressed,
                            },
                        }
                    )

        if conflicts:
            return JSONResponse(
                status_code=409,
                content={"status": "conflict", "conflicts": conflicts},
            )

    logger.debug("Details: %s...", req.details[:100])

    # Iterate and update
    results = []
    for instance in req.instances:
        try:
            logger.debug(
                "Updating instance: %s (Vulnerability: %s)",
                instance.get("finding_uuid"),
                instance.get("vulnerability_uuid"),
            )

            # Check Role Logic
            role = get_user_role(user)

            # Get existing details for merging
            finding_uuid = instance.get("finding_uuid")
            original_analysis = (
                req.original_analysis.get(finding_uuid)
                if req.original_analysis
                else None
            )
            existing_details = (
                original_analysis.get("analysisDetails", "")
                if original_analysis
                else ""
            )

            # Use shared logic for tag processing and state aggregation
            if req.comparison_mode == "REPLACE":
                # In REPLACE mode, we trust the details provided by the client as the full source of truth
                final_details_str = req.details
                aggregated_state = calculate_aggregated_state(req.details)
            else:
                final_details_str, aggregated_state = process_assessment_details(
                    req.details, user, role, req.team, req.state, existing_details
                )

            await client.update_analysis(
                project_uuid=instance["project_uuid"],
                component_uuid=instance["component_uuid"],
                vulnerability_uuid=instance["vulnerability_uuid"],
                state=aggregated_state,
                details=final_details_str,
                comment=f"{req.comment}{' [Team: ' + req.team + ']' if req.team else ''} -- {user}"
                if req.comment
                else f"[Team: {req.team}] -- {user}"
                if req.team
                else f"Assessed -- {user}",
                justification=req.justification
                if aggregated_state == "NOT_AFFECTED"
                else "NOT_SET",
                suppressed=req.suppressed,
            )
            results.append(
                {
                    "status": "success",
                    "uuid": instance["finding_uuid"],
                    "new_state": aggregated_state,
                    "new_details": final_details_str,
                }
            )
        except Exception as e:
            results.append(
                {
                    "status": "error",
                    "uuid": instance.get("finding_uuid"),
                    "error": str(e),
                }
            )

    return results


@api_router.get("/project/{project_uuid}/component/{component_uuid}/dependency-chains")
async def get_dependency_chains(
    project_uuid: str,
    component_uuid: str,
    client: DTClient = Depends(get_client),
):
    bom = await client.get_bom(project_uuid)
    if not bom:
        return []

    team_mapping = load_team_mapping()
    processor = BOMAnalysisCache(bom, team_mapping)
    # component_name is not strictly needed for lookup if uuid works, but we can pass empty string
    return processor.get_dependency_paths(component_uuid, component_name="")


@api_router.get("/projects/{project_name}/tmrescore/context")
async def get_tmrescore_context(
    project_name: str,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    settings = TMRescoreSettings()

    llm_enrichment_available = False
    llm_enrichment_status = "integration_disabled"
    llm_enrichment_warning = None

    if settings.enabled:
        try:
            async with TMRescoreClient(settings) as tmrescore_client:
                health = await tmrescore_client.get_health()
            llm_enrichment_available = bool(health.get("ollama_configured"))
            llm_enrichment_status = (
                "available" if llm_enrichment_available else "not_configured"
            )
            if not llm_enrichment_available:
                llm_enrichment_warning = (
                    "LLM enrichment requires OLLAMA_HOST to be configured on the tmrescore backend."
                )
        except Exception as exc:
            llm_enrichment_status = "unreachable"
            logger.warning(
                "Unable to determine tmrescore Ollama configuration for %s: %s",
                project_name,
                exc,
            )
            llm_enrichment_warning = (
                "Could not verify LLM enrichment availability from the tmrescore backend."
            )
    else:
        llm_enrichment_status = "integration_disabled"
        llm_enrichment_warning = (
            "TMRescore integration is not configured. Set DTVP_TMRESCORE_URL to enable threat-model analysis."
        )

    try:
        projects = await client.get_projects(project_name)
    except Exception as e:
        logger.error("Error fetching projects for tmrescore context: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Dependency-Track unavailable while preparing threat-model analysis context.",
        )

    versions = [project for project in projects if project.get("name") == project_name]
    versions = sort_projects_by_version(versions)

    if not versions:
        raise HTTPException(status_code=404, detail="Project not found")

    latest_version = versions[-1].get("version", "unknown")

    return {
        "enabled": settings.enabled,
        "project_name": project_name,
        "latest_version": latest_version,
        "versions": [version.get("version") for version in versions],
        "recommended_scope": "merged_versions",
        "scopes": [
            {
                "id": "merged_versions",
                "label": "Merged Multi-Version SBOM",
                "description": "Recommended. Builds a synthetic analysis-only SBOM with separate roots per project version so historical findings stay attached to the components that actually carried them.",
            },
            {
                "id": "latest_only",
                "label": "Latest Version Only",
                "description": "Uses only the latest Dependency-Track version. This is a clean single-version snapshot, but it intentionally ignores findings that exist only in older releases.",
            },
        ],
        "warnings": [
            "Do not combine the latest SBOM with vulnerabilities from older versions. That would create false positives on components that are not part of that inventory.",
            "The merged mode produces an analysis-only synthetic SBOM. It is appropriate for threat-model rescoring, but not as a deployable inventory attestation.",
            "Upload the current threat model and optional mapping inputs for each run so the rescoring reflects the latest architecture assumptions.",
        ],
        "llm_enrichment": {
            "available": llm_enrichment_available,
            "status": llm_enrichment_status,
            "default_model": os.getenv("DTVP_TMRESCORE_OLLAMA_MODEL", "qwen2.5:7b"),
            "host_configured": llm_enrichment_available,
            "warning": llm_enrichment_warning,
        },
    }


@api_router.get("/projects/{project_name}/tmrescore/sbom")
async def download_tmrescore_analysis_sbom(
    project_name: str,
    scope: str = "merged_versions",
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    inventory = await prepare_tmrescore_analysis_inventory(project_name, scope, client)
    synthetic_sbom = inventory["synthetic_sbom"]
    latest_version = inventory["latest_version"]
    safe_project_name = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in project_name
    ).strip("-") or "project"
    filename = (
        f"{safe_project_name}-{scope}-{latest_version}-analysis-sbom.cyclonedx.json"
    )

    return Response(
        content=json.dumps(synthetic_sbom, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@api_router.get("/projects/{project_name}/tmrescore/sbom/summary")
async def get_tmrescore_analysis_sbom_summary(
    project_name: str,
    scope: str = "merged_versions",
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    inventory = await prepare_tmrescore_analysis_inventory(project_name, scope, client)
    synthetic_sbom = inventory["synthetic_sbom"]
    return {
        "scope": scope,
        "latest_version": inventory["latest_version"],
        "analyzed_versions": inventory["analyzed_versions"],
        "component_count": len(synthetic_sbom.get("components") or []),
        "vulnerability_count": len(synthetic_sbom.get("vulnerabilities") or []),
        "strategy_note": inventory["strategy_note"],
    }


@api_router.post("/projects/{project_name}/tmrescore/analyze")
async def analyze_project_with_tmrescore(
    project_name: str,
    threatmodel: UploadFile = File(...),
    items_csv: UploadFile | None = File(None),
    config: UploadFile | None = File(None),
    scope: str = Form("merged_versions"),
    chain_analysis: bool = Form(True),
    prioritize: bool = Form(True),
    what_if: bool = Form(False),
    enrich: bool = Form(False),
    ollama_model: str = Form("qwen2.5:7b"),
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(
            status_code=503,
            detail="TMRescore integration is not configured. Set DTVP_TMRESCORE_URL to enable threat-model analysis.",
        )

    inventory = await prepare_tmrescore_analysis_inventory(project_name, scope, client)
    latest_version = inventory["latest_version"]
    synthetic_sbom = inventory["synthetic_sbom"]
    dtvp_original_proposals = inventory["dtvp_original_proposals"]

    session_version_label = (
        latest_version
        if scope == "latest_only"
        else f"multi-version:{latest_version}"
    )

    threatmodel_bytes = await threatmodel.read()
    items_csv_bytes = await items_csv.read() if items_csv else None
    config_bytes = await config.read() if config else None
    prune_tmrescore_analysis_tasks()

    async with TMRescoreClient(settings) as tmrescore_client:
        session = await tmrescore_client.create_session(project_name, session_version_label)
        session_id = session.get("session_id")

    analyzed_versions = inventory["analyzed_versions"]
    strategy_note = inventory["strategy_note"]

    tmrescore_analysis_tasks[session_id] = {
        "session_id": session_id,
        "project_name": project_name,
        "session": session,
        "scope": scope,
        "latest_version": latest_version,
        "analyzed_versions": analyzed_versions,
        "sbom_component_count": len(synthetic_sbom.get("components") or []),
        "sbom_vulnerability_count": len(synthetic_sbom.get("vulnerabilities") or []),
        "strategy_note": strategy_note,
        "llm_enrichment": {
            "enabled": enrich,
            "ollama_model": ollama_model if enrich else None,
        },
        "status": "running",
        "progress": 10,
        "message": "Queued tmrescore analysis.",
        "log": ["Queued tmrescore analysis."],
        "result": None,
        "error": None,
        "created_at": datetime.now().timestamp(),
        "updated_at": datetime.now().timestamp(),
        "completed_at": None,
    }

    asyncio.create_task(
        run_tmrescore_analysis_task(
            tmrescore_analysis_tasks[session_id],
            settings,
            project_name,
            threatmodel_bytes,
            synthetic_sbom,
            dtvp_original_proposals,
            items_csv_bytes,
            config_bytes,
            chain_analysis,
            prioritize,
            what_if,
            enrich,
            ollama_model,
        )
    )

    return build_tmrescore_cached_state(
        tmrescore_analysis_tasks[session_id],
        include_result=False,
    )


@api_router.get("/projects/{project_name}/tmrescore/proposals")
async def get_tmrescore_project_proposals(
    project_name: str,
    user: str = Depends(get_current_user),
):
    cached = tmrescore_project_cache.get(project_name)
    if not cached:
        raise HTTPException(
            status_code=404,
            detail="No cached threat-model proposals are available for this project yet.",
        )
    normalized_cached = normalize_tmrescore_snapshot(cached)
    if normalized_cached != cached:
        persist_tmrescore_project_snapshot(project_name, normalized_cached)
    return normalized_cached


@api_router.get("/projects/{project_name}/tmrescore/state")
async def get_tmrescore_project_state(
    project_name: str,
    user: str = Depends(get_current_user),
):
    prune_tmrescore_analysis_tasks()
    task = get_latest_tmrescore_project_task(project_name)
    if not task:
        raise HTTPException(
            status_code=404,
            detail="No cached tmrescore analysis state is available for this project.",
        )
    include_result = str(task.get("status") or "").lower() == "completed"
    return build_tmrescore_cached_state(task, include_result=include_result)


@api_router.get("/tmrescore/sessions/{session_id}/progress")
async def get_tmrescore_progress(
    session_id: str,
    user: str = Depends(get_current_user),
):
    prune_tmrescore_analysis_tasks()
    task = tmrescore_analysis_tasks.get(session_id)
    if task:
        return build_tmrescore_cached_state(task, include_result=False)

    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="TMRescore integration is not configured")

    async with TMRescoreClient(settings) as tmrescore_client:
        payload = await tmrescore_client.get_progress(session_id)

    status = str(payload.get("status") or "running")
    progress = int(payload.get("progress") or 0)
    message = payload.get("message") or describe_tmrescore_progress(status, progress)
    return {
        "session_id": session_id,
        "status": status,
        "progress": progress,
        "message": message,
        "log": [message],
        "error": None,
        "result": None,
    }


@api_router.get("/tmrescore/sessions/{session_id}/results")
async def get_tmrescore_results(
    session_id: str,
    user: str = Depends(get_current_user),
):
    prune_tmrescore_analysis_tasks()
    task = tmrescore_analysis_tasks.get(session_id)
    if task:
        if task.get("result"):
            return task["result"]
        status = str(task.get("status") or "running").lower()
        if status == "failed":
            raise HTTPException(
                status_code=409,
                detail=task.get("error") or "TMRescore analysis failed",
            )
        raise HTTPException(
            status_code=409,
            detail="TMRescore analysis is not complete yet. Poll /progress until status is completed.",
        )

    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="TMRescore integration is not configured")

    async with TMRescoreClient(settings) as tmrescore_client:
        return await tmrescore_client.get_results(session_id)


@api_router.get("/tmrescore/sessions/{session_id}/results/json")
async def get_tmrescore_results_json(
    session_id: str,
    user: str = Depends(get_current_user),
):
    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="TMRescore integration is not configured")

    async with TMRescoreClient(settings) as tmrescore_client:
        return await tmrescore_client.get_results_json(session_id)


@api_router.get("/tmrescore/sessions/{session_id}/results/vex")
async def get_tmrescore_results_vex(
    session_id: str,
    user: str = Depends(get_current_user),
):
    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="TMRescore integration is not configured")

    async with TMRescoreClient(settings) as tmrescore_client:
        return await tmrescore_client.get_results_vex(session_id)


@api_router.get("/tmrescore/sessions/{session_id}/outputs/{filename}")
async def get_tmrescore_output_file(
    session_id: str,
    filename: str,
    user: str = Depends(get_current_user),
):
    settings = TMRescoreSettings()
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="TMRescore integration is not configured")

    async with TMRescoreClient(settings) as tmrescore_client:
        response = await tmrescore_client.get_output_file(session_id, filename)

    media_type = response.headers.get("content-type", "application/octet-stream")
    content_disposition = response.headers.get("content-disposition")
    headers = {}
    if content_disposition:
        headers["content-disposition"] = content_disposition
    return Response(content=response.content, media_type=media_type, headers=headers)


@api_router.get("/openapi.json")
def get_open_api_endpoint():
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )


@api_router.get("/settings/mapping")
async def get_team_mapping(user: str = Depends(get_current_user)):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(
            status_code=403, detail="Only reviewers can view team mapping"
        )
    return load_team_mapping()


@api_router.post("/settings/mapping")
async def upload_team_mapping(
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(
            status_code=403, detail="Only reviewers can modify team mapping"
        )
    target_path = get_team_mapping_path()
    # Ensure directory exists
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    # Write file
    try:
        with open(target_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Validate JSON (optional but good)
        with open(target_path, "r") as f:
            import json

            json.load(f)

        return {
            "status": "success",
            "message": f"Team mapping updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api_router.put("/settings/mapping")
async def update_team_mapping(
    mapping: Dict[str, Any],
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(
            status_code=403, detail="Only reviewers can modify team mapping"
        )
    target_path = get_team_mapping_path()
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        with open(target_path, "w") as f:
            json.dump(mapping, f, indent=2)

        return {
            "status": "success",
            "message": f"Team mapping updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api_router.get("/settings/roles")
async def get_roles(user: str = Depends(get_current_user)):
    # Only reviewers can see roles?
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(status_code=403, detail="Only reviewers can view roles")
    return load_user_roles()


@api_router.post("/settings/roles")
async def upload_roles(
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(status_code=403, detail="Only reviewers can modify roles")

    target_path = get_user_roles_path()
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        content = await file.read()
        # Validate format
        try:
            json.loads(content)
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON"}

        with open(target_path, "wb") as f:
            f.write(content)

        return {
            "status": "success",
            "message": f"User roles updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api_router.put("/settings/roles")
async def update_roles(
    roles: Dict[str, str],
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(status_code=403, detail="Only reviewers can modify roles")

    target_path = get_user_roles_path()
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        with open(target_path, "w") as f:
            json.dump(roles, f, indent=2)

        return {
            "status": "success",
            "message": f"User roles updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api_router.get("/settings/rescore-rules")
async def get_rescore_rules(user: str = Depends(get_current_user)):
    rules = load_rescore_rules()
    if rules is None:
        rules = {"transitions": []}
    return rules


@api_router.post("/settings/rescore-rules")
async def upload_rescore_rules(
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(
            status_code=403, detail="Only reviewers can modify rescore rules"
        )

    target_path = get_rescore_rules_path()
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        content = await file.read()
        try:
            json.loads(content)
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid JSON"}

        with open(target_path, "wb") as f:
            f.write(content)

        return {
            "status": "success",
            "message": f"Rescore rules updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api_router.put("/settings/rescore-rules")
async def update_rescore_rules(
    rules: Dict[str, Any],
    user: str = Depends(get_current_user),
):
    role = get_user_role(user)
    if role != "REVIEWER":
        raise HTTPException(
            status_code=403, detail="Only reviewers can modify rescore rules"
        )

    target_path = get_rescore_rules_path()
    dir_path = os.path.dirname(target_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        with open(target_path, "w") as f:
            json.dump(rules, f, indent=2)

        return {
            "status": "success",
            "message": f"Rescore rules updated at {target_path}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


app.include_router(api_router, prefix=context_path)

# Serve Frontend if it exists (for production)
if os.path.isdir("frontend/dist"):
    # Redirect /context_path to /context_path/ to avoid 404 on mount
    if context_path:

        @app.get(context_path)
        async def redirect_to_context_path():
            return RedirectResponse(url=f"{context_path}/")

    # Mount assets directory explicitly
    if os.path.isdir("frontend/dist/assets"):
        app.mount(
            f"{context_path}/assets",
            StaticFiles(directory="frontend/dist/assets"),
            name="assets",
        )

    # Catch-all route for SPA
    @app.get(f"{context_path}/{{path:path}}")
    async def serve_spa(path: str):
        # Prevent path traversal
        if ".." in path:
            return serve_index()

        # Check if specific file exists
        file_path = os.path.join("frontend/dist", path)
        if path and os.path.isfile(file_path):
            return FileResponse(file_path)

        # Default to index.html for SPA routing
        return serve_index()

    def serve_index():
        try:
            with open("frontend/dist/index.html", "r") as f:
                content = f.read()

            # Replace environment placeholders
            frontend_url = auth_settings.FRONTEND_URL or ""
            # Fallback for local dev if not set
            if not frontend_url:
                # We can't easily know the external URL here, but UI handles defaults.
                pass

            content = content.replace("${DTVP_CONTEXT_PATH}", context_path or "/")
            content = content.replace("${DTVP_FRONTEND_URL}", frontend_url)
            content = content.replace(
                "${DTVP_DEV_DISABLE_AUTH}",
                "true" if auth_settings.DEV_DISABLE_AUTH else "false",
            )

            # If we have a context path, we need to adjust absolute paths in index.html
            # so they point to the correct sub-path (e.g. /dtvp/assets/...)
            if context_path:
                content = content.replace('src="/', f'src="{context_path}/')
                content = content.replace('href="/', f'href="{context_path}/')

            return HTMLResponse(content)
        except Exception as e:
            return HTMLResponse(
                f"Frontend not found or error loading: {str(e)}", status_code=404
            )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
