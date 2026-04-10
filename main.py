import asyncio
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
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth import auth_settings, get_current_user
from auth import router as auth_router
from dt_client import DTClient, DTSettings, get_client
from dt_cache import cache_manager, PendingUpdateExistsError
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

logger = logging.getLogger("dtvp")
logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting DTVP version {VERSION} (build {BUILD_COMMIT})")
    try:
        await cache_manager.initialize()
    except Exception as exc:
        logger.warning("Cache manager failed to initialize: %s", exc)

    app.state.cache_sync_task = asyncio.create_task(cache_manager.background_sync_loop())
    try:
        yield
    finally:
        task = getattr(app.state, "cache_sync_task", None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


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
        return await cache_manager.get_projects(client, name)
    except Exception as e:
        logger.error("Error fetching projects from Dependency-Track: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Dependency-Track unavailable for project search. Please check DT server settings.",
        )


@api_router.get("/cache-status")
async def cache_status(
    user: str = Depends(get_current_user),
):
    try:
        return cache_manager.get_cache_status()
    except Exception as e:
        logger.error("Error fetching cache status: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Unable to determine cache freshness at this time.",
        )


# Job Manager
tasks = {}

assessment_locks: Dict[tuple[str, str, str], asyncio.Lock] = {}
assessment_lock_registry = asyncio.Lock()


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str
    progress: int = 0
    result: Optional[List[dict]] = None


async def _acquire_assessment_locks(
    keys: List[tuple[str, str, str]],
) -> tuple[bool, Optional[tuple[str, str, str]], List[asyncio.Lock]]:
    acquired: List[asyncio.Lock] = []
    async with assessment_lock_registry:
        for key in keys:
            lock = assessment_locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                assessment_locks[key] = lock
            if lock.locked():
                for held in acquired:
                    held.release()
                return False, key, []
            await lock.acquire()
            acquired.append(lock)

    return True, None, acquired


def _release_assessment_locks(acquired: List[asyncio.Lock]) -> None:
    for lock in acquired:
        if lock.locked():
            lock.release()


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
        cache_manager.get_vulnerabilities(client, version_info["uuid"], cve=cve),
        cache_manager.get_project_vulnerabilities(client, version_info["uuid"]),
        cache_manager.get_bom(client, version_info["uuid"]),
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


async def process_grouped_vulns_task(
    task_id: str, name: str, cve: Optional[str], client: DTClient
):
    try:
        tasks[task_id]["status"] = "running"
        tasks[task_id]["message"] = "Fetching projects..."
        tasks[task_id].setdefault("log", []).append("Fetching projects...")
        logger.info("Task %s started for grouped vulnerabilities", task_id)

        # 1. Get all projects matching name to find versions
        projects = await cache_manager.get_projects(client, name)
        if name:
            versions = [p for p in projects if p.get("name") == name]
        else:
            # If name is empty, we want ALL projects/versions
            versions = projects

        # Sort versions deterministically by version string to ensure stable processing order
        versions.sort(key=lambda x: x.get("version", ""))

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
        total_versions = len(versions)

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
        projects = await cache_manager.get_projects(client, name)
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
    versions.sort(key=lambda x: x.get("version", ""))

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

    assessment_keys = []
    for instance in req.instances:
        assessment_keys.append(
            (
                instance.get("project_uuid"),
                instance.get("component_uuid"),
                instance.get("vulnerability_uuid"),
            )
        )

    ok, conflict_key, acquired_locks = await _acquire_assessment_locks(
        assessment_keys
    )
    if not ok:
        detail = {
            "status": "conflict",
            "message": "Another update is already in progress for this finding.",
            "project_uuid": conflict_key[0],
            "component_uuid": conflict_key[1],
            "vulnerability_uuid": conflict_key[2],
        }
        return JSONResponse(status_code=409, content=detail)

    try:
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

                payload = {
                    "project_uuid": instance["project_uuid"],
                    "component_uuid": instance["component_uuid"],
                    "vulnerability_uuid": instance["vulnerability_uuid"],
                    "state": aggregated_state,
                    "details": final_details_str,
                    "comment": f"{req.comment}{' [Team: ' + req.team + ']' if req.team else ''} -- {user}"
                    if req.comment
                    else f"[Team: {req.team}] -- {user}"
                    if req.team
                    else f"Assessed -- {user}",
                    "justification": req.justification
                    if aggregated_state == "NOT_AFFECTED"
                    else "NOT_SET",
                    "suppressed": req.suppressed,
                }

                try:
                    update_id = await cache_manager.queue_analysis_update(payload)
                except PendingUpdateExistsError as exc:
                    return JSONResponse(
                        status_code=409,
                        content={
                            "status": "conflict",
                            "message": str(exc),
                        },
                    )

                try:
                    await client.update_analysis(**payload)
                    await cache_manager.remove_pending_update(update_id)
                    results.append(
                        {
                            "status": "success",
                            "uuid": instance["finding_uuid"],
                            "new_state": aggregated_state,
                            "new_details": final_details_str,
                        }
                    )
                except Exception as e:
                    logger.warning(
                        "Queued DT update because remote update failed: %s", e
                    )
                    results.append(
                        {
                            "status": "error",
                            "queued": True,
                            "uuid": instance.get("finding_uuid"),
                            "error": str(e),
                            "new_state": aggregated_state,
                            "new_details": final_details_str,
                        }
                    )
            except HTTPException:
                raise
            except Exception as e:
                results.append(
                    {
                        "status": "error",
                        "uuid": instance.get("finding_uuid"),
                        "error": str(e),
                    }
                )

        return results
    finally:
        _release_assessment_locks(acquired_locks)


@api_router.get("/project/{project_uuid}/component/{component_uuid}/dependency-chains")
async def get_dependency_chains(
    project_uuid: str,
    component_uuid: str,
    client: DTClient = Depends(get_client),
):
    bom = await cache_manager.get_bom(client, project_uuid)
    if not bom:
        return []

    team_mapping = load_team_mapping()
    processor = BOMAnalysisCache(bom, team_mapping)
    # component_name is not strictly needed for lookup if uuid works, but we can pass empty string
    return processor.get_dependency_paths(component_uuid, component_name="")


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
