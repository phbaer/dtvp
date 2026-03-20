from fastapi import FastAPI, Depends, APIRouter, UploadFile, File
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware  # noqa: F401 kept for potential future use
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import logging
import os
import asyncio
import uuid
from datetime import datetime
import shutil
import json

logger = logging.getLogger(__name__)
from fastapi import HTTPException, Request

from auth import router as auth_router, get_current_user, auth_settings
from dt_client import get_client, DTClient, DTSettings
from logic import (
    group_vulnerabilities,
    get_team_mapping_path,
    load_team_mapping,
    get_user_roles_path,
    load_user_roles,
    get_user_role,
    BOMAnalysisCache,
    process_assessment_details,
    calculate_aggregated_state,
    load_rescore_rules,
    get_rescore_rules_path,
    calculate_statistics,
)


from version import VERSION, BUILD_COMMIT

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting DTVP version {VERSION} (build {BUILD_COMMIT})")
    yield


app = FastAPI(title="DTVP", version=VERSION, lifespan=lifespan)


# CORS: reflect any origin so the app works from localhost, LAN IPs, or machine hostnames.
# We deliberately allow any origin since DTVP is a locally-hosted tool and API keys
# are the real authentication mechanism. The credential cookies are scoped to same-site
# by the browser, so this does not meaningfully loosen security.
class DynamicCORSMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            origin = headers.get(b"origin", b"").decode()

            async def send_with_cors(message):
                if message["type"] == "http.response.start" and origin:
                    cors_headers = [
                        (b"access-control-allow-origin", origin.encode()),
                        (b"access-control-allow-credentials", b"true"),
                        (b"access-control-allow-methods", b"GET, POST, PUT, DELETE, OPTIONS, PATCH"),
                        (b"access-control-allow-headers", b"*"),
                        (b"vary", b"Origin"),
                    ]
                    message = dict(message)
                    message["headers"] = list(message.get("headers", [])) + cors_headers
                await send(message)

            # Handle CORS preflight
            if scope.get("method") == "OPTIONS" or headers.get(b"access-control-request-method"):
                async def preflight_send(message):
                    pass
                response = {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [
                        (b"access-control-allow-origin", origin.encode() if origin else b"*"),
                        (b"access-control-allow-credentials", b"true"),
                        (b"access-control-allow-methods", b"GET, POST, PUT, DELETE, OPTIONS, PATCH"),
                        (b"access-control-allow-headers", b"*"),
                        (b"access-control-max-age", b"600"),
                        (b"content-length", b"0"),
                        (b"vary", b"Origin"),
                    ],
                }
                await send(response)
                await send({"type": "http.response.body", "body": b""})
                return

            await self.app(scope, receive, send_with_cors)
        else:
            await self.app(scope, receive, send)

app.add_middleware(DynamicCORSMiddleware)

# Prefix all routes if CONTEXT_PATH is set
context_path = auth_settings.CONTEXT_PATH.rstrip("/")
if context_path and not context_path.startswith("/"):
    context_path = "/" + context_path

# Auth router
app.include_router(auth_router, prefix=context_path)

# API Router
api_router = APIRouter(prefix="/api", tags=["api"])


@api_router.get("/version")
def get_version():
    return {"version": VERSION, "build": BUILD_COMMIT}


@api_router.get("/changelog")
def get_changelog():
    changelog_path = os.path.join(os.getcwd(), "CHANGELOG.md")
    if os.path.exists(changelog_path):
        with open(changelog_path, "r") as f:
            return {"content": f.read()}
    return {"content": "Changelog not available."}


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
    # Allow calling /projects without a query string to fetch all projects.
    return await client.get_projects(name or "")


# Job Manager
tasks = {}


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str
    progress: int = 0
    result: Optional[List[dict]] = None


async def process_grouped_vulns_task(
    task_id: str, name: str, cve: Optional[str], client: DTClient
):
    try:
        tasks[task_id]["status"] = "running"
        tasks[task_id]["message"] = "Fetching projects..."

        # 1. Get all projects matching name to find versions
        projects = await client.get_projects(name)
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

        tasks[task_id]["message"] = (
            f"Found {len(versions)} versions. Fetching vulnerabilities..."
        )

        # Pre-load mapping once
        team_mapping = load_team_mapping()

        # 2. Sequential fetching with progress update to avoid overloading backend
        combined_data = []
        bom_cache_map = {}  # uuid -> BOMAnalysisCache
        total_versions = len(versions)

        for i, v in enumerate(versions):
            # Update progress
            progress = int((i / total_versions) * 90)
            tasks[task_id]["progress"] = progress
            tasks[task_id]["message"] = (
                f"Processing version {v['version']} ({i + 1}/{total_versions})..."
            )

            # Fetch findings and full details
            findings = await client.get_vulnerabilities(v["uuid"], cve=cve)
            full_vulns = await client.get_project_vulnerabilities(v["uuid"])

            # Fetch and PROCESS BOM immediately to save memory
            try:
                bom = await client.get_bom(v["uuid"])
                # Create cache immediately and discard raw BOM
                bom_cache_map[v["uuid"]] = BOMAnalysisCache(bom, team_mapping)
                del bom  # Hint for GC
            except Exception as e:
                # Fallback
                logger.warning(f"Failed to create BOM cache for project {v.get('uuid')}: {e}")
                bom_cache_map[v["uuid"]] = BOMAnalysisCache({}, team_mapping)

            # Map vulnId -> vuln_obj for quick lookup
            vuln_map = {vuln.get("vulnId"): vuln for vuln in full_vulns}

            # Merge vector into each finding's vulnerability summary if missing
            for finding in findings:
                vuln_summary = finding.get("vulnerability", {})
                vuln_id = vuln_summary.get("vulnId")
                full_vuln = vuln_map.get(vuln_id)
                if full_vuln:
                    for key in [
                        "cvssV4Vector",
                        "cvssV4BaseScore",
                        "cvssV3Vector",
                        "cvssV2Vector",
                        "cvssV3BaseScore",
                        "cvssV2BaseScore",
                        "aliases",
                    ]:
                        if key in full_vuln and key not in vuln_summary:
                            vuln_summary[key] = full_vuln[key]

            # Store only what is needed: version info and findings
            # NO BOM here
            combined_data.append({"version": v, "vulnerabilities": findings})

        tasks[task_id]["message"] = "Grouping vulnerabilities..."

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
        logger.error(f"Task {task_id} failed: {e}")
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
    projects = await client.get_projects(name or "")
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
    combined_data = []
    bom_cache_map = {}
    version_counts = {}

    # We fetch findings for each version
    for v in versions:
        findings = await client.get_vulnerabilities(v["uuid"], cve=cve)
        full_vulns = await client.get_project_vulnerabilities(v["uuid"])

        # Track counts per version before grouping
        version_counts[v["version"]] = len(findings)

        try:
            bom = await client.get_bom(v["uuid"])
            bom_cache_map[v["uuid"]] = BOMAnalysisCache(bom, team_mapping)
        except Exception as e:
            logger.warning(f"Failed to get BOM for project {v.get('uuid')}: {e}")
            bom_cache_map[v["uuid"]] = BOMAnalysisCache({}, team_mapping)

        vuln_map = {vuln.get("vulnId"): vuln for vuln in full_vulns}
        for finding in findings:
            vuln_summary = finding.get("vulnerability", {})
            vuln_id = vuln_summary.get("vulnId")
            full_vuln = vuln_map.get(vuln_id)
            if full_vuln:
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

        combined_data.append({"version": v, "vulnerabilities": findings})

    # 2. Group vulnerabilities
    grouped = group_vulnerabilities(
        combined_data, project_boms={}, processed_boms=bom_cache_map
    )

    # 3. Calculate statistics
    stats = calculate_statistics(grouped)
    stats["version_counts"] = version_counts

    return stats


# Old endpoint kept for compatibility if needed, or removed?
# Requirement implied replacing the behavior. Let's keep it but maybe it won't be used by UI.
# actually, let's remove the old implementation logic and just return empty or error if used?
# Or just keep it as is for API compatibility but UI uses the new one.
# But for the "fix", we should probably encourage using the new one.


@api_router.post("/assessments/details")
async def get_assessment_details(
    req: AssessmentDetailsRequest,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    logger.info(
        f"Fetching assessment details for {len(req.instances)} instances (User: {user})"
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
            logger.error(f"Error fetching analysis for {inst.get('finding_uuid')}: {res}")
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
    logger.info(f"Update assessment request from {user} for {len(req.instances)} instances")
    logger.debug(
        f"State: {req.state}, Suppressed: {req.suppressed}, Force: {req.force}, Original Analysis Provided: {bool(req.original_analysis)}"
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
                    logger.warning(f"Conflict found for {finding_uuid}")
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

    logger.debug(f"Details: {req.details[:100]}...")

    # Iterate and update
    results = []
    for instance in req.instances:
        try:
            logger.debug(
                f"  Updating instance: {instance.get('finding_uuid')} (Vulnerability: {instance.get('vulnerability_uuid')})"
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
                justification=(req.justification or "NOT_SET"),
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
    async def serve_spa(path: str, request: Request):
        # Prevent path traversal
        if ".." in path:
            return serve_index(request)

        # Check if specific file exists
        file_path = os.path.join("frontend/dist", path)
        if path and os.path.isfile(file_path):
            return FileResponse(file_path)

        # Default to index.html for SPA routing
        return serve_index(request)

    def serve_index(request: Request = None):
        try:
            with open("frontend/dist/index.html", "r") as f:
                content = f.read()

            # Derive the frontend URL from the request so API calls are always
            # same-origin regardless of the hostname used to access the app
            # (localhost, IP address, machine name, etc.).
            # Fall back to the configured FRONTEND_URL only when no request is available.
            if request is not None:
                scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
                host = request.headers.get("X-Forwarded-Host", request.headers.get("host", ""))
                frontend_url = f"{scheme}://{host}" if host else (auth_settings.FRONTEND_URL or "")
            else:
                frontend_url = auth_settings.FRONTEND_URL or ""

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
