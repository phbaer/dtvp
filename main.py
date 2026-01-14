from fastapi import FastAPI, Depends, APIRouter, UploadFile, File
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import asyncio
import uuid
from datetime import datetime
import shutil

from auth import router as auth_router, get_current_user, auth_settings
from dt_client import get_client, DTClient, DTSettings
from logic import (
    group_vulnerabilities,
    get_team_mapping_path,
    load_team_mapping,
    BOMAnalysisCache,
)


from version import VERSION, BUILD_COMMIT

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Starting DTVP version {VERSION} (build {BUILD_COMMIT})")
    yield


app = FastAPI(title="DTVP", version=VERSION, lifespan=lifespan)


# CORS for frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000"],
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


@api_router.get("/version")
def get_version():
    return {"version": VERSION, "build": BUILD_COMMIT}


# Models
class AssessmentRequest(BaseModel):
    instances: List[dict]  # List of instance objects from the group
    state: str
    details: str
    comment: Optional[str] = None
    suppressed: bool = False


@api_router.get("/projects")
async def search_projects(
    name: str,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    return await client.get_projects(name)


# Job Manager
tasks = {}


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str
    progress: int = 0
    result: Optional[List[dict]] = None


async def process_grouped_vulns_task(task_id: str, name: str, client: DTClient):
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
            findings = await client.get_vulnerabilities(v["uuid"])
            full_vulns = await client.get_project_vulnerabilities(v["uuid"])

            # Fetch and PROCESS BOM immediately to save memory
            try:
                bom = await client.get_bom(v["uuid"])
                # Create cache immediately and discard raw BOM
                bom_cache_map[v["uuid"]] = BOMAnalysisCache(bom, team_mapping)
                del bom  # Hint for GC
            except Exception:
                # Fallback
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
                        "cvssV3Vector",
                        "cvssV2Vector",
                        "cvssV3BaseScore",
                        "cvssV2BaseScore",
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
        print(f"Task {task_id} failed: {e}")
    finally:
        # Close the client since we created it or it was passed
        pass


@api_router.post("/tasks/group-vulns")
async def start_group_vulns_task(
    name: str,
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

    # Instantiate a fresh client for the background task
    # We need to manually handle its lifecycle or let the task handle it
    # But get_client is an async generator now.
    # Let's import get_client and use it properly in the task wrapper.
    async def task_wrapper():
        # Manually invoke the client context
        settings = DTSettings()
        async with DTClient(settings.api_url, settings.api_key) as client:
            await process_grouped_vulns_task(task_id, name, client)

    asyncio.create_task(task_wrapper())

    return {"task_id": task_id}


@api_router.get("/tasks/{task_id}")
async def get_task_status(task_id: str, user: str = Depends(get_current_user)):
    task = tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    return task


# Old endpoint kept for compatibility if needed, or removed?
# Requirement implied replacing the behavior. Let's keep it but maybe it won't be used by UI.
# actually, let's remove the old implementation logic and just return empty or error if used?
# Or just keep it as is for API compatibility but UI uses the new one.
# But for the "fix", we should probably encourage using the new one.


@api_router.post("/assessment")
async def update_assessment(
    req: AssessmentRequest,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    print(f"Update assessment request from {user} for {len(req.instances)} instances")
    print(f"State: {req.state}, Suppressed: {req.suppressed}")
    print(f"Details: {req.details[:100]}...")

    # Iterate and update
    results = []
    for instance in req.instances:
        try:
            print(
                f"  Updating instance: {instance.get('finding_uuid')} (Vulnerability: {instance.get('vulnerability_uuid')})"
            )
            await client.update_analysis(
                project_uuid=instance["project_uuid"],
                component_uuid=instance["component_uuid"],
                vulnerability_uuid=instance["vulnerability_uuid"],
                state=req.state,
                details=req.details,
                comment=f"{req.comment} -- {user}" if req.comment else None,
                suppressed=req.suppressed,
            )
            results.append({"status": "success", "uuid": instance["finding_uuid"]})
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
    limit: int = 10,
    offset: int = 0,
    client: DTClient = Depends(get_client),
):
    bom = await client.get_bom(project_uuid)
    if not bom:
        return {"paths": [], "total": 0, "limit": limit, "offset": offset}

    team_mapping = load_team_mapping()
    processor = BOMAnalysisCache(bom, team_mapping)
    # component_name is not strictly needed for lookup if uuid works, but we can pass empty string
    return processor.get_dependency_paths(
        component_uuid, component_name="", limit=limit, offset=offset
    )


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
    return load_team_mapping()


@api_router.post("/settings/mapping")
async def upload_team_mapping(
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
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
