from fastapi import FastAPI, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import asyncio

from auth import router as auth_router, get_current_user, auth_settings
from dt_client import get_client, DTClient
from logic import group_vulnerabilities

app = FastAPI(title="DTVP", version="0.1.0")

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


@api_router.get("/projects/{name}/grouped-vulnerabilities")
async def get_grouped_vulns(
    name: str,
    client: DTClient = Depends(get_client),
    user: str = Depends(get_current_user),
):
    # 1. Get all projects matching name to find versions
    projects = await client.get_projects(name)
    versions = [p for p in projects if p.get("name") == name]

    if not versions:
        return []

    # 2. Fetch findings and full project vulnerabilities for all versions in parallel
    finding_tasks = []
    full_vuln_tasks = []
    for v in versions:
        finding_tasks.append(client.get_vulnerabilities(v["uuid"]))
        full_vuln_tasks.append(client.get_project_vulnerabilities(v["uuid"]))

    finding_results = await asyncio.gather(*finding_tasks)
    full_vuln_results = await asyncio.gather(*full_vuln_tasks)

    # 3. Combine Structure
    combined_data = []
    for i, v in enumerate(versions):
        findings = finding_results[i]
        full_vulns = full_vuln_results[i]
        
        # Map vulnId -> vuln_obj for quick lookup
        vuln_map = {vuln.get("vulnId"): vuln for vuln in full_vulns}
        
        # Merge vector into each finding's vulnerability summary if missing
        for finding in findings:
            vuln_summary = finding.get("vulnerability", {})
            vuln_id = vuln_summary.get("vulnId")
            full_vuln = vuln_map.get(vuln_id)
            if full_vuln:
                # Merge keys like cvssV3Vector, cvssV2Vector, cvssV3BaseScore, cvssV2BaseScore
                for key in ["cvssV3Vector", "cvssV2Vector", "cvssV3BaseScore", "cvssV2BaseScore"]:
                    if key in full_vuln and key not in vuln_summary:
                        vuln_summary[key] = full_vuln[key]

        combined_data.append({"version": v, "vulnerabilities": findings})

    return group_vulnerabilities(combined_data)


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
            print(f"  Updating instance: {instance.get('finding_uuid')} (Vulnerability: {instance.get('vulnerability_uuid')})")
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


from fastapi.openapi.utils import get_openapi


@api_router.get("/openapi.json")
def get_open_api_endpoint():
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )


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
            return FileResponse("frontend/dist/index.html")

        # Check if specific file exists
        file_path = os.path.join("frontend/dist", path)
        if path and os.path.isfile(file_path):
            return FileResponse(file_path)

        # Default to index.html for SPA routing
        return FileResponse("frontend/dist/index.html")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
