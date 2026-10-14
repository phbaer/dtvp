import json
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from dtvp.api import DB, Auth, require_admin
from dtvp.auth import issue
from dtvp.domain import import_sbom
from dtvp.models import Base, Membership, Project, Release, User, Workspace, now
from dtvp.storage import canonical

FIXTURES = Path(__file__).resolve().parent.parent / "playground" / "fixtures"
router = APIRouter(prefix="/api/v2/playground")
PERSONAS = {
    "analyst": ("Platform analyst", ["analyst"], "Platform"),
    "reviewer": ("Platform reviewer", ["reviewer"], "Platform"),
    "viewer": ("Platform viewer", ["viewer"], "Platform"),
    "operations": ("Operations analyst", ["analyst"], "Operations"),
    "administrator": ("Organization administrator", ["admin", "reviewer"], "Platform"),
}


def seed(db, artifacts):
    if db.scalar(select(Workspace.id).limit(1)):
        return
    workspaces = {name: Workspace(name=name) for name in ["Platform", "Operations"]}
    db.add_all(workspaces.values())
    db.flush()
    for subject, (name, roles, workspace) in PERSONAS.items():
        user = User(
            issuer="playground", subject=subject, name=name, org_admin=subject == "administrator"
        )
        db.add(user)
        db.flush()
        db.add(Membership(user_id=user.id, workspace_id=workspaces[workspace].id, roles=roles))
        if subject == "administrator":
            db.add(
                Membership(
                    user_id=user.id, workspace_id=workspaces["Operations"].id, roles=["admin"]
                )
            )
    db.flush()
    admin = db.scalar(select(User).where(User.subject == "administrator"))
    for workspace_name, project_name, fixture in [
        ("Platform", "Demo Gateway", "release.cdx.json"),
        ("Operations", "Demo Worker", "release.spdx.json"),
    ]:
        project = Project(workspace_id=workspaces[workspace_name].id, name=project_name)
        db.add(project)
        db.flush()
        release = Release(project_id=project.id, version="1.0.0")
        db.add(release)
        db.flush()
        import_sbom(
            db,
            artifacts,
            release,
            (FIXTURES / fixture).read_bytes(),
            source="pipeline:demo",
            event_id="baseline",
            occurred_at=now() - timedelta(minutes=5),
            completeness="complete",
            context={
                "provider": "demo-ci",
                "run_id": "demo-1",
                "commit": "synthetic",
                "branch": "main",
                "status": "succeeded",
            },
            actor_id=admin.id,
        )


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    persona: str


@router.get("/personas")
def personas(request: Request):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    return [{"id": subject, "name": values[0]} for subject, values in PERSONAS.items()]


@router.post("/login")
def login(data: Login, request: Request, response: Response, db: DB):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    if data.persona not in PERSONAS:
        raise HTTPException(422, "Unknown playground persona")
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != request.app.state.settings.public_url.rstrip("/"):
        raise HTTPException(403, "Request origin is not allowed")
    user = db.scalar(select(User).where(User.issuer == "playground", User.subject == data.persona))
    token, csrf, _ = issue(db, user)
    response.set_cookie("dtvp_session", token, httponly=True, samesite="strict", max_age=43200)
    response.set_cookie("dtvp_csrf", csrf, samesite="strict", max_age=43200)
    return {"name": user.name}


@router.post("/reset")
def reset(request: Request, db: DB, actor: Auth):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    require_admin(actor)
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    seed(db, request.app.state.artifacts)
    return {"status": "reset", "sign_in_required": True}


@router.post("/replay/{scenario}")
def replay(scenario: str, request: Request, db: DB, actor: Auth):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    project = db.scalar(select(Project).where(Project.name == "Demo Gateway"))
    actor.require(db, project, "write")
    release = db.scalar(select(Release).where(Release.project_id == project.id))
    bom = json.loads((FIXTURES / "release.cdx.json").read_bytes())
    if scenario == "release-change":
        bom["vulnerabilities"][0]["description"] += " New evidence requires revalidation."
    elif scenario == "conflict":
        bom["vulnerabilities"][0]["ratings"][0].update(
            vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", score=7.8
        )
    elif scenario == "partial":
        bom["vulnerabilities"] = []
    elif scenario != "baseline":
        raise HTTPException(422, "Unknown scenario")
    result = import_sbom(
        db,
        request.app.state.artifacts,
        release,
        canonical(bom),
        source="pipeline:alternative" if scenario == "conflict" else "pipeline:demo",
        event_id=f"{scenario}:{now().isoformat()}",
        occurred_at=now(),
        completeness="partial" if scenario == "partial" else "complete",
        context={"provider": "demo-ci", "scenario": scenario},
        actor_id=actor.user.id,
    )
    return {"revision_id": result.id}
