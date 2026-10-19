"""Playground identities only; composition and scenarios are explicitly loaded files."""

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from dtvp.api import DB
from dtvp.api_contract import API_PREFIX
from dtvp.auth import issue
from dtvp.models import Membership, User, Workspace

router = APIRouter(prefix=API_PREFIX + "/playground")
PERSONAS = {
    "analyst": ("Platform analyst", ["analyst"], "Platform"),
    "reviewer": ("Platform reviewer", ["reviewer"], "Platform"),
    "license-analyst": ("License analyst", ["license_analyst"], "Platform"),
    "license-reviewer": ("License reviewer", ["license_reviewer"], "Platform"),
    "documentary-analyst": ("Documentation analyst", ["documentary_analyst"], "Platform"),
    "documentary-reviewer": ("Documentation reviewer", ["documentary_reviewer"], "Platform"),
    "coordinator": ("Security coordinator", ["coordinator"], "Platform"),
    "operations-reviewer": ("Operations reviewer", ["reviewer"], "Operations"),
    "viewer": ("Platform viewer", ["viewer"], "Platform"),
    "operations": ("Operations analyst", ["analyst"], "Operations"),
    "administrator": ("Organization administrator", ["admin", "reviewer"], "Platform"),
}


def seed(db, artifacts=None):
    teams = {}
    for name in {values[2] for values in PERSONAS.values()}:
        team = db.scalar(select(Workspace).where(Workspace.name == name))
        if team is None:
            team = Workspace(name=name)
            db.add(team)
            db.flush()
        teams[name] = team
    for subject, (name, roles, workspace) in PERSONAS.items():
        if db.scalar(select(User).where(User.issuer == "playground", User.subject == subject)):
            continue
        user = User(
            issuer="playground", subject=subject, name=name, org_admin=subject == "administrator"
        )
        db.add(user)
        db.flush()
        db.add(Membership(user_id=user.id, workspace_id=teams[workspace].id, roles=roles))
        if subject == "administrator":
            db.add(
                Membership(user_id=user.id, workspace_id=teams["Operations"].id, roles=["admin"])
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
    user = db.scalar(select(User).where(User.issuer == "playground", User.subject == data.persona))
    token, csrf, _ = issue(db, user)
    response.set_cookie("dtvp_session", token, httponly=True, samesite="strict", max_age=43200)
    response.set_cookie("dtvp_csrf", csrf, samesite="strict", max_age=43200)
    return {"name": user.name}
