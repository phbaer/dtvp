import secrets
from dataclasses import dataclass
from datetime import UTC, timedelta

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from dtvp.models import Credential, Grant, Membership, Project, User, now
from dtvp.storage import digest

ROLE_CAPABILITIES = {
    "viewer": {"read"},
    "analyst": {"read", "write", "assess", "snapshot", "evidence"},
    "reviewer": {"read", "assess", "approve", "snapshot", "evidence"},
    "coordinator": {"read", "rescore", "snapshot"},
    "license_analyst": {"read", "license_assess"},
    "license_reviewer": {"read", "license_approve"},
    "admin": {"read", "write", "manage", "snapshot", "export", "evidence"},
}


def aware(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def capabilities(roles):
    return set().union(*(ROLE_CAPABILITIES.get(role, set()) for role in roles))


@dataclass
class Actor:
    user: User
    credential: Credential
    memberships: dict[str, set[str]]

    def workspace(self, workspace_id: str, capability: str):
        caps = self.memberships.get(workspace_id, set())
        if self.credential.kind == "api":
            if workspace_id != self.credential.workspace_id:
                return False
            caps = caps.intersection(self.credential.capabilities)
        return capability in caps

    def allowed(self, db: Session, project: Project, capability: str):
        if self.credential.kind == "api" and self.credential.projects:
            if project.id not in self.credential.projects:
                return False
        if self.workspace(project.workspace_id, capability):
            return True
        for grant in db.scalars(select(Grant).where(Grant.project_id == project.id)):
            if capability in grant.capabilities and self.workspace(grant.workspace_id, capability):
                return True
        return False

    def require(self, db: Session, project: Project | None, capability="read"):
        if project is None or not self.allowed(db, project, capability):
            raise HTTPException(404, "Resource unavailable in your scope")
        return project


def authenticate(request: Request, db: Session) -> Actor:
    authorization = request.headers.get("authorization", "")
    machine = authorization.startswith("Bearer ")
    token = (
        authorization.removeprefix("Bearer ") if machine else request.cookies.get("dtvp_session")
    )
    credential = db.scalar(
        select(Credential).where(
            Credential.token_hash == digest((token or "").encode()), Credential.revoked.is_(False)
        )
    )
    if not credential or aware(credential.expires_at) <= now():
        raise HTTPException(401, "Sign in required")
    if machine != (credential.kind == "api"):
        raise HTTPException(401, "Credential transport mismatch")
    if not machine and request.method not in {"GET", "HEAD", "OPTIONS"}:
        supplied = digest(request.headers.get("x-csrf-token", "").encode())
        origin = request.headers.get("origin")
        if not secrets.compare_digest(supplied, credential.csrf_hash or ""):
            raise HTTPException(403, "Session expired or invalid request token")
        if origin and origin.rstrip("/") != request.app.state.settings.public_url.rstrip("/"):
            raise HTTPException(403, "Request origin is not allowed")
    user = db.get(User, credential.user_id)
    memberships = {
        m.workspace_id: capabilities(m.roles)
        for m in db.scalars(select(Membership).where(Membership.user_id == user.id))
    }
    return Actor(user, credential, memberships)


def issue(
    db,
    user,
    *,
    kind="session",
    workspace_id=None,
    projects=None,
    allowed=None,
    name="session",
    hours=12,
):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    credential = Credential(
        user_id=user.id,
        token_hash=digest(token.encode()),
        kind=kind,
        workspace_id=workspace_id,
        projects=projects or [],
        capabilities=allowed or [],
        name=name,
        csrf_hash=digest(csrf.encode()) if kind == "session" else None,
        expires_at=now() + timedelta(hours=hours),
    )
    db.add(credential)
    db.flush()
    return token, csrf, credential
