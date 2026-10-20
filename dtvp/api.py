from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
)
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dtvp import __version__
from dtvp.api_contract import API_PREFIX, API_VERSION
from dtvp.auth import Actor, authenticate, issue
from dtvp.domain import (
    audit,
)
from dtvp.jobs import NATIVE_JOB_KINDS
from dtvp.migration_models import Snapshot
from dtvp.models import Audit, Credential, Grant, Job, Membership, Project, User, Workspace
from dtvp.schemas import (
    MemberInput,
    ProjectInput,
    ProjectResolveInput,
    ShareInput,
    TokenInput,
    WorkspaceInput,
)
from dtvp.storage import canonical

router = APIRouter(prefix=API_PREFIX)


def database(request: Request):
    with request.app.state.sessions() as db:
        db.info["artifact_dir"] = request.app.state.settings.artifact_dir
        try:
            yield db
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Conflicting or duplicate record") from None


# Commit before sending success, cookies or tokens to the client.
DB = Annotated[Session, Depends(database, scope="function")]


def actor(request: Request, db: DB):
    return authenticate(request, db)


Auth = Annotated[Actor, Depends(actor)]


def project_for(db, actor, project_id, capability="read"):
    return actor.require(db, db.get(Project, project_id), capability)


def snapshot_for(db, actor, snapshot_id):
    snapshot = db.get(Snapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot unavailable")
    project_for(db, actor, snapshot.project_id)
    return snapshot


def visible_project_query(actor, capability="read"):
    workspace_ids = [key for key in actor.memberships if actor.workspace(key, capability)]
    granted = select(Grant.project_id).where(
        Grant.workspace_id.in_(workspace_ids),
        cast(Grant.capabilities, String).contains(f'"{capability}"'),
    )
    query = select(Project).where(
        or_(Project.workspace_id.in_(workspace_ids), Project.id.in_(granted))
    )
    if actor.credential.kind == "api" and actor.credential.projects:
        query = query.where(Project.id.in_(actor.credential.projects))
    return query


def visible_projects(db, actor):
    return list(db.scalars(visible_project_query(actor).order_by(Project.name, Project.id)))


def project_summary(db, actor, project):
    return {
        "id": project.id,
        "name": project.name,
        "workspace_id": project.workspace_id,
        "capabilities": [
            c
            for c in {
                "read",
                "write",
                "assess",
                "approve",
                "snapshot",
                "manage",
                "export",
                "rescore",
                "evidence",
            }
            if actor.allowed(db, project, c)
        ],
    }


@router.get("/catalog/projects")
def project_catalog(
    db: DB,
    actor: Auth,
    q: str = "",
    workspace_id: str = "",
    cursor: str = "",
    limit: int = Query(25, ge=1, le=100),
):
    from dtvp.catalog import after_cursor, page_cursor

    scope = ["projects", q, workspace_id]
    query = visible_project_query(actor)
    if q:
        query = query.where(Project.name.icontains(q, autoescape=True))
    if workspace_id:
        query = query.where(Project.workspace_id == workspace_id)
    query = after_cursor(query, Project.name, Project.id, cursor, scope)
    rows = list(db.scalars(query.order_by(Project.name, Project.id).limit(limit + 1)))
    items = []
    for project in rows[:limit]:
        item = project_summary(db, actor, project)
        item["workspace"] = db.get(Workspace, project.workspace_id).name
        from dtvp.knowledge.projection import heads

        item["version_count"] = db.scalar(
            select(func.count())
            .select_from(heads)
            .where(heads.c.project_id == project.id, heads.c.kind == "branch")
        )
        items.append(item)
    return {
        "items": items,
        "next_cursor": page_cursor(rows[limit - 1].name, rows[limit - 1].id, scope)
        if len(rows) > limit
        else None,
    }


def require_admin(actor, workspace_id=None):
    if workspace_id:
        if actor.workspace(workspace_id, "manage"):
            return
    elif actor.user.org_admin and actor.credential.kind == "session":
        return
    raise HTTPException(403, "Administrator membership required")


def bounded_metadata(value):
    if len(canonical(value)) > 64 * 1024:
        raise HTTPException(422, "Metadata exceeds 64 KiB")


@router.get("/version")
def version():
    return {"version": __version__, "api": API_VERSION}


@router.get("/me")
def me(db: DB, actor: Auth, request: Request):
    return {
        "id": actor.user.id,
        "name": actor.user.name,
        "org_admin": actor.user.org_admin and actor.credential.kind == "session",
        "playground": request.app.state.settings.playground,
        "vscorer_url": request.app.state.settings.vscorer_url,
        "agentyzer": {
            "enabled": request.app.state.settings.playground
            or request.app.state.settings.agentyzer_enabled,
            "mode": "synthetic"
            if request.app.state.settings.playground
            and not request.app.state.settings.agentyzer_enabled
            else "external",
        },
        "workspaces": [
            {
                "id": workspace_id,
                "name": db.get(Workspace, workspace_id).name,
                "capabilities": sorted(
                    c for c in actor.memberships[workspace_id] if actor.workspace(workspace_id, c)
                ),
            }
            for workspace_id in actor.memberships
            if actor.workspace(workspace_id, "read")
        ],
    }


@router.get("/workspaces")
def workspaces(db: DB, actor: Auth):
    return [
        {"id": w.id, "name": w.name}
        for w in db.scalars(select(Workspace).order_by(Workspace.name))
        if actor.workspace(w.id, "read")
        or (actor.user.org_admin and actor.credential.kind == "session")
    ]


@router.post("/workspaces", status_code=201)
def new_workspace(data: WorkspaceInput, db: DB, actor: Auth):
    require_admin(actor)
    workspace = Workspace(name=data.name)
    db.add(workspace)
    db.flush()
    db.add(Membership(workspace_id=workspace.id, user_id=actor.user.id, roles=["admin"]))
    audit(db, actor.user.id, "workspace.create", workspace.id)
    return {"id": workspace.id, "name": workspace.name}


@router.get("/workspaces/{workspace_id}/members")
def members(workspace_id: str, db: DB, actor: Auth):
    require_admin(actor, workspace_id)
    return [
        {
            "user_id": u.id,
            "name": u.name,
            "issuer": u.issuer,
            "subject": u.subject,
            "roles": m.roles,
        }
        for m, u in db.execute(
            select(Membership, User).join(User).where(Membership.workspace_id == workspace_id)
        )
    ]


@router.put("/workspaces/{workspace_id}/members")
def set_member(workspace_id: str, data: MemberInput, db: DB, actor: Auth):
    require_admin(actor, workspace_id)
    if not db.get(Workspace, workspace_id):
        raise HTTPException(404, "Workspace unavailable")
    user = db.scalar(select(User).where(User.issuer == data.issuer, User.subject == data.subject))
    if not user:
        user = User(issuer=data.issuer, subject=data.subject, name=data.name)
        db.add(user)
        db.flush()
    member = db.get(Membership, (workspace_id, user.id))
    if member:
        member.roles = data.roles
    else:
        db.add(Membership(workspace_id=workspace_id, user_id=user.id, roles=data.roles))
    audit(
        db,
        actor.user.id,
        "membership.set",
        user.id,
        details={"workspace_id": workspace_id, "roles": data.roles},
    )
    return {"user_id": user.id, "roles": data.roles}


@router.post("/credentials", status_code=201)
def create_credential(data: TokenInput, db: DB, actor: Auth):
    require_admin(actor, data.workspace_id)
    if not set(data.capabilities).issubset(actor.memberships.get(data.workspace_id, set())):
        raise HTTPException(403, "Token cannot exceed your capabilities")
    for project_id in data.projects:
        project_for(db, actor, project_id)
    token, _, credential = issue(
        db,
        actor.user,
        kind="api",
        workspace_id=data.workspace_id,
        projects=data.projects,
        allowed=data.capabilities,
        name=data.name,
        hours=data.hours,
    )
    audit(
        db,
        actor.user.id,
        "credential.issue",
        credential.id,
        details={"workspace_id": data.workspace_id, "capabilities": data.capabilities},
    )
    return {"id": credential.id, "token": token, "expires_at": credential.expires_at.isoformat()}


@router.get("/credentials")
def credentials(db: DB, actor: Auth):
    return [
        {
            "id": c.id,
            "name": c.name,
            "workspace_id": c.workspace_id,
            "projects": c.projects,
            "capabilities": c.capabilities,
            "expires_at": c.expires_at.isoformat(),
            "revoked": c.revoked,
        }
        for c in db.scalars(
            select(Credential).where(Credential.user_id == actor.user.id, Credential.kind == "api")
        )
    ]


@router.delete("/credentials/{credential_id}", status_code=204)
def revoke_credential(credential_id: str, db: DB, actor: Auth):
    credential = db.get(Credential, credential_id)
    if not credential or credential.user_id != actor.user.id:
        raise HTTPException(404, "Credential unavailable")
    credential.revoked = True
    audit(db, actor.user.id, "credential.revoke", credential.id)


@router.get("/projects")
def projects(db: DB, actor: Auth):
    return [
        {
            "id": p.id,
            "name": p.name,
            "workspace_id": p.workspace_id,
            "capabilities": [
                c
                for c in {
                    "read",
                    "write",
                    "assess",
                    "approve",
                    "snapshot",
                    "manage",
                    "export",
                    "rescore",
                    "evidence",
                }
                if actor.allowed(db, p, c)
            ],
        }
        for p in visible_projects(db, actor)
    ]


@router.post("/projects/resolve")
def resolve_project(data: ProjectResolveInput, db: DB, actor: Auth):
    """Resolve one exact upload target; create only in an authorized owner workspace."""

    def result(project, created=False):
        actor.require(db, project, "write")
        return {
            "id": project.id,
            "name": project.name,
            "workspace_id": project.workspace_id,
            "created": created,
        }

    project = db.get(Project, data.project)
    if project is not None:
        actor.require(db, project, "write")
        if data.workspace_id is not None and project.workspace_id != data.workspace_id:
            raise HTTPException(409, "Product belongs to a different workspace")
        return result(project)

    visible_ids = (
        visible_project_query(actor)
        .with_only_columns(Project.id)
        .union(visible_project_query(actor, "write").with_only_columns(Project.id))
    )
    query = select(Project).where(Project.id.in_(visible_ids), Project.name == data.project)
    if data.workspace_id is not None:
        query = query.where(Project.workspace_id == data.workspace_id)
    matches = list(db.scalars(query.limit(2)))
    if len(matches) > 1:
        raise HTTPException(409, "Product name is ambiguous; specify its ID or workspace")
    if matches:
        return result(matches[0])

    # A project-limited credential must never create a target outside its allowlist.
    if actor.credential.kind == "api" and actor.credential.projects:
        raise HTTPException(403, "Project-restricted credentials cannot create products")
    workspace_id = data.workspace_id
    if workspace_id is None:
        writable = [key for key in actor.memberships if actor.workspace(key, "write")]
        if not writable:
            raise HTTPException(403, "Product creation requires workspace write permission")
        if len(writable) != 1:
            raise HTTPException(422, "Specify a workspace when creating a product")
        workspace_id = writable[0]
    if not actor.workspace(workspace_id, "write"):
        raise HTTPException(403, "Product creation requires workspace write permission")
    # Serialize name creation in PostgreSQL; the unique constraint remains a final guard.
    workspace = db.scalar(select(Workspace).where(Workspace.id == workspace_id).with_for_update())
    if workspace is None:
        raise HTTPException(404, "Workspace unavailable")
    project = db.scalar(
        select(Project).where(Project.workspace_id == workspace_id, Project.name == data.project)
    )
    if project is not None:
        return result(project)
    project = Project(workspace_id=workspace_id, name=data.project)
    db.add(project)
    db.flush()
    audit(db, actor.user.id, "project.create", project.id, project.id)
    return result(project, created=True)


@router.get("/projects/{project_id}")
def project_read(project_id: str, db: DB, actor: Auth):
    return project_summary(db, actor, project_for(db, actor, project_id))


@router.post("/projects", status_code=201)
def create_project(data: ProjectInput, db: DB, actor: Auth):
    if not actor.workspace(data.workspace_id, "write"):
        raise HTTPException(403, "Project creation requires write permission")
    project = Project(workspace_id=data.workspace_id, name=data.name)
    db.add(project)
    db.flush()
    audit(db, actor.user.id, "project.create", project.id, project.id)
    return {"id": project.id, "name": project.name, "workspace_id": project.workspace_id}


@router.put("/projects/{project_id}/sharing")
def share_project(project_id: str, data: ShareInput, db: DB, actor: Auth):
    project = project_for(db, actor, project_id, "manage")
    if not db.get(Workspace, data.workspace_id):
        raise HTTPException(404, "Workspace unavailable")
    db.refresh(project, with_for_update=True)
    grant = db.get(Grant, (project.id, data.workspace_id))
    if grant:
        grant.capabilities = data.capabilities
    else:
        db.add(
            Grant(
                project_id=project.id,
                workspace_id=data.workspace_id,
                capabilities=data.capabilities,
            )
        )
    audit(
        db,
        actor.user.id,
        "project.share",
        project.id,
        project.id,
        {"workspace_id": data.workspace_id, "capabilities": data.capabilities},
    )
    return data.model_dump()


@router.get("/jobs")
def jobs(db: DB, actor: Auth):
    project_ids = [p.id for p in visible_projects(db, actor)]
    return [
        {
            "id": j.id,
            "kind": j.kind,
            "project_id": j.project_id,
            "version": j.payload.get("version"),
            "finding_id": j.payload.get("finding_id"),
            "status": j.status,
            "error": j.error,
            "attempts": j.attempts,
            "result": j.result,
            "created_at": j.created_at.isoformat(),
        }
        for j in db.scalars(
            select(Job)
            .where(Job.project_id.in_(project_ids), Job.kind.in_(NATIVE_JOB_KINDS))
            .order_by(Job.created_at.desc())
            .limit(100)
        )
    ]


@router.get("/projects/{project_id}/audit")
def project_audit(
    project_id: str, db: DB, actor: Auth, cursor: str = "", limit: int = Query(50, ge=1, le=200)
):
    project_for(db, actor, project_id)
    rows = list(
        db.scalars(
            select(Audit)
            .where(Audit.project_id == project_id, Audit.id > cursor)
            .order_by(Audit.id)
            .limit(limit + 1)
        )
    )
    return {
        "items": [
            {
                "id": a.id,
                "actor_id": a.actor_id,
                "action": a.action,
                "subject_id": a.subject_id,
                "details": a.details,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows[:limit]
        ],
        "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
    }
