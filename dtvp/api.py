import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import JSONResponse
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dtvp import __version__
from dtvp.auth import Actor, authenticate, issue
from dtvp.domain import (
    approve_decision,
    audit,
    current_observations,
    finding_detail,
    import_evidence,
    import_sbom,
    inventory,
    lock_release,
    submit_decision,
)
from dtvp.jobs import enqueue
from dtvp.models import (
    Audit,
    Component,
    Credential,
    Finding,
    Grant,
    Job,
    Membership,
    Project,
    Release,
    Revision,
    Snapshot,
    User,
    Workspace,
    now,
)
from dtvp.parsers import validate_advisory
from dtvp.providers import ADVISORY_PROVIDERS, MATCHERS
from dtvp.schemas import (
    ApprovalInput,
    BulkApply,
    BulkInput,
    DecisionInput,
    EvidenceInput,
    ImportInput,
    JobInput,
    MemberInput,
    MetadataInput,
    ProjectInput,
    ReleaseInput,
    ShareInput,
    SnapshotInput,
    TokenInput,
    WorkspaceInput,
)
from dtvp.snapshots import create_snapshot
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v2")


def database(request: Request):
    with request.app.state.sessions() as db:
        db.info["artifact_dir"] = request.app.state.settings.artifact_dir
        try:
            yield db
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Conflicting or duplicate record") from None


DB = Annotated[Session, Depends(database)]


def actor(request: Request, db: DB):
    return authenticate(request, db)


Auth = Annotated[Actor, Depends(actor)]


def project_for(db, actor, project_id, capability="read"):
    return actor.require(db, db.get(Project, project_id), capability)


def release_for(db, actor, release_id, capability="read"):
    release = db.get(Release, release_id)
    if not release:
        raise HTTPException(404, "Release unavailable")
    project_for(db, actor, release.project_id, capability)
    return release


def finding_for(db, actor, finding_id, capability="read"):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding unavailable")
    release_for(db, actor, finding.release_id, capability)
    return finding


def snapshot_for(db, actor, snapshot_id):
    snapshot = db.get(Snapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot unavailable")
    project_for(db, actor, snapshot.project_id)
    return snapshot


def visible_project_query(actor):
    workspace_ids = [key for key in actor.memberships if actor.workspace(key, "read")]
    granted = select(Grant.project_id).where(
        Grant.workspace_id.in_(workspace_ids),
        cast(Grant.capabilities, String).contains('"read"'),
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
        item["release_count"] = db.scalar(
            select(func.count()).select_from(Release).where(Release.project_id == project.id)
        )
        item["finding_count"] = db.scalar(
            select(func.count())
            .select_from(Finding)
            .join(Release)
            .where(Release.project_id == project.id, Finding.active.is_(True))
        )
        items.append(item)
    return {
        "items": items,
        "next_cursor": page_cursor(rows[limit - 1].name, rows[limit - 1].id, scope)
        if len(rows) > limit
        else None,
    }


@router.get("/catalog/projects/{project_id}/releases")
def release_catalog(
    project_id: str,
    db: DB,
    actor: Auth,
    q: str = "",
    cursor: str = "",
    limit: int = Query(25, ge=1, le=100),
):
    from dtvp.catalog import after_cursor, page_cursor

    project_for(db, actor, project_id)
    scope = ["releases", project_id, q]
    query = select(Release).where(Release.project_id == project_id)
    if q:
        query = query.where(Release.version.icontains(q, autoescape=True))
    query = after_cursor(
        query,
        Release.created_at,
        Release.id,
        cursor,
        scope,
        descending=True,
        value_parser=datetime.fromisoformat,
    )
    rows = list(
        db.scalars(query.order_by(Release.created_at.desc(), Release.id.desc()).limit(limit + 1))
    )
    return {
        "items": [
            {"id": r.id, "version": r.version, "generation": r.generation} for r in rows[:limit]
        ],
        "next_cursor": page_cursor(
            rows[limit - 1].created_at.isoformat(), rows[limit - 1].id, scope
        )
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


def check_time(value):
    if value.tzinfo is None or value > now():
        raise HTTPException(422, "Source time must have a timezone and cannot be in the future")
    return value.astimezone(UTC)


@router.get("/version")
def version():
    return {"version": __version__, "api": "v2"}


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
                    "evidence",
                }
                if actor.allowed(db, p, c)
            ],
        }
        for p in visible_projects(db, actor)
    ]


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


@router.get("/projects/{project_id}/releases")
def releases(project_id: str, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    return [
        {"id": r.id, "version": r.version, "generation": r.generation, "metadata": r.metadata_json}
        for r in db.scalars(
            select(Release)
            .where(Release.project_id == project_id)
            .order_by(Release.created_at.desc())
        )
    ]


@router.post("/projects/{project_id}/releases", status_code=201)
def create_release(project_id: str, data: ReleaseInput, db: DB, actor: Auth):
    project_for(db, actor, project_id, "write")
    release = Release(project_id=project_id, version=data.version)
    db.add(release)
    db.flush()
    audit(db, actor.user.id, "release.create", release.id, project_id)
    return {"id": release.id, "version": release.version}


@router.get("/releases/{release_id}/components")
def components(
    release_id: str,
    db: DB,
    actor: Auth,
    cursor: str = "",
    q: str = "",
    limit: int = Query(50, ge=1, le=200),
):
    release = release_for(db, actor, release_id)
    effective, values, active_ids = inventory(db, release)
    selected = sorted(
        (
            c
            for c in values.values()
            if c.id in active_ids
            and c.id > cursor
            and (not q or q.casefold() in f"{c.name} {c.version} {c.purl}".casefold())
        ),
        key=lambda c: c.id,
    )
    rows = selected[:limit]
    return {
        "items": [
            {
                "id": c.id,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "metadata": c.metadata_json,
                "metadata_version": c.metadata_version,
                "sources": [
                    {"revision_id": r.id, "source": r.source, "ref": ref}
                    for r in effective
                    for ref, cid in r.document["component_ids"].items()
                    if cid == c.id
                ],
            }
            for c in rows
        ],
        "next_cursor": rows[-1].id if len(selected) > limit else None,
        "total": len(active_ids),
        "coverage": [r.completeness for r in effective],
    }


@router.put("/components/{component_id}/metadata")
def component_metadata(component_id: str, data: MetadataInput, db: DB, actor: Auth):
    component = db.get(Component, component_id)
    if not component:
        raise HTTPException(404, "Component unavailable")
    release_for(db, actor, component.release_id, "write")
    lock_release(db, component.release_id)
    db.refresh(component)
    if component.metadata_version != data.expected_version:
        raise HTTPException(409, "Metadata changed; reload first")
    bounded_metadata(data.metadata)
    component.metadata_json = data.metadata
    component.metadata_version += 1
    release = db.get(Release, component.release_id)
    for finding in db.scalars(select(Finding).where(Finding.component_id == component.id)):
        finding.evidence_revision += 1
        finding.state_version += 1
    audit(db, actor.user.id, "metadata.update", component.id, release.project_id)
    return {"metadata": component.metadata_json, "metadata_version": component.metadata_version}


@router.get("/releases/{release_id}/revisions")
def release_revisions(release_id: str, db: DB, actor: Auth):
    release_for(db, actor, release_id)
    return [
        {
            "id": r.id,
            "source": r.source,
            "event_id": r.event_id,
            "sha256": r.artifact_sha,
            "occurred_at": r.occurred_at.isoformat(),
            "format": r.format,
            "completeness": r.completeness,
            "context": r.context,
        }
        for r in db.scalars(
            select(Revision)
            .where(Revision.release_id == release_id)
            .order_by(Revision.occurred_at.desc())
        )
    ]


@router.get("/revisions/{revision_id}/artifact")
def original_artifact(revision_id: str, db: DB, actor: Auth, request: Request):
    revision = db.get(Revision, revision_id)
    if not revision:
        raise HTTPException(404, "Revision unavailable")
    release_for(db, actor, revision.release_id)
    return Response(
        request.app.state.artifacts.read(revision.artifact_sha),
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="original-sbom"'},
    )


@router.post("/releases/{release_id}/ingestions", status_code=201)
def ingest(release_id: str, data: ImportInput, db: DB, actor: Auth, request: Request):
    release = release_for(db, actor, release_id, "write")
    bounded_metadata(data.context)
    revision = import_sbom(
        db,
        request.app.state.artifacts,
        release,
        canonical(data.sbom),
        source=data.source,
        event_id=data.event_id,
        occurred_at=check_time(data.occurred_at),
        completeness=data.completeness,
        context=data.context,
        actor_id=actor.user.id,
    )
    return {
        "id": revision.id,
        "sha256": revision.artifact_sha,
        "completeness": revision.completeness,
    }


@router.post("/releases/{release_id}/uploads", status_code=201)
def upload(
    release_id: str,
    db: DB,
    actor: Auth,
    request: Request,
    file: UploadFile = File(),
    source: str = Form("file"),
    event_id: str = Form(""),
    completeness: str = Form("complete"),
):
    release = release_for(db, actor, release_id, "write")
    if completeness not in {"complete", "partial"} or not source or len(source) > 200:
        raise HTTPException(422, "Invalid source/completeness")
    raw = file.file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(413, "Upload too large")
    event_id = event_id or digest(raw)
    previous = db.scalar(
        select(Revision).where(
            Revision.release_id == release.id,
            Revision.source == source,
            Revision.event_id == event_id,
        )
    )
    occurred_at = previous.occurred_at.replace(tzinfo=UTC) if previous else now()
    revision = import_sbom(
        db,
        request.app.state.artifacts,
        release,
        raw,
        source=source,
        event_id=event_id,
        occurred_at=occurred_at,
        completeness=completeness,
        context={"filename": file.filename},
        actor_id=actor.user.id,
    )
    return {"id": revision.id, "sha256": revision.artifact_sha}


@router.get("/findings")
def findings(
    db: DB,
    actor: Auth,
    release_id: str | None = None,
    project_id: str = "",
    workspace_id: str = "",
    owner: str = "",
    sort: str = Query("id", pattern="^(id|identifier|component|project)$"),
    q: str = "",
    lifecycle: str = "",
    cursor: str = "",
    limit: int = Query(25, ge=1, le=100),
):
    authorized = visible_project_query(actor).with_only_columns(Project.id)
    query = (
        select(Finding, Release, Project)
        .join(Release, Finding.release_id == Release.id)
        .join(Project)
        .join(Component, Finding.component_id == Component.id)
    )
    query = query.where(Project.id.in_(authorized), Finding.active.is_(True))
    if project_id:
        project_for(db, actor, project_id)
        query = query.where(Project.id == project_id)
    if workspace_id:
        query = query.where(Project.workspace_id == workspace_id)
    if owner:
        query = query.where(
            Component.metadata_json["owner"].as_string().icontains(owner, autoescape=True)
        )
    from dtvp.catalog import after_cursor, page_cursor

    order = {
        "id": Finding.id,
        "identifier": Finding.identifier,
        "component": Component.name,
        "project": Project.name,
    }[sort]
    scope = ["findings", release_id, project_id, workspace_id, owner, sort, q, lifecycle]
    if sort == "id":
        query = query.where(Finding.id > cursor)
    else:
        query = after_cursor(query, order, Finding.id, cursor, scope)
    if release_id:
        release_for(db, actor, release_id)
        query = query.where(Release.id == release_id)
    if q:
        query = query.where(
            or_(
                Finding.identifier.icontains(q, autoescape=True),
                Component.name.icontains(q, autoescape=True),
                Component.purl.icontains(q, autoescape=True),
                Project.name.icontains(q, autoescape=True),
                Release.version.icontains(q, autoescape=True),
            )
        )
    items, last = [], None
    observations = {}
    # Cursor advances over scanned rows even when a lifecycle filter rejects a row.
    # Bounded scanning prevents an empty result from expanding without limit.
    scanned = list(db.execute(query.order_by(order, Finding.id).limit(501)))
    consumed = 0
    for finding, release, project in scanned:
        if len(items) == limit:
            break
        consumed += 1
        value = {
            "id": finding.id,
            "identifier": finding.identifier,
            "component": db.get(Component, finding.component_id).name,
            "project": project.name,
        }[sort]
        last = finding.id if sort == "id" else page_cursor(value, finding.id, scope)
        if release.id not in observations:
            observations[release.id] = current_observations(db, release.id)
        detail = finding_detail(db, finding, observations=observations[release.id])
        if lifecycle and detail["lifecycle"] != lifecycle:
            continue
        detail.update(
            project=project.name,
            project_id=project.id,
            release=release.version,
            capabilities=[
                c for c in {"assess", "approve", "evidence"} if actor.allowed(db, project, c)
            ],
            latest_decision=detail["decisions"][0] if detail["decisions"] else None,
        )
        items.append(
            {
                key: value
                for key, value in detail.items()
                if key
                not in {"observations", "evidence", "decisions", "approval", "imported_assessments"}
            }
        )
    return {
        "items": items,
        "next_cursor": last if consumed < len(scanned) or len(scanned) == 501 else None,
    }


@router.get("/findings/{finding_id}")
def finding(finding_id: str, db: DB, actor: Auth):
    stored = finding_for(db, actor, finding_id)
    detail = finding_detail(db, stored)
    release = db.get(Release, stored.release_id)
    project = db.get(Project, release.project_id)
    detail.update(
        project=project.name,
        release=release.version,
        capabilities=[
            c for c in {"assess", "approve", "evidence"} if actor.allowed(db, project, c)
        ],
    )
    return detail


@router.post("/findings/{finding_id}/decisions", status_code=201)
def decision(finding_id: str, data: DecisionInput, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "assess")
    bounded_metadata(data.details)
    result = submit_decision(
        db, actor, finding, data.expected_version, data.state, data.rationale, data.details
    )
    return {"id": result.id, "state_version": finding.state_version}


@router.post("/findings/{finding_id}/approvals")
def approval(finding_id: str, data: ApprovalInput, db: DB, actor: Auth):
    stored = finding_for(db, actor, finding_id, "approve")
    approve_decision(
        db,
        actor,
        stored,
        data.expected_version,
        data.decision_id,
        request_changes=data.action == "request_changes",
    )
    return {"state_version": stored.state_version}


@router.post("/approvals/preview")
def bulk_preview(data: BulkInput, db: DB, actor: Auth):
    for item in data.items:
        stored = finding_for(db, actor, item.finding_id, "approve")
        detail = finding_detail(db, stored)
        if (
            detail["state_version"] != item.expected_version
            or detail["lifecycle"] != "ready"
            or (
                not detail["decisions"]
                or detail["decisions"][0]["id"] != item.decision_id
                or detail["decisions"][0]["author_id"] == actor.user.id
            )
        ):
            raise HTTPException(
                409, "Selection includes changed, incomplete, or self-authored decisions"
            )
    return {"count": len(data.items), "preview_digest": digest(canonical(data.model_dump()))}


@router.post("/approvals/apply")
def bulk_apply(data: BulkApply, db: DB, actor: Auth):
    if data.preview_digest != digest(
        canonical({"items": [item.model_dump() for item in data.items]})
    ):
        raise HTTPException(409, "Selection differs from preview")
    stored = [finding_for(db, actor, item.finding_id, "approve") for item in data.items]
    for release_id in sorted({f.release_id for f in stored}):
        lock_release(db, release_id)
    for item, finding in zip(data.items, stored, strict=True):
        approve_decision(db, actor, finding, item.expected_version, item.decision_id)
    return {"approved": len(stored)}


@router.post("/findings/{finding_id}/evidence", status_code=201)
def evidence(finding_id: str, data: EvidenceInput, db: DB, actor: Auth):
    finding = finding_for(db, actor, finding_id, "evidence")
    bounded_metadata(data.assertion)
    if "advisory" in data.assertion:
        validate_advisory(data.assertion["advisory"])
    if data.snapshot_id:
        snapshot = snapshot_for(db, actor, data.snapshot_id)
        if snapshot.release_id != finding.release_id:
            raise HTTPException(422, "Evidence snapshot belongs to a different release")
        if data.source == "vscorer":
            if data.assertion.get("kind") != "contextual-assessment":
                raise HTTPException(
                    422, "VScorer returns contextual evidence, not affectedness decisions"
                )
            if not data.assertion.get("assessment_id") or not data.assertion.get("base_vector"):
                raise HTTPException(422, "VScorer assessment ID and original Base vector required")
            from dtvp.storage import Artifacts

            artifacts = Artifacts(db.info["artifact_dir"])
            payload = json.loads(artifacts.read(snapshot.sha))
            exported = next(
                (
                    entry
                    for entry in payload["vscorer"]["cves"]
                    if entry["cve_id"] == finding.identifier
                ),
                None,
            )
            frozen = next(
                (entry for entry in payload["findings"] if entry["id"] == finding.id), None
            )
            if (
                not frozen
                or not exported
                or exported["cvss_vector"] != data.assertion["base_vector"]
            ):
                raise HTTPException(
                    422, "VScorer result does not match the exported finding and Base vector"
                )
            if data.assertion.get("component_refs") != exported["component_refs"]:
                raise HTTPException(
                    422, "VScorer result must identify the exact exported component refs"
                )
    elif data.source == "vscorer":
        raise HTTPException(422, "VScorer evidence must identify its source snapshot")
    result = import_evidence(
        db,
        actor.user.id,
        finding,
        source=data.source,
        external_id=data.external_id,
        assertion=data.assertion,
        snapshot_id=data.snapshot_id,
    )
    return {"id": result.id, "state_version": finding.state_version}


@router.post("/snapshots", status_code=201)
def snapshot(data: SnapshotInput, db: DB, actor: Auth, request: Request):
    release = release_for(db, actor, data.release_id, "snapshot")
    result = create_snapshot(db, request.app.state.artifacts, actor, release, data.revision_id)
    return {"id": result.id, **result.manifest}


@router.get("/snapshots/{snapshot_id}")
def manifest(snapshot_id: str, db: DB, actor: Auth):
    result = snapshot_for(db, actor, snapshot_id)
    return {"id": result.id, **result.manifest}


@router.get("/snapshots/{snapshot_id}/bundle")
def snapshot_bundle(snapshot_id: str, db: DB, actor: Auth, request: Request):
    stored = snapshot_for(db, actor, snapshot_id)
    return Response(
        request.app.state.artifacts.read(stored.sha),
        media_type="application/json",
        headers={
            "ETag": f'"{stored.sha}"',
            "Content-Disposition": 'attachment; filename="dtvp-snapshot.json"',
        },
    )


@router.get("/snapshots/{snapshot_id}/sbom")
def snapshot_sbom(snapshot_id: str, db: DB, actor: Auth, request: Request):
    stored = snapshot_for(db, actor, snapshot_id)
    payload = json.loads(request.app.state.artifacts.read(stored.sha))
    return JSONResponse(
        payload["sbom"], headers={"Content-Disposition": 'attachment; filename="sbom.cdx.json"'}
    )


@router.get("/snapshots/{snapshot_id}/vulnerabilities")
def snapshot_vulnerabilities(
    snapshot_id: str,
    db: DB,
    actor: Auth,
    request: Request,
    cursor: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
):
    stored = snapshot_for(db, actor, snapshot_id)
    payload = json.loads(request.app.state.artifacts.read(stored.sha))
    items = payload["findings"]
    return {
        "items": items[cursor : cursor + limit],
        "next_cursor": cursor + limit if cursor + limit < len(items) else None,
        "snapshot_id": snapshot_id,
        "sha256": stored.sha,
    }


@router.get("/snapshots/{snapshot_id}/exports/vscorer")
def vscorer_export(snapshot_id: str, db: DB, actor: Auth, request: Request):
    stored = snapshot_for(db, actor, snapshot_id)
    payload = json.loads(request.app.state.artifacts.read(stored.sha))
    return {
        "snapshot_id": snapshot_id,
        "manifest": stored.manifest,
        "cves": payload["vscorer"],
        "sbom": payload["sbom"],
        "finding_mapping": [
            {
                "finding_id": f["id"],
                "component_id": f["component_id"],
                "identifier": f["identifier"],
            }
            for f in payload["findings"]
        ],
    }


@router.get("/snapshots/{snapshot_id}/exports/vscorer/worklist")
def vscorer_worklist(snapshot_id: str, db: DB, actor: Auth, request: Request):
    stored = snapshot_for(db, actor, snapshot_id)
    payload = json.loads(request.app.state.artifacts.read(stored.sha))
    return JSONResponse(
        payload["vscorer"], headers={"Content-Disposition": 'attachment; filename="cves.json"'}
    )


@router.get("/providers")
def providers(actor: Auth, request: Request):
    enabled = request.app.state.settings.providers_enabled
    return [
        {"id": provider, "kind": kind, "enabled": provider in enabled}
        for kind, registry in [("matcher", MATCHERS), ("advisory", ADVISORY_PROVIDERS)]
        for provider in registry
    ]


@router.post("/jobs", status_code=202)
def new_job(data: JobInput, db: DB, actor: Auth, request: Request):
    settings = request.app.state.settings
    release = release_for(
        db, actor, data.release_id, "evidence" if data.kind == "enrich" else "write"
    )
    if data.kind == "import-dt":
        if not settings.dt_url or not settings.dt_api_key or not data.external_project_id:
            raise HTTPException(
                422, "Configure the read-only DT source and select its project UUID"
            )
        project = db.get(Project, release.project_id)
        configured = (
            project.metadata_json.get("connectors", {})
            .get("dependency-track", {})
            .get("project_id")
        )
        if not configured or data.external_project_id != configured:
            raise HTTPException(
                403, "An administrator must bind this DTVP product to the DT project first"
            )
    else:
        registry = MATCHERS if data.kind == "match" else ADVISORY_PROVIDERS
        if data.provider not in registry or data.provider not in settings.providers_enabled:
            raise HTTPException(
                422, "Provider is unavailable or disabled by deployment configuration"
            )
    if data.provider and data.provider.startswith("demo") and not settings.playground:
        raise HTTPException(422, "Synthetic providers are playground-only")
    result = enqueue(db, actor, release, data.kind, data.model_dump(exclude={"kind", "release_id"}))
    audit(db, actor.user.id, "job.enqueue", result.id, release.project_id, {"kind": data.kind})
    return {"id": result.id, "status": result.status}


@router.get("/jobs")
def jobs(db: DB, actor: Auth):
    project_ids = [p.id for p in visible_projects(db, actor)]
    return [
        {
            "id": j.id,
            "kind": j.kind,
            "finding_id": j.payload.get("finding_id"),
            "status": j.status,
            "error": j.error,
            "attempts": j.attempts,
            "result": j.result,
            "created_at": j.created_at.isoformat(),
        }
        for j in db.scalars(
            select(Job)
            .where(Job.project_id.in_(project_ids))
            .order_by(Job.created_at.desc())
            .limit(100)
        )
    ]


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, db: DB, actor: Auth):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
    if not job:
        raise HTTPException(404, "Job unavailable")
    project_for(
        db, actor, job.project_id, "evidence" if job.kind in {"enrich", "analyse"} else "write"
    )
    if job.status in {"queued", "running"}:
        job.status = "cancelled"
    return {"status": job.status}


@router.post("/jobs/{job_id}/retry", status_code=202)
def retry_job(job_id: str, db: DB, actor: Auth):
    old = db.get(Job, job_id)
    if not old:
        raise HTTPException(404, "Job unavailable")
    project_for(
        db, actor, old.project_id, "evidence" if old.kind in {"enrich", "analyse"} else "write"
    )
    if old.status not in {"failed", "cancelled"}:
        raise HTTPException(409, "Only failed or cancelled jobs can be retried")
    if old.kind == "analyse":
        raise HTTPException(
            409, "Reload the finding and explicitly submit a new analysis against current evidence"
        )
    result = enqueue(db, actor, db.get(Release, old.payload["release_id"]), old.kind, old.payload)
    return {"id": result.id, "status": result.status}


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
