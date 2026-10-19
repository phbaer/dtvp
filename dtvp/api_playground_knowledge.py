"""Explicit file-defined synthetic scenarios; never mounted in production."""

import fcntl
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from dtvp.api import DB, Auth
from dtvp.api_contract import API_PREFIX
from dtvp.auth import capabilities
from dtvp.knowledge.demo_scenarios import DemoScenario, build_scenario
from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.projection import catch_up
from dtvp.models import Grant, Membership, Project, User, Workspace
from dtvp.storage import canonical, digest

router = APIRouter(prefix=API_PREFIX + "/playground/knowledge")


def fixture_users(db):
    subjects = {
        "administrator",
        "analyst",
        "reviewer",
        "operations",
        "operations-reviewer",
        "license-analyst",
    }
    users = {
        user.subject: user
        for user in db.scalars(
            select(User).where(User.issuer == "playground", User.subject.in_(subjects))
        )
    }
    teams = {
        team.name: team.id
        for team in db.scalars(
            select(Workspace).where(Workspace.name.in_(["Platform", "Operations"]))
        )
    }
    if set(users) != subjects or set(teams) != {"Platform", "Operations"}:
        raise HTTPException(409, "Standard playground personas and teams are required")
    return users, teams


def authorize_fixture(db, project, user):
    def authorize(team_id, capability):
        member = db.get(Membership, (team_id, user.id))
        grant = db.get(Grant, (project.id, team_id))
        if not member or capability not in capabilities(member.roles):
            raise PermissionError("Synthetic persona lacks the required team role")
        if team_id != project.workspace_id and (not grant or capability not in grant.capabilities):
            raise PermissionError("Synthetic persona lacks project sharing")

    return authorize


@router.post("/load")
def load_scenario(data: DemoScenario, request: Request, db: DB, actor: Auth):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    if actor.credential.kind != "session" or actor.user.issuer != "playground":
        raise HTTPException(403, "Demo scenarios require an explicit synthetic playground session")
    journal = request.app.state.knowledge
    scenario_sha = digest(canonical(data.model_dump(mode="json")))
    with (journal.root / "playground-scenario.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        users, teams = fixture_users(db)
        projects = list(
            db.scalars(select(Project).where(Project.workspace_id == teams["Platform"]))
        )
        matches = [
            project
            for project in projects
            if project.metadata_json.get("playground_fixture") == data.fixture_id
        ]
        if len(matches) > 1:
            raise HTTPException(409, "Demo fixture identity is ambiguous")
        project = matches[0] if matches else None
        if project and (
            project.metadata_json.get("playground_fixture_sha256") != scenario_sha
            or project.name != data.project_name
        ):
            raise HTTPException(
                409,
                "Fixture payload changed; choose a new fixture_id and project_name to preserve existing work",
            )
        if project is None and any(project.name == data.project_name for project in projects):
            raise HTTPException(
                409,
                "Another project already uses this name; choose a distinct scenario project_name",
            )
        if project is None:
            project = Project(
                workspace_id=teams["Platform"],
                name=data.project_name,
                metadata_json={
                    "playground_fixture": data.fixture_id,
                    "playground_fixture_sha256": scenario_sha,
                    "synthetic": True,
                    "fixture_actors": "named synthetic playground personas",
                },
            )
            db.add(project)
            db.flush()
            db.add(
                Grant(
                    project_id=project.id,
                    workspace_id=teams["Operations"],
                    capabilities=["read", "assess", "approve"],
                )
            )
            db.flush()
        current = product_heads(journal.references(), project.id)
        preserved_existing = bool(current)
        if not current:
            with TemporaryDirectory(prefix="knowledge-scenario-", dir=journal.root) as folder:
                staging = Journal(Path(folder))
                try:
                    build_scenario(staging, db, project, users, teams, data, authorize_fixture)
                except PermissionError as error:
                    raise HTTPException(403, str(error)) from error
                refs = staging.references()
                # Durable access metadata must precede the authoritative journal publication.
                db.commit()
                for path in staging.objects.root.glob("*/*"):
                    journal.objects.put(staging.objects.read(path.parent.name + path.name))
                try:
                    journal.publish(
                        request_id=digest(canonical([data.fixture_id, project.id, scenario_sha])),
                        fingerprint=digest(canonical(refs)),
                        updates=[
                            Update(ref=Ref.model_validate_json(key), expected=None, target=state)
                            for key, state in sorted(refs.items())
                        ],
                    )
                except Conflict as error:
                    raise HTTPException(409, str(error)) from error
                current = product_heads(journal.references(), project.id)
    catch_up(request.app.state.engine, journal)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "version": data.selected_version
        if data.selected_version in current
        else sorted(current)[-1],
        "synthetic": True,
        "fixture_id": data.fixture_id,
        "scenario_sha256": scenario_sha,
        "preserved_existing": preserved_existing,
        "actors": "synthetic playground personas; no real assessments or approvals",
    }
