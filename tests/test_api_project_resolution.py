"""Implicit CLI product targets retain workspace and credential boundaries."""

import json

import pytest
from sqlalchemy import select

from dtvp.auth import issue
from dtvp.models import Audit, Grant, Membership, Project, User, Workspace
from tests.conftest import login

PATH = "/api/v1/projects/resolve"


def resolve(client, name, **fields):
    return client.post(PATH, json={"project": name, **fields})


def test_exact_name_creates_once_and_id_resolves_same_product(analyst, app):
    first = resolve(analyst, "Nightly Device")
    assert first.status_code == 200, first.text
    project = first.json()
    assert project["created"] is True and project["name"] == "Nightly Device"
    for selector in ("Nightly Device", project["id"]):
        repeated = resolve(analyst, selector)
        assert repeated.status_code == 200, repeated.text
        assert repeated.json() == {**project, "created": False}
    with app.state.sessions() as db:
        assert len(list(db.scalars(select(Project).where(Project.name == "Nightly Device")))) == 1
        assert len(list(db.scalars(select(Audit).where(Audit.subject_id == project["id"])))) == 1


def test_resolved_product_accepts_new_versions_and_updates_without_expected_head(analyst, bom):
    project = resolve(analyst, "CI Device").json()
    metadata = {
        "request_id": "nightly-1",
        "source": "pipeline:nightly",
        "build_number": 1,
        "occurred_at": "2026-10-20T01:00:00Z",
        "completeness": "complete",
    }

    def upload(version, fields):
        return analyst.post(
            f"/api/v1/projects/{project['id']}/versions/{version}/files",
            data={"metadata": json.dumps(fields)},
            files={"file": ("sbom.json", json.dumps(bom).encode(), "application/json")},
        )

    first = upload("7.1", metadata)
    assert first.status_code == 201, first.text
    second = upload("7.1", {**metadata, "request_id": "nightly-2", "build_number": 2})
    assert second.status_code == 201, second.text
    assert second.json()["updates"][0]["target"] != first.json()["updates"][0]["target"]
    replay = upload("7.1", metadata)
    assert replay.status_code == 201, replay.text
    for key in ("publication", "sequence", "updates"):
        assert replay.json()[key] == first.json()[key]
    assert replay.json()["projected_sequence"] == second.json()["projected_sequence"]
    parallel = upload("7.2", {**metadata, "request_id": "parallel-1"})
    assert parallel.status_code == 201, parallel.text
    versions = analyst.get(f"/api/v1/projects/{project['id']}/versions").json()
    assert {row["version"] for row in versions["items"]} == {"7.1", "7.2"}


def test_creation_workspace_must_be_unambiguous_and_names_are_exact(analyst, app):
    with app.state.sessions.begin() as db:
        other = db.scalar(select(Workspace).where(Workspace.name == "Operations"))
        user = db.scalar(select(User).where(User.subject == "analyst"))
        db.add(Membership(workspace_id=other.id, user_id=user.id, roles=["analyst"]))
        workspace_id = other.id
    assert resolve(analyst, "Multi-team Device").status_code == 422
    first = resolve(analyst, "Multi-team Device", workspace_id=workspace_id)
    assert first.status_code == 200, first.text
    assert first.json()["workspace_id"] == workspace_id
    # Similar names must not silently become the same product.
    second = resolve(analyst, "multi-team device", workspace_id=workspace_id)
    assert second.status_code == 200 and second.json()["id"] != first.json()["id"]


def test_duplicate_visible_names_require_id_or_owner_workspace(analyst, app):
    with app.state.sessions.begin() as db:
        user = db.scalar(select(User).where(User.subject == "analyst"))
        workspaces = list(db.scalars(select(Workspace)))
        for team in workspaces:
            if team.name == "Operations":
                db.add(Membership(workspace_id=team.id, user_id=user.id, roles=["analyst"]))
            db.add(Project(workspace_id=team.id, name="Shared Name"))
        workspace_id = workspaces[0].id
    response = resolve(analyst, "Shared Name")
    assert response.status_code == 409, response.text
    assert resolve(analyst, "Shared Name", workspace_id=workspace_id).status_code == 200


def test_read_only_users_and_foreign_workspace_cannot_create_or_write(analyst, app):
    project = resolve(analyst, "Existing Device").json()
    with app.state.sessions() as db:
        foreign = db.scalar(select(Workspace).where(Workspace.name == "Operations")).id
    assert resolve(analyst, "Forbidden Device", workspace_id=foreign).status_code == 403
    assert resolve(analyst, project["id"], workspace_id=foreign).status_code == 409
    login(analyst, "viewer")
    assert resolve(analyst, "Existing Device").status_code == 404
    assert resolve(analyst, "New Forbidden Device").status_code == 403


def test_inaccessible_project_id_is_never_reinterpreted_as_a_new_name(analyst, app):
    with app.state.sessions.begin() as db:
        foreign = db.scalar(select(Workspace).where(Workspace.name == "Operations"))
        hidden = Project(workspace_id=foreign.id, name="Hidden")
        db.add(hidden)
        db.flush()
        hidden_id = hidden.id
    assert resolve(analyst, hidden_id).status_code == 404
    with app.state.sessions() as db:
        assert db.scalar(select(Project).where(Project.name == hidden_id)) is None


@pytest.mark.parametrize("capabilities", [["read", "write"], ["write"]])
def test_project_restricted_machine_token_can_update_but_never_create(analyst, app, capabilities):
    project = resolve(analyst, "Token Device").json()
    with app.state.sessions.begin() as db:
        user = db.scalar(select(User).where(User.subject == "analyst"))
        token, _, _ = issue(
            db,
            user,
            kind="api",
            workspace_id=project["workspace_id"],
            projects=[project["id"]],
            allowed=capabilities,
            name="CI",
            hours=1,
        )
    analyst.headers["Authorization"] = "Bearer " + token
    assert resolve(analyst, project["id"]).status_code == 200
    assert resolve(analyst, "Token Device").status_code == 200
    assert resolve(analyst, "Outside Token Allowlist").status_code == 403
    with app.state.sessions() as db:
        assert db.scalar(select(Project).where(Project.name == "Outside Token Allowlist")) is None


def test_write_only_machine_token_resolves_shared_product_instead_of_creating_duplicate(
    analyst, app
):
    with app.state.sessions.begin() as db:
        teams = {row.name: row.id for row in db.scalars(select(Workspace))}
        project = Project(workspace_id=teams["Operations"], name="Shared CI Device")
        db.add(project)
        db.flush()
        project_id = project.id
        db.add(Grant(project_id=project.id, workspace_id=teams["Platform"], capabilities=["write"]))
        user = db.scalar(select(User).where(User.subject == "analyst"))
        token, _, _ = issue(
            db,
            user,
            kind="api",
            workspace_id=teams["Platform"],
            projects=[],
            allowed=["write"],
            name="Write-only CI",
            hours=1,
        )
    analyst.headers["Authorization"] = "Bearer " + token
    response = resolve(analyst, "Shared CI Device")
    assert response.status_code == 200, response.text
    assert response.json()["id"] == project_id and response.json()["created"] is False
    with app.state.sessions() as db:
        assert len(list(db.scalars(select(Project).where(Project.name == "Shared CI Device")))) == 1
