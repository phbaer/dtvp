"""Product sharing is inspectable under current project-read authorization."""

from sqlalchemy import select

from dtvp.auth import issue
from dtvp.models import Grant, Membership, Project, User, Workspace
from tests.conftest import login


def setup(client):
    login(client, "administrator")
    teams = {row["name"]: row["id"] for row in client.get("/api/v1/workspaces").json()}
    project = client.get("/api/v1/catalog/projects?q=Demo%20Gateway").json()["items"][0]
    return f"/api/v1/projects/{project['id']}/sharing", project, teams


def test_owner_and_explicit_grants_are_readable_without_management_permission(client):
    path, _, teams = setup(client)
    assert (
        client.put(
            path, json={"workspace_id": teams["Operations"], "capabilities": ["read", "assess"]}
        ).status_code
        == 200
    )
    managed = client.get(path)
    assert managed.status_code == 200
    assert managed.json() == {
        "owner": {"id": teams["Platform"], "name": "Platform"},
        "grants": [
            {
                "workspace_id": teams["Operations"],
                "workspace_name": "Operations",
                "capabilities": ["read", "assess"],
            }
        ],
        "capabilities": ["manage"],
    }
    login(client, "viewer")
    result = client.get(path)
    assert result.status_code == 200
    assert result.json() == {**managed.json(), "capabilities": []}
    assert (
        client.put(path, json={"workspace_id": teams["Operations"], "capabilities": []}).status_code
        == 404
    )


def test_shared_reader_loses_access_immediately_when_grant_is_revoked(client):
    path, _, teams = setup(client)
    login(client, "operations")
    assert client.get(path).status_code == 404
    login(client, "administrator")
    assert (
        client.put(
            path, json={"workspace_id": teams["Operations"], "capabilities": ["read"]}
        ).status_code
        == 200
    )
    login(client, "operations")
    assert client.get(path).status_code == 200
    assert client.get(path).json()["capabilities"] == []
    login(client, "administrator")
    assert (
        client.put(path, json={"workspace_id": teams["Operations"], "capabilities": []}).status_code
        == 200
    )
    assert client.get(path).json()["grants"][0]["capabilities"] == []
    login(client, "operations")
    assert client.get(path).status_code == 404


def test_current_membership_rechecked_and_foreign_products_do_not_leak(client, app):
    path, project, teams = setup(client)
    with app.state.sessions.begin() as db:
        foreign = Workspace(name="Foreign workspace")
        db.add(foreign)
        db.flush()
        hidden = Project(name="Foreign product", workspace_id=foreign.id)
        db.add(hidden)
        db.flush()
        hidden_id = hidden.id
    assert client.get(f"/api/v1/projects/{hidden_id}/sharing").status_code == 404
    assert client.get("/api/v1/projects/missing/sharing").status_code == 404
    login(client, "viewer")
    assert client.get(path).status_code == 200
    with app.state.sessions.begin() as db:
        viewer = db.scalar(select(User).where(User.subject == "viewer"))
        db.delete(db.get(Membership, (teams["Platform"], viewer.id)))
    assert client.get(path).status_code == 404
    with app.state.sessions.begin() as db:
        assert db.get(Project, project["id"]) is not None
        assert db.get(Grant, (project["id"], teams["Operations"])) is None


def test_machine_credentials_cannot_exceed_read_and_project_scope(client, app):
    path, project, teams = setup(client)
    with app.state.sessions.begin() as db:
        admin = db.scalar(select(User).where(User.subject == "administrator"))
        read_token, _, _ = issue(
            db,
            admin,
            kind="api",
            workspace_id=teams["Platform"],
            projects=[project["id"]],
            allowed=["read"],
        )
        foreign_token, _, _ = issue(
            db,
            admin,
            kind="api",
            workspace_id=teams["Platform"],
            projects=["another-product"],
            allowed=["read", "manage"],
        )
    response = client.get(path, headers={"Authorization": f"Bearer {read_token}"})
    assert response.status_code == 200
    assert response.json()["capabilities"] == []
    assert client.get(path, headers={"Authorization": f"Bearer {foreign_token}"}).status_code == 404
