from tests.conftest import login


def test_csrf_machine_scope_and_revocation(client):
    assert client.get("/api/v1/projects").status_code == 401
    login(client, "administrator")
    workspace_id = client.get("/api/v1/me").json()["workspaces"][0]["id"]
    projects = client.get("/api/v1/projects").json()
    project = next(p for p in projects if p["workspace_id"] == workspace_id)
    client.headers["X-CSRF-Token"] = "wrong"
    assert (
        client.post(
            "/api/v1/projects", json={"workspace_id": workspace_id, "name": "Unauthorized"}
        ).status_code
        == 403
    )
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    response = client.post(
        "/api/v1/credentials",
        json={
            "workspace_id": workspace_id,
            "name": "Generator",
            "projects": [project["id"]],
            "capabilities": ["read"],
            "hours": 1,
        },
    )
    assert response.status_code == 201, response.text
    credential = response.json()
    client.headers["Authorization"] = "Bearer " + credential["token"]
    assert [p["id"] for p in client.get("/api/v1/projects").json()] == [project["id"]]
    assert (
        client.post(
            f"/api/v1/projects/{project['id']}/releases", json={"version": "no"}
        ).status_code
        == 404
    )
    client.headers.pop("Authorization")
    assert client.delete(f"/api/v1/credentials/{credential['id']}").status_code == 204
    client.headers["Authorization"] = "Bearer " + credential["token"]
    assert client.get("/api/v1/projects").status_code == 401


def test_no_membership_no_access(client):
    from dtvp.auth import issue
    from dtvp.models import User

    with client.app.state.sessions.begin() as db:
        user = User(issuer="test", subject="no-membership", name="No grants")
        db.add(user)
        db.flush()
        token, _, _ = issue(db, user, kind="api", workspace_id=None, allowed=["read"])
    client.headers["Authorization"] = "Bearer " + token
    assert client.get("/api/v1/projects").json() == []
    assert client.get("/api/v1/portfolio").json()["items"] == []




def test_session_is_committed_before_the_login_response(app):
    from fastapi.testclient import TestClient
    from sqlalchemy import event

    events = []

    def committed(session):
        events.append("commit")

    async def monitored_app(scope, receive, send):
        async def record_send(message):
            if (
                scope.get("path") == "/api/v1/playground/login"
                and message["type"] == "http.response.start"
            ):
                events.append("response")
            await send(message)

        await app(scope, receive, record_send)

    session_class = app.state.sessions.class_
    event.listen(session_class, "after_commit", committed)
    try:
        with TestClient(monitored_app) as client:
            events.clear()
            response = client.post("/api/v1/playground/login", json={"persona": "analyst"})
            assert response.status_code == 200
            assert events == ["commit", "response"]
            assert client.get("/api/v1/me").status_code == 200
    finally:
        event.remove(session_class, "after_commit", committed)
