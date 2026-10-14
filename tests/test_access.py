from tests.conftest import login


def test_team_isolation_and_revoked_sharing(analyst, release_id):
    client = analyst
    private_project = client.get("/api/v2/projects").json()[0]
    finding_id = client.get("/api/v2/findings").json()["items"][0]["id"]
    snapshot = client.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    login(client, "operations")
    for endpoint in [
        f"/releases/{release_id}/components",
        f"/findings/{finding_id}",
        f"/snapshots/{snapshot['id']}/bundle",
        f"/projects/{private_project['id']}/audit",
    ]:
        assert client.get("/api/v2" + endpoint).status_code == 404
    assert [row["identifier"] for row in client.get("/api/v2/findings").json()["items"]] == [
        "CVE-2099-20003"
    ]
    operations_id = client.get("/api/v2/me").json()["workspaces"][0]["id"]
    login(client, "administrator")
    assert (
        client.put(
            f"/api/v2/projects/{private_project['id']}/sharing",
            json={"workspace_id": operations_id, "capabilities": ["read"]},
        ).status_code
        == 200
    )
    login(client, "operations")
    assert client.get(f"/api/v2/findings/{finding_id}").status_code == 200
    assert (
        client.post(
            f"/api/v2/findings/{finding_id}/decisions",
            json={"expected_version": 1, "state": "affected", "rationale": "Not granted."},
        ).status_code
        == 404
    )
    login(client, "administrator")
    client.put(
        f"/api/v2/projects/{private_project['id']}/sharing",
        json={"workspace_id": operations_id, "capabilities": []},
    )
    login(client, "operations")
    assert client.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").status_code == 404


def test_csrf_machine_scope_and_revocation(client):
    assert client.get("/api/v2/projects").status_code == 401
    login(client, "administrator")
    workspace_id = client.get("/api/v2/me").json()["workspaces"][0]["id"]
    projects = client.get("/api/v2/projects").json()
    project = next(p for p in projects if p["workspace_id"] == workspace_id)
    client.headers["X-CSRF-Token"] = "wrong"
    assert (
        client.post(
            "/api/v2/projects", json={"workspace_id": workspace_id, "name": "Unauthorized"}
        ).status_code
        == 403
    )
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]
    response = client.post(
        "/api/v2/credentials",
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
    assert [p["id"] for p in client.get("/api/v2/projects").json()] == [project["id"]]
    assert (
        client.post(
            f"/api/v2/projects/{project['id']}/releases", json={"version": "no"}
        ).status_code
        == 404
    )
    client.headers.pop("Authorization")
    assert client.delete(f"/api/v2/credentials/{credential['id']}").status_code == 204
    client.headers["Authorization"] = "Bearer " + credential["token"]
    assert client.get("/api/v2/projects").status_code == 401


def test_no_membership_no_access(client):
    from dtvp.auth import issue
    from dtvp.models import User

    with client.app.state.sessions.begin() as db:
        user = User(issuer="test", subject="no-membership", name="No grants")
        db.add(user)
        db.flush()
        token, _, _ = issue(db, user, kind="api", workspace_id=None, allowed=["read"])
    client.headers["Authorization"] = "Bearer " + token
    assert client.get("/api/v2/projects").json() == []
    assert [row["identifier"] for row in client.get("/api/v2/findings").json()["items"]] == [
        "CVE-2099-20003"
    ]


def test_dt_read_credential_cannot_import_an_unbound_project(analyst, release_id):
    from tests.conftest import login

    analyst.app.state.settings.dt_url = "https://dt.example.invalid"
    analyst.app.state.settings.dt_api_key = "test-read-key"
    project_id = analyst.get("/api/v2/projects").json()[0]["id"]
    external = "00000000-0000-0000-0000-000000000001"
    payload = {"kind": "import-dt", "release_id": release_id, "external_project_id": external}
    assert analyst.post("/api/v2/jobs", json=payload).status_code == 403
    assert (
        analyst.put(
            f"/api/v2/projects/{project_id}/connectors/dependency-track",
            json={"external_project_id": external},
        ).status_code
        == 404
    )
    login(analyst, "administrator")
    assert (
        analyst.put(
            f"/api/v2/projects/{project_id}/connectors/dependency-track",
            json={"external_project_id": external},
        ).status_code
        == 200
    )
    login(analyst)
    assert analyst.post("/api/v2/jobs", json=payload).status_code == 202
