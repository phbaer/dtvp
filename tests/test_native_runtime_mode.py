"""Only the first public API and journal workflows are exposed."""

from fastapi.testclient import TestClient

from dtvp.api_contract import API_PREFIX
from dtvp.migration_models import Release
from dtvp.models import Project
from tests.conftest import login
from tests.test_knowledge_api import body, imported, product


def test_only_native_api_routes_and_shared_identity_services(analyst, bom):
    paths = analyst.get("/openapi.json").json()["paths"]
    assert all(
        path.startswith((API_PREFIX + "/", "/auth/", "/healthz", "/readyz")) for path in paths
    )
    for suffix in (
        "findings",
        "snapshots",
        "statistics",
        "playground/reset",
        "playground/scale",
        "playground/knowledge/seed",
    ):
        assert f"{API_PREFIX}/{suffix}" not in paths
    assert "/api/v2/me" not in paths and "/api/v3/me" not in paths
    assert "legacy_review_enabled" not in analyst.get(API_PREFIX + "/me").json()
    assert analyst.get(API_PREFIX + "/cvss/metrics/3.1").status_code == 200
    project_id = product(analyst)
    head = imported(analyst, project_id, "native-1", body(bom))
    assert (
        analyst.get(
            f"{API_PREFIX}/projects/{project_id}/states/{head}/license-worklist"
        ).status_code
        == 200
    )
    assert f"{API_PREFIX}/projects/{{project_id}}/scoring/preview" in paths
    assert f"{API_PREFIX}/projects/{{project_id}}/scoring/rules/preview" in paths
    assert (
        f"{API_PREFIX}/projects/{{project_id}}/versions/{{version}}/migration/v2/preview" in paths
    )


def test_playground_startup_creates_identities_only_and_keeps_existing_archive_rows(app):
    with TestClient(app) as client:
        login(client)
        assert client.get(API_PREFIX + "/projects").json() == []
        with app.state.sessions.begin() as db:
            workspace = client.get(API_PREFIX + "/me").json()["workspaces"][0]["id"]
            project = Project(workspace_id=workspace, name="Retained imported history")
            db.add(project)
            db.flush()
            release = Release(project_id=project.id, version="archived")
            db.add(release)
            db.flush()
            release_id = release.id
        from dtvp.playground import seed

        with app.state.sessions.begin() as db:
            seed(db)
            assert db.get(Release, release_id) is not None
        assert client.get(f"{API_PREFIX}/projects/{project.id}/releases").status_code == 404
