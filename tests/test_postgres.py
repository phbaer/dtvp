"""Disposable PostgreSQL startup and durable native workflow qualification."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from dtvp.config import Settings
from dtvp.db import engine_for, migrate, schema_ready
from dtvp.main import create_app
from dtvp.storage import digest
from tests.conftest import login
from tests.test_workflow_api import reviewed, score_input, setup, url, workspace


@pytest.mark.postgres
def test_postgres_migrations_concurrent_startup_restart_and_auth(tmp_path, bom):
    database_url = os.getenv("DTVP_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("Set DTVP_TEST_DATABASE_URL to a disposable database")
    if not database_url.rsplit("/", 1)[-1].endswith("_test"):
        pytest.fail("Disposable test database name must end in _test")
    engine = engine_for(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    settings = Settings(
        _env_file=None,
        playground=True,
        database_url=database_url,
        artifact_dir=tmp_path / "artifacts",
        frontend_dir=tmp_path / "absent",
    )
    # First application startup implicitly creates the complete schema.
    with TestClient(create_app(settings)) as client:
        assert schema_ready(engine)
        assert client.get("/api/v1/me").status_code == 401
        login(client, "administrator")
        teams = client.get("/api/v1/workspaces").json()
        platform = next(team["id"] for team in teams if team["name"] == "Platform")
        created = client.post(
            "/api/v1/projects", json={"workspace_id": platform, "name": "PG native product"}
        )
        assert created.status_code == 201, created.text
        project, _ = setup(client, bom)
        row, _ = reviewed(client, project)
        login(client, "coordinator")
        data = score_input(client, project, row)
        preview = client.post(url(project, "/scoring/preview"), json=data)
        assert preview.status_code == 200 and preview.json()["eligible"], preview.text
        published = client.post(
            url(project, "/scoring/publish"), json={**data, "preview": preview.json()["preview"]}
        )
        assert published.status_code == 201, published.text
        scored = workspace(client, project)
        selected = next(item for item in scored["items"] if item["id"] == row["id"])
        assert selected["published_score"]["current"]
        assert selected["published_score"]["base_score"] == 9.8
        state = scored["state"]
        bundle_path = url(project, f"/states/{state}/bundle")
        bundle = client.get(bundle_path)
        assert bundle.status_code == 200
        original = bundle.content
        assert bundle.headers["x-content-sha256"] == digest(original)
        assert client.get("/readyz").status_code == 200
    # Concurrent implicit-upgrade machinery must remain idempotent after startup.
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: migrate(engine), range(3)))
    assert schema_ready(engine)
    # Retained historical schema remains available for explicit offline migration.
    assert {"releases", "revisions", "snapshots"} <= set(inspect(engine).get_table_names())
    assert "document" in {column["name"] for column in inspect(engine).get_columns("revisions")}
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM releases")) == 0
    # Restart recovers exactly the same immutable bundle and reviewed contextual score.
    with TestClient(create_app(settings)) as client:
        login(client, "coordinator")
        assert client.get("/readyz").status_code == 200
        assert client.get(bundle_path).content == original
        current = workspace(client, project)
        assert current["state"] == state
        assert next(item for item in current["items"] if item["id"] == row["id"])[
            "published_score"
        ]["current"]
        # Revoke a live principal's membership using the manager API. Its existing
        # session must immediately lose both current and pinned historical access.
        manager = TestClient(client.app)
        try:
            login(manager, "administrator")
            response = manager.put(
                f"/api/v1/workspaces/{platform}/members",
                json={
                    "issuer": "playground",
                    "subject": "coordinator",
                    "name": "Security coordinator",
                    "roles": [],
                },
            )
            assert response.status_code == 200, response.text
            assert client.get(bundle_path).status_code == 404
            assert client.get(url(project, "/versions/7.1.1/workspace")).status_code == 404
            assert client.post(url(project, "/scoring/preview"), json=data).status_code == 404
            assert manager.get(bundle_path).content == original
        finally:
            manager.close()
    engine.dispose()
