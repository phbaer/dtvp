import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from dtvp.config import Settings
from dtvp.db import engine_for, migrate, schema_ready
from dtvp.main import create_app
from tests.conftest import login


@pytest.mark.postgres
def test_postgres_migrations_concurrent_startup_restart_and_auth(tmp_path):
    url = os.getenv("DTVP_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set DTVP_TEST_DATABASE_URL to a disposable database")
    if not url.rsplit("/", 1)[-1].endswith("_test"):
        pytest.fail("Disposable test database name must end in _test")
    engine = engine_for(url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: migrate(engine), range(3)))
    assert schema_ready(engine)
    assert str(inspect(engine).get_columns("revisions")[7]["type"])
    settings = Settings(
        _env_file=None, playground=True, database_url=url, artifact_dir=tmp_path / "artifacts"
    )
    with TestClient(create_app(settings)) as client:
        login(client)
        project = client.get("/api/v2/projects").json()[0]
        release = client.get(f"/api/v2/projects/{project['id']}/releases").json()[0]
        result = client.post("/api/v2/snapshots", json={"release_id": release["id"]})
        assert result.status_code == 201
        snapshot_id = result.json()["id"]
        original = client.get(f"/api/v2/snapshots/{snapshot_id}/bundle").content
    with TestClient(create_app(settings)) as client:
        login(client)
        assert client.get("/readyz").status_code == 200
        assert client.get(f"/api/v2/snapshots/{snapshot_id}/bundle").content == original
    engine.dispose()
