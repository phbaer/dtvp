import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from dtvp.config import Settings
from dtvp.db import engine_for, migrate, schema_ready
from dtvp.jobs import work_once
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
        assert (
            client.get("/api/v2/catalog/projects?q=Gateway").json()["items"][0]["id"]
            == project["id"]
        )
        finding = client.get("/api/v2/findings?sort=identifier&limit=1").json()
        assert client.get(
            "/api/v2/findings", params={"sort": "identifier", "cursor": finding["next_cursor"]}
        ).json()["items"]
        target = finding["items"][0]
        analysis = client.post(
            f"/api/v2/findings/{target['id']}/analyses",
            json={"expected_version": target["state_version"]},
        )
        assert analysis.status_code == 202
        analysis_id = analysis.json()["id"]
        assert work_once(client.app.state.sessions, client.app.state.artifacts, settings)
        assert (
            client.get(f"/api/v2/findings/{target['id']}/analyses").json()["items"][0]["result"][
                "proposal_state"
            ]
            == "affected"
        )
        login(client, "administrator")
        teams = client.get("/api/v2/me").json()["workspaces"]
        operations = next(team["id"] for team in teams if team["name"] == "Operations")
        assert (
            client.put(
                f"/api/v2/projects/{project['id']}/sharing",
                json={"workspace_id": operations, "capabilities": ["read"]},
            ).status_code
            == 200
        )
        login(client, "operations")
        assert len(client.get("/api/v2/catalog/projects").json()["items"]) == 2
    with TestClient(create_app(settings)) as client:
        login(client)
        assert client.get("/readyz").status_code == 200
        statistics = client.get("/api/v2/statistics").json()
        assert statistics["totals"]["findings"] == 2
        assert statistics["workflow"] == {"open": 2}
        from tests.test_rescoring import BASE, VECTOR

        finding = next(
            row
            for row in client.get("/api/v2/findings").json()["items"]
            if row["identifier"] == "CVE-2099-20001"
        )
        body = {
            "kind": "manual",
            "base_vector": BASE,
            "vector": VECTOR,
            "rationale": "PostgreSQL context verified.",
        }
        preview = client.post(
            f"/api/v2/findings/{finding['id']}/rescoring/preview",
            json={
                "expected_version": finding["state_version"],
                "state": "not_affected",
                "rescoring": body,
            },
        )
        assert preview.status_code == 200, preview.text
        result = client.post(
            f"/api/v2/findings/{finding['id']}/decisions",
            json={
                "expected_version": finding["state_version"],
                "state": "not_affected",
                "rationale": "Reviewed scoped exposure.",
                "rescoring": {**body, "preview_digest": preview.json()["preview_digest"]},
            },
        )
        assert result.status_code == 201, result.text
        login(client, "reviewer")
        current = client.get(f"/api/v2/findings/{finding['id']}").json()
        assert (
            client.post(
                f"/api/v2/findings/{finding['id']}/approvals",
                json={
                    "expected_version": current["state_version"],
                    "decision_id": result.json()["id"],
                },
            ).status_code
            == 200
        )
        assert client.get("/api/v2/statistics").json()["totals"]["adopted_rescoring"] == 1
        assert (
            client.get("/api/v2/findings?sort=effective_score").json()["items"][-1][
                "effective_score"
            ]
            == 0
        )
        assert client.get(f"/api/v2/snapshots/{snapshot_id}/bundle").content == original
        assert (
            client.get(f"/api/v2/analyses/{analysis_id}/report").json()["assessment"][
                "application_eligible"
            ]
            is True
        )
    engine.dispose()
