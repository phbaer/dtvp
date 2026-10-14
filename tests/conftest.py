from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dtvp.config import Settings
from dtvp.main import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(
            _env_file=None,
            playground=True,
            database_url="sqlite:///:memory:",
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def login(client, persona="analyst"):
    response = client.post("/api/v2/playground/login", json={"persona": persona})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]


@pytest.fixture
def analyst(client):
    login(client)
    return client


@pytest.fixture
def release_id(analyst):
    projects = analyst.get("/api/v2/projects").json()
    return analyst.get(f"/api/v2/projects/{projects[0]['id']}/releases").json()[0]["id"]


@pytest.fixture
def bom():
    import json

    path = Path(__file__).resolve().parent.parent / "playground/fixtures/release.cdx.json"
    return json.loads(path.read_text())
