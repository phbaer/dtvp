from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from dtvp.config import Settings
from dtvp.main import create_app
from dtvp.models import Project, Workspace


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
        # Explicit empty test projects; runtime playground seeding creates identities only.
        with app.state.sessions.begin() as db:
            for workspace in db.scalars(select(Workspace)):
                db.add(Project(workspace_id=workspace.id, name="Demo Gateway" if workspace.name == "Platform" else "Demo Worker"))
        yield client


def login(client, persona="analyst"):
    response = client.post("/api/v1/playground/login", json={"persona": persona})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies["dtvp_csrf"]


@pytest.fixture
def analyst(client):
    login(client)
    return client


@pytest.fixture
def bom():
    import json

    path = Path(__file__).resolve().parent.parent / "playground/fixtures/release.cdx.json"
    return json.loads(path.read_text())
