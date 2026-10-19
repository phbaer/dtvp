"""Quiesced full-installation rehearsal, distinct from rebuilding projections.

SQLite runs by default; an explicitly configured disposable PostgreSQL pair
exercises actual Docker pg_dump/pg_restore. Production configuration and remote
identity/provider qualification remain deployment acceptance gates.
"""

import os
import shutil
import sqlite3
import subprocess

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text
from sqlalchemy.engine import make_url

from dtvp.config import Settings
from dtvp.db import engine_for
from dtvp.knowledge.projection import catch_up, cursor, heads, records
from dtvp.knowledge.verification import verify_journal
from dtvp.main import create_app
from dtvp.models import Credential, Job, Membership, Project, User
from tests.conftest import login
from tests.test_workflow_api import reviewed, setup, url, workspace


def configured(directory, database_url=None):
    return Settings(
        _env_file=None,
        playground=True,
        database_url=database_url or f"sqlite:///{directory / 'operational.sqlite'}",
        artifact_dir=directory / "artifacts",
        frontend_dir=directory / "absent",
    )


PG_ENV = ("DTVP_RECOVERY_SOURCE_URL", "DTVP_RECOVERY_TARGET_URL", "DTVP_RECOVERY_CONTAINER")


def postgres_pair():
    source, target = (make_url(os.environ[key]) for key in PG_ENV[:2])
    if (
        not source.drivername.startswith("postgresql")
        or not target.drivername.startswith("postgresql")
        or not (source.database or "").endswith("_recovery_test")
        or not (target.database or "").endswith("_recovery_test")
        or source.database == target.database
        or (source.host, source.port, source.username)
        != (target.host, target.port, target.username)
    ):
        pytest.fail("Recovery needs distinct disposable *_recovery_test databases on one server")
    return source, target


def restore_database(backend, source, candidate):
    if backend == "sqlite":
        with sqlite3.connect(source / "operational.sqlite") as old:
            with sqlite3.connect(candidate / "operational.sqlite") as restored:
                old.backup(restored)
        return
    old, restored = postgres_pair()
    container = os.environ["DTVP_RECOVERY_CONTAINER"]
    # Passwords never enter argv or captured output. These opt-in disposable
    # containers must permit their application user to run local socket tools.
    dump = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "pg_dump",
            "-U",
            old.username,
            "-d",
            old.database,
            "--format=custom",
            "--no-owner",
            "--no-acl",
        ],
        check=True,
        capture_output=True,
    ).stdout
    subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "pg_restore",
            "-U",
            restored.username,
            "-d",
            restored.database,
            "--clean",
            "--if-exists",
            "--exit-on-error",
            "--single-transaction",
            "--no-owner",
            "--no-acl",
        ],
        input=dump,
        check=True,
        capture_output=True,
    )


def tree_hashes(directory):
    from dtvp.storage import digest

    return {
        str(path.relative_to(directory)): digest(path.read_bytes())
        for path in directory.rglob("*")
        if path.is_file()
    }


def operational_rows(app):
    with app.state.sessions() as db:
        return {
            model.__tablename__: [
                {column.name: getattr(row, column.name) for column in model.__table__.columns}
                for row in db.scalars(select(model).order_by(model.id))
            ]
            for model in (User, Credential, Project, Job)
        } | {
            "memberships": [
                (row.workspace_id, row.user_id, row.roles)
                for row in db.scalars(
                    select(Membership).order_by(Membership.workspace_id, Membership.user_id)
                )
            ]
        }


@pytest.mark.parametrize(
    "backend", ["sqlite"] + (["postgres"] if all(os.getenv(key) for key in PG_ENV) else [])
)
def test_offline_installation_restore_preserves_permissions_jobs_history_and_issued_bytes(
    tmp_path, bom, backend
):
    source, candidate = tmp_path / "source", tmp_path / "candidate"
    source.mkdir()
    source_url = target_url = None
    if backend == "postgres":
        postgres_pair()
        source_url, target_url = (os.environ[key] for key in PG_ENV[:2])
        # Only the explicitly opted-in disposable source is reset; restore writes
        # only to its separately named disposable candidate database.
        engine = engine_for(source_url)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    original = create_app(configured(source, source_url))
    with TestClient(original) as client:
        login(client, "administrator")
        team = next(
            item for item in client.get("/api/v1/workspaces").json()
            if item["name"] == "Platform"
        )
        created = client.post(
            "/api/v1/projects",
            json={"workspace_id": team["id"], "name": "Synthetic recovery rehearsal"},
        )
        assert created.status_code == 201, created.text
        project_id, _ = setup(client, bom, versions=("7.1.1", "7.1.2"))
        reviewed(client, project_id)
        current = workspace(client, project_id)
        assert current["items"][0]["coverage"]["status"] == "approved"
        login(client, "administrator")
        tagged = client.post(
            url(project_id, "/tags"),
            json={"name": "restored-release", "state": current["state"], "request_id": "tag"},
        )
        assert tagged.status_code == 201, tagged.text
        issued = client.post(url(project_id, f"/states/{current['state']}/exports/bundle"))
        assert issued.status_code == 201, issued.text
        issued = issued.json()
        archived = {
            name: client.get(details["url"]).content for name, details in issued["files"].items()
        }
        actor = client.get("/api/v1/me").json()["id"]
        # Operational remote outcomes must survive; journal replay cannot recover them.
        with original.state.sessions.begin() as db:
            db.add(
                Job(
                    id="recovery-uncertain-job",
                    project_id=project_id,
                    actor_id=actor,
                    kind="agentyzer-native",
                    status="failed",
                    payload={"scope": "synthetic-rehearsal"},
                    result={"remote_submission": {"status": "uncertain"}},
                    error="Synthetic uncertain POST; do not resubmit automatically",
                    attempts=1,
                )
            )
        before_rows = operational_rows(original)
        before_workspace = workspace(client, project_id)
        verification = verify_journal(original.state.knowledge)
        original_head = original.state.knowledge.head()
        references = original.state.knowledge.references()
        auth_cookies = httpx.Cookies(client.cookies)
    # All writers stopped. Original backup remains unchanged throughout rehearsal.
    source_files = tree_hashes(source / "artifacts")
    candidate.mkdir()
    restore_database(backend, source, candidate)
    shutil.copytree(source / "artifacts", candidate / "artifacts")
    assert tree_hashes(candidate / "artifacts") == source_files
    restored = create_app(configured(candidate, target_url))
    assert restored.state.knowledge.head() == original_head
    assert restored.state.knowledge.references() == references
    assert verify_journal(restored.state.knowledge) == verification
    assert operational_rows(restored) == before_rows
    # Rebuild only the native projection; operational tables must stay exact.
    with restored.state.engine.begin() as connection:
        connection.execute(delete(records))
        connection.execute(delete(heads))
        connection.execute(delete(cursor))
        connection.execute(cursor.insert().values(id=1, publication_sha=None, sequence=0))
    catch_up(restored.state.engine, restored.state.knowledge, rebuild=True)
    assert operational_rows(restored) == before_rows
    with TestClient(restored) as client:
        client.cookies.update(auth_cookies)
        assert client.get("/api/v1/me").json()["id"] == actor
        assert workspace(client, project_id) == before_workspace
        receipt = client.get(url(project_id, f"/issued-exports/{issued['receipt_sha256']}"))
        assert receipt.status_code == 200, receipt.text
        assert receipt.json() == {
            key: value for key, value in issued.items() if key != "projection"
        }
        for name, details in issued["files"].items():
            assert client.get(details["url"]).content == archived[name]
        assert client.get("/api/v1/findings").status_code == 404
        login(client, "operations")
        assert client.get(url(project_id, "/versions/7.1.1/workspace")).status_code == 404
        assert client.get(issued["files"]["bundle.json"]["url"]).status_code == 404
    assert tree_hashes(source / "artifacts") == source_files
    assert operational_rows(original) == before_rows
