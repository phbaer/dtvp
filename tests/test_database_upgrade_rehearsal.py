"""Opt-in local-image PostgreSQL 17→18 candidate rehearsal; no production cutover."""

import json
import os
import shutil
import socket
import subprocess
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from dtvp.main import create_app
from dtvp.models import Job
from scripts import database_upgrade as upgrade
from tests.conftest import login
from tests.test_installation_recovery import configured, operational_rows, tree_hashes
from tests.test_workflow_api import reviewed, setup, url, workspace

pytestmark = pytest.mark.skipif(
    os.getenv("DTVP_UPGRADE_REHEARSAL") != "1",
    reason="Explicit isolated local Docker rehearsal required",
)


def test_stopped_application_major_upgrade_preserves_native_and_operational_state(
    tmp_path, bom, monkeypatch
):
    for image in ("postgres:17", "postgres:18"):
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode:
            pytest.skip(
                "Rehearsal needs preexisting local PostgreSQL 17 and 18 images; no images pulled"
            )
    token = uuid4().hex
    source_name, candidate_name = f"dtvp-upgrade-{token}-source", f"dtvp-upgrade-{token}-candidate"
    source_volume = f"dtvp-upgrade-{token}-data"
    password = "synthetic-upgrade-only-123"
    monkeypatch.setenv("DTVP_UPGRADE_TARGET_PASSWORD", password)
    source, candidate, backups = tmp_path / "source", tmp_path / "candidate", tmp_path / "dumps"
    source.mkdir()
    candidate.mkdir()
    target_volume = None
    target_nonce = None
    docker = upgrade.docker
    try:
        docker(
            "volume",
            "create",
            "--label",
            f"dtvp.rehearsal={token}",
            source_volume,
            stdout=subprocess.DEVNULL,
        )
        docker(
            "run",
            "--pull=never",
            "--name",
            source_name,
            "--label",
            f"dtvp.rehearsal={token}",
            "-e",
            "POSTGRES_PASSWORD",
            "-e",
            "POSTGRES_USER=dtvp",
            "-e",
            "POSTGRES_DB=dtvp",
            "--mount",
            f"type=volume,source={source_volume},target=/var/lib/postgresql/data",
            "-p",
            "127.0.0.1::5432",
            "-d",
            "postgres:17",
            env={**os.environ, "POSTGRES_PASSWORD": password},
            stdout=subprocess.DEVNULL,
        )
        for _ in range(60):
            result = subprocess.run(
                ["docker", "exec", source_name, "pg_isready", "-h", "127.0.0.1", "-U", "dtvp"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("Owned PostgreSQL 17 rehearsal source did not start")
        port = int(upgrade.output("port", source_name, "5432/tcp").rsplit(":", 1)[1])
        source_url = f"postgresql+psycopg://dtvp:{password}@127.0.0.1:{port}/dtvp"
        original = create_app(configured(source, source_url))
        with TestClient(original) as client:
            project, _ = setup(client, bom, versions=("7.1.1", "7.1.2"))
            reviewed(client, project)
            login(client, "analyst")
            before_workspace = workspace(client, project)
            login(client, "administrator")
            exported = client.post(
                url(project, f"/states/{before_workspace['state']}/exports/bundle")
            )
            assert exported.status_code == 201, exported.text
            exported = exported.json()
            archived = {
                name: client.get(item["url"]).content for name, item in exported["files"].items()
            }
            cookies = httpx.Cookies(client.cookies)
            actor = client.get("/api/v1/me").json()["id"]
            with original.state.sessions.begin() as db:
                db.add(
                    Job(
                        id="upgrade-uncertain-job",
                        project_id=project,
                        actor_id=actor,
                        kind="agentyzer-native",
                        status="failed",
                        payload={"rehearsal": True},
                        result={"remote_submission": {"status": "uncertain"}},
                        error="Synthetic uncertain request; never resubmit",
                        attempts=1,
                    )
                )
            rows = operational_rows(original)
            head = original.state.knowledge.head()
            refs = original.state.knowledge.references()
        # Application contexts are closed: no application writers during dump/restore.
        artifacts = tree_hashes(source / "artifacts")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            target_port = reservation.getsockname()[1]
        upgrade.main(
            [
                "--source-container",
                source_name,
                "--target-name",
                candidate_name,
                "--backup-dir",
                str(backups),
                "--port",
                str(target_port),
                "--writers-stopped",
            ]
        )
        manifest = json.loads((backups / f"{candidate_name}.manifest.json").read_text())
        target_volume = manifest["target_volume"]
        target_nonce = target_volume.rsplit("-", 1)[1]
        assert manifest["source_major"] == 17 and manifest["target_major"] == 18
        assert operational_rows(original) == rows and tree_hashes(source / "artifacts") == artifacts
        shutil.copytree(source / "artifacts", candidate / "artifacts")
        restored = create_app(
            configured(
                candidate, f"postgresql+psycopg://dtvp:{password}@127.0.0.1:{target_port}/dtvp"
            )
        )
        assert operational_rows(restored) == rows
        assert (
            restored.state.knowledge.head() == head
            and restored.state.knowledge.references() == refs
        )
        with TestClient(restored) as client:
            client.cookies.update(cookies)
            assert client.get("/api/v1/me").json()["id"] == actor
            login(client, "analyst")
            assert workspace(client, project) == before_workspace
            login(client, "administrator")
            for name, item in exported["files"].items():
                assert client.get(item["url"]).content == archived[name]
            login(client, "operations")
            assert client.get(url(project, "/versions/7.1.1/workspace")).status_code == 404
            assert client.get(exported["files"]["bundle.json"]["url"]).status_code == 404
        assert tree_hashes(source / "artifacts") == artifacts
        original.state.engine.dispose()
        restored.state.engine.dispose()
    finally:
        # Only this test's unpredictable, ownership-labelled resources may be removed.
        manifest_path = backups / f"{candidate_name}.manifest.json"
        if manifest_path.exists():
            target_volume = json.loads(manifest_path.read_text())["target_volume"]
            target_nonce = target_volume.rsplit("-", 1)[1]
        for name, label, expected in (
            (source_name, "dtvp.rehearsal", token),
            (candidate_name, "dtvp.upgrade", target_nonce),
        ):
            result = subprocess.run(
                ["docker", "inspect", "--format", '{{index .Config.Labels "' + label + '"}}', name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and expected and result.stdout.strip() == expected:
                docker("rm", "-f", name, stdout=subprocess.DEVNULL)
        for name, label, expected in (
            (source_volume, "dtvp.rehearsal", token),
            (target_volume, "dtvp.upgrade", target_nonce),
        ):
            if not name or not expected:
                continue
            result = subprocess.run(
                [
                    "docker",
                    "volume",
                    "inspect",
                    "--format",
                    '{{index .Labels "' + label + '"}}',
                    name,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip() == expected:
                docker("volume", "rm", name, stdout=subprocess.DEVNULL)
