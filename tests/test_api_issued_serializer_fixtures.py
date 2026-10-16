"""Old captured files retain exact bytes while every fetch uses current authorization."""

import pytest
from sqlalchemy import select

from dtvp.models import Credential, Project
from dtvp.storage import digest
from tests.conftest import login
from tests.test_issued_serializer_fixtures import VARIANTS, disable_current_builders, restore
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app


@pytest.mark.parametrize("variant", VARIANTS)
def test_old_fixture_all_consumer_downloads_cached_preparation_and_current_auth(
    analyst, app, tmp_path, monkeypatch, variant
):
    journal, expected, _ = restore(tmp_path, variant)
    project = expected["project_id"]
    visible = analyst.get("/api/v2/projects").json()[0]["id"]
    with app.state.sessions.begin() as db:
        workspace = db.get(Project, visible).workspace_id
        db.add(
            Project(id=project, name="Synthetic serializer compatibility", workspace_id=workspace)
        )
    app.state.knowledge = journal
    disable_current_builders(monkeypatch)
    before = journal.head()
    downloads = []
    for capture in expected["captures"]:
        prefix = f"/api/v3/projects/{project}"
        path = prefix + "/issued-exports/" + capture["receipt_sha256"]
        description = analyst.get(path)
        assert description.status_code == 200, description.text
        assert description.json()["serializer_id"] == capture["serializer_id"]
        for name, file in capture["files"].items():
            url = path + "/files/" + name
            response = analyst.get(url)
            assert response.status_code == 200, response.text
            assert response.content == journal.objects.read(file["sha256"])
            assert response.headers["X-Content-SHA256"] == file["sha256"]
            downloads.append(url)
        prepare = prefix + "/states/" + expected["state"]
        if capture["kind"] == "knowledge-bundle":
            repeated = analyst.post(prepare + "/exports/bundle")
            assert repeated.status_code == 201, repeated.text
            assert repeated.json()["receipt_sha256"] == capture["receipt_sha256"]
        else:
            repeated = analyst.post(prepare + "/" + capture["kind"], json=capture["selector"])
            assert repeated.status_code == 200, repeated.text
            assert {key: repeated.json()[key] for key in capture["payload"]} == capture["payload"]
            if capture["kind"] == "vscorer-input":
                for public, stored in (
                    ("sbom.cdx.json", "sbom.json"),
                    ("cves.json", "cves.json"),
                    ("dtvp-source.json", "receipt.json"),
                ):
                    assert repeated.json()["files"][public].encode() == journal.objects.read(
                        capture["files"][stored]["sha256"]
                    )
    assert journal.head() == before
    login(analyst, "operations")
    for url in downloads:
        assert analyst.get(url).status_code == 404
    login(analyst)
    with app.state.sessions.begin() as db:
        current = db.scalar(
            select(Credential).where(
                Credential.token_hash == digest(analyst.cookies["dtvp_session"].encode())
            )
        )
        current.revoked = True
    assert analyst.get(downloads[0]).status_code == 401
