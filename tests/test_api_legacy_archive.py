"""Management authorization must precede consuming an uploaded archive stream."""

import pytest

from dtvp import api_legacy_archive
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product
from tests.test_knowledge_legacy_archive import fixture
from tests.test_workflow_api import url

app = knowledge_app


def endpoint(client):
    return url(product(client), "/migration/v1-archive/preview")


def test_raw_archive_preview_pure_bounded_no_source_text_or_credentials(analyst, app):
    path = endpoint(analyst)
    login(analyst, "administrator")
    journal = app.state.knowledge
    before = journal.head(), set(journal.objects.root.rglob("*"))
    response = analyst.post(path, content=fixture(), headers={"Content-Type": "application/zip"})
    assert response.status_code == 200, response.text
    assert response.json()["writes"] is False and response.json()["statistics"]["versions"] == 1
    assert "fixture-secret" not in response.text and "Synthetic Reviewer" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert before == (journal.head(), set(journal.objects.root.rglob("*")))
    page = analyst.post(
        path, content=fixture(), params={"offset": 1}, headers={"Content-Type": "application/zip"}
    )
    assert (
        page.json()["items"] == []
        and page.json()["preview_digest"] == response.json()["preview_digest"]
    )


@pytest.mark.parametrize("actor", ["viewer", None])
def test_unprivileged_upload_stream_never_consumed(analyst, actor):
    path = endpoint(analyst)
    if actor:
        login(analyst, actor)
    else:
        analyst.cookies.clear()
    consumed = []

    def forbidden():
        consumed.append(True)
        raise AssertionError("Unauthorized archive body was consumed before authorization")
        yield b"unreachable"

    response = analyst.post(path, content=forbidden(), headers={"Content-Type": "application/zip"})
    assert response.status_code == (404 if actor else 401)
    assert consumed == []


def test_size_limits_content_type_and_generic_middleware_preserved(analyst, app, monkeypatch):
    path = endpoint(analyst)
    login(analyst, "administrator")
    assert analyst.post(path, content=fixture()).status_code == 415
    assert (
        analyst.post(path, content=b"bad", headers={"Content-Type": "application/zip"}).status_code
        == 422
    )
    monkeypatch.setattr(app.state.settings, "max_upload_bytes", 32)
    assert (
        analyst.post(
            path, content=b"x" * 33, headers={"Content-Type": "application/zip"}
        ).status_code
        == 413
    )
    monkeypatch.setattr(app.state.settings, "max_upload_bytes", 1000)
    monkeypatch.setattr(api_legacy_archive, "MAX_COMPRESSED", 32)
    assert (
        analyst.post(
            path, content=b"x" * 33, headers={"Content-Type": "application/zip"}
        ).status_code
        == 413
    )
    # A nonmatching/trailing-slash path retains the ordinary middleware's configured bound.
    monkeypatch.setattr(app.state.settings, "max_upload_bytes", 32)
    assert analyst.post(path + "/", content=b"x" * 33).status_code == 413
    assert analyst.put(path, content=b"x" * 33).status_code == 413
