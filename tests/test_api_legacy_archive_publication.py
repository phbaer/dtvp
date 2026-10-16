"""Reviewed archive publication checks current authority before upload and replay."""

import json

import pytest
from sqlalchemy import func, select
from starlette.requests import Request

from dtvp.models import Credential, Membership, User
from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product
from tests.test_knowledge_legacy_archive_publication import arguments, sanitized
from tests.test_workflow_api import url

app = knowledge_app


def headers(data):
    return {
        "Content-Type": "application/zip",
        "X-DTVP-Migration": json.dumps(data, ensure_ascii=True),
    }


def prepare(client):
    project = product(client)
    login(client, "administrator")
    args = arguments()
    return (
        project,
        url(project, "/versions/archive-1/migration/v1-archive"),
        args["data"].model_dump(mode="json"),
    )


def preview(client, path, metadata):
    response = client.post(path + "/preview", headers=headers(metadata), content=sanitized())
    assert response.status_code == 200, response.text
    return response.json()


def test_preview_and_apply_exact_artifacts_no_roles_or_native_human_authority(analyst, app):
    project, path, metadata = prepare(analyst)
    before = app.state.knowledge.head()
    with app.state.sessions() as db:
        users = db.scalar(select(func.count()).select_from(User))
        memberships = db.scalar(select(func.count()).select_from(Membership))
    proposed = preview(analyst, path, metadata)
    assert app.state.knowledge.head() == before
    assert proposed["archive_sha256"] == metadata["archive_sha256"]
    applied = metadata | {"preview_digest": proposed["preview_digest"]}
    response = analyst.post(path + "/apply", headers=headers(applied), content=sanitized())
    assert response.status_code in {200, 201}, response.text
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(User)) == users
        assert db.scalar(select(func.count()).select_from(Membership)) == memberships
    repeated = analyst.post(path + "/apply", headers=headers(applied), content=sanitized())
    assert repeated.status_code == response.status_code and repeated.json() == response.json()
    denied = metadata | {"request_id": "not-sanitized", "acknowledge_sanitized_export": False}
    assert (
        analyst.post(path + "/preview", headers=headers(denied), content=sanitized()).status_code
        == 422
    )


@pytest.mark.parametrize("persona", ["analyst", "reviewer", "viewer"])
def test_unauthorized_publication_never_reads_upload(analyst, persona):
    _, path, metadata = prepare(analyst)
    login(analyst, persona)
    consumed = []

    def forbidden():
        consumed.append(True)
        raise AssertionError("Unprivileged upload consumed")
        yield b"unreachable"

    response = analyst.post(path + "/preview", headers=headers(metadata), content=forbidden())
    assert response.status_code == 404, response.text
    assert consumed == []


def credential(client, app, project):
    with app.state.sessions() as db:
        selected = db.scalar(
            select(Credential).where(
                Credential.token_hash == digest(client.cookies["dtvp_session"].encode())
            )
        )
        assert selected and selected.kind == "session"
        return {"id": selected.id, "user_id": selected.user_id}


def test_revoked_actor_is_rejected_before_replay_upload(analyst, app):
    project, path, metadata = prepare(analyst)
    issued = credential(analyst, app, project)
    proposed = preview(analyst, path, metadata)
    applied = metadata | {"preview_digest": proposed["preview_digest"]}
    response = analyst.post(path + "/apply", headers=headers(applied), content=sanitized())
    assert response.status_code in {200, 201}, response.text
    with app.state.sessions.begin() as db:
        db.get(Credential, issued["id"]).revoked = True
    consumed = []

    def forbidden():
        consumed.append(True)
        raise AssertionError("Revoked replay upload consumed")
        yield b"unreachable"

    before = app.state.knowledge.head()
    response = analyst.post(path + "/apply", headers=headers(applied), content=forbidden())
    assert response.status_code == 401, response.text
    assert not consumed and app.state.knowledge.head() == before


@pytest.mark.parametrize("revocation", ["credential", "roles"])
def test_credential_revocation_during_upload_prevents_publication(
    analyst, app, monkeypatch, revocation
):
    project, path, metadata = prepare(analyst)
    issued = credential(analyst, app, project)
    proposed = preview(analyst, path, metadata)
    applied = metadata | {"preview_digest": proposed["preview_digest"]}
    original = Request.stream

    async def revoke_after_authorization(request):
        with app.state.sessions.begin() as db:
            if revocation == "credential":
                db.get(Credential, issued["id"]).revoked = True
            else:
                db.get(User, issued["user_id"]).org_admin = False
                for membership in db.scalars(
                    select(Membership).where(Membership.user_id == issued["user_id"])
                ):
                    membership.roles = ["viewer"]
        async for chunk in original(request):
            yield chunk

    before = app.state.knowledge.head()
    monkeypatch.setattr(Request, "stream", revoke_after_authorization)
    response = analyst.post(path + "/apply", headers=headers(applied), content=sanitized())
    assert response.status_code in {401, 403, 404}, response.text
    assert app.state.knowledge.head() == before


@pytest.mark.parametrize(
    "case",
    [
        "metadata_null",
        "root_null",
        "component_null",
        "component_children_null",
        "root_children_null",
        "root_child_null",
        "root_child_invalid_ref",
        "root_child_duplicate_ref",
    ],
)
def test_malformed_raw_tree_returns_422_without_publication(analyst, app, case):
    from tests.test_knowledge_legacy_archive_publication import malformed_archive

    _, path, _ = prepare(analyst)
    raw = malformed_archive(case)
    metadata = arguments(raw)["data"].model_dump(mode="json")
    before = app.state.knowledge.head(), set(app.state.knowledge.objects.root.rglob("*"))
    for action, data in (("preview", metadata), ("apply", metadata | {"preview_digest": "0" * 64})):
        response = analyst.post(path + "/" + action, headers=headers(data), content=raw)
        assert response.status_code == 422, response.text
    assert before == (app.state.knowledge.head(), set(app.state.knowledge.objects.root.rglob("*")))
