"""Qualified pipeline observations are bounded and never grant native approval."""

import json

from sqlalchemy import select
from starlette.requests import Request

from dtvp.models import Credential
from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_integration_events import proof

app = knowledge_app


def prepared(client, bom):
    project = product(client)
    source_commit, target_commit, objects, _ = proof()
    common = {
        "subject_kind": "build",
        "subject_digest": "sha256:" + "e" * 64,
        "pipeline_run": "target-build",
    }
    source = imported(
        client,
        project,
        "7.1.1",
        body(
            bom,
            request_id="source-build",
            context=common
            | {"analysis_source": {"repository_name": "gateway", "source_commit": source_commit}},
        ),
    )
    target = imported(
        client,
        project,
        "7.1.2",
        body(
            bom,
            request_id="target-build",
            context=common
            | {"analysis_source": {"repository_name": "gateway", "source_commit": target_commit}},
        ),
    )
    payload = {
        "request_id": "integration-event",
        "source": source,
        "target": target,
        "expected_target": target,
        "repository": "gateway",
        "source_commit": source_commit,
        "target_commit": target_commit,
        "target_subject_digest": common["subject_digest"],
        "pipeline_run": "target-build",
        "integration_kind": "merge",
        "occurred_at": "2026-10-16T01:00:00Z",
        "rationale": "Exact qualified target pipeline declares integration",
        "git_commit_objects": objects,
    }
    return project, f"/api/v1/projects/{project}/integration-events", payload


def test_record_list_exact_replay_and_read_only_event_bound_preview(analyst, app, bom):
    project, path, payload = prepared(analyst, bom)
    response = analyst.post(path, json=payload)
    assert response.status_code == 201, response.text
    result = response.json()
    assert analyst.post(path, json=payload).json() == result
    state = result["updates"][0]["target"]
    selected = analyst.get(
        f"/api/v1/projects/{project}/states/{state}/integration-events/{result['event_id']}"
    )
    assert selected.status_code == 200, selected.text
    assert selected.json()["git_ancestry"]["status"] == "verified_commit_object_ancestry"
    assert not selected.json()["software_integration_verified"]
    page = analyst.get(
        f"/api/v1/projects/{project}/states/{state}/integration-events", params={"limit": 1}
    ).json()
    assert page["items"] == [selected.json()] and page["total"] == 1 and page["next_offset"] is None
    before = app.state.knowledge.head()
    preview = analyst.post(
        path + f"/{result['event_id']}/synchronization-preview", json={"target": state}
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["proposals"]["mode"] == "two_state"
    assert preview.json()["basis_selection"] == "none_no_inferred_common_basis"
    assert not preview.json()["apply_supported"]
    assert app.state.knowledge.head() == before


def test_read_only_actor_cannot_consume_proof_upload_or_record_event(analyst, bom):
    _, path, _ = prepared(analyst, bom)
    login(analyst, "viewer")
    consumed = []

    def forbidden():
        consumed.append(True)
        raise AssertionError("Unauthorized proof body consumed")
        yield b"unreachable"

    response = analyst.post(path, content=forbidden(), headers={"Content-Type": "application/json"})
    assert response.status_code == 404, response.text
    assert not consumed


def session_id(client, app):
    with app.state.sessions() as db:
        return db.scalar(
            select(Credential.id).where(
                Credential.token_hash == digest(client.cookies["dtvp_session"].encode())
            )
        )


def test_revoked_session_before_receipt_replay_does_not_read_upload(analyst, app, bom):
    _, path, payload = prepared(analyst, bom)
    response = analyst.post(path, json=payload)
    assert response.status_code == 201, response.text
    identity = session_id(analyst, app)
    with app.state.sessions.begin() as db:
        db.get(Credential, identity).revoked = True
    consumed = []

    def forbidden():
        consumed.append(True)
        raise AssertionError("Revoked replay proof body consumed")
        yield b"unreachable"

    before = app.state.knowledge.head()
    denied = analyst.post(path, content=forbidden(), headers={"Content-Type": "application/json"})
    assert denied.status_code == 401 and not consumed
    assert app.state.knowledge.head() == before


def test_session_revocation_during_proof_upload_prevents_publication(
    analyst, app, bom, monkeypatch
):
    _, path, payload = prepared(analyst, bom)
    identity = session_id(analyst, app)
    original = Request.stream

    async def revoked(request):
        with app.state.sessions.begin() as db:
            db.get(Credential, identity).revoked = True
        async for chunk in original(request):
            yield chunk

    monkeypatch.setattr(Request, "stream", revoked)
    before = app.state.knowledge.head()
    response = analyst.post(path, json=payload)
    assert response.status_code == 401, response.text
    assert app.state.knowledge.head() == before


def test_invalid_partial_or_oversized_proof_returns_generic_failure_no_publication(
    analyst, app, bom
):
    _, path, payload = prepared(analyst, bom)
    before = app.state.knowledge.head()
    partial = dict(payload)
    partial["git_commit_objects"] = {
        payload["target_commit"]: payload["git_commit_objects"][payload["target_commit"]]
    }
    response = analyst.post(path, json=partial)
    assert response.status_code == 422, response.text
    app.state.settings.max_upload_bytes = 100
    response = analyst.post(
        path, content=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413, response.text
    assert app.state.knowledge.head() == before
