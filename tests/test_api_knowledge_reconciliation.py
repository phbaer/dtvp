"""Actual HTTP correspondence confirms provenance, never transfers human decisions."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.journal import CommitUncertain, Journal
from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def prepare(client, bom, *, approved=False):
    project, _ = setup(client, bom)
    if approved:
        reviewed(client, project)
    login(client, "administrator")
    source = workspace(client, project)["state"]
    old = bom["components"][0]["bom-ref"]
    new = old + "-renamed"

    def rewrite(value, field=""):
        if isinstance(value, dict):
            return {key: rewrite(item, key) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite(item, field) for item in value]
        return new if field in {"bom-ref", "ref", "dependsOn"} and value == old else value

    target = imported(
        client,
        project,
        "7.1.1",
        body(rewrite(copy.deepcopy(bom)), expected=source, request_id="renamed", build_number=2),
    )
    pairs = [{"kind": "component", "source_id": old, "target_id": new}]
    response = client.post(
        url(project, "/reconciliation/preview"),
        json={"source": source, "target": target, "pairs": pairs},
    )
    assert response.status_code == 200, response.text
    data = {
        "request_id": "confirm-mapping",
        "expected": target,
        "expected_revision": None,
        "source": source,
        "preview_digest": response.json()["preview_digest"],
        "pairs": pairs,
        "rationale": "Reviewed producer reference migration",
        "evidence": [{"ticket": "migration-123"}],
    }
    return project, source, target, data


def confirm(client, project, data, name="mapping"):
    return client.post(url(project, f"/versions/7.1.1/reconciliations/{name}/confirm"), json=data)


def registry(client, project, state, **params):
    response = client.get(url(project, f"/states/{state}/reconciliations"), params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_confirm_replay_and_retraction_retain_scope_and_do_not_transfer_approval(analyst, app, bom):
    project, source, target, data = prepare(analyst, bom, approved=True)
    journal = app.state.knowledge
    before = load_sections(journal, target)
    response = confirm(analyst, project, data)
    assert response.status_code == 201, response.text
    receipt = response.json()
    state = receipt["updates"][0]["target"]
    after = load_sections(journal, state)
    assert {key: value for key, value in before.items() if key != "history"} == {
        key: value for key, value in after.items() if key != "history"
    }
    assert confirm(analyst, project, data).json()["publication"] == receipt["publication"]
    active = registry(analyst, project, state, limit=1)
    assert active["capabilities"] == ["write"] and active["total"] == 1
    payload = active["items"][0]["payload"]
    assert (
        payload["source"] == source and payload["target"] == target and payload["stage"] == "active"
    )
    revoke = {
        "request_id": "retract-mapping",
        "expected": state,
        "expected_revision": active["items"][0]["revision"],
        "reason": "Producer withdrew claimed correspondence",
    }
    revoked = analyst.post(
        url(project, "/versions/7.1.1/reconciliations/mapping/retract"), json=revoke
    )
    assert revoked.status_code == 201, revoked.text
    final = revoked.json()["updates"][0]["target"]
    assert registry(analyst, project, final)["items"][0]["payload"]["stage"] == "retracted"
    assert registry(analyst, project, state)["items"][0]["payload"]["stage"] == "active"
    assert registry(analyst, project, source)["total"] == 0
    assert (
        analyst.post(
            url(project, "/versions/7.1.1/reconciliations/mapping/retract"), json=revoke
        ).json()["publication"]
        == revoked.json()["publication"]
    )


def test_read_write_and_project_authorization_are_separate(analyst, app, bom):
    project, source, target, data = prepare(analyst, bom)
    login(analyst, "reviewer")
    preview = analyst.post(
        url(project, "/reconciliation/preview"),
        json={"source": source, "target": target, "pairs": data["pairs"]},
    )
    assert preview.status_code == 200, preview.text
    assert registry(analyst, project, target)["capabilities"] == []
    before = app.state.knowledge.head()
    assert confirm(analyst, project, data).status_code == 404
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert (
        analyst.post(
            url(project, "/reconciliation/preview"),
            json={"source": source, "target": target, "pairs": data["pairs"]},
        ).status_code
        == 404
    )
    assert analyst.get(url(project, f"/states/{target}/reconciliations")).status_code == 404
    assert confirm(analyst, project, data).status_code == 404


def test_stale_heads_revision_preview_and_hard_conflicts_do_not_publish(analyst, app, bom):
    project, source, target, data = prepare(analyst, bom)
    journal = app.state.knowledge
    before = journal.head()
    assert confirm(analyst, project, {**data, "preview_digest": "f" * 64}).status_code == 409
    assert confirm(analyst, project, {**data, "expected_revision": "f" * 64}).status_code == 409
    missing = analyst.post(
        url(project, "/reconciliation/preview"),
        json={
            "source": source,
            "target": target,
            "pairs": [{**data["pairs"][0], "target_id": "missing"}],
        },
    )
    assert missing.status_code == 200 and not missing.json()["eligible"]
    assert (
        confirm(
            analyst,
            project,
            {
                **data,
                "pairs": [{**data["pairs"][0], "target_id": "missing"}],
                "preview_digest": missing.json()["preview_digest"],
            },
        ).status_code
        == 409
    )
    assert journal.head() == before
    assert (
        analyst.post(
            url(project, "/reconciliation/preview"),
            json={"source": target, "target": source, "pairs": data["pairs"]},
        ).status_code
        == 409
    )
    assert (
        analyst.post(
            url(project, "/reconciliation/preview"),
            json={"source": "f" * 64, "target": target, "pairs": data["pairs"]},
        ).status_code
        == 404
    )
    assert (
        analyst.post(
            url(project, "/reconciliation/preview"),
            json={"source": source, "target": target, "pairs": data["pairs"] * 101},
        ).status_code
        == 422
    )
    assert (
        analyst.get(
            url(project, f"/states/{target}/reconciliations"), params={"limit": 201}
        ).status_code
        == 422
    )
    response = confirm(analyst, project, data)
    assert response.status_code == 201
    assert confirm(analyst, project, {**data, "request_id": str(uuid4())}).status_code == 409


@pytest.mark.parametrize("failure", ["projection", "uncertain"])
def test_uncertain_or_pending_projection_replays_exact_commit(
    analyst, app, bom, monkeypatch, failure
):
    project, _, _, data = prepare(analyst, bom)
    if failure == "projection":
        from dtvp import api_knowledge

        native = api_knowledge.catch_up

        def unavailable(*args, **kwargs):
            raise OSError("Projection offline")

        monkeypatch.setattr(api_knowledge, "catch_up", unavailable)
    else:
        native = Journal.publish

        def uncertain(self, **kwargs):
            receipt = native(self, **kwargs)
            raise CommitUncertain(receipt[0])

        monkeypatch.setattr(Journal, "publish", uncertain)
    first = confirm(analyst, project, data)
    assert first.status_code == (202 if failure == "projection" else 503), first.text
    head = app.state.knowledge.head()
    if failure == "projection":
        monkeypatch.setattr(api_knowledge, "catch_up", native)
    else:
        monkeypatch.setattr(Journal, "publish", native)
    replay = confirm(analyst, project, data)
    assert replay.status_code == 201, replay.text
    assert replay.json()["publication"] == first.json()["publication"]
    assert app.state.knowledge.head() == head
