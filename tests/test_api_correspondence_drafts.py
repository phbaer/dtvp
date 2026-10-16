"""HTTP adoption uses target permissions and explicit immutable correspondence."""

import copy
from uuid import uuid4

from dtvp.knowledge.ownership import policy_ref
from dtvp.knowledge.reconciliation import correspondence_key
from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_api_knowledge_synchronization_apply import prepared as synchronized
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import url, workspace

app = knowledge_app


def prepared(client, app, bom, *, other_team=False):
    project, payload, row = synchronized(client, bom, other_team=other_team)
    journal = app.state.knowledge
    source_context = load_sections(journal, payload["source"])["ownership"][
        "context:" + payload["source_context_id"]
    ]
    target_context = load_sections(journal, payload["target"])["ownership"][
        "context:" + payload["target_context_id"]
    ]
    pairs = [
        {
            "kind": "component",
            "source_id": source_context["component_ref"],
            "target_id": target_context["component_ref"],
        },
        {
            "kind": "context",
            "source_id": payload["source_context_id"],
            "target_id": payload["target_context_id"],
        },
    ]
    response = client.post(
        url(project, "/reconciliation/preview"),
        json={"source": payload["source"], "target": payload["target"], "pairs": pairs},
    )
    assert response.status_code == 200, response.text
    response = client.post(
        url(project, "/versions/7.1.2/reconciliations/explicit/confirm"),
        json={
            "request_id": str(uuid4()),
            "expected": payload["target"],
            "expected_revision": None,
            "source": payload["source"],
            "preview_digest": response.json()["preview_digest"],
            "pairs": pairs,
            "rationale": "Explicitly inspected both component and consuming context",
        },
    )
    assert response.status_code == 201, response.text
    target_state = workspace(client, project, "7.1.2")["state"]
    record = load_sections(journal, target_state)["history"][correspondence_key("explicit")]
    return project, {
        "source": payload["source"],
        "target": target_state,
        "source_context_id": payload["source_context_id"],
        "target_context_id": payload["target_context_id"],
        "vulnerability_id": payload["vulnerability_id"],
        "source_assessment_revision": payload["source_assessment_revision"],
        "assertions": {"explicit": record["revision"]},
        "expected_policy": journal.resolve(policy_ref(project)),
    }


def apply_payload(client, project, data):
    response = client.post(url(project, "/correspondence-drafts/preview"), json=data)
    assert response.status_code == 200, response.text
    return {
        **data,
        "request_id": str(uuid4()),
        "preview_digest": response.json()["preview_digest"],
        "assessment_id": "adopted-target-decision",
        "conditions": "Only the selected target consuming configuration.",
        "reason": "Target analyst explicitly adopts source rationale pending independent target review.",
    }, response.json()


def test_other_target_analyst_adopts_approved_historical_source_without_source_write(
    analyst, app, bom
):
    project, data = prepared(analyst, app, bom)
    source_before = copy.deepcopy(load_sections(app.state.knowledge, data["source"]))
    imported(
        analyst,
        project,
        "7.1.1",
        body(bom, request_id=str(uuid4()), expected=data["source"], build_number=2),
    )
    newer_source = workspace(analyst, project)["state"]
    assert newer_source != data["source"]
    login(analyst, "reviewer")
    payload, preview = apply_payload(analyst, project, data)
    assert preview["draft_allowed"] and preview["category"] == "needs_review"
    response = analyst.post(url(project, "/correspondence-drafts"), json=payload)
    assert response.status_code == 201, response.text
    updated = workspace(analyst, project, "7.1.2")
    item = next(
        item
        for item in updated["items"]
        if item["context_id"] == data["target_context_id"]
        and item["vulnerability_id"] == data["vulnerability_id"]
    )
    assert item["coverage"]["status"] == "draft" and not item["coverage"]["approved"]
    record = item["coverage"]["assessment"]
    assert record["payload"]["author_id"] != preview["source_author_id"]
    assert record["payload"]["evidence"][-1]["source_author_id"] == preview["source_author_id"]
    assert workspace(analyst, project)["state"] == newer_source
    assert load_sections(app.state.knowledge, data["source"]) == source_before
    replay = analyst.post(url(project, "/correspondence-drafts"), json=payload)
    assert replay.status_code == 201 and replay.json() == response.json()
    assert (
        analyst.post(
            url(project, "/correspondence-drafts"), json=payload | {"reason": "Changed request"}
        ).status_code
        == 409
    )


def test_other_team_is_read_only_and_cannot_publish_draft(analyst, app, bom):
    project, data = prepared(analyst, app, bom, other_team=True)
    payload, preview = apply_payload(analyst, project, data)
    assert not preview["draft_allowed"]
    before = app.state.knowledge.head()
    response = analyst.post(url(project, "/correspondence-drafts"), json=payload)
    assert response.status_code == 403, response.text
    assert app.state.knowledge.head() == before


def test_stale_preview_and_incomplete_assertions_fail_closed(analyst, app, bom):
    project, data = prepared(analyst, app, bom)
    payload, _ = apply_payload(analyst, project, data)
    before = app.state.knowledge.head()
    assert (
        analyst.post(
            url(project, "/correspondence-drafts"), json=payload | {"preview_digest": "0" * 64}
        ).status_code
        == 409
    )
    assert (
        analyst.post(
            url(project, "/correspondence-drafts/preview"),
            json=data | {"assertions": {"missing": "0" * 64}},
        ).status_code
        == 409
    )
    assert app.state.knowledge.head() == before


def test_uncertain_http_publication_replays_without_duplicate_target_revision(
    analyst, app, bom, monkeypatch
):
    from dtvp.knowledge.journal import CommitUncertain, Journal

    project, data = prepared(analyst, app, bom)
    payload, _ = apply_payload(analyst, project, data)
    native = Journal.publish

    def uncertain(self, **kwargs):
        receipt = native(self, **kwargs)
        raise CommitUncertain(receipt[0])

    monkeypatch.setattr(Journal, "publish", uncertain)
    response = analyst.post(url(project, "/correspondence-drafts"), json=payload)
    assert response.status_code == 503, response.text
    committed = app.state.knowledge.head()
    monkeypatch.setattr(Journal, "publish", native)
    replay = analyst.post(url(project, "/correspondence-drafts"), json=payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["publication"] == response.json()["publication"]
    assert app.state.knowledge.head() == committed


def test_historical_source_candidates_are_bounded_and_exact(analyst, app, bom):
    project, data = prepared(analyst, app, bom)
    response = analyst.get(
        url(project, f"/states/{data['source']}/correspondence-draft-candidates"),
        params={"limit": 1},
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["state"] == data["source"] and result["current_policy"] == data["expected_policy"]
    assert len(result["items"]) == 1
    row = next(item for item in result["items"] if item["context_id"] == data["source_context_id"])
    assert row["approved_assessment"]["revision"] == data["source_assessment_revision"]
    assert row["summary_only"] and "evidence" not in row["approved_assessment"]["payload"]
    empty = analyst.get(
        url(project, f"/states/{data['source']}/correspondence-draft-candidates"),
        params={"q": "no-matching-CVE"},
    )
    assert empty.status_code == 200 and empty.json()["total"] == 0
    assert (
        analyst.get(
            url(project, "/states/" + "0" * 64 + "/correspondence-draft-candidates")
        ).status_code
        == 422
    )
