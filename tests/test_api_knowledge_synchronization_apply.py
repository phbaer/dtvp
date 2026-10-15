"""HTTP synchronization copies explicit author content into an unapproved target draft."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.assessments import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app
SOURCE, TARGET = "7.1.1", "7.1.2"


def prepared(client, bom, *, other_team=False):
    project_id, teams = setup(client, bom, versions=(SOURCE, TARGET))
    if other_team:
        login(client, "administrator")
        apply_policy(
            client,
            project_id,
            [
                {"selector": "*", "team_id": teams["Platform"], "versions": [SOURCE]},
                {"selector": "*", "team_id": teams["Operations"], "versions": [TARGET]},
            ],
            request_id=str(uuid4()),
        )
        login(client)
    reviewed(client, project_id)
    login(client)
    source = workspace(client, project_id, SOURCE)["state"]
    target = workspace(client, project_id, TARGET)["state"]
    response = client.post(
        url(project_id, "/synchronization/preview"), json={"source": source, "target": target}
    )
    assert response.status_code == 200, response.text
    result = response.json()
    row = next(item for item in result["items"] if item["source"].get("assessment"))
    payload = {
        "request_id": str(uuid4()),
        "source": source,
        "target": target,
        "preview_digest": result["preview_digest"],
        "source_context_id": row["source_context_id"],
        "target_context_id": row["target_context_id"],
        "vulnerability_id": row["vulnerability_id"],
        "source_assessment_revision": row["source"]["assessment_revision"],
        "conditions": "Same customer deployment and protective configuration.",
        "reason": "Explicitly reuse the source analysis for this parallel release.",
    }
    return project_id, payload, row


def apply(client, project_id, payload):
    return client.post(url(project_id, "/synchronization/drafts"), json=payload)


def test_author_applies_exact_source_content_as_target_draft_only_and_replay_is_durable(
    analyst, app, bom
):
    project_id, payload, row = prepared(analyst, bom)
    assert row["draft_allowed"]
    journal = app.state.knowledge
    source_before = copy.deepcopy(load_sections(journal, payload["source"]))
    target_before = copy.deepcopy(load_sections(journal, payload["target"]))
    response = apply(analyst, project_id, payload)
    assert response.status_code == 201, response.text
    updates = response.json()["updates"]
    assert len(updates) == 1 and updates[0]["ref"]["name"] == TARGET
    source_after = workspace(analyst, project_id, SOURCE)
    target_after = workspace(analyst, project_id, TARGET)
    assert source_after["state"] == payload["source"]
    assert load_sections(journal, source_after["state"]) == source_before
    changed = load_sections(journal, target_after["state"])
    for section in target_before:
        if section != "assessments":
            assert changed[section] == target_before[section]
    selected = next(
        item
        for item in target_after["items"]
        if item["context_id"] == payload["target_context_id"]
        and item["vulnerability_id"] == payload["vulnerability_id"]
    )
    assert selected["coverage"]["status"] == "draft"
    assert not selected["coverage"]["approved"] and not selected["coverage"]["submitted"]
    record = selected["coverage"]["assessment"]
    assert record["payload"]["previous"] == payload["source_assessment_revision"]
    assert record["payload"]["conditions"] == payload["conditions"]
    assert record["payload"]["evidence"][-1]["source"] == payload["source"]
    assert record["payload"]["evidence"][-1]["target"] == payload["target"]
    assert record["payload"]["evidence"][-1]["requires_new_target_review"] is True
    assert record["payload"]["evidence"][-1]["software_integration_verified"] is False
    replay = apply(analyst, project_id, payload)
    assert replay.status_code == 201 and replay.json() == response.json()
    assert workspace(analyst, project_id, TARGET)["state"] == target_after["state"]
    altered = apply(
        analyst, project_id, payload | {"reason": "Changed action under the same request"}
    )
    assert altered.status_code == 409, altered.text


def test_non_author_with_assess_capability_cannot_copy_another_authors_content(analyst, app, bom):
    project_id, payload, _ = prepared(analyst, bom)
    login(analyst, "reviewer")
    assert "assess" in workspace(analyst, project_id, TARGET)["items"][0]["capabilities"]
    preview = analyst.post(
        url(project_id, "/synchronization/preview"),
        json={"source": payload["source"], "target": payload["target"]},
    )
    assert preview.status_code == 200
    assert not any(row["draft_allowed"] for row in preview.json()["items"])
    before = app.state.knowledge.head()
    response = apply(analyst, project_id, payload)
    assert response.status_code == 403, response.text
    assert app.state.knowledge.head() == before


def test_source_author_still_requires_target_team_assessment_permission(analyst, app, bom):
    project_id, payload, row = prepared(analyst, bom, other_team=True)
    assert not row["draft_allowed"]
    before = app.state.knowledge.head()
    response = apply(analyst, project_id, payload)
    assert response.status_code == 403, response.text
    assert app.state.knowledge.head() == before


@pytest.mark.parametrize("version", [SOURCE, TARGET])
def test_new_source_or_target_head_refuses_stale_preview_without_mutation(
    analyst, app, bom, version
):
    project_id, payload, _ = prepared(analyst, bom)
    login(analyst, "administrator")
    imported(
        analyst,
        project_id,
        version,
        body(
            bom,
            request_id="later-" + version,
            expected=payload["source" if version == SOURCE else "target"],
            build_number=2,
        ),
    )
    login(analyst)
    before = app.state.knowledge.head()
    response = apply(analyst, project_id, payload)
    assert response.status_code == 409, response.text
    assert app.state.knowledge.head() == before


@pytest.mark.parametrize("field", ["preview_digest", "source_assessment_revision"])
def test_wrong_preview_or_assessment_pin_is_conflict_and_never_drafts(analyst, app, bom, field):
    project_id, payload, _ = prepared(analyst, bom)
    before = app.state.knowledge.head()
    response = apply(analyst, project_id, payload | {field: "f" * 64})
    assert response.status_code == 409, response.text
    assert app.state.knowledge.head() == before
