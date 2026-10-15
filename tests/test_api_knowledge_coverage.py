"""HTTP candidate previews retain project/team boundaries and complete page pins."""

import copy

from dtvp.models import Grant
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app
VERSIONS = ("6.15.6", "7.1.1", "7.1.2", "7.2.0")


def selected(client, project_id, version="7.1.1", name="demo-http"):
    current = workspace(client, project_id, version)
    row = next(item for item in current["items"] if item["component"]["name"] == name)
    return {
        "source": current["state"],
        "context_id": row["context_id"],
        "vulnerability_id": row["vulnerability_id"],
    }


def preview(client, project_id, payload, **params):
    return client.post(url(project_id, "/coverage/candidates"), json=payload, params=params)


def test_complete_preview_digest_and_counts_across_pages_without_writes(analyst, app, bom):
    project_id, _ = setup(analyst, bom, VERSIONS)
    payload = selected(analyst, project_id)
    before = app.state.knowledge.head()
    first = preview(analyst, project_id, payload, limit=1)
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["total"] == result["statistics"]["rows"] == 4
    assert result["statistics"]["assessment_candidates"] == 4
    assert result["source"]["capabilities"] == ["assess"]
    assert result["next_offset"] == 1
    second = preview(
        analyst,
        project_id,
        {**payload, "expected_preview": result["preview_digest"]},
        offset=1,
        limit=2,
    )
    assert second.status_code == 200, second.text
    assert second.json()["preview_digest"] == result["preview_digest"]
    assert second.json()["statistics"] == result["statistics"]
    assert len(second.json()["items"]) == 2
    assert all(row["capabilities"] == ["assess"] for row in second.json()["items"])
    assert all(not row["coverage"]["approved"] for row in second.json()["items"])
    assert app.state.knowledge.head() == before
    login(analyst, "viewer")
    viewer = preview(analyst, project_id, payload).json()
    assert viewer["source"]["capabilities"] == []
    assert all(row["capabilities"] == [] and row["assessment_candidate"] for row in viewer["items"])
    assert viewer["preview_digest"] == result["preview_digest"]


def test_team_capabilities_require_project_permission_and_actual_owning_team(analyst, app, bom):
    project_id, teams = setup(analyst, bom)
    login(analyst, "administrator")
    apply_policy(
        analyst,
        project_id,
        [
            {"selector": "*", "team_id": teams["Platform"]},
            {"selector": "demo-parser", "team_id": teams["Operations"]},
        ],
        request_id="coverage-split-teams",
    )
    login(analyst, "reviewer")
    payload = selected(analyst, project_id, name="demo-parser")
    result = preview(analyst, project_id, payload)
    assert result.status_code == 200, result.text
    assert result.json()["source"]["capabilities"] == []
    assert result.json()["items"][0]["assessment_candidate"]
    assert result.json()["items"][0]["capabilities"] == []
    login(analyst, "operations-reviewer")
    assert preview(analyst, project_id, payload).status_code == 404
    # Owning-team reviewer has roles, but a read-only project grant cannot add approval.
    with app.state.sessions.begin() as db:
        db.add(
            Grant(project_id=project_id, workspace_id=teams["Operations"], capabilities=["read"])
        )
    result = preview(analyst, project_id, payload)
    assert result.status_code == 200, result.text
    assert result.json()["source"]["capabilities"] == []
    assert result.json()["items"][0]["capabilities"] == []
    with app.state.sessions.begin() as db:
        grant = db.get(Grant, (project_id, teams["Operations"]))
        grant.capabilities = ["read", "assess", "approve"]
    allowed = preview(analyst, project_id, payload).json()
    assert allowed["source"]["capabilities"] == ["assess", "approve"]
    assert allowed["items"][0]["capabilities"] == ["assess", "approve"]


def test_changed_heads_require_fresh_page_preview_but_pinned_source_survives(analyst, bom):
    project_id, _ = setup(analyst, bom, VERSIONS)
    payload = selected(analyst, project_id)
    initial = preview(analyst, project_id, payload).json()
    old = initial["heads"]["7.1.2"]
    changed = copy.deepcopy(bom)
    changed["components"][0]["version"] = "1.2.1"
    new = imported(
        analyst,
        project_id,
        "7.1.2",
        body(changed, request_id="coverage-new-nightly", expected=old, build_number=2),
    )
    stale = preview(
        analyst, project_id, {**payload, "expected_preview": initial["preview_digest"]}, offset=1
    )
    assert stale.status_code == 409, stale.text
    refreshed = preview(analyst, project_id, payload).json()
    assert refreshed["source"]["state"] == payload["source"]
    assert refreshed["heads"]["7.1.2"] == new
    assert refreshed["preview_digest"] != initial["preview_digest"]
    assert any(row["classification"] == "material_changed" for row in refreshed["items"])


def test_absent_contexts_missing_states_and_request_validation_are_explicit(analyst, app, bom):
    project_id, _ = setup(analyst, bom, ("7.1.1", "7.1.2"))
    payload = selected(analyst, project_id)
    old = workspace(analyst, project_id, "7.1.2")["state"]
    changed = copy.deepcopy(bom)
    changed["components"] = [item for item in changed["components"] if item["bom-ref"] != "http"]
    changed["dependencies"] = [edge for edge in changed["dependencies"] if edge["ref"] != "http"]
    for edge in changed["dependencies"]:
        edge["dependsOn"] = [ref for ref in edge["dependsOn"] if ref != "http"]
    changed["vulnerabilities"] = changed["vulnerabilities"][1:]
    imported(
        analyst,
        project_id,
        "7.1.2",
        body(changed, request_id="coverage-removed", expected=old, build_number=2),
    )
    result = preview(analyst, project_id, payload)
    assert result.status_code == 200, result.text
    absent = next(row for row in result.json()["items"] if row["version"] == "7.1.2")
    assert absent["context"] is None and absent["capabilities"] == []
    assert absent["availability"] == "component_absent" and not absent["assessment_candidate"]
    login(analyst, "administrator")
    foreign_project = next(
        item["id"] for item in analyst.get("/api/v2/projects").json() if item["id"] != project_id
    )
    foreign_state = imported(analyst, foreign_project, "7.1.1", body(bom))
    login(analyst)
    before = app.state.knowledge.head()
    assert preview(analyst, project_id, {**payload, "source": foreign_state}).status_code == 404
    assert preview(analyst, project_id, {**payload, "source": "a" * 64}).status_code == 404
    assert preview(analyst, project_id, {**payload, "context_id": "b" * 64}).status_code == 422
    assert preview(analyst, project_id, {**payload, "expected_preview": "bad"}).status_code == 422
    assert preview(analyst, project_id, payload, limit=201).status_code == 422
    assert preview(analyst, project_id, payload, offset=-1).status_code == 422
    assert preview(analyst, "not-this-project", payload).status_code == 404
    assert app.state.knowledge.head() == before
