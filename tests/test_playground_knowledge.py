"""Interactive workflow fixture is explicit, synthetic and never resets user work."""

from conftest import login
from fastapi.testclient import TestClient

from dtvp.api_playground_knowledge import PROJECT_NAME, VERSIONS, document
from dtvp.config import Settings
from dtvp.knowledge.journal import Ref
from dtvp.main import create_app
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app

PATH = "/api/v3/playground/knowledge/seed"


def seed(client):
    result = client.post(PATH, json={})
    assert result.status_code == 200, result.text
    return result.json()


def workspace(client, demo, version=None):
    result = client.get(
        f"/api/v3/projects/{demo['project_id']}/versions/{version or demo['version']}/workspace"
    )
    assert result.status_code == 200, result.text
    return result.json()


def test_demo_has_real_contextual_workflow_states_and_historical_tag(analyst, app):
    before = analyst.get("/api/v2/projects").json()
    demo = seed(analyst)
    assert demo["project_name"] == PROJECT_NAME
    assert demo["synthetic"] and not demo["preserved_existing"]
    current = workspace(analyst, demo)
    assert len(current["items"]) == 4
    assert {item["coverage"]["status"] for item in current["items"]} == {
        "approved",
        "submitted",
        "reassessment_needed",
        "unassessed",
    }
    assert {item["context"]["root_ref"] for item in current["items"]} == {
        "platform-app",
        "operations-app",
    }
    assert len({item["context"]["team_id"] for item in current["items"]}) == 2
    assert "draft" in {
        item["coverage"]["status"] for item in workspace(analyst, demo, VERSIONS[0])["items"]
    }
    approved = next(item for item in current["items"] if item["coverage"]["status"] == "approved")
    assert (
        approved["coverage"]["review"]["reviewer_id"]
        != approved["coverage"]["assessment"]["payload"]["author_id"]
    )
    journal = app.state.knowledge
    historical = journal.resolve(
        Ref(kind="tag", project_id=demo["project_id"], name="workflow-demo-reviewed-baseline")
    )
    assert historical and historical != current["state"]
    assert journal.state(historical).version == VERSIONS[1]
    assert len(analyst.get("/api/v2/projects").json()) == len(before) + 1


def test_repeat_preserves_interactive_assessment_and_existing_heads(analyst, app):
    demo = seed(analyst)
    login(analyst, "operations")
    current = workspace(analyst, demo)
    row = next(item for item in current["items"] if item["coverage"]["status"] == "unassessed")
    changed = analyst.post(
        f"/api/v3/projects/{demo['project_id']}/assessments/interactive-draft/draft",
        json={
            "request_id": "interactive-draft",
            "expected_versions": {demo["version"]: current["state"]},
            "expected_revision": None,
            "targets": [
                {
                    "version": demo["version"],
                    "context_id": row["context_id"],
                    "vulnerability_id": row["vulnerability_id"],
                }
            ],
            "state": "under_investigation",
            "rationale": "Interactive work must survive loading the demo again.",
        },
    )
    assert changed.status_code == 201, changed.text
    refs = app.state.knowledge.references()
    projects = analyst.get("/api/v2/projects").json()
    again = seed(analyst)
    assert again["project_id"] == demo["project_id"] and again["preserved_existing"]
    assert app.state.knowledge.references() == refs
    assert analyst.get("/api/v2/projects").json() == projects
    item = next(item for item in workspace(analyst, demo)["items"] if item["id"] == row["id"])
    assert item["coverage"]["assessment"]["payload"]["rationale"].startswith("Interactive work")


def test_seed_keeps_unrelated_project_inventory_and_policy(client, app):
    login(client, "administrator")
    project = next(
        item for item in client.get("/api/v2/projects").json() if item["name"] == "Demo Gateway"
    )
    team = next(
        item for item in client.get("/api/v2/me").json()["workspaces"] if item["name"] == "Platform"
    )
    base = f"/api/v3/projects/{project['id']}"
    imported = client.post(
        f"{base}/versions/unrelated/imports",
        json={
            "request_id": "unrelated-import",
            "expected": None,
            "source": "test",
            "build_number": 1,
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "completeness": "complete",
            "sbom": document("unrelated"),
        },
    )
    assert imported.status_code == 201, imported.text
    initial = client.get(f"{base}/ownership").json()
    policy = client.put(
        f"{base}/ownership",
        json={
            "request_id": "unrelated-policy",
            "expected_policy": initial["policy_state"],
            "expected_versions": initial["versions"],
            "rules": [{"selector": "*", "team_id": team["id"]}],
        },
    )
    assert policy.status_code == 201, policy.text
    before = {
        key: value
        for key, value in app.state.knowledge.references().items()
        if Ref.model_validate_json(key).project_id == project["id"]
    }
    seed(client)
    after = {
        key: value
        for key, value in app.state.knowledge.references().items()
        if Ref.model_validate_json(key).project_id == project["id"]
    }
    assert after == before


def test_seed_requires_session_csrf_and_rejects_arbitrary_data(client):
    assert client.post(PATH, json={}).status_code == 401
    login(client, "viewer")
    assert client.post(PATH, json={"reset": True}).status_code == 422
    client.headers.pop("X-CSRF-Token")
    assert client.post(PATH, json={}).status_code == 403


def test_production_has_no_demo_seed_route(tmp_path):
    app = create_app(
        Settings(
            _env_file=None,
            playground=False,
            session_secret="production-test-secret-00000000000000",
            database_url="postgresql+psycopg://unused:unused@127.0.0.1/unused",
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )
    # Route registration needs no production database or lifespan execution.
    client = TestClient(app)
    try:
        assert client.post(PATH, json={}).status_code == 404
    finally:
        client.close()


def test_specialist_scenario_has_native_inputs_proposals_and_license_example(analyst, app):
    from dtvp.api_playground_knowledge import SPECIALIST_PROJECT_NAME
    from dtvp.knowledge.agentyzer import derive_analysis_input
    from dtvp.knowledge.licenses import license_worklist
    from dtvp.knowledge.vscorer import derive_context_inputs

    ordinary = seed(analyst)
    original_refs = app.state.knowledge.references()
    response = analyst.post(PATH, json={"scenario": "specialists"})
    assert response.status_code == 200, response.text
    demo = response.json()
    assert demo["project_name"] == SPECIALIST_PROJECT_NAME
    assert demo["project_id"] != ordinary["project_id"]
    current = workspace(analyst, demo)
    row = next(
        item
        for item in current["items"]
        if item["context"]["root_ref"] == "platform-app"
        and item["component"]["name"] == "shared-tls"
    )
    analysis = derive_analysis_input(
        app.state.knowledge, current["state"], row["context_id"], row["vulnerability_id"]
    )
    assert analysis["ready_to_submit"]
    assert analysis["receipt"]["analysis_source"]["repository_name"] == "synthetic-workflow"
    assert analysis["receipt"]["build_binding_verified"] is False
    scoring = derive_context_inputs(
        app.state.knowledge,
        current["state"],
        row["context_id"],
        "shared-tls",
        {row["vulnerability_id"]: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )
    assert scoring["eligible"]
    assert row["coverage"]["status"] == "approved"
    proposal = row["scoring_proposals"][0]
    assert proposal["current"] and proposal["eligible"]
    assert proposal["provider_authenticity"] == "caller_asserted_not_verified"
    assert row["published_score"] is None
    evidence = row["code_analysis"][0]
    assert evidence["current"] and not evidence["application_eligible"]
    assert not evidence["rescoring_eligible"]
    assert evidence["build_binding_verified"] is False
    assert "Synthetic" in evidence["source_label"]
    licenses = license_worklist(app.state.knowledge, current["state"])
    tls = next(item for item in licenses["items"] if item["component_ref"] == "shared-tls")
    assert tls["evidence"]["status"] == "reported"
    assert tls["license_review"]["status"] == "submitted"
    assert not tls["license_review"]["approved"]
    for key, value in original_refs.items():
        assert app.state.knowledge.references()[key] == value
    login(analyst, "operations")
    unassessed = next(
        item for item in current["items"] if item["coverage"]["status"] == "unassessed"
    )
    saved = analyst.post(
        f"/api/v3/projects/{demo['project_id']}/assessments/specialist-interactive/draft",
        json={
            "request_id": "specialist-interactive",
            "expected_versions": {demo["version"]: current["state"]},
            "expected_revision": None,
            "targets": [
                {
                    "version": demo["version"],
                    "context_id": unassessed["context_id"],
                    "vulnerability_id": unassessed["vulnerability_id"],
                }
            ],
            "state": "under_investigation",
            "rationale": "Preserve this interactive specialist workspace edit.",
        },
    )
    assert saved.status_code == 201, saved.text
    refs = app.state.knowledge.references()
    again = analyst.post(PATH, json={"scenario": "specialists"})
    assert again.status_code == 200 and again.json()["preserved_existing"]
    assert app.state.knowledge.references() == refs
