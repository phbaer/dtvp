"""Editable file scenarios exercise real domain workflows without resetting work."""

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from dtvp.api_playground_knowledge import authorize_fixture
from dtvp.config import Settings
from dtvp.knowledge.assessments import AssessmentInput, Target, save_assessment
from dtvp.knowledge.demo_scenarios import DemoScenario
from dtvp.knowledge.journal import Ref
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.main import create_app
from dtvp.models import Project, User, Workspace
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app
PATH = "/api/v1/playground/knowledge/load"
SCENARIOS = Path(__file__).parent.parent / "playground/scenarios"


def scenario(name="workflow"):
    return json.loads((SCENARIOS / (name + ".json")).read_bytes())


def load(client, value=None):
    response = client.post(PATH, json=value or scenario())
    assert response.status_code == 200, response.text
    return response.json()


def workspace(app, demo, version=None):
    journal = app.state.knowledge
    state = journal.resolve(Ref(project_id=demo["project_id"], name=version or demo["version"]))
    return load_workspace(journal, state, paginate=False)


def test_file_demo_has_contextual_states_and_historical_tag(analyst, app):
    demo = load(analyst)
    assert demo["project_name"] == scenario()["project_name"]
    assert demo["synthetic"] and not demo["preserved_existing"]
    current = workspace(app, demo)
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
        item["coverage"]["status"] for item in workspace(app, demo, "7.1.1")["items"]
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
    assert journal.state(historical).version == "7.1.2"
    assert demo["scenario_sha256"] and "synthetic" in demo["actors"]


def test_repeat_preserves_interactive_native_assessment_and_heads(analyst, app):
    demo = load(analyst)
    current = workspace(app, demo)
    row = next(item for item in current["items"] if item["coverage"]["status"] == "unassessed")
    with app.state.sessions.begin() as db:
        user = db.scalar(
            select(User).where(User.issuer == "playground", User.subject == "operations")
        )
        project = db.get(Project, demo["project_id"])
        save_assessment(
            app.state.knowledge,
            project_id=project.id,
            actor_id=user.id,
            assessment_id="interactive-draft",
            data=AssessmentInput(
                request_id="interactive-draft",
                expected_versions={demo["version"]: current["state"]},
                expected_revision=None,
                targets=[
                    Target(
                        version=demo["version"],
                        context_id=row["context_id"],
                        vulnerability_id=row["vulnerability_id"],
                    )
                ],
                state="under_investigation",
                rationale="Interactive work must survive reloading this exact scenario.",
            ),
            submit=False,
            authorize=authorize_fixture(db, project, user),
        )
    before = app.state.knowledge.references()
    again = load(analyst)
    assert again["project_id"] == demo["project_id"] and again["preserved_existing"]
    assert app.state.knowledge.references() == before
    assert any(
        item["coverage"]
        .get("assessment", {})
        .get("payload", {})
        .get("rationale", "")
        .startswith("Interactive work")
        for item in workspace(app, demo)["items"]
    )


def test_file_load_preserves_unrelated_native_project(analyst, app):
    value = scenario()
    with app.state.sessions.begin() as db:
        team = db.scalar(select(Workspace).where(Workspace.name == "Platform"))
        project = Project(workspace_id=team.id, name="Independent interactive project")
        db.add(project)
        db.flush()
        project_id = project.id
    baseline = value["baselines"][0]
    import_inventory(
        app.state.knowledge,
        project_id=project_id,
        version="unrelated",
        actor_id="pipeline",
        request_id="independent",
        expected=None,
        source="test",
        build_number=1,
        occurred_at=baseline["occurred_at"],
        sbom=baseline["sbom"],
    )
    before = {
        key: state
        for key, state in app.state.knowledge.references().items()
        if Ref.model_validate_json(key).project_id == project_id
    }
    load(analyst)
    after = {
        key: state
        for key, state in app.state.knowledge.references().items()
        if Ref.model_validate_json(key).project_id == project_id
    }
    assert before == after


def test_changed_scenario_same_identity_rejects_overwrite_and_new_identity_is_editable(
    analyst, app
):
    original = load(analyst)
    changed = scenario()
    changed["baselines"][0]["sbom"]["components"].append(
        {
            "bom-ref": "custom-library",
            "name": "Locally edited library",
            "type": "library",
            "version": "2",
        }
    )
    before = app.state.knowledge.references()
    response = analyst.post(PATH, json=changed)
    assert response.status_code == 409
    assert app.state.knowledge.references() == before
    changed.update(fixture_id="custom-workflow/1", project_name="My edited native scenario")
    custom = load(analyst, changed)
    assert custom["project_id"] != original["project_id"]
    state = app.state.knowledge.resolve(Ref(project_id=custom["project_id"], name="7.1.1"))
    assert (
        load_sections(app.state.knowledge, state)["inventory"]["component:ref:custom-library"][
            "name"
        ]
        == "Locally edited library"
    )


def test_scenario_requires_csrf_and_explicit_versioned_payload(client):
    assert client.post(PATH, json=scenario()).status_code == 401
    login(client, "viewer")
    assert client.post(PATH, json={"scenario": "workflow"}).status_code == 422
    client.headers.pop("X-CSRF-Token")
    assert client.post(PATH, json=scenario()).status_code == 403


def test_production_exposes_no_scenario_or_seed_endpoint(tmp_path):
    value = create_app(
        Settings(
            _env_file=None,
            playground=False,
            session_secret="production-test-secret-00000000000000",
            database_url="postgresql+psycopg://unused:unused@127.0.0.1/unused",
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )
    paths = set(value.openapi()["paths"])
    assert PATH not in paths and "/api/v1/playground/knowledge/seed" not in paths
    client = TestClient(value)
    try:
        assert client.post(PATH, json=scenario()).status_code == 404
    finally:
        client.close()


def test_specialist_file_contains_explicit_native_proposals_without_publishing_scores(analyst, app):
    regular = load(analyst)
    before = app.state.knowledge.references()
    demo = load(analyst, scenario("specialists"))
    assert demo["project_id"] != regular["project_id"]
    current = workspace(app, demo)
    row = next(
        item
        for item in current["items"]
        if item["context"]["root_ref"] == "platform-app"
        and item["component"]["name"] == "shared-tls"
    )
    assert row["scoring_proposals"][0]["eligible"]
    assert row["scoring_proposals"][0]["verification"] == "operator_bound_minimal_rest_exchange"
    assert row["published_score"] is None
    assert row["code_analysis"] and not row["code_analysis"][0]["application_eligible"]
    assert all(app.state.knowledge.references()[key] == state for key, state in before.items())
    from dtvp.knowledge.licenses import license_worklist

    licenses = license_worklist(app.state.knowledge, current["state"])
    tls = next(item for item in licenses["items"] if item["component_ref"] == "shared-tls")
    assert tls["license_review"]["status"] == "submitted" and not tls["license_review"]["approved"]


@pytest.mark.parametrize(
    "change", ["unknown_step", "real_flag", "duplicate_version", "pin_override"]
)
def test_scenario_schema_rejects_scripts_and_unsafe_overrides(change):
    value = copy.deepcopy(scenario())
    if change == "unknown_step":
        value["steps"] = [{"execute": "rm -rf"}]
    elif change == "real_flag":
        value["synthetic"] = False
    elif change == "duplicate_version":
        value["baselines"].append(copy.deepcopy(value["baselines"][0]))
    else:
        value["assessments"][0]["assessment"]["expected_versions"] = {}
    with pytest.raises(ValueError):
        DemoScenario.model_validate(value)


def test_demo_release_tag_retains_file_and_synthetic_review_provenance(analyst, app):
    demo = load(analyst)
    journal = app.state.knowledge
    tag = scenario()["tags"][0]
    state = journal.resolve(Ref(kind="tag", project_id=demo["project_id"], name=tag["name"]))
    marker = load_sections(journal, state)["history"]["synthetic-scenario"]
    assert marker["synthetic"] is True
    assert marker["human_approval_assurance"] == "simulated fixture decisions only"
    assert marker["scenario_sha256"] in journal.state(state).artifacts
    assert json.loads(journal.objects.read(marker["scenario_sha256"])) == DemoScenario.model_validate(scenario()).model_dump(mode="json")


def test_invalid_synthetic_persona_review_is_forbidden_without_publication(analyst, app):
    value = scenario()
    approved = next(item for item in value["assessments"] if item.get("review"))
    approved["review"]["persona"] = "analyst"
    before = app.state.knowledge.references()
    response = analyst.post(PATH, json=value)
    assert response.status_code == 403
    assert app.state.knowledge.references() == before
    with app.state.sessions() as db:
        assert db.scalar(select(Project).where(Project.name == value["project_name"])) is None
