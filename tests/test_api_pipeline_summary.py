"""Pipeline reads reauthorize every call and admit only committed product states."""

from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, workspace

app = knowledge_app


def endpoint(project, state):
    return f"/api/v1/projects/{project}/states/{state}/evidence-summary"


def test_pinned_summary_matches_full_workspace_and_remains_historical(analyst, app, bom):
    project, _ = setup(analyst, bom)
    current = workspace(analyst, project)
    before = app.state.knowledge.head(), app.state.knowledge.references()
    response = analyst.get(endpoint(project, current["state"]))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["vulnerabilities"]["totals"] == current["statistics"]["totals"]
    assert result["state"] == current["state"] and result["version"] == "7.1.1"
    assert not result["documents"]["current_approved"]
    assert not result["licenses"]["current_approved_components"]
    assert result["inventory"]["coverage_verification"] == "not_verified"
    assert (app.state.knowledge.head(), app.state.knowledge.references()) == before
    login(analyst, "administrator")
    imported(
        analyst,
        project,
        "7.1.1",
        body(
            bom,
            request_id="after-summary",
            expected=current["state"],
            build_number=2,
        ),
    )
    assert analyst.get(endpoint(project, current["state"])).json() == result
    login(analyst, "viewer")
    assert analyst.get(endpoint(project, current["state"])).json() == result
    login(analyst, "operations")
    assert analyst.get(endpoint(project, current["state"])).status_code == 404


def test_foreign_uncommitted_and_nonstate_inputs_are_not_summary_destinations(analyst, app, bom):
    project, _ = setup(analyst, bom)
    current = workspace(analyst, project)
    journal = app.state.knowledge
    standalone = journal.snapshot(
        project_id=project,
        version="unpublished",
        actor_id="producer",
        reason="unpublished",
        sections=load_sections(journal, current["state"]),
    )
    artifact = journal.store({"not": "state"})
    before = journal.head()
    for state in (standalone, artifact, "f" * 64):
        assert analyst.get(endpoint(project, state)).status_code == 404
    assert analyst.get(endpoint("different-product", current["state"])).status_code == 404
    assert journal.head() == before
