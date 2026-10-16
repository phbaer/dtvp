"""Searchable pinned occurrences stay distinct, bounded and permission scoped."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def catalog(client, project, state, **params):
    return client.get(url(project, f"/states/{state}/reconciliation-candidates"), params=params)


def test_components_and_contexts_are_distinct_bounded_searchable_and_readonly(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    before = app.state.knowledge.head()
    first = catalog(analyst, project, state, kind="component", limit=1)
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 4 and first.json()["next_offset"] == 1
    assert len(first.json()["items"]) == 1
    result = catalog(analyst, project, state, kind="component", q="PKG:NPM/DEMO-HTTP")
    assert result.json()["total"] == 1
    row = result.json()["items"][0]
    assert row["id"] == row["component_ref"] == "http" and row["root_ref"] is None
    contexts = catalog(analyst, project, state, kind="context", q="demo-http").json()
    assert contexts["total"] == 1
    context = contexts["items"][0]
    assert context["id"] != row["id"] and context["component_ref"] == row["id"]
    assert context["root_ref"] == "gateway" and context["root"]["name"] == "Demo Gateway"
    assert context["ownership_status"] == "resolved" and context["team_id"]
    assert app.state.knowledge.head() == before
    login(analyst, "viewer")
    assert catalog(analyst, project, state, kind="component").status_code == 200
    login(analyst, "operations")
    assert catalog(analyst, project, state, kind="component").status_code == 404


def test_historical_ownership_is_pinned_and_uncommitted_states_rejected(analyst, app, bom):
    project, teams = setup(analyst, bom)
    original = workspace(analyst, project)["state"]
    before = catalog(analyst, project, original, kind="context").json()
    login(analyst, "administrator")
    apply_policy(
        analyst,
        project,
        [{"selector": "*", "team_id": teams["Operations"]}],
        request_id="catalog-reassign",
    )
    current = workspace(analyst, project)["state"]
    assert catalog(analyst, project, original, kind="context").json() == before
    assert all(
        row["team_id"] == teams["Operations"]
        for row in catalog(analyst, project, current, kind="context").json()["items"]
    )
    journal = app.state.knowledge
    from dtvp.knowledge.workspace import load_sections

    unpublished = journal.snapshot(
        project_id=project,
        version="7.1.1",
        actor_id="fixture",
        reason="Not committed",
        sections=load_sections(journal, current),
    )
    assert catalog(analyst, project, unpublished, kind="component").status_code == 404
    assert catalog(analyst, project, "f" * 64, kind="component").status_code == 404


def test_query_validation_and_empty_search_do_not_invent_occurrences(analyst, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    empty = catalog(analyst, project, state, kind="context", q="not-present").json()
    assert empty["items"] == [] and empty["total"] == 0 and empty["next_offset"] is None
    for params in (
        {"kind": "bad"},
        {"kind": "component", "limit": 201},
        {"kind": "component", "offset": -1},
        {"kind": "component", "q": "x" * 201},
    ):
        assert catalog(analyst, project, state, **params).status_code == 422
