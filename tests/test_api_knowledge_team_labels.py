"""Mutable display labels enrich authorized HTTP views, never immutable source exports."""

from sqlalchemy import select

from dtvp.knowledge.exports import export_bytes
from dtvp.knowledge.workspace import load_workspace
from dtvp.models import Membership, User, Workspace
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def prepared(client, app, bom):
    project_id, teams = setup(client, bom)
    login(client, "administrator")
    apply_policy(
        client,
        project_id,
        [
            {"selector": "*", "team_id": teams["Platform"]},
            {"selector": "demo-parser", "team_id": teams["Operations"]},
        ],
        request_id="split-team-labels",
    )
    with app.state.sessions() as db:
        hidden = Workspace(name="Unrelated secret team")
        db.add(hidden)
        db.commit()
        hidden_id = hidden.id
    login(client, "reviewer")
    return project_id, teams, hidden_id


def test_labels_cover_complete_paginated_authorized_selection_not_just_actor_memberships(
    analyst, app, bom
):
    project_id, teams, hidden = prepared(analyst, app, bom)
    me = analyst.get("/api/v1/me").json()
    assert teams["Operations"] not in {item["id"] for item in me["workspaces"]}
    response = workspace(analyst, project_id, limit=1)
    assert len(response["items"]) == 1 and response["statistics"]["context_findings"] == 2
    assert response["team_labels"] == {
        teams["Platform"]: "Platform",
        teams["Operations"]: "Operations",
    }
    assert hidden not in response["team_labels"]
    assert set(response["team_labels"]) == set(response["statistics"]["by_team"])
    assert all(isinstance(name, str) for name in response["team_labels"].values())
    for row in response["items"]:
        if row["context"]["team_id"] == teams["Operations"]:
            assert row["capabilities"] == []  # A display name never grants the team's role.


def test_filter_and_detail_labels_do_not_enumerate_unrelated_teams(analyst, app, bom):
    project_id, teams, hidden = prepared(analyst, app, bom)
    filtered = workspace(analyst, project_id, team_id=teams["Operations"])
    assert filtered["team_labels"] == {teams["Operations"]: "Operations"}
    row = filtered["items"][0]
    assert row["capabilities"] == []
    detail = analyst.get(
        url(project_id, f"/versions/7.1.1/workspace/{row['context_id']}/{row['vulnerability_id']}")
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["team_labels"] == {teams["Operations"]: "Operations"}
    assert hidden not in detail.text
    empty = workspace(analyst, project_id, q="no-matching-finding")
    assert empty["team_labels"] == {}


def test_current_label_rename_does_not_change_pure_workspace_or_immutable_bundle(analyst, app, bom):
    project_id, teams, _ = prepared(analyst, app, bom)
    response = workspace(analyst, project_id)
    state = response["state"]
    journal = app.state.knowledge
    before = export_bytes(journal, state)
    pure = load_workspace(journal, state)
    assert "team_labels" not in pure
    with app.state.sessions() as db:
        db.get(Workspace, teams["Operations"]).name = "Operations renamed"
        db.commit()
    after = workspace(analyst, project_id)
    assert (
        after["state"] == state
        and after["team_labels"][teams["Operations"]] == "Operations renamed"
    )
    assert export_bytes(journal, state) == before
    assert load_workspace(journal, state) == pure


def test_project_read_denial_precedes_team_label_resolution(analyst, app, bom):
    project_id, teams, hidden = prepared(analyst, app, bom)
    row = workspace(analyst, project_id)["items"][0]
    login(analyst, "operations")
    for suffix in ("", f"/{row['context_id']}/{row['vulnerability_id']}"):
        response = analyst.get(url(project_id, "/versions/7.1.1/workspace" + suffix))
        assert response.status_code == 404, response.text
        assert "team_labels" not in response.text and hidden not in response.text
    login(analyst, "reviewer")
    with app.state.sessions() as db:
        user = db.scalar(select(User).where(User.subject == "reviewer"))
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == user.id, Membership.workspace_id == teams["Platform"]
            )
        )
        db.delete(membership)
        db.commit()
    assert analyst.get(url(project_id, "/versions/7.1.1/workspace")).status_code == 404
