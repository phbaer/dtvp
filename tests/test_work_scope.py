"""Membership work views count the full selection without changing access."""

import sys

import httpx
import pytest
import respx
from sqlalchemy import select

from dtvp.auth import issue
from dtvp.cli import main
from dtvp.models import Grant, Membership, User
from tests.conftest import login
from tests.test_knowledge_ownership import apply_policy
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as scope_workspace  # noqa: F401
from tests.test_workflow_api import setup, workspace


def test_union_and_empty_scope_are_applied_before_counts_and_pagination(scope_workspace):  # noqa: F811
    from dtvp.knowledge.workspace import load_workspace

    journal, state = snapshot(scope_workspace)
    union = load_workspace(journal, state, work_scope="my_teams", team_ids={"A", "B"}, limit=1)
    assert union["statistics"]["context_findings"] == 3
    assert len(union["items"]) == 1
    assert union["next_offset"] == 1
    narrow = load_workspace(journal, state, work_scope="my_teams", team_ids={"A", "B"}, team_id="B")
    assert narrow["statistics"]["context_findings"] == 1
    empty = load_workspace(journal, state, work_scope="my_teams", team_ids=set())
    assert empty["items"] == []
    assert empty["statistics"]["context_findings"] == 0


def test_memberships_grants_and_current_credentials(analyst, app, bom):
    project_id, teams = setup(analyst, bom)
    login(analyst, "administrator")
    apply_policy(
        analyst,
        project_id,
        [
            {"selector": "demo-http", "team_id": teams["Platform"]},
            {"selector": "demo-parser", "team_id": teams["Operations"]},
        ],
        request_id="work-scope-policy",
    )
    login(analyst)
    user_id = analyst.get("/api/v1/me").json()["id"]
    assert (
        workspace(analyst, project_id, work_scope="my_teams")["statistics"]["context_findings"] == 1
    )
    # Sharing grants make a product accessible, never make another team a membership.
    with app.state.sessions.begin() as db:
        db.merge(
            Grant(
                project_id=project_id,
                workspace_id=teams["Operations"],
                capabilities=["read", "assess", "approve"],
            )
        )
    assert (
        workspace(analyst, project_id, work_scope="my_teams")["statistics"]["context_findings"] == 1
    )
    with app.state.sessions.begin() as db:
        db.add(Membership(user_id=user_id, workspace_id=teams["Operations"], roles=["reviewer"]))
    union = workspace(analyst, project_id, work_scope="my_teams", limit=1)
    assert union["statistics"]["context_findings"] == 2
    assert union["next_offset"] == 1
    assert (
        workspace(analyst, project_id, work_scope="my_teams", offset=1, limit=1)["items"][0]["id"]
        != union["items"][0]["id"]
    )
    assert (
        workspace(analyst, project_id, work_scope="my_teams", team_id=teams["Operations"])[
            "statistics"
        ]["context_findings"]
        == 1
    )
    for suffix in ("/portfolio",):
        response = analyst.get(
            f"/api/v1/projects/{project_id}{suffix}", params={"work_scope": "my_teams"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["statistics"]["context_findings"] == 2
    organization = analyst.get(
        "/api/v1/portfolio", params={"work_scope": "my_teams", "project": project_id}
    )
    assert organization.status_code == 200, organization.text
    assert organization.json()["statistics"]["context_findings"] == 2
    with app.state.sessions.begin() as db:
        user = db.get(User, user_id)
        token, _, _ = issue(
            db,
            user,
            kind="api",
            workspace_id=teams["Platform"],
            projects=[project_id],
            allowed=["read", "assess"],
        )
    analyst.headers["Authorization"] = "Bearer " + token
    assert (
        workspace(analyst, project_id, work_scope="my_teams")["statistics"]["context_findings"] == 1
    )
    assert (
        workspace(analyst, project_id, work_scope="my_teams", team_id=teams["Operations"])["items"]
        == []
    )
    analyst.headers.pop("Authorization")
    with app.state.sessions.begin() as db:
        for member in db.scalars(select(Membership).where(Membership.user_id == user_id)):
            member.roles = ["viewer"]
    assert workspace(analyst, project_id, work_scope="my_teams")["items"] == []
    assert workspace(analyst, project_id, work_scope="all")["statistics"]["context_findings"] == 2
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/versions/7.1.1/workspace",
            params={"work_scope": "invalid"},
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "command,suffix", [("workspace", "/versions/1/workspace"), ("portfolio", "/portfolio")]
)
@respx.mock
def test_cli_forwards_scope(monkeypatch, capsys, command, suffix):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    argv = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        command,
        "--project",
        "project",
        "--work-scope",
        "my_teams",
        "--json",
    ]
    if command == "workspace":
        argv.extend(["--version", "1"])
    monkeypatch.setattr(sys, "argv", argv)
    route = respx.get("http://dtvp.test/api/v1/projects/project" + suffix).mock(
        return_value=httpx.Response(200, json={})
    )
    main()
    assert route.calls[0].request.url.params["work_scope"] == "my_teams"


def test_unresolved_ownership_has_explicit_manager_views(scope_workspace):  # noqa: F811
    from dtvp.knowledge.workspace import load_workspace

    journal, sections = scope_workspace
    contexts = [
        value
        for key, value in sections["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "shared"
    ]
    contexts[0].update(team_id=None, candidate_teams=[], team_scope={}, status="unassigned")
    contexts[1].update(
        team_id=None,
        candidate_teams=["A", "B"],
        team_scope={"A": True, "B": True},
        status="conflict",
    )
    _, state = snapshot(scope_workspace)
    unassigned = load_workspace(journal, state, work_scope="unassigned")
    disputed = load_workspace(journal, state, work_scope="conflicts")
    assert unassigned["statistics"]["context_findings"] == 1
    assert disputed["statistics"]["context_findings"] == 1
    assert unassigned["items"][0]["id"] != disputed["items"][0]["id"]
