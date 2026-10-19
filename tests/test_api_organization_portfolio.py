"""Cross-project workload counts do not broaden project or credential visibility."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import setup, workspace

app = knowledge_app


def test_global_full_counts_precede_project_paging_and_filters(analyst, app, bom):
    first, teams = setup(analyst, bom, versions=("7.1.1", "7.1.2"))
    login(analyst, "administrator")
    created = analyst.post(
        "/api/v1/projects",
        json={"workspace_id": teams["Platform"], "name": "Second portfolio product"},
    )
    assert created.status_code == 201, created.text
    second = created.json()["id"]
    imported(analyst, second, "7.1.1", body(bom, request_id="second-portfolio"))
    apply_policy(analyst, second, [{"selector": "*", "team_id": teams["Platform"]}])
    login(analyst)
    before = app.state.knowledge.head()
    params = [("project", first), ("project", second), ("limit", 1)]
    response = analyst.get("/api/v1/portfolio", params=params)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["project_count"] == result["total"] == 2
    assert result["version_count"] == 3
    assert result["statistics"]["context_findings"] == 6
    assert result["statistics"]["unique_vulnerabilities"] == 2
    assert len(result["items"]) == 1 and result["next_offset"] == 1
    assert set(result["heads"]) == {first, second}
    more = analyst.get(
        "/api/v1/portfolio",
        params=[*params, ("offset", 1), ("expected_heads", result["heads_digest"])],
    ).json()
    assert more["statistics"] == result["statistics"]
    assert {item["project_id"] for item in result["items"] + more["items"]} == {first, second}
    filtered = analyst.get("/api/v1/portfolio", params=[*params, ("q", "nothing-matches")]).json()
    assert filtered["statistics"]["context_findings"] == 0
    assert all(item["state_evidence"] for item in filtered["items"])
    assert app.state.knowledge.head() == before
    assert (
        analyst.get("/api/v1/portfolio", params=[*params, ("expected_heads", "0" * 64)]).status_code
        == 409
    )


def test_authorization_applies_to_each_explicit_project_and_default_selection(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    login(analyst, "operations")
    hidden = analyst.get("/api/v1/portfolio", params={"project": project})
    assert hidden.status_code == 404 and state not in hidden.text
    default = analyst.get("/api/v1/portfolio")
    assert default.status_code == 200, default.text
    assert project not in default.json()["heads"] and state not in default.text
    login(analyst, "analyst")
    assert (
        analyst.get(
            "/api/v1/portfolio", params=[("project", project), ("project", project)]
        ).status_code
        == 422
    )
    assert analyst.get("/api/v1/portfolio", params={"project": "unknown"}).status_code == 404
    assert analyst.get("/api/v1/portfolio", params={"source_severity": "urgent"}).status_code == 422
    assert analyst.get("/api/v1/portfolio", params={"lifecycle": "bogus"}).status_code == 422


def test_readonly_machine_credential_does_not_expand_to_other_projects(analyst, bom):
    project, teams = setup(analyst, bom)
    login(analyst, "administrator")
    response = analyst.post(
        "/api/v1/credentials",
        json={
            "workspace_id": teams["Platform"],
            "name": "Scoped portfolio consumer",
            "projects": [project],
            "capabilities": ["read"],
            "hours": 1,
        },
    )
    assert response.status_code == 201, response.text
    credential = response.json()
    analyst.headers["Authorization"] = "Bearer " + credential["token"]
    result = analyst.get("/api/v1/portfolio")
    assert result.status_code == 200, result.text
    assert set(result.json()["heads"]) == {project}
    assert result.json()["project_count"] == 1
    assert set(item["project_id"] for item in result.json()["items"]) == {project}
    analyst.headers.pop("Authorization")
    assert analyst.delete("/api/v1/credentials/" + credential["id"]).status_code == 204
    analyst.headers["Authorization"] = "Bearer " + credential["token"]
    assert analyst.get("/api/v1/portfolio").status_code == 401
