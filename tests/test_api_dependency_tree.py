"""Tree reads retain exact state and current project authorization."""

from copy import deepcopy

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_pinned_tree_pagination_subtrees_and_revoked_access(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    path = url(project, f"/states/{state}/dependency-tree")
    before = app.state.knowledge.head()
    response = analyst.get(path)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["state"] == state and result["items"]
    assert sum(row["vulnerability_count"] for row in result["items"]) >= 2
    assert analyst.get(path, params={"limit": 1}).json()["next_offset"] == 1
    assert (
        analyst.get(path, params={"offset": 1, "limit": 1}).json()["items"] == result["items"][1:2]
    )
    ref = result["items"][-1]["component_ref"]
    subtree = analyst.get(path, params={"root_ref": ref, "max_depth": 0}).json()
    assert subtree["items"][0]["component_ref"] == ref
    assert subtree["items"][0]["depth"] == 0
    assert analyst.get(path, params={"root_ref": "absent"}).status_code == 404
    assert analyst.get(path, params={"max_depth": 21}).status_code == 422
    assert app.state.knowledge.head() == before
    login(analyst, "administrator")
    changed = deepcopy(bom)
    changed["components"].append({"bom-ref": "new", "name": "New dependency", "type": "library"})
    new = imported(
        analyst, project, "7.1.1", body(changed, request_id="next", expected=state, build_number=2)
    )
    assert analyst.get(path).json() == result
    assert any(
        row["component_ref"] == "new"
        for row in analyst.get(url(project, f"/states/{new}/dependency-tree")).json()["items"]
    )
    login(analyst, "operations")
    assert analyst.get(path).status_code == 404


def test_tree_does_not_accept_another_products_state(analyst, bom):
    project, teams = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    login(analyst, "administrator")
    other = analyst.post(
        "/api/v1/projects", json={"workspace_id": teams["Platform"], "name": "Other product"}
    ).json()["id"]
    assert analyst.get(url(other, f"/states/{state}/dependency-tree")).status_code == 404
    assert analyst.get(url(other, f"/states/{state}/dependency-children")).status_code == 404
    assert (
        analyst.get(
            url(other, f"/states/{state}/dependency-paths"), params={"component_ref": "root"}
        ).status_code
        == 404
    )


def test_dependency_paths_are_pinned_read_only_and_authorized(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    tree = analyst.get(url(project, f"/states/{state}/dependency-tree")).json()
    ref = tree["items"][-1]["component_ref"]
    endpoint = url(project, f"/states/{state}/dependency-paths")
    before = app.state.knowledge.head()
    response = analyst.get(endpoint, params={"component_ref": ref, "root_ref": ref})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["state"] == state and result["component_ref"] == ref
    assert result["paths"][0][0]["component_ref"] == ref
    assert analyst.get(endpoint, params={"component_ref": "absent"}).status_code == 404
    assert analyst.get(endpoint, params={"component_ref": ref, "limit": 51}).status_code == 422
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert analyst.get(endpoint, params={"component_ref": ref}).status_code == 404


def test_branch_children_are_scoped_pinned_and_authorized(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = workspace(analyst, project)["state"]
    endpoint = url(project, f"/states/{state}/dependency-children")
    before = app.state.knowledge.head()
    response = analyst.get(endpoint)
    assert response.status_code == 200, response.text
    roots = response.json()
    root = next(row for row in roots["items"] if row["child_count"])
    params = [("parent_ref", root["component_ref"]), ("path", root["component_ref"]), ("limit", 1)]
    response = analyst.get(endpoint, params=params)
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["ancestor_path"] == root["path"]
    assert all(row["depth"] == 1 and row["path"][:-1] == root["path"] for row in page["items"])
    if page["next_offset"] is not None:
        next_page = analyst.get(endpoint, params=[*params, ("offset", page["next_offset"])]).json()
        assert next_page["items"][0]["component_ref"] != page["items"][0]["component_ref"]
    assert analyst.get(endpoint, params={"parent_ref": "absent"}).status_code == 404
    assert analyst.get(endpoint, params={"limit": 201}).status_code == 422
    assert (
        analyst.get(
            endpoint, params=[("parent_ref", root["component_ref"]), ("path", "absent")]
        ).status_code
        == 422
    )
    assert analyst.get(endpoint, params=[("path", "root")] * 101).status_code == 422
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert analyst.get(endpoint).status_code == 404
