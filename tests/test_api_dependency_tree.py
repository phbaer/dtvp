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
