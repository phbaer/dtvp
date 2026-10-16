"""No-finding components remain discoverable without changing review authority."""

from copy import deepcopy

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url

app = knowledge_app


def test_no_finding_components_search_full_counts_contexts_and_permission(analyst, app, bom):
    source = deepcopy(bom)
    source["vulnerabilities"] = []
    source["components"].append(
        {"bom-ref": "no-finding", "type": "library", "name": "Quiet dependency", "version": "1"}
    )
    source["dependencies"][0].setdefault("dependsOn", []).append("no-finding")
    project, teams = setup(analyst, source)
    state = analyst.get(url(project, "/versions/7.1.1/workspace")).json()["state"]
    assert not analyst.get(url(project, "/versions/7.1.1/workspace")).json()["items"]
    path = url(project, f"/states/{state}/components")
    before = app.state.knowledge.head()
    all_rows = analyst.get(path, params={"limit": 1}).json()
    assert len(all_rows["items"]) == 1 and all_rows["statistics"]["component_occurrences"] > 1
    value = analyst.get(path, params={"q": "QUIET", "team_id": teams["Platform"]}).json()
    assert value["statistics"]["component_occurrences"] == 1
    assert value["items"][0]["component_ref"] == "no-finding"
    assert value["items"][0]["ownership_statuses"] == ["resolved"]
    contexts = analyst.get(path + "/contexts", params={"component_ref": "no-finding"}).json()
    assert contexts["total"] >= 1
    detail = analyst.get(
        url(project, f"/states/{state}/component-context"),
        params={"component_ref": "no-finding", "context_id": contexts["items"][0]["id"]},
    )
    assert detail.status_code == 200 and not detail.json()["capabilities"]
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert analyst.get(path).status_code == 404


def test_historical_exact_pin_and_unknown_graph_are_not_clearance(analyst, app, bom):
    source = deepcopy(bom)
    source.pop("dependencies", None)
    project, _ = setup(analyst, source)
    old = analyst.get(url(project, "/versions/7.1.1/workspace")).json()["state"]
    login(analyst, "administrator")
    changed = deepcopy(source)
    changed["components"].append({"bom-ref": "new", "type": "library", "name": "New package"})
    new = imported(
        analyst, project, "7.1.1", body(changed, request_id="next", expected=old, build_number=2)
    )
    old_path = url(project, f"/states/{old}/components")
    previous = analyst.get(old_path).json()
    current = analyst.get(url(project, f"/states/{new}/components")).json()
    assert previous["head"] == new and previous["state"] == old
    assert (
        current["statistics"]["component_occurrences"]
        == previous["statistics"]["component_occurrences"] + 1
    )
    assert any("topology_unknown" in value["ownership_statuses"] for value in previous["items"])
    ref = previous["items"][0]["component_ref"]
    detail = analyst.get(
        url(project, f"/states/{old}/component-context"), params={"component_ref": ref}
    ).json()
    assert (
        not detail["capabilities"]
        and "selected_state_is_not_current_head" in detail["blocked_reasons"]
    )
    assert analyst.get(url(project, "/states/" + "f" * 64 + "/components")).status_code == 404
    assert (
        analyst.get(old_path + "/contexts", params={"component_ref": "absent"}).status_code == 404
    )


def test_foreign_and_nonstate_objects_are_not_inventory_destinations(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = analyst.get(url(project, "/versions/7.1.1/workspace")).json()["state"]
    login(analyst, "administrator")
    team = analyst.get("/api/v2/projects").json()[0]["workspace_id"]
    other = analyst.post(
        "/api/v2/projects", json={"workspace_id": team, "name": "Other inventory"}
    ).json()["id"]
    assert analyst.get(url(other, f"/states/{state}/components")).status_code == 404
    artifact = app.state.knowledge.store({"not": "a committed state"})
    assert analyst.get(url(project, f"/states/{artifact}/components")).status_code == 404
