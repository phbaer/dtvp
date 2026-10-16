"""Component-context presentation never grants metadata or graph authority."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def selection(client, project):
    value = workspace(client, project)
    row = value["items"][0]
    return (
        value["state"],
        row,
        {"component_ref": row["context"]["component_ref"], "context_id": row["context_id"]},
    )


def test_scoped_capability_and_declared_graph_do_not_mutate_source_or_human_state(
    analyst, app, bom
):
    project, _ = setup(analyst, bom)
    state, row, params = selection(analyst, project)
    path = url(project, f"/states/{state}/component-context")
    before = app.state.knowledge.head()
    result = analyst.get(path, params=params)
    assert result.status_code == 200, result.text
    value = result.json()
    assert value["capabilities"] == []
    assert value["component"]["bom-ref"] == params["component_ref"]
    assert value["defaults"]["cybersecurity"]["criticality"] == "unknown"
    assert value["topology"]["consuming_root"] == row["context"]["root_ref"]
    assert value["topology"]["incoming_total"] >= len(value["topology"]["incoming"])
    assert app.state.knowledge.head() == before
    login(analyst, "administrator")
    assert analyst.get(path, params=params).json()["capabilities"] == ["curate"]
    assert analyst.get(path, params={**params, "context_id": "f" * 64}).status_code == 404
    assert analyst.get(path, params={"component_ref": "absent"}).status_code == 404
    login(analyst, "operations")
    assert analyst.get(path, params=params).status_code == 404


def test_exact_head_and_revision_roundtrip_replay_and_historical_read_only(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state, _, params = selection(analyst, project)
    login(analyst, "administrator")
    selected = analyst.get(url(project, f"/states/{state}/component-context"), params=params).json()
    annotations = selected["defaults"]
    annotations["cybersecurity"].update(criticality="critical", exposure="external")
    annotations["support"]["references"] = ["SUPPORT-42"]
    annotations["properties"] = {"producer-note": "Keep authored extension fields"}
    payload = {
        "request_id": "context-edit",
        "expected": state,
        "expected_revision": None,
        "component_ref": params["component_ref"],
        "annotations": annotations,
        "provenance": {"source": "Component owner", "reference": "DESIGN-42"},
        "rationale": "Recorded deployment evidence",
    }
    endpoint = url(project, "/versions/7.1.1/metadata")
    result = analyst.put(endpoint, json=payload)
    assert result.status_code == 201, result.text
    assert analyst.put(endpoint, json=payload).json() == result.json()
    old = analyst.get(url(project, f"/states/{state}/component-context"), params=params).json()
    assert old["metadata"] is None and old["capabilities"] == []
    assert "selected_state_is_not_current_head" in old["blocked_reasons"]
    current = workspace(analyst, project)
    details = analyst.get(
        url(project, f"/states/{current['state']}/component-context"), params=params
    ).json()
    assert details["metadata"]["payload"]["annotations"] == annotations
    assert details["metadata"]["status"] == "current"
    assert analyst.put(endpoint, json={**payload, "request_id": "stale-edit"}).status_code == 409


def test_neighbor_lists_are_bounded_and_missing_graph_is_explicitly_unknown(analyst, bom):
    from copy import deepcopy

    from tests.test_knowledge_api import body, imported

    project, _ = setup(analyst, bom)
    _, _, params = selection(analyst, project)
    expanded = deepcopy(bom)
    for index in range(75):
        ref = f"consumer-{index:03}"
        expanded["components"].append({"bom-ref": ref, "type": "library", "name": ref})
        expanded["dependencies"].append({"ref": ref, "dependsOn": [params["component_ref"]]})
    state = imported(analyst, project, "large", body(expanded, request_id="large-neighborhood"))
    response = analyst.get(
        url(project, f"/states/{state}/component-context"),
        params={"component_ref": params["component_ref"]},
    )
    assert response.status_code == 200, response.text
    topology = response.json()["topology"]
    assert topology["incoming_total"] >= 75 and len(topology["incoming"]) == 50
    assert topology["neighbor_limit"] == 50
    unknown = deepcopy(bom)
    unknown.pop("dependencies")
    state = imported(analyst, project, "unknown", body(unknown, request_id="unknown-topology"))
    value = analyst.get(
        url(project, f"/states/{state}/component-context"),
        params={"component_ref": params["component_ref"]},
    ).json()
    assert value["topology"]["dependency_graph"] == "not_reported"
    assert value["topology"]["incoming_total"] == value["topology"]["outgoing_total"] == 0
    assert "unknown or absent edges" in value["topology"]["limitations"][0]
