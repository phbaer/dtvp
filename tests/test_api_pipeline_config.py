"""Pipeline policy API retains current access checks for historical captures."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_pipeline_config import data
from tests.test_workflow_api import url

app = knowledge_app


def test_configuration_pins_retained_mapping_and_current_permissions(analyst, app, bom):
    project = product(analyst)
    state = imported(analyst, project, "1", body(bom))
    login(analyst, "administrator")
    path = url(project, "/pipeline-config")
    empty = analyst.get(path)
    assert empty.status_code == 200 and empty.json()["configuration_state"] is None
    value = data(expected_versions={"1": state}).model_dump(mode="json")
    first = analyst.put(path, json=value)
    assert first.status_code == 201, first.text
    policy = first.json()["updates"][0]["target"]
    assert analyst.get(path).json()["configuration_state"] == policy
    context = analyst.get(
        url(project, f"/states/{state}/pipeline-context"), params={"configuration": policy}
    )
    assert context.status_code == 200, context.text
    assert context.json()["configuration_state"] == policy
    second = analyst.put(
        path, json=value | {"request_id": "later", "expected_policy": policy, "mappings": []}
    )
    assert second.status_code == 201, second.text
    assert analyst.get(path, params={"configuration": policy}).json()["configuration"]["mappings"]
    assert analyst.put(path, json=value).json()["publication"] == first.json()["publication"]
    login(analyst, "viewer")
    assert analyst.get(path).status_code == 200
    assert analyst.put(path, json=value).status_code == 404
    assert analyst.get(url("missing", "/pipeline-config")).status_code == 404


def test_stale_heads_and_unknown_configuration_are_rejected(analyst, app, bom):
    project = product(analyst)
    imported(analyst, project, "1", body(bom))
    login(analyst, "administrator")
    path = url(project, "/pipeline-config")
    assert analyst.put(path, json=data().model_dump(mode="json")).status_code == 409
    assert analyst.get(path, params={"configuration": "0" * 64}).status_code == 422
