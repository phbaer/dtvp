"""Native coordinator rules and manager policy permissions over the public API."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import reviewed, score_input, setup, url

app = knowledge_app


def test_policy_permissions_cas_preview_publish_and_receipt_replay(analyst, bom):
    project, _ = setup(analyst, bom)
    path = url(project, "/scoring-policy")
    policy = analyst.get(path).json()
    import copy

    configured = copy.deepcopy(policy["config"])
    custom = copy.deepcopy(configured["transitions"][0])
    custom["trigger"]["state"] = "EXPLOITABLE"
    configured["transitions"].append(custom)
    config = {"request_id": "configure-policy", "expected_policy": None, "config": configured}
    assert analyst.put(path, json=config).status_code == 404
    row, _ = reviewed(analyst, project)
    login(analyst, "administrator")
    saved = analyst.put(path, json=config)
    assert saved.status_code == 200, saved.text
    pinned = analyst.get(path).json()
    assert pinned["state"] and pinned["digest"] != policy["digest"]
    stale = analyst.put(path, json={**config, "request_id": "stale-config"})
    assert stale.status_code == 409
    data = {
        **score_input(analyst, project, row),
        "expected_policy": pinned["state"],
        "rule_basis": "applicability",
    }
    preview_path = url(project, "/scoring/rules/preview")
    assert analyst.post(preview_path, json=data).status_code == 404
    login(analyst, "coordinator")
    result = analyst.post(preview_path, json=data)
    assert result.status_code == 200, result.text
    preview = result.json()
    assert preview["eligible"] and preview["provenance"]["rule_state"] == "affected"
    publication = {**data, "preview": preview["preview"]}
    publish_path = url(project, "/scoring/rules/publish")
    result = analyst.post(publish_path, json=publication)
    assert result.status_code == 201, result.text
    login(analyst, "administrator")
    assert (
        analyst.put(
            path, json={**config, "expected_policy": pinned["state"], "request_id": "policy-next"}
        ).status_code
        == 200
    )
    login(analyst, "coordinator")
    replay = analyst.post(publish_path, json=publication)
    assert replay.status_code == 201
    assert all(
        replay.json()[key] == result.json()[key] for key in ("publication", "sequence", "updates")
    )
    login(analyst, "analyst")
    assert analyst.post(publish_path, json=publication).status_code == 404
    assert analyst.get(path).status_code == 200
