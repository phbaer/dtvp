from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_rescoring import BASE, VECTOR
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app
CPE = "cpe:2.3:a:example:demo_http:*:*:*:*:*:*:*:*"


def test_internal_cpe_inputs_are_owned_pinned_and_not_applicability(analyst, bom):
    project_id, _ = setup(analyst, bom)
    row = workspace(analyst, project_id)["items"][0]
    state = workspace(analyst, project_id)["state"]
    data = {
        "request_id": "cpe-inputs",
        "expected": None,
        "catalog": [],
        "rules": {
            row["component"]["purl"]: {
                "cpe": CPE,
                "source": "reviewed-import",
                "reason": "Synthetic identity mapping",
            }
        },
    }
    path = url(project_id, "/cpe")
    assert analyst.put(path, json=data).status_code == 404
    login(analyst, "administrator")
    imported = analyst.put(path, json=data)
    assert imported.status_code == 201, imported.text
    policy = analyst.get(path).json()["policy_state"]
    result = analyst.get(
        url(project_id, f"/states/{state}/cpe"),
        params={"component_ref": row["context"]["component_ref"], "policy": policy},
    )
    assert result.status_code == 200, result.text
    assert result.json()["policy_state"] == policy
    assert result.json()["proposal"]["applicability"] == "not_assessed"
    assert result.json()["proposal"]["candidates"]
    assert workspace(analyst, project_id)["state"] == state
    tag = analyst.post(
        url(project_id, "/tags"),
        json={"name": "not-product", "state": policy, "request_id": "bad-tag"},
    )
    assert tag.status_code == 409


def test_vscorer_native_inputs_require_explicit_original_base_and_snapshot_access(analyst, bom):
    project_id, _ = setup(analyst, bom)
    current = workspace(analyst, project_id)
    row = current["items"][0]
    path = url(project_id, f"/states/{current['state']}/vscorer-input")
    data = {
        "context_id": row["context_id"],
        "component_ref": row["context"]["component_ref"],
        "base_selections": {row["vulnerability_id"]: BASE},
    }
    result = analyst.post(path, json=data)
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["eligible"] is True
    from dtvp.storage import digest

    assert (
        digest(result["files"]["sbom.cdx.json"].encode())
        == result["dtvp_source"]["artifacts"]["sbom_sha256"]
    )
    assert (
        digest(result["files"]["cves.json"].encode())
        == result["dtvp_source"]["artifacts"]["cves_sha256"]
    )
    assert result["dtvp_source"]["state"] == current["state"]
    assert result["dtvp_source"]["context_id"] == row["context_id"]
    assert result["cves"]["cves"][0]["component_refs"] == [row["context"]["component_ref"]]
    assert result["dtvp_source"]["selected_source_base"][row["vulnerability_id"]]["vector"] == BASE
    assert (
        analyst.post(
            path, json={**data, "base_selections": {row["vulnerability_id"]: VECTOR}}
        ).status_code
        == 422
    )
    assert workspace(analyst, project_id)["state"] == current["state"]
    login(analyst, "viewer")
    assert analyst.post(path, json=data).status_code == 404
