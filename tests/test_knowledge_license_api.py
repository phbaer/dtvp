from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_license_worklist_is_pinned_bounded_and_does_not_clear(analyst, bom):
    bom["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    project_id, _ = setup(analyst, bom)
    state = workspace(analyst, project_id)["state"]
    path = url(project_id, f"/states/{state}/license-worklist")
    response = analyst.get(path, params={"limit": 1})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["format"] == "dtvp.license-worklist/1"
    assert result["total"] > len(result["items"]) == 1
    assert result["statistics"]["by_evidence_status"]["reported"] == 1
    assert all(row["clearance"] == "not_assessed" for row in result["items"])
    assert workspace(analyst, project_id)["state"] == state
    assert analyst.get(path, params={"limit": 201}).status_code == 422
