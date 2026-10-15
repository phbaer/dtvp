from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_authored_metadata_requires_management_and_binds_reviewer_context(analyst, bom):
    project_id, _ = setup(analyst, bom)
    before = workspace(analyst, project_id)
    row = before["items"][0]
    payload = {
        "request_id": "curated-context",
        "expected": before["state"],
        "expected_revision": None,
        "component_ref": row["context"]["component_ref"],
        "annotations": {
            "cybersecurity": {"criticality": "high", "exposure": "internal"},
            "deployment": {"usage": "Report generation"},
        },
        "provenance": {"source": "Component owner", "reference": "DESIGN-42"},
        "rationale": "Recorded deployment context.",
    }
    path = url(project_id, "/versions/7.1.1/metadata")
    assert analyst.put(path, json=payload).status_code == 404
    login(analyst, "administrator")
    response = analyst.put(path, json=payload)
    assert response.status_code == 201, response.text
    assert analyst.put(path, json=payload).json() == response.json()
    after = workspace(analyst, project_id)
    updated = next(item for item in after["items"] if item["id"] == row["id"])
    assert updated["curated_metadata"]["status"] == "current"
    assert (
        updated["curated_metadata"]["payload"]["annotations"]["deployment"]["usage"]
        == "Report generation"
    )
    assert updated["coverage"]["status"] == "unassessed"
    historical = analyst.get(url(project_id, f"/states/{before['state']}/metadata"))
    assert historical.status_code == 200, historical.text
    assert historical.json()["items"] == []
    listed = analyst.get(url(project_id, f"/states/{after['state']}/metadata"))
    assert listed.json()["total"] == 1
