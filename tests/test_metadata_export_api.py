"""Issued metadata for a nonfinding component stays scoped and byte exact."""

from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_nonfinding_support_is_issued_with_server_status_and_current_project_authorization(
    analyst, bom
):
    project, _ = setup(analyst, bom)
    before = workspace(analyst, project)
    ref = bom["metadata"]["component"]["bom-ref"]
    assert all(row["component"]["bom-ref"] != ref for row in before["items"])
    login(analyst, "administrator")
    response = analyst.put(
        url(project, "/versions/7.1.1/metadata"),
        json={
            "request_id": "nonfinding-support",
            "expected": before["state"],
            "expected_revision": None,
            "component_ref": ref,
            "annotations": {
                "support": {"status": "internally_maintained", "end_of_life": "2031-01-01"}
            },
            "provenance": {"source": "Component owner", "reference": "SUPPORT-42"},
            "rationale": "Explicit product support record",
        },
    )
    assert response.status_code == 201, response.text
    state = workspace(analyst, project)["state"]
    issue = analyst.post(url(project, f"/states/{state}/exports/bundle"))
    assert issue.status_code == 201, issue.text
    issued = issue.json()
    assert issued["serializer_id"] == "dtvp.knowledge-bundle-serializer/2"
    file = analyst.get(issued["files"]["bundle.json"]["url"])
    assert digest(file.content) == issued["source_receipt"]["bundle_sha256"]
    register = file.json()["component_metadata"]
    assert register["by_status"] == {"current": 1}
    record = register["items"][0]
    assert record["payload"]["component_ref"] == ref and record["applicable"] is True
    assert record["payload"]["provenance"]["reference"] == "SUPPORT-42"
    assert analyst.post(url(project, f"/states/{state}/exports/bundle")).json() == issued
    assert analyst.get(issued["files"]["bundle.json"]["url"]).content == file.content
    login(analyst, "operations")
    assert analyst.get(issued["files"]["bundle.json"]["url"]).status_code == 404
