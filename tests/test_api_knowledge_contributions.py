"""Contribution synthesis is scoped detail-only; native lists stay lean."""

from urllib.parse import quote

from dtvp.api_contract import API_PREFIX
from tests.test_knowledge_api import app as source_app
from tests.test_workflow_api import setup, workspace

app = source_app


def test_detail_exposes_scoped_contributions_without_mutating_lists_or_history(client, bom):
    project, _ = setup(client, bom)
    current = workspace(client, project)
    row = current["items"][0]
    assert "contributions" not in row
    route = f"{API_PREFIX}/projects/{project}/versions/7.1.1/workspace/{row['context_id']}/{quote(row['vulnerability_id'], safe='')}"
    response = client.get(route, params={"expected": current["state"]})
    assert response.status_code == 200, response.text
    detail = response.json()
    report = detail["contributions"]
    assert report["scope"] == {
        "state": current["state"],
        "version": "7.1.1",
        "context_id": row["context_id"],
        "component_ref": row["context"]["component_ref"],
        "vulnerability_id": row["vulnerability_id"],
    }
    assert report["vulnerability_sources"]
    assert all(
        item["adoption"]["status"] == "not_recorded" and not item["adoption"]["published_score"]
        for item in report["vulnerability_sources"]
    )
    assert report["cpe"]["accepted"] == []
    assert "contributions" not in workspace(client, project)["items"][0]
    assert workspace(client, project)["state"] == current["state"]
    assert client.get(route, params={"expected": "0" * 64}).status_code == 409
    assert client.get(route.replace(row["vulnerability_id"], "CVE-2099-99999")).status_code == 404
