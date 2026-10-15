"""Product-only pinned history and full-set semantic comparison over HTTP."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_historical_product_refs_and_semantic_comparison(analyst, bom):
    project_id, _ = setup(analyst, bom)
    first = workspace(analyst, project_id)["state"]
    second = imported(
        analyst, project_id, "7.1.2", body(bom, request_id="parallel", predecessor=first)
    )
    login(analyst, "administrator")
    tagged = analyst.post(
        url(project_id, "/tags"),
        json={
            "request_id": "released",
            "name": "release-7.1.1",
            "state": first,
        },
    )
    assert tagged.status_code == 201, tagged.text
    refs = analyst.get(url(project_id, "/refs"), params={"limit": 1}).json()
    assert refs["total"] == 3
    assert len(refs["items"]) == 1
    assert refs["next_offset"] == 1
    history = analyst.get(url(project_id, "/history"), params={"version": "7.1.1"}).json()
    assert history["items"]
    assert all(row["version"] == "7.1.1" for row in history["items"])
    path = url(project_id, "/compare/details")
    result = analyst.get(path, params={"before": first, "after": second, "limit": 1})
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["before_version"] == "7.1.1"
    assert result["after_version"] == "7.1.2"
    assert result["limitations"]
    assert result["total"] >= len(result["items"])
    assert workspace(analyst, project_id)["state"] == first
    assert workspace(analyst, project_id, version="7.1.2")["state"] == second
    assert analyst.get(path, params={"before": "a" * 64, "after": second}).status_code == 422
    assert (
        analyst.get(path, params={"before": first, "after": second, "limit": 201}).status_code
        == 422
    )
