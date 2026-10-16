"""Comparison observes explicit retained inputs under current product authorization."""

from dtvp.knowledge.evidence import evidence_ref
from tests.conftest import login
from tests.test_knowledge_advisory_documents import feed
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def prepared(client, app, bom):
    project, _ = setup(client, bom)
    initial = workspace(client, project)["state"]
    login(client, "administrator")
    response = client.post(
        url(project, "/evidence/imports"),
        json={
            "request_id": "feed-comparison",
            "expected_evidence": None,
            "expected_versions": {"7.1.1": initial},
            "source": "provider",
            "revision": 1,
            "document": feed(),
        },
    )
    assert response.status_code == 201, response.text
    evidence = app.state.knowledge.resolve(evidence_ref(project))
    return project, {"inventory_state": initial, "evidence_state": evidence}


def test_authorized_pinned_comparison_pages_digest_and_no_mutation(analyst, app, bom):
    project, data = prepared(analyst, app, bom)
    before = app.state.knowledge.head()
    login(analyst, "viewer")
    endpoint = url(project, "/compare/intelligence")
    first = analyst.post(endpoint, json=data, params={"limit": 1})
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["total"] == result["statistics"]["claim_groups"] == 1
    assert result["items"][0]["status"] == "added"
    second = analyst.post(
        endpoint,
        json={**data, "expected_digest": result["report_digest"]},
        params={"offset": 1, "limit": 1},
    )
    assert second.status_code == 200 and second.json()["items"] == []
    assert second.json()["report_digest"] == result["report_digest"]
    assert app.state.knowledge.head() == before
    assert analyst.post(endpoint, json={**data, "expected_digest": "0" * 64}).status_code == 409
    login(analyst, "operations")
    assert analyst.post(endpoint, json=data).status_code == 404


def test_unknown_uncommitted_and_cross_scope_hashes_do_not_grant_access(analyst, app, bom):
    project, data = prepared(analyst, app, bom)
    endpoint = url(project, "/compare/intelligence")
    blob = app.state.knowledge.store({"private": "raw data"})
    for payload in (
        {**data, "inventory_state": blob},
        {**data, "evidence_state": blob},
        {**data, "inventory_state": data["evidence_state"]},
        {**data, "evidence_state": data["inventory_state"]},
    ):
        response = analyst.post(endpoint, json=payload)
        assert response.status_code == 404, response.text
    assert (
        analyst.post(endpoint, json={"inventory_state": data["inventory_state"]}).status_code == 422
    )
    assert analyst.post(endpoint, json=data, params={"limit": 201}).status_code == 422
    empty = analyst.post(endpoint, json={**data, "evidence_state": None})
    assert empty.status_code == 200 and empty.json()["items"] == []
