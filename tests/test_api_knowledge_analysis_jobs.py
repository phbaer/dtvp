import httpx
import pytest
import respx

from dtvp.models import Job
from tests.conftest import login
from tests.test_knowledge_agentyzer import qualified
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_workflow_api import url, workspace

app = knowledge_app


def prepared(client, app, bom):
    project_id = product(client)
    state = imported(client, project_id, "7.1.1", body(bom, context=qualified()))
    row = next(
        item
        for item in workspace(client, project_id)["items"]
        if item["vulnerability_id"] == "CVE-2099-20001"
    )
    app.state.settings.agentyzer_enabled = True
    app.state.settings.agentyzer_url = "http://agentyzer.test"
    login(client, "administrator")
    response = client.put(
        url(project_id, "/connectors/agentyzer"), json={"component_name": "gateway"}
    )
    assert response.status_code == 200, response.text
    login(client, "analyst")
    return project_id, {
        "request_id": "native-job-one",
        "expected": state,
        "context_id": row["context_id"],
        "vulnerability_id": row["vulnerability_id"],
    }


def endpoint(project_id, version="7.1.1"):
    return url(project_id, f"/versions/{version}/analysis-jobs")


def test_enqueue_idempotency_paging_scope_and_safe_job_dto(analyst, app, bom):
    project_id, payload = prepared(analyst, app, bom)
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 202, response.text
    first = response.json()
    assert first["status"] == "queued"
    assert first["capabilities"] == ["cancel"]
    assert analyst.post(endpoint(project_id), json=payload).json() == first
    assert (
        analyst.post(endpoint(project_id), json={**payload, "user_guidance": "Changed"}).status_code
        == 409
    )
    page = analyst.get(endpoint(project_id), params={"limit": 1}).json()
    assert page["items"] == [first]
    assert page["capabilities"] == ["submit"]
    assert analyst.get(
        endpoint(project_id),
        params={
            "context_id": payload["context_id"],
            "vulnerability_id": payload["vulnerability_id"],
        },
    ).json()["items"] == [first]
    assert analyst.get(endpoint(project_id), params={"context_id": "0" * 64}).json()["items"] == []
    assert (
        analyst.get(endpoint(project_id), params={"vulnerability_id": "CVE-unrelated"}).json()[
            "items"
        ]
        == []
    )
    assert analyst.get(endpoint(project_id, "other")).json()["items"] == []
    item = url(project_id, f"/analysis-jobs/{first['id']}")
    assert analyst.get(item).json() == first
    assert "credential_id" not in response.text and "endpoint_digest" not in response.text
    assert analyst.post(f"/api/v2/jobs/{first['id']}/retry").status_code == 409
    login(analyst, "reviewer")
    assert analyst.get(item).json()["capabilities"] == []
    assert analyst.post(item + "/cancel").status_code == 403
    login(analyst, "analyst")
    assert analyst.post(item + "/cancel").json()["status"] == "cancelled"
    assert analyst.post(item + "/retry").status_code == 409


@respx.mock
def test_worker_native_roundtrip_publishes_evidence_and_updates_projection(analyst, app, bom):
    from sqlalchemy import select

    from dtvp.jobs import work_once
    from dtvp.knowledge.agentyzer import derive_analysis_input
    from dtvp.knowledge.projection import cursor

    project_id, payload = prepared(analyst, app, bom)
    derived = derive_analysis_input(
        app.state.knowledge, payload["expected"], payload["context_id"], payload["vulnerability_id"]
    )
    envelope = report(derived)
    submitted = respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(202, json={"job_id": "job-1"})
    )
    respx.get("http://agentyzer.test/jobs/job-1").mock(
        return_value=httpx.Response(200, json=envelope["job"])
    )
    respx.get("http://agentyzer.test/jobs/job-1/result").mock(
        return_value=httpx.Response(200, json=envelope["report"])
    )
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 202, response.text
    job_id = response.json()["id"]
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    result = analyst.get(url(project_id, f"/analysis-jobs/{job_id}")).json()
    assert result["status"] == "succeeded", result
    assert result["result"]["projection"] == "current"
    current = workspace(analyst, project_id)
    row = next(
        item
        for item in current["items"]
        if item["context_id"] == payload["context_id"]
        and item["vulnerability_id"] == payload["vulnerability_id"]
    )
    assert row["code_analysis"][0]["current"]
    assert row["coverage"]["status"] == "unassessed"
    assert row["published_score"] is None
    with app.state.engine.connect() as connection:
        assert (
            connection.execute(select(cursor.c.publication_sha)).scalar_one()
            == app.state.knowledge.head()
        )
    assert not work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    assert len(submitted.calls) == 1


@pytest.mark.parametrize("failure", ["viewer", "stale", "unbound", "foreign"])
def test_native_job_admission_rejects_unauthorized_or_unpinned_inputs(analyst, app, bom, failure):
    project_id, payload = prepared(analyst, app, bom)
    if failure == "viewer":
        login(analyst, "viewer")
        expected = 404
    elif failure == "stale":
        imported(
            analyst,
            project_id,
            "7.1.1",
            body(
                bom,
                context=qualified(),
                expected=payload["expected"],
                request_id="next-build",
                build_number=2,
            ),
        )
        expected = 409
    elif failure == "unbound":
        login(analyst, "administrator")
        analyst.put(
            url(project_id, "/connectors/agentyzer"), json={"component_name": "different-repo"}
        )
        login(analyst, "analyst")
        expected = 403
    else:
        payload["expected"] = "f" * 64
        expected = 404
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == expected, response.text
    with app.state.sessions() as db:
        assert not db.query(Job).filter(Job.kind == "analyse-native").all()
