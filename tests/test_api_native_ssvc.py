"""Native SSVC uses existing authenticated, scoped assessment/review endpoints."""

from tests.conftest import login
from tests.test_knowledge_api import app as source_app
from tests.test_knowledge_ssvc import selection
from tests.test_workflow_api import assessment, setup, url, workspace

app = source_app


def test_native_ssvc_models_require_auth_and_publish_through_review(client, bom):
    assert client.get("/api/v1/ssvc/models").status_code == 401
    project, _ = setup(client, bom)
    response = client.get("/api/v1/ssvc/models")
    assert response.status_code == 200
    assert response.json()["models"][0]["sha256"] == selection().model_sha256
    response, assessment_id, payload = assessment(client, project, ssvc=selection().model_dump())
    assert response.status_code == 201, response.text
    current = workspace(client, project)
    row = current["items"][0]
    assert row["ssvc"]["status"] == "submitted"
    revision = row["coverage"]["assessment"]["revision"]
    body = {
        "request_id": "review-ssvc",
        "expected_versions": {"7.1.1": current["state"]},
        "assessment_id": assessment_id,
        "assessment_revision": revision,
        "targets": payload["targets"],
        "action": "approve",
        "rationale": "Checked explicit SSVC answers and evidence.",
    }
    own = client.post(url(project, "/reviews"), json=body)
    assert own.status_code in {403, 404}
    login(client, "reviewer")
    response = client.post(url(project, "/reviews"), json=body)
    assert response.status_code == 201, response.text
    approved = workspace(client, project)["items"][0]
    assert approved["ssvc"]["approved"]["outcome_label"] == "Defer"
    assert workspace(client, project, ssvc_action="IMMEDIATE")["items"] == []
    assert workspace(client, project, ssvc_action="DEFER")["items"]
    for params, expected in (
        ({"ssvc_action": "IMMEDIATE"}, 0),
        ({"ssvc_action": "DEFER", "ssvc_status": "approved"}, 1),
    ):
        response = client.get(url(project, "/portfolio"), params=params)
        assert response.status_code == 200, response.text
        assert response.json()["statistics"]["context_findings"] == expected
    assert client.get(url(project, "/portfolio"), params={"ssvc_action": "unknown"}).status_code == 422


def test_native_ssvc_rejects_client_outcome_and_stale_model_pin(client, bom):
    project, _ = setup(client, bom)
    before = workspace(client, project)["state"]
    response, _, _ = assessment(
        client, project, ssvc={**selection().model_dump(), "outcome": "Immediate"}
    )
    assert response.status_code == 422
    response, _, _ = assessment(
        client, project, ssvc={**selection().model_dump(), "model_sha256": "0" * 64}
    )
    assert response.status_code == 422, response.text
    assert workspace(client, project)["state"] == before
