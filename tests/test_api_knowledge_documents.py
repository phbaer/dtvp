import json

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app
RAW = b"# Synthetic architecture\nExact reviewable bytes.\n"


def prepared(client, app, bom):
    project_id, _ = setup(client, bom)
    state = workspace(client, project_id)["state"]
    issued = client.post(url(project_id, f"/states/{state}/exports/bundle"))
    assert issued.status_code == 201, issued.text
    login(client, "documentary-analyst")
    return project_id, {
        "request_id": "document-one",
        "expected": state,
        "expected_revision": None,
        "document_id": "architecture",
        "issued_receipt_sha": issued.json()["receipt_sha256"],
        "renderer": {"name": "Synthetic generator", "version": "fixture-1"},
        "configuration": {"format": "markdown"},
        "title": "Synthetic architecture",
        "purpose": "architecture",
        "rationale": "Review this exact generated artifact.",
        "filename": "architecture.md",
        "media_type": "text/markdown",
    }


def upload(client, project_id, metadata):
    return client.post(
        url(project_id, "/versions/7.1.1/documents/submit"),
        data={"metadata": json.dumps(metadata)},
        files={"file": ("architecture.md", RAW, "text/markdown")},
    )


def listing(client, project_id):
    state = workspace(client, project_id)["state"]
    response = client.get(url(project_id, f"/states/{state}/documents"))
    assert response.status_code == 200, response.text
    return response.json()


def test_document_upload_exact_download_independent_review_and_idempotency(analyst, app, bom):
    project_id, metadata = prepared(analyst, app, bom)
    response = upload(analyst, project_id, metadata)
    assert response.status_code == 201, response.text
    assert upload(analyst, project_id, metadata).json() == response.json()
    current = listing(analyst, project_id)
    row = current["items"][0]
    assert row["status"] == "submitted" and row["source_current"]
    assert row["capabilities"] == ["revise"]
    artifact = row["document"]["payload"]["artifact_sha256"]
    assert (
        analyst.get(url(project_id, f"/states/{current['state']}/artifacts/{artifact}")).content
        == RAW
    )
    review = {
        "request_id": "review-one",
        "expected": current["state"],
        "document_id": "architecture",
        "revision": row["document"]["revision"],
        "action": "approve",
        "rationale": "Reviewed exact artifact and archived inputs.",
    }
    path = url(project_id, "/versions/7.1.1/documents/reviews")
    assert analyst.post(path, json=review).status_code == 404
    login(analyst, "reviewer")
    assert analyst.post(path, json=review).status_code == 404
    login(analyst, "documentary-reviewer")
    assert listing(analyst, project_id)["items"][0]["capabilities"] == ["review"]
    approved = analyst.post(path, json=review)
    assert approved.status_code == 201, approved.text
    assert analyst.post(path, json=review).json() == approved.json()
    result = listing(analyst, project_id)["items"][0]
    assert result["status"] == "approved" and result["approved_source_current"]
    assert workspace(analyst, project_id)["statistics"]["approved"] == 0


def test_document_historical_review_needs_acknowledgement_and_retains_old_artifact(
    analyst, app, bom
):
    project_id, metadata = prepared(analyst, app, bom)
    assert upload(analyst, project_id, metadata).status_code == 201
    login(analyst, "analyst")
    old = listing(analyst, project_id)
    state = imported(
        analyst,
        project_id,
        "7.1.1",
        body(bom, request_id="new-build", expected=old["state"], build_number=2),
    )
    login(analyst, "documentary-reviewer")
    row = listing(analyst, project_id)["items"][0]
    assert not row["source_current"]
    review = {
        "request_id": "historical-review",
        "expected": state,
        "document_id": "architecture",
        "revision": row["document"]["revision"],
        "action": "approve",
        "rationale": "Review of historical pinned inputs only.",
    }
    path = url(project_id, "/versions/7.1.1/documents/reviews")
    assert analyst.post(path, json=review).status_code == 409
    response = analyst.post(path, json={**review, "acknowledge_historical": True})
    assert response.status_code == 201, response.text
    result = listing(analyst, project_id)
    assert result["items"][0]["status"] == "approved"
    assert not result["items"][0]["approved_source_current"]
    artifact = row["document"]["payload"]["artifact_sha256"]
    assert (
        analyst.get(url(project_id, f"/states/{result['state']}/artifacts/{artifact}")).content
        == RAW
    )
    login(analyst, "operations")
    assert analyst.get(url(project_id, f"/states/{result['state']}/documents")).status_code == 404
