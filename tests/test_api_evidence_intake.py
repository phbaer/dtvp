"""Exact file previews are non-publishing, scoped and honest about semantic limits."""

import json

from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_evidence_api import path, payload, state, vex_for
from tests.test_workflow_api import setup

app = knowledge_app


def inputs(client, project, bom):
    document = vex_for(bom)
    data = payload(client, project, document)
    del data["document"]
    raw = json.dumps(document, indent=3).encode() + b"\n"
    return data, raw


def file_preview(client, project, data, raw):
    return client.post(
        path(project, "/files/preview"),
        files={"file": ("vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )


def test_raw_preview_matches_exact_source_bytes_and_never_publishes(analyst, app, bom):
    project, _ = setup(analyst, bom)
    data, raw = inputs(analyst, project, bom)
    before = app.state.knowledge.head()
    response = file_preview(analyst, project, data, raw)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["artifact_sha"] == digest(raw) and not result["committed"]
    assert result["source_revision"] == 1 and result["source"] == "supplier"
    assert result["expected_versions"] == data["expected_versions"]
    assert result["application"]["7.1.1"]["application"]["matched"] == 1
    assert result["trust"] == "unverified_publisher_and_signature"
    assert "supersession" in result["limitations"][0]
    assert state(analyst, project)["total"] == 0
    assert app.state.knowledge.head() == before
    assert file_preview(analyst, project, data, raw).json() == result
    imported = analyst.post(
        path(project, "/files"),
        files={"file": ("vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )
    assert imported.status_code == 201, imported.text
    assert analyst.get(path(project, f"/{digest(raw)}/source")).content == raw


def test_retained_previews_allow_readers_but_require_exact_document_membership(analyst, app, bom):
    project, _ = setup(analyst, bom)
    data, raw = inputs(analyst, project, bom)
    response = analyst.post(
        path(project, "/files"),
        files={"file": ("vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )
    assert response.status_code == 201
    current = state(analyst, project)
    assert current["total"] == 1 and current["capabilities"] == ["import", "withdraw"]
    pins = {
        "expected_evidence": current["evidence_state"],
        "expected_versions": current["versions"],
    }
    login(analyst, "viewer")
    assert state(analyst, project)["capabilities"] == []
    before = app.state.knowledge.head()
    response = analyst.post(path(project, f"/{digest(raw)}/preview"), json=pins)
    assert response.status_code == 200, response.text
    assert response.json()["active"]
    arbitrary = app.state.knowledge.objects.put(b"Unrelated retained secret")
    assert analyst.post(path(project, f"/{arbitrary}/preview"), json=pins).status_code == 404
    assert file_preview(analyst, project, data, raw).status_code in {403, 404}
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert analyst.post(path(project, f"/{digest(raw)}/preview"), json=pins).status_code == 404


def test_inactive_evidence_remains_readable_without_reactivation(analyst, app, bom):
    project, _ = setup(analyst, bom)
    data, raw = inputs(analyst, project, bom)
    assert (
        analyst.post(
            path(project, "/files"),
            files={"file": ("vex.json", raw, "application/json")},
            data={"metadata": json.dumps(data)},
        ).status_code
        == 201
    )
    current = state(analyst, project)
    withdrawn = analyst.post(
        path(project, "/withdrawals"),
        json={
            "request_id": "withdraw",
            "expected_evidence": current["evidence_state"],
            "expected_versions": current["versions"],
            "artifact_sha": digest(raw),
            "reason": "Supplier withdrew this statement.",
        },
    )
    assert withdrawn.status_code == 201
    current = state(analyst, project)
    before = app.state.knowledge.head()
    response = analyst.post(
        path(project, f"/{digest(raw)}/preview"),
        json={
            "expected_evidence": current["evidence_state"],
            "expected_versions": current["versions"],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["active"] is False
    assert response.json()["application"]["7.1.1"]["application"]["selection"] == "inactive"
    assert state(analyst, project)["documents"][0]["active"] is False
    assert app.state.knowledge.head() == before


def test_stale_pins_duplicate_json_xml_and_bad_metadata_fail_without_writes(analyst, app, bom):
    project, _ = setup(analyst, bom)
    data, raw = inputs(analyst, project, bom)
    before = app.state.knowledge.head()
    assert (
        file_preview(analyst, project, {**data, "expected_evidence": "f" * 64}, raw).status_code
        == 409
    )
    assert file_preview(analyst, project, {**data, "expected_versions": {}}, raw).status_code == 409
    assert file_preview(analyst, project, data, b'{"a":1,"a":2}').status_code == 422
    assert file_preview(analyst, project, data, b"<CycloneDX/>").status_code == 422
    assert file_preview(analyst, project, {**data, "document": {}}, raw).status_code == 422
    assert file_preview(analyst, project, {**data, "revision": True}, raw).status_code == 422
    assert app.state.knowledge.head() == before


def test_evidence_preview_before_inventory_keeps_unassigned_scope_explicit(analyst, app, bom):
    from tests.test_knowledge_api import product

    project = product(analyst)
    data, raw = inputs(analyst, project, bom)
    assert data["expected_versions"] == {}
    before = app.state.knowledge.head()
    response = file_preview(analyst, project, data, raw)
    assert response.status_code == 200, response.text
    assert response.json()["application"]["unassigned"]["application"]["matched"] == 0
    assert response.json()["application"]["unassigned"]["unmatched"]
    assert app.state.knowledge.head() == before
