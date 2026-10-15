"""HTTP evidence intake enforces scope and preserves immutable human/source state."""

import copy

import pytest

from dtvp.knowledge.exports import export_bytes
from dtvp.knowledge.journal import CommitUncertain
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_knowledge_agentyzer import qualified
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_workflow_api import url, workspace

app = knowledge_app
VERSION = "7.1.1"


def prepare(client, bom):
    project_id = product(client)
    state = imported(client, project_id, VERSION, body(bom, context=qualified()))
    before = workspace(client, project_id)
    row = next(item for item in before["items"] if item["vulnerability_id"] == "CVE-2099-20001")
    response = client.post(
        url(project_id, f"/states/{state}/agentyzer-input"),
        json={"context_id": row["context_id"], "vulnerability_id": row["vulnerability_id"]},
    )
    assert response.status_code == 200, response.text
    derived = response.json()
    return (
        project_id,
        row,
        {
            "request_id": "native-analysis-result",
            "expected": state,
            "input_receipt": derived["receipt"],
            "raw_report": report(derived),
            "source_label": "Repository analysis",
        },
    )


def endpoint(project_id):
    return url(project_id, f"/versions/{VERSION}/proposals/agentyzer")


def selected(client, project_id, row, **params):
    result = workspace(client, project_id, **params)
    return result, next(item for item in result["items"] if item["id"] == row["id"])


def test_native_returned_evidence_roundtrip_preserves_pins_sources_and_raw_artifact(
    analyst, app, bom
):
    project_id, row, payload = prepare(analyst, bom)
    journal = app.state.knowledge
    before = load_sections(journal, payload["expected"])
    sealed = export_bytes(journal, payload["expected"])
    assert "code_analysis" not in row
    login(analyst, "reviewer")  # Evidence capability does not require source-write capability.
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 201, response.text
    assert analyst.post(endpoint(project_id), json=payload).json() == response.json()
    after, updated = selected(analyst, project_id, row)
    evidence = updated["code_analysis"][0]
    assert evidence["application_eligible"] and evidence["rescoring_eligible"]
    assert evidence["current"] and evidence["proposal"]["score"] == 0
    assert updated["published_score"] is None
    assert updated["coverage"]["status"] == "unassessed"
    assert updated["scoring_proposals"][0]["provider"] == "agentyzer"
    current = load_sections(journal, after["state"])
    for key in ("inventory", "ownership", "vulnerabilities", "assessments", "reviews"):
        assert current[key] == before[key]
    assert export_bytes(journal, payload["expected"]) == sealed
    path = url(project_id, f"/states/{after['state']}/proposals/agentyzer/{evidence['id']}/report")
    downloaded = analyst.get(path)
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == canonical(payload["raw_report"])
    assert downloaded.headers["X-Content-SHA256"] == digest(downloaded.content)
    assert downloaded.headers["X-DTVP-Representation"] == "canonical_json"
    assert analyst.get(path.replace(after["state"], payload["expected"])).status_code == 404
    detail = analyst.get(
        url(
            project_id,
            f"/versions/{VERSION}/workspace/{row['context_id']}/{row['vulnerability_id']}",
        )
    )
    assert detail.status_code == 200
    assert detail.json()["code_analysis"] == updated["code_analysis"]
    filtered = workspace(analyst, project_id, provider="agentyzer", limit=1)
    assert filtered["statistics"]["context_findings"] == 1
    assert [item["id"] for item in filtered["items"]] == [row["id"]]


def test_bare_partial_report_is_visible_and_provider_filtered_without_a_score(analyst, bom):
    project_id, row, payload = prepare(analyst, bom)
    payload["raw_report"] = payload["raw_report"]["report"]
    payload["raw_report"]["assessment"].pop("adjusted_cvss")
    payload["raw_report"]["assessment"]["version_analysis"] = ["malformed"]
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 201, response.text
    filtered, updated = selected(analyst, project_id, row, provider="Repository analysis", limit=1)
    assert filtered["statistics"]["context_findings"] == 1
    assert "scoring_proposals" not in updated
    evidence = updated["code_analysis"][0]
    assert not evidence["application_eligible"] and not evidence["rescoring_eligible"]
    assert "native_vulnerability_request_binding_missing" in evidence["ineligibility_reasons"]
    assert updated["coverage"]["status"] == "unassessed"


@pytest.mark.parametrize("source", ["foreign", "missing"])
def test_source_state_authorization_precedes_intake(analyst, app, bom, monkeypatch, source):
    import dtvp.api_agentyzer_results as api

    project_id, _, payload = prepare(analyst, bom)
    journal = app.state.knowledge
    if source == "foreign":
        payload["input_receipt"]["state"] = journal.snapshot(
            project_id="private-product",
            version=VERSION,
            actor_id="other",
            reason="Private source",
            sections=load_sections(journal, payload["expected"]),
        )
    else:
        payload["input_receipt"]["state"] = "f" * 64
    before = journal.head()
    monkeypatch.setattr(
        api,
        "import_agentyzer_result",
        lambda *args, **kwargs: pytest.fail("Unauthorized source reached intake"),
    )
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 404, response.text
    assert journal.head() == before


def test_evidence_permissions_csrf_and_report_read_scope(analyst, app, bom):
    project_id, row, payload = prepare(analyst, bom)
    before = app.state.knowledge.head()
    login(analyst, "viewer")
    assert analyst.post(endpoint(project_id), json=payload).status_code == 404
    login(analyst, "operations")
    assert analyst.post(endpoint(project_id), json=payload).status_code == 404
    assert app.state.knowledge.head() == before
    login(analyst)
    csrf = analyst.headers.pop("X-CSRF-Token")
    assert analyst.post(endpoint(project_id), json=payload).status_code == 403
    analyst.headers["X-CSRF-Token"] = csrf
    response = analyst.post(endpoint(project_id), json=payload)
    assert response.status_code == 201, response.text
    after, updated = selected(analyst, project_id, row)
    evidence = updated["code_analysis"][0]
    path = url(project_id, f"/states/{after['state']}/proposals/agentyzer/{evidence['id']}/report")
    login(analyst, "viewer")
    assert analyst.get(path).status_code == 200
    login(analyst, "operations")
    assert analyst.get(path).status_code == 404


def test_target_and_receipt_conflicts_do_not_publish(analyst, app, bom):
    project_id, _, payload = prepare(analyst, bom)
    before = app.state.knowledge.head()
    tampered = copy.deepcopy(payload)
    tampered["input_receipt"]["subject_digest"] = "sha256:" + "b" * 64
    response = analyst.post(endpoint(project_id), json=tampered)
    assert response.status_code == 422, response.text
    assert app.state.knowledge.head() == before
    assert analyst.post(endpoint(project_id), json=payload).status_code == 201
    stale = {**payload, "request_id": "another-request"}
    assert analyst.post(endpoint(project_id), json=stale).status_code == 409


def test_projection_pending_retry_is_idempotent(analyst, app, bom, monkeypatch):
    import dtvp.api_knowledge as api

    project_id, row, payload = prepare(analyst, bom)
    original = api.catch_up
    monkeypatch.setattr(
        api,
        "catch_up",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("Projection unavailable")),
    )
    pending = analyst.post(endpoint(project_id), json=payload)
    assert pending.status_code == 202, pending.text
    assert pending.json()["committed"] is True and pending.json()["projection"] == "pending"
    head = app.state.knowledge.head()
    monkeypatch.setattr(api, "catch_up", original)
    replay = analyst.post(endpoint(project_id), json=payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["publication"] == pending.json()["publication"]
    assert app.state.knowledge.head() == head
    _, updated = selected(analyst, project_id, row)
    assert len(updated["code_analysis"]) == 1


def test_uncertain_publication_asks_for_identical_retry_without_claiming_failure(
    analyst, app, bom, monkeypatch
):
    project_id, row, payload = prepare(analyst, bom)
    journal = app.state.knowledge
    original = journal.publish

    def uncertain(*args, **kwargs):
        result = original(*args, **kwargs)
        raise CommitUncertain(result[0])

    monkeypatch.setattr(journal, "publish", uncertain)
    result = analyst.post(endpoint(project_id), json=payload)
    assert result.status_code == 503, result.text
    assert result.json()["committed"] is None
    assert result.json()["request_id"] == payload["request_id"]
    monkeypatch.setattr(journal, "publish", original)
    replay = analyst.post(endpoint(project_id), json=payload)
    assert replay.status_code == 201, replay.text
    _, updated = selected(analyst, project_id, row)
    assert len(updated["code_analysis"]) == 1
