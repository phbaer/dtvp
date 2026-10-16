"""Actual HTTP strict subset selection, exact file retention and publication boundaries."""

import copy
import json

from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_evidence_api import path, payload, state, vex_for
from tests.test_workflow_api import setup

app = knowledge_app
PROFILE = "dtvp-openvex-0.2.0-exact/1"


def test_conformance_reports_bounded_failures_without_writes_or_approval(analyst, app, bom):
    project, _ = setup(analyst, bom)
    document = vex_for(bom)
    document["statements"][0]["products"][0]["subcomponents"] = [{"@id": "pkg:generic/other@1"}]
    before = app.state.knowledge.head()
    response = analyst.post(
        path(project, "/conformance"), json={"document": document, "validation_profile": PROFILE}
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["valid"] is False
    assert report["diagnostics"][0]["code"] == "scope_semantics_unsupported"
    assert report["schema_validation"] == "dtvp_supported_subset_only"
    assert report["signature_verification"] == "not_performed"
    data = payload(analyst, project, document, validation_profile=PROFILE)
    for endpoint in ("/preview", "/imports"):
        response = analyst.post(path(project, endpoint), json=data)
        assert response.status_code == 422, response.text
    assert app.state.knowledge.head() == before
    assert state(analyst, project)["total"] == 0
    login(analyst, "viewer")
    assert analyst.post(
        path(project, "/conformance"), json={"document": document, "validation_profile": PROFILE}
    ).status_code in {403, 404}


def test_strict_json_preview_import_and_exact_replay_keep_profile_attribution(analyst, app, bom):
    project, _ = setup(analyst, bom)
    document = vex_for(bom)
    document["signature"] = {"value": "unverified"}
    data = payload(analyst, project, document, validation_profile=PROFILE)
    before = app.state.knowledge.head()
    response = analyst.post(path(project, "/preview"), json=data)
    assert response.status_code == 200, response.text
    assert response.json()["conformance"]["warnings"][0]["code"] == "signature_present_not_verified"
    assert app.state.knowledge.head() == before
    response = analyst.post(path(project, "/imports"), json=data)
    assert response.status_code == 201, response.text
    assert response.json()["committed"]
    replay = analyst.post(path(project, "/imports"), json=data)
    assert replay.status_code == 201 and replay.json() == response.json()
    current = state(analyst, project)
    assert current["documents"][0]["document"]["conformance"]["profile"] == PROFILE
    changed = copy.deepcopy(data)
    changed["validation_profile"] = None
    assert analyst.post(path(project, "/imports"), json=changed).status_code == 409


def test_strict_file_preview_and_import_validate_identical_original_bytes(analyst, app, bom):
    project, _ = setup(analyst, bom)
    data = payload(analyst, project, vex_for(bom), validation_profile=PROFILE)
    raw = json.dumps(data.pop("document"), indent=3).encode() + b"\n"
    before = app.state.knowledge.head()
    response = analyst.post(
        path(project, "/files/preview"),
        files={"file": ("vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )
    assert response.status_code == 200, response.text
    assert response.json()["artifact_sha"] == digest(raw)
    assert response.json()["conformance"]["valid"]
    assert app.state.knowledge.head() == before
    response = analyst.post(
        path(project, "/files"),
        files={"file": ("vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )
    assert response.status_code == 201, response.text
    assert analyst.get(path(project, f"/{digest(raw)}/source")).content == raw
