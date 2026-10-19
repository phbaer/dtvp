"""Actual HTTP evidence intake, preview, authorization and baseline reconciliation."""

import copy
import json
from uuid import uuid4

from dtvp.knowledge.assessments import load_sections
from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_assembly import assembly, publish, selection, source_import
from tests.test_knowledge_vex import claims, openvex
from tests.test_workflow_api import VERSION, reviewed, setup, workspace

app = knowledge_app


def path(project_id, suffix=""):
    return f"/api/v1/projects/{project_id}/evidence{suffix}"


def state(client, project_id):
    result = client.get(path(project_id))
    assert result.status_code == 200, result.text
    return result.json()


def payload(client, project_id, document, **changes):
    current = state(client, project_id)
    return {
        "request_id": str(uuid4()),
        "expected_evidence": current["evidence_state"],
        "expected_versions": current["versions"],
        "source": "supplier",
        "revision": 1,
        "document": document,
        **changes,
    }


def vex_for(bom, *, status="not_affected", **changes):
    document = openvex(status=status, product=bom["components"][0]["purl"], **changes)
    document["statements"][0]["vulnerability"]["name"] = bom["vulnerabilities"][0]["id"]
    return document


def ingest(client, project_id, document, **changes):
    data = payload(client, project_id, document, **changes)
    result = client.post(path(project_id, "/imports"), json=data)
    assert result.status_code == 201, result.text
    return data, result.json()


def test_json_preview_is_read_only_and_canonical_import_retains_exact_original(analyst, app, bom):
    project_id = product(analyst)
    imported(analyst, project_id, VERSION, body(bom))
    document = vex_for(bom)
    data = payload(analyst, project_id, document)
    before = app.state.knowledge.head()
    preview = analyst.post(path(project_id, "/preview"), json=data)
    assert preview.status_code == 200, preview.text
    assert not preview.json()["committed"]
    assert len(preview.json()["application"][VERSION]["would_apply"]) == 1
    assert app.state.knowledge.head() == before
    assert state(analyst, project_id)["documents"] == []
    result = analyst.post(path(project_id, "/imports"), json=data)
    assert result.status_code == 201, result.text
    sha = digest(canonical(document))
    current = state(analyst, project_id)
    assert current["evidence_state"]
    assert current["documents"][0]["artifact_sha"] == sha
    original = analyst.get(path(project_id, f"/{sha}/source"))
    assert original.status_code == 200
    assert original.content == canonical(document)
    assert original.headers["x-content-sha256"] == sha
    committed = app.state.knowledge.head()
    assert analyst.post(path(project_id, "/imports"), json=data).json() == result.json()
    assert app.state.knowledge.head() == committed
    conflict = analyst.post(path(project_id, "/imports"), json={**data, "revision": 2})
    assert conflict.status_code == 409


def test_file_original_bytes_and_supported_subset_validation(analyst, app, bom):
    project_id = product(analyst)
    document = vex_for(bom)
    raw = json.dumps(document, indent=3).encode() + b"\n"
    data = payload(analyst, project_id, document)
    del data["document"]
    response = analyst.post(
        path(project_id, "/files"),
        files={"file": ("supplier-vex.json", raw, "application/json")},
        data={"metadata": json.dumps(data)},
    )
    assert response.status_code == 201, response.text
    sha = digest(raw)
    assert analyst.get(path(project_id, f"/{sha}/source")).content == raw
    committed = app.state.knowledge.head()
    invalid = copy.deepcopy(document)
    invalid["@context"] = "https://openvex.dev/ns/v0.3.0"
    bad = analyst.post(
        path(project_id, "/imports"),
        json=payload(analyst, project_id, invalid, request_id="unsupported", revision=2),
    )
    assert bad.status_code == 422, bad.text
    assert app.state.knowledge.head() == committed


def test_evidence_before_sbom_survives_nightly_replacement_and_assembly(analyst, app, bom):
    project_id = product(analyst)
    document = vex_for(bom)
    ingest(analyst, project_id, document)
    assert state(analyst, project_id)["versions"] == {}
    first = imported(analyst, project_id, VERSION, body(bom))
    sections = load_sections(app.state.knowledge, first)
    assert len(claims(sections)) == 1
    assert len(sections["vulnerabilities"]) == len(bom["vulnerabilities"]) + 2
    second = imported(
        analyst,
        project_id,
        VERSION,
        body(bom, request_id="next-nightly", expected=first, build_number=2),
    )
    assert len(claims(load_sections(app.state.knowledge, second))) == 1
    # A separately assembled version reuses the product evidence selection but
    # matches each constituent occurrence independently, with namespaced refs.
    sources = [
        source_import(analyst, project_id, part, bom, version="7.1.2")
        for part in ("application", "container")
    ]
    assembled = publish(
        analyst,
        project_id,
        assembly(
            [selection("application", sources[0]), selection("container", sources[1])],
            request_id="assembled-evidence",
        ),
        version="7.1.2",
    )
    matches = claims(load_sections(app.state.knowledge, assembled))
    assert len(matches) == 2
    assert len({item["ref"] for item in matches}) == 2
    assert state(analyst, project_id)["documents"][0]["active"]


def test_evidence_capability_and_current_download_authorization(analyst, bom):
    project_id = product(analyst)
    document = vex_for(bom)
    ingest(analyst, project_id, document)
    sha = digest(canonical(document))
    login(analyst, "viewer")
    denied = analyst.post(
        path(project_id, "/imports"), json=payload(analyst, project_id, document, revision=2)
    )
    assert denied.status_code == 404
    assert analyst.get(path(project_id, f"/{sha}/source")).status_code == 200
    login(analyst, "administrator")
    teams = {team["name"]: team["id"] for team in analyst.get("/api/v1/workspaces").json()}
    shared = analyst.put(
        f"/api/v1/projects/{project_id}/sharing",
        json={"workspace_id": teams["Operations"], "capabilities": ["read"]},
    )
    assert shared.status_code == 200
    login(analyst, "operations")
    assert analyst.get(path(project_id, f"/{sha}/source")).status_code == 200
    data = payload(analyst, project_id, document, revision=2)
    assert analyst.post(path(project_id, "/preview"), json=data).status_code == 404
    assert analyst.post(path(project_id, "/imports"), json=data).status_code == 404
    login(analyst, "administrator")
    assert (
        analyst.put(
            f"/api/v1/projects/{project_id}/sharing",
            json={"workspace_id": teams["Operations"], "capabilities": []},
        ).status_code
        == 200
    )
    login(analyst, "operations")
    assert analyst.get(path(project_id)).status_code == 404
    assert analyst.get(path(project_id, f"/{sha}/source")).status_code == 404


def test_conflicting_sources_and_withdrawal_preserve_human_history_and_original_base_facts(
    analyst, app, bom
):
    project_id, _ = setup(analyst, bom)
    reviewed(analyst, project_id)
    prior = workspace(analyst, project_id)
    human = load_sections(app.state.knowledge, prior["state"])
    original_ratings = {item["id"]: item["source_ratings"] for item in prior["items"]}
    supplier = vex_for(bom)
    ingest(analyst, project_id, supplier)
    other = vex_for(bom, status="affected", action_statement="Upgrade the package")
    other["author"] = "Another publisher"
    preview = analyst.post(
        path(project_id, "/preview"),
        json=payload(analyst, project_id, other, source="another-publisher"),
    )
    assert preview.status_code == 200, preview.text
    contradictions = preview.json()["application"][VERSION]["contradictions"]
    assert contradictions[0]["statuses"] == ["affected", "not_affected"]
    ingest(analyst, project_id, other, source="another-publisher")
    current = workspace(analyst, project_id)
    sections = load_sections(app.state.knowledge, current["state"])
    assert sections["assessments"] == human["assessments"]
    assert sections["reviews"] == human["reviews"]
    assert len(claims(sections)) == 2
    for row in current["items"]:
        assert row["source_ratings"] == original_ratings[row["id"]]
        assert row["published_score"] is None
    sha = digest(canonical(supplier))
    selected = state(analyst, project_id)
    response = analyst.post(
        path(project_id, "/withdrawals"),
        json={
            "request_id": "withdraw-supplier",
            "expected_evidence": selected["evidence_state"],
            "expected_versions": selected["versions"],
            "artifact_sha": sha,
            "reason": "Supplier withdrew the statement.",
        },
    )
    assert response.status_code == 201, response.text
    assert analyst.get(path(project_id, f"/{sha}/source")).content == canonical(supplier)
    after = load_sections(app.state.knowledge, state(analyst, project_id)["versions"][VERSION])
    assert len(claims(after)) == 1
    assert after["assessments"] == human["assessments"] and after["reviews"] == human["reviews"]


def test_evidence_revisions_require_explicit_ordinals_and_exact_all_version_heads(
    analyst, app, bom
):
    project_id = product(analyst)
    for version in (VERSION, "7.1.2"):
        imported(analyst, project_id, version, body(bom, request_id="import-" + version))
    document = vex_for(bom)
    ingest(analyst, project_id, document, revision=5)
    before = app.state.knowledge.head()
    old = analyst.post(
        path(project_id, "/imports"), json=payload(analyst, project_id, document, revision=4)
    )
    assert old.status_code == 409
    incomplete = analyst.post(
        path(project_id, "/imports"),
        json=payload(
            analyst,
            project_id,
            document,
            revision=6,
            expected_versions={VERSION: state(analyst, project_id)["versions"][VERSION]},
        ),
    )
    assert incomplete.status_code == 409
    assert app.state.knowledge.head() == before
    ingest(analyst, project_id, document, revision=6)
    selected = state(analyst, project_id)
    assert len(selected["documents"]) == 1 and selected["documents"][0]["source_revision"] == 6
