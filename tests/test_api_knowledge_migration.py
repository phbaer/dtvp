"""Real v2 approved snapshot -> explicitly unapproved native model, with scoped raw provenance."""

import pytest

from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app


@pytest.fixture
def legacy(analyst, release_id):
    finding = analyst.get("/api/v2/findings").json()["items"][0]
    decision = analyst.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={
            "expected_version": finding["state_version"],
            "state": "affected",
            "rationale": "Legacy deployment evidence reviewed",
        },
    )
    assert decision.status_code == 201, decision.text
    login(analyst, "reviewer")
    current = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    approval = analyst.post(
        f"/api/v2/findings/{finding['id']}/approvals",
        json={"expected_version": current["state_version"], "decision_id": decision.json()["id"]},
    )
    assert approval.status_code == 200, approval.text
    snapshot = analyst.post("/api/v2/snapshots", json={"release_id": release_id})
    assert snapshot.status_code == 201, snapshot.text
    snapshot = snapshot.json()
    raw = analyst.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").content
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    login(analyst, "administrator")
    return project, snapshot, raw


def path(project, operation):
    return f"/api/v3/projects/{project}/versions/migrated/migration/v2/{operation}"


def body(snapshot):
    return {
        "request_id": "explicit-migration",
        "snapshot_id": snapshot["id"],
        "snapshot_sha": snapshot["sha256"],
        "expected": None,
        "expected_policy": None,
        "expected_evidence": None,
        "source": "pipeline/main",
        "build_number": 0,
        "occurred_at": "2026-10-16T03:00:00Z",
        "acknowledge_historical_claims": True,
    }


def test_actual_approved_snapshot_archives_exact_originals_without_native_approval(
    analyst, app, legacy
):
    project, snapshot, raw = legacy
    journal = app.state.knowledge
    before = journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))
    result = analyst.post(path(project, "preview"), json=body(snapshot))
    assert result.status_code == 200, result.text
    preview = result.json()
    assert preview["statistics"]["captured_latest_approvals"] >= 1
    assert (journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))) == before
    data = {**body(snapshot), "preview_digest": preview["preview_digest"]}
    applied = analyst.post(path(project, "apply"), json=data)
    assert applied.status_code == 201, applied.text
    state = applied.json()["updates"][0]["target"]
    sections = load_sections(journal, state)
    assert all(not sections[name] for name in ("assessments", "reviews", "scoring"))
    assert journal.objects.read(snapshot["sha256"]) == raw
    summary = next(
        value for key, value in sections["history"].items() if key.startswith("migration:")
    )
    for sha in summary["source_artifacts"]:
        assert journal.objects.read(sha) == app.state.artifacts.read(sha)
    current = analyst.get(f"/api/v3/projects/{project}/versions/migrated/workspace").json()
    assert current["statistics"]["totals"]["context_findings"] > 0
    assert current["statistics"]["approved"] == 0
    assert (
        analyst.get(
            f"/api/v3/projects/{project}/states/{state}/artifacts/{snapshot['sha256']}"
        ).content
        == raw
    )
    assert analyst.post(path(project, "apply"), json=data).json() == applied.json()
    assert (
        analyst.post(path(project, "apply"), json={**data, "source": "changed"}).status_code == 409
    )
    assert (
        analyst.post(
            path(project, "preview"), json={**body(snapshot), "request_id": "another"}
        ).status_code
        == 409
    )


def test_current_source_target_authorization_and_corrupt_originals_fail_before_publication(
    analyst, app, legacy
):
    project, snapshot, _ = legacy
    login(analyst, "viewer")
    assert analyst.post(path(project, "preview"), json=body(snapshot)).status_code in {403, 404}
    login(analyst, "operations")
    assert analyst.post(path(project, "preview"), json=body(snapshot)).status_code == 404
    login(analyst, "administrator")
    bad = {**body(snapshot), "snapshot_sha": "f" * 64}
    assert analyst.post(path(project, "preview"), json=bad).status_code == 409
    preview = analyst.post(path(project, "preview"), json=body(snapshot)).json()
    import json

    payload = json.loads(app.state.artifacts.read(snapshot["sha256"]))
    app.state.artifacts.path(payload["original_sha256"]).unlink()
    before = app.state.knowledge.head()
    assert (
        analyst.post(
            path(project, "apply"),
            json={**body(snapshot), "preview_digest": preview["preview_digest"]},
        ).status_code
        == 409
    )
    assert app.state.knowledge.head() == before


@pytest.mark.parametrize("mode", ["projection", "uncertain"])
def test_projection_pending_exact_receipt_retry_does_not_need_deleted_legacy_artifacts(
    analyst, app, legacy, monkeypatch, mode
):
    import dtvp.api_knowledge as api

    project, snapshot, _ = legacy
    preview = analyst.post(path(project, "preview"), json=body(snapshot)).json()
    data = {**body(snapshot), "preview_digest": preview["preview_digest"]}
    original = api.catch_up
    publisher = app.state.knowledge.publish
    if mode == "projection":
        monkeypatch.setattr(
            api, "catch_up", lambda *_: (_ for _ in ()).throw(RuntimeError("Projection offline"))
        )
    else:
        from dtvp.knowledge.journal import CommitUncertain

        def uncertain(**kwargs):
            receipt = publisher(**kwargs)
            raise CommitUncertain(receipt[0])

        monkeypatch.setattr(app.state.knowledge, "publish", uncertain)
    first = analyst.post(path(project, "apply"), json=data)
    assert first.status_code == (202 if mode == "projection" else 503)
    publication = app.state.knowledge.head()
    app.state.artifacts.path(snapshot["sha256"]).unlink()
    monkeypatch.setattr(api, "catch_up", original)
    monkeypatch.setattr(app.state.knowledge, "publish", publisher)
    retry = analyst.post(path(project, "apply"), json=data)
    assert retry.status_code == 201 and retry.json()["publication"] == publication


def test_target_management_does_not_grant_source_snapshot_access(analyst, app, legacy, monkeypatch):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from dtvp.models import Grant, Membership, Project, User, Workspace

    source, snapshot, _ = legacy
    with Session(app.state.engine) as db:
        operations = db.scalar(select(User).where(User.subject == "operations"))
        team = db.scalar(select(Workspace).where(Workspace.name == "Operations"))
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == operations.id, Membership.workspace_id == team.id
            )
        )
        membership.roles = ["admin"]
        target = db.scalar(select(Project).where(Project.workspace_id == team.id)).id
        team_id = team.id
        db.commit()
    login(analyst, "operations")
    original = app.state.artifacts.read
    original_path = app.state.artifacts.path
    monkeypatch.setattr(
        app.state.artifacts,
        "path",
        lambda *_: (_ for _ in ()).throw(AssertionError("Unauthorized artifact stat")),
    )
    monkeypatch.setattr(
        app.state.artifacts,
        "read",
        lambda *_: (_ for _ in ()).throw(AssertionError("Unauthorized artifact read")),
    )
    assert analyst.post(path(target, "preview"), json=body(snapshot)).status_code == 404
    with Session(app.state.engine) as db:
        db.add(Grant(project_id=source, workspace_id=team_id, capabilities=["read"]))
        db.commit()
    assert analyst.post(path(target, "preview"), json=body(snapshot)).status_code == 404
    with Session(app.state.engine) as db:
        db.get(Grant, (source, team_id)).capabilities = ["read", "snapshot"]
        db.commit()
    monkeypatch.setattr(app.state.artifacts, "read", original)
    monkeypatch.setattr(app.state.artifacts, "path", original_path)
    response = analyst.post(path(target, "preview"), json=body(snapshot))
    assert response.status_code == 200, response.text
    assert response.json()["source_proof"]["project_id"] == source
    assert response.json()["target"]["project_id"] == target


def test_actual_spdx_snapshot_uses_original_relationship_and_license_semantics(
    analyst, app, legacy
):
    project, _, _ = legacy
    release = analyst.post(f"/api/v2/projects/{project}/releases", json={"version": "spdx-source"})
    assert release.status_code == 201, release.text
    release_id = release.json()["id"]
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SPDX source",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.invalid/migration-spdx",
        "creationInfo": {"creators": ["Tool: migration-test"], "created": "2026-10-16T00:00:00Z"},
        "packages": [
            {
                "SPDXID": "SPDXRef-App",
                "name": "Application",
                "versionInfo": "1",
                "licenseDeclared": "NOASSERTION",
            },
            {
                "SPDXID": "SPDXRef-Library",
                "name": "Library",
                "versionInfo": "2",
                "licenseDeclared": "MIT",
                "licenseConcluded": "MIT",
            },
            {
                "SPDXID": "SPDXRef-Helper",
                "name": "Helper",
                "versionInfo": "3",
                "licenseDeclared": "Apache-2.0",
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-App",
            },
            {
                "spdxElementId": "SPDXRef-App",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-Library",
            },
            {
                "spdxElementId": "SPDXRef-App",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Helper",
            },
        ],
    }
    result = analyst.post(
        f"/api/v2/releases/{release_id}/ingestions",
        json={
            "source": "spdx-pipeline",
            "event_id": "spdx-1",
            "occurred_at": "2026-10-16T01:00:00Z",
            "sbom": spdx,
        },
    )
    assert result.status_code == 201, result.text
    response = analyst.post("/api/v2/snapshots", json={"release_id": release_id})
    assert response.status_code == 201, response.text
    snapshot = response.json()
    old_bom = analyst.get(f"/api/v2/snapshots/{snapshot['id']}/sbom").json()
    assert (
        "SPDXRef-Library"
        in next(edge for edge in old_bom["dependencies"] if edge["ref"] == "SPDXRef-App")[
            "dependsOn"
        ]
    )
    request = body(snapshot)
    preview = analyst.post(path(project, "preview"), json=request)
    assert preview.status_code == 200, preview.text
    assert preview.json()["composition"]["legacy_derived_edges_not_adopted"] == 2
    applied = analyst.post(
        path(project, "apply"), json={**request, "preview_digest": preview.json()["preview_digest"]}
    )
    assert applied.status_code == 201, applied.text
    state = applied.json()["updates"][0]["target"]
    sections = load_sections(app.state.knowledge, state)
    inventory = sections["inventory"]
    assert inventory["baseline"]["format"] == "spdx-2.3-json"
    assert inventory["baseline"]["representation"] == "original_bytes"
    assert inventory["dependencies"]["edges"] == [
        {"ref": "SPDXRef-App", "dependsOn": ["SPDXRef-Helper"]}
    ]
    assert {item["kind"] for item in inventory["relationships"]["items"]} == {
        "DESCRIBES",
        "CONTAINS",
        "DEPENDS_ON",
    }
    worklist = analyst.get(f"/api/v3/projects/{project}/states/{state}/license-worklist").json()
    library = next(item for item in worklist["items"] if item["component_ref"] == "SPDXRef-Library")
    assert library["source"]["format"] == "spdx-2.3-json"
    assert library["evidence"]["status"] == "reported"
    assert any(fact["value"] == "MIT" for fact in library["evidence"]["facts"])
    assert library["clearance"] == "not_assessed"


@pytest.mark.parametrize("kind", ["bundle", "original"])
def test_oversized_authorized_files_rejected_before_loading_bytes(
    analyst, app, legacy, monkeypatch, kind
):
    import json
    from types import SimpleNamespace

    from dtvp.knowledge.migration import MAX_BUNDLE_BYTES, MAX_SOURCE_BYTES

    project, snapshot, raw = legacy
    selected = snapshot["sha256"] if kind == "bundle" else json.loads(raw)["original_sha256"]
    bound = MAX_BUNDLE_BYTES if kind == "bundle" else MAX_SOURCE_BYTES
    artifacts = app.state.artifacts
    original_path, original_read = artifacts.path, artifacts.read
    calls = []

    def path_for(sha):
        if sha == selected:
            return SimpleNamespace(stat=lambda: SimpleNamespace(st_size=bound + 1))
        return original_path(sha)

    def read(sha):
        assert sha != selected, "Oversized files must be rejected before allocating their bytes"
        calls.append(sha)
        return original_read(sha)

    monkeypatch.setattr(artifacts, "path", path_for)
    monkeypatch.setattr(artifacts, "read", read)
    before = app.state.knowledge.head()
    response = analyst.post(path(project, "preview"), json=body(snapshot))
    assert response.status_code == 409, response.text
    assert app.state.knowledge.head() == before
    assert calls == ([] if kind == "bundle" else [snapshot["sha256"]])
