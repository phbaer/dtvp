"""Actual HTTP workflow: scoped human decisions, independent review and scoring."""

from uuid import uuid4

from sqlalchemy import select

from dtvp.models import Membership, User
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_ownership import apply_policy
from tests.test_rescoring import BASE, VECTOR

app = knowledge_app
VERSION = "7.1.1"


def url(project_id, suffix=""):
    return f"/api/v3/projects/{project_id}{suffix}"


def workspace(client, project_id, version=VERSION, **params):
    result = client.get(url(project_id, f"/versions/{version}/workspace"), params=params)
    assert result.status_code == 200, result.text
    return result.json()


def setup(client, bom, versions=(VERSION,)):
    login(client, "administrator")
    project_id = product(client)
    teams = {item["name"]: item["id"] for item in client.get("/api/v2/workspaces").json()}
    for version in versions:
        imported(client, project_id, version, body(bom, request_id="build-" + version))
    apply_policy(client, project_id, [{"selector": "*", "team_id": teams["Platform"]}])
    login(client)
    return project_id, teams


def target(row, version=VERSION):
    return {
        "version": version,
        "context_id": row["context_id"],
        "vulnerability_id": row["vulnerability_id"],
    }


def assessment(
    client,
    project_id,
    *,
    row=None,
    versions=(VERSION,),
    stage="submit",
    assessment_id=None,
    state="affected",
    expected_revision=None,
    **changes,
):
    current = {version: workspace(client, project_id, version) for version in versions}
    row = row or current[versions[0]]["items"][0]
    targets = [
        target(
            next(
                item
                for item in current[version]["items"]
                if item["context_id"] == row["context_id"]
                and item["vulnerability_id"] == row["vulnerability_id"]
            ),
            version,
        )
        for version in versions
    ]
    payload = {
        "request_id": str(uuid4()),
        "expected_versions": {version: value["state"] for version, value in current.items()},
        "expected_revision": expected_revision,
        "targets": targets,
        "state": state,
        "rationale": "Reviewed deployment evidence",
        **changes,
    }
    assessment_id = assessment_id or str(uuid4())
    response = client.post(url(project_id, f"/assessments/{assessment_id}/{stage}"), json=payload)
    return response, assessment_id, payload


def reviewed(client, project_id, row=None, versions=(VERSION,)):
    response, assessment_id, submitted = assessment(client, project_id, row=row, versions=versions)
    assert response.status_code == 201, response.text
    login(client, "reviewer")
    current = {version: workspace(client, project_id, version) for version in versions}
    row = next(
        item
        for item in current[versions[0]]["items"]
        if item["context_id"] == submitted["targets"][0]["context_id"]
        and item["vulnerability_id"] == submitted["targets"][0]["vulnerability_id"]
    )
    review = {
        "request_id": str(uuid4()),
        "expected_versions": {version: value["state"] for version, value in current.items()},
        "assessment_id": assessment_id,
        "assessment_revision": row["coverage"]["assessment"]["revision"],
        "targets": submitted["targets"],
        "action": "approve",
        "rationale": "Independent review",
    }
    response = client.post(url(project_id, "/reviews"), json=review)
    assert response.status_code == 201, response.text
    return row, review


def score_input(client, project_id, row, version=VERSION):
    return {
        "request_id": str(uuid4()),
        "expected_versions": {version: workspace(client, project_id, version)["state"]},
        "targets": [target(row, version)],
        "base_vector": BASE,
        "vector": VECTOR,
        "rationale": "Current reviewed deployment context",
    }


def test_workspace_permissions_details_and_full_filtered_statistics(analyst, bom):
    project_id, teams = setup(analyst, bom)
    current = workspace(analyst, project_id, limit=1)
    assert len(current["items"]) == 1
    assert current["statistics"]["totals"]["context_findings"] == 2
    assert current["next_offset"] == 1
    row = current["items"][0]
    assert row["capabilities"] == ["assess"]
    assert row["source_ratings"][0]["observed_source"] == "pipeline/main"
    assert row["source_severity"] == "critical"
    detail = analyst.get(
        url(
            project_id,
            f"/versions/{VERSION}/workspace/{row['context_id']}/{row['vulnerability_id']}",
        )
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["id"] == row["id"]
    filtered = workspace(analyst, project_id, team_id=teams["Platform"], q=row["vulnerability_id"])
    assert filtered["statistics"]["context_findings"] == 1
    assert workspace(analyst, project_id, lifecycle="approved")["items"] == []
    login(analyst, "operations")
    assert analyst.get(url(project_id, f"/versions/{VERSION}/workspace")).status_code == 404


def test_not_affected_requires_reason_and_request_changes_requires_reassessment(analyst, bom):
    project_id, _ = setup(analyst, bom)
    failed, _, _ = assessment(analyst, project_id, state="not_affected")
    assert failed.status_code == 422, failed.text
    response, assessment_id, _ = assessment(
        analyst, project_id, state="not_affected", justification="code_not_reachable"
    )
    assert response.status_code == 201, response.text
    current = workspace(analyst, project_id)
    row = current["items"][0]
    login(analyst, "reviewer")
    payload = {
        "request_id": str(uuid4()),
        "expected_versions": {VERSION: current["state"]},
        "assessment_id": assessment_id,
        "assessment_revision": row["coverage"]["assessment"]["revision"],
        "targets": [target(row)],
        "action": "request_changes",
        "rationale": "Add reachability evidence",
    }
    response = analyst.post(url(project_id, "/reviews"), json=payload)
    assert response.status_code == 201, response.text
    coverage = workspace(analyst, project_id)["items"][0]["coverage"]
    assert coverage["status"] == "reassessment_needed"
    assert coverage["recorded"] and not coverage["submitted"] and not coverage["approved"]


def test_independent_review_and_admin_only_role_cannot_assess(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    login(analyst, "reviewer")
    response, assessment_id, payload = assessment(analyst, project_id)
    assert response.status_code == 201, response.text
    current = workspace(analyst, project_id)
    row = current["items"][0]
    response = analyst.post(
        url(project_id, "/reviews"),
        json={
            "request_id": str(uuid4()),
            "expected_versions": {VERSION: current["state"]},
            "assessment_id": assessment_id,
            "assessment_revision": row["coverage"]["assessment"]["revision"],
            "targets": payload["targets"],
            "action": "approve",
            "rationale": "Self approval attempt",
        },
    )
    assert response.status_code == 403, response.text
    with app.state.sessions() as db:
        admin = db.scalar(select(User).where(User.subject == "administrator"))
        membership = db.scalar(select(Membership).where(Membership.user_id == admin.id))
        membership.roles = ["admin"]
        db.commit()
    login(analyst, "administrator")
    response, _, _ = assessment(analyst, project_id)
    assert response.status_code == 404, response.text


def test_coordinator_gate_is_per_vulnerability_and_source_base_is_immutable(analyst, bom):
    project_id, _ = setup(analyst, bom)
    row = workspace(analyst, project_id)["items"][0]
    proposal = score_input(analyst, project_id, row)
    assert analyst.post(url(project_id, "/scoring/preview"), json=proposal).status_code == 404
    login(analyst, "coordinator")
    blocked = analyst.post(url(project_id, "/scoring/preview"), json=proposal)
    assert blocked.status_code == 200, blocked.text
    assert not blocked.json()["eligible"]
    assert (
        analyst.post(
            url(project_id, "/scoring/publish"),
            json={**proposal, "preview": blocked.json()["preview"]},
        ).status_code
        == 409
    )
    login(analyst)
    reviewed(analyst, project_id, row)
    login(analyst, "coordinator")
    proposal = score_input(analyst, project_id, row)
    preview = analyst.post(url(project_id, "/scoring/preview"), json=proposal)
    assert preview.status_code == 200, preview.text
    assert preview.json()["eligible"]
    assert any(
        item["coverage"]["status"] == "unassessed"
        for item in workspace(analyst, project_id)["items"]
    )
    assert (
        analyst.post(
            url(project_id, "/scoring/publish"),
            json={**proposal, "preview": preview.json()["preview"]},
        ).status_code
        == 201
    )
    row = workspace(analyst, project_id)["items"][0]
    assert row["published_score"]["current"]
    assert row["source_ratings"][0]["score"] == 9.8
    assert row["published_score"]["score"] < 9.8
    changed_base = BASE.replace("AV:N", "AV:P")
    invalid = {
        **score_input(analyst, project_id, row),
        "base_vector": changed_base,
        "vector": changed_base + "/MAV:P",
    }
    assert analyst.post(url(project_id, "/scoring/preview"), json=invalid).status_code == 422


def approve(client, project_id, assessment_id, revision, targets, persona="reviewer"):
    login(client, persona)
    expected = {
        item["version"]: workspace(client, project_id, item["version"])["state"] for item in targets
    }
    return client.post(
        url(project_id, "/reviews"),
        json={
            "request_id": str(uuid4()),
            "expected_versions": expected,
            "assessment_id": assessment_id,
            "assessment_revision": revision,
            "targets": targets,
            "action": "approve",
            "rationale": "Independent scoped approval",
        },
    )


def test_parallel_versions_require_explicit_review_coverage_and_atomic_cas(analyst, bom):
    versions = (VERSION, "7.1.2")
    project_id, _ = setup(analyst, bom, versions)
    response, assessment_id, payload = assessment(analyst, project_id, versions=versions)
    assert response.status_code == 201, response.text
    row = workspace(analyst, project_id)["items"][0]
    revision = row["coverage"]["assessment"]["revision"]
    response = approve(analyst, project_id, assessment_id, revision, payload["targets"][:1])
    assert response.status_code == 201, response.text
    assert workspace(analyst, project_id)["items"][0]["coverage"]["approved"]
    assert not workspace(analyst, project_id, "7.1.2")["items"][0]["coverage"]["approved"]
    login(analyst, "coordinator")
    preview = analyst.post(
        url(project_id, "/scoring/preview"), json=score_input(analyst, project_id, row)
    )
    assert preview.status_code == 200 and preview.json()["eligible"], preview.text
    preview = analyst.post(
        url(project_id, "/scoring/preview"), json=score_input(analyst, project_id, row, "7.1.2")
    )
    assert preview.status_code == 200 and not preview.json()["eligible"], preview.text
    login(analyst)
    stale = {**payload, "request_id": str(uuid4()), "expected_revision": revision}
    result = analyst.post(url(project_id, f"/assessments/{assessment_id}/draft"), json=stale)
    assert result.status_code == 409, result.text
    assert (
        workspace(analyst, project_id, "7.1.2")["items"][0]["coverage"]["assessment"]["revision"]
        == revision
    )


def test_all_consuming_teams_must_review_same_vulnerability(analyst, bom):
    import copy

    bom = copy.deepcopy(bom)
    bom["components"].extend(
        [
            {"type": "application", "name": "app-a", "version": "1", "bom-ref": "app-a"},
            {"type": "application", "name": "app-b", "version": "1", "bom-ref": "app-b"},
        ]
    )
    bom["dependencies"][0]["dependsOn"] = ["app-a", "app-b"]
    bom["dependencies"].extend(
        [
            {"ref": "app-a", "dependsOn": ["http", "parser"]},
            {"ref": "app-b", "dependsOn": ["http"]},
        ]
    )
    project_id, teams = setup(analyst, bom)
    login(analyst, "administrator")
    response = analyst.put(
        f"/api/v2/projects/{project_id}/sharing",
        json={"workspace_id": teams["Operations"], "capabilities": ["read", "assess", "approve"]},
    )
    assert response.status_code == 200, response.text
    apply_policy(
        analyst,
        project_id,
        [
            {"selector": "app-a", "team_id": teams["Platform"]},
            {"selector": "app-b", "team_id": teams["Operations"]},
        ],
        request_id="split-roots",
        context_roots={VERSION: ["app-a", "app-b"]},
    )
    login(analyst)
    rows = workspace(analyst, project_id, q="CVE-2099-20001")["items"]
    assert len(rows) == 2
    platform = next(row for row in rows if row["context"]["team_id"] == teams["Platform"])
    operations = next(row for row in rows if row["context"]["team_id"] == teams["Operations"])
    response, _, _ = assessment(analyst, project_id, row=operations)
    assert response.status_code == 403, response.text
    reviewed(analyst, project_id, row=platform)
    login(analyst, "coordinator")
    result = analyst.post(
        url(project_id, "/scoring/preview"), json=score_input(analyst, project_id, platform)
    )
    assert result.status_code == 200 and not result.json()["eligible"], result.text
    assert result.json()["blocked"][0]["required_contexts"] == 2
    login(analyst, "operations")
    response, assessment_id, payload = assessment(analyst, project_id, row=operations)
    assert response.status_code == 201, response.text
    current = next(
        row for row in workspace(analyst, project_id)["items"] if row["id"] == operations["id"]
    )
    response = approve(
        analyst,
        project_id,
        assessment_id,
        current["coverage"]["assessment"]["revision"],
        payload["targets"],
        "operations-reviewer",
    )
    assert response.status_code == 201, response.text
    login(analyst, "coordinator")
    result = analyst.post(
        url(project_id, "/scoring/preview"), json=score_input(analyst, project_id, platform)
    )
    assert result.status_code == 200 and result.json()["eligible"], result.text


def test_approved_score_survives_draft_and_reassignment_but_not_material_import(analyst, bom):
    import copy

    project_id, teams = setup(analyst, bom)
    row, review = reviewed(analyst, project_id)
    login(analyst, "coordinator")
    proposal = score_input(analyst, project_id, row)
    preview = analyst.post(url(project_id, "/scoring/preview"), json=proposal)
    assert preview.status_code == 200, preview.text
    response = analyst.post(
        url(project_id, "/scoring/publish"), json={**proposal, "preview": preview.json()["preview"]}
    )
    assert response.status_code == 201, response.text
    login(analyst)
    response, _, _ = assessment(
        analyst,
        project_id,
        row=row,
        stage="draft",
        assessment_id=review["assessment_id"],
        expected_revision=review["assessment_revision"],
        state="under_investigation",
    )
    assert response.status_code == 201, response.text
    current = workspace(analyst, project_id)["items"][0]
    assert current["coverage"]["approved"]
    assert current["coverage"]["assessment"]["stage"] == "draft"
    assert current["published_score"]["current"]
    login(analyst, "administrator")
    apply_policy(
        analyst,
        project_id,
        [{"selector": "*", "team_id": teams["Operations"]}],
        request_id="reassign",
    )
    current = workspace(analyst, project_id)["items"][0]
    assert current["coverage"]["historical_team_id"] == teams["Platform"]
    assert current["coverage"]["approved"]
    assert current["published_score"]["current"]
    changed = copy.deepcopy(bom)
    changed["vulnerabilities"][0]["description"] += " Additional material source evidence."
    imported(
        analyst,
        project_id,
        VERSION,
        body(
            changed,
            expected=workspace(analyst, project_id)["state"],
            request_id="changed-source",
            build_number=2,
        ),
    )
    current = workspace(analyst, project_id)["items"][0]
    assert current["coverage"]["status"] == "reassessment_needed"
    assert not current["published_score"]["current"]


def test_projection_failure_returns_committed_pending_and_retries_receipt(
    analyst, app, bom, monkeypatch
):
    import dtvp.api_knowledge as api_knowledge

    project_id, _ = setup(analyst, bom)
    before = app.state.knowledge.head()
    with monkeypatch.context() as patch:

        def fail_projection(*args, **kwargs):
            raise RuntimeError("Disposable projection temporarily unavailable")

        patch.setattr(api_knowledge, "catch_up", fail_projection)
        response, assessment_id, payload = assessment(analyst, project_id)
        assert response.status_code == 202, response.text
    committed = app.state.knowledge.head()
    assert committed != before
    retry = analyst.post(url(project_id, f"/assessments/{assessment_id}/submit"), json=payload)
    assert retry.status_code == 201, retry.text
    assert app.state.knowledge.head() == committed
    assert workspace(analyst, project_id)["statistics"]["submitted"] == 1
