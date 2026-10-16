"""Bulk HTTP admission and atomic scoped reviews share the existing review engine."""

from uuid import uuid4

import pytest

from dtvp.knowledge.journal import CommitUncertain, Journal
from dtvp.knowledge.workspace import load_sections
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import assessment, setup, target, url, workspace

app = knowledge_app


def prepared(client, bom):
    project, _ = setup(client, bom, versions=("7.1.1", "7.1.2"))
    response, identifier, submitted = assessment(client, project, versions=("7.1.1", "7.1.2"))
    assert response.status_code == 201, response.text
    versions = {version: workspace(client, project, version) for version in ("7.1.1", "7.1.2")}
    items = []
    for version, value in versions.items():
        row = next(
            row
            for row in value["items"]
            if row["context_id"] == submitted["targets"][0]["context_id"]
            and row["vulnerability_id"] == submitted["targets"][0]["vulnerability_id"]
        )
        items.append(
            {
                "target": target(row, version),
                "assessment_id": identifier,
                "assessment_revision": row["coverage"]["assessment"]["revision"],
            }
        )
    login(client, "reviewer")
    return project, {
        "request_id": str(uuid4()),
        "expected_versions": {version: value["state"] for version, value in versions.items()},
        "items": items,
        "action": "approve",
        "rationale": "Independent exact-target batch review",
    }


def preview(client, project, data, **params):
    response = client.post(url(project, "/reviews/bulk/preview"), json=data, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_preview_full_counts_selected_only_one_version_and_idempotent_replay(analyst, app, bom):
    project, data = prepared(analyst, bom)
    before = app.state.knowledge.head()
    first = preview(analyst, project, data, offset=0, limit=1)
    assert first["statistics"]["ready"] == first["total"] == 2
    assert len(first["items"]) == 1 and first["next_offset"] == 1
    assert app.state.knowledge.head() == before
    selected = first["items"][0]
    request = {**data, "preview_digest": first["preview_digest"], "selected": [selected["item_id"]]}
    response = analyst.post(url(project, "/reviews/bulk/apply"), json=request)
    assert response.status_code == 201, response.text
    receipt = response.json()
    assert (
        len(receipt["updates"]) == 1
        and receipt["updates"][0]["ref"]["name"] == selected["target"]["version"]
    )
    for version, parent in data["expected_versions"].items():
        current = workspace(analyst, project, version)
        assert current["statistics"]["approved"] == int(version == selected["target"]["version"])
        after = load_sections(app.state.knowledge, current["state"])
        old = load_sections(app.state.knowledge, parent)
        assert (
            after["vulnerabilities"] == old["vulnerabilities"]
            and after["scoring"] == old["scoring"]
        )
    replay = analyst.post(url(project, "/reviews/bulk/apply"), json=request)
    assert replay.status_code == 201 and replay.json()["publication"] == receipt["publication"]
    changed = analyst.post(
        url(project, "/reviews/bulk/apply"), json={**request, "rationale": "different"}
    )
    assert changed.status_code == 409


def test_author_and_project_permissions_exclude_without_any_review(analyst, app, bom):
    project, data = prepared(analyst, bom)
    login(analyst)
    result = preview(analyst, project, data)
    assert result["statistics"]["by_reason"] == {"self_authored": 2}
    request = {
        **data,
        "preview_digest": result["preview_digest"],
        "selected": [result["items"][0]["item_id"]],
    }
    before = app.state.knowledge.head()
    assert analyst.post(url(project, "/reviews/bulk/apply"), json=request).status_code == 404
    assert app.state.knowledge.head() == before
    login(analyst, "operations")
    assert analyst.post(url(project, "/reviews/bulk/preview"), json=data).status_code == 404


def test_unknown_selection_and_stale_plan_never_partially_apply(analyst, app, bom):
    project, data = prepared(analyst, bom)
    result = preview(analyst, project, data)
    request = {
        **data,
        "preview_digest": result["preview_digest"],
        "selected": [result["items"][0]["item_id"], "f" * 64],
    }
    before = app.state.knowledge.head()
    assert analyst.post(url(project, "/reviews/bulk/apply"), json=request).status_code == 409
    assert app.state.knowledge.head() == before
    selected = [row["item_id"] for row in result["items"]]
    applied = analyst.post(
        url(project, "/reviews/bulk/apply"), json={**request, "selected": selected}
    )
    assert applied.status_code == 201, applied.text
    stale = analyst.post(
        url(project, "/reviews/bulk/apply"),
        json={**request, "request_id": str(uuid4()), "selected": selected},
    )
    assert stale.status_code == 409
    fresh = {
        **data,
        "request_id": str(uuid4()),
        "expected_versions": {
            version: workspace(analyst, project, version)["state"]
            for version in data["expected_versions"]
        },
    }
    assert preview(analyst, project, fresh)["statistics"]["by_reason"] == {
        "already_reviewed_current": 2
    }


@pytest.mark.parametrize("failure", ["projection", "uncertain"])
def test_retry_after_commit_does_not_revalidate_stale_plan_or_publish_twice(
    analyst, app, bom, monkeypatch, failure
):
    project, data = prepared(analyst, bom)
    result = preview(analyst, project, data)
    request = {
        **data,
        "preview_digest": result["preview_digest"],
        "selected": [row["item_id"] for row in result["items"]],
    }
    if failure == "projection":
        from dtvp import api_knowledge

        native = api_knowledge.catch_up

        def broken(*args, **kwargs):
            raise OSError("Projection offline")

        monkeypatch.setattr(api_knowledge, "catch_up", broken)
    else:
        native = Journal.publish

        def uncertain(self, **kwargs):
            receipt = native(self, **kwargs)
            raise CommitUncertain(receipt[0])

        monkeypatch.setattr(Journal, "publish", uncertain)
    first = analyst.post(url(project, "/reviews/bulk/apply"), json=request)
    assert first.status_code == (202 if failure == "projection" else 503), first.text
    before = app.state.knowledge.head()
    if failure == "projection":
        monkeypatch.setattr(api_knowledge, "catch_up", native)
    else:
        monkeypatch.setattr(Journal, "publish", native)
    retry = analyst.post(url(project, "/reviews/bulk/apply"), json=request)
    assert retry.status_code == 201, retry.text
    assert retry.json()["publication"] == first.json()["publication"]
    assert app.state.knowledge.head() == before


def test_current_responsible_team_authority_is_required_even_with_project_approval_role(
    analyst, app, bom
):
    from tests.test_knowledge_ownership import apply_policy

    project, data = prepared(analyst, bom)
    login(analyst, "administrator")
    teams = {row["name"]: row["id"] for row in analyst.get("/api/v2/workspaces").json()}
    apply_policy(
        analyst,
        project,
        [{"selector": "*", "team_id": teams["Operations"]}],
        request_id="reassigned-bulk-review",
    )
    data["expected_versions"] = {
        version: workspace(analyst, project, version)["state"]
        for version in data["expected_versions"]
    }
    login(analyst, "reviewer")
    result = preview(analyst, project, data)
    assert result["statistics"]["by_reason"] == {"missing_authority": 2}
    request = {
        **data,
        "preview_digest": result["preview_digest"],
        "selected": [result["items"][0]["item_id"]],
    }
    before = app.state.knowledge.head()
    denied = analyst.post(url(project, "/reviews/bulk/apply"), json=request)
    assert denied.status_code == 409, denied.text
    assert app.state.knowledge.head() == before
