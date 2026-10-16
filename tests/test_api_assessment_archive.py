"""Authorized archive publication is explicit, atomic, replayable and history preserving."""

import copy
from uuid import uuid4

import pytest
from sqlalchemy import select

from dtvp.knowledge.journal import CommitUncertain, Journal
from dtvp.models import Membership, User
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def seed(client, bom):
    project, _ = setup(client, bom)
    row, review = reviewed(client, project)
    prior = workspace(client, project)["state"]
    original = client.get(url(project, f"/states/{prior}/bundle")).content
    login(client, "administrator")
    changed = copy.deepcopy(bom)
    changed["vulnerabilities"] = []
    imported(
        client,
        project,
        "7.1.1",
        body(changed, request_id="vulns-removed", expected=prior, build_number=2),
    )
    endpoint = url(project, "/maintenance/assessment-archive")
    plan = client.post(endpoint + "/preview").json()
    request = {
        "request_id": str(uuid4()),
        "plan_hash": plan["plan_hash"],
        "project_refs": plan["project_refs"],
        "assessment_ids": [review["assessment_id"]],
        "reason": "No occurrence remains; preserve exact historical evidence",
    }
    return project, endpoint, request, prior, original


def test_atomic_archive_project_readable_provenance_and_historical_bundle_unchanged(
    analyst, app, bom
):
    project, endpoint, data, prior, original = seed(analyst, bom)
    response = analyst.post(endpoint + "/apply", json=data)
    assert response.status_code == 201, response.text
    assert len(response.json()["updates"]) == 2
    current = workspace(analyst, project)
    sections = app.state.knowledge.records(current["state"], "assessments")
    assert not sections and not app.state.knowledge.records(current["state"], "reviews")
    login(analyst, "viewer")
    assert analyst.get(endpoint).json()["total"] == 1
    detail = analyst.get(endpoint + "/" + data["assessment_ids"][0]).json()
    assert detail["current_approval"] is False and detail["revision_total"] == 1
    assert any(item["record"].get("status") == "approved" for item in detail["records"])
    assert analyst.get(url(project, f"/states/{prior}/bundle")).content == original
    assert analyst.post(endpoint + "/preview").status_code in {403, 404}
    assert analyst.post(endpoint + "/apply", json=data).status_code in {403, 404}
    login(analyst, "operations")
    assert analyst.get(endpoint).status_code == 404
    assert analyst.get(endpoint + "/" + data["assessment_ids"][0]).status_code == 404


@pytest.mark.parametrize("failure", ["projection", "uncertain"])
def test_exact_retry_current_authority_before_receipt_and_no_second_publication(
    analyst, app, bom, monkeypatch, failure
):
    project, endpoint, data, _, _ = seed(analyst, bom)
    if failure == "projection":
        from dtvp import api_knowledge

        native = api_knowledge.catch_up

        def broken(*args, **kwargs):
            raise OSError("Projection temporarily unavailable")

        monkeypatch.setattr(api_knowledge, "catch_up", broken)
    else:
        native = Journal.publish

        def uncertain(self, **kwargs):
            receipt = native(self, **kwargs)
            raise CommitUncertain(receipt[0])

        monkeypatch.setattr(Journal, "publish", uncertain)
    result = analyst.post(endpoint + "/apply", json=data)
    assert result.status_code == (202 if failure == "projection" else 503), result.text
    committed = app.state.knowledge.head()
    if failure == "projection":
        monkeypatch.setattr(api_knowledge, "catch_up", native)
    else:
        monkeypatch.setattr(Journal, "publish", native)
    with app.state.sessions() as db:
        user = db.scalar(select(User).where(User.subject == "administrator"))
        memberships = list(db.scalars(select(Membership).where(Membership.user_id == user.id)))
        original_roles = {member.workspace_id: list(member.roles) for member in memberships}
        for member in memberships:
            member.roles = ["viewer"]
        db.commit()
    # Same actor/credential, now revoked manager authority: receipt is not an authorization bypass.
    assert analyst.post(endpoint + "/apply", json=data).status_code in {403, 404}
    with app.state.sessions() as db:
        for member in db.scalars(select(Membership).where(Membership.user_id == user.id)):
            member.roles = original_roles[member.workspace_id]
        db.commit()
    retry = analyst.post(endpoint + "/apply", json=data)
    assert retry.status_code == 201, retry.text
    assert retry.json()["publication"] == result.json()["publication"]
    assert app.state.knowledge.head() == committed
    assert (
        analyst.post(endpoint + "/apply", json={**data, "reason": "different"}).status_code == 409
    )


def test_changed_references_validation_and_bounded_body_do_not_archive(analyst, app, bom):
    project, endpoint, data, prior, _ = seed(analyst, bom)
    assert (
        analyst.post(
            url(project, "/tags"),
            json={"name": "protected-late", "state": prior, "request_id": "late-tag"},
        ).status_code
        == 201
    )
    before = app.state.knowledge.head()
    assert analyst.post(endpoint + "/apply", json=data).status_code == 409
    assert analyst.post(endpoint + "/apply", json={**data, "reason": "  "}).status_code == 422
    assert (
        analyst.post(
            endpoint + "/apply", json={**data, "assessment_ids": data["assessment_ids"] * 2}
        ).status_code
        == 422
    )
    assert (
        analyst.post(
            endpoint + "/apply",
            content=b"x" * (2 * 1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert app.state.knowledge.head() == before
