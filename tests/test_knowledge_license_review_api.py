"""Organization license judgment requires dedicated roles and independent review."""

from sqlalchemy import select

from dtvp.models import Membership, User
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def worklist(client, project_id, state):
    response = client.get(url(project_id, f"/states/{state}/license-worklist"))
    assert response.status_code == 200, response.text
    return response.json()


def test_license_roles_independent_pins_pending_and_material_revalidation(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    before = workspace(analyst, project_id)
    row = before["items"][0]
    component = row["context"]["component_ref"]
    payload = {
        "request_id": "license-submit",
        "expected": before["state"],
        "expected_revision": None,
        "component_ref": component,
        "concluded_expression": "LicenseRef-Reviewed-Terms",
        "disposition": "restricted",
        "obligations": ["Include attribution"],
        "distribution": "Binary distribution",
        "modification": "Unmodified",
        "linking": "Dynamic",
        "rationale": "Reviewed supplier terms and intended distribution.",
        "evidence": [{"reference": "LEGAL-42"}],
        "provenance": {"source": "License specialist"},
    }
    prefix = url(project_id, "/versions/7.1.1/licenses")
    assert analyst.post(prefix + "/submit", json=payload).status_code == 404
    login(analyst, "administrator")
    assert analyst.post(prefix + "/submit", json=payload).status_code == 404
    login(analyst, "license-analyst")
    response = analyst.post(prefix + "/submit", json=payload)
    assert response.status_code == 201, response.text
    assert analyst.post(prefix + "/submit", json=payload).json() == response.json()
    submitted = workspace(analyst, project_id)["state"]
    selected = next(
        item
        for item in worklist(analyst, project_id, submitted)["items"]
        if item["component_ref"] == component
    )
    revision = selected["license_review"]["assessment"]["revision"]
    review = {
        "request_id": "license-review",
        "expected": submitted,
        "component_ref": component,
        "revision": revision,
        "action": "approve",
        "rationale": "Independent review of exact usage and terms.",
    }
    assert analyst.post(prefix + "/reviews", json=review).status_code == 404
    with app.state.sessions.begin() as db:
        user = db.scalar(
            select(User).where(User.issuer == "playground", User.subject == "license-analyst")
        )
        membership = db.scalar(select(Membership).where(Membership.user_id == user.id))
        membership.roles = ["license_analyst", "license_reviewer"]
    assert analyst.post(prefix + "/reviews", json=review).status_code == 403
    login(analyst, "license-reviewer")
    approved = analyst.post(prefix + "/reviews", json=review)
    assert approved.status_code == 201, approved.text
    approved_state = workspace(analyst, project_id)["state"]
    accepted = next(
        item
        for item in worklist(analyst, project_id, approved_state)["items"]
        if item["component_ref"] == component
    )
    assert accepted["clearance"] == "organization_reviewed"
    assert accepted["license_review"]["approved"] is True
    login(analyst, "license-analyst")
    draft = analyst.post(
        prefix + "/draft",
        json={
            **payload,
            "request_id": "new-draft",
            "expected": approved_state,
            "expected_revision": revision,
            "rationale": "Pending additional usage review.",
            "disposition": "allowed",
        },
    )
    assert draft.status_code == 201, draft.text
    pending_state = workspace(analyst, project_id)["state"]
    pending = next(
        item
        for item in worklist(analyst, project_id, pending_state)["items"]
        if item["component_ref"] == component
    )
    assert pending["license_review"]["approved"] is True
    assert pending["license_review"]["pending"] is True
    filtered = analyst.get(
        url(project_id, f"/states/{pending_state}/license-worklist"),
        params={"review_status": "pending", "approved_disposition": "restricted", "limit": 1},
    ).json()
    assert filtered["total"] == filtered["statistics"]["components"] == 1
    assert filtered["items"][0]["component_ref"] == component
    assert analyst.get(
        url(project_id, f"/states/{pending_state}/license-worklist"),
        params={"approved_disposition": "allowed"},
    ).json()["total"] == 0
    login(analyst)
    bom["components"][0]["licenses"] = [{"expression": "LicenseRef-Changed-Supplier-Terms"}]
    changed = imported(
        analyst,
        project_id,
        "7.1.1",
        body(bom, request_id="license-source-change", expected=pending_state, build_number=2),
    )
    stale = next(
        item
        for item in worklist(analyst, project_id, changed)["items"]
        if item["component_ref"] == component
    )
    assert stale["license_review"]["approved"] is False
    assert stale["license_review"]["status"] == "stale"
    assert (
        next(
            item
            for item in worklist(analyst, project_id, approved_state)["items"]
            if item["component_ref"] == component
        )["license_review"]["approved"]
        is True
    )
