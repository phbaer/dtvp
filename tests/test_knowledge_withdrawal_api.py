"""Withdrawal edits current selection, preserving authored history and release tags."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_knowledge_ownership import apply_policy
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def test_withdraw_restore_preserves_assessments_tags_and_authority(analyst, app, bom):
    project_id, teams = setup(analyst, bom)
    reviewed(analyst, project_id)
    before = workspace(analyst, project_id)
    assert before["statistics"]["approved"] > 0
    login(analyst, "administrator")
    assert (
        analyst.post(
            url(project_id, "/tags"),
            json={
                "request_id": "old-release",
                "name": "old-release",
                "state": before["state"],
            },
        ).status_code
        == 201
    )
    payload = {
        "request_id": "withdraw",
        "expected": before["state"],
        "reason": "Incorrect producer SBOM; retain evidence pending correction.",
    }
    path = url(project_id, "/versions/7.1.1/withdrawal")
    response = analyst.post(path, json=payload)
    assert response.status_code == 201, response.text
    assert analyst.post(path, json=payload).json() == response.json()
    withdrawn = workspace(analyst, project_id)
    assert withdrawn["items"] == []
    assert withdrawn["baseline_status"] == "withdrawn"
    assert withdrawn["statistics"]["retained_absent_assessments"] > 0
    retained_path = url(project_id, f"/states/{withdrawn['state']}/retained-assessments")
    retained = analyst.get(retained_path, params={"team_id": teams["Platform"], "limit": 1})
    assert retained.status_code == 200, retained.text
    assert retained.json()["total"] > 0
    assert retained.json()["items"][0]["availability"] == "absent"
    assert retained.json()["items"][0]["assessment"]["payload"]["rationale"]
    assert analyst.get(retained_path, params={"team_id": "unrelated"}).json()["items"] == []
    assert (
        analyst.post(
            url(project_id, "/tags"),
            json={
                "request_id": "bad-release",
                "name": "bad-release",
                "state": withdrawn["state"],
            },
        ).status_code
        == 409
    )
    # Policy changes must still work while a branch has no active selection.
    apply_policy(
        analyst,
        project_id,
        [{"selector": "*", "team_id": teams["Platform"]}],
        request_id="policy-after-withdrawal",
    )
    current = workspace(analyst, project_id)
    restored = imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            bom,
            request_id="corrected-build",
            expected=current["state"],
            build_number=2,
        ),
    )
    assert (
        workspace(analyst, project_id)["statistics"]["approved"] == before["statistics"]["approved"]
    )
    assert restored != before["state"]
    refs = analyst.get(url(project_id, "/refs")).json()["items"]
    assert next(ref["state"] for ref in refs if ref["name"] == "old-release") == before["state"]
    invalid = analyst.post(path, json={**payload, "request_id": "stale-withdraw"})
    assert invalid.status_code == 409
