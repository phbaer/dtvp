from tests.conftest import login
from tests.test_rescoring import BASE, VECTOR, target

BODY = {
    "kind": "manual",
    "base_vector": BASE,
    "vector": VECTOR,
    "rationale": "Verified deployment context.",
}


def assess(client, persona="analyst", state="not_affected"):
    login(client, persona)
    finding = target(client)
    response = client.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={
            "expected_version": finding["state_version"],
            "state": state,
            "justification": "protected_at_runtime" if state == "not_affected" else None,
            "rationale": f"Evidence examined by {persona}.",
            "workspace_id": finding["review_workspace_id"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def approve(client, decision, persona="reviewer"):
    login(client, persona)
    finding = target(client)
    response = client.post(
        f"/api/v2/findings/{finding['id']}/approvals",
        json={"expected_version": finding["state_version"], "decision_id": decision},
    )
    assert response.status_code == 200, response.text


def publish(client):
    login(client, "coordinator")
    finding = target(client)
    payload = {"expected_version": finding["state_version"], "rescoring": BODY}
    preview = client.post(f"/api/v2/findings/{finding['id']}/rescoring/preview", json=payload)
    if preview.status_code != 200:
        return preview
    payload["rescoring"] = BODY | {"preview_digest": preview.json()["preview_digest"]}
    return client.post(f"/api/v2/findings/{finding['id']}/rescoring", json=payload)


def test_coordinator_permissions_and_per_vulnerability_gate(analyst):
    finding = target(analyst)
    for persona in ["analyst", "reviewer", "administrator", "viewer"]:
        login(analyst, persona)
        payload = {"expected_version": finding["state_version"], "rescoring": BODY}
        for path in ["rescoring/preview", "rescoring"]:
            assert (
                analyst.post(f"/api/v2/findings/{finding['id']}/{path}", json=payload).status_code
                == 404
            )
    assert publish(analyst).status_code == 409
    decision = assess(analyst)
    assert publish(analyst).status_code == 409
    approve(analyst, decision)
    assert target(analyst)["effective_score"] == 9.8
    assert publish(analyst).status_code == 201  # Another vulnerability remains open.
    scored = target(analyst)
    assert scored["effective_score"] == 0 and scored["original_score"] == 9.8
    login(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/decisions",
            json={
                "expected_version": scored["state_version"],
                "state": "affected",
                "rationale": "New assessment",
                "rescoring": BODY,
            },
        ).status_code
        == 422
    )
    replacement = assess(analyst)
    assert target(analyst)["adopted_rescoring"] is None
    assert len(target(analyst)["rescoring_history"]) == 1
    assert publish(analyst).status_code == 409
    approve(analyst, replacement)
    assert publish(analyst).status_code == 201


def test_independent_required_team_reviews_and_assignment_invalidation(analyst, release_id):
    login(analyst, "administrator")
    teams = {w["name"]: w["id"] for w in analyst.get("/api/v2/me").json()["workspaces"]}
    project = next(p for p in analyst.get("/api/v2/projects").json() if p["name"] == "Demo Gateway")
    assert (
        analyst.put(
            f"/api/v2/projects/{project['id']}/sharing",
            json={
                "workspace_id": teams["Operations"],
                "capabilities": ["read", "assess", "approve", "evidence"],
            },
        ).status_code
        == 200
    )
    finding = target(analyst)
    assert (
        analyst.put(
            f"/api/v2/findings/{finding['id']}/review-teams",
            json={
                "expected_version": finding["state_version"],
                "workspace_ids": list(teams.values()),
            },
        ).status_code
        == 200
    )
    platform = assess(analyst, state="affected")
    operations = assess(analyst, "operations")
    login(analyst, "reviewer")
    current = target(analyst)
    assert current["latest_decision"]["id"] == platform
    assert analyst.post(
        f"/api/v2/findings/{current['id']}/approvals",
        json={"expected_version": current["state_version"], "decision_id": operations},
    ).status_code in (403, 404)
    approve(analyst, platform)
    assert publish(analyst).status_code == 409
    approve(analyst, operations, "operations-reviewer")
    assert target(analyst)["review_coverage"]["ready"]
    assert target(analyst)["review_coverage"]["state"] == "affected"
    assert publish(analyst).status_code == 201
    snapshot = analyst.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    vex = analyst.get(f"/api/v2/snapshots/{snapshot['id']}/exports/vex").json()
    statement = next(v for v in vex["vulnerabilities"] if v["id"] == finding["identifier"])
    assert statement["analysis"]["state"] == "exploitable"
    assert (
        "analyst" in statement["analysis"]["detail"]
        and "operations" in statement["analysis"]["detail"]
    )
    login(analyst, "administrator")
    assert (
        analyst.put(
            f"/api/v2/projects/{project['id']}/sharing",
            json={"workspace_id": teams["Operations"], "capabilities": ["read"]},
        ).status_code
        == 200
    )
    assert target(analyst)["adopted_rescoring"] is None
    assert any(r["status"] == "blocked_access" for r in target(analyst)["review_coverage"]["teams"])
    assert (
        analyst.put(
            f"/api/v2/projects/{project['id']}/sharing",
            json={
                "workspace_id": teams["Operations"],
                "capabilities": ["read", "assess", "approve", "evidence"],
            },
        ).status_code
        == 200
    )
    assert target(analyst)["adopted_rescoring"] is None
    assert publish(analyst).status_code == 409
    login(analyst, "administrator")
    current = target(analyst)
    assert (
        analyst.put(
            f"/api/v2/findings/{current['id']}/review-teams",
            json={
                "expected_version": current["state_version"],
                "workspace_ids": [teams["Platform"]],
            },
        ).status_code
        == 200
    )
    assert target(analyst)["adopted_rescoring"] is None
    assert not target(analyst)["review_coverage"]["ready"]


def test_restored_rule_configuration_cannot_resurrect_a_previous_score(analyst):
    import copy

    from tests.test_rescoring import reviewed, submit

    finding = reviewed(analyst)
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    initial = analyst.get(f"/api/v2/projects/{project}/rescore-policy").json()
    body = {
        "kind": "rule",
        "base_vector": BASE,
        "policy_digest": initial["digest"],
        "rationale": "Verified team context",
    }
    assert submit(analyst, finding, body).status_code == 201
    login(analyst, "administrator")
    changed = copy.deepcopy(initial["config"])
    changed["transitions"][0]["actions"]["3.1"]["MAC"] = "L"
    for version, config in [(0, changed), (1, initial["config"])]:
        assert (
            analyst.put(
                f"/api/v2/projects/{project}/rescore-policy",
                json={"expected_version": version, "config": config},
            ).status_code
            == 200
        )
        assert target(analyst)["adopted_rescoring"] is None
        assert target(analyst)["review_coverage"]["ready"]
