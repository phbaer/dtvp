from tests.conftest import login


def test_bulk_preview_atomic_conflicts_duplicates_and_independent_approval(analyst):
    findings = analyst.get("/api/v2/findings").json()["items"]
    for finding in findings:
        assert (
            analyst.post(
                f"/api/v2/findings/{finding['id']}/decisions",
                json={
                    "expected_version": finding["state_version"],
                    "state": "affected",
                    "rationale": "Exposure verified",
                },
            ).status_code
            == 201
        )
    login(analyst, "reviewer")
    rows = analyst.get("/api/v2/findings").json()["items"]
    items = [
        {
            "finding_id": row["id"],
            "expected_version": row["state_version"],
            "decision_id": row["latest_decision"]["id"],
        }
        for row in rows
    ]
    preview = analyst.post("/api/v2/approvals/preview", json={"items": items})
    assert preview.status_code == 200 and preview.json()["count"] == 2
    assert (
        analyst.post("/api/v2/approvals/preview", json={"items": [items[0], items[0]]}).status_code
        == 422
    )
    # Change the second item so the first would have been approved before conflict.
    login(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{items[1]['finding_id']}/evidence",
            json={
                "source": "test",
                "external_id": "change",
                "assertion": {"kind": "scope", "summary": "Changed exposure"},
            },
        ).status_code
        == 201
    )
    login(analyst, "reviewer")
    assert (
        analyst.post(
            "/api/v2/approvals/apply",
            json={"items": items, "preview_digest": preview.json()["preview_digest"]},
        ).status_code
        == 409
    )
    assert all(
        row["approval"] is None
        for row in [analyst.get(f"/api/v2/findings/{item['finding_id']}").json() for item in items]
    )
    login(analyst)
    changed = analyst.get(f"/api/v2/findings/{items[1]['finding_id']}").json()
    assert (
        analyst.post(
            f"/api/v2/findings/{changed['id']}/decisions",
            json={
                "expected_version": changed["state_version"],
                "state": "affected",
                "rationale": "Changed evidence reviewed",
            },
        ).status_code
        == 201
    )
    login(analyst, "reviewer")
    rows = analyst.get("/api/v2/findings").json()["items"]
    items = [
        {
            "finding_id": row["id"],
            "expected_version": row["state_version"],
            "decision_id": row["latest_decision"]["id"],
        }
        for row in rows
    ]
    preview = analyst.post("/api/v2/approvals/preview", json={"items": items}).json()
    assert (
        analyst.post(
            "/api/v2/approvals/apply",
            json={"items": items, "preview_digest": preview["preview_digest"]},
        ).json()["approved"]
        == 2
    )
    assert all(
        row["lifecycle"] == "approved" for row in analyst.get("/api/v2/findings").json()["items"]
    )
