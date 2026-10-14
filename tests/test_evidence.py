from dtvp.models import now


def test_unchanged_refresh_preserves_decision_revision_and_keeps_history(analyst):
    finding = analyst.get("/api/v2/findings").json()["items"][0]
    body = {
        "source": "test-matcher",
        "external_id": "first",
        "assertion": {
            "kind": "match",
            "method": "exact-coordinate",
            "checked_at": now().isoformat(),
            "advisory": {"id": finding["identifier"], "ratings": []},
        },
    }
    first = analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=body)
    assert first.status_code == 201
    current = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    body["external_id"] = "refresh"
    body["assertion"]["checked_at"] = now().isoformat()
    assert analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=body).status_code == 201
    refreshed = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert refreshed["evidence_revision"] == current["evidence_revision"]
    assert len(refreshed["evidence"]) == 2
    body["external_id"] = "changed"
    body["assertion"]["advisory"]["description"] = "New affected scope information"
    analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=body)
    assert (
        analyst.get(f"/api/v2/findings/{finding['id']}").json()["evidence_revision"]
        == current["evidence_revision"] + 1
    )


def test_malformed_advisory_rejected_before_publication(analyst):
    finding = analyst.get("/api/v2/findings").json()["items"][0]
    result = analyst.post(
        f"/api/v2/findings/{finding['id']}/evidence",
        json={
            "source": "invalid",
            "external_id": "bad",
            "assertion": {"advisory": {"ratings": "invalid"}},
        },
    )
    assert result.status_code == 422
    assert analyst.get(f"/api/v2/findings/{finding['id']}").status_code == 200
