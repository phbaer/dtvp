from dtvp.models import now
from tests.conftest import login


def test_statistics_counts_full_scope_states_sharing_and_owners(analyst, release_id):
    stats = analyst.get("/api/v2/statistics").json()
    assert stats["totals"]["findings"] == stats["totals"]["unique_vulnerabilities"] == 2
    assert stats["workflow"] == {"open": 2}
    assert stats["base_severity"] == {"critical": 1, "high": 1}
    finding = analyst.get("/api/v2/findings").json()["items"][0]
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/decisions",
            json={
                "expected_version": finding["state_version"],
                "state": "affected",
                "rationale": "Exposure confirmed",
            },
        ).status_code
        == 201
    )
    stats = analyst.get("/api/v2/statistics").json()
    assert stats["workflow"] == {"ready": 1, "open": 1}
    login(analyst, "reviewer")
    detail = analyst.get(f"/api/v2/findings/{finding['id']}").json()
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/approvals",
            json={
                "expected_version": detail["state_version"],
                "decision_id": detail["decisions"][0]["id"],
            },
        ).status_code
        == 200
    )
    assert analyst.get("/api/v2/statistics?lifecycle=approved").json()["totals"]["findings"] == 1
    login(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/evidence",
            json={
                "source": "test",
                "external_id": "changed",
                "assertion": {"kind": "scope", "timestamp": now().isoformat()},
            },
        ).status_code
        == 201
    )
    assert analyst.get("/api/v2/statistics").json()["workflow"]["needs_revalidation"] == 1
    login(analyst, "administrator")
    projects = analyst.get("/api/v2/projects").json()
    platform = next(p for p in projects if p["name"] == "Demo Gateway")
    teams = analyst.get("/api/v2/me").json()["workspaces"]
    operations = next(w["id"] for w in teams if w["name"] == "Operations")
    total = analyst.get("/api/v2/statistics").json()["totals"]["findings"]
    assert (
        analyst.put(
            f"/api/v2/projects/{platform['id']}/sharing",
            json={"workspace_id": operations, "capabilities": ["read"]},
        ).status_code
        == 200
    )
    assert analyst.get("/api/v2/statistics").json()["totals"]["findings"] == total
    login(analyst, "operations")
    shared = analyst.get("/api/v2/statistics").json()
    assert len(shared["teams"]) == 2
    assert sum(team["total"] for team in shared["teams"]) == total
    login(analyst, "administrator")
    assert (
        analyst.put(
            f"/api/v2/projects/{platform['id']}/sharing",
            json={"workspace_id": operations, "capabilities": []},
        ).status_code
        == 200
    )
    login(analyst, "operations")
    assert all(
        team["name"] != "Platform" for team in analyst.get("/api/v2/statistics").json()["teams"]
    )
    assert analyst.get(f"/api/v2/statistics?project_id={platform['id']}").status_code == 404


def test_statistics_is_not_limited_to_the_first_page(analyst):
    login(analyst, "administrator")
    assert (
        analyst.post(
            "/api/v2/playground/scale", json={"projects": 30, "findings_per_project": 20}
        ).status_code
        == 200
    )
    login(analyst)
    stats = analyst.get("/api/v2/statistics?project_limit=5").json()
    assert stats["totals"]["findings"] == 602
    assert stats["totals"]["unique_vulnerabilities"] == 22
    assert stats["workflow"]["open"] == 602
    assert len(stats["project_page"]["items"]) == 5 and stats["project_page"]["next_cursor"] == 5
    assert stats["owners"][0]["total"] == 602
    assert (
        analyst.get("/api/v2/statistics?q=Scale%20product%200030").json()["totals"]["findings"]
        == 20
    )


def test_owner_drilldown_matches_exact_counts(analyst, release_id):
    components = analyst.get(f"/api/v2/releases/{release_id}/components").json()["items"]
    for index, owner in enumerate(["Platform", "Platform services"]):
        component = components[index]
        assert (
            analyst.put(
                f"/api/v2/components/{component['id']}/metadata",
                json={
                    "expected_version": component["metadata_version"],
                    "metadata": {"owner": owner},
                },
            ).status_code
            == 200
        )
    stats = analyst.get("/api/v2/statistics").json()
    for owner in stats["owners"]:
        query = {"owner": owner["name"], "owner_match": "exact"}
        count = analyst.get("/api/v2/statistics", params=query).json()["totals"]["findings"]
        assert count == owner["total"]
        assert len(analyst.get("/api/v2/findings", params=query).json()["items"]) == count
