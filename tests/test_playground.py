from dtvp.playground import seed
from tests.conftest import login


def test_playground_teams_have_findings_and_restart_preserves_assessments(client, app):
    login(client, "operations")
    finding = client.get("/api/v2/findings").json()["items"][0]
    assert finding["identifier"] == "CVE-2099-20003"
    response = client.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={
            "expected_version": finding["state_version"],
            "state": "affected",
            "rationale": "Demo review retained across startup.",
        },
    )
    assert response.status_code == 201
    before = client.get(f"/api/v2/findings/{finding['id']}").json()
    with app.state.sessions.begin() as db:
        seed(db, app.state.artifacts)
        seed(db, app.state.artifacts)
    after = client.get(f"/api/v2/findings/{finding['id']}").json()
    assert after == before
    assert len(client.get("/api/v2/findings").json()["items"]) == 1
    login(client)
    assert len(client.get("/api/v2/findings").json()["items"]) == 2
