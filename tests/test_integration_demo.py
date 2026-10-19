"""Parallel nightly builds invalidate integration inputs without advancing other versions."""

from scripts.knowledge_integration_demo import VERSIONS, seed
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app


def test_cascade_demo_records_each_edge_and_rejects_stale_nightly_evidence(client):
    report = seed(client)
    assert report["synthetic"] and report["stale_integration_rejected"]
    assert len(report["events"]) == 2
    before, after = report["states_before_nightly"], report["states_after_nightly"]
    assert set(before) == set(after) == set(VERSIONS)
    assert before["7.2.0"] != after["7.2.0"]
    assert all(before[version] == after[version] for version in VERSIONS[:-1])
    prefix = f"/api/v1/projects/{report['project_id']}"
    for event in report["events"]:
        value = client.get(
            prefix + f"/states/{event['target_state']}/integration-events/{event['event_id']}"
        )
        assert value.status_code == 200, value.text
        assert value.json()["git_ancestry"]["status"] == "verified_commit_object_ancestry"
        assert value.json()["software_integration_verified"] is False
    for version in VERSIONS:
        response = client.get(prefix + f"/states/{after[version]}/bundle")
        assert response.status_code == 200, response.text
        bundle = response.json()
        assert all(
            not bundle[key]
            for key in ("retained_assessments", "retained_reviews", "retained_scoring")
        )
