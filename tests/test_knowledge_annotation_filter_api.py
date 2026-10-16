"""Authored context uses the same full filtered scope in queue and portfolio."""

from copy import deepcopy

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_current_and_stale_annotations_filter_full_counts_without_reclassifying_findings(
    analyst, bom
):
    project, _ = setup(analyst, bom)
    initial = workspace(analyst, project)
    ref = initial["items"][0]["component"]["bom-ref"]
    login(analyst, "administrator")
    response = analyst.put(
        url(project, "/versions/7.1.1/metadata"),
        json={
            "request_id": "queue-context",
            "expected": initial["state"],
            "expected_revision": None,
            "component_ref": ref,
            "annotations": {
                "cybersecurity": {"criticality": "critical", "exposure": "external"},
                "support": {"status": "unsupported"},
            },
            "provenance": {"source": "deployment-owner"},
            "rationale": "Recorded deployment context, no applicability judgment",
        },
    )
    assert response.status_code == 201, response.text
    filters = {
        "criticality": "critical",
        "exposure": "external",
        "support_status": "unsupported",
        "metadata_status": "current",
    }
    selected = workspace(analyst, project, **filters)
    assert selected["items"]
    assert all(row["component"]["bom-ref"] == ref for row in selected["items"])
    assert all(row["coverage"]["status"] == "unassessed" for row in selected["items"])
    page = workspace(analyst, project, limit=1, **filters)
    assert page["statistics"] == selected["statistics"]
    portfolio = analyst.get(url(project, "/portfolio"), params=filters)
    assert portfolio.status_code == 200, portfolio.text
    assert portfolio.json()["statistics"]["context_findings"] == len(selected["items"])
    current = workspace(analyst, project)
    changed = deepcopy(bom)
    component = next(c for c in changed["components"] if c["bom-ref"] == ref)
    component["version"] = "changed-identity"
    imported(
        analyst,
        project,
        "7.1.1",
        body(changed, request_id="identity-change", build_number=2, expected=current["state"]),
    )
    assert workspace(analyst, project, **filters)["items"] == []
    stale = workspace(analyst, project, metadata_status="stale", criticality="unknown")
    assert len(stale["items"]) == len(selected["items"])
    assert all(
        row["curated_metadata"]["payload"]["annotations"]["cybersecurity"]["criticality"]
        == "critical"
        for row in stale["items"]
    )
    assert (
        analyst.get(
            url(project, "/versions/7.1.1/workspace"), params={"criticality": "safe"}
        ).status_code
        == 422
    )
    for field in ("criticality", "exposure", "support_status", "metadata_status"):
        assert analyst.get(url(project, "/portfolio"), params={field: "invalid"}).status_code == 422
    login(analyst, "operations")
    assert analyst.get(url(project, "/portfolio"), params=filters).status_code == 404
