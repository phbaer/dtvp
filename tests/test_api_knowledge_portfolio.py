"""Actual HTTP portfolio statistics require project access and pin all selected heads."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def portfolio(client, project, **params):
    response = client.get(url(project, "/portfolio"), params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_multiversion_counts_shared_decision_and_filtered_full_workload(analyst, bom):
    project, teams = setup(analyst, bom, versions=("7.1.1", "7.1.2"))
    reviewed(analyst, project, versions=("7.1.1", "7.1.2"))
    result = portfolio(analyst, project)
    assert set(result["heads"]) == {"7.1.1", "7.1.2"}
    stats = result["statistics"]
    assert stats["context_findings"] == 4
    assert stats["unique_vulnerabilities"] == 2
    assert stats["unique_latest_logical_assessments"] == 1
    assert stats["unique_approved_logical_assessments"] == 1
    assert stats["reviewed_covered_targets"] == 2
    assert stats["required_context_review_workload"]["remaining_targets"] == 2
    filtered = portfolio(
        analyst, project, lifecycle="approved", team_id=teams["Platform"], team_review="approved"
    )
    assert filtered["statistics"]["context_findings"] == 2
    assert filtered["team_labels"] == {teams["Platform"]: "Platform"}
    assert all(value["context_findings"] == 1 for value in filtered["by_version"].values())
    assert portfolio(analyst, project, q="no-match")["statistics"]["context_findings"] == 0


def test_selected_versions_expected_digest_and_read_only_head_replay(analyst, app, bom):
    project, _ = setup(analyst, bom, versions=("7.1.1", "7.1.2"))
    journal = app.state.knowledge
    before = journal.head()
    result = portfolio(analyst, project, version=["7.1.2"])
    assert set(result["heads"]) == {"7.1.2"}
    assert (
        portfolio(analyst, project, version=["7.1.2"], expected_heads=result["heads_digest"])
        == result
    )
    assert journal.head() == before
    stale = analyst.get(url(project, "/portfolio"), params={"expected_heads": "f" * 64})
    assert stale.status_code == 409, stale.text
    login(analyst, "administrator")
    imported(analyst, project, "7.1.3", body(bom, request_id="new-version"))
    assert (
        analyst.get(
            url(project, "/portfolio"), params={"expected_heads": result["heads_digest"]}
        ).status_code
        == 409
    )
    assert (
        portfolio(analyst, project, version=["7.1.2"], expected_heads=result["heads_digest"])
        == result
    )


def test_project_read_denial_precedes_head_or_team_information(analyst, bom):
    project, _ = setup(analyst, bom)
    login(analyst, "operations")
    denied = analyst.get(url(project, "/portfolio"), params={"version": "missing"})
    assert denied.status_code == 404, denied.text
    assert "heads" not in denied.text and "team_labels" not in denied.text
    assert analyst.get(url("missing-project", "/portfolio")).status_code == 404


def test_filter_values_version_selection_and_digest_are_validated(analyst, bom):
    project, _ = setup(analyst, bom)
    for params in (
        {"version": "missing"},
        {"version": ["7.1.1"] * 201},
        {"source_severity": "urgent"},
        {"lifecycle": "anything"},
        {"expected_heads": "invalid"},
        {"q": "x" * 501},
    ):
        response = analyst.get(url(project, "/portfolio"), params=params)
        assert response.status_code == 422, response.text
    filtered = portfolio(
        analyst,
        project,
        source_severity="critical",
        provider="pipeline/main",
        dependency="known_direct",
    )
    assert filtered["statistics"]["context_findings"] == 1
    assert len(workspace(analyst, project, source_severity="critical")["items"]) == 1
