"""Queue and portfolio evidence predicates share full filtered counts."""

import pytest

from dtvp.knowledge.workspace import load_workspace
from tests.test_api_knowledge_agentyzer_results import endpoint, prepare
from tests.test_knowledge_agentyzer import qualified
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import url, workspace

app = knowledge_app


def test_received_current_becomes_historical_only_after_new_source_without_rewriting_past(
    analyst, app, bom
):
    project, selected, payload = prepare(analyst, bom)
    response = analyst.post(endpoint(project), json=payload)
    assert response.status_code == 201, response.text
    previous = workspace(analyst, project)["state"]
    imported(
        analyst,
        project,
        "7.1.1",
        body(
            bom,
            request_id="changed-source",
            expected=previous,
            build_number=2,
            context=qualified(commit="b" * 40),
        ),
    )
    historical = workspace(analyst, project, agentyzer_evidence="historical_only", limit=1)
    assert [row["id"] for row in historical["items"]] == [selected["id"]]
    assert historical["statistics"]["context_findings"] == 1
    assert not workspace(analyst, project, agentyzer_evidence="current")["items"]
    assert not workspace(analyst, project, agentyzer_evidence="eligible")["items"]
    assert (
        analyst.get(
            url(project, "/versions/7.1.1/workspace"),
            params={"expected": previous, "agentyzer_evidence": "eligible"},
        ).status_code
        == 409
    )
    pinned = load_workspace(
        app.state.knowledge, previous, filters={"agentyzer_evidence": "eligible"}
    )
    assert [row["id"] for row in pinned["items"]] == [selected["id"]]


def test_received_evidence_filters_apply_before_queue_paging_and_all_portfolio_counts(
    analyst, app, bom
):
    project, selected, payload = prepare(analyst, bom)
    initial = workspace(analyst, project)
    total = initial["statistics"]["context_findings"]
    assert total > 1
    imported = analyst.post(endpoint(project), json=payload)
    assert imported.status_code == 201, imported.text
    before = app.state.knowledge.head()
    for value in ("current", "eligible"):
        result = workspace(
            analyst, project, agentyzer_evidence=value, vscorer_evidence="missing", limit=1
        )
        assert result["statistics"]["context_findings"] == 1
        assert [row["id"] for row in result["items"]] == [selected["id"]]
        assert result["next_offset"] is None
        assert not result["items"][0]["coverage"]["approved"]
        for path, params in (
            (url(project, "/portfolio"), {}),
            ("/api/v3/portfolio", {"project": project, "limit": 1}),
        ):
            response = analyst.get(
                path, params=params | {"agentyzer_evidence": value, "vscorer_evidence": "missing"}
            )
            assert response.status_code == 200, response.text
            assert response.json()["statistics"]["context_findings"] == 1
    missing = workspace(analyst, project, agentyzer_evidence="missing", limit=1)
    assert missing["statistics"]["context_findings"] == total - 1
    assert all(row["id"] != selected["id"] for row in missing["items"])
    assert (
        workspace(analyst, project, agentyzer_evidence="historical_only")["statistics"][
            "context_findings"
        ]
        == 0
    )
    assert app.state.knowledge.head() == before


@pytest.mark.parametrize("field", ["agentyzer_evidence", "vscorer_evidence"])
def test_received_filter_values_are_typed_on_each_api(analyst, bom, field):
    project, _, _ = prepare(analyst, bom)
    for path in (
        url(project, "/versions/7.1.1/workspace"),
        url(project, "/portfolio"),
        "/api/v3/portfolio",
    ):
        response = analyst.get(path, params={field: "approved"})
        assert response.status_code == 422, response.text
