"""Server filter scope is shared by queue statistics and bounded pages."""

from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_filters_apply_before_statistics_and_paging(analyst, bom):
    project_id, _ = setup(analyst, bom)
    full = workspace(analyst, project_id)
    assert len(full["items"]) > 1
    identifier = full["items"][0]["component"]["bom-ref"]
    filtered = workspace(analyst, project_id, component=identifier)
    first_page = workspace(analyst, project_id, component=identifier, limit=1)
    assert len(first_page["items"]) == 1
    assert first_page["statistics"]["context_findings"] == len(filtered["items"])
    assert all(identifier in row["component"]["bom-ref"] for row in filtered["items"])
    empty = workspace(analyst, project_id, provider="unobserved-provider")
    assert empty["items"] == []
    assert empty["statistics"]["context_findings"] == 0
    unknown = workspace(analyst, project_id, contextual_severity="unknown")
    assert len(unknown["items"]) == len(full["items"])
    assert workspace(analyst, project_id, contextual_severity="none")["items"] == []
    direct = workspace(analyst, project_id, dependency="direct")
    assert all(item["dependency_relation"] == "direct" for item in direct["items"])
    invalid = analyst.get(
        url(project_id, "/versions/7.1.1/workspace"), params={"source_severity": "invalid"}
    )
    assert invalid.status_code == 422
