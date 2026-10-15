from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def test_retention_plan_is_management_only_read_only_and_pinned(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    path = url(project_id, "/maintenance/retention-preview")
    assert analyst.get(path).status_code == 404
    reviewed(analyst, project_id)
    before = workspace(analyst, project_id)["state"]
    login(analyst, "administrator")
    journal = app.state.knowledge
    publication = journal.head()
    result = analyst.get(path, params={"limit": 1})
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["statistics"]["revision_statuses"]["active"] > 0
    assert result["branch_heads"]["7.1.1"] == before
    assert journal.head() == publication
    assert analyst.get(path, params={"expected": result["plan_hash"]}).status_code == 200
    assert analyst.get(path, params={"expected": "a" * 64}).status_code == 409
