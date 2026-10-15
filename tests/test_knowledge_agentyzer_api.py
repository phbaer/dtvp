"""Code-analysis input export never submits a job or grants build verification."""

from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_analysis_recipe_requires_qualified_source_and_preserves_pinned_scope(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    original = workspace(analyst, project_id)
    row = original["items"][0]
    payload = {"context_id": row["context_id"], "vulnerability_id": row["vulnerability_id"]}
    path = url(project_id, f"/states/{original['state']}/agentyzer-input")
    unknown = analyst.post(path, json=payload)
    assert unknown.status_code == 200, unknown.text
    assert unknown.json()["ready_to_submit"] is False
    assert unknown.json()["request"] is None
    current = imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            bom,
            request_id="qualified",
            expected=original["state"],
            build_number=2,
            context={
                "analysis_source": {"repository_name": "pipeline-repo", "source_commit": "A" * 40}
            },
        ),
    )
    publication = app.state.knowledge.head()
    recipe = analyst.post(url(project_id, f"/states/{current}/agentyzer-input"), json=payload)
    assert recipe.status_code == 200, recipe.text
    recipe = recipe.json()
    assert recipe["ready_to_submit"] is True
    assert recipe["request"]["source_commit"] == "a" * 40
    assert recipe["request"]["component_name"] == "pipeline-repo"
    assert recipe["receipt"]["state"] == current
    assert recipe["receipt"]["context_id"] == row["context_id"]
    assert recipe["coverage"]["repository_authorization"] == "not_checked"
    assert recipe["coverage"]["artifact_binding_verified"] is False
    assert workspace(analyst, project_id)["state"] == current
    assert app.state.knowledge.head() == publication
