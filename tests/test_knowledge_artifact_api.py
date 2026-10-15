from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_workflow_api import url

app = knowledge_app


def test_download_requires_pinned_artifact_and_current_project_access(analyst, app, bom):
    project_id = product(analyst)
    state = imported(analyst, project_id, "7.1.1", body(bom))
    artifact = digest(canonical(bom))
    path = url(project_id, f"/states/{state}/artifacts/{artifact}")
    response = analyst.get(path)
    assert response.status_code == 200, response.text
    assert response.content == canonical(bom)
    assert response.headers["x-content-sha256"] == digest(response.content)
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    unrelated = app.state.knowledge.objects.put(b"Not retained by this state")
    assert analyst.get(url(project_id, f"/states/{state}/artifacts/{unrelated}")).status_code == 404
    foreign = app.state.knowledge.snapshot(
        project_id="other-product",
        version="1",
        actor_id="other",
        reason="Other",
        sections={key: {} for key in app.state.knowledge.state(state).sections},
        artifacts=[artifact],
    )
    assert (
        analyst.get(url(project_id, f"/states/{foreign}/artifacts/{artifact}")).status_code == 404
    )
    login(analyst, "operations")
    assert analyst.get(path).status_code == 404
