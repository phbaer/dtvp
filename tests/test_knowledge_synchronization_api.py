"""Preview never rebases inventory or extends independent review scope."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import reviewed, setup, url, workspace

app = knowledge_app


def test_native_preview_has_no_side_effects_or_implicit_approval(analyst, bom):
    project_id, _ = setup(analyst, bom)
    reviewed(analyst, project_id)
    source = workspace(analyst, project_id)["state"]
    login(analyst)
    target = imported(
        analyst, project_id, "7.1.2", body(bom, request_id="parallel", predecessor=source)
    )
    assert workspace(analyst, project_id, version="7.1.2")["statistics"]["approved"] == 0
    path = url(project_id, "/synchronization/preview")
    response = analyst.post(path, json={"source": source, "target": target})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["mode"] == "two_state"
    assert result["apply_supported"] is False
    assert result["provenance"]["software_integration_verified"] is False
    assert result["items"]
    assert all(item["requires_new_target_review"] for item in result["items"])
    assert workspace(analyst, project_id)["state"] == source
    assert workspace(analyst, project_id, version="7.1.2")["state"] == target
    based = analyst.post(path, json={"source": source, "target": target, "basis": source})
    assert based.status_code == 200, based.text
    assert based.json()["mode"] == "three_way"
    assert analyst.post(path, json={"source": source, "target": "a" * 64}).status_code == 422
