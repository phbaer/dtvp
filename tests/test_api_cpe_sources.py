"""Real HTTP curated source workflow uses current project scope and exact retained bytes."""

import pytest

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_cpe_sources import arguments, dictionary, mappings
from tests.test_workflow_api import url

app = knowledge_app


def prepare(client):
    project = product(client)
    login(client, "administrator")
    return project, url(project, "/cpe/sources"), arguments()["data"].model_dump(mode="json")


def publish(client, path, data):
    preview = client.post(path + "/preview", json=data)
    assert preview.status_code == 200, preview.text
    applied = data | {"preview_digest": preview.json()["preview_digest"]}
    result = client.post(path + "/apply", json=applied)
    assert result.status_code == 201, result.text
    return result, applied


def test_offline_dictionary_history_artifacts_rank_and_exact_replay(analyst, app, bom):
    project, path, data = prepare(analyst)
    before = app.state.knowledge.head()
    proposed = analyst.post(path + "/preview", json=data)
    assert proposed.status_code == 200 and app.state.knowledge.head() == before
    result, applied = publish(analyst, path, data)
    state = result.json()["updates"][0]["target"]
    report = analyst.get(path + f"/{state}/dictionary")
    assert report.status_code == 200 and report.json()["total"] == 1
    original = analyst.get(path + f"/{state}/dictionary/artifact")
    assert original.status_code == 200 and original.content == dictionary()
    assert original.headers["x-content-sha256"] == data["artifact_sha256"]
    later = arguments(mappings(), expected=state, request_id="mapping", kind="mapping_history")[
        "data"
    ].model_dump(mode="json")
    csv_result, _ = publish(analyst, path, later)
    csv_state = csv_result.json()["updates"][0]["target"]
    assert analyst.get(path + f"/{csv_state}/mapping_history/artifact").content == mappings()
    inventory = imported(analyst, project, "test", body(bom))
    ranked = analyst.post(
        url(project, f"/states/{inventory}/cpe/rank-retained"),
        json={"component_ref": bom["components"][0]["bom-ref"], "policy": state},
    )
    assert ranked.status_code == 200, ranked.text
    assert ranked.json()["policy_state"] == state
    assert ranked.json()["report"]["selection"] is None
    repeated = analyst.post(path + "/apply", json=applied)
    assert repeated.status_code == 201
    assert repeated.json()["publication"] == result.json()["publication"]
    assert repeated.json()["updates"] == result.json()["updates"]
    login(analyst, "viewer")
    assert analyst.get(path + f"/{state}/dictionary/artifact").status_code == 200
    assert analyst.post(path + "/apply", json=applied).status_code == 404


@pytest.mark.parametrize("persona", ["analyst", "reviewer", "viewer"])
def test_current_manage_auth_before_json_decoding(analyst, persona):
    _, path, _ = prepare(analyst)
    login(analyst, persona)
    result = analyst.post(
        path + "/preview", content=b"not-json", headers={"content-type": "application/json"}
    )
    assert result.status_code == 404


def test_source_state_cross_project_oversize_and_digest_fail_closed(analyst, app):
    project, path, data = prepare(analyst)
    result, _ = publish(analyst, path, data)
    state = result.json()["updates"][0]["target"]
    assert (
        analyst.get(url("another-project", f"/cpe/sources/{state}/dictionary/artifact")).status_code
        == 404
    )
    wrong = data | {"request_id": "wrong-sha", "expected": state, "artifact_sha256": "0" * 64}
    assert analyst.post(path + "/preview", json=wrong).status_code == 422
    assert analyst.get(path + "/" + "0" * 64 + "/dictionary/artifact").status_code == 422
    old_limit = app.state.settings.max_upload_bytes
    app.state.settings.max_upload_bytes = 32
    try:
        assert analyst.post(path + "/preview", json=data).status_code == 413
    finally:
        app.state.settings.max_upload_bytes = old_limit


def test_retained_artifact_rechecks_current_reader_scope(analyst, app):
    from sqlalchemy import delete, select

    from dtvp.models import Membership, User

    _, path, data = prepare(analyst)
    result, _ = publish(analyst, path, data)
    state = result.json()["updates"][0]["target"]
    login(analyst, "viewer")
    assert analyst.get(path + f"/{state}/dictionary/artifact").status_code == 200
    with app.state.sessions.begin() as db:
        user = db.scalar(select(User).where(User.subject == "viewer"))
        assert user
        db.execute(delete(Membership).where(Membership.user_id == user.id))
    assert analyst.get(path + f"/{state}/dictionary/artifact").status_code == 404
