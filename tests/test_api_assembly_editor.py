"""Guided assembly remains an explicit pinned structural publication."""

from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product
from tests.test_knowledge_assembly import assembly, path, selection, source_import

app = knowledge_app


def endpoint(project_id, suffix):
    return path(project_id, "empty") + "/assembly-" + suffix


def seed(client, bom):
    project_id = product(client)
    state = source_import(client, project_id, "application", bom, version="empty")
    return project_id, state


def test_bootstrap_pure_preview_and_exact_receipt_replay(analyst, app, bom):
    project_id, state = seed(analyst, bom)
    target = analyst.get(
        f"/api/v1/projects/{project_id}/assembly-target", params={"version": "empty"}
    )
    assert target.status_code == 200, target.text
    assert target.json()["previous_kind"] == "none"
    choices = analyst.get(
        f"/api/v1/projects/{project_id}/assembly-parts",
        params={"version": "empty", "q": "app", "limit": 1},
    ).json()
    assert choices["items"][0]["state"] == state
    payload = assembly([selection("application", state)], coherence={"status": "unverified"})
    refs = app.state.knowledge.references()
    objects = set(app.state.knowledge.objects.root.rglob("*"))
    preview = analyst.post(endpoint(project_id, "preview"), json=payload)
    assert preview.status_code == 200, preview.text
    assert preview.json()["coherence"]["status"] == "unverified"
    assert preview.json()["coverage_verification"] == "not_verified"
    assert app.state.knowledge.references() == refs
    assert set(app.state.knowledge.objects.root.rglob("*")) == objects
    applied = analyst.post(
        endpoint(project_id, "apply"),
        json={"assembly": payload, "preview_digest": preview.json()["preview_digest"]},
    )
    assert applied.status_code == 201, applied.text
    replay = analyst.post(
        endpoint(project_id, "apply"), json={"assembly": payload, "preview_digest": "0" * 64}
    )
    assert replay.status_code == 201 and replay.json() == applied.json()


def test_selected_historical_pin_survives_source_head_advance(analyst, app, bom):
    project_id, state = seed(analyst, bom)
    payload = assembly([selection("application", state)])
    preview = analyst.post(endpoint(project_id, "preview"), json=payload).json()
    source_import(
        analyst,
        project_id,
        "application",
        bom,
        version="empty",
        expected=state,
        build_number=2,
        request_id="source-update",
    )
    response = analyst.post(
        endpoint(project_id, "apply"),
        json={"assembly": payload, "preview_digest": preview["preview_digest"]},
    )
    assert response.status_code == 201, response.text
    head = response.json()["updates"][0]["target"]
    manifest = app.state.knowledge.load(app.state.knowledge.records(head, "inventory")["assembly"])
    assert manifest["parts"][0]["state"] == state


def test_bad_admission_digest_and_changed_product_head_do_not_publish(analyst, app, bom):
    project_id, state = seed(analyst, bom)
    payload = assembly([selection("application", state)])
    preview = analyst.post(endpoint(project_id, "preview"), json=payload).json()
    response = analyst.post(
        endpoint(project_id, "apply"), json={"assembly": payload, "preview_digest": "0" * 64}
    )
    assert response.status_code == 409
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/assembly-target", params={"version": "empty"}
        ).json()["state"]
        is None
    )
    other = {**payload, "request_id": "competing"}
    assert analyst.post(path(project_id, "empty") + "/assembly", json=other).status_code == 201
    response = analyst.post(
        endpoint(project_id, "apply"),
        json={"assembly": payload, "preview_digest": preview["preview_digest"]},
    )
    assert response.status_code == 409


def test_missing_required_is_explicit_and_previous_withdrawal_requires_reason(analyst, app, bom):
    project_id, state = seed(analyst, bom)
    payload = assembly([selection("application", state)])
    first = analyst.post(path(project_id, "empty") + "/assembly", json=payload).json()["updates"][
        0
    ]["target"]
    missing = assembly(
        [selection("application", None)],
        request_id="missing",
        expected=first,
        coherence={"status": "unverified"},
    )
    assert analyst.post(endpoint(project_id, "preview"), json=missing).status_code == 409
    missing.update(
        withdrawn_parts=["application"], withdrawal_reason="Producer withdrew this input"
    )
    preview = analyst.post(endpoint(project_id, "preview"), json=missing)
    assert preview.status_code == 200, preview.text
    assert preview.json()["readiness"] == "incomplete"
    assert preview.json()["missing_required_parts"] == ["application"]


def test_read_only_target_does_not_grant_assembly_and_foreign_parts_are_hidden(analyst, bom):
    from tests.conftest import login

    project_id, state = seed(analyst, bom)
    payload = assembly([selection("application", state)])
    login(analyst, "coordinator")
    target = analyst.get(
        f"/api/v1/projects/{project_id}/assembly-target", params={"version": "empty"}
    )
    assert target.status_code == 200 and target.json()["capabilities"] == []
    assert analyst.post(endpoint(project_id, "preview"), json=payload).status_code == 404
    login(analyst, "operations")
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/assembly-parts", params={"version": "empty"}
        ).status_code
        == 404
    )
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/assembly-target", params={"version": "empty"}
        ).status_code
        == 404
    )


def test_unknown_or_nonstate_predecessors_are_not_dereferenced(analyst, app, bom):
    project_id, state = seed(analyst, bom)
    journal = app.state.knowledge
    baseline = journal.load(journal.records(state, "inventory")["baseline"])
    before = journal.head()
    for predecessor in ("f" * 64, baseline["artifact_sha"]):
        response = analyst.get(
            f"/api/v1/projects/{project_id}/assembly-target",
            params={"version": "empty", "predecessor": predecessor},
        )
        assert response.status_code == 404, response.text
        payload = assembly([selection("application", state)], predecessor=predecessor)
        assert analyst.post(endpoint(project_id, "preview"), json=payload).status_code == 404
        assert (
            analyst.post(
                endpoint(project_id, "apply"),
                json={"assembly": payload, "preview_digest": "a" * 64},
            ).status_code
            == 404
        )
    assert journal.head() == before
