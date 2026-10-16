"""Ownership editor retains v1 selectors and applies only explicit full-policy previews."""

from uuid import uuid4

from dtvp.models import Workspace
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url

app = knowledge_app


def editor(client, project):
    response = client.get(url(project, "/ownership/editor"))
    assert response.status_code == 200, response.text
    return response.json()


def encode(client, project, **fields):
    return client.post(url(project, "/ownership/selectors/encode"), json=fields)


def policy(client, project, rules=None):
    state = editor(client, project)
    return {
        "request_id": str(uuid4()),
        "expected_policy": state["policy_state"],
        "expected_versions": state["versions"],
        "rules": rules if rules is not None else state["policy"]["rules"],
        "context_roots": state["policy"]["context_roots"],
    }


def preview(client, project, data):
    response = client.post(url(project, "/ownership/editor/preview"), json=data)
    assert response.status_code == 200, response.text
    return response.json()


def test_selector_builder_preserves_namespace_case_purl_and_wildcard_semantics(analyst, bom):
    project, _ = setup(analyst, bom)
    rows = [
        (
            {"name": "Lib", "namespace_mode": "exact", "namespace": "acme", "case_sensitive": True},
            "cs::acme:Lib",
        ),
        ({"name": "Lib", "namespace_mode": "known_empty"}, "nogroup::Lib"),
        ({"name": "Lib", "namespace_mode": "absent_or_unknown"}, "Lib"),
        ({"mode": "purl", "purl": "pkg:generic/acme/lib@1"}, "purl::pkg:generic/acme/lib@1"),
        ({"mode": "fallback"}, "*"),
    ]
    for fields, raw in rows:
        response = encode(analyst, project, **fields)
        assert response.status_code == 200, response.text
        assert response.json()["raw"] == raw and response.json()["representable"]
    assert encode(analyst, project, name="acme/Lib").status_code == 422
    assert encode(analyst, project, mode="purl", purl="invalid").status_code == 422


def test_pure_preview_full_policy_apply_cas_and_policy_replay(analyst, app, bom):
    project, teams = setup(analyst, bom, versions=("7.1.1", "7.1.2"))
    login(analyst, "administrator")
    data = policy(
        analyst,
        project,
        [
            {
                "selector": "*",
                "team_id": teams["Operations"],
                "aliases": ["display-only"],
                "versions": None,
            }
        ],
    )
    before = app.state.knowledge.head()
    objects = set(app.state.knowledge.objects.root.rglob("*"))
    checked = preview(analyst, project, data)
    assert app.state.knowledge.head() == before
    assert set(app.state.knowledge.objects.root.rglob("*")) == objects
    assert set(checked["versions"]) == {"7.1.1", "7.1.2"}
    assert all(item["changed_contexts"] > 0 for item in checked["versions"].values())
    response = analyst.post(
        url(project, "/ownership/editor/apply"),
        json={**data, "preview_digest": checked["preview_digest"]},
    )
    assert response.status_code == 201, response.text
    replay = analyst.post(
        url(project, "/ownership/editor/apply"), json={**data, "preview_digest": "f" * 64}
    )
    assert (
        replay.status_code == 201 and replay.json()["publication"] == response.json()["publication"]
    )
    changed = {
        **data,
        "rules": [{**data["rules"][0], "aliases": ["changed"]}],
        "preview_digest": checked["preview_digest"],
    }
    assert analyst.post(url(project, "/ownership/editor/apply"), json=changed).status_code == 409
    assert analyst.post(url(project, "/ownership/editor/preview"), json=data).status_code == 409


def test_lossless_unknown_selectors_roots_and_scoped_rule_versions(analyst, bom):
    project, teams = setup(analyst, bom, versions=("7.1.1", "7.1.2"))
    login(analyst, "administrator")
    data = policy(
        analyst,
        project,
        [
            {
                "selector": "strange::literal",
                "team_id": teams["Platform"],
                "aliases": ["label"],
                "versions": ["7.1.1"],
            }
        ],
    )
    data["context_roots"] = {"7.1.1": ["gateway"]}
    checked = preview(analyst, project, data)
    response = analyst.post(
        url(project, "/ownership/editor/apply"),
        json={**data, "preview_digest": checked["preview_digest"]},
    )
    assert response.status_code == 201, response.text
    state = editor(analyst, project)
    assert state["policy"] == {"rules": data["rules"], "context_roots": data["context_roots"]}
    assert not state["selectors"][0]["representable"]
    assert state["selectors"][0]["raw"] == "strange::literal"


def test_readers_get_only_mapped_or_membership_team_names_and_cannot_edit(analyst, app, bom):
    project, teams = setup(analyst, bom)
    with app.state.sessions() as db:
        hidden = Workspace(name="Secret unmapped team")
        db.add(hidden)
        db.commit()
        hidden_id = hidden.id
    read = editor(analyst, project)
    assert read["capabilities"] == [] and hidden_id not in {
        item["id"] for item in read["available_teams"]
    }
    data = policy(analyst, project)
    assert analyst.post(url(project, "/ownership/editor/preview"), json=data).status_code == 404
    login(analyst, "administrator")
    assert hidden_id in {item["id"] for item in editor(analyst, project)["available_teams"]}
    login(analyst, "operations")
    assert analyst.get(url(project, "/ownership/editor")).status_code == 404


def test_new_branch_invalidates_preview_and_unknown_team_cannot_apply(analyst, bom):
    project, _ = setup(analyst, bom)
    login(analyst, "administrator")
    data = policy(analyst, project)
    checked = preview(analyst, project, data)
    imported(analyst, project, "7.1.2", body(bom, request_id="parallel-new-version"))
    assert (
        analyst.post(
            url(project, "/ownership/editor/apply"),
            json={**data, "preview_digest": checked["preview_digest"]},
        ).status_code
        == 409
    )
    data = policy(analyst, project, [{"selector": "*", "team_id": "does-not-exist"}])
    assert analyst.post(url(project, "/ownership/editor/preview"), json=data).status_code == 422
