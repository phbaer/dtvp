"""Real authorized HTTP ranking remains bounded, pinned and non-publishing."""

import copy

import pytest

from dtvp.api_cpe_ranking import MAX_BODY, RankingInput
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def setup(analyst, bom):
    project = product(analyst)
    sbom = copy.deepcopy(bom)
    sbom["components"][0].update({"purl": "pkg:npm/foo@1", "version": "1"})
    state = imported(analyst, project, "ranking", body(sbom))
    path = f"/api/v3/projects/{project}/states/{state}/cpe/rank"
    data = {
        "component_ref": sbom["components"][0]["bom-ref"],
        "records": [
            {
                "cpeName": "cpe:2.3:a:a:foo:*:*:*:*:*:node.js:*:*",
                "source": "offline-catalog",
                "refs": [{"ref": "https://npmjs.com/package/foo"}],
            }
        ],
    }
    return project, state, path, data


def test_reader_ranking_preserves_heads_objects_and_full_digest_across_pages(analyst, app, bom):
    project, state, path, data = setup(analyst, bom)
    login(analyst, "viewer")
    journal = app.state.knowledge
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    result = analyst.post(path, json=data)
    assert result.status_code == 200, result.text
    assert result.json()["inventory_state"] == state and result.json()["committed"] is False
    report = result.json()["report"]
    assert report["counts"] == {"supplied": 1, "candidates": 1, "rejected": 0}
    assert report["selection"] is None and report["policy_proposal"]["candidates"] == []
    assert (
        analyst.post(path, json={**data, "offset": 1, "limit": 1}).json()["report"][
            "content_digest"
        ]
        == report["content_digest"]
    )
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))
    login(analyst, "operations")
    assert analyst.post(path, json=data).status_code == 404


def test_exact_component_committed_scope_policy_scope_and_input_validation(analyst, app, bom):
    project, state, path, data = setup(analyst, bom)
    assert analyst.post(path, json={**data, "component_ref": "missing"}).status_code == 404
    sections = {
        name: {
            key: app.state.knowledge.load(sha)
            for key, sha in app.state.knowledge.records(state, name).items()
        }
        for name in app.state.knowledge.state(state).sections
    }
    orphan = app.state.knowledge.snapshot(
        project_id=project,
        version="orphan",
        actor_id="test",
        reason="Unpublished",
        sections=sections,
        parents=[state],
    )
    assert analyst.post(path.replace(state, orphan), json=data).status_code == 404
    assert analyst.post(path, json={**data, "policy": state}).status_code == 404
    assert (
        analyst.post(
            path,
            json={**data, "records": [{"cpeName": "bad", "source": "x", "deprecated": "false"}]},
        ).status_code
        == 422
    )
    assert (
        analyst.post(path, json={**data, "records": []}).json()["report"]["ambiguity"]
        == "no_candidate"
    )
    login(analyst, "administrator")
    policy_body = {
        "request_id": "ranking-policy",
        "expected": None,
        "catalog": [
            {"purl": "pkg:npm/foo", "cpe": data["records"][0]["cpeName"], "source": "reviewed-map"}
        ],
        "rules": {},
    }
    result = analyst.put(f"/api/v3/projects/{project}/cpe", json=policy_body)
    assert result.status_code == 201, result.text
    policy = result.json()["updates"][0]["target"]
    result = analyst.post(path, json={**data, "policy": policy})
    assert result.status_code == 200 and result.json()["policy_state"] == policy
    assert result.json()["report"]["policy_proposal"]["candidates"]


def test_oversized_body_rejected_before_decoding_and_unauthorized_before_body(
    analyst, app, bom, monkeypatch
):
    _, _, path, _ = setup(analyst, bom)

    def fail(*args, **kwargs):
        pytest.fail("Oversized JSON must not be decoded/validated")

    monkeypatch.setattr(RankingInput, "model_validate", fail)
    payload = b"x" * (MAX_BODY + 1)
    assert (
        analyst.post(
            path, content=payload, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )
    login(analyst, "operations")
    assert (
        analyst.post(
            path, content=payload, headers={"Content-Type": "application/json"}
        ).status_code
        == 404
    )


def test_assembled_part_root_and_retained_policy_are_explicitly_available(analyst, app, bom):
    from dtvp.knowledge.assembly import namespaced_ref
    from tests.test_knowledge_assembly import assembly, publish, selection, source_import

    project = product(analyst)
    sbom = copy.deepcopy(bom)
    sbom["metadata"]["component"].update({"purl": "pkg:npm/foo@1", "version": "1"})
    part = source_import(analyst, project, "package", sbom)
    state = publish(analyst, project, assembly([selection("package", part)]))
    root_ref = namespaced_ref("package", sbom["metadata"]["component"]["bom-ref"])
    path = f"/api/v3/projects/{project}/states/{state}/cpe/rank"
    data = {
        "component_ref": root_ref,
        "records": [
            {
                "cpeName": "cpe:/a:vendor:foo:1",
                "source": "offline",
                "refs": [{"ref": "https://npmjs.com/package/foo"}],
            }
        ],
    }
    result = analyst.post(path, json=data)
    assert result.status_code == 200, result.text
    assert result.json()["report"]["counts"]["candidates"] == 1
    assert result.json()["policy_selection"] == "current_configuration"
    login(analyst, "administrator")
    policy = {"request_id": "old", "expected": None, "catalog": [], "rules": {}}
    old = analyst.put(f"/api/v3/projects/{project}/cpe", json=policy).json()["updates"][0]["target"]
    assert (
        analyst.put(
            f"/api/v3/projects/{project}/cpe", json={**policy, "request_id": "new", "expected": old}
        ).status_code
        == 201
    )
    result = analyst.post(path, json={**data, "policy": old})
    assert result.status_code == 200 and result.json()["policy_state"] == old
    assert result.json()["policy_selection"] == "explicit_retained"


def test_alias_cycle_is_a_validation_error_and_nested_malformed_json_is_bounded(analyst, app, bom):
    project, _, path, data = setup(analyst, bom)
    login(analyst, "administrator")
    rules = {
        "pkg:npm/foo": {"target_purl": "pkg:npm/bar", "source": "test"},
        "pkg:npm/bar": {"target_purl": "pkg:npm/foo", "source": "test"},
    }
    assert (
        analyst.put(
            f"/api/v3/projects/{project}/cpe",
            json={"request_id": "cyclic", "expected": None, "catalog": [], "rules": rules},
        ).status_code
        == 201
    )
    result = analyst.post(path, json=data)
    assert result.status_code == 422 and "Cyclic" in result.json()["detail"]
    assert (
        analyst.post(
            path, content=b"[" * 2000 + b"]" * 2000, headers={"Content-Type": "application/json"}
        ).status_code
        == 422
    )
