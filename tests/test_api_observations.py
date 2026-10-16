"""Observation HTTP intake keeps inventory changes explicit and currently authorized."""

import json

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product
from tests.test_knowledge_observations import COLLECTION, bom, inputs
from tests.test_workflow_api import url

app = knowledge_app


def setup(client):
    project = product(client)
    state = imported(client, project, "1", body(bom(), source="build", context=COLLECTION))
    return project, state, url(project, "/versions/1")


def observation_data(project, state, **changes):
    return inputs(state, **changes).model_dump(mode="json")


def test_import_preview_adoption_replay_paging_and_viewer_access(analyst, app):
    project, state, path = setup(analyst)
    value = observation_data(project, state)
    result = analyst.post(path + "/observation-imports", json=value)
    assert result.status_code == 201, result.text
    observation = result.json()["updates"][0]["target"]
    assert analyst.get(path + "/inventory").json()["state"] == state
    rows = analyst.get(path + "/observation-sources", params={"limit": 1}).json()
    assert rows["total"] == 1 and rows["next_offset"] is None
    assert rows["items"][0]["baseline"]["role"] == "observation"
    assert analyst.get(path + "/observation-sources", params={"offset": 1}).json()["items"] == []
    assert analyst.get(path + "/observation-sources", params={"limit": 201}).status_code == 422
    selection = {
        "request_id": "select",
        "expected": state,
        "expected_configuration": None,
        "sources": [
            {
                "source": "scanner",
                "state": observation,
                "accepted_components": ["scan-extra"],
                "accepted_relationships": [
                    {"from": "scan-app", "to": "scan-extra", "kind": "DEPENDS_ON"}
                ],
                "reason": "CI owner confirms extra library",
            }
        ],
    }
    preview = analyst.post(path + "/observation-selection/preview", json=selection)
    assert preview.status_code == 200, preview.text
    assert preview.json()["reports"][0]["bounded_sample"]
    applied = selection | {"preview_digest": preview.json()["preview_digest"]}
    final = analyst.post(path + "/observation-selection", json=applied)
    assert final.status_code == 201, final.text
    assert (
        analyst.post(path + "/observation-selection", json=applied).json()["publication"]
        == final.json()["publication"]
    )
    retained = analyst.get(path + "/observation-selection").json()
    assert retained["selection"]["sources"]
    assert (
        analyst.post(path + "/observation-imports", json=value).json()["publication"]
        == result.json()["publication"]
    )
    assert analyst.post(path + "/observation-selection/preview", json=selection).status_code == 409
    login(analyst, "viewer")
    assert analyst.get(path + "/observation-sources").status_code == 200
    assert analyst.post(path + "/observation-imports", json=value).status_code == 404
    assert analyst.post(path + "/observation-selection", json=applied).status_code == 404
    assert analyst.get(url("missing", "/versions/1/observation-sources")).status_code == 404


def test_original_file_intake_digest_declaration_and_bad_scope(analyst, app):
    project, state, path = setup(analyst)
    value = observation_data(project, state)
    sbom = value.pop("sbom")
    original = json.dumps(sbom, indent=2).encode()
    result = analyst.post(
        path + "/observation-files",
        data={"metadata": json.dumps(value)},
        files={"file": ("binary-scan.cdx.json", original, "application/json")},
    )
    assert result.status_code == 201, result.text
    state_sha = result.json()["updates"][0]["target"]
    assert (
        app.state.knowledge.objects.read(
            app.state.knowledge.load(
                app.state.knowledge.records(state_sha, "inventory")["baseline"]
            )["artifact_sha"]
        )
        == original
    )
    bad = observation_data(
        project, state, request_id="wrong-product", expected=state_sha, build_number=2
    )
    bad["subject_declaration"] = {
        "product_id": "other",
        "version": "1",
        "subject_id": "runtime",
        "build_id": "1",
        "authority_sbom_sha256": "a" * 64,
        "observation_sbom_sha256": "b" * 64,
    }
    assert analyst.post(path + "/observation-imports", json=bad).status_code == 422
    old = app.state.settings.max_upload_bytes
    app.state.settings.max_upload_bytes = 16
    try:
        assert (
            analyst.post(
                path + "/observation-files",
                data={"metadata": json.dumps(value)},
                files={"file": ("scan.json", original)},
            ).status_code
            == 413
        )
    finally:
        app.state.settings.max_upload_bytes = old


def test_part_observation_qualifies_only_selected_tree_and_removal_restores_assembly(analyst, app):
    from dtvp.knowledge.assembly import namespaced_ref
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.knowledge.workspace import load_sections
    from tests.test_knowledge_assembly import assembly, publish, selection, source_import

    project = product(analyst)
    part_a = source_import(
        analyst, project, "engine", bom(), version="1", source="build", context=COLLECTION
    )
    part_b = source_import(
        analyst, project, "service", bom(), version="1", source="build", context=COLLECTION
    )
    state = publish(
        analyst,
        project,
        assembly([selection("engine", part_a), selection("service", part_b)]),
        version="1",
    )
    path = url(project, "/versions/1")
    value = observation_data(project, state, part_id="engine")
    response = analyst.post(path + "/observation-imports", json=value)
    assert response.status_code == 201, response.text
    observation = response.json()["updates"][0]["target"]
    payload = {
        "request_id": "select-part",
        "expected": state,
        "expected_configuration": None,
        "sources": [
            {
                "source": "scanner",
                "part_id": "engine",
                "state": observation,
                "accepted_components": ["scan-extra"],
                "accepted_relationships": [
                    {"from": "scan-app", "to": "scan-extra", "kind": "DEPENDS_ON"}
                ],
                "reason": "Explicit engine-only adoption",
            }
        ],
    }
    preview = analyst.post(path + "/observation-selection/preview", json=payload)
    assert preview.status_code == 200, preview.text
    result = analyst.post(
        path + "/observation-selection",
        json=payload | {"preview_digest": preview.json()["preview_digest"]},
    )
    assert result.status_code == 201, result.text
    merged = result.json()["updates"][0]["target"]
    journal = app.state.knowledge
    sections = load_sections(journal, merged)
    asserted = sections["inventory"]["observation_assertions"]["components"]
    assert namespaced_ref("engine", "lib") in asserted
    assert namespaced_ref("service", "lib") not in asserted
    observed_claims = [
        claim
        for claim in sections["vulnerabilities"].values()
        if claim["source"] == "observation:scanner"
    ]
    assert {claim["ref"] for claim in observed_claims} == {namespaced_ref("engine", "lib")}
    service_components = {
        key: value
        for key, value in load_sections(journal, state)["inventory"].items()
        if value.get("dtvp_origin", {}).get("part_id") == "service"
    }
    assert {key: sections["inventory"][key] for key in service_components} == service_components
    sections["assessments"]["retained-part"] = {"historical": "part assessment"}
    with_decision = journal.snapshot(
        project_id=project,
        version="1",
        actor_id="test",
        reason="Historical assessment",
        sections=sections,
        parents=[merged],
    )
    journal.publish(
        request_id="retained-part-assessment",
        fingerprint=with_decision,
        updates=[
            Update(ref=Ref(project_id=project, name="1"), expected=merged, target=with_decision)
        ],
    )
    removal = {
        "request_id": "remove-part-view",
        "expected": with_decision,
        "expected_configuration": None,
        "sources": [],
        "removal_reason": "Drop obsolete binary observation",
    }
    preview = analyst.post(path + "/observation-selection/preview", json=removal)
    assert preview.status_code == 200, preview.text
    result = analyst.post(
        path + "/observation-selection",
        json=removal | {"preview_digest": preview.json()["preview_digest"]},
    )
    assert result.status_code == 201, result.text
    final = load_sections(journal, result.json()["updates"][0]["target"])
    assert final["assessments"] == sections["assessments"]
    assert final["inventory"]["assembly"] == load_sections(journal, state)["inventory"]["assembly"]
    assert (
        final["inventory"]["dependencies"]
        == load_sections(journal, state)["inventory"]["dependencies"]
    )
    assert "observation_assertions" not in final["inventory"]
