"""Pinned cross-part declarations survive HTTP previews, publication and retries."""

import copy

from dtvp.knowledge.journal import Ref
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product
from tests.test_knowledge_assembly import assembly, path, selection, source_import
from tests.test_knowledge_assembly_relationships import payload

app = knowledge_app


def seeded(client, bom):
    project = product(client)
    a = source_import(client, project, "application", bom)
    b = source_import(client, project, "container", bom)
    return project, payload(a, b)


def test_preview_apply_manifest_target_and_exact_replay_preserve_pinned_declarations(
    analyst, app, bom
):
    project, value = seeded(analyst, bom)
    prefix = path(project)
    before = app.state.knowledge.head()
    preview = analyst.post(prefix + "/assembly-preview", json=value)
    assert preview.status_code == 200, preview.text
    data = preview.json()
    assert data["input"]["cross_part_relationships"] == value["cross_part_relationships"]
    assert data["relationship_diagnostics"]["dependency_relations"] == 1
    assert app.state.knowledge.head() == before
    request = {"assembly": value, "preview_digest": data["preview_digest"]}
    applied = analyst.post(prefix + "/assembly-apply", json=request)
    assert applied.status_code == 201, applied.text
    target = analyst.get(
        f"/api/v1/projects/{project}/assembly-target", params={"version": "7.1.1"}
    ).json()
    assert target["cross_part_relationships"] == value["cross_part_relationships"]
    manifest = analyst.get(f"/api/v1/projects/{project}/states/{target['state']}/assembly").json()[
        "manifest"
    ]
    assert manifest["cross_part_relationships"] == value["cross_part_relationships"]
    assert analyst.post(prefix + "/assembly-apply", json=request).json() == applied.json()
    cleared = assembly(
        value["parts"],
        request_id="remove-mapping",
        expected=target["state"],
        relationship_change_reason="Relationship explicitly retired",
    )
    advanced = analyst.post(prefix + "/assembly", json=cleared)
    assert advanced.status_code == 201, advanced.text
    replay = analyst.post(prefix + "/assembly-apply", json=request)
    assert replay.status_code == 201, replay.text
    assert replay.json()["publication"] == applied.json()["publication"]
    assert replay.json()["updates"] == applied.json()["updates"]
    assert (
        app.state.knowledge.resolve(Ref(project_id=project, name="7.1.1"))
        == advanced.json()["updates"][0]["target"]
    )


def test_unknown_reference_stale_revision_and_tampered_preview_fail_closed(analyst, app, bom):
    project, value = seeded(analyst, bom)
    prefix = path(project)
    previous = app.state.knowledge.head()
    for field, invalid in (
        ("ref", "pkg:generic/no-identity-guess"),
        ("state", "0" * 64),
        ("part_id", "missing"),
    ):
        changed = copy.deepcopy(value)
        changed["cross_part_relationships"][0]["to"][field] = invalid
        response = analyst.post(prefix + "/assembly-preview", json=changed)
        assert response.status_code == 422, response.text
    preview = analyst.post(prefix + "/assembly-preview", json=value).json()
    changed = copy.deepcopy(value)
    changed["cross_part_relationships"][0]["kind"] = "CONTAINS"
    response = analyst.post(
        prefix + "/assembly-apply",
        json={"assembly": changed, "preview_digest": preview["preview_digest"]},
    )
    assert response.status_code == 409, response.text
    assert app.state.knowledge.head() == previous


def test_old_selection_cannot_drop_declared_topology_and_read_denial_hides_pins(analyst, bom):
    project, value = seeded(analyst, bom)
    response = analyst.post(path(project) + "/assembly", json=value)
    assert response.status_code == 201, response.text
    state = response.json()["updates"][0]["target"]
    old = assembly(
        [selection(item["part_id"], item["state"]) for item in value["parts"]],
        request_id="old-form",
        expected=state,
    )
    assert analyst.post(path(project) + "/assembly-preview", json=old).status_code == 409
    login(analyst, "operations")
    denied = analyst.post(path(project) + "/assembly-preview", json=value)
    assert denied.status_code == 404 and state not in denied.text
