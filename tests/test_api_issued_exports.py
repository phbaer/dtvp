import json

from dtvp.knowledge.journal import Ref
from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_rescoring import BASE
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_frozen_bundle_downloads_survive_serializer_changes_and_keep_project_scope(
    analyst, app, bom, monkeypatch
):
    import dtvp.knowledge.issued_exports as exports

    project_id, _ = setup(analyst, bom)
    state = workspace(analyst, project_id)["state"]
    response = analyst.post(url(project_id, f"/states/{state}/exports/bundle"))
    assert response.status_code == 201, response.text
    issued = response.json()
    raw = analyst.get(issued["files"]["bundle.json"]["url"])
    assert raw.status_code == 200
    assert digest(raw.content) == issued["source_receipt"]["bundle_sha256"]
    assert json.loads(raw.content)["state"] == state
    assert app.state.knowledge.resolve(Ref(project_id=project_id, name="7.1.1")) == state
    head = app.state.knowledge.head()
    monkeypatch.setattr(
        exports,
        "export_bytes",
        lambda *args: (_ for _ in ()).throw(AssertionError("Old serializer must not run")),
    )
    assert analyst.post(url(project_id, f"/states/{state}/exports/bundle")).json() == issued
    assert analyst.get(issued["files"]["bundle.json"]["url"]).content == raw.content
    assert app.state.knowledge.head() == head
    assert (
        analyst.get(
            url(project_id, f"/issued-exports/{issued['receipt_sha256']}/files/unknown.json")
        ).status_code
        == 404
    )
    login(analyst, "operations")
    assert analyst.get(issued["files"]["bundle.json"]["url"]).status_code == 404


def test_vscorer_preparation_reuses_issued_payload_before_any_new_derivation(
    analyst, app, bom, monkeypatch
):
    import dtvp.knowledge.vscorer as vscorer

    project_id, _ = setup(analyst, bom)
    current = workspace(analyst, project_id)
    row = current["items"][0]
    path = url(project_id, f"/states/{current['state']}/vscorer-input")
    body = {
        "context_id": row["context_id"],
        "component_ref": row["component"]["bom-ref"],
        "base_selections": {row["vulnerability_id"]: BASE},
    }
    response = analyst.post(path, json=body)
    assert response.status_code == 200, response.text
    first = response.json()
    monkeypatch.setattr(
        vscorer,
        "derive_context_inputs",
        lambda *args: (_ for _ in ()).throw(AssertionError("Frozen inputs must win")),
    )
    assert analyst.post(path, json=body).json() == first
    for name, key in (("sbom.cdx.json", "sbom"), ("cves.json", "cves")):
        assert (
            digest(first["files"][name].encode())
            == first["dtvp_source"]["artifacts"][key + "_sha256"]
        )
    assert workspace(analyst, project_id)["state"] == current["state"]
