"""Pinned consumer downloads retain integrity and enforce current authorization."""

import copy
import hashlib

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import VERSION, setup, url, workspace

app = knowledge_app


def download(client, project_id, state, resource):
    return client.get(url(project_id, f"/states/{state}/{resource}"))


def test_native_bundle_manifest_and_worklist_share_pinned_identity(analyst, bom):
    project_id, _ = setup(analyst, bom)
    state = workspace(analyst, project_id)["state"]
    bundle = download(analyst, project_id, state, "bundle")
    manifest = download(analyst, project_id, state, "manifest")
    worklist = download(analyst, project_id, state, "vscorer-worklist")
    for response in (bundle, manifest, worklist):
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        payload = response.json()
        assert payload["project_id"] == project_id
        assert payload["version"] == VERSION
        assert payload["state"] == state
    sha = hashlib.sha256(bundle.content).hexdigest()
    assert bundle.headers["x-content-sha256"] == sha == manifest.json()["bundle_sha256"]
    assert len(bundle.content) == manifest.json()["bundle_bytes"]
    assert bundle.json()["format"] == "dtvp.knowledge-bundle/1"
    assert manifest.json()["format"] == "dtvp.knowledge-export/1"
    assert worklist.json()["format"] == "dtvp.knowledge-vscorer-worklist/1"
    assert len(bundle.json()["findings"]) == len(worklist.json()["items"]) == 2
    assert all(not finding["coverage"]["approved"] for finding in bundle.json()["findings"])
    assert all(finding["published_score"] is None for finding in bundle.json()["findings"])
    assert all(item["published_contextual_score"] is None for item in worklist.json()["items"])
    assert "cves" not in worklist.json()


def test_reimport_and_policy_changes_do_not_mutate_prior_downloads(analyst, bom):
    from tests.test_knowledge_ownership import apply_policy

    project_id, teams = setup(analyst, bom)
    original_state = workspace(analyst, project_id)["state"]
    resources = ("bundle", "manifest", "vscorer-worklist")
    before = {
        resource: download(analyst, project_id, original_state, resource).content
        for resource in resources
    }
    changed = copy.deepcopy(bom)
    changed["vulnerabilities"][0]["description"] = "Changed source description"
    imported(
        analyst,
        project_id,
        VERSION,
        body(changed, expected=original_state, request_id="new-build", build_number=2),
    )
    login(analyst, "administrator")
    apply_policy(
        analyst,
        project_id,
        [{"selector": "*", "team_id": teams["Operations"]}],
        request_id="new-policy",
    )
    current = workspace(analyst, project_id)["state"]
    assert current != original_state
    for resource in resources:
        pinned = download(analyst, project_id, original_state, resource)
        assert pinned.status_code == 200, pinned.text
        assert pinned.content == before[resource]
        assert download(analyst, project_id, current, resource).content != before[resource]


def test_current_authorization_and_product_binding_apply_to_historical_exports(analyst, bom):
    project_id, teams = setup(analyst, bom)
    state = workspace(analyst, project_id)["state"]
    resources = ("bundle", "manifest", "vscorer-worklist")
    login(analyst, "operations")
    for resource in resources:
        assert download(analyst, project_id, state, resource).status_code == 404
    login(analyst, "administrator")
    response = analyst.put(
        f"/api/v1/projects/{project_id}/sharing",
        json={"workspace_id": teams["Operations"], "capabilities": ["read"]},
    )
    assert response.status_code == 200, response.text
    login(analyst, "operations")
    for resource in resources:
        assert download(analyst, project_id, state, resource).status_code == 200
    login(analyst, "administrator")
    response = analyst.put(
        f"/api/v1/projects/{project_id}/sharing",
        json={"workspace_id": teams["Operations"], "capabilities": []},
    )
    assert response.status_code == 200, response.text
    login(analyst, "operations")
    for resource in resources:
        assert download(analyst, project_id, state, resource).status_code == 404
    login(analyst, "administrator")
    response = analyst.post(
        "/api/v1/projects", json={"workspace_id": teams["Platform"], "name": "Different product"}
    )
    assert response.status_code == 201, response.text
    other_id = response.json()["id"]
    for resource in resources:
        assert download(analyst, other_id, state, resource).status_code == 404
        assert download(analyst, project_id, "f" * 64, resource).status_code == 404
