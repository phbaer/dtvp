"""Non-US native jobs use current authorization and pinned baseline identifiers."""

import copy

import pytest
import respx

from dtvp.jobs import work_once
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.ownership import product_heads
from tests.test_knowledge_api import app as knowledge_app
from tests.test_non_us_advisory_sources import CVE, EUVD, JVN, route
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


@pytest.mark.parametrize("provider,identifier", [("euvd", CVE), ("euvd", EUVD), ("jvn", JVN)])
@respx.mock
def test_non_us_native_refresh_is_discoverable_pinned_and_retrieves_exact_raw(
    analyst, app, bom, provider, identifier
):
    document = copy.deepcopy(bom)
    document["vulnerabilities"][0]["id"] = identifier
    project_id, _ = setup(analyst, document)
    app.state.settings.providers_enabled = [provider]
    upstream = route(provider, identifier)
    discovery = analyst.get(url(project_id, "/advisory-refresh"), params={"q": identifier}).json()
    assert discovery["identifiers"] == [identifier]
    assert discovery["selected_provider"] is None
    filtered = analyst.get(
        url(project_id, "/advisory-refresh"), params={"provider": "jvn", "q": identifier}
    ).json()
    assert filtered["selected_provider"] == "jvn"
    assert filtered["unsupported_total"] == (0 if provider == "jvn" else 1)
    assert filtered["identifiers"] == ([identifier] if provider == "jvn" else [])
    option = next(item for item in discovery["providers"] if item["id"] == provider)
    assert (
        option["enabled"]
        and ("JVNDB" if provider == "jvn" else "EUVD") in option["identifier_formats"]
    )
    request = {
        "request_id": "non-us-advisory",
        "provider": provider,
        "identifiers": [identifier],
        "expected_versions": product_heads(app.state.knowledge.references(), project_id),
        "expected_evidence": app.state.knowledge.resolve(evidence_ref(project_id)),
        "revision": 0,
    }
    path = url(project_id, "/advisory-jobs")
    queued = analyst.post(path, json=request)
    assert queued.status_code == 202, queued.text
    assert work_once(app.state.sessions, app.state.artifacts, app.state.settings)
    job = analyst.get(path + "/" + queued.json()["id"]).json()
    assert job["status"] == "succeeded", job
    assert upstream.call_count == 1
    result = job["result"]
    sha = result["raw_artifact_shas"][0]
    artifact = analyst.get(
        url(project_id, "/evidence/artifacts/" + sha),
        params={"expected_evidence": result["evidence_state"]},
    )
    assert artifact.status_code == 200
    assert artifact.content == upstream.calls[0].response.content
    current = workspace(analyst, project_id)
    assert any("Source-attributed enrichment" in str(item) for item in current["items"])
    assert all(not item["coverage"].get("approved") for item in current["items"])
    assert (
        analyst.post(
            path,
            json={
                **request,
                "request_id": "bad-kind",
                "identifiers": [CVE if provider == "jvn" else JVN],
            },
        ).status_code
        == 422
    )
    assert upstream.call_count == 1
