"""CyBeats public SDK read-query contract, mocked only; no guessed SBOM download."""

import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from dtvp.knowledge.cybeats import OPERATIONS, collect, signed_request, validate_capture
from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app
ID = "synthetic-import-123"


def settings(**changes):
    return SimpleNamespace(
        providers_enabled=["cybeats"],
        cybeats_url="https://cybeats.invalid",
        cybeats_access_key="test-access-key",
        cybeats_secret_access_key="test-secret-key",
        **changes,
    )


def upstream(request):
    assert request.method == "POST"
    expected = hmac.new(
        b"test-secret-key",
        request.headers["x-fwup-dtstmp"].encode() + request.content,
        hashlib.sha256,
    ).digest()
    assert request.headers["x-fwup-vsig"] == base64.urlsafe_b64encode(expected).decode().rstrip("=")
    assert request.headers["x-fwup-access-key-id"] == "test-access-key"
    body = json.loads(request.content)
    if request.url.path.endswith("/getbykey"):
        assert body == {"id": ID}
        return httpx.Response(
            200, json={"data": {"id": ID, "status": 7110, "enrichmentStatus": 7010}}
        )
    assert request.url.path == "/v1/sboms/componentcatalog/software"
    assert body == {"importId": ID}
    return httpx.Response(
        200,
        json={
            "entities": [
                {
                    "depsVulns": [
                        {
                            "id": "CVE-2099-10001",
                            "summary": "Aggregate claim without occurrence binding",
                        }
                    ]
                }
            ]
        },
    )


def captured():
    with httpx.Client(transport=httpx.MockTransport(upstream)) as client:
        return collect(settings(), ID, http=client, clock=lambda: 1_700_000_000)


def test_vendor_signing_vector_and_only_documented_reads():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "cybeats-sdk-contract.json").read_text()
    )
    assert OPERATIONS == tuple(
        (item["operation"], item["path"], item["field"]) for item in fixture["operations"]
    )
    vector = fixture["signing_vector"]
    path, raw, headers = signed_request(
        vector["import_id"],
        "import_status",
        vector["access_key"],
        vector["secret_key"],
        timestamp=vector["timestamp"],
    )
    assert path == fixture["operations"][0]["path"]
    assert raw == vector["body"].encode()
    assert headers["x-fwup-vsig"] == vector["signature"]
    value = captured()
    assert len(validate_capture(value, endpoint="https://cybeats.invalid", import_id=ID)) == 2
    assert "test-secret-key" not in json.dumps(value) and "test-access-key" not in json.dumps(value)


@pytest.mark.parametrize("change", ["bytes", "identity", "pending", "operation", "scope"])
def test_forged_or_incomplete_capture_rejected(change):
    value = captured()
    if change == "bytes":
        value["responses"][0]["sha256"] = "0" * 64
    elif change in {"identity", "pending"}:
        response = value["responses"][0]
        document = json.loads(base64.b64decode(response["content_base64"]))
        document["data"]["id" if change == "identity" else "status"] = (
            "foreign" if change == "identity" else 7000
        )
        raw = canonical(document)
        response.update(sha256=digest(raw), content_base64=base64.b64encode(raw).decode())
    elif change == "operation":
        value["responses"][0]["path"] = "/v1/sboms/imports/add"
    else:
        value["import_id"] = "foreign"
    with pytest.raises(ValueError):
        validate_capture(value, endpoint="https://cybeats.invalid", import_id=ID)


def prepare(analyst, app, monkeypatch):
    login(analyst, "administrator")
    project = analyst.get("/api/v1/projects").json()[0]["id"]
    base = f"/api/v1/projects/{project}/versions/cybeats-version"
    for key, value in vars(settings()).items():
        monkeypatch.setattr(app.state.settings, key, value)
    seen = []

    def respond(request):
        seen.append(request)
        return upstream(request)

    monkeypatch.setattr(
        "dtvp.providers.client", lambda: httpx.Client(transport=httpx.MockTransport(respond))
    )
    bound = analyst.put(
        base + "/connectors/cybeats", json={"import_id": ID, "expected_import_id": None}
    )
    assert bound.status_code == 200, bound.text
    return base, seen


def test_mocked_read_capture_explicit_export_import_retains_raw_and_never_invents_findings(
    analyst, app, bom, monkeypatch
):
    base, seen = prepare(analyst, app, monkeypatch)
    original = app.state.knowledge.head()
    response = analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID})
    assert response.status_code == 200, response.text
    assert app.state.knowledge.head() == original and len(seen) == 2
    value = response.json()["capture"]
    raw = canonical(value)
    doc = copy.deepcopy(bom)
    doc.pop("vulnerabilities", None)
    metadata = {
        "request_id": "cybeats-explicit-import",
        "expected": None,
        "source": "cybeats",
        "build_number": 1,
        "occurred_at": "2026-10-16T00:00:00Z",
        "completeness": "complete",
        "expected_import_id": ID,
        "capture_sha256": digest(raw),
        "acknowledge_project_reader_disclosure": True,
    }
    files = {"file": ("export.cdx.json", canonical(doc)), "capture_file": ("capture.json", raw)}
    imported = analyst.post(
        base + "/sources/cybeats/import", data={"metadata": json.dumps(metadata)}, files=files
    )
    assert imported.status_code == 201, imported.text
    replay = analyst.post(
        base + "/sources/cybeats/import", data={"metadata": json.dumps(metadata)}, files=files
    )
    assert replay.json()["publication"] == imported.json()["publication"]
    state = imported.json()["updates"][0]["target"]
    bundle = analyst.get(f"/api/v1/projects/{base.split('/')[4]}/states/{state}/bundle").json()
    assert (
        bundle["inventory"]["baseline"]["source_provenance"]["composition_binding"]
        == "operator_declared_supplied_export"
    )
    assert app.state.knowledge.objects.read(digest(raw)) == raw
    assert not bundle["findings"]
    assert len(seen) == 2


def test_binding_disabled_provider_and_reader_never_contact_upstream(analyst, app, monkeypatch):
    base, seen = prepare(analyst, app, monkeypatch)
    assert (
        analyst.post(
            base + "/sources/cybeats/capture", json={"expected_import_id": "foreign"}
        ).status_code
        == 409
    )
    monkeypatch.setattr(app.state.settings, "providers_enabled", [])
    assert (
        analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID}).status_code
        == 422
    )
    login(analyst, "viewer")
    assert (
        analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID}).status_code
        == 404
    )
    assert seen == []
