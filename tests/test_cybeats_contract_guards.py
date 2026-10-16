"""CyBeats boundaries: malformed uploads, exact replay, disclosure and revocation."""

import base64
import copy
import json

import httpx
import pytest
from sqlalchemy import delete, select

from dtvp.knowledge.cybeats import connection, validate_capture
from dtvp.models import Credential, Membership, Project
from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_cybeats_source import ID, captured, prepare, settings, upstream
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app
_UNSET = object()


def submission(bom, *, capture=_UNSET, **changes):
    value = captured() if capture is _UNSET else capture
    raw = canonical(value)
    document = copy.deepcopy(bom)
    document.pop("vulnerabilities", None)
    metadata = {
        "request_id": "guarded-cybeats-import",
        "expected": None,
        "source": "cybeats",
        "build_number": 1,
        "occurred_at": "2026-10-16T00:00:00Z",
        "completeness": "complete",
        "expected_import_id": ID,
        "capture_sha256": digest(raw),
        "acknowledge_project_reader_disclosure": True,
        **changes,
    }
    return {
        "data": {"metadata": json.dumps(metadata)},
        "files": {
            "file": ("export.cdx.json", canonical(document)),
            "capture_file": ("capture.json", raw),
        },
    }


@pytest.mark.parametrize("occurred", [None, [], 123, "x" * 101])
def test_malformed_observation_time_is_a_clean_validation_failure(occurred):
    value = captured()
    value["occurred_at"] = occurred
    with pytest.raises(ValueError):
        validate_capture(value, endpoint="https://cybeats.invalid", import_id=ID)


@pytest.mark.parametrize(
    "url",
    [
        None,
        "https://cybeats.invalid:bad",
        "https://cybeats.invalid:999999",
        "https://cybeats.\ninvalid",
        "https://user:secret@cybeats.invalid",
        "https://cybeats.invalid/path",
    ],
)
def test_invalid_configured_origin_is_rejected_before_network(url):
    configured = settings()
    configured.cybeats_url = url
    with pytest.raises(ValueError):
        connection(configured)


@pytest.mark.parametrize("value", [None, [], 123, "malformed"])
def test_nonobject_capture_upload_never_publishes(analyst, app, bom, monkeypatch, value):
    base, seen = prepare(analyst, app, monkeypatch)
    before = app.state.knowledge.head()
    result = analyst.post(base + "/sources/cybeats/import", **submission(bom, capture=value))
    assert result.status_code == 422, result.text
    assert app.state.knowledge.head() == before and seen == []


@pytest.mark.parametrize("location", ["decoded-response", "outer-capture"])
def test_literal_configured_credential_echo_never_enters_project_artifacts(
    analyst, app, bom, monkeypatch, location
):
    base, seen = prepare(analyst, app, monkeypatch)
    value = captured()
    if location == "outer-capture":
        value["unexpected_credential"] = "test-secret-key"
    else:
        response = value["responses"][1]
        raw = canonical({"entities": [], "echo": "prefix-test-secret-key-suffix"})
        response.update(sha256=digest(raw), content_base64=base64.b64encode(raw).decode())
    before = app.state.knowledge.head()
    result = analyst.post(base + "/sources/cybeats/import", **submission(bom, capture=value))
    assert result.status_code == 422 and "test-secret-key" not in result.text
    assert app.state.knowledge.head() == before and seen == []
    assert not app.state.knowledge.objects.path(digest(canonical(value))).exists()


def test_live_read_credential_echo_is_not_returned_or_retained(analyst, app, monkeypatch):
    base, _ = prepare(analyst, app, monkeypatch)

    def reflect(request):
        result = upstream(request)
        body = result.json()
        body["echo"] = "test-access-key"
        return httpx.Response(200, json=body)

    monkeypatch.setattr(
        "dtvp.providers.client", lambda: httpx.Client(transport=httpx.MockTransport(reflect))
    )
    before = app.state.knowledge.head()
    result = analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID})
    assert result.status_code == 422 and "test-access-key" not in result.text
    assert app.state.knowledge.head() == before


def test_exact_receipt_replay_survives_source_rebinding_and_provider_disable(
    analyst, app, bom, monkeypatch
):
    base, seen = prepare(analyst, app, monkeypatch)
    request = submission(bom)
    first = analyst.post(base + "/sources/cybeats/import", **request)
    assert first.status_code == 201, first.text
    before = app.state.knowledge.head()
    assert (
        analyst.put(
            base + "/connectors/cybeats",
            json={"import_id": "replacement-import", "expected_import_id": ID},
        ).status_code
        == 200
    )
    monkeypatch.setattr(app.state.settings, "providers_enabled", [])
    monkeypatch.setattr(app.state.settings, "cybeats_url", "")
    repeated = analyst.post(base + "/sources/cybeats/import", **request)
    assert (
        repeated.status_code == 201
        and repeated.json()["publication"] == first.json()["publication"]
    ), repeated.text
    assert app.state.knowledge.head() == before and seen == []
    new = analyst.post(
        base + "/sources/cybeats/import", **submission(bom, request_id="new-request")
    )
    assert new.status_code == 409
    assert app.state.knowledge.head() == before
    login(analyst, "viewer")
    assert analyst.post(base + "/sources/cybeats/import", **request).status_code == 404


@pytest.mark.parametrize("change", ["credential", "membership", "binding", "disabled"])
def test_each_remote_query_rechecks_current_authorization_and_binding(
    analyst, app, monkeypatch, change
):
    base, _ = prepare(analyst, app, monkeypatch)
    token_hash = digest(analyst.cookies["dtvp_session"].encode())
    project_id = base.split("/")[4]
    seen = []

    def revoke(request):
        seen.append(request)
        response = upstream(request)
        if len(seen) == 1:
            if change == "disabled":
                app.state.settings.providers_enabled = []
            else:
                with app.state.sessions.begin() as db:
                    credential = db.scalar(
                        select(Credential).where(Credential.token_hash == token_hash)
                    )
                    if change == "credential":
                        credential.revoked = True
                    elif change == "membership":
                        db.execute(
                            delete(Membership).where(Membership.user_id == credential.user_id)
                        )
                    else:
                        project = db.get(Project, project_id)
                        metadata = copy.deepcopy(project.metadata_json)
                        metadata["connectors"]["cybeats"]["versions"]["cybeats-version"][
                            "import_id"
                        ] = "replacement-import"
                        project.metadata_json = metadata
        return response

    monkeypatch.setattr(
        "dtvp.providers.client", lambda: httpx.Client(transport=httpx.MockTransport(revoke))
    )
    before = app.state.knowledge.head()
    result = analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID})
    assert (
        result.status_code
        == {"credential": 401, "membership": 404, "binding": 409, "disabled": 422}[change]
    ), result.text
    assert len(seen) == 1 and app.state.knowledge.head() == before


@pytest.mark.parametrize("failure", ["redirect", "timeout", "http-error", "byte-limit"])
def test_network_failure_is_bounded_and_never_exposes_provider_details(
    analyst, app, monkeypatch, failure
):
    base, _ = prepare(analyst, app, monkeypatch)
    seen = []

    def fail(request):
        seen.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("test-secret-key")
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://attacker.invalid"})
        if failure == "http-error":
            return httpx.Response(503, text="test-secret-key")
        return upstream(request)

    if failure == "byte-limit":
        monkeypatch.setattr("dtvp.knowledge.cybeats.MAX_RESPONSE_BYTES", 10)
    monkeypatch.setattr(
        "dtvp.providers.client", lambda: httpx.Client(transport=httpx.MockTransport(fail))
    )
    before = app.state.knowledge.head()
    result = analyst.post(base + "/sources/cybeats/capture", json={"expected_import_id": ID})
    assert result.status_code == (422 if failure == "byte-limit" else 502), result.text
    assert "test-secret-key" not in result.text and len(seen) == 1
    assert app.state.knowledge.head() == before
