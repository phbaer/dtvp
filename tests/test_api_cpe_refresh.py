"""Scoped CPE acquisition rechecks project authority and retains explicit apply."""

import httpx
import pytest

from tests.conftest import login
from tests.test_api_cpe_sources import prepare
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_cpe_refresh import body, request

app = knowledge_app


def remote(monkeypatch, app):
    import dtvp.providers

    seen = []

    def respond(req):
        seen.append(req)
        return httpx.Response(200, json=body())

    monkeypatch.setattr(app.state.settings, "providers_enabled", ["nvd"])
    monkeypatch.setattr(
        dtvp.providers, "client", lambda: httpx.Client(transport=httpx.MockTransport(respond))
    )
    return seen


def test_scoped_capture_preview_apply_and_raw_download(analyst, app, monkeypatch):
    _, path, _ = prepare(analyst)
    seen = remote(monkeypatch, app)
    before = app.state.knowledge.head()
    captured = analyst.post(path + "/refresh", json=request().model_dump())
    assert captured.status_code == 200, captured.text
    assert len(seen) == 1 and app.state.knowledge.head() == before
    result = captured.json()
    assert result["committed"] is False
    data = result["source_input"] | {"preview_digest": result["preview"]["preview_digest"]}
    applied = analyst.post(path + "/apply", json=data)
    assert applied.status_code == 201, applied.text
    state = applied.json()["updates"][0]["target"]
    assert (
        analyst.get(path + f"/{state}/dictionary/artifact").headers["x-content-sha256"]
        == data["artifact_sha256"]
    )
    assert (
        analyst.post(path + "/apply", json=data).json()["publication"]
        == applied.json()["publication"]
    )
    assert len(seen) == 1


@pytest.mark.parametrize("persona", ["viewer", "analyst", "reviewer"])
def test_capture_authorizes_before_body_or_network(analyst, app, monkeypatch, persona):
    _, path, _ = prepare(analyst)
    seen = remote(monkeypatch, app)
    login(analyst, persona)
    assert analyst.post(path + "/refresh", content=b"not-json").status_code == 404
    assert seen == []


def test_stale_policy_rejected_before_network_and_disabled_by_default(analyst, app, monkeypatch):
    _, path, _ = prepare(analyst)
    seen = remote(monkeypatch, app)
    assert (
        analyst.post(path + "/refresh", json=request(expected="a" * 64).model_dump()).status_code
        == 409
    )
    assert seen == []
    monkeypatch.setattr(app.state.settings, "providers_enabled", [])
    assert analyst.post(path + "/refresh", json=request().model_dump()).status_code == 422
    assert seen == []


def test_remote_error_is_sanitized_and_leaves_policy_unchanged(analyst, app, monkeypatch):
    import dtvp.providers

    _, path, _ = prepare(analyst)
    remote(monkeypatch, app)
    monkeypatch.setattr(
        dtvp.providers,
        "client",
        lambda: httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(429))),
    )
    before = app.state.knowledge.head()
    result = analyst.post(path + "/refresh", json=request().model_dump())
    assert result.status_code == 502 and "no policy was changed" in result.text
    assert app.state.knowledge.head() == before


def test_management_revocation_during_capture_returns_no_source(analyst, app, monkeypatch):
    from sqlalchemy import delete, select

    import dtvp.providers
    from dtvp.models import Membership, User

    _, path, _ = prepare(analyst)
    remote(monkeypatch, app)

    def revoke(req):
        with app.state.sessions.begin() as db:
            manager = db.scalar(select(User).where(User.subject == "administrator"))
            db.execute(delete(Membership).where(Membership.user_id == manager.id))
        return httpx.Response(200, json=body())

    monkeypatch.setattr(
        dtvp.providers, "client", lambda: httpx.Client(transport=httpx.MockTransport(revoke))
    )
    before = app.state.knowledge.head()
    result = analyst.post(path + "/refresh", json=request().model_dump())
    assert result.status_code == 404
    assert app.state.knowledge.head() == before


def test_cpe_429_sets_shared_provider_cooldown_before_another_capture(analyst, app, monkeypatch):
    from sqlalchemy import select

    import dtvp.providers
    from dtvp.models import AdvisoryProviderThrottle

    _, path, _ = prepare(analyst)
    remote(monkeypatch, app)
    seen = []

    def limited(req):
        seen.append(req)
        return httpx.Response(429, headers={"Retry-After": "120"})

    monkeypatch.setattr(
        dtvp.providers, "client", lambda: httpx.Client(transport=httpx.MockTransport(limited))
    )
    assert analyst.post(path + "/refresh", json=request().model_dump()).status_code == 502
    with app.state.sessions() as db:
        assert db.scalar(select(AdvisoryProviderThrottle)).cooldown_until is not None
    repeated = analyst.post(
        path + "/refresh", json=request(request_id="another-capture").model_dump()
    )
    assert repeated.status_code == 422 and "30 seconds" in repeated.text
    assert len(seen) == 1
