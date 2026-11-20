from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from jose import jwt
from joserfc.errors import JoseError

from dtvp import auth
from dtvp.auth import auth_settings, get_oidc_client
from dtvp.main import app, get_current_user
from dtvp.session_services import issue_session_token
from test_setup import mock_dt


def build_mock_oidc_client():
    oauth = OAuth()
    return oauth.register(
        name="oidc",
        client_id="mock_id",
        client_secret="mock_secret",
        server_metadata_url=(
            "http://mock-oidc/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "client_secret_post",
            "transport": httpx2.ASGITransport(app=mock_dt.app),
        },
    )


def fake_oidc_client(*, token=None, error=None):
    client = MagicMock()
    client.authorize_redirect = AsyncMock(
        return_value=RedirectResponse("https://auth.example.com/login")
    )
    client.authorize_access_token = AsyncMock(
        return_value=(
            token if token is not None else {"userinfo": {"sub": "testuser"}}
        ),
        side_effect=error,
    )
    return client


@pytest.fixture(autouse=True)
def use_real_auth():
    auth._create_oidc_client.cache_clear()
    mock_dt.oidc_authorization_codes.clear()
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]
    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", False):
        yield
    auth._create_oidc_client.cache_clear()
    mock_dt.oidc_authorization_codes.clear()


def test_oidc_client_uses_discovery_pkce_and_configured_auth_method():
    confidential = auth._create_oidc_client(
        "https://auth.example.com", "client-id", "client-secret"
    )

    assert confidential._server_metadata_url == (
        "https://auth.example.com/.well-known/openid-configuration"
    )
    assert confidential.client_kwargs["scope"] == "openid profile email"
    assert confidential.client_kwargs["code_challenge_method"] == "S256"
    assert (
        confidential.client_kwargs["token_endpoint_auth_method"]
        == "client_secret_post"
    )

    public = auth._create_oidc_client(
        "https://auth.example.com", "client-id", ""
    )
    assert public.client_secret is None
    assert public.client_kwargs["token_endpoint_auth_method"] == "none"


def test_get_oidc_client_requires_authority_and_client_id():
    with patch("dtvp.auth.auth_settings") as settings:
        settings.authority = ""
        with pytest.raises(HTTPException) as exc:
            get_oidc_client()
        assert exc.value.detail == "OIDC Authority not configured"

        settings.authority = "https://auth.example.com"
        settings.client_id = ""
        with pytest.raises(HTTPException) as exc:
            get_oidc_client()
        assert exc.value.detail == "OIDC Client ID not configured"


def test_login_delegates_to_authlib(client):
    oidc_client = fake_oidc_client()
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client):
        response = client.get("/auth/login", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "https://auth.example.com/login"
    oidc_client.authorize_redirect.assert_awaited_once()
    _, redirect_uri = oidc_client.authorize_redirect.await_args.args
    assert redirect_uri == auth_settings.redirect_uri


def test_authlib_oidc_login_round_trip_uses_pkce_and_validates_id_token(client):
    oidc_client = build_mock_oidc_client()
    redirect_uri = "http://testserver/auth/callback"
    with (
        patch.object(auth_settings, "OIDC_REDIRECT_URI", redirect_uri),
        patch.object(auth_settings, "FRONTEND_URL", "http://testserver"),
        patch("dtvp.auth.get_oidc_client", return_value=oidc_client),
    ):
        login_response = client.get("/auth/login", follow_redirects=False)
        authorization_url = urlparse(login_response.headers["location"])
        authorization_params = parse_qs(authorization_url.query)

        assert login_response.status_code == 302
        assert authorization_params["response_type"] == ["code"]
        assert authorization_params["code_challenge_method"] == ["S256"]
        assert len(authorization_params["code_challenge"][0]) == 43
        assert authorization_params["nonce"][0]
        assert authorization_params["state"][0]

        provider = client.__class__(mock_dt.app, base_url="http://mock-oidc")
        provider_response = provider.post(
            "/auth/authorize",
            data={
                "username": "reviewer",
                "redirect_uri": authorization_params["redirect_uri"][0],
                "client_id": authorization_params["client_id"][0],
                "state": authorization_params["state"][0],
                "nonce": authorization_params["nonce"][0],
                "code_challenge": authorization_params["code_challenge"][0],
                "code_challenge_method": authorization_params[
                    "code_challenge_method"
                ][0],
            },
            follow_redirects=False,
        )
        callback_url = urlparse(provider_response.headers["location"])
        callback_response = client.get(
            f"{callback_url.path}?{callback_url.query}", follow_redirects=False
        )

    assert callback_response.status_code == 307
    session_cookie = callback_response.cookies.get("session_token")
    assert session_cookie is not None
    session = jwt.decode(
        session_cookie,
        auth.session_config.secret_key,
        algorithms=["HS256"],
    )
    assert session["sub"] == "reviewer"
    assert session["typ"] == "dtvp-session"
    assert session["ver"] == 0
    assert client.cookies.get("oidc_state") is None


def test_callback_uses_validated_authlib_claims(client):
    oidc_client = fake_oidc_client(
        token={
            "userinfo": {
                "sub": "sub_user",
                "preferred_username": "preferred_user",
                "email": "email@example.com",
            }
        }
    )
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client):
        response = client.get(
            "/auth/callback?code=code&state=state", follow_redirects=False
        )

    session = jwt.decode(
        response.cookies["session_token"],
        auth.session_config.secret_key,
        algorithms=["HS256"],
    )
    assert response.status_code == 307
    assert session["sub"] == "sub_user"


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (MismatchingStateError(), "Invalid OIDC login state"),
        (
            OAuthError(error="invalid_grant", description="bad code"),
            "Failed to authenticate with OIDC provider",
        ),
        (JoseError("bad signature"), "Invalid OIDC identity token"),
    ],
)
def test_callback_rejects_authlib_validation_errors(client, error, detail):
    oidc_client = fake_oidc_client(error=error)
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client):
        response = client.get(
            "/auth/callback?code=code&state=state", follow_redirects=False
        )

    assert response.status_code == 400
    assert response.json()["detail"] == detail


@pytest.mark.parametrize(
    ("token", "detail"),
    [
        ({"access_token": "token"}, "OIDC identity token missing"),
        (
            {"userinfo": {"name": "No Identifier"}},
            "OIDC identity token has no user identifier",
        ),
    ],
)
def test_callback_rejects_missing_identity_claims(client, token, detail):
    oidc_client = fake_oidc_client(token=token)
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client):
        response = client.get(
            "/auth/callback?code=code&state=state", follow_redirects=False
        )

    assert response.status_code == 400
    assert response.json()["detail"] == detail


def test_me_endpoint(client):
    token = issue_session_token(auth.session_config, "testuser", 0)
    client.cookies.set("session_token", token)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

    client.cookies.clear()
    response = client.get("/auth/me")
    assert response.status_code == 401

    client.cookies.set("session_token", "invalid.token.here")
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_redirect_uri_and_cookie_settings():
    from dtvp.auth import AuthSettings

    settings = AuthSettings(
        DTVP_OIDC_REDIRECT_URI=None,
        DTVP_FRONTEND_URL="https://base.url",
        DTVP_CONTEXT_PATH="ctx",
    )
    assert settings.redirect_uri == "https://base.url/ctx/auth/callback"
    assert settings.oidc_cookie_path == "/ctx/auth"
    assert settings.application_cookie_path == "/ctx"
    assert settings.secure_cookies is True

    settings = AuthSettings(DTVP_OIDC_REDIRECT_URI="http://custom/callback")
    assert settings.redirect_uri == "http://custom/callback"
    assert settings.secure_cookies is False


def test_callback_context_path_slashes(client):
    oidc_client = fake_oidc_client(token={"userinfo": {"sub": "me"}})
    with (
        patch("dtvp.auth.get_oidc_client", return_value=oidc_client),
        patch.object(auth_settings, "CONTEXT_PATH", "mycontext"),
    ):
        response = client.get(
            "/auth/callback?code=code&state=state", follow_redirects=False
        )

    assert response.status_code == 307
    assert "/mycontext" in response.headers["location"]


def test_logout_redirects_to_login(client):
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].endswith("/login")


@pytest.mark.asyncio
async def test_get_current_user_dev_disable_auth():
    from dtvp.auth import get_current_user

    class DummyRequest:
        cookies = {}
        headers = {}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=True):
        user = await get_current_user(DummyRequest())
        assert user == "devuser"


@pytest.mark.asyncio
async def test_get_current_user_rejects_request_without_dtvp_session():
    from dtvp.auth import get_current_user

    class DummyRequest:
        cookies = {}
        headers = {}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=False):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(DummyRequest())

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_ignores_dependency_track_identity_material():
    from dtvp.auth import get_current_user

    class DummyRequest:
        cookies = {
            "corporate_sso": "cookie-value",
            "dt_session": "legacy-dt-cookie",
            "session_token": "",
        }
        headers = {"Authorization": "Bearer dependency-track-token"}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=False):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(DummyRequest())

    assert exc.value.status_code == 401


# --- expiring, versioned session tokens -----------------------------------


def _claims(token):
    return jwt.decode(token, auth.session_config.secret_key, algorithms=["HS256"])


def _session_cookie_headers(response):
    return [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith("session_token=")
    ]


def _login(client, username="testuser"):
    oidc_client = fake_oidc_client(token={"userinfo": {"sub": username}})
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client):
        response = client.get(
            "/auth/callback?code=code&state=state", follow_redirects=False
        )
    assert response.status_code == 307
    return response


def _me(client, token):
    client.cookies.clear()
    client.cookies.set("session_token", token)
    return client.get("/auth/me")


def test_callback_issues_a_typed_expiring_versioned_cookie(client):
    response = _login(client)

    claims = _claims(response.cookies["session_token"])
    assert claims["typ"] == "dtvp-session"
    assert claims["sub"] == "testuser"
    assert claims["ver"] == 0
    assert claims["exp"] - claims["iat"] == 12 * 3600
    [header] = _session_cookie_headers(response)
    assert "Max-Age=43200" in header
    assert "HttpOnly" in header


def test_legacy_cookie_without_expiry_is_rejected(client):
    legacy = jwt.encode(
        {"sub": "testuser"}, auth.session_config.secret_key, algorithm="HS256"
    )
    assert _me(client, legacy).status_code == 401


def test_expired_cookie_is_rejected(client):
    import time

    token = issue_session_token(
        auth.session_config, "testuser", 0, now=time.time() - 13 * 3600
    )
    assert _me(client, token).status_code == 401


def test_ssvc_evidence_token_is_not_a_session(client):
    from dtvp.ssvc_enrichment_services import sign_evidence

    evidence = sign_evidence({"value": "N", "source": "kev"})
    assert _me(client, evidence).status_code == 401


def test_logout_ends_every_session_of_the_user(client):
    first = _login(client).cookies["session_token"]
    second = _login(client).cookies["session_token"]
    assert _me(client, first).status_code == 200
    assert _me(client, second).status_code == 200

    client.cookies.clear()
    client.cookies.set("session_token", first)
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].endswith("/login")
    [cleared] = _session_cookie_headers(response)
    assert "Max-Age=0" in cleared or 'session_token=""' in cleared

    assert _me(client, first).status_code == 401
    assert _me(client, second).status_code == 401

    fresh = _login(client).cookies["session_token"]
    assert _claims(fresh)["ver"] == 1
    assert _me(client, fresh).status_code == 200


def test_logout_with_a_revoked_cookie_does_not_end_newer_sessions(client):
    old = _login(client).cookies["session_token"]
    client.cookies.set("session_token", old)
    client.get("/auth/logout", follow_redirects=False)
    newer = _login(client).cookies["session_token"]

    client.cookies.clear()
    client.cookies.set("session_token", old)
    assert client.get("/auth/logout", follow_redirects=False).status_code == 307

    assert _me(client, newer).status_code == 200


def test_logout_without_cookie_still_redirects(client):
    client.cookies.clear()
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].endswith("/login")


@pytest.mark.parametrize("failing", ["session_version", "revoke_sessions"])
def test_logout_says_so_when_the_sessions_cannot_be_ended(client, failing):
    import sqlite3

    token = _login(client).cookies["session_token"]
    client.cookies.set("session_token", token)
    with patch.object(
        auth.access_token_store,
        failing,
        side_effect=sqlite3.OperationalError("locked"),
    ):
        response = client.get("/auth/logout", follow_redirects=False)
    # Not a silent sign-out: the session would stay valid everywhere.
    assert response.status_code == 503
    assert "could not be ended" in response.json()["detail"]
    assert not _session_cookie_headers(response)
    assert _me(client, token).status_code == 200


def test_callback_reports_an_unreadable_session_store_as_unavailable(client):
    import sqlite3

    oidc_client = fake_oidc_client(token={"userinfo": {"sub": "alice"}})
    with patch("dtvp.auth.get_oidc_client", return_value=oidc_client), patch.object(
        auth.access_token_store,
        "session_version",
        side_effect=sqlite3.OperationalError("locked"),
    ):
        response = client.get("/auth/callback?code=code&state=state", follow_redirects=False)
    assert response.status_code == 503
    assert not _session_cookie_headers(response)


def test_revoking_reports_an_unwritable_session_store_as_unavailable(client):
    import sqlite3

    reviewer = _login(client, "rita").cookies["session_token"]
    with patch("dtvp.auth.get_user_role", return_value="REVIEWER"), patch.object(
        auth.access_token_store,
        "revoke_sessions",
        side_effect=sqlite3.OperationalError("locked"),
    ):
        response = _revoke(client, reviewer, "alice")
    assert response.status_code == 503


def _revoke(client, token, username, **kwargs):
    client.cookies.clear()
    client.cookies.set("session_token", token)
    return client.post(
        "/auth/sessions/revoke", json={"username": username}, **kwargs
    )


def test_reviewer_revokes_another_users_sessions(client):
    alice = _login(client, "alice").cookies["session_token"]
    reviewer = _login(client, "rita").cookies["session_token"]

    with patch("dtvp.auth.get_user_role", return_value="REVIEWER"):
        response = _revoke(client, reviewer, "  alice ")

    assert response.status_code == 200
    assert response.json() == {"status": "revoked", "username": "alice"}
    assert not _session_cookie_headers(response)
    assert _me(client, alice).status_code == 401
    assert _me(client, reviewer).status_code == 200


def test_analyst_cannot_revoke_another_users_sessions(client):
    bob = _login(client, "bob").cookies["session_token"]
    analyst = _login(client, "ann").cookies["session_token"]

    with patch("dtvp.auth.get_user_role", return_value="ANALYST"):
        response = _revoke(client, analyst, "bob")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only reviewers can revoke another user's sessions"
    )
    assert _me(client, bob).status_code == 200


def test_analyst_revokes_own_sessions_and_the_cookie_is_cleared(client):
    import time

    # Past half its lifetime, so authentication would renew it.
    analyst = issue_session_token(
        auth.session_config, "ann", 0, now=time.time() - 7 * 3600
    )

    with patch("dtvp.auth.get_user_role", return_value="ANALYST"):
        response = _revoke(client, analyst, "ann")

    assert response.status_code == 200
    [cleared] = _session_cookie_headers(response)
    assert "Max-Age=0" in cleared or 'session_token=""' in cleared
    assert _me(client, analyst).status_code == 401


def test_access_token_cannot_revoke_sessions(client, monkeypatch):
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    _record, plain = auth.access_token_store.create(
        username="alice", name="agent", scopes=["read", "write"]
    )
    client.cookies.clear()
    response = client.post(
        "/auth/sessions/revoke",
        json={"username": "alice"},
        headers={"Authorization": f"Bearer {plain}"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("username", ["", "   ", "x" * 257])
def test_revoke_requires_a_username(client, username):
    token = _login(client).cookies["session_token"]
    assert _revoke(client, token, username).status_code == 422


def test_unauthenticated_revoke_is_rejected(client):
    client.cookies.clear()
    response = client.post("/auth/sessions/revoke", json={"username": "alice"})
    assert response.status_code == 401


def _refreshed(response):
    headers = _session_cookie_headers(response)
    assert len(headers) == 1
    return headers[0].split(";", 1)[0].split("=", 1)[1]


def test_session_past_half_its_lifetime_is_renewed(client):
    import time

    now = time.time()
    old = issue_session_token(auth.session_config, "testuser", 0, now=now - 7 * 3600)

    response = _me(client, old)

    assert response.status_code == 200
    claims = _claims(_refreshed(response))
    assert claims["ver"] == 0
    assert claims["sub"] == "testuser"
    assert abs(claims["iat"] - now) < 60
    assert claims["exp"] - claims["iat"] == 12 * 3600


def test_session_is_renewed_on_api_routes_too(client):
    import time

    old = issue_session_token(
        auth.session_config, "testuser", 0, now=time.time() - 7 * 3600
    )
    client.cookies.clear()
    client.cookies.set("session_token", old)

    response = client.get("/api/settings/tokens")

    assert response.status_code == 200
    assert _claims(_refreshed(response))["exp"] > _claims(old)["exp"]


def test_fresh_session_is_not_renewed(client):
    import time

    token = issue_session_token(
        auth.session_config, "testuser", 0, now=time.time() - 3600
    )
    response = _me(client, token)
    assert response.status_code == 200
    assert not _session_cookie_headers(response)


def test_session_version_lookup_failure_is_503_not_401(client):
    import sqlite3

    token = issue_session_token(auth.session_config, "testuser", 0)
    with patch.object(
        auth.access_token_store,
        "session_version",
        side_effect=sqlite3.OperationalError("disk I/O error"),
    ):
        response = _me(client, token)
    assert response.status_code == 503
    assert response.json()["detail"] == "Session check unavailable"
