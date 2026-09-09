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
        auth_settings.SESSION_SECRET_KEY,
        algorithms=["HS256"],
    )
    assert session["sub"] == "reviewer"
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
        auth_settings.SESSION_SECRET_KEY,
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
    token = jwt.encode(
        {"sub": "testuser"}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
    )
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
