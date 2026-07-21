import base64
import hashlib
import time
import uuid
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, patch

import pytest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from dtvp import auth
from dtvp.auth import (
    OIDC_TRANSACTION_COOKIE_NAME,
    SESSION_ALGORITHM,
    SESSION_AUDIENCE,
    SESSION_COOKIE_NAME,
    SESSION_ISSUER,
    AuthSettings,
    auth_settings,
    create_session_token,
    decode_session_token,
    get_current_principal,
    get_oidc_config,
    validate_auth_configuration,
)
from dtvp.main import app, get_current_user

OIDC_ISSUER = "https://auth.example.com"
OIDC_CONFIG = {
    "issuer": OIDC_ISSUER,
    "authorization_endpoint": f"{OIDC_ISSUER}/login",
    "token_endpoint": f"{OIDC_ISSUER}/token",
    "jwks_uri": f"{OIDC_ISSUER}/jwks",
    "id_token_signing_alg_values_supported": ["RS256"],
}
OIDC_KEY_ID = "test-signing-key"
OIDC_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OIDC_PRIVATE_PEM = OIDC_PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


OIDC_PUBLIC_NUMBERS = OIDC_PRIVATE_KEY.public_key().public_numbers()
OIDC_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": OIDC_KEY_ID,
            "n": _base64url_uint(OIDC_PUBLIC_NUMBERS.n),
            "e": _base64url_uint(OIDC_PUBLIC_NUMBERS.e),
        }
    ]
}


@pytest.fixture(autouse=True)
def use_real_auth():
    app.dependency_overrides.pop(get_current_user, None)
    auth._oidc_config_cache = None
    auth._oidc_config_cached_at = 0.0
    auth._jwks_cache.clear()
    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", False):
        yield


def _start_login(client) -> dict[str, str]:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 307
    query = parse_qs(urlparse(response.headers["location"]).query)
    return {key: values[0] for key, values in query.items()}


def _id_token(
    *,
    nonce: str,
    subject: str = "subject-123",
    preferred_username: str = "testuser",
    issuer: str = OIDC_ISSUER,
    audience: str = "test-client",
    expires_at: int | None = None,
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "preferred_username": preferred_username,
        "nonce": nonce,
        "iat": now,
        "exp": expires_at if expires_at is not None else now + 300,
    }
    claims.update(extra_claims or {})
    return jwt.encode(
        claims,
        OIDC_PRIVATE_PEM,
        algorithm="RS256",
        headers={"kid": OIDC_KEY_ID},
    )


def _access_token_hash(access_token: str = "access-token") -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode(
        "ascii"
    )


def _mock_successful_token_exchange(respx_mock, *, nonce: str, **token_kwargs):
    respx_mock.get(OIDC_CONFIG["jwks_uri"]).respond(json=OIDC_JWKS)
    return respx_mock.post(OIDC_CONFIG["token_endpoint"]).respond(
        json={
            "access_token": "access-token",
            "id_token": _id_token(nonce=nonce, **token_kwargs),
            "token_type": "Bearer",
        }
    )


@pytest.mark.asyncio
async def test_get_oidc_config_validates_and_caches_discovery(respx_mock):
    config_url = f"{OIDC_ISSUER}/.well-known/openid-configuration"
    route = respx_mock.get(config_url).respond(json=OIDC_CONFIG)

    config = await get_oidc_config()
    assert config["authorization_endpoint"] == OIDC_CONFIG["authorization_endpoint"]
    assert await get_oidc_config() is config
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_get_oidc_config_rejects_issuer_mismatch(respx_mock):
    config_url = f"{OIDC_ISSUER}/.well-known/openid-configuration"
    respx_mock.get(config_url).respond(json={**OIDC_CONFIG, "issuer": "https://evil.example"})

    with pytest.raises(HTTPException) as exc:
        await get_oidc_config()

    assert exc.value.status_code == 503
    assert exc.value.detail == "OIDC discovery issuer mismatch"


def test_login_uses_state_nonce_and_pkce(client):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        response = client.get("/auth/login", follow_redirects=False)

    assert response.status_code == 307
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["client_id"] == ["test-client"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid profile email"]
    assert len(query["state"][0]) >= 32
    assert len(query["nonce"][0]) >= 32
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) >= 43
    assert response.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie
    assert "Max-Age=300" in set_cookie


@pytest.mark.asyncio
async def test_callback_validates_token_and_creates_expiring_session(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        token_route = _mock_successful_token_exchange(
            respx_mock,
            nonce=login_params["nonce"],
        )
        response = client.get(
            f"/auth/callback?code=safe-code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 307
    assert response.headers["location"] == "http://localhost:8000"
    session_token = response.cookies.get(SESSION_COOKIE_NAME)
    assert session_token is not None
    payload = decode_session_token(session_token)
    assert payload["sub"] == "subject-123"
    assert payload["username"] == "testuser"
    assert payload["exp"] > payload["iat"]
    posted_form = token_route.calls[0].request.content.decode("utf-8")
    posted = parse_qs(posted_form)
    verifier = posted["code_verifier"][0]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert challenge == login_params["code_challenge"]


@pytest.mark.asyncio
async def test_callback_validates_oidc_access_token_hash(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        _mock_successful_token_exchange(
            respx_mock,
            nonce=login_params["nonce"],
            extra_claims={"at_hash": _access_token_hash()},
        )
        response = client.get(
            f"/auth/callback?code=safe-code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 307


@pytest.mark.asyncio
async def test_callback_rejects_oidc_access_token_hash_mismatch(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        _mock_successful_token_exchange(
            respx_mock,
            nonce=login_params["nonce"],
            extra_claims={"at_hash": "invalid-hash"},
        )
        response = client.get(
            f"/auth/callback?code=safe-code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.cookies.get(SESSION_COOKIE_NAME) is None


@pytest.mark.asyncio
async def test_callback_rejects_state_mismatch_before_token_exchange(client):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        _start_login(client)
        response = client.get(
            "/auth/callback?code=safe-code&state=attacker-state",
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Login transaction is invalid"
    assert response.cookies.get(SESSION_COOKIE_NAME) is None


@pytest.mark.asyncio
async def test_callback_rejects_missing_transaction(client):
    response = client.get(
        "/auth/callback?code=safe-code&state=some-state",
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Login transaction is missing"


@pytest.mark.asyncio
async def test_callback_rejects_token_exchange_failure(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        respx_mock.post(OIDC_CONFIG["token_endpoint"]).respond(status_code=400)
        response = client.get(
            f"/auth/callback?code=bad-code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authentication failed"


@pytest.mark.asyncio
async def test_callback_rejects_malformed_id_token(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        respx_mock.post(OIDC_CONFIG["token_endpoint"]).respond(
            json={"access_token": "token", "id_token": "bad.token"}
        )
        response = client.get(
            f"/auth/callback?code=code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.cookies.get(SESSION_COOKIE_NAME) is None


@pytest.mark.asyncio
async def test_callback_rejects_wrong_nonce(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        _mock_successful_token_exchange(respx_mock, nonce="wrong-nonce")
        response = client.get(
            f"/auth/callback?code=code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.cookies.get(SESSION_COOKIE_NAME) is None


@pytest.mark.asyncio
async def test_callback_rejects_expired_id_token(client, respx_mock):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        _mock_successful_token_exchange(
            respx_mock,
            nonce=login_params["nonce"],
            expires_at=int(time.time()) - 1,
        )
        response = client.get(
            f"/auth/callback?code=code&state={login_params['state']}",
            follow_redirects=False,
        )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_callback_uses_preferred_username_for_application_identity(
    client, respx_mock
):
    with patch(
        "dtvp.auth.get_oidc_config",
        new=AsyncMock(return_value=OIDC_CONFIG),
    ):
        login_params = _start_login(client)
        _mock_successful_token_exchange(
            respx_mock,
            nonce=login_params["nonce"],
            subject="stable-subject",
            preferred_username="reviewer-name",
        )
        response = client.get(
            f"/auth/callback?code=code&state={login_params['state']}",
            follow_redirects=False,
        )

    payload = decode_session_token(response.cookies[SESSION_COOKIE_NAME])
    assert payload["sub"] == "stable-subject"
    assert payload["username"] == "reviewer-name"


def test_frontend_target_does_not_duplicate_context_path():
    settings = AuthSettings(
        DTVP_ENVIRONMENT="test",
        DTVP_FRONTEND_URL="http://localhost/dtvp",
        DTVP_CONTEXT_PATH="/dtvp",
        DTVP_OIDC_REDIRECT_URI=None,
    )
    assert settings.frontend_target == "http://localhost/dtvp"
    assert settings.redirect_uri == "http://localhost/dtvp/auth/callback"


def test_redirect_uri_calculation_adds_context_path_once():
    settings = AuthSettings(
        DTVP_ENVIRONMENT="test",
        DTVP_FRONTEND_URL="http://base.url",
        DTVP_CONTEXT_PATH="ctx",
        DTVP_OIDC_REDIRECT_URI=None,
    )
    assert settings.redirect_uri == "http://base.url/ctx/auth/callback"


def test_validate_auth_configuration_rejects_weak_secret():
    settings = AuthSettings(
        DTVP_ENVIRONMENT="production",
        DTVP_OIDC_AUTHORITY="https://auth.example.com",
        DTVP_OIDC_CLIENT_ID="client",
        DTVP_OIDC_CLIENT_SECRET="client-secret",
        DTVP_OIDC_REDIRECT_URI="https://app.example.com/auth/callback",
        DTVP_FRONTEND_URL="https://app.example.com",
        DTVP_SESSION_SECRET_KEY="change_me",
    )
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        validate_auth_configuration(settings)


def test_validate_auth_configuration_rejects_dev_bypass_in_production():
    settings = AuthSettings(
        DTVP_ENVIRONMENT="production",
        DTVP_DEV_DISABLE_AUTH=True,
    )
    with pytest.raises(RuntimeError, match="cannot be enabled in production"):
        validate_auth_configuration(settings)


def test_production_cookie_is_secure():
    settings = AuthSettings(
        DTVP_ENVIRONMENT="production",
        DTVP_FRONTEND_URL="https://app.example.com",
    )
    assert settings.cookie_secure is True


def test_me_endpoint_accepts_only_complete_valid_session(client):
    token = create_session_token(subject="subject-123", username="testuser")
    client.cookies.set(SESSION_COOKIE_NAME, token)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

    client.cookies.clear()
    response = client.get("/auth/me")
    assert response.status_code == 401

    client.cookies.set(SESSION_COOKIE_NAME, "invalid.token.here")
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_session_rejects_expired_token():
    now = int(time.time())
    expired = jwt.encode(
        {
            "iss": SESSION_ISSUER,
            "aud": SESSION_AUDIENCE,
            "iat": now - 600,
            "exp": now - 300,
            "jti": str(uuid.uuid4()),
            "sub": "subject",
            "username": "testuser",
        },
        auth_settings.session_secret,
        algorithm=SESSION_ALGORITHM,
    )
    with pytest.raises(Exception):
        decode_session_token(expired)


def test_logout_is_post_only_and_clears_session(client):
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(subject="subject", username="testuser"),
    )
    response = client.post(
        "/auth/logout",
        headers={"Origin": "http://localhost:8000"},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}
    assert response.cookies.get(SESSION_COOKIE_NAME) is None

    # The SPA catch-all may serve GET /auth/logout, but it must not mutate the
    # session now that logout is a POST-only API action.
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(subject="subject", username="testuser"),
    )
    assert client.get("/auth/logout").status_code == 200
    assert client.get("/auth/me").status_code == 200


@pytest.mark.asyncio
async def test_get_oidc_config_no_authority():
    auth._oidc_config_cache = None
    with patch("dtvp.auth.auth_settings") as mock_settings:
        mock_settings.authority = ""
        with pytest.raises(HTTPException) as exc:
            await get_oidc_config()
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_get_current_user_dev_disable_auth():
    class DummyRequest:
        cookies = {}
        headers = {}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=True):
        assert await get_current_user(DummyRequest()) == "devuser"


@pytest.mark.asyncio
async def test_current_principal_preserves_subject_username_and_role():
    class DummyRequest:
        cookies = {
            SESSION_COOKIE_NAME: create_session_token(
                subject="stable-subject",
                username="alice",
            )
        }

    with patch("dtvp.auth.get_user_role", return_value="REVIEWER"):
        principal = await get_current_principal(DummyRequest())

    assert principal.subject == "stable-subject"
    assert principal.username == "alice"
    assert principal.role.value == "REVIEWER"


@pytest.mark.asyncio
async def test_get_current_user_rejects_request_without_dtvp_session():
    class DummyRequest:
        cookies = {}
        headers = {}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=False):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(DummyRequest())
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_ignores_dependency_track_identity_material():
    class DummyRequest:
        cookies = {
            "corporate_sso": "cookie-value",
            "dt_session": "legacy-dt-cookie",
            SESSION_COOKIE_NAME: "",
        }
        headers = {"Authorization": "Bearer dependency-track-token"}

    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", new=False):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(DummyRequest())
    assert exc.value.status_code == 401
