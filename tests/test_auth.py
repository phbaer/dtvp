import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from jose import jwt
from auth import auth_settings, get_oidc_config
from main import app, get_current_user


@pytest.fixture(autouse=True)
def use_real_auth():
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]
    with patch("auth.auth_settings.DEV_DISABLE_AUTH", False):
        yield


async def test_get_oidc_config(respx_mock):
    # Mocking httpx call via respx
    mock_authority = "https://auth.example.com"
    config_url = f"{mock_authority}/.well-known/openid-configuration"
    respx_mock.get(config_url).respond(
        json={
            "authorization_endpoint": "https://auth.example.com/login",
            "token_endpoint": "https://auth.example.com/token",
        }
    )

    # Clear cache if any
    import auth

    auth._oidc_config_cache = None

    with patch.object(auth_settings, "OIDC_AUTHORITY", mock_authority):
        config = await get_oidc_config()
        assert config["authorization_endpoint"] == "https://auth.example.com/login"

        # Test cache
        config2 = await get_oidc_config()
        assert config2 is config


def test_login_redirect(client):
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {
            "authorization_endpoint": "https://auth.example.com/login"
        }

        response = client.get("/auth/login", follow_redirects=False)
        assert response.status_code == 307
        assert "https://auth.example.com/login" in response.headers["location"]


@pytest.mark.asyncio
async def test_callback_success(client, respx_mock):
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {"token_endpoint": "https://auth.example.com/token"}

        # Mock token response
        respx_mock.post("https://auth.example.com/token").respond(
            json={
                "id_token": jwt.encode(
                    {"sub": "testuser", "email": "test@example.com"},
                    "secret",
                    algorithm="HS256",
                )
            }
        )

        response = client.get(
            "/auth/callback?code=fairly-safe-code", follow_redirects=False
        )
        assert response.status_code == 307  # Redirect to dashboard
        assert response.cookies.get("session_token") is not None


@pytest.mark.asyncio
async def test_callback_failure(client, respx_mock):
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {"token_endpoint": "https://auth.example.com/token"}

        # Mock token response failure
        respx_mock.post("https://auth.example.com/token").respond(status_code=400)

        response = client.get("/auth/callback?code=bad-code", follow_redirects=False)
        assert response.status_code == 400


def test_me_endpoint(client):
    with patch("auth.auth_settings.DEV_DISABLE_AUTH", new=False):
        # Success case
        token = jwt.encode(
            {"sub": "testuser"}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256"
        )

        # Set cookie on client instance instead of per-request
        client.cookies.set("session_token", token)
        response = client.get("/auth/me")
        assert response.status_code == 200
        assert response.json()["username"] == "testuser"

        # Failure case
        client.cookies.clear()  # Clear persisted cookies
        response = client.get("/auth/me")
        assert response.status_code == 401

        # Invalid token case
        client.cookies.set("session_token", "invalid.token.here")
        response = client.get("/auth/me")
        assert response.status_code == 401


def test_redirect_uri_calculation():
    from auth import AuthSettings

    # Test fallback calculation
    settings = AuthSettings(
        DTVP_OIDC_REDIRECT_URI=None,
        DTVP_FRONTEND_URL="http://base.url",
        DTVP_CONTEXT_PATH="ctx",
    )
    assert settings.redirect_uri == "http://base.url/ctx/auth/callback"

    # Test explicit set
    settings = AuthSettings(DTVP_OIDC_REDIRECT_URI="http://custom/callback")
    assert settings.redirect_uri == "http://custom/callback"


@pytest.mark.asyncio
async def test_get_oidc_config_no_authority():
    import auth

    auth._oidc_config_cache = None
    with patch("auth.auth_settings") as mock_settings:
        mock_settings.authority = ""
        with pytest.raises(HTTPException) as exc:
            await get_oidc_config()
        assert exc.value.status_code == 500
        assert exc.value.detail == "OIDC Authority not configured"


@pytest.mark.asyncio
async def test_callback_claim_error(client, respx_mock):
    # Mock config and token response
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {"token_endpoint": "https://auth.example.com/token"}

        respx_mock.post("https://auth.example.com/token").respond(
            json={"id_token": "bad.token"}
        )

        # Mock jwt.get_unverified_claims to raise exception
        with patch("jose.jwt.get_unverified_claims", side_effect=Exception("Explode")):
            response = client.get("/auth/callback?code=code", follow_redirects=False)
            assert response.status_code == 307

            # Check session token contains "user" as username
            cookie = response.cookies.get("session_token")
            payload = jwt.decode(
                cookie, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"]
            )
            assert payload["sub"] == "user"


@pytest.mark.asyncio
async def test_callback_context_path_slashes(client, respx_mock):
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {"token_endpoint": "https://auth.example.com/token"}

        respx_mock.post("https://auth.example.com/token").respond(
            json={"id_token": jwt.encode({"sub": "me"}, "secret", algorithm="HS256")}
        )

        # Mock settings to have path without slash
        with patch("auth.auth_settings.CONTEXT_PATH", new="mycontext"):
            response = client.get("/auth/callback?code=code", follow_redirects=False)
            assert response.status_code == 307
            assert "/mycontext" in response.headers["location"]


@pytest.mark.asyncio
async def test_callback_claim_priority(client, respx_mock):
    # Mock config and token response
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {"token_endpoint": "https://auth.example.com/token"}

        # Mock token response with all claims
        respx_mock.post("https://auth.example.com/token").respond(
            json={
                "id_token": jwt.encode(
                    {
                        "sub": "sub_user",
                        "preferred_username": "pref_user",
                        "email": "email@example.com",
                    },
                    "secret",
                    algorithm="HS256",
                )
            }
        )

        response = client.get(
            "/auth/callback?code=fairly-safe-code", follow_redirects=False
        )
        assert response.status_code == 307

        cookie = response.cookies.get("session_token")
        assert cookie is not None

        payload = jwt.decode(
            cookie, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"]
        )
        assert payload["sub"] == "sub_user"
