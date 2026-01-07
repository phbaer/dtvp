import pytest
from unittest.mock import AsyncMock, patch
from jose import jwt
from auth import auth_settings, get_oidc_config
from main import app, get_current_user

@pytest.fixture(autouse=True)
def use_real_auth():
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]
    yield
async def test_get_oidc_config(respx_mock):
    # Mocking httpx call via respx
    config_url = f"{auth_settings.authority.rstrip('/')}/.well-known/openid-configuration"
    respx_mock.get(config_url).respond(json={
        "authorization_endpoint": "https://auth.example.com/login",
        "token_endpoint": "https://auth.example.com/token"
    })
    
    # Clear cache if any
    import auth
    auth._oidc_config_cache = None
    
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
        mock_config.return_value = {
            "token_endpoint": "https://auth.example.com/token"
        }
        
        # Mock token response
        respx_mock.post("https://auth.example.com/token").respond(json={
            "id_token": jwt.encode({"sub": "testuser", "email": "test@example.com"}, "secret", algorithm="HS256")
        })
        
        response = client.get("/auth/callback?code=fairly-safe-code", follow_redirects=False)
        assert response.status_code == 307 # Redirect to dashboard
        assert response.cookies.get("session_token") is not None


@pytest.mark.asyncio
async def test_callback_failure(client, respx_mock):
    with patch("auth.get_oidc_config", new_callable=AsyncMock) as mock_config:
        mock_config.return_value = {
            "token_endpoint": "https://auth.example.com/token"
        }
        
        # Mock token response failure
        respx_mock.post("https://auth.example.com/token").respond(status_code=400)
        
        response = client.get("/auth/callback?code=bad-code", follow_redirects=False)
        assert response.status_code == 400

def test_me_endpoint(client):
    # Success case
    token = jwt.encode({"sub": "testuser"}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256")
    
    # Set cookie on client instance instead of per-request
    client.cookies.set("session_token", token)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    
    # Failure case
    client.cookies.clear() # Clear persisted cookies
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
        DTVP_CONTEXT_PATH="ctx"
    )
    assert settings.redirect_uri == "http://base.url/ctx/auth/callback"

    # Test explicit set
    settings = AuthSettings(
        DTVP_OIDC_REDIRECT_URI="http://custom/callback"
    )
    assert settings.redirect_uri == "http://custom/callback"
