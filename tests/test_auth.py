import pytest
from jose import jwt
from auth import auth_settings
from main import app, get_current_user


@pytest.fixture(autouse=True)
def use_real_auth(client):
    from main import get_current_user_token_payload

    overrides = app.dependency_overrides
    if get_current_user in overrides:
        del overrides[get_current_user]
    if get_current_user_token_payload in overrides:
        del overrides[get_current_user_token_payload]
    yield


@pytest.mark.asyncio
async def test_login_redirect(client, respx_mock):
    # Mock OIDC configuration discovery
    respx_mock.get("https://oidc.example.com/.well-known/openid-configuration").respond(
        status_code=200,
        json={
            "authorization_endpoint": "https://oidc.example.com/auth",
            "token_endpoint": "https://oidc.example.com/token",
        },
    )

    # Set auth authority for test
    auth_settings.OIDC_AUTHORITY = "https://oidc.example.com"
    auth_settings.OIDC_CLIENT_ID = "client-id"

    response = client.get("/auth/login", follow_redirects=False)

    assert response.status_code == 307
    assert "https://oidc.example.com/auth" in response.headers["location"]
    assert "client_id=client-id" in response.headers["location"]
    assert "redirect_uri=" in response.headers["location"]


@pytest.mark.asyncio
async def test_oidc_callback_success(client, respx_mock):
    # Mock OIDC configuration
    respx_mock.get("https://oidc.example.com/.well-known/openid-configuration").respond(
        status_code=200,
        json={
            "authorization_endpoint": "https://oidc.example.com/auth",
            "token_endpoint": "https://oidc.example.com/token",
        },
    )

    # Mock Token Endpoint
    id_token = jwt.encode(
        {"sub": "oidc-user", "preferred_username": "jdoe", "email": "jdoe@example.com"},
        "secret",
        algorithm="HS256",
    )
    access_token = "mock-access-token"

    respx_mock.post("https://oidc.example.com/token").respond(
        status_code=200,
        json={
            "id_token": id_token,
            "access_token": access_token,
        },
    )

    auth_settings.OIDC_AUTHORITY = "https://oidc.example.com"

    response = client.get("/auth/callback?code=mock-code", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "/"  # Redirect to dashboard

    # Verify Session
    cookie = response.cookies.get("session_token")
    assert cookie is not None

    payload = jwt.decode(cookie, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"])
    assert payload["sub"] == "jdoe"
    assert payload["dt_token"] == access_token


def test_logout(client):
    # Set a cookie
    client.cookies.set("session_token", "fake")
    response = client.post("/auth/logout")
    assert response.status_code == 200

    # Verify Set-Cookie header instructs deletion
    assert "set-cookie" in response.headers
    # Starlette delete_cookie sets max-age=0 or expires in past
    assert (
        'session_token="";' in response.headers["set-cookie"]
        or "Max-Age=0" in response.headers["set-cookie"]
    )


def test_me_endpoint(client):
    token = jwt.encode(
        {"sub": "testuser", "dt_token": "token"},
        auth_settings.SESSION_SECRET_KEY,
        algorithm="HS256",
    )
    client.cookies.set("session_token", token)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
