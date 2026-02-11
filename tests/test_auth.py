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
    assert "response_type=id_token+token" in response.headers["location"]
    assert "nonce=" in response.headers["location"]
    # Ensure PKCE is gone
    assert "code_challenge=" not in response.headers["location"]

    # Verify cookie is set
    assert "oidc_nonce" in response.cookies


@pytest.mark.asyncio
async def test_implicit_callback_post(client, respx_mock):
    # Mock DT User Teams call
    respx_mock.get(f"{auth_settings.FRONTEND_URL}/api/v1/team/self").respond(
        status_code=200, json=[]
    )

    # We need to trust the ID token, so we'll mock jwt.get_unverified_claims in the app??
    # Actually checking logic calls jwt.get_unverified_claims, so we can just pass a real JWT structure
    # that doesn't need to be signed by a real key for this test since we skip sig verification
    # ALTHOUGH the code uses get_unverified_claims which ignores signature.

    nonce = "mock-nonce"
    id_token = jwt.encode(
        {"sub": "jdoe", "preferred_username": "jdoe", "nonce": nonce},
        "secret",
        algorithm="HS256",
    )
    access_token = "mock-access-token"

    auth_settings.OIDC_AUTHORITY = "https://oidc.example.com"

    # Simulate cookie set by login
    client.cookies.set("oidc_nonce", nonce)

    response = client.post(
        "/auth/implicit-callback",
        json={"id_token": id_token, "access_token": access_token},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "success"}

    # Verify Session
    cookie = response.cookies.get("session_token")
    assert cookie is not None

    payload = jwt.decode(cookie, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"])
    assert payload["sub"] == "jdoe"
    assert payload["dt_token"] == access_token


@pytest.mark.asyncio
async def test_implicit_callback_invalid_nonce(client):
    # Test mismatch nonce
    nonce = "correct-nonce"
    bad_nonce = "bad-nonce"

    id_token = jwt.encode(
        {"sub": "jdoe", "nonce": bad_nonce}, "secret", algorithm="HS256"
    )

    client.cookies.set("oidc_nonce", nonce)

    response = client.post(
        "/auth/implicit-callback", json={"id_token": id_token, "access_token": "at"}
    )

    assert response.status_code == 400
    assert "Invalid Nonce" in response.json()["detail"]


@pytest.mark.asyncio
async def test_implicit_callback_missing_cookie(client):
    id_token = jwt.encode({"sub": "jdoe"}, "secret", algorithm="HS256")
    response = client.post(
        "/auth/implicit-callback", json={"id_token": id_token, "access_token": "at"}
    )
    assert response.status_code == 400
    assert "Missing OIDC nonce" in response.json()["detail"]


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
