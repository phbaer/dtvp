"""Real Authlib code/PKCE flow and locally signed JWTs; no external IdP needed."""

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import func, select

from dtvp.config import Settings
from dtvp.main import create_app
from dtvp.models import Credential, Membership, User
from dtvp.oidc import AUTH_FAILURE

ISSUER = "https://idp.example.test"
PUBLIC = "https://dtvp.example.test"
CLIENT = "dtvp-client"
SECRET = "synthetic-client-secret-not-for-output"


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, parameters={"kid": "fixture-signing-key"})


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(
            _env_file=None,
            playground=True,
            database_url="sqlite:///:memory:",
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
            public_url=PUBLIC,
            oidc_issuer=ISSUER,
            oidc_client_id=CLIENT,
            oidc_client_secret=SECRET,
        )
    )


@pytest.fixture
def handshake(app, signing_key):
    with (
        respx.mock(assert_all_called=False) as router,
        TestClient(app, base_url=PUBLIC, follow_redirects=False) as client,
    ):
        router.get(ISSUER + "/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/jwks",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        )
        router.get(ISSUER + "/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [signing_key.as_dict(private=False)]})
        )
        state = {"claims": {}, "omit": [], "key": signing_key, "token_response": None}
        outgoing = []

        def token_response(request):
            params = parse_qs(request.content.decode())
            outgoing.append(params)
            assert params["code"] == ["synthetic-code"]
            assert params["redirect_uri"] == [PUBLIC + "/auth/callback"]
            assert params["grant_type"] == ["authorization_code"]
            verifier = params["code_verifier"][0]
            actual = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            assert actual == state["authorization"]["code_challenge"][0]
            if state["token_response"] is not None:
                return state["token_response"]
            now = int(time.time())
            claims = {
                "iss": ISSUER,
                "sub": "subject-1",
                "aud": CLIENT,
                "iat": now,
                "exp": now + 600,
                "nonce": state["authorization"]["nonce"][0],
                "name": "OIDC Person",
                **state["claims"],
            }
            for key in state["omit"]:
                claims.pop(key, None)
            encoded = jwt.encode(
                {"alg": "RS256", "kid": "fixture-signing-key"}, claims, state["key"]
            )
            return httpx.Response(
                200,
                json={
                    "access_token": "synthetic-access-token",
                    "token_type": "Bearer",
                    "id_token": encoded,
                },
            )

        endpoint = router.post(ISSUER + "/token").mock(side_effect=token_response)

        def start():
            login = client.get("/auth/login")
            assert login.status_code == 302, login.text
            parsed = urlsplit(login.headers["location"])
            assert parsed.scheme == "https" and parsed.netloc == "idp.example.test"
            authorization = parse_qs(parsed.query)
            assert authorization["response_type"] == ["code"]
            assert authorization["scope"] == ["openid profile"]
            assert authorization["client_id"] == [CLIENT]
            assert authorization["redirect_uri"] == [PUBLIC + "/auth/callback"]
            assert authorization["code_challenge_method"] == ["S256"]
            assert authorization["state"][0] and authorization["nonce"][0]
            state["authorization"] = authorization
            return authorization["state"][0]

        def finish(value=None):
            return client.get(
                "/auth/callback",
                params={
                    "code": "synthetic-code",
                    "state": value or state["authorization"]["state"][0],
                },
            )

        yield client, state, start, finish, endpoint, router


def identities(app):
    with app.state.sessions() as db:
        user = db.scalar(select(User).where(User.issuer == ISSUER))
        count = db.scalar(
            select(func.count()).select_from(Credential).join(User).where(User.issuer == ISSUER)
        )
        return user, count


def test_real_signed_login_unknown_identity_has_no_membership_and_pkce_nonce_are_bound(
    app, handshake
):
    client, state, start, finish, endpoint, _ = handshake
    state["claims"] = {"groups": ["admin"], "roles": ["admin"], "org_admin": True}
    start()
    result = finish()
    assert result.status_code == 307 and result.headers["location"] == "/", result.text
    assert endpoint.call_count == 1
    me = client.get("/api/v1/me")
    assert me.status_code == 200 and me.json()["name"] == "OIDC Person"
    assert me.json()["workspaces"] == [] and not me.json()["org_admin"]
    assert client.get("/api/v1/catalog/projects").json()["items"] == []
    user, count = identities(app)
    assert user and count == 1 and not user.org_admin
    with app.state.sessions() as db:
        assert (
            db.scalar(
                select(func.count()).select_from(Membership).where(Membership.user_id == user.id)
            )
            == 0
        )
    cookies = result.headers.get_list("set-cookie")
    session = next(value for value in cookies if value.startswith("dtvp_session="))
    csrf = next(value for value in cookies if value.startswith("dtvp_csrf="))
    assert "HttpOnly" in session and "Secure" in session and "SameSite=strict" in session
    assert "HttpOnly" not in csrf and "Secure" in csrf
    assert SECRET not in str(result.headers) and "synthetic-access-token" not in str(result.headers)
    again = finish()
    assert again.status_code == 403 and again.json()["detail"] == AUTH_FAILURE
    assert endpoint.call_count == 1 and identities(app)[1] == 1
    start()
    assert finish().status_code == 307
    assert identities(app)[0].id == user.id and identities(app)[1] == 2


@pytest.mark.parametrize(
    "claims,omit",
    [
        ({"iss": "https://untrusted.example.test"}, []),
        ({"aud": "another-client", "azp": CLIENT}, []),
        ({"aud": ["another-client"], "azp": CLIENT}, []),
        ({"aud": [CLIENT, "another-client"], "azp": "another-client"}, []),
        ({"exp": 1}, []),
        ({"iat": 9999999999}, []),
        ({"nonce": "another-nonce"}, []),
        ({"nonce": "another-nonce", "nonce_supported": False}, []),
        ({"nonce_supported": False}, ["nonce"]),
        ({}, ["aud"]),
        ({}, ["sub"]),
        ({}, ["exp"]),
        ({"sub": 7}, []),
        ({"sub": ["subject-1"]}, []),
        ({"iss": 7}, []),
        ({"aud": True}, []),
        ({"name": None}, []),
        ({"iat": "not-a-date"}, []),
        ({"nonce": ["wrong-nonce"], "nonce_supported": False}, []),
        ({"sub": ""}, []),
        ({"sub": "x" * 256}, []),
        ({"sub": "subject\nforged"}, []),
        ({"name": {"raw": SECRET}}, []),
        ({"name": "x" * 201}, []),
        ({"name": "Name\nforged"}, []),
    ],
)
def test_invalid_signed_claims_never_create_user_or_credentials(app, handshake, claims, omit):
    client, state, start, finish, endpoint, _ = handshake
    state["claims"], state["omit"] = claims, omit
    start()
    result = finish()
    assert result.status_code == 403, result.text
    assert result.json()["detail"] == AUTH_FAILURE
    assert not client.cookies.get("dtvp_session")
    assert identities(app) == (None, 0)
    assert endpoint.call_count == 1
    assert SECRET not in result.text and "another-client" not in result.text


def test_different_signature_is_rejected(app, handshake):
    _, state, start, finish, endpoint, _ = handshake
    state["key"] = RSAKey.generate_key(2048, parameters={"kid": "fixture-signing-key"})
    start()
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0) and endpoint.call_count == 1


@pytest.mark.parametrize(
    "variant", ["wrong-state", "missing-state", "tampered-cookie", "provider-error"]
)
def test_state_or_provider_error_fails_before_token_exchange(app, handshake, variant):
    client, _, start, finish, endpoint, _ = handshake
    start()
    if variant == "wrong-state":
        result = finish("wrong-state")
    elif variant == "missing-state":
        result = client.get("/auth/callback", params={"code": "synthetic-code"})
    elif variant == "tampered-cookie":
        client.cookies.clear()
        client.cookies.set("session", "forged.invalid.signature")
        result = finish()
    else:
        result = client.get(
            "/auth/callback", params={"error": "access_denied", "error_description": SECRET}
        )
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert endpoint.call_count == 0 and identities(app) == (None, 0)
    assert SECRET not in result.text


@pytest.mark.parametrize(
    "body",
    [
        {"access_token": "synthetic-access-token", "token_type": "Bearer"},
        {"error": "invalid_grant", "error_description": SECRET},
        [SECRET],
        {"access_token": "synthetic-access-token", "token_type": "Bearer", "id_token": [SECRET]},
        {"access_token": "synthetic-access-token", "token_type": "Bearer", "id_token": None},
        {
            "access_token": "synthetic-access-token",
            "token_type": "Bearer",
            "userinfo": {"iss": ISSUER, "sub": "forged"},
        },
    ],
)
def test_missing_id_token_and_provider_payload_errors_are_sanitized(app, handshake, body):
    _, state, start, finish, _, _ = handshake
    state["token_response"] = httpx.Response(200, json=body)
    start()
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0)
    assert SECRET not in result.text


def test_revoked_session_is_denied_after_valid_oidc_login(app, handshake):
    client, _, start, finish, _, _ = handshake
    start()
    assert finish().status_code == 307
    user, _ = identities(app)
    with app.state.sessions.begin() as db:
        credential = db.scalar(select(Credential).where(Credential.user_id == user.id))
        credential.revoked = True
    assert client.get("/api/v1/me").status_code == 401


@pytest.mark.parametrize("failure", ["http", "timeout", "malformed-json"])
def test_provider_transport_and_json_failures_never_expose_provider_details(
    app, handshake, failure
):
    _, state, start, finish, endpoint, _ = handshake
    start()
    if failure == "http":
        state["token_response"] = httpx.Response(503, text=SECRET)
    elif failure == "malformed-json":
        state["token_response"] = httpx.Response(200, content=("not JSON " + SECRET).encode())
    else:
        endpoint.mock(side_effect=httpx.ReadTimeout(SECRET))
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0) and SECRET not in result.text


def test_discovery_failure_is_sanitized_and_creates_no_credentials(app, handshake):
    client, _, _, _, _, router = handshake
    router.get(ISSUER + "/.well-known/openid-configuration").mock(
        return_value=httpx.Response(503, text=SECRET)
    )
    result = client.get("/auth/login")
    assert (
        result.status_code == 503 and result.json()["detail"] == "Sign-in provider is unavailable"
    )
    assert SECRET not in result.text and identities(app) == (None, 0)


def test_missing_configuration_retains_disabled_routes(client, app):
    app.state.settings.oidc_issuer = ""
    assert client.get("/auth/login").status_code == 503
    assert client.get("/auth/callback").status_code == 404


def test_provider_nonce_flag_cannot_accept_an_array_claim_even_if_it_contains_requested_nonce(
    app, handshake
):
    _, state, start, finish, _, _ = handshake
    start()
    state["claims"] = {"nonce": [state["authorization"]["nonce"][0]], "nonce_supported": False}
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0)


@pytest.mark.parametrize("body", [[], 123, {}, {"issuer": ISSUER}])
def test_malformed_discovery_fails_with_generic_provider_unavailable(app, handshake, body):
    client, _, _, _, _, router = handshake
    router.get(ISSUER + "/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=body)
    )
    result = client.get("/auth/login")
    assert (
        result.status_code == 503 and result.json()["detail"] == "Sign-in provider is unavailable"
    )
    assert identities(app) == (None, 0)


@pytest.mark.parametrize(
    "body",
    [
        [],
        123,
        {},
        {"keys": [None]},
        {"keys": [{"kty": [SECRET]}]},
        {"keys": [{"kty": "RSA", "n": [SECRET], "e": "AQAB"}]},
    ],
)
def test_malformed_jwks_fails_before_credentials_without_reflection(app, handshake, body):
    _, _, start, finish, _, router = handshake
    router.get(ISSUER + "/jwks").mock(return_value=httpx.Response(200, json=body))
    start()
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0) and SECRET not in result.text


def test_missing_jwks_configuration_is_a_sanitized_callback_failure(app, handshake):
    _, _, start, finish, _, router = handshake
    router.get(ISSUER + "/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
            },
        )
    )
    start()
    result = finish()
    assert result.status_code == 403 and result.json()["detail"] == AUTH_FAILURE
    assert identities(app) == (None, 0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorization_endpoint", "javascript:alert(1)"),
        ("token_endpoint", "https://user:secret@idp.example.test/token"),
        ("jwks_uri", "file:///tmp/keys.json"),
        ("id_token_signing_alg_values_supported", ["none"]),
    ],
)
def test_unsafe_provider_endpoints_and_unsigned_id_tokens_are_not_enabled(
    app, handshake, field, value
):
    client, _, _, _, _, router = handshake
    metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        field: value,
    }
    router.get(ISSUER + "/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=metadata)
    )
    result = client.get("/auth/login")
    assert (
        result.status_code == 503 and result.json()["detail"] == "Sign-in provider is unavailable"
    )
    assert identities(app) == (None, 0)
