import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from jose import jwt

from test_setup import mock_dt


def pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def test_mock_dt_can_override_analysis_state():
    client = TestClient(mock_dt.app)
    params = {
        "project": mock_dt.PROJECT_UUID,
        "component": mock_dt.COMPONENT_UUID,
        "vulnerability": mock_dt.VULN_UUID_1,
    }

    original = client.get("/api/v1/analysis", params=params)
    assert original.status_code == 200
    assert original.json()["analysisState"] != "NOT_AFFECTED"

    override_response = client.post(
        "/api/v1/mock/analysis",
        json={
            "project": mock_dt.PROJECT_UUID,
            "component": mock_dt.COMPONENT_UUID,
            "vulnerability": mock_dt.VULN_UUID_1,
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Simulated conflict state",
        },
    )

    assert override_response.status_code == 200
    assert override_response.json()["analysisState"] == "NOT_AFFECTED"
    assert override_response.json()["analysisDetails"] == "Simulated conflict state"

    updated = client.get("/api/v1/analysis", params=params)
    assert updated.status_code == 200
    assert updated.json()["analysisState"] == "NOT_AFFECTED"
    assert updated.json()["analysisDetails"] == "Simulated conflict state"


def test_mock_dt_can_reset_analysis_state():
    client = TestClient(mock_dt.app)
    params = {
        "project": mock_dt.PROJECT_UUID,
        "component": mock_dt.COMPONENT_UUID,
        "vulnerability": mock_dt.VULN_UUID_1,
    }

    client.post(
        "/api/v1/mock/analysis",
        json={
            "project": mock_dt.PROJECT_UUID,
            "component": mock_dt.COMPONENT_UUID,
            "vulnerability": mock_dt.VULN_UUID_1,
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Temporary state",
        },
    )

    reset_response = client.post("/api/v1/mock/analysis/reset")
    assert reset_response.status_code == 200
    assert reset_response.json()["status"] == "reset"

    restored = client.get("/api/v1/analysis", params=params)
    assert restored.status_code == 200
    assert restored.json()["analysisState"] != "NOT_AFFECTED"
    assert restored.json()["analysisDetails"] != "Temporary state"


def test_mock_oidc_requires_matching_pkce_verifier():
    client = TestClient(mock_dt.app)
    code_verifier = "a" * 64
    challenge = pkce_challenge(code_verifier)
    authorize_response = client.get(
        "/auth/authorize",
        params={
            "client_id": "mock_id",
            "redirect_uri": "http://localhost/auth/callback",
            "state": "mock-state",
            "response_type": "code",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize_response.status_code == 200

    authorize_post = client.post(
        "/auth/authorize",
        data={
            "username": "reviewer",
            "redirect_uri": "http://localhost/auth/callback",
            "client_id": "mock_id",
            "state": "mock-state",
            "nonce": "mock-nonce",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    callback_params = parse_qs(urlparse(authorize_post.headers["location"]).query)

    token_response = client.post(
        "/auth/token",
        data={
            "code": callback_params["code"][0],
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost/auth/callback",
            "client_id": "mock_id",
            "client_secret": "mock_secret",
            "code_verifier": code_verifier,
        },
    )

    assert callback_params["state"] == ["mock-state"]
    assert token_response.status_code == 200
    claims = jwt.decode(
        token_response.json()["id_token"],
        mock_dt._OIDC_PUBLIC_JWK,
        algorithms=["RS256"],
        audience="mock_id",
        issuer="http://testserver",
    )
    assert claims["sub"] == "reviewer"
    assert claims["nonce"] == "mock-nonce"


def test_mock_oidc_rejects_wrong_pkce_verifier():
    client = TestClient(mock_dt.app)
    code_verifier = "b" * 64
    authorize_post = client.post(
        "/auth/authorize",
        data={
            "username": "analyst",
            "redirect_uri": "http://localhost/auth/callback",
            "client_id": "mock_id",
            "state": "mock-state",
            "nonce": "mock-nonce",
            "code_challenge": pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlparse(authorize_post.headers["location"]).query)["code"][0]

    token_response = client.post(
        "/auth/token",
        data={
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost/auth/callback",
            "client_id": "mock_id",
            "code_verifier": "wrong-" + code_verifier,
        },
    )

    assert token_response.status_code == 400
    assert token_response.json()["detail"] == "Invalid PKCE code verifier"
