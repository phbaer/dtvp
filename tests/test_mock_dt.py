import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import jwt
from fastapi.testclient import TestClient

from test_setup import mock_dt


def test_mock_oidc_provider_supports_nonce_pkce_and_jwks():
    client = TestClient(mock_dt.app)
    verifier = "mock-code-verifier-that-is-long-enough-for-pkce-1234567890"
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    params = {
        "client_id": "mock-client",
        "redirect_uri": "http://localhost/auth/callback",
        "state": "expected-state",
        "nonce": "expected-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    authorize = client.get("/auth/authorize", params=params)
    assert authorize.status_code == 200
    assert 'name="nonce" value="expected-nonce"' in authorize.text

    approved = client.post(
        "/auth/authorize",
        data={**params, "username": "reviewer"},
        follow_redirects=False,
    )
    assert approved.status_code == 303
    callback_query = parse_qs(urlparse(approved.headers["location"]).query)
    assert callback_query["state"] == ["expected-state"]

    token = client.post(
        "/auth/token",
        data={
            "code": callback_query["code"][0],
            "grant_type": "authorization_code",
            "redirect_uri": params["redirect_uri"],
            "client_id": params["client_id"],
            "client_secret": "mock-secret",
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200
    jwks = client.get("/auth/jwks").json()
    claims = jwt.decode(
        token.json()["id_token"],
        jwt.PyJWK.from_dict(jwks["keys"][0]),
        algorithms=["RS256"],
        issuer="http://testserver",
        audience="mock-client",
    )
    assert claims["sub"] == "reviewer"
    assert claims["nonce"] == "expected-nonce"


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
