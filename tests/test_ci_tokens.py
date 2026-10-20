"""Long-lived CI tokens retain live permissions, scope, expiry and revocation."""

import json
import sys
from datetime import datetime, timedelta

import pytest
import respx
from sqlalchemy import select

from dtvp import auth
from dtvp.cli import main
from dtvp.models import Credential, Membership
from tests.conftest import login


def create(client, **changes):
    me = client.get("/api/v1/me").json()
    team = me["workspaces"][0]["id"]
    return client.post(
        "/api/v1/credentials",
        json={
            "workspace_id": team,
            "name": "Nightly CI",
            "capabilities": ["read", "write"],
            "hours": 24 * 365,
            **changes,
        },
    )


@pytest.mark.parametrize("days", [365, 3650])
def test_long_lived_token_imports_after_90_days_and_remains_project_scoped(
    client, app, bom, monkeypatch, days
):
    login(client, "administrator")
    team = client.get("/api/v1/me").json()["workspaces"][0]["id"]
    product_response = client.post(
        "/api/v1/projects/resolve", json={"project": "CI scoped product", "workspace_id": team}
    )
    assert product_response.status_code == 200, product_response.text
    product = product_response.json()
    response = create(client, hours=days * 24, projects=[product["id"]])
    assert response.status_code == 201, response.text
    token = response.json()
    assert (
        abs(
            (datetime.fromisoformat(token["expires_at"]) - auth.now()).total_seconds()
            - days * 86400
        )
        < 10
    )
    with app.state.sessions() as db:
        saved = db.get(Credential, token["id"])
        assert saved.token_hash != token["token"]
        assert saved.capabilities == ["read", "write"]
    original_now = auth.now
    monkeypatch.setattr(auth, "now", lambda: original_now() + timedelta(days=120))
    client.headers["Authorization"] = "Bearer " + token["token"]
    assert [item["id"] for item in client.get("/api/v1/projects").json()] == [product["id"]]
    assert client.get("/api/v1/me").json()["workspaces"][0]["capabilities"] == ["read", "write"]
    target = client.get(
        f"/api/v1/projects/{product['id']}/intake-target", params={"version": "1.0"}
    ).json()
    imported = client.post(
        f"/api/v1/projects/{product['id']}/versions/1.0/files",
        data={
            "metadata": json.dumps(
                {**target["defaults"], "request_id": "ci-upload", "expected": None}
            )
        },
        files={"file": ("bom.cdx.json", json.dumps(bom).encode(), "application/json")},
    )
    assert imported.status_code == 201, imported.text
    assert (
        client.post("/api/v1/projects/resolve", json={"project": "Outside CI scope"}).status_code
        == 403
    )
    listing = client.get("/api/v1/credentials")
    assert token["token"] not in listing.text and "token_hash" not in listing.text
    monkeypatch.setattr(auth, "now", lambda: original_now() + timedelta(days=days + 1))
    assert client.get("/api/v1/projects").status_code == 401


def test_long_lived_token_loses_removed_permissions_and_is_revocable(client, app):
    login(client, "administrator")
    owner = client.get("/api/v1/me").json()
    token = create(client).json()
    with app.state.sessions.begin() as db:
        membership = db.scalar(select(Membership).where(Membership.user_id == owner["id"]))
        original_roles = list(membership.roles)
        membership.roles = ["viewer"]
    client.headers["Authorization"] = "Bearer " + token["token"]
    assert client.get("/api/v1/me").json()["workspaces"][0]["capabilities"] == ["read"]
    assert (
        client.post("/api/v1/projects/resolve", json={"project": "No longer writable"}).status_code
        == 403
    )
    with app.state.sessions.begin() as db:
        db.scalar(
            select(Membership).where(Membership.user_id == owner["id"])
        ).roles = original_roles
    client.headers.pop("Authorization")
    assert client.delete("/api/v1/credentials/" + token["id"]).status_code == 204
    client.headers["Authorization"] = "Bearer " + token["token"]
    assert client.get("/api/v1/me").status_code == 401


def test_lifetime_bounds_and_minting_authority_are_retained(client):
    login(client, "administrator")
    assert create(client, hours=24 * 3650 + 1).status_code == 422
    assert create(client, hours=0).status_code == 422
    response = create(client)
    client.headers["Authorization"] = "Bearer " + response.json()["token"]
    # A CI token cannot create more tokens, even if its issuer is an administrator.
    assert create(client).status_code == 403


@respx.mock
def test_cli_token_listing_and_revocation_never_expose_secrets(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    prefix = ["dtvp", "knowledge", "--url", "http://dtvp.test", "advanced", "tokens"]
    row = {
        "id": "token-id",
        "name": "Nightly CI",
        "expires_at": "2027-10-20T00:00:00Z",
        "revoked": False,
        "capabilities": ["read", "write"],
        "projects": ["product-id"],
    }
    respx.get("http://dtvp.test/api/v1/credentials").respond(200, json=[row])
    monkeypatch.setattr(sys, "argv", [*prefix, "list"])
    main()
    assert "Nightly CI" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", [*prefix, "list", "--json"])
    main()
    assert json.loads(capsys.readouterr().out) == [row]
    route = respx.delete("http://dtvp.test/api/v1/credentials/token-id").respond(204)
    monkeypatch.setattr(sys, "argv", [*prefix, "revoke", "token-id"])
    main()
    assert route.called
    assert capsys.readouterr().out.strip() == "Token revoked."


def test_team_scoped_ci_token_can_create_new_product_implicitly(client):
    login(client, "administrator")
    token = create(client).json()
    client.headers["Authorization"] = "Bearer " + token["token"]
    team = client.get("/api/v1/me").json()["workspaces"][0]["id"]
    result = client.post("/api/v1/projects/resolve", json={"project": "CI-created product"})
    assert result.status_code == 200, result.text
    assert result.json()["created"] is True
    assert result.json()["workspace_id"] == team
