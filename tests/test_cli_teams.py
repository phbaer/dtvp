"""Team CLI transport, explicit role replacement and server authorization."""

import json
import sys

import pytest
import respx

from dtvp.cli import main
from tests.conftest import login


def invoke(monkeypatch, *arguments):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", ["dtvp", "knowledge", "--url", "http://dtvp.test", *arguments])
    main()


@respx.mock
def test_create_team_with_administrator_session(monkeypatch, capsys):
    monkeypatch.setenv("TEST_SESSION", "session-secret")
    monkeypatch.setenv("DTVP_CSRF_TOKEN", "csrf-secret")
    route = respx.post("http://dtvp.test/api/v1/workspaces").respond(
        201, json={"id": "platform", "name": "Platform"}
    )
    invoke(monkeypatch, "--session-env", "TEST_SESSION", "teams", "create", "--name", "Platform")
    request = route.calls.last.request
    assert json.loads(request.content) == {"name": "Platform"}
    assert "dtvp_session=session-secret" in request.headers["cookie"]
    assert request.headers["X-CSRF-Token"] == "csrf-secret"
    assert capsys.readouterr().out.strip() == "platform  Platform"
    assert route.call_count == 1


@respx.mock
def test_list_alias_and_member_identity_output(monkeypatch, capsys):
    respx.get("http://dtvp.test/api/v1/workspaces").respond(
        200, json=[{"id": "platform", "name": "Platform"}]
    )
    invoke(monkeypatch, "teams", "list")
    assert "platform  Platform" in capsys.readouterr().out
    members = [
        {
            "user_id": "alice",
            "name": "Alice",
            "issuer": "https://idp.test",
            "subject": "alice-subject",
            "roles": ["analyst", "reviewer"],
        }
    ]
    respx.get("http://dtvp.test/api/v1/workspaces/platform/members").respond(200, json=members)
    invoke(monkeypatch, "teams", "members", "--team", "platform")
    text = capsys.readouterr().out
    assert "issuer=https://idp.test" in text and "subject=alice-subject" in text
    assert "roles=analyst,reviewer" in text
    invoke(monkeypatch, "teams", "members", "--team", "platform", "--json")
    assert json.loads(capsys.readouterr().out) == members


@respx.mock
def test_assign_sends_exact_identity_and_replacement_roles(monkeypatch, capsys):
    route = respx.put("http://dtvp.test/api/v1/workspaces/platform/members").respond(
        200, json={"user_id": "alice", "roles": ["analyst", "reviewer"]}
    )
    invoke(
        monkeypatch,
        "teams",
        "assign",
        "--team",
        "platform",
        "--issuer",
        "https://idp.test",
        "--subject",
        "alice-subject",
        "--name",
        "Alice",
        "--role",
        "analyst",
        "--role",
        "reviewer",
        "--role",
        "analyst",
        "--json",
    )
    assert json.loads(route.calls.last.request.content) == {
        "issuer": "https://idp.test",
        "subject": "alice-subject",
        "name": "Alice",
        "roles": ["analyst", "reviewer"],
    }
    assert json.loads(capsys.readouterr().out)["roles"] == ["analyst", "reviewer"]
    assert route.call_count == 1


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
def test_team_creation_reports_denial_without_retry(monkeypatch, capsys, status):
    route = respx.post("http://dtvp.test/api/v1/workspaces").respond(
        status, json={"detail": "Not authorized"}
    )
    with pytest.raises(SystemExit) as error:
        invoke(monkeypatch, "teams", "create", "--name", "Platform")
    assert error.value.code == 1
    assert f"HTTP {status}: Not authorized" in capsys.readouterr().err
    assert route.call_count == 1


@pytest.mark.parametrize("roles", [[], ["--role", "invalid"]])
def test_assign_requires_explicit_valid_roles(monkeypatch, roles):
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch,
            "teams",
            "assign",
            "--team",
            "platform",
            "--issuer",
            "issuer",
            "--subject",
            "subject",
            "--name",
            "Alice",
            *roles,
        )
    assert error.value.code == 2


@respx.mock
def test_member_listing_empty(monkeypatch, capsys):
    respx.get("http://dtvp.test/api/v1/workspaces/platform/members").respond(200, json=[])
    invoke(monkeypatch, "teams", "members", "--team", "platform")
    assert capsys.readouterr().out.strip() == "No members."


def test_backend_team_creation_and_role_replacement(client):
    login(client, "administrator")
    created = client.post("/api/v1/workspaces", json={"name": "CLI team"})
    assert created.status_code == 201
    path = f"/api/v1/workspaces/{created.json()['id']}/members"
    assert client.get(path).json()[0]["roles"] == ["admin"]
    member = {
        "issuer": "https://idp.test",
        "subject": "alice",
        "name": "Alice",
        "roles": ["analyst", "reviewer"],
    }
    first = client.put(path, json=member)
    assert first.status_code == 200
    second = client.put(path, json={**member, "roles": ["viewer"]})
    assert second.status_code == 200
    assert second.json()["user_id"] == first.json()["user_id"]
    assert [m["roles"] for m in client.get(path).json() if m["subject"] == "alice"] == [["viewer"]]
    login(client, "analyst")
    assert client.get(path).status_code == 403
    assert client.put(path, json=member).status_code == 403
    assert client.post("/api/v1/workspaces", json={"name": "Denied"}).status_code == 403
