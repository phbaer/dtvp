from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.access_token_services import (
    MAX_ACTIVE_TOKENS_PER_USER,
    AccessTokenError,
    AccessTokenStore,
    access_token_store,
    forwardable_bearer,
)


@pytest.fixture
def store(tmp_path):
    return AccessTokenStore(str(tmp_path / "tokens.sqlite"))


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")


@pytest.fixture
def session(client):
    main.app.dependency_overrides[main.get_session_user] = lambda: "alice"
    yield client


def _bearer(plain):
    return {"Authorization": f"Bearer {plain}"}


# --- store ---------------------------------------------------------------


def test_create_returns_plain_value_once_and_stores_only_a_digest(store):
    record, plain = store.create(username="alice", name="  my   agent ", scopes=["read"])

    assert plain.startswith("dtvp_pat_")
    assert record.name == "my agent"
    assert record.scopes == ("read",)
    assert plain.encode() not in open(store.path, "rb").read()
    assert store.verify(plain).token_id == record.token_id
    assert [t.token_id for t in store.list_for_user("alice")] == [record.token_id]
    assert store.list_for_user("bob") == []


def test_write_scope_implies_read(store):
    record, _plain = store.create(username="alice", name="a", scopes=["write"])
    assert record.scopes == ("read", "write")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "scopes": ["read"]},
        {"name": "x" * 101, "scopes": ["read"]},
        {"name": "a", "scopes": []},
        {"name": "a", "scopes": ["admin"]},
        {"name": "a", "scopes": ["read"], "expires_in_days": 0},
        {"name": "a", "scopes": ["read"], "expires_in_days": 366},
        {"name": "a", "scopes": ["read"], "expires_in_days": True},
    ],
)
def test_create_rejects_invalid_requests(store, kwargs):
    with pytest.raises(AccessTokenError):
        store.create(username="alice", **kwargs)


def test_verify_rejects_unknown_tampered_expired_and_revoked_tokens(store):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    record, plain = store.create(
        username="alice", name="a", scopes=["read"], expires_in_days=1, now=now
    )

    assert store.verify("dtvp_pat_unknown", now=now) is None
    assert store.verify(plain + "x", now=now) is None
    assert store.verify("not-a-token", now=now) is None
    assert store.verify(plain, now=now + timedelta(hours=23)) is not None
    assert store.verify(plain, now=now + timedelta(days=1)) is None

    assert store.revoke(username="bob", token_id=record.token_id) is False
    assert store.verify(plain, now=now) is not None
    assert store.revoke(username="alice", token_id=record.token_id) is True
    assert store.verify(plain, now=now) is None


def test_last_used_is_recorded(store):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    _record, plain = store.create(username="alice", name="a", scopes=["read"], now=now)
    assert store.list_for_user("alice")[0].last_used_at is None
    store.verify(plain, now=now + timedelta(minutes=5))
    assert store.list_for_user("alice")[0].last_used_at == (
        now + timedelta(minutes=5)
    ).isoformat()


def test_active_token_limit_ignores_revoked_tokens(store):
    records = [
        store.create(username="alice", name=f"t{i}", scopes=["read"])[0]
        for i in range(MAX_ACTIVE_TOKENS_PER_USER)
    ]
    with pytest.raises(AccessTokenError):
        store.create(username="alice", name="extra", scopes=["read"])
    store.revoke(username="alice", token_id=records[0].token_id)
    store.create(username="alice", name="extra", scopes=["read"])


def test_audit_entries_are_listed_newest_first_and_scoped(store):
    alice, _ = store.create(username="alice", name="a", scopes=["write"])
    bob, _ = store.create(username="bob", name="b", scopes=["write"])
    store.record_audit(
        token=alice, agent="agent-1", action="save_assessment",
        outcome="success", target={"findings": ["f1"]}, detail="x" * 5000,
    )
    store.record_audit(token=bob, agent="agent-2", action="save_assessment", outcome="conflict")

    everything = store.list_audit()
    assert [e["username"] for e in everything] == ["bob", "alice"]
    own = store.list_audit(username="alice")
    assert own[0]["target"] == {"findings": ["f1"]}
    assert own[0]["agent"] == "agent-1"
    assert len(own[0]["detail"]) == 2000


# --- management routes ---------------------------------------------------


def test_tokens_are_disabled_by_default(session):
    listing = session.get("/api/settings/tokens").json()
    assert listing["enabled"] is False and listing["tokens"] == []
    assert session.post("/api/settings/tokens", json={"name": "a"}).status_code == 404


def test_create_list_and_revoke_through_the_api(session, enabled):
    created = session.post(
        "/api/settings/tokens",
        json={"name": "agent", "scopes": ["read", "write"], "expires_in_days": 30},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["token"].startswith("dtvp_pat_")

    listing = session.get("/api/settings/tokens").json()
    assert listing["enabled"] is True
    assert [t["id"] for t in listing["tokens"]] == [body["id"]]
    assert "token" not in listing["tokens"][0]

    assert session.post("/api/settings/tokens", json={"name": ""}).status_code == 422
    assert session.delete("/api/settings/tokens/unknown").status_code == 404
    assert session.delete(f"/api/settings/tokens/{body['id']}").status_code == 200
    assert session.get("/api/settings/tokens").json()["tokens"][0]["revoked_at"]


def test_a_token_cannot_manage_tokens(client, enabled):
    _record, plain = access_token_store.create(
        username="alice", name="a", scopes=["read", "write"]
    )
    for response in (
        client.get("/api/settings/tokens", headers=_bearer(plain)),
        client.post("/api/settings/tokens", json={"name": "b"}, headers=_bearer(plain)),
    ):
        assert response.status_code == 403


def test_audit_is_limited_to_own_entries_for_analysts(session, enabled):
    alice, _ = access_token_store.create(username="alice", name="a", scopes=["write"])
    bob, _ = access_token_store.create(username="bob", name="b", scopes=["write"])
    for token in (alice, bob):
        access_token_store.record_audit(
            token=token, agent="x", action="save_assessment", outcome="success"
        )

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        own = session.get("/api/settings/tokens/audit").json()
    assert [e["username"] for e in own] == ["alice"]
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        everything = session.get("/api/settings/tokens/audit").json()
    assert {e["username"] for e in everything} == {"alice", "bob"}


# --- bearer authentication on the REST API -------------------------------


def test_bearer_token_authenticates_reads(client, enabled):
    _record, plain = access_token_store.create(
        username="alice", name="a", scopes=["read"]
    )
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/projects", headers=_bearer(plain)).status_code == 200
    me = client.get("/auth/me", headers=_bearer(plain))
    assert me.json()["username"] == "alice"


def test_bearer_token_is_rejected_when_invalid_or_disabled(client, monkeypatch):
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    record, plain = access_token_store.create(
        username="alice", name="a", scopes=["read"]
    )
    bad = client.get("/api/projects", headers=_bearer("dtvp_pat_nope"))
    assert bad.status_code == 401
    assert bad.headers["www-authenticate"] == "Bearer"

    access_token_store.revoke(username="alice", token_id=record.token_id)
    assert client.get("/api/projects", headers=_bearer(plain)).status_code == 401

    _record, fresh = access_token_store.create(
        username="alice", name="b", scopes=["read"]
    )
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "false")
    assert client.get("/api/projects", headers=_bearer(fresh)).status_code == 401


def test_bearer_token_cannot_write_through_rest_even_with_write_scope(client, enabled):
    _record, plain = access_token_store.create(
        username="alice", name="a", scopes=["read", "write"]
    )
    payload = {
        "instances": [
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "x",
    }
    assert client.post("/api/assessment", json=payload, headers=_bearer(plain)).status_code == 403
    assert client.put("/api/settings/roles", json={}, headers=_bearer(plain)).status_code == 403
    assert main.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None

    # This route rewrites the shared task snapshots, so it is not a read.
    details = client.post(
        "/api/assessments/details", json={"instances": []}, headers=_bearer(plain)
    )
    assert details.status_code == 403


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Basic abc", None),
        ("Bearer ", None),
        ("Bearer dt-user-token", "dt-user-token"),
        ("Bearer dtvp_pat_abc_def", None),
        ("Bearer  dtvp_pat_abc_def", None),
        ("Bearer \tdtvp_pat_abc_def ", None),
    ],
)
def test_access_tokens_are_never_forwarded_to_dependency_track(header, expected):
    assert forwardable_bearer(header) == expected


def test_group_task_route_does_not_forward_an_access_token(client, enabled, mock_dt_client):
    _record, plain = access_token_store.create(
        username="alice", name="a", scopes=["read"]
    )
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    with patch("dtvp.main.DTClient", return_value=mock_dt_client) as dt_client_cls:
        response = client.post(
            "/api/tasks/group-vulns?name=X",
            headers={"Authorization": f"Bearer  {plain}"},
        )
    assert response.status_code == 200
    assert dt_client_cls.call_args.kwargs["token"] == ""
