import json
import stat

from starlette.requests import Request

from dtvp import main
from dtvp.auth import SESSION_COOKIE_NAME
from dtvp.request_security import (
    SlidingWindowRateLimiter,
    allowed_hosts,
    host_is_allowed,
    normalized_origin,
    origin_is_allowed,
    rate_limit_for_request,
    request_identity,
    trusted_request_id,
)
from dtvp.security_audit import (
    AuditRequestContext,
    emit_security_audit,
    reset_audit_request_context,
    set_audit_request_context,
    validate_security_audit_configuration,
)


def test_host_and_origin_matching_are_exact():
    assert host_is_allowed("app.example.com", ["app.example.com"])
    assert host_is_allowed("review.example.com", ["*.example.com"])
    assert not host_is_allowed("example.com.evil.test", ["*.example.com"])
    assert normalized_origin("https://APP.example.com:443/dtvp") == (
        "https://app.example.com"
    )
    assert origin_is_allowed(
        "https://app.example.com",
        ["https://app.example.com/dtvp"],
    )
    assert not origin_is_allowed(
        "https://app.example.com.evil.test",
        ["https://app.example.com"],
    )
    assert normalized_origin("https://app.example.com:invalid") == ""


def test_production_host_defaults_only_include_the_public_frontend(monkeypatch):
    monkeypatch.delenv("DTVP_ALLOWED_HOSTS", raising=False)

    assert allowed_hosts(
        frontend_url="https://app.example.com/dtvp",
        production=True,
    ) == ["app.example.com"]


def test_request_ids_must_be_bounded_safe_tokens():
    assert trusted_request_id("request-123") == "request-123"
    assert trusted_request_id("bad request") is None
    assert trusted_request_id("x" * 129) is None


def test_sliding_window_rate_limiter_is_identity_scoped():
    limiter = SlidingWindowRateLimiter(max_buckets=2)
    assert limiter.check("mutation", "alice", limit=2, window_seconds=60, now=1).allowed
    assert limiter.check("mutation", "alice", limit=2, window_seconds=60, now=2).allowed
    denied = limiter.check("mutation", "alice", limit=2, window_seconds=60, now=3)
    assert denied.allowed is False
    assert denied.retry_after > 0
    assert limiter.check("mutation", "bob", limit=2, window_seconds=60, now=3).allowed
    assert limiter.check("mutation", "alice", limit=2, window_seconds=60, now=62).allowed


def _request(path: str, *, method: str = "POST") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("192.0.2.10", 1234),
            "server": ("app.example.test", 443),
        }
    )


def test_code_analysis_mutations_use_expensive_rate_limit():
    paths = (
        "/api/code-analysis/assess",
        "/api/code-analysis/auto-sweep/run",
        "/api/code-analysis/results/run-1/benchmark",
    )

    assert all(
        rate_limit_for_request(_request(path))[0] == "expensive" for path in paths
    )
    assert rate_limit_for_request(
        _request("/api/code-analysis/results/run-1", method="DELETE")
    )[0] == "mutation"


def test_quota_identity_requires_validated_actor_and_includes_ip():
    assert request_identity("192.0.2.10") == "ip:192.0.2.10"
    alice = request_identity("192.0.2.10", authenticated_actor="alice")
    assert alice.startswith("actor:")
    assert alice.endswith(":ip:192.0.2.10")
    assert request_identity("192.0.2.11", authenticated_actor="alice") != alice


def test_invalid_cookie_rotation_cannot_bypass_authentication_quota(
    client,
    monkeypatch,
):
    monkeypatch.setenv("DTVP_AUTH_RATE_LIMIT", "1")
    main.request_rate_limiter.reset()
    try:
        client.cookies.set(SESSION_COOKIE_NAME, "invalid-cookie-one")
        first = client.get("/auth/login", follow_redirects=False)
        client.cookies.set(SESSION_COOKIE_NAME, "invalid-cookie-two")
        second = client.get("/auth/login", follow_redirects=False)
    finally:
        main.request_rate_limiter.reset()
        client.cookies.pop(SESSION_COOKIE_NAME, None)

    assert first.status_code != 429
    assert second.status_code == 429


def test_security_audit_is_owner_only_and_redacts_sensitive_detail(tmp_path, monkeypatch):
    path = tmp_path / "security" / "audit.jsonl"
    monkeypatch.setenv("DTVP_SECURITY_AUDIT_PATH", str(path))
    validate_security_audit_configuration()
    token = set_audit_request_context(
        AuditRequestContext(
            request_id="request-1",
            actor="alice",
            role="REVIEWER",
            remote_ip="192.0.2.10",
        )
    )
    try:
        event = emit_security_audit(
            "settings.update",
            outcome="success",
            resource_type="settings",
            resource_id="team-mapping",
            details={"token": "must-not-appear", "changed": ["teams"]},
        )
    finally:
        reset_audit_request_context(token)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    persisted = json.loads(path.read_text().strip())
    assert persisted["event_id"] == event["event_id"]
    assert persisted["actor"] == "alice"
    assert persisted["details"] == {"changed": ["teams"]}
    assert "must-not-appear" not in path.read_text()
    assert len(persisted["event_hash"]) == 64


def test_security_audit_rotates_with_bounded_owner_only_backups(tmp_path, monkeypatch):
    path = tmp_path / "security" / "audit.jsonl"
    monkeypatch.setenv("DTVP_SECURITY_AUDIT_PATH", str(path))
    monkeypatch.setenv("DTVP_SECURITY_AUDIT_MAX_BYTES", "1")
    monkeypatch.setenv("DTVP_SECURITY_AUDIT_BACKUP_COUNT", "2")
    validate_security_audit_configuration()

    for index in range(4):
        emit_security_audit(
            "rotation.test",
            outcome="success",
            resource_id=str(index),
        )

    files = [path, path.with_name("audit.jsonl.1"), path.with_name("audit.jsonl.2")]
    assert all(item.exists() for item in files)
    assert not path.with_name("audit.jsonl.3").exists()
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in files)
    assert json.loads(path.read_text(encoding="utf-8"))["resource_id"] == "3"
    assert main.audit_health()["backup_count"] == 2


def test_http_boundary_rejects_unknown_hosts_and_cross_origin_mutations(client):
    host_response = client.get(
        "/api/version",
        headers={"Host": "attacker.example", "X-Request-ID": "host-test"},
    )
    assert host_response.status_code == 400
    assert host_response.headers["X-Request-ID"] == "host-test"

    origin_response = client.post(
        "/auth/logout",
        headers={
            "Origin": "https://attacker.example",
            "X-Request-ID": "origin-test",
        },
    )
    assert origin_response.status_code == 403
    assert origin_response.headers["X-Request-ID"] == "origin-test"

    client.cookies.set(SESSION_COOKIE_NAME, "invalid-but-cookie-authenticated")
    missing_origin = client.post(
        "/auth/logout",
        headers={"X-Request-ID": "missing-origin-test"},
    )
    assert missing_origin.status_code == 403
    assert missing_origin.headers["X-Request-ID"] == "missing-origin-test"


def test_http_boundary_emits_request_id_and_mutation_audit(client, tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("DTVP_SECURITY_AUDIT_PATH", str(path))
    main.request_rate_limiter.reset()

    response = client.post(
        "/auth/logout",
        headers={
            "Origin": "http://localhost:8000",
            "X-Request-ID": "logout-request",
        },
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "logout-request"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert events[-1]["request_id"] == "logout-request"
    assert events[-1]["action"] == "http.post"
    assert events[-1]["outcome"] == "success"
