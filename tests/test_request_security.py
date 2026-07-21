import json
import stat

from dtvp import main
from dtvp.auth import SESSION_COOKIE_NAME
from dtvp.request_security import (
    SlidingWindowRateLimiter,
    allowed_hosts,
    host_is_allowed,
    normalized_origin,
    origin_is_allowed,
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
