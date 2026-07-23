"""HTTP trust-boundary helpers: hosts, origins, client identity, and quotas."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import Request

from .configuration import RateLimitSettings

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _csv(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def allowed_hosts(*, frontend_url: str, production: bool) -> list[str]:
    configured = _csv("DTVP_ALLOWED_HOSTS")
    if production and "*" in configured:
        raise RuntimeError("DTVP_ALLOWED_HOSTS cannot contain '*' in production")
    hostname = urlsplit(frontend_url).hostname
    defaults = set(configured)
    if not production:
        defaults.update({"localhost", "127.0.0.1", "::1", "dtvp", "testserver"})
    if hostname:
        defaults.add(hostname)
    return sorted(defaults)


def host_is_allowed(host: str, configured_hosts: list[str]) -> bool:
    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False
    for configured in configured_hosts:
        pattern = configured.strip().lower().rstrip(".")
        if pattern == "*" or candidate == pattern:
            return True
        if pattern.startswith("*.") and candidate.endswith(pattern[1:]):
            prefix = candidate[: -len(pattern[1:])]
            if prefix and not prefix.endswith("."):
                return True
    return False


def normalized_origin(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    default_port = 443 if parts.scheme == "https" else 80
    try:
        port = parts.port or default_port
    except ValueError:
        return ""
    suffix = "" if port == default_port else f":{port}"
    return f"{parts.scheme}://{parts.hostname.lower()}{suffix}"


def origin_is_allowed(origin: str, configured_origins: list[str]) -> bool:
    candidate = normalized_origin(origin)
    return bool(candidate) and candidate in {
        normalized for value in configured_origins if (normalized := normalized_origin(value))
    }


def trusted_request_id(value: str | None) -> str | None:
    candidate = (value or "").strip()
    return candidate if REQUEST_ID_RE.fullmatch(candidate) else None


def resolve_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    networks = []
    for value in _csv("DTVP_TRUSTED_PROXY_CIDRS"):
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    if not any(peer_ip in network for network in networks):
        return peer
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(forwarded))
    except ValueError:
        return peer


def request_identity(request: Request, remote_ip: str, session_cookie_name: str) -> str:
    session = request.cookies.get(session_cookie_name, "")
    if session:
        digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:24]
        return f"session:{digest}"
    return f"ip:{remote_ip}"


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after: int


class SlidingWindowRateLimiter:
    """Bounded in-process quota layer; the reverse proxy adds the IP edge limit."""

    def __init__(self, *, max_buckets: int = 10_000) -> None:
        self.max_buckets = max_buckets
        self._guard = threading.Lock()
        self._buckets: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()

    def check(
        self,
        scope: str,
        identity: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        if limit <= 0:
            return RateLimitDecision(True, 0)
        current = time.monotonic() if now is None else now
        cutoff = current - max(1, window_seconds)
        key = (scope, identity)
        with self._guard:
            bucket = self._buckets.setdefault(key, deque())
            self._buckets.move_to_end(key)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (current - bucket[0])))
                return RateLimitDecision(False, retry_after)
            bucket.append(current)
            while len(self._buckets) > self.max_buckets:
                self._buckets.popitem(last=False)
        return RateLimitDecision(True, 0)

    def reset(self) -> None:
        with self._guard:
            self._buckets.clear()


def rate_limit_for_request(request: Request) -> tuple[str, int, int] | None:
    path = request.url.path
    method = request.method.upper()
    settings = RateLimitSettings.from_env()
    window = settings.window_seconds
    if path.endswith("/auth/login") or path.endswith("/auth/callback"):
        return "authentication", settings.authentication, window
    expensive_markers = (
        "/tasks/group-vulns",
        "/code-analysis/requests",
        "/project-archives/imports",
        "/tmrescore/analyze",
        "/bulk-workflows/",
    )
    if method in UNSAFE_METHODS and any(marker in path for marker in expensive_markers):
        return "expensive", settings.expensive, window
    if method in UNSAFE_METHODS:
        return "mutation", settings.mutation, window
    return None
