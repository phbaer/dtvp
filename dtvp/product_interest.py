"""Product interest from the browser (ADR 0004, "Product interest from the
browser").

The leader tab of a browser sends the union of the products its tabs show to
``PUT /api/events/interest``. Each ``(user, client_id)`` holds one lease that
lives for the watch TTL after its last renewal; an empty product list ends it.
Sync work never renews a lease. The scheduler (ADR 0004 step 5) reads
``watched()`` together with its other interest sources.

Leases are held in the process, like the event hub.

Activity (ADR 0004 amendment of 2026-11-23, "Idle without users"): the
scheduler reads the source only while someone uses River, that is while a
lease lives or an authenticated API or MCP request came within the watch TTL
(``note_request``, ``active``).
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable

DEFAULT_WATCH_TTL_SECONDS = 900
MAX_LEASES_PER_USER = 20
# Short leases from a user's own reads (``touch``): a cap of their own, so
# reading many products never pushes out a browser's lease.
MAX_READ_LEASES_PER_USER = 50
_READ_PREFIX = "read:"


def watch_ttl_seconds() -> int:
    try:
        value = int(os.getenv("DTVP_SYNC_WATCH_TTL_SECONDS", DEFAULT_WATCH_TTL_SECONDS))
    except ValueError:
        return DEFAULT_WATCH_TTL_SECONDS
    return value if value > 0 else DEFAULT_WATCH_TTL_SECONDS


@dataclass(frozen=True)
class Lease:
    user: str
    client_id: str
    products: tuple[str, ...]
    expires_at: float


class ProductInterest:
    def __init__(
        self,
        ttl_seconds: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ttl_seconds = ttl_seconds or watch_ttl_seconds()
        self._clock = clock
        self._leases: dict[tuple[str, str], Lease] = {}
        self._lock = threading.Lock()
        # When the last authenticated API or MCP request came.
        self._last_request: float | None = None

    def _prune_locked(self, now: float) -> None:
        for key in [key for key, lease in self._leases.items() if lease.expires_at <= now]:
            del self._leases[key]

    def put(self, user: str, client_id: str, products: list[str]) -> Lease | None:
        """Renew the lease of ``(user, client_id)`` with these products; an
        empty list ends it. A user's oldest leases give way beyond
        ``MAX_LEASES_PER_USER`` browsers."""
        names = tuple(sorted({str(p).strip() for p in products if str(p).strip()}))
        key = (user, client_id)
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            if not names:
                self._leases.pop(key, None)
                return None
            lease = Lease(user, client_id, names, now + self.ttl_seconds)
            self._leases[key] = lease
            is_read = client_id.startswith(_READ_PREFIX)
            cap = MAX_READ_LEASES_PER_USER if is_read else MAX_LEASES_PER_USER
            own = sorted(
                (
                    item
                    for item in self._leases.values()
                    if item.user == user
                    and item.client_id.startswith(_READ_PREFIX) == is_read
                ),
                key=lambda item: item.expires_at,
            )
            for stale in own[: max(0, len(own) - cap)]:
                del self._leases[(stale.user, stale.client_id)]
            return lease

    def touch(self, user: str, product: str | None) -> None:
        """A short lease for one product, from a user's own read: polling a
        task of the product, an MCP project tool, or opening it. Renewed at
        most once a minute; never from sync work (ADR 0004, "Interest and
        leases")."""
        name = str(product or "").strip()
        if not user or not name:
            return
        key = (user, f"{_READ_PREFIX}{name.lower()}")
        with self._lock:
            now = self._clock()
            current = self._leases.get(key)
            if current is not None and current.expires_at - now > self.ttl_seconds - 60:
                return
        self.put(user, key[1], [name])

    def watched(self) -> set[str]:
        """The products of every live lease."""
        with self._lock:
            self._prune_locked(self._clock())
            return {product for lease in self._leases.values() for product in lease.products}

    def note_request(self, user: str | None = None) -> None:
        """An authenticated API or MCP request: River is in use for the TTL."""
        if user is None or str(user).strip():
            with self._lock:
                self._last_request = self._clock()

    def active(self) -> bool:
        """Whether someone uses River: a live lease, or a request within the TTL."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            if self._leases:
                return True
            return self._last_request is not None and now - self._last_request < self.ttl_seconds

    def activity(self) -> dict[str, object]:
        """For the status: active or not, the live leases, and how long ago
        the last authenticated request came."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            leases = len(self._leases)
            last = self._last_request
        ago = None if last is None else round(now - last, 1)
        return {
            "active": bool(leases) or (ago is not None and ago < self.ttl_seconds),
            "leases": leases,
            "last_request_seconds_ago": ago,
            "ttl_seconds": self.ttl_seconds,
        }

    def leases(self) -> list[Lease]:
        with self._lock:
            self._prune_locked(self._clock())
            return list(self._leases.values())
