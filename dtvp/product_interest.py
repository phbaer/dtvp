"""Product interest from the browser (ADR 0004, "Product interest from the
browser").

The leader tab of a browser sends the union of the products its tabs show to
``PUT /api/events/interest``. Each ``(user, client_id)`` holds one lease that
lives for the watch TTL after its last renewal; an empty product list ends it.
Sync work never renews a lease. The scheduler (ADR 0004 step 5) reads
``watched()`` together with its other interest sources.

Leases are held in the process, like the event hub.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable

DEFAULT_WATCH_TTL_SECONDS = 900
MAX_LEASES_PER_USER = 20


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
            own = sorted(
                (item for item in self._leases.values() if item.user == user),
                key=lambda item: item.expires_at,
            )
            for stale in own[: max(0, len(own) - MAX_LEASES_PER_USER)]:
                del self._leases[(stale.user, stale.client_id)]
            return lease

    def watched(self) -> set[str]:
        """The products of every live lease."""
        with self._lock:
            self._prune_locked(self._clock())
            return {product for lease in self._leases.values() for product in lease.products}

    def leases(self) -> list[Lease]:
        with self._lock:
            self._prune_locked(self._clock())
            return list(self._leases.values())
