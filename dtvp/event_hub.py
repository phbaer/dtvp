"""The app-wide event hub behind ``GET /api/events`` (ADR 0004, decision 6).

Events carry identifiers, counts, and times, never data. Each event gets a
sequence number that only increases within one process; a ring buffer keeps
the most recent events so a client that reconnects with its last cursor can
replay what it missed. The boot id tells a client that the process restarted
and its cursor no longer means anything.

``publish`` is thread-safe and never awaits, so it can be called from worker
threads and from the event loop alike. Callers publish after their data is
visible to readers.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

AUDIENCE_ALL = "all"
AUDIENCE_REVIEWER = "reviewer"
_AUDIENCES = {AUDIENCE_ALL, AUDIENCE_REVIEWER}


@dataclass(frozen=True)
class ServerEvent:
    seq: int
    type: str
    at: str
    product: str | None
    audience: str
    frame: str
    envelope: dict


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def format_frame(event_id: str, event_type: str, data: Any) -> str:
    """One SSE frame. ``data`` is serialised on one line."""
    payload = json.dumps(data, separators=(",", ":"), default=str)
    return f"id: {event_id}\nevent: {event_type}\ndata: {payload}\n\n"


class EventHub:
    def __init__(
        self,
        *,
        buffer_size: int = 2000,
        max_connections: int = 200,
        max_connections_per_user: int = 20,
        boot_id: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.boot_id = boot_id or secrets.token_hex(8)
        self.buffer_size = max(1, int(buffer_size))
        self.max_connections = max(1, int(max_connections))
        self.max_connections_per_user = max(1, int(max_connections_per_user))
        self._clock = clock
        self._lock = threading.RLock()
        self._seq = 0
        self._buffer: deque[ServerEvent] = deque(maxlen=self.buffer_size)
        self._evicted_through = 0
        self._waiters: set[asyncio.Future[None]] = set()
        self._connections = 0
        self._user_connections: dict[str, int] = {}
        self._closed = False

    # -- cursor ------------------------------------------------------------

    def current_seq(self) -> int:
        with self._lock:
            return self._seq

    def cursor(self, seq: int | None = None) -> str:
        return f"{self.boot_id}:{self.current_seq() if seq is None else seq}"

    def parse_cursor(self, raw: str | None) -> tuple[str, int] | None:
        """``(boot_id, seq)`` of a cursor, or None when it is malformed."""
        if not raw or not isinstance(raw, str):
            return None
        boot, sep, seq_text = raw.strip().rpartition(":")
        if not sep or not boot or not seq_text.isdigit():
            return None
        return boot, int(seq_text)

    # -- publishing --------------------------------------------------------

    def publish(
        self,
        type: str,
        data: dict,
        *,
        product: str | None = None,
        audience: str = AUDIENCE_ALL,
    ) -> int:
        if audience not in _AUDIENCES:
            raise ValueError(f"Unknown event audience: {audience}")
        with self._lock:
            self._seq += 1
            seq = self._seq
            at = _iso(self._clock())
            envelope = {
                "seq": seq,
                "at": at,
                "type": type,
                "product": product,
                "data": data,
            }
            event = ServerEvent(
                seq=seq,
                type=type,
                at=at,
                product=product,
                audience=audience,
                frame=format_frame(f"{self.boot_id}:{seq}", type, envelope),
                envelope=envelope,
            )
            if len(self._buffer) == self._buffer.maxlen:
                self._evicted_through = self._buffer[0].seq
            self._buffer.append(event)
            waiters = tuple(self._waiters)
            self._waiters.clear()
        self._wake(waiters)
        return seq

    @staticmethod
    def _wake(waiters: tuple[asyncio.Future[None], ...]) -> None:
        for waiter in waiters:
            loop = waiter.get_loop()

            def wake(target: asyncio.Future[None] = waiter) -> None:
                if not target.done():
                    target.set_result(None)

            try:
                loop.call_soon_threadsafe(wake)
            except RuntimeError:
                # The waiter's loop has closed; nobody is waiting any more.
                pass

    def events_after(self, seq: int) -> list[ServerEvent] | None:
        """Events after ``seq`` in order, or None when the cursor cannot be
        served: older than the buffer, or ahead of the hub."""
        with self._lock:
            if seq < self._evicted_through or seq > self._seq:
                return None
            return [event for event in self._buffer if event.seq > seq]

    async def wait(self, after_seq: int, *, timeout_seconds: float) -> int:
        """Wait until an event after ``after_seq`` exists, the timeout passes,
        or the hub closes. Returns the current seq."""
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
        with self._lock:
            if self._seq > after_seq or self._closed:
                return self._seq
            self._waiters.add(waiter)
        try:
            await asyncio.wait_for(waiter, timeout=max(0.0, timeout_seconds))
        except TimeoutError:
            pass
        finally:
            with self._lock:
                self._waiters.discard(waiter)
        return self.current_seq()

    # -- connections -------------------------------------------------------

    # Refusal reasons of ``acquire_connection``.
    REFUSED_FULL = "full"
    REFUSED_USER = "user_limit"

    def acquire_connection(self, user: str | None = None) -> str | None:
        """Take a stream slot. Returns None when it was taken, ``REFUSED_FULL``
        when the process cap is reached or the hub is closed, or
        ``REFUSED_USER`` when ``user`` already holds
        ``max_connections_per_user`` streams, so one principal cannot take
        every slot."""
        with self._lock:
            if self._closed or self._connections >= self.max_connections:
                return self.REFUSED_FULL
            if user is not None:
                held = self._user_connections.get(user, 0)
                if held >= self.max_connections_per_user:
                    return self.REFUSED_USER
                self._user_connections[user] = held + 1
            self._connections += 1
            return None

    def try_acquire_connection(self, user: str | None = None) -> bool:
        return self.acquire_connection(user) is None

    def release_connection(self, user: str | None = None) -> None:
        with self._lock:
            self._connections = max(0, self._connections - 1)
            if user is not None:
                held = self._user_connections.get(user, 0) - 1
                if held > 0:
                    self._user_connections[user] = held
                else:
                    self._user_connections.pop(user, None)

    def user_connection_count(self, user: str) -> int:
        with self._lock:
            return self._user_connections.get(user, 0)

    @property
    def connection_count(self) -> int:
        with self._lock:
            return self._connections

    def close(self) -> None:
        """End every open stream; used at shutdown."""
        with self._lock:
            self._closed = True
            waiters = tuple(self._waiters)
            self._waiters.clear()
        self._wake(waiters)

    def reopen(self) -> None:
        """Accept streams again after ``close``; the application lifespan
        calls it at startup, so a restarted app (tests) can stream."""
        with self._lock:
            self._closed = False

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed
