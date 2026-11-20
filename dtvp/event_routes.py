"""``GET /api/events`` and ``GET /api/events/poll`` (ADR 0004, decision 6).

The stream is Server-Sent Events read with ``fetch``. It starts with
``hello``, replays what the client missed when it sends a cursor, and then
follows the hub. Every heartbeat re-runs the authentication dependency on
the request that opened the stream, so a revoked or expired access token, or a
different user, ends the stream with an ``auth`` frame, and a role change
switches the reviewer filter in place.

A browser session cookie is a stateless JWT without expiry, so re-reading it
proves nothing new: a logout in another browser or an expired session does not
end the stream here. ``EventRouteDeps.session_valid`` is the hook for
server-side session state; until that exists it accepts every session. The
browser's own logout stops every tab through the channel (ADR 0004), and the
stream ends at ``max_stream_seconds`` at the latest.

Heartbeats carry the cursor as ``id:``, so a client that cannot see some
events (an analyst and reviewer-only ``export.state``) still advances past
them and resumes without a needless gap resync.

This module does not import ``dtvp.main``; tests build a small app around it.
"""

from __future__ import annotations

import asyncio
import json
import inspect
import logging
import random as _random
import time
import weakref
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .event_hub import AUDIENCE_REVIEWER, EventHub, ServerEvent, format_frame

logger = logging.getLogger(__name__)

STREAM_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "X-Accel-Buffering": "no",
}

RESYNC_RESTART = "restart"
RESYNC_GAP = "gap"
RESYNC_INVALID_CURSOR = "invalid_cursor"


@dataclass
class EventRouteDeps:
    hub: EventHub
    authenticate: Callable[[Request], Awaitable[str]]
    get_user_role: Callable[[str], str]
    build: str
    source_state: Callable[[], dict]
    heartbeat_seconds: float = 15.0
    max_stream_seconds: float = 1800.0
    poll_limit: int = 500
    # Retry-After of a refused connection, in seconds.
    retry_after_seconds: int = 30
    # Each stream ends after max_stream_seconds shortened by up to this
    # fraction, so streams opened together do not all rotate together.
    max_stream_jitter: float = 0.1
    random: Callable[[], float] = _random.random
    # Server-side session check at each heartbeat: ``(request, user)`` ->
    # bool, sync or async. None accepts every session; server-side session
    # versioning plugs in here.
    session_valid: Callable[[Request, str], Any] | None = None


def _is_reviewer(role: Any) -> bool:
    return str(role or "").upper() == "REVIEWER"


def _visible(event: ServerEvent, reviewer: bool) -> bool:
    return event.audience != AUDIENCE_REVIEWER or reviewer


def _resolve_start(
    hub: EventHub, since: str | None
) -> tuple[int, list[ServerEvent], str | None]:
    """Where a client resumes: ``(cursor seq, events to replay, resync reason)``.

    Without a cursor the client starts at the current seq. A cursor that
    cannot be served yields one resync reason and also starts at the current
    seq."""
    if not since:
        return hub.current_seq(), [], None
    parsed = hub.parse_cursor(since)
    if parsed is None:
        return hub.current_seq(), [], RESYNC_INVALID_CURSOR
    boot_id, seq = parsed
    if boot_id != hub.boot_id:
        return hub.current_seq(), [], RESYNC_RESTART
    replay = hub.events_after(seq)
    if replay is None:
        return hub.current_seq(), [], RESYNC_GAP
    return seq, replay, None


def _auth_frame(status_code: int) -> str:
    return f"event: auth\ndata: {json.dumps({'status': status_code})}\n\n"


def _heartbeat_frame(cursor: str) -> str:
    """A comment with the cursor as ``id:``; it dispatches no event."""
    return f"id: {cursor}\n: hb\n\n"


async def _session_still_valid(deps: EventRouteDeps, request: Request, user: str) -> bool:
    if deps.session_valid is None:
        return True
    result = deps.session_valid(request, user)
    if inspect.isawaitable(result):
        result = await result
    return bool(result)


def create_event_router(deps: EventRouteDeps) -> APIRouter:
    router = APIRouter()
    hub = deps.hub

    async def _role_flag(user: str) -> bool:
        return _is_reviewer(await asyncio.to_thread(deps.get_user_role, user))

    @router.get("/events")
    async def stream_events(
        request: Request,
        user: str = Depends(deps.authenticate),
        since: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None),
    ):
        reviewer = await _role_flag(user)
        refusal = hub.acquire_connection(user)
        if refusal is not None:
            per_user = refusal == EventHub.REFUSED_USER
            return JSONResponse(
                {
                    "detail": "Too many live update connections for this user"
                    if per_user
                    else "Too many live update connections"
                },
                status_code=429 if per_user else 503,
                headers={"Retry-After": str(deps.retry_after_seconds)},
            )

        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                hub.release_connection(user)

        cursor_text = since if since is not None else last_event_id

        async def event_stream() -> AsyncIterator[str]:
            nonlocal reviewer
            try:
                start_seq, replay, resync_reason = _resolve_start(hub, cursor_text)
                yield format_frame(
                    hub.cursor(start_seq),
                    "hello",
                    {
                        "boot_id": hub.boot_id,
                        "seq": hub.current_seq(),
                        "build": deps.build,
                        "source": deps.source_state(),
                    },
                )
                cursor = start_seq
                if resync_reason is not None:
                    yield format_frame(
                        hub.cursor(cursor),
                        "resync",
                        {"seq": cursor, "reason": resync_reason},
                    )
                for event in replay:
                    if _visible(event, reviewer):
                        yield event.frame
                    cursor = event.seq

                started = time.monotonic()
                jitter = min(1.0, max(0.0, deps.max_stream_jitter)) * deps.random()
                deadline = started + max(0.0, deps.max_stream_seconds) * (1.0 - jitter)
                next_heartbeat = started + deps.heartbeat_seconds
                while True:
                    now = time.monotonic()
                    await hub.wait(
                        cursor,
                        timeout_seconds=max(
                            0.0, min(next_heartbeat - now, deadline - now)
                        ),
                    )
                    if hub.closed:
                        return
                    events = hub.events_after(cursor)
                    if events is None:
                        cursor = hub.current_seq()
                        yield format_frame(
                            hub.cursor(cursor),
                            "resync",
                            {"seq": cursor, "reason": RESYNC_GAP},
                        )
                    else:
                        for event in events:
                            if _visible(event, reviewer):
                                yield event.frame
                            cursor = event.seq

                    now = time.monotonic()
                    if now >= next_heartbeat:
                        next_heartbeat = now + deps.heartbeat_seconds
                        if await request.is_disconnected():
                            return
                        try:
                            current_user = await deps.authenticate(request)
                        except HTTPException as exc:
                            yield _auth_frame(exc.status_code)
                            return
                        if current_user != user or not await _session_still_valid(
                            deps, request, current_user
                        ):
                            yield _auth_frame(401)
                            return
                        reviewer = await _role_flag(current_user)
                        yield _heartbeat_frame(hub.cursor(cursor))
                    if now >= deadline:
                        # Hand over the cursor past events this client could
                        # not see before the stream ends.
                        yield _heartbeat_frame(hub.cursor(cursor))
                        return
            finally:
                release()

        stream = event_stream()
        # A response that is cancelled before its body starts never runs the
        # generator's finally block; release the slot when it is collected.
        weakref.finalize(stream, release)
        return StreamingResponse(
            stream,
            media_type="text/event-stream; charset=utf-8",
            headers=STREAM_HEADERS,
        )

    @router.get("/events/poll")
    async def poll_events(
        user: str = Depends(deps.authenticate),
        since: str | None = Query(default=None),
    ):
        reviewer = await _role_flag(user)
        if not since:
            return {
                "boot_id": hub.boot_id,
                "cursor": hub.cursor(),
                "events": [],
                "resync": None,
                "more": False,
            }
        start_seq, events, resync_reason = _resolve_start(hub, since)
        returned: list[dict] = []
        cursor = start_seq
        more = False
        for event in events:
            if len(returned) >= deps.poll_limit:
                more = True
                break
            if _visible(event, reviewer):
                returned.append(event.envelope)
            cursor = event.seq
        return {
            "boot_id": hub.boot_id,
            "cursor": hub.cursor(cursor),
            "events": returned,
            "resync": resync_reason,
            "more": more,
        }

    return router
