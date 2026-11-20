import json
import threading
from unittest.mock import patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from dtvp.access_token_services import access_token_store
from dtvp.auth import get_current_user
from dtvp.event_hub import EventHub
from dtvp.event_routes import EventRouteDeps, create_event_router


class FakeAuth:
    """Authenticates the user named in ``X-User``; ``fail`` switches every
    later check to a 401."""

    def __init__(self):
        self.fail = False
        self.calls = 0

    async def __call__(self, request: Request) -> str:
        self.calls += 1
        user = request.headers.get("x-user")
        if self.fail or not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return user


class Env:
    def __init__(self, **overrides):
        self.hub = overrides.pop("hub", None) or EventHub(boot_id="boot1")
        self.auth = FakeAuth()
        self.roles = {"rita": "REVIEWER", "anna": "ANALYST"}
        deps = EventRouteDeps(
            hub=self.hub,
            authenticate=overrides.pop("authenticate", self.auth),
            get_user_role=lambda user: self.roles.get(user, "ANALYST"),
            build="1.2.3+abc",
            source_state=lambda: {"dt": "ok"},
            heartbeat_seconds=overrides.pop("heartbeat_seconds", 0.05),
            max_stream_seconds=overrides.pop("max_stream_seconds", 0.3),
            poll_limit=overrides.pop("poll_limit", 500),
            random=overrides.pop("random", lambda: 0.0),
            session_valid=overrides.pop("session_valid", None),
        )
        app = FastAPI()
        app.include_router(create_event_router(deps), prefix="/api")
        self.client = TestClient(app)

    def stream(self, user="rita", params=None, headers=None):
        all_headers = {"X-User": user} if user else {}
        all_headers.update(headers or {})
        response = self.client.get("/api/events", params=params, headers=all_headers)
        return response, parse_sse(response.text)


def parse_sse(text):
    """Frames as dicts with id, event, data (decoded), and comments."""
    frames = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        frame = {"comments": []}
        data_lines = []
        for line in block.split("\n"):
            if line.startswith(":"):
                frame["comments"].append(line[1:].strip())
                continue
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "data":
                data_lines.append(value)
            else:
                frame[field] = value
        if data_lines:
            frame["data"] = json.loads("\n".join(data_lines))
        frames.append(frame)
    return frames


def events(frames):
    return [frame for frame in frames if "event" in frame]


def later(seconds, action):
    timer = threading.Timer(seconds, action)
    timer.start()
    return timer


def test_stream_starts_with_hello_and_has_stream_headers():
    env = Env()
    env.hub.publish("before", {})
    response, frames = env.stream()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache, no-transform"
    assert response.headers["x-accel-buffering"] == "no"
    hello = events(frames)[0]
    assert hello["event"] == "hello"
    assert hello["id"] == "boot1:1"
    assert hello["data"] == {
        "boot_id": "boot1",
        "seq": 1,
        "build": "1.2.3+abc",
        "source": {"dt": "ok"},
    }
    # Without a cursor nothing older is replayed.
    assert [frame["event"] for frame in events(frames)] == ["hello"]


def test_live_events_arrive_and_heartbeats_are_sent():
    env = Env()
    timer = later(0.1, lambda: env.hub.publish("projects.changed", {"count": 3}))
    _response, frames = env.stream()
    timer.join()

    live = [frame for frame in events(frames) if frame["event"] == "projects.changed"]
    assert len(live) == 1
    assert live[0]["id"] == "boot1:1"
    assert live[0]["data"]["data"] == {"count": 3}
    assert any("hb" in frame["comments"] for frame in frames)


def test_resume_replays_exactly_the_events_after_the_cursor():
    env = Env()
    for index in range(5):
        env.hub.publish("e", {"i": index})
    _response, frames = env.stream(params={"since": "boot1:2"})

    assert [frame["id"] for frame in events(frames)] == [
        "boot1:2",
        "boot1:3",
        "boot1:4",
        "boot1:5",
    ]
    assert events(frames)[0]["event"] == "hello"


def test_last_event_id_header_resumes_and_the_query_wins():
    env = Env()
    for index in range(4):
        env.hub.publish("e", {"i": index})

    _response, frames = env.stream(headers={"Last-Event-ID": "boot1:3"})
    assert [frame["id"] for frame in events(frames)[1:]] == ["boot1:4"]

    _response, frames = env.stream(
        params={"since": "boot1:1"}, headers={"Last-Event-ID": "boot1:3"}
    )
    assert [frame["id"] for frame in events(frames)[1:]] == [
        "boot1:2",
        "boot1:3",
        "boot1:4",
    ]


@pytest.mark.parametrize(
    "since, reason",
    [
        ("otherboot:1", "restart"),
        ("boot1:1", "gap"),
        ("boot1:99", "gap"),
        ("garbage", "invalid_cursor"),
    ],
)
def test_unservable_cursor_sends_one_resync(since, reason):
    env = Env(hub=EventHub(boot_id="boot1", buffer_size=2))
    for index in range(5):
        env.hub.publish("e", {"i": index})
    _response, frames = env.stream(params={"since": since})

    kinds = [frame["event"] for frame in events(frames)]
    assert kinds == ["hello", "resync"]
    resync = events(frames)[1]
    assert resync["data"] == {"seq": 5, "reason": reason}
    assert resync["id"] == "boot1:5"


def test_reviewer_events_are_filtered_for_analysts():
    env = Env()
    env.hub.publish("export.state", {"failed": 1}, audience="reviewer")
    env.hub.publish("projects.changed", {})

    _response, frames = env.stream(user="anna", params={"since": "boot1:0"})
    assert [frame["event"] for frame in events(frames)] == ["hello", "projects.changed"]

    _response, frames = env.stream(user="rita", params={"since": "boot1:0"})
    assert [frame["event"] for frame in events(frames)] == [
        "hello",
        "export.state",
        "projects.changed",
    ]

    # The analyst skips the reviewer event live, too, and still receives the
    # next one.
    def publish_both():
        env.hub.publish("export.state", {"failed": 2}, audience="reviewer")
        env.hub.publish("projects.changed", {"n": 2})

    timer = later(0.08, publish_both)
    _response, frames = env.stream(user="anna")
    timer.join()
    assert [frame["event"] for frame in events(frames)] == ["hello", "projects.changed"]


def test_role_change_switches_the_filter_at_the_next_heartbeat():
    env = Env(heartbeat_seconds=0.05, max_stream_seconds=0.5)
    env.roles["anna"] = "ANALYST"

    def promote():
        env.roles["anna"] = "REVIEWER"

    def publish():
        env.hub.publish("export.state", {"failed": 3}, audience="reviewer")

    timers = [later(0.05, promote), later(0.25, publish)]
    _response, frames = env.stream(user="anna")
    for timer in timers:
        timer.join()
    assert "export.state" in [frame["event"] for frame in events(frames)]


def test_failed_recheck_sends_auth_and_ends_the_stream():
    env = Env(heartbeat_seconds=0.05, max_stream_seconds=5)

    def revoke_credentials():
        # Models a revoked access token: the dependency now fails for the
        # request that opened the stream. A cookie logout does not do this.
        env.auth.fail = True

    timer = later(0.1, revoke_credentials)
    response, frames = env.stream()
    timer.join()

    assert response.status_code == 200
    last = events(frames)[-1]
    assert last["event"] == "auth"
    assert last["data"] == {"status": 401}
    assert env.hub.connection_count == 0


def test_unauthenticated_connect_is_rejected():
    env = Env()
    response = env.client.get("/api/events")
    assert response.status_code == 401
    assert env.hub.connection_count == 0


def test_connection_cap_answers_503_and_a_finished_stream_frees_its_slot():
    env = Env(hub=EventHub(boot_id="boot1", max_connections=2))
    assert env.hub.try_acquire_connection()
    response, _frames = env.stream()
    assert response.status_code == 200
    assert env.hub.connection_count == 1

    assert env.hub.try_acquire_connection()
    response = env.client.get("/api/events", headers={"X-User": "rita"})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    assert response.json() == {"detail": "Too many live update connections"}


def test_closing_the_hub_ends_open_streams():
    env = Env(max_stream_seconds=30, heartbeat_seconds=30)
    timer = later(0.1, env.hub.close)
    response, frames = env.stream()
    timer.join()
    assert response.status_code == 200
    assert [frame["event"] for frame in events(frames)] == ["hello"]


def test_poll_without_cursor_returns_the_current_cursor():
    env = Env()
    env.hub.publish("e", {})
    body = env.client.get("/api/events/poll", headers={"X-User": "rita"}).json()
    assert body == {
        "boot_id": "boot1",
        "cursor": "boot1:1",
        "events": [],
        "resync": None,
        "more": False,
    }


def test_poll_returns_events_filters_and_pages():
    env = Env(poll_limit=2)
    env.hub.publish("a", {})
    env.hub.publish("export.state", {}, audience="reviewer")
    env.hub.publish("b", {})
    env.hub.publish("c", {})

    body = env.client.get(
        "/api/events/poll", params={"since": "boot1:0"}, headers={"X-User": "anna"}
    ).json()
    assert [event["type"] for event in body["events"]] == ["a", "b"]
    assert body["cursor"] == "boot1:3"
    assert body["more"] is True
    assert body["resync"] is None

    body = env.client.get(
        "/api/events/poll", params={"since": body["cursor"]}, headers={"X-User": "anna"}
    ).json()
    assert [event["type"] for event in body["events"]] == ["c"]
    assert body["cursor"] == "boot1:4"
    assert body["more"] is False


def test_poll_reports_resync():
    env = Env()
    env.hub.publish("a", {})
    body = env.client.get(
        "/api/events/poll", params={"since": "elsewhere:1"}, headers={"X-User": "rita"}
    ).json()
    assert body["resync"] == "restart"
    assert body["events"] == []
    assert body["cursor"] == "boot1:1"


def test_poll_requires_authentication():
    env = Env()
    assert env.client.get("/api/events/poll").status_code == 401


def test_real_current_user_accepts_a_read_scoped_access_token(monkeypatch):
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")
    _record, plain = access_token_store.create(
        username="alice", name="agent", scopes=["read"]
    )
    env = Env(authenticate=get_current_user, max_stream_seconds=0.1)
    with patch("dtvp.auth.auth_settings.DEV_DISABLE_AUTH", False):
        response = env.client.get(
            "/api/events", headers={"Authorization": f"Bearer {plain}"}
        )
        assert response.status_code == 200
        assert events(parse_sse(response.text))[0]["event"] == "hello"

        rejected = env.client.get(
            "/api/events", headers={"Authorization": "Bearer dtvp_pat_unknown"}
        )
        assert rejected.status_code == 401
        assert env.client.get("/api/events").status_code == 401


def test_application_wires_the_hub_and_the_project_list_producer(client):
    import asyncio

    from dtvp import dt_cache, main

    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    start = client.get("/api/events/poll").json()
    assert start["boot_id"] == main.event_hub.boot_id

    class Source:
        async def get_projects(self, name=""):
            return [{"uuid": "wired-1", "name": "Wired", "version": "1.0"}]

    asyncio.run(dt_cache.cache_manager._refresh_project_list(Source()))

    body = client.get("/api/events/poll", params={"since": start["cursor"]}).json()
    types = [event["type"] for event in body["events"]]
    assert "projects.changed" in types
    assert "source.state" in types or main.source_state_tracker.snapshot()["dt"] == "ok"


def test_heartbeat_hands_an_analyst_the_cursor_past_hidden_events():
    env = Env(hub=EventHub(boot_id="boot1", buffer_size=5), max_stream_seconds=0.4)

    def publish_hidden():
        import time as _time

        # Slowly enough that the live loop keeps up with the small buffer.
        for index in range(10):
            env.hub.publish("export.state", {"failed": index}, audience="reviewer")
            _time.sleep(0.01)

    timer = later(0.08, publish_hidden)
    _response, frames = env.stream(user="anna")
    timer.join()

    assert [frame["event"] for frame in events(frames)] == ["hello"]
    ids = [frame["id"] for frame in frames if "id" in frame]
    assert ids[-1] == "boot1:10"

    # Resuming from the last id the client saw needs no resync.
    _response, frames = env.stream(user="anna", params={"since": ids[-1]})
    assert [frame["event"] for frame in events(frames)] == ["hello"]


def test_session_hook_ends_the_stream_at_the_heartbeat():
    valid = {"rita": True}

    async def session_valid(request, user):
        return valid[user]

    env = Env(heartbeat_seconds=0.05, max_stream_seconds=5, session_valid=session_valid)
    timer = later(0.1, lambda: valid.update(rita=False))
    response, frames = env.stream()
    timer.join()

    assert response.status_code == 200
    assert events(frames)[-1] == {"comments": [], "event": "auth", "data": {"status": 401}}
    assert env.hub.connection_count == 0


def test_without_a_session_hook_a_cookie_session_streams_until_rotation():
    env = Env(heartbeat_seconds=0.05, max_stream_seconds=0.3)
    _response, frames = env.stream()
    assert "auth" not in [frame["event"] for frame in events(frames)]


def test_per_user_cap_answers_429_and_leaves_room_for_others():
    env = Env(hub=EventHub(boot_id="boot1", max_connections=10, max_connections_per_user=1))
    assert env.hub.try_acquire_connection("rita")

    response = env.client.get("/api/events", headers={"X-User": "rita"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
    assert response.json() == {"detail": "Too many live update connections for this user"}

    response, _frames = env.stream(user="anna")
    assert response.status_code == 200
    assert env.hub.user_connection_count("anna") == 0
    assert env.hub.user_connection_count("rita") == 1


def test_stream_lifetime_is_shortened_by_the_jitter():
    import time as _time

    env = Env(heartbeat_seconds=5, max_stream_seconds=1.0, random=lambda: 1.0)
    started = _time.monotonic()
    env.stream()
    elapsed = _time.monotonic() - started
    # Up to 10 % shorter: 0.9 s with random() == 1.
    assert 0.85 <= elapsed < 0.98
