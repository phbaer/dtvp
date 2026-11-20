import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from dtvp.event_hub import EventHub
from dtvp.event_producers import (
    AssessmentEventProducer,
    CacheRefreshProducer,
    ExportStateProducer,
    ProjectListEventProducer,
    SourceStateTracker,
    export_state_from_entries,
    project_list_diff,
)


def _project(uuid, name="App", version="1.0", **extra):
    return {"uuid": uuid, "name": name, "version": version, **extra}


# --- project_list_diff -------------------------------------------------------


def test_first_list_is_reported_as_initial():
    assert project_list_diff([], [_project("a"), _project("b")]) == {
        "initial": True,
        "count": 2,
        "added": [],
        "removed": [],
        "changed": [],
        "truncated": False,
    }


def test_added_removed_and_changed_fields():
    previous = [
        _project("a", dtvpSourceMarks={"bom": 1, "analysis": 1}),
        _project("b"),
        {"name": "no uuid"},
    ]
    current = [
        _project("a", dtvpSourceMarks={"bom": 2, "analysis": 1}, active=False),
        _project("c", name="New", version="2.0"),
    ]
    assert project_list_diff(previous, current) == {
        "added": [{"uuid": "c", "name": "New", "version": "2.0"}],
        "removed": [{"uuid": "b", "name": "App", "version": "1.0"}],
        "changed": [
            {
                "uuid": "a",
                "name": "App",
                "version": "1.0",
                "fields": ["active", "source_data"],
            }
        ],
        "truncated": False,
        "count": 2,
    }


def test_risk_score_and_metrics_alone_are_no_change():
    previous = [_project("a", lastRiskScore=1, metrics={"critical": 1})]
    current = [_project("a", lastRiskScore=9, metrics={"critical": 3})]
    assert project_list_diff(previous, current) is None
    assert project_list_diff([], []) is None


def test_long_lists_are_truncated():
    previous = [_project("seed")]
    current = previous + [_project(f"n{index}") for index in range(5)]
    diff = project_list_diff(previous, current, limit=2)
    assert len(diff["added"]) == 2
    assert diff["truncated"] is True
    assert diff["count"] == 6


def test_project_list_producer_publishes_only_changes():
    hub = EventHub(boot_id="b")
    producer = ProjectListEventProducer(hub)
    producer([_project("a")], [_project("a")])
    assert hub.current_seq() == 0
    producer([_project("a")], [_project("a"), _project("b")])
    (event,) = hub.events_after(0)
    assert event.type == "projects.changed"
    assert event.product is None
    assert event.audience == "all"
    assert event.envelope["data"]["added"][0]["uuid"] == "b"


# --- SourceStateTracker -------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def _status_error(code):
    request = httpx.Request("GET", "http://dt/api/v1/project")
    return httpx.HTTPStatusError(
        "error", request=request, response=httpx.Response(code, request=request)
    )


def test_source_state_publishes_transitions_only():
    hub = EventHub(boot_id="b")
    clock = _Clock()
    tracker = SourceStateTracker(hub, clock)
    assert tracker.snapshot()["dt"] == "unknown"

    clock.advance(1)
    tracker(True, None)
    clock.advance(60)
    tracker(True, None)
    assert [event.envelope["data"]["dt"] for event in hub.events_after(0)] == ["ok"]
    assert tracker.snapshot()["since"] == "2026-11-20T08:00:01Z"
    assert tracker.snapshot()["last_success_at"] == "2026-11-20T08:01:01Z"

    clock.advance(1)
    tracker(False, httpx.ConnectError("refused"))
    tracker(False, httpx.ConnectError("refused"))
    clock.advance(1)
    tracker(False, _status_error(401))

    states = [event.envelope["data"] for event in hub.events_after(0)]
    assert [state["dt"] for state in states] == ["ok", "down", "misconfigured"]
    assert states[1]["error_class"] == "ConnectError"
    assert states[2]["error_class"] == "HTTPStatusError"
    assert states[2]["last_success_at"] == "2026-11-20T08:01:01Z"

    tracker(False, _status_error(503))
    assert tracker.snapshot()["dt"] == "down"


# --- AssessmentEventProducer --------------------------------------------------


def test_assessment_events_are_grouped_by_product():
    hub = EventHub(boot_id="b")
    versions = [
        _project("p1", name="Alpha"),
        _project("p2", name="Alpha", version="2.0"),
        _project("p3", name="Beta"),
        # Known only by its uuid (active but not in the stored list).
        {"uuid": "p4", "name": "p4", "version": ""},
    ]
    producer = AssessmentEventProducer(hub, lambda: versions)
    producer(
        [
            ("p1", "c1", "v1"),
            ("p2", "c1", "v1"),
            ("p1", "c2", "v2"),
            ("p3", "c1", "v1"),
            ("p4", "c9", "v9"),
            ("unknown", "c1", "v1"),
        ]
    )
    by_product = {
        event.product: event.envelope["data"] for event in hub.events_after(0)
    }
    assert by_product["Alpha"] == {
        "product": "Alpha",
        "project_uuids": ["p1", "p2"],
        "keys_count": 3,
        "origin": "local",
    }
    assert by_product["Beta"]["project_uuids"] == ["p3"]
    assert by_product[None]["project_uuids"] == ["p4", "unknown"]
    assert by_product[None]["product"] is None


def test_no_keys_no_event():
    hub = EventHub(boot_id="b")
    AssessmentEventProducer(hub, lambda: [])([])
    assert hub.current_seq() == 0


# --- ExportStateProducer ------------------------------------------------------


class _Outbox:
    def __init__(self):
        self.entries = []
        self.calls = 0

    def list_pending(self):
        self.calls += 1
        return list(self.entries)


class _Cache:
    def __init__(self):
        self.assessment_outbox = _Outbox()


def test_export_state_numbers_follow_the_cache_status_rules():
    assert export_state_from_entries(
        [
            {"created_at": "2026-11-20T10:00:00Z", "last_error": "boom"},
            {"created_at": "2026-11-19T10:00:00Z"},
            {},
        ]
    ) == {"pending": 3, "failed": 1, "oldest_pending_at": "2026-11-19T10:00:00Z"}


@pytest.mark.asyncio
async def test_export_state_publishes_first_and_on_change_only_for_reviewers():
    hub = EventHub(boot_id="b")
    cache = _Cache()
    producer = ExportStateProducer(hub, cache)

    assert await producer.publish_if_changed() is True
    assert await producer.publish_if_changed() is False
    cache.assessment_outbox.entries = [{"created_at": "t1", "last_error": "x"}]
    assert await producer.publish_if_changed() is True

    events = hub.events_after(0)
    assert [event.audience for event in events] == ["reviewer", "reviewer"]
    assert events[0].envelope["data"] == {
        "pending": 0,
        "failed": 0,
        "oldest_pending_at": None,
    }
    assert events[1].envelope["data"] == {
        "pending": 1,
        "failed": 1,
        "oldest_pending_at": "t1",
    }


@pytest.mark.asyncio
async def test_export_state_loop_coalesces_marks():
    hub = EventHub(boot_id="b")
    cache = _Cache()
    producer = ExportStateProducer(hub, cache, min_interval=0.05, safety_interval=30)
    producer.mark_dirty()  # before the loop runs: ignored, nothing to wake
    task = asyncio.create_task(producer.run())
    try:
        await asyncio.sleep(0.02)
        assert hub.current_seq() == 1  # the first computation publishes
        calls_after_start = cache.assessment_outbox.calls

        cache.assessment_outbox.entries = [{"created_at": "t1"}]
        for _ in range(5):
            producer.mark_dirty()
        await asyncio.sleep(0.15)

        assert cache.assessment_outbox.calls == calls_after_start + 1
        assert hub.current_seq() == 2
        assert hub.events_after(1)[0].envelope["data"]["pending"] == 1
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


# --- CacheRefreshProducer -----------------------------------------------------


@pytest.mark.asyncio
async def test_cache_refreshed_is_published_when_the_refresh_time_moves():
    hub = EventHub(boot_id="b")
    state = {"at": "2026-11-20T10:00:00+00:00"}
    producer = CacheRefreshProducer(hub, lambda: state["at"])

    # The first value is only remembered.
    assert await producer.publish_if_changed() is False
    assert await producer.publish_if_changed() is False
    state["at"] = "2026-11-20T10:05:00+00:00"
    assert await producer.publish_if_changed() is True
    assert await producer.publish_if_changed() is False

    (event,) = hub.events_after(0)
    assert event.type == "cache.refreshed"
    assert event.audience == "all"
    assert event.envelope["data"] == {"last_refreshed_at": "2026-11-20T10:05:00+00:00"}


@pytest.mark.asyncio
async def test_cache_refreshed_follows_a_mark_from_the_cache():
    hub = EventHub(boot_id="b")
    state = {"at": None}
    producer = CacheRefreshProducer(hub, lambda: state["at"], min_interval=0.02)
    task = asyncio.create_task(producer.run())
    try:
        await asyncio.sleep(0.01)
        assert hub.current_seq() == 0
        state["at"] = "2026-11-20T10:05:00+00:00"
        producer.mark_dirty()
        await asyncio.sleep(0.1)
        assert [event.type for event in hub.events_after(0)] == ["cache.refreshed"]
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


def test_application_registers_the_cache_refresh_producer():
    from dtvp import main

    assert main.cache_refresh_producer.mark_dirty in (
        main.cache_manager._cache_status_listeners
    )


def test_a_list_stored_before_the_source_marks_existed_reports_no_change():
    previous = [_project("a")]
    current = [_project("a", dtvpSourceMarks={"bom": 2, "analysis": 2})]
    assert project_list_diff(previous, current) is None
