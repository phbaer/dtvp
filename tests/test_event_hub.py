import asyncio
import json
import threading
from datetime import datetime, timezone

import pytest

from dtvp.event_hub import EventHub


def _hub(**kwargs):
    kwargs.setdefault("boot_id", "boot1")
    kwargs.setdefault("clock", lambda: datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc))
    return EventHub(**kwargs)


def test_seq_increases_and_frames_carry_the_cursor():
    hub = _hub()
    assert hub.current_seq() == 0
    assert hub.publish("a", {"x": 1}) == 1
    assert hub.publish("b", {"x": 2}, product="P") == 2
    assert hub.current_seq() == 2
    assert hub.cursor() == "boot1:2"

    first, second = hub.events_after(0)
    assert first.frame.startswith("id: boot1:1\nevent: a\ndata: ")
    assert first.frame.endswith("\n\n")
    envelope = json.loads(second.frame.split("data: ", 1)[1])
    assert envelope == {
        "seq": 2,
        "at": "2026-11-20T12:00:00Z",
        "type": "b",
        "product": "P",
        "data": {"x": 2},
    }
    assert second.envelope == envelope


def test_events_after_returns_later_events_in_order():
    hub = _hub()
    for index in range(5):
        hub.publish("e", {"i": index})
    assert [event.seq for event in hub.events_after(2)] == [3, 4, 5]
    assert hub.events_after(5) == []


def test_ring_buffer_evicts_and_reports_a_gap():
    hub = _hub(buffer_size=3)
    for index in range(5):
        hub.publish("e", {"i": index})
    # 1 and 2 are gone; a client at 2 has seen everything that was evicted.
    assert hub.events_after(1) is None
    assert [event.seq for event in hub.events_after(2)] == [3, 4, 5]


def test_a_future_cursor_cannot_be_served():
    hub = _hub()
    hub.publish("e", {})
    assert hub.events_after(2) is None


def test_parse_cursor():
    hub = _hub()
    assert hub.parse_cursor("boot1:7") == ("boot1", 7)
    assert hub.parse_cursor("other:3") == ("other", 3)
    for raw in (None, "", "boot1", "boot1:", ":5", "boot1:-1", "boot1:x"):
        assert hub.parse_cursor(raw) is None


def test_unknown_audience_is_rejected():
    with pytest.raises(ValueError):
        _hub().publish("e", {}, audience="admins")


@pytest.mark.asyncio
async def test_publish_from_another_thread_wakes_a_waiter():
    hub = _hub()
    waiter = asyncio.create_task(hub.wait(0, timeout_seconds=5))
    await asyncio.sleep(0.01)
    thread = threading.Thread(target=hub.publish, args=("e", {}))
    thread.start()
    result = await asyncio.wait_for(waiter, timeout=2)
    thread.join()
    assert result == 1


@pytest.mark.asyncio
async def test_wait_returns_at_once_when_events_exist_and_times_out_otherwise():
    hub = _hub()
    hub.publish("e", {})
    assert await hub.wait(0, timeout_seconds=5) == 1
    assert await hub.wait(1, timeout_seconds=0.01) == 1


@pytest.mark.asyncio
async def test_close_wakes_waiters():
    hub = _hub()
    waiter = asyncio.create_task(hub.wait(0, timeout_seconds=5))
    await asyncio.sleep(0.01)
    hub.close()
    assert await asyncio.wait_for(waiter, timeout=1) == 0
    assert hub.closed
    assert not hub.try_acquire_connection()
    hub.reopen()
    assert not hub.closed


def test_connection_cap():
    hub = _hub(max_connections=2)
    assert hub.try_acquire_connection()
    assert hub.try_acquire_connection()
    assert not hub.try_acquire_connection()
    assert hub.connection_count == 2
    hub.release_connection()
    assert hub.try_acquire_connection()
    assert hub.connection_count == 2


def test_per_user_cap_leaves_slots_for_other_users():
    hub = _hub(max_connections=10, max_connections_per_user=2)
    assert hub.acquire_connection("anna") is None
    assert hub.acquire_connection("anna") is None
    assert hub.acquire_connection("anna") == EventHub.REFUSED_USER
    assert hub.acquire_connection("rita") is None
    assert hub.connection_count == 3
    assert hub.user_connection_count("anna") == 2

    hub.release_connection("anna")
    assert hub.user_connection_count("anna") == 1
    assert hub.acquire_connection("anna") is None


def test_global_cap_wins_over_the_per_user_cap():
    hub = _hub(max_connections=1, max_connections_per_user=5)
    assert hub.acquire_connection("anna") is None
    assert hub.acquire_connection("rita") == EventHub.REFUSED_FULL
    assert hub.user_connection_count("rita") == 0
