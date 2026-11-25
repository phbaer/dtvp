"""Without users the sync reads nothing from the source but what the export
and explicit requests need (ADR 0004 amendment of 2026-11-23, "Idle without
users"); when someone comes back, one project-list read, then only what
changed."""

from dtvp.product_interest import ProductInterest
from tests.test_source_sync import _finding, _marked, _scheduler
from tests.test_unchanged_read import Assessed

TTL = 900


def _non_export(source):
    return [call for call in source.calls if call[0] != "update"]


async def _imported_then_idle(tmp_path, *, refresh=600):
    """Two products read while someone used River; then everyone left."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, active=False)
    source = Assessed()
    source.projects = [_marked(project, "b1", "a1") for project in source.projects]
    manager.refresh_interval_seconds = refresh
    scheduler.interest.note_request("rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    await manager.flush_cache_writes()
    assert sorted(set(source.synced())) == ["a1", "b1"]
    clock.advance(TTL + 1)  # the last request is older than the TTL: idle
    await scheduler.run_cycle(source)
    await scheduler.drain()
    assert scheduler.active is False
    source.calls.clear()
    return scheduler, manager, hub, clock, source


async def test_without_users_only_the_export_reaches_the_source(tmp_path):
    scheduler, manager, hub, clock, source = await _imported_then_idle(tmp_path)
    # A saved assessment waits for its export.
    await manager.persist_assessment_updates([{
        "project_uuid": "a1", "component_uuid": "c1", "vulnerability_uuid": "v1",
        "state": "EXPLOITABLE", "details": "Reachable.", "suppressed": False,
    }], replace=True, origin="user", author="carol")

    for _ in range(40):  # past the list interval, the safety re-read, everything
        clock.advance(scheduler.schedule.safety / 10)
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert _non_export(source) == []
    assert ("update", "a1") in source.calls  # the export still ran
    assert scheduler.status()["activity"]["active"] is False
    assert scheduler.progress()["active"] is False
    await manager.close()


async def test_a_lease_reads_the_list_once_then_only_what_changed(tmp_path):
    scheduler, manager, hub, clock, source = await _imported_then_idle(tmp_path, refresh=3600)
    clock.advance(scheduler.schedule.safety * 2)  # a long quiet night
    source.projects[1] = _marked(source.projects[1], "b1", "a2")  # DT re-analysed Beta

    scheduler.interest.put("alice", "tab", ["Alpha"])  # someone opens River
    for _ in range(5):
        clock.advance(60)
        scheduler.interest.put("alice", "tab", ["Alpha"])
        await scheduler.run_cycle(source)
        await scheduler.drain()

    calls = _non_export(source)
    assert calls.count(("projects",)) == 1
    # Beta's hint changed: findings and records. Alpha is opened and was read
    # over a night ago, longer than the safety interval: read too. Nothing else.
    assert sorted(call for call in calls if call[0] != "projects") == [
        ("bom", "a1"), ("findings", "a1"), ("findings", "b1"), ("vulns", "a1"), ("vulns", "b1"),
    ]
    assert scheduler.active is True and scheduler.status()["activity"]["leases"] == 1
    await manager.close()


async def test_coming_back_is_no_safety_reread_of_everything(tmp_path):
    scheduler, manager, hub, clock, source = await _imported_then_idle(tmp_path, refresh=3600)
    clock.advance(scheduler.schedule.safety * 2)
    scheduler.interest.note_request("rita")  # an API request, no product open

    for _ in range(5):
        clock.advance(60)
        scheduler.interest.note_request("rita")
        await scheduler.run_cycle(source)
        await scheduler.drain()

    # The safety interval counts only time in use: nothing is due yet.
    assert [call for call in _non_export(source) if call[0] != "projects"] == []
    clock.advance(scheduler.schedule.safety + 60)
    scheduler.interest.note_request("rita")
    await scheduler.run_cycle(source)
    await scheduler.drain()
    assert {call[1] for call in _non_export(source) if call[0] == "findings"} == {"a1", "b1"}
    await manager.close()


async def test_a_request_while_idle_runs_and_reads_nothing_else(tmp_path):
    scheduler, manager, hub, clock, source = await _imported_then_idle(tmp_path)
    clock.advance(scheduler.schedule.safety * 2)

    scheduler.request_reads(["b1"], by="rita")
    await scheduler.run_cycle(source)
    await scheduler.drain()

    assert ("projects",) not in source.calls
    assert sorted(set(call[1] for call in _non_export(source))) == ["b1"]
    assert scheduler.active is False
    await manager.close()


def test_activity_is_a_lease_or_a_recent_request():
    tick = [0.0]
    interest = ProductInterest(ttl_seconds=TTL, clock=lambda: tick[0])
    assert interest.active() is False
    interest.note_request("rita")
    assert interest.active() is True
    tick[0] += TTL + 1
    assert interest.active() is False
    interest.put("alice", "tab", ["Alpha"])
    assert interest.active() is True and interest.activity()["leases"] == 1
    tick[0] += TTL + 1
    assert interest.active() is False


def test_an_authenticated_request_counts_as_use():
    from dtvp import auth

    seen = []
    auth.add_request_listener(seen.append)
    try:
        assert auth._note_request("rita") == "rita"
    finally:
        auth._request_listeners.remove(seen.append)
    assert seen == ["rita"]
