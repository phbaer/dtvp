"""Where a sync's time goes, its progress, and cancelling it (ADR 0004)."""

import asyncio
import logging

from dtvp.source_sync import P0_REQUEST, TokenBucket, _LOW_PRIORITY
from tests.test_portfolio_pass import BulkSource, _imported
from tests.test_source_sync import Source, _scheduler


async def test_a_sync_records_where_its_time_went(tmp_path, caplog):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    caplog.set_level(logging.INFO, logger="dtvp.source_sync")
    await scheduler.run_cycle(Source())
    await scheduler.drain()

    [first, *_] = scheduler.recent
    assert set(first["phases"]) >= {"preparing", "findings", "vulns", "bom", "commit"}
    assert first["requests"] >= 3 and first["seconds"] >= 0
    assert "status" not in first and scheduler.status()["recent_syncs"]
    assert any("waiting for the budget" in r.getMessage() for r in caplog.records)
    await manager.close()


async def test_progress_is_published_at_most_twice_a_second(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    for _ in range(20):
        scheduler._progress()
    sent = len(hub.of("source.sync_progress"))
    await asyncio.sleep(scheduler.PROGRESS_INTERVAL_SECONDS + 0.1)
    # One right away, one for the rest once the interval passed.
    assert sent == 1 and len(hub.of("source.sync_progress")) == 2
    await manager.close()


async def test_progress_shows_the_running_versions_and_their_phase(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    release = asyncio.Event()

    class Slow(Source):
        async def get_vulnerabilities(self, project_uuid, cve=None):
            await release.wait()
            return await super().get_vulnerabilities(project_uuid, cve)

    await scheduler.run_cycle(Slow(), wait=False)
    await asyncio.sleep(0.05)
    progress = scheduler.progress()
    assert {entry["uuid"] for entry in progress["running"]} == {"a1", "b1"}
    assert {entry["phase"] for entry in progress["running"]} == {"findings"}
    release.set()
    await scheduler.drain()
    assert scheduler.progress()["running"] == []
    await manager.close()


async def test_cancel_stops_running_syncs_without_a_failure(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)

    class Hanging(Source):
        async def get_vulnerabilities(self, project_uuid, cve=None):
            await asyncio.Event().wait()

    await scheduler.run_cycle(Hanging(), wait=False)
    await asyncio.sleep(0.05)
    assert scheduler.running == {"a1", "b1"}

    result = scheduler.cancel(["running"], by="rita")
    await scheduler.drain()

    assert sorted(result["running"]) == ["a1", "b1"]
    assert scheduler.running == set() and scheduler._items == {}
    for row in manager.sync_state.rows():
        assert row["staged_generation"] is None
        assert int(row.get("consecutive_failures") or 0) == 0
        assert row["status"] != "failed"
    assert not hub.of("version.sync_failed")
    assert scheduler.breaker.state == "ok"
    # The project's exchange gate is free again: an export can proceed.
    gate = manager._project_exchange("a1")
    async with gate.write():
        pass
    await manager.close()


async def test_cancel_withdraws_waiting_requests(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    await scheduler.run_cycle(source)
    await scheduler.drain()
    await scheduler.run_cycle(source)
    await scheduler.drain()

    scheduler.request_reads(["a1", "b1"], by="rita")
    scheduler.plan()
    assert all(item.priority == P0_REQUEST for item in scheduler.queue.values())
    result = scheduler.cancel(["requests"], by="rita")

    assert sorted(result["requests"]) == ["a1", "b1"]
    assert not any(item.priority == P0_REQUEST for item in scheduler.queue.values())
    versions = {v["project_uuid"]: v for v in manager.sync_state.list_versions()}
    assert {versions[u]["request"]["state"] for u in ("a1", "b1")} == {"cancelled"}
    assert all(row["requested_at"] is None for row in manager.sync_state.rows())
    await manager.close()


async def test_cancel_stops_the_portfolio_pass(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    gate = asyncio.Event()

    class SlowList(BulkSource):
        async def portfolio_findings(self, *, page_size=1000, on_page=None):
            if self.calls and on_page:
                on_page(1, 3)
            await gate.wait()
            return await super().portfolio_findings(page_size=page_size, on_page=on_page)

    source = SlowList(versions=8)
    await _imported(scheduler, manager, source)
    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    await scheduler.run_cycle(source, wait=False)
    await asyncio.sleep(0.05)
    assert scheduler._pass is not None and not scheduler._pass.done()
    assert scheduler.progress()["pass"]["phase"] == "reading"

    result = scheduler.cancel(["pass", "requests"], by="rita")
    await scheduler.drain()

    assert result["pass"] is True
    assert scheduler.last_pass["outcome"] == "cancelled"
    assert scheduler._pass_holds == set()
    assert [e["phase"] for e in hub.of("source.portfolio_pass")][-1] == "cancelled"
    assert source.synced() == []  # nothing read one by one instead
    await manager.close()


async def test_a_request_does_not_wait_for_the_pass_interval(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=8)
    await _imported(scheduler, manager, source)
    scheduler._pass_ended = scheduler._monotonic()  # a pass just ended
    scheduler.last_pass = {"outcome": "done"}

    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    await scheduler.run_cycle(source)
    await scheduler.drain()

    assert source.portfolio_calls() == 1 and source.synced() == []
    await manager.close()


async def test_versions_due_during_a_pass_wait_for_the_next_one(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    gate = asyncio.Event()

    class SlowList(BulkSource):
        async def portfolio_findings(self, *, page_size=1000, on_page=None):
            await gate.wait()
            return await super().portfolio_findings(page_size=page_size, on_page=on_page)

    source = SlowList(versions=16)
    await _imported(scheduler, manager, source)
    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    await scheduler.run_cycle(source, wait=False)
    await asyncio.sleep(0.05)
    scheduler.request_reads([f"p{i}" for i in range(8, 16)], by="rita")
    scheduler.plan()
    await scheduler.run_cycle(source, wait=False)
    await asyncio.sleep(0.05)
    assert source.synced() == []  # held, not read one by one beside the pass
    gate.set()
    for _ in range(4):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    assert source.synced() == []
    assert source.portfolio_calls() == 2
    await manager.close()


async def test_low_priority_requests_wait_for_the_others():
    clock = [0.0]

    async def sleep(seconds):
        clock[0] += seconds
        await asyncio.sleep(0)

    bucket = TokenBucket(1, 1, clock=lambda: clock[0], sleep=sleep)
    order = []

    async def low():
        token = _LOW_PRIORITY.set(True)
        try:
            await bucket.acquire()
            order.append("low")
        finally:
            _LOW_PRIORITY.reset(token)

    async def high(name):
        await bucket.acquire()
        order.append(name)

    await bucket.acquire()  # the burst is used up
    await asyncio.gather(low(), high("h1"), high("h2"))
    assert order == ["h1", "h2", "low"]
