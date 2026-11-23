"""The background sync scheduler (ADR 0004 step 5): limits, planning,
priorities, staged commits, failures, recovery and events."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from dtvp.dt_cache import CacheManager
from dtvp.event_producers import AssessmentEventProducer, SourceStateTracker
from dtvp.product_interest import ProductInterest
from dtvp.source_sync import (
    BREAKER_DOWN,
    BREAKER_MISCONFIGURED,
    BREAKER_OK,
    P0_REQUEST,
    P1_WATCHED_FIRST,
    P2_DUE,
    P3_BACKFILL,
    P4_SAFETY,
    CircuitBreaker,
    LimitedSource,
    Schedule,
    SourceSync,
    SourceUnavailable,
    SyncItem,
    TokenBucket,
    _stagger,
    plan_version,
)

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


class Hub:
    def __init__(self):
        self.events = []

    def publish(self, type, data, *, product=None, audience="all"):
        self.events.append((type, data))
        return len(self.events)

    def of(self, type):
        return [data for kind, data in self.events if kind == type]


class Clock:
    def __init__(self, on_advance=None):
        # The cache stamps reads with the wall clock: start there.
        self.now = datetime.now(timezone.utc)
        self.tick = 1000.0
        self.on_advance = on_advance

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.tick += seconds
        if self.on_advance is not None:
            self.on_advance()


def _finding(component, vuln="v1"):
    return {
        "component": {"uuid": component, "name": "lib", "version": "1.0"},
        "vulnerability": {"uuid": vuln, "vulnId": f"CVE-{vuln}"},
        "analysis": {"analysisState": "NOT_SET", "analysisDetails": "", "isSuppressed": False},
    }


class PlainSource:
    """Two products, one version each; no change hints (ports.ChangeHints)."""

    def __init__(self):
        self.projects = [
            {"uuid": "a1", "name": "Alpha", "version": "1", "active": True},
            {"uuid": "b1", "name": "Beta", "version": "1", "active": True},
        ]
        self.findings = {"a1": [_finding("c1")], "b1": [_finding("c2")]}
        self.fail = set()
        self.calls = []

    async def get_projects(self, name=None):
        self.calls.append(("projects",))
        return [dict(project) for project in self.projects]

    async def get_vulnerabilities(self, project_uuid, cve=None):
        self.calls.append(("findings", project_uuid))
        if project_uuid in self.fail:
            raise httpx.ConnectError("down")
        return [dict(finding) for finding in self.findings.get(project_uuid, [])]

    async def get_project_vulnerabilities(self, project_uuid):
        self.calls.append(("vulns", project_uuid))
        return []

    async def get_bom(self, project_uuid):
        self.calls.append(("bom", project_uuid))
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}

    async def get_analysis(self, *args):
        return None

    async def get_vulnerability_affected(self, source, vuln_id):
        return None

    def synced(self):
        return [call[1] for call in self.calls if call[0] == "findings"]


class Source(PlainSource):
    """Like Dependency-Track: change hints under ``dtvpSourceMarks``."""

    def change_hint_kinds(self):
        return ("bom", "analysis")


def _scheduler(tmp_path, *, watched=(), concurrency=2, active=True):
    """``active``: someone uses DTVP (a request is noted at every clock
    step), so the scheduler reads the source; ``False`` leaves it idle
    unless a test adds a lease or a request."""
    clock = Clock(on_advance=None)
    manager = CacheManager(base_path=str(tmp_path))
    manager.refresh_interval_seconds = 3600
    interest = ProductInterest(clock=lambda: clock.tick)
    if active:
        interest.note_request("tester")
        clock.on_advance = lambda: interest.note_request("tester")
    for product in watched:
        interest.put("alice", "tab", [product])
    hub = Hub()
    tracker = SourceStateTracker(hub)
    scheduler = SourceSync(
        manager,
        hub=hub,
        interest=interest,
        source_state=tracker,
        schedule=Schedule(concurrency=concurrency),
        bucket=TokenBucket(1000, 1000),
        breaker=CircuitBreaker(clock=lambda: clock.tick),
        now=lambda: clock.now,
        monotonic=lambda: clock.tick,
    )
    scheduler.breaker._on_change = scheduler._breaker_changed
    return scheduler, manager, hub, clock


# -- limits ------------------------------------------------------------------


async def test_the_token_bucket_allows_a_burst_then_the_rate():
    now = [0.0]
    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    bucket = TokenBucket(2.0, 3.0, clock=lambda: now[0], sleep=sleep)
    for _ in range(5):
        await bucket.acquire()
    # Three at once, then one every half second.
    assert sleeps == [pytest.approx(0.5), pytest.approx(0.5)]


def test_the_breaker_opens_after_five_counted_failures_and_closes_on_success():
    changes = []
    tick = [0.0]
    breaker = CircuitBreaker(clock=lambda: tick[0], on_change=lambda *a: changes.append(a))
    not_found = httpx.HTTPStatusError(
        "404", request=httpx.Request("GET", "http://dt"), response=httpx.Response(404)
    )
    for _ in range(10):
        breaker.failure(not_found)  # not a sign that the source is down
    for _ in range(4):
        breaker.failure(httpx.ConnectError("down"))
    assert breaker.state == BREAKER_OK
    breaker.failure(httpx.ConnectError("down"))
    assert breaker.state == BREAKER_DOWN and not breaker.probe_due()
    tick[0] += 30
    assert breaker.probe_due()
    breaker.success()
    assert breaker.state == BREAKER_OK
    assert changes == [(BREAKER_DOWN, "ConnectError"), (BREAKER_OK, None)]


def test_a_rejected_key_opens_the_breaker_at_once_as_misconfigured():
    breaker = CircuitBreaker()
    breaker.failure(
        httpx.HTTPStatusError(
            "401", request=httpx.Request("GET", "http://dt"), response=httpx.Response(401)
        )
    )
    assert breaker.state == BREAKER_MISCONFIGURED


async def test_the_limited_source_takes_tokens_and_stops_while_open():
    calls = []

    class Inner:
        async def get_projects(self, name=None):
            calls.append(name)
            return []

    breaker = CircuitBreaker(threshold=1)
    limited = LimitedSource(Inner(), TokenBucket(100, 100), breaker)
    assert await limited.get_projects("x") == []
    breaker.failure(httpx.ConnectError("down"))
    with pytest.raises(SourceUnavailable):
        await limited.get_projects("y")
    assert calls == ["x"]


# -- planning ----------------------------------------------------------------


def _row(**values):
    base = {
        "project_uuid": "p1", "product_name": "App", "active_in_dt": 1,
        "status": "synced", "settled_status": "synced", "last_success_at": NOW.isoformat(),
        "findings_read_at": NOW.isoformat(), "vulns_read_at": NOW.isoformat(),
        "bom_read_at": NOW.isoformat(), "source_bom_hint": "1",
        "read_bom_signal": "1", "source_analysis_hint": "1",
        "read_analysis_signal": "1", "next_due_at": None, "requested_at": None,
    }
    return {**base, **values}


@pytest.mark.parametrize(
    "row, watched, seconds_later, expected",
    [
        (_row(), False, 60, None),
        (_row(), True, 60, None),
        # A watched product is not polled: unchanged hints, nothing due ...
        (_row(), True, 121, None),
        (_row(), True, 6 * 3600, None),
        # ... until it is opened with its last read older than the safety interval.
        (_row(), True, 12 * 3600, (P1_WATCHED_FIRST, ("findings", "vulns", "bom"),
                                   "opened, last read older than the safety interval")),
        (_row(), False, 12 * 3600, (P4_SAFETY, ("findings", "vulns", "bom"), "safety re-read")),
        (_row(last_success_at=None), False, 0, (P3_BACKFILL, ("findings", "vulns", "bom"), "first import, backfill")),
        (_row(last_success_at=None), True, 0, (P1_WATCHED_FIRST, ("findings", "vulns", "bom"), "first import, watched")),
        (_row(source_bom_hint="2"), False, 0, (P2_DUE, ("findings", "vulns", "bom"), "change hint: bom")),
        (_row(source_analysis_hint="2"), False, 0, (P2_DUE, ("findings", "vulns"), "change hint: analysis")),
        (_row(requested_at=NOW.isoformat()), False, 0, (P0_REQUEST, ("findings", "vulns", "bom"), "request")),
        (_row(status="gone"), True, 0, None),
        (_row(active_in_dt=0), True, 0, None),
        (
            _row(settled_status="failed", next_due_at=(NOW + timedelta(minutes=5)).isoformat()),
            True, 121, None,
        ),
        (
            # A request waits for the backoff too.
            _row(
                settled_status="failed", requested_at=NOW.isoformat(),
                next_due_at=(NOW + timedelta(minutes=5)).isoformat(),
            ),
            True, 0, None,
        ),
    ],
)
def test_what_is_due(row, watched, seconds_later, expected):
    now = NOW + timedelta(seconds=seconds_later)
    assert plan_version(row, watched=watched, now=now, schedule=Schedule()) == expected


def test_waiting_raises_the_priority_one_level_per_ten_minutes():
    item = SyncItem("p1", P4_SAFETY, ("findings",), enqueued_at=0.0)
    assert [item.effective(minutes * 60) for minutes in (0, 9, 10, 25, 60)] == [4, 4, 3, 2, 0]


# -- the scheduler ---------------------------------------------------------------


async def test_a_watched_product_is_imported_first_then_the_backfill(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, watched=["beta"], concurrency=1)
    source = Source()

    await scheduler.run_cycle(source)
    await scheduler.run_cycle(source)

    assert source.synced() == ["b1", "a1"]
    rows = {row["project_uuid"]: row for row in manager.sync_state.rows()}
    assert {row["status"] for row in rows.values()} == {"synced"}
    assert {row["generation"] for row in rows.values()} == {1}
    synced = hub.of("version.synced")
    assert [(event["uuid"], event["first_import"]) for event in synced] == [
        ("b1", True), ("a1", True),
    ]
    assert manager.active_project_uuids == {"b1"}
    await manager.close()


async def test_a_watched_product_is_read_on_a_hint_change_and_only_a_change_is_announced(tmp_path):
    """No polling (ADR 0004, 2026-11-23): a watched product with unchanged
    hints is not read again, however long it stays open; a hint change
    reads it, and only a change is announced."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, watched=["Alpha"])
    source = Source()
    source.projects = [_marked(project, "b1", "a1") for project in source.projects]
    manager.refresh_interval_seconds = 60
    await scheduler.run_cycle(source)
    await scheduler.drain()
    source.calls.clear()

    for _ in range(30):  # 30 list reads over 2.5 h, every interval of old passed
        clock.advance(300)
        await scheduler.run_cycle(source)
        await scheduler.drain()
    assert [call for call in source.calls if call[0] != "projects"] == []
    assert len(hub.of("version.synced")) == 2  # the two first imports

    source.findings["a1"].append(_finding("c9", vuln="v9"))
    source.projects[0] = _marked(source.projects[0], "b1", "a2")  # DT re-analysed Alpha
    clock.advance(300)
    await scheduler.run_cycle(source)
    await scheduler.drain()
    assert [call for call in source.calls if call[0] != "projects"] == [
        ("findings", "a1"), ("vulns", "a1"),
    ]
    [*_, changed] = hub.of("version.synced")
    assert changed["uuid"] == "a1" and changed["first_import"] is False
    assert (changed["findings_added"], changed["new_vuln_ids"]) == (1, ["CVE-v9"])
    assert changed["kinds_changed"] == ["findings"] and changed["generation"] == 2
    await manager.close()


async def test_a_failing_version_backs_off_and_reports_the_transition_once(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    source.fail.add("a1")

    await scheduler.run_cycle(source)
    [row] = [r for r in manager.sync_state.rows() if r["project_uuid"] == "a1"]
    assert row["status"] == "failed" and row["consecutive_failures"] == 1
    assert datetime.fromisoformat(row["next_due_at"]) == clock.now + timedelta(seconds=60)
    assert [event["uuid"] for event in hub.of("version.sync_failed")] == ["a1"]

    source.calls.clear()
    clock.advance(30)
    await scheduler.run_cycle(source)
    assert ("findings", "a1") not in source.calls

    clock.advance(31)
    await scheduler.run_cycle(source)
    [row] = [r for r in manager.sync_state.rows() if r["project_uuid"] == "a1"]
    assert row["consecutive_failures"] == 2
    assert datetime.fromisoformat(row["next_due_at"]) == clock.now + timedelta(seconds=120)
    # Still failing is not a new transition.
    assert len(hub.of("version.sync_failed")) == 1

    source.fail.clear()
    clock.advance(121)
    await scheduler.run_cycle(source)
    [row] = [r for r in manager.sync_state.rows() if r["project_uuid"] == "a1"]
    assert row["status"] == "synced" and row["consecutive_failures"] == 0
    await manager.close()


async def test_an_open_breaker_pauses_the_export_and_every_read(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    exports = []

    async def export(client):
        exports.append(client)

    manager.export_if_automatic = export
    source = Source()
    for _ in range(5):
        scheduler.breaker.failure(httpx.ConnectError("down"))
    assert [event["dt"] for event in hub.of("source.state")] == ["down"]

    await scheduler.run_cycle(source)
    assert exports == [] and source.calls == []

    clock.advance(31)  # the probe answers: the source is back
    await scheduler.run_cycle(source)
    assert scheduler.breaker.state == BREAKER_OK
    assert len(exports) == 1 and source.synced()
    assert [event["dt"] for event in hub.of("source.state") if "dt" in event][-1] == "ok"
    await manager.close()


async def test_a_restart_settles_interrupted_syncs(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await scheduler.run_cycle(source)
    store = manager.sync_state
    store.stage("a1")
    store.set_status("b1", "queued")

    restarted = SourceSync(manager, now=lambda: clock.now, monotonic=lambda: clock.tick)
    restarted.recover()

    rows = {row["project_uuid"]: row for row in store.rows()}
    # The interrupted sync is dropped and queued again first.
    assert (rows["a1"]["status"], rows["a1"]["staged_generation"]) == ("queued", None)
    assert rows["a1"]["settled_status"] == "synced"
    assert list(restarted.queue) == ["a1"]
    assert rows["b1"]["status"] == "synced"
    await manager.close()


async def test_the_backlog_is_part_of_the_source_state(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    await scheduler.run_cycle(source)
    # One of two versions done; one waits, then none.
    await scheduler.run_cycle(source)
    backlogs = [event["backlog"] for event in hub.of("source.state")]
    assert backlogs[0] > 0 and backlogs[-1] == 0
    await manager.close()


async def test_sync_states_are_published_at_most_every_five_seconds(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    row = {"project_uuid": "a1", "product_name": "Alpha"}
    scheduler._publish_state(row, "queued")
    scheduler._publish_state(row, "queued")
    clock.advance(5)
    scheduler._publish_state(row, "queued")
    assert len(hub.of("version.sync_state")) == 2
    await manager.close()


# -- interest, project list, origins -------------------------------------------


def test_a_users_read_takes_a_short_lease_renewed_at_most_once_a_minute():
    tick = [0.0]
    interest = ProductInterest(ttl_seconds=900, clock=lambda: tick[0])
    interest.touch("alice", "App")
    first = interest.leases()[0].expires_at
    tick[0] += 30
    interest.touch("alice", "App")
    assert interest.leases()[0].expires_at == first
    tick[0] += 31
    interest.touch("alice", "App")
    assert interest.leases()[0].expires_at == 961
    assert interest.watched() == {"App"}
    interest.touch("", "App")
    interest.touch("bob", " ")
    assert len(interest.leases()) == 1


async def test_a_stored_project_list_is_served_without_a_request(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    source = Source()
    first = await manager.get_projects(source)
    second = await manager.get_projects(source)
    assert first == second and source.calls == [("projects",)]
    await manager.close()


def test_assessment_events_carry_their_origin():
    hub = Hub()
    producer = AssessmentEventProducer(hub, lambda: [{"uuid": "p1", "name": "App"}])
    producer([("p1", "c", "v")], origin="dt")
    producer([("p1", "c", "v")], value_changed=False, origin="export_echo")
    producer([("p1", "c", "v")])
    assert [event["origin"] for event in hub.of("assessments.changed")] == [
        "dt", "export_echo", "local",
    ]


async def test_the_loop_wakes_on_a_save(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    cycles = []

    async def cycle(client, **_kwargs):
        cycles.append(client)

    scheduler.run_cycle = cycle
    wakeup = asyncio.Event()
    task = asyncio.create_task(scheduler.run(Source(), wakeup=wakeup))
    await asyncio.sleep(0.05)
    wakeup.set()
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(cycles) >= 2
    await manager.close()


# -- review of #324 ------------------------------------------------------------


class CountingBucket(TokenBucket):
    def __init__(self):
        super().__init__(1000, 1000)
        self.taken = 0

    async def acquire(self):
        self.taken += 1
        await super().acquire()


def _dt_client(handler):
    from dtvp.dt_client import DTClient

    client = DTClient("http://dt", api_key="k")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def test_the_budget_counts_http_requests_not_calls():
    """A paginated project list pays for every page."""
    def handler(request):
        page = int(request.url.params.get("pageNumber", "1"))
        size = 100 if page < 3 else 50
        return httpx.Response(
            200, json=[{"uuid": f"u{page}-{n}", "name": "P", "version": "1"} for n in range(size)]
        )

    client = _dt_client(handler)
    bucket = CountingBucket()
    limited = LimitedSource(client, bucket, CircuitBreaker())
    projects = await limited.get_projects("")
    assert len(projects) == 250 and bucket.taken == 3
    await client.close()


async def test_the_probe_is_one_cheap_request_within_the_budget():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"version": "4.14.2"})

    client = _dt_client(handler)
    bucket = CountingBucket()
    breaker = CircuitBreaker(threshold=1)
    breaker.failure(httpx.ConnectError("down"))
    await LimitedSource(client, bucket, breaker).probe()
    assert seen == ["/api/version"] and bucket.taken == 1
    await client.close()


async def test_the_request_hook_is_installed_once_per_client(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    client = _dt_client(lambda request: httpx.Response(200, json=[]))
    assert scheduler.limited(client) is scheduler.limited(client)
    assert len(client.client.event_hooks["request"]) == 1
    await client.close()
    await manager.close()


async def test_a_failed_list_read_counts_once_for_the_breaker(tmp_path):
    """As wired in main: the list listener and the call both see a failure."""
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    manager.add_source_state_listener(scheduler.breaker.observe)
    manager.refresh_interval_seconds = 0
    source = Source()

    async def down(name=None):
        raise httpx.ConnectError("down")

    async def no_export(client):
        pass

    source.get_projects = down
    manager.export_if_automatic = no_export
    for _ in range(3):
        await scheduler.run_cycle(source)
        clock.advance(1)
    assert (scheduler.breaker.failures, scheduler.breaker.state) == (3, BREAKER_OK)
    await manager.close()


async def test_a_large_first_start_sends_a_backlog_not_an_event_per_version(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    source.projects = [
        {"uuid": f"p{n}", "name": f"P{n}", "version": "1", "active": True} for n in range(500)
    ]
    await manager._refresh_project_list(source)
    scheduler.plan()
    assert hub.of("version.sync_state") == []
    assert [event["backlog"] for event in hub.of("source.state")] == [500]
    assert {row["status"] for row in manager.sync_state.rows()} == {"queued"}
    await manager.close()


async def test_planning_reads_the_rows_on_a_change_or_a_timer(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await scheduler.run_cycle(source)
    await scheduler.run_cycle(source)  # plans once after the syncs finished
    reads = []
    original = manager.sync_state.rows
    manager.sync_state.rows = lambda: reads.append(1) or original()

    for _ in range(5):
        clock.advance(1)
        await scheduler.run_cycle(source)
    assert reads == []
    clock.advance(15)
    await scheduler.run_cycle(source)
    assert len(reads) == 1
    await manager.close()


def _marked(project, bom, analysis):
    return {**project, "dtvpSourceMarks": {"bom": bom, "analysis": analysis}}


async def test_list_signals_reread_what_they_announce(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    source.projects = [_marked(source.projects[0], "b1", "a1")]
    manager.refresh_interval_seconds = 0
    await scheduler.run_cycle(source)
    source.calls.clear()

    source.projects = [_marked(source.projects[0], "b1", "a2")]
    clock.advance(20)
    await scheduler.run_cycle(source)
    assert [call for call in source.calls if call[0] != "projects"] == [
        ("findings", "a1"), ("vulns", "a1"),
    ]
    source.calls.clear()

    source.projects = [_marked(source.projects[0], "b2", "a2")]
    clock.advance(20)
    await scheduler.run_cycle(source)
    assert [call for call in source.calls if call[0] != "projects"] == [
        ("findings", "a1"), ("vulns", "a1"), ("bom", "a1"),
    ]
    source.calls.clear()
    clock.advance(20)
    await scheduler.run_cycle(source)
    assert [call for call in source.calls if call[0] != "projects"] == []
    await manager.close()


# -- sources without change hints (ports.ChangeHints) -------------------------


def test_a_version_without_hints_is_read_again_on_staggered_intervals():
    schedule = Schedule()
    row = _row()
    factor = _stagger("p1")

    def due(seconds):
        return plan_version(
            row, watched=False, now=NOW + timedelta(seconds=seconds),
            schedule=schedule, hinted=False,
        )

    assert 0.75 <= factor < 1
    # Changed hints mean nothing without hints: nothing is due early.
    assert plan_version(
        _row(source_bom_hint="2"), watched=False, now=NOW, schedule=schedule, hinted=False
    ) is None
    assert due(3600 * factor - 1) is None
    assert due(3600 * factor + 1) == (P3_BACKFILL, ("findings",), "unhinted findings interval")
    assert due(6 * 3600 * factor + 1) == (P3_BACKFILL, ("findings", "vulns"), "unhinted findings interval")
    assert due(24 * 3600 * factor + 1)[1] == ("findings", "vulns", "bom")
    # With hints, an unwatched version waits for a hint or the safety re-read.
    assert plan_version(
        row, watched=False, now=NOW + timedelta(hours=2), schedule=schedule
    ) is None


def test_the_stagger_spreads_versions_over_the_interval():
    factors = [_stagger(f"version-{index}") for index in range(200)]
    assert all(0.75 <= factor < 1 for factor in factors)
    assert max(factors) - min(factors) > 0.2
    assert len({round(factor, 3) for factor in factors}) > 100


async def test_a_source_without_hints_reads_hourly_and_the_bom_after_changed_findings(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = PlainSource()
    manager.refresh_interval_seconds = 3600 * 24
    await scheduler.run_cycle(source)
    assert scheduler.hinted is False
    assert sorted(source.synced()) == ["a1", "b1"]
    # Stored documents are written in the background; a version whose
    # findings are not stored yet would count as read but missing.
    await manager.flush_cache_writes()
    source.calls.clear()

    clock.advance(20 * 60)
    await scheduler.run_cycle(source)
    assert [call for call in source.calls if call[0] != "projects"] == []

    # After an hour (staggered) the findings are read again; changed
    # findings make the BOM due next.
    source.findings["a1"] = [_finding("c1"), _finding("c9")]
    clock.advance(45 * 60)
    await scheduler.run_cycle(source)
    reads = [call for call in source.calls if call[0] != "projects"]
    assert sorted(reads) == [("findings", "a1"), ("findings", "b1")]
    assert manager.sync_state.row("a1")["bom_read_at"] is None
    assert manager.sync_state.row("b1")["bom_read_at"] is not None
    source.calls.clear()
    clock.advance(20)
    await scheduler.run_cycle(source)
    # Only the version whose findings changed reads its BOM.
    boms = [call for call in source.calls if call[0] == "bom"]
    assert boms == [("bom", "a1")]
    await manager.close()


async def test_the_dependency_track_client_declares_its_hints():
    from dtvp.dt_client import DTClient
    from dtvp.ports import ChangeHints, change_hint

    assert issubclass(DTClient, ChangeHints) or hasattr(DTClient, "change_hint_kinds")
    assert not isinstance(PlainSource(), ChangeHints)
    assert isinstance(Source(), ChangeHints)
    assert change_hint({"dtvpSourceMarks": {"bom": 3}}, "bom") == 3
    assert change_hint({"name": "x"}, "bom") is None


async def test_the_export_shares_the_budget(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    scheduler.bucket = CountingBucket()
    seen = []

    async def export(client):
        seen.append(client)
        await client.get_projects("")

    manager.export_if_automatic = export
    await scheduler.run_cycle(Source())
    assert isinstance(seen[0], LimitedSource) and scheduler.bucket.taken >= 1
    await manager.close()


async def test_a_refused_call_is_no_failure_of_the_version(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await scheduler.run_cycle(source)
    for _ in range(5):
        scheduler.breaker.failure(httpx.ConnectError("down"))
    item = SyncItem("a1", P2_DUE, ("findings",), clock.tick)
    assert await scheduler.sync_version(scheduler.limited(source), item) is False
    row = manager.sync_state.row("a1")
    assert (row["status"], row["consecutive_failures"], row["next_due_at"]) == ("synced", 0, None)
    assert hub.of("version.sync_failed") == []
    await manager.close()


async def test_a_queued_version_no_longer_due_settles(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, watched=["Alpha"], concurrency=1)
    source = Source()
    await scheduler.run_cycle(source)
    await scheduler.run_cycle(source)
    await manager.flush_cache_writes()  # stored, or the findings count as missing
    clock.advance(scheduler.schedule.safety + 5)  # opened, last read older than that
    scheduler.interest.put("alice", "tab", ["Alpha"])  # the open tab renews its lease
    scheduler.plan()
    assert manager.sync_state.row("a1")["status"] == "queued"
    assert scheduler.queue["a1"].reason == "opened, last read older than the safety interval"
    scheduler.interest.put("alice", "tab", [])  # nobody watches Alpha any more
    scheduler.active_since = clock.now  # and the safety re-read counts from now
    scheduler.plan()
    assert "a1" not in scheduler.queue
    assert manager.sync_state.row("a1")["status"] == "synced"
    await manager.close()


async def test_a_slow_version_holds_only_its_own_slot(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=2)
    source = Source()
    gate = asyncio.Event()
    original = source.get_vulnerabilities

    async def slow(project_uuid, cve=None):
        if project_uuid == "a1":
            await gate.wait()
        return await original(project_uuid, cve)

    source.get_vulnerabilities = slow
    exports = []

    async def export(client):
        exports.append(1)

    manager.export_if_automatic = export
    await scheduler.run_cycle(source, wait=False)
    await asyncio.sleep(0.05)
    # b1 finished; a1 still runs; the next pass exports without waiting.
    assert manager.sync_state.row("b1")["status"] == "synced"
    await scheduler.run_cycle(source, wait=False)
    await asyncio.sleep(0.01)  # the export runs as its own task
    assert len(exports) == 2 and scheduler.running == {"a1"}
    gate.set()
    await scheduler.drain()
    assert manager.sync_state.row("a1")["status"] == "synced"
    await manager.close()


def test_a_failed_probe_waits_another_interval():
    tick = [0.0]
    breaker = CircuitBreaker(threshold=1, clock=lambda: tick[0])
    breaker.failure(httpx.ConnectError("down"))
    tick[0] = 30
    assert breaker.probe_due()
    breaker.failure(httpx.ConnectError("still down"))
    assert not breaker.probe_due()
    tick[0] = 59
    assert not breaker.probe_due()
    tick[0] = 60
    assert breaker.probe_due()


def test_the_backlog_is_published_when_it_empties_fills_or_moves_by_ten():
    hub = Hub()
    tracker = SourceStateTracker(hub)
    for backlog in (5, 9, 14, 15, 4, 0, 0, 1):
        tracker.set_backlog(backlog)
    assert [event["backlog"] for event in hub.of("source.state")] == [5, 15, 4, 0, 1]


def test_read_leases_do_not_push_out_a_browsers_lease():
    tick = [0.0]
    interest = ProductInterest(ttl_seconds=900, clock=lambda: tick[0])
    interest.put("alice", "tab", ["Kept"])
    for n in range(80):
        tick[0] += 1
        interest.touch("alice", f"Read{n}")
    watched = interest.watched()
    assert "Kept" in watched
    # The read leases keep their own cap: the newest 50.
    assert len(watched) == 51 and "Read79" in watched and "Read0" not in watched


# -- re-review of #324 -----------------------------------------------------------


async def test_a_failure_the_cache_does_not_record_still_backs_off(tmp_path):
    """An error outside a recorded read (here the BOM step) counts as a
    failure: the version backs off and the transition is announced once."""
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await scheduler.run_cycle(source)
    attempts = []

    async def broken(client, project_uuid, refresh=False):
        attempts.append(project_uuid)
        raise RuntimeError("bad payload")

    manager.get_bom = broken
    clock.advance(13 * 3600)  # the safety re-read, BOM included
    for _ in range(6):
        scheduler.mark_dirty()
        await scheduler.run_cycle(source)
        clock.advance(20)
    row = manager.sync_state.row("a1")
    assert attempts.count("a1") <= 2
    assert (row["settled_status"], row["consecutive_failures"]) == ("failed", attempts.count("a1"))
    assert len([e for e in hub.of("version.sync_failed") if e["uuid"] == "a1"]) == 1
    await manager.close()


async def test_stopping_the_loop_waits_for_its_syncs(tmp_path):
    """The client closes after ``run`` returns: no sync may still use it."""
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    started, stopped = asyncio.Event(), []

    async def hang(project_uuid, cve=None):
        started.set()
        try:
            await asyncio.sleep(3600)
        finally:
            stopped.append(project_uuid)

    source.get_vulnerabilities = hang
    loop = asyncio.create_task(scheduler.run(source, wakeup=asyncio.Event()))
    await asyncio.wait_for(started.wait(), 2)
    loop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop
    assert sorted(stopped) == ["a1", "b1"] and not scheduler._tasks
    await manager.close()


def test_a_request_path_success_does_not_close_a_misconfigured_breaker():
    breaker = CircuitBreaker()
    breaker.failure(
        httpx.HTTPStatusError(
            "401", request=httpx.Request("GET", "http://dt"), response=httpx.Response(401)
        )
    )
    breaker.observe(True)  # a user's own read succeeded
    assert breaker.state == BREAKER_MISCONFIGURED
    breaker.success()  # the scheduler's own call succeeded
    assert breaker.state == BREAKER_OK


async def test_a_failed_probe_is_not_repeated_before_the_interval(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    probes = []

    class Down(Source):
        async def get_projects(self, name=None):
            probes.append(1)
            raise httpx.ConnectError("down")

    for _ in range(5):
        scheduler.breaker.failure(httpx.ConnectError("down"))
    source = Down()
    clock.advance(30)
    await scheduler.run_cycle(source)
    for _ in range(29):
        clock.advance(1)
        await scheduler.run_cycle(source)
    assert len(probes) == 1
    clock.advance(1)
    await scheduler.run_cycle(source)
    assert len(probes) == 2
    await manager.close()


async def test_a_finished_sync_is_planned_after_at_once(tmp_path):
    """Without the timer: a sync's end marks the plan as due."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    scheduler.PLAN_INTERVAL_SECONDS = 3600
    scheduler._next_enrich = float("inf")  # the version ranges read the rows too
    source = Source()
    await scheduler.run_cycle(source)  # plans both, syncs one
    await scheduler.run_cycle(source)  # syncs the other
    assert {row["status"] for row in manager.sync_state.rows()} == {"synced"}
    reads = []
    original = manager.sync_state.rows
    manager.sync_state.rows = lambda: reads.append(1) or original()
    await scheduler.run_cycle(source)  # planned because the last sync ended
    await scheduler.run_cycle(source)  # nothing changed since: no plan
    assert len(reads) == 1
    await manager.close()


async def test_an_export_waits_for_a_findings_read_of_the_same_project(tmp_path):
    """The read and its classification come before the export's write."""
    manager = CacheManager(base_path=str(tmp_path))
    order = []
    reading = asyncio.Event()
    release = asyncio.Event()

    class Exchange(Source):
        async def get_vulnerabilities(self, project_uuid, cve=None):
            reading.set()
            await release.wait()
            order.append("read")
            return [_finding("c1")]

        async def update_analysis(self, **kwargs):
            order.append("write")
            return {}

    source = Exchange()
    await manager.persist_assessment_updates(
        [{"project_uuid": "a1", "component_uuid": "c1", "vulnerability_uuid": "v1",
          "state": "NOT_AFFECTED", "details": "Ours.", "suppressed": False}],
        replace=True,
    )
    read = asyncio.create_task(manager.import_findings(source, "a1"))
    await reading.wait()
    # The project is being read: its key waits for the next batch instead
    # of holding this one up.
    await asyncio.wait_for(manager.flush_pending_updates(source), 1)
    assert order == []
    release.set()
    await read
    await manager.flush_pending_updates(source)
    assert order == ["read", "write"]
    await manager.close()


async def test_a_findings_read_waits_for_an_export_write_in_flight():
    """Writes of one project share the gate; a read waits until they end."""
    from dtvp.dt_cache import _ExchangeGate

    gate = _ExchangeGate()
    order = []
    release = asyncio.Event()

    async def write(name):
        async with gate.write():
            order.append(f"{name} start")
            await release.wait()
            order.append(f"{name} end")

    async def read():
        async with gate.read():
            order.append("read")

    writes = [asyncio.create_task(write(n)) for n in ("w1", "w2")]
    await asyncio.sleep(0.01)
    reader = asyncio.create_task(read())
    await asyncio.sleep(0.01)
    assert order == ["w1 start", "w2 start"]  # both writes at once, no read
    release.set()
    await asyncio.gather(*writes, reader)
    assert order[-1] == "read"


# -- third review of #324 --------------------------------------------------------


async def test_an_overtaken_export_is_noted_before_a_read_compares(tmp_path):
    """Saved again while the write was in flight: the value the source now
    holds is recorded as exported before a waiting read classifies it."""
    manager = CacheManager(base_path=str(tmp_path))
    order = []
    in_write = asyncio.Event()
    finish_write = asyncio.Event()
    original_note = manager.assessment_outbox.note_exported

    def note(key, payload):
        order.append("noted")
        return original_note(key, payload)

    manager.assessment_outbox.note_exported = note

    class Exchange(Source):
        async def get_vulnerabilities(self, project_uuid, cve=None):
            order.append("read")
            return [_finding("c1")]

        async def update_analysis(self, **kwargs):
            in_write.set()
            await finish_write.wait()
            return {}

    source = Exchange()
    value = {"project_uuid": "a1", "component_uuid": "c1", "vulnerability_uuid": "v1",
             "suppressed": False}
    await manager.persist_assessment_updates(
        [{**value, "state": "NOT_AFFECTED", "details": "First."}], replace=True
    )
    export = asyncio.create_task(manager.flush_pending_updates(source))
    await in_write.wait()
    # Saved again while the write is in flight, and a read starts.
    await manager.persist_assessment_updates(
        [{**value, "state": "EXPLOITABLE", "details": "Second."}], replace=True
    )
    read = asyncio.create_task(manager.import_findings(source, "a1"))
    await asyncio.sleep(0.01)
    finish_write.set()
    await export
    await read
    assert order[:2] == ["noted", "read"]
    await manager.close()


async def test_the_loop_keeps_planning_while_an_export_waits(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    blocked = asyncio.Event()
    exports = []

    async def export(client):
        exports.append(1)
        await blocked.wait()

    manager.export_if_automatic = export
    source = Source()
    await asyncio.wait_for(scheduler.run_cycle(source, wait=False), 1)
    await asyncio.sleep(0.01)
    clock.advance(20)
    await asyncio.wait_for(scheduler.run_cycle(source, wait=False), 1)

    # The versions are planned and synced while the export waits. Wait for
    # that with a deadline rather than a fixed sleep: CI runners are slower.
    async def synced():
        while {row["status"] for row in manager.sync_state.rows()} != {"synced"}:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(synced(), 10)
    # One export at a time, and it is still waiting.
    assert exports == [1]
    blocked.set()
    await scheduler.drain()
    await manager.close()


async def test_a_waiting_read_goes_before_new_writes():
    from dtvp.dt_cache import _ExchangeGate

    gate = _ExchangeGate()
    order = []
    release_first = asyncio.Event()

    async def first_write():
        async with gate.write():
            order.append("w1")
            await release_first.wait()

    async def read():
        async with gate.read():
            order.append("read")

    async def second_write():
        async with gate.write():
            order.append("w2")

    tasks = [asyncio.create_task(first_write())]
    await asyncio.sleep(0.01)
    tasks.append(asyncio.create_task(read()))
    await asyncio.sleep(0.01)
    tasks.append(asyncio.create_task(second_write()))
    await asyncio.sleep(0.01)
    assert order == ["w1"]  # the second write waits behind the waiting read
    release_first.set()
    await asyncio.gather(*tasks)
    assert order == ["w1", "read", "w2"]


async def test_a_cancelled_holder_frees_the_gate():
    from dtvp.dt_cache import _ExchangeGate

    gate = _ExchangeGate()
    holding = asyncio.Event()

    async def read():
        async with gate.read():
            holding.set()
            await asyncio.sleep(3600)

    reader = asyncio.create_task(read())
    await holding.wait()
    reader.cancel()
    reader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await reader
    assert not gate.read_pending()

    async def write():
        async with gate.write():
            return True

    assert await asyncio.wait_for(write(), 1)


async def test_idle_gates_are_dropped(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    async with manager._project_exchange("a1").read():
        pass
    async with manager._project_exchange("b1").write():
        pass
    await asyncio.sleep(0.01)
    assert manager.__dict__.get("_exchange_gates") == {}
    await manager.close()


async def test_the_version_ranges_are_read_through_the_budget(tmp_path):
    """The scheduler's budgeted wrapper hides the source's methods from a
    protocol check; the ranges of the recommendation must still be read."""
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    reads = []

    class Ranges(Source):
        async def get_project_vulnerabilities(self, project_uuid):
            return [{"uuid": "v1", "vulnId": "CVE-v1", "source": "NVD"}]

        async def get_vulnerability_affected(self, source, vuln_id):
            reads.append(vuln_id)
            return {"affectedComponents": []}

    source = Ranges()
    await scheduler.run_cycle(source)
    await scheduler.drain()

    assert await manager.refresh_fixed_versions(scheduler.limited(source), "a1") == 1
    assert reads == ["CVE-v1"]
    await manager.close()


async def test_the_version_ranges_wait_until_no_version_is_read(tmp_path):
    """They run between syncs, at low priority, never inside a sync."""
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    order = []

    class Ranges(Source):
        async def get_vulnerabilities(self, project_uuid, cve=None):
            order.append(("findings", project_uuid))
            return await super().get_vulnerabilities(project_uuid, cve)

        async def get_project_vulnerabilities(self, project_uuid):
            return [{"uuid": "v1", "vulnId": f"CVE-{project_uuid}", "source": "NVD"}]

        async def get_vulnerability_affected(self, source, vuln_id):
            order.append(("ranges", vuln_id))
            return {"affectedComponents": []}

    source = Ranges()
    for _ in range(4):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    kinds = [kind for kind, _ in order]
    assert kinds.count("findings") == 2 and kinds.count("ranges") == 2
    # Every range read comes after both versions' findings reads.
    assert kinds.index("ranges") > max(i for i, k in enumerate(kinds) if k == "findings")
    await manager.close()
