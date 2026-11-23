"""Manual requests: read a version now, ask the source for an analysis
(ADR 0004 step 8)."""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.sync_routes import create_sync_router
from tests.test_source_sync import Source, _scheduler


class AnalysingSource(Source):
    """A source that can be asked for an analysis (ports.AnalysisTrigger)."""

    source_display_name = "Test Source"

    def __init__(self):
        super().__init__()
        self.analyses = []
        self.running_polls = 0

    async def request_analysis(self, project_uuid):
        self.analyses.append(project_uuid)
        return f"token-{project_uuid}"

    async def analysis_running(self, token):
        self.running_polls += 1
        return self.running_polls < 2


async def _settled(scheduler, manager, source):
    """One cycle that imports everything, so later reads are only requests."""
    await scheduler.run_cycle(source)
    await scheduler.run_cycle(source)
    source.calls.clear()


async def test_a_requested_version_is_read_before_anything_else(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    await _settled(scheduler, manager, source)

    [first] = scheduler.request_reads(["b1"], by="rita")
    # A repeat while the request waits is the same request.
    [again] = scheduler.request_reads(["b1"], by="rita")
    assert first["new"] and not again["new"]
    assert again["request_id"] == first["request_id"]
    await scheduler.run_cycle(source)

    assert source.calls[0] == ("findings", "b1")
    assert {kind for kind, *_ in source.calls} >= {"findings", "vulns", "bom"}
    row = manager.sync_state.row("b1")
    assert row["requested_at"] is None and row["status"] == "synced"
    # Done, with the read time; then it can be requested again.
    [version] = [v for v in manager.sync_state.list_versions() if v["project_uuid"] == "b1"]
    assert version["request"]["id"] == first["request_id"]
    assert version["request"]["state"] == "done" and version["request"]["read_at"]
    [later] = scheduler.request_reads(["b1"], by="rita")
    assert later["new"] and later["request_id"] != first["request_id"]
    await manager.close()


async def test_a_request_wakes_the_loop(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await _settled(scheduler, manager, source)
    manager._assessment_sync_wakeup.clear()

    scheduler.request_reads(["a1"], by="rita")

    assert manager._assessment_sync_wakeup.is_set()
    await manager.close()


async def test_an_unknown_or_gone_version_is_not_requested(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await _settled(scheduler, manager, source)

    assert scheduler.request_reads(["nope"], by="rita") == []
    source.projects = [p for p in source.projects if p["uuid"] != "b1"]
    clock.advance(3601)
    await scheduler.run_cycle(source)  # the list read marks b1 gone
    assert scheduler.request_reads(["b1"], by="rita") == []
    await manager.close()


async def test_the_source_is_asked_for_an_analysis_then_the_version_is_read(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    scheduler.ANALYSIS_POLL_SECONDS = 0
    source = AnalysingSource()
    await _settled(scheduler, manager, source)

    assert scheduler.can_request_analysis
    assert scheduler.status()["source"] == {"name": "Test Source", "can_request_analysis": True}
    assert await scheduler.request_analysis(["a1"], by="rita") == ["a1"]
    # One analysis at a time per version.
    assert await scheduler.request_analysis(["a1"], by="rita") == []
    assert scheduler.status()["analysing"] == ["a1"]
    await scheduler.drain()

    assert source.analyses == ["a1"]
    assert source.running_polls == 2  # polled until it finished
    assert manager.sync_state.row("a1")["requested_at"] is not None
    assert ("analysing" in [e["status"] for e in hub.of("version.sync_state")])
    await scheduler.run_cycle(source)
    assert source.calls[0] == ("findings", "a1")
    await manager.close()


async def test_a_source_without_analysis_cannot_be_asked(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await _settled(scheduler, manager, source)

    assert not scheduler.can_request_analysis
    with pytest.raises(NotImplementedError):
        await scheduler.request_analysis(["a1"], by="rita")
    await manager.close()


async def test_an_analysis_request_spends_the_shared_budget(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    scheduler.ANALYSIS_POLL_SECONDS = 0
    source = AnalysingSource()
    await _settled(scheduler, manager, source)
    spent = []
    acquire = scheduler.bucket.acquire

    async def counting():
        spent.append(1)
        await acquire()

    scheduler.bucket.acquire = counting
    await scheduler.request_analysis(["b1"], by="rita")
    await scheduler.drain()

    assert len(spent) >= 1 + source.running_polls
    await manager.close()


# -- routes ----------------------------------------------------------------------


def _client(scheduler, manager, *, role="REVIEWER"):
    app = FastAPI()
    app.include_router(
        create_sync_router(
            lambda: manager.sync_state,
            current_user_dependency=lambda: "rita",
            scheduler_status=scheduler.status,
            scheduler=scheduler,
            is_reviewer=lambda user: role == "REVIEWER",
        ),
        prefix="/api",
    )
    return TestClient(app)


async def test_the_request_routes(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = AnalysingSource()
    scheduler.ANALYSIS_POLL_SECONDS = 0
    await _settled(scheduler, manager, source)
    client = _client(scheduler, manager)

    one = client.post("/api/sync/requests", json={"project_uuid": "a1"}).json()
    again = client.post("/api/sync/requests", json={"project_uuid": "a1"}).json()
    product = client.post("/api/sync/requests", json={"product": "beta"}).json()
    assert (one["requested"], one["already_requested"]) == (["a1"], [])
    assert (again["requested"], again["already_requested"]) == ([], ["a1"])
    assert again["requests"][0]["request_id"] == one["requests"][0]["request_id"]
    assert product["requested"] == ["b1"]
    versions = {
        v["project_uuid"]: v for v in client.get("/api/sync/versions").json()["versions"]
    }
    assert versions["a1"]["request"] == {
        "id": one["requests"][0]["request_id"], "by": "rita",
        "at": versions["a1"]["requested_at"], "state": "requested",
    }

    assert client.post("/api/sync/requests", json={}).status_code == 422
    assert client.post(
        "/api/sync/requests", json={"project_uuid": "a1", "product": "Alpha"}
    ).status_code == 422
    assert client.post("/api/sync/requests", json={"product": "Nothing"}).status_code == 404

    analysis = client.post("/api/sync/analysis-requests", json={"product": "Alpha"})
    assert analysis.status_code == 200 and analysis.json()["requested"] == ["a1"]
    status = client.get("/api/sync/status").json()["scheduler_state"]
    assert status["source"]["can_request_analysis"] is True
    await scheduler.drain()
    await manager.close()


async def test_requests_are_for_reviewers_and_need_a_capable_source(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Source()
    await _settled(scheduler, manager, source)

    analyst = _client(scheduler, manager, role="ANALYST")
    assert analyst.post("/api/sync/requests", json={"project_uuid": "a1"}).status_code == 403
    assert analyst.post("/api/sync/analysis-requests", json={"project_uuid": "a1"}).status_code == 403

    reviewer = _client(scheduler, manager)
    assert reviewer.post(
        "/api/sync/analysis-requests", json={"project_uuid": "a1"}
    ).status_code == 501
    assert reviewer.get("/api/sync/status").json()["scheduler_state"]["source"] == {
        "name": "the source", "can_request_analysis": False,
    }
    await manager.close()


async def test_the_dependency_track_client_asks_for_an_analysis():
    import httpx

    from dtvp.dt_client import DTClient
    from dtvp.ports import AnalysisTrigger, source_display_name

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("/analyze"):
            return httpx.Response(200, json={"token": "t-1"})
        return httpx.Response(200, json={"processing": False})

    client = DTClient("https://dt.example", "key")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    assert isinstance(client, AnalysisTrigger)
    assert source_display_name(client) == "Dependency-Track"
    assert await client.request_analysis("p-1") == "t-1"
    assert await client.analysis_running("t-1") is False
    assert seen == [
        ("POST", "/api/v1/finding/project/p-1/analyze"),
        ("GET", "/api/v1/event/token/t-1"),
    ]
    await client.close()


async def test_a_request_reads_every_kind_within_one_planning_interval(tmp_path):
    """The ninth reading's test: a request leads to a read of findings,
    vulnerability records and BOM within PLAN_INTERVAL_SECONDS when the
    source is reachable (the request wakes the loop and plans at once)."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    await _settled(scheduler, manager, source)

    scheduler.request_reads(["a1"], by="rita")
    started = clock.tick
    await scheduler.run_cycle(source)

    assert clock.tick - started < scheduler.PLAN_INTERVAL_SECONDS
    assert {call for call in source.calls if call[1:] == ("a1",)} == {
        ("findings", "a1"), ("vulns", "a1"), ("bom", "a1"),
    }
    await manager.close()


async def test_a_failed_request_says_why_and_stays(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = Source()
    await _settled(scheduler, manager, source)
    source.fail.add("a1")

    [request] = scheduler.request_reads(["a1"], by="rita")
    await scheduler.run_cycle(source)

    [version] = [v for v in manager.sync_state.list_versions() if v["project_uuid"] == "a1"]
    assert version["request"]["id"] == request["request_id"]
    assert version["request"]["state"] == "failed"
    assert "ConnectError" in version["request"]["error"]
    assert version["requested_at"]  # tried again after the backoff
    await manager.close()


async def test_a_version_whose_stored_findings_are_missing_is_read_again(tmp_path):
    """The sync state says read, but no findings are stored (a database
    replaced without the other): the version is read again, once."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=2)
    source = Source()
    await _settled(scheduler, manager, source)
    # Stored documents are written in the background: wait for b1's (and
    # a1's) before taking a1's away, or a slow runner sees b1's missing too.
    await manager.flush_cache_writes()
    connection = manager.store._connection()
    with connection:
        connection.execute(
            "DELETE FROM source_snapshots WHERE kind = 'findings' AND project_uuid = 'a1'"
        )

    clock.advance(16)  # the next plan: the read is too recent to judge
    await scheduler.run_cycle(source)
    assert source.synced() == []
    clock.advance(300)  # now the missing findings count
    await scheduler.run_cycle(source)
    assert "a1" in source.synced() and "b1" not in source.synced()

    await manager.flush_cache_writes()
    source.calls.clear()
    clock.advance(400)
    await scheduler.run_cycle(source)
    assert "a1" not in source.synced()  # once
    await manager.close()


async def test_after_a_restore_every_active_version_is_read_once(tmp_path):
    """A restore (python -m dtvp.backup) brings back the stored documents but
    not the sync state, which it starts empty: every active version is then
    read once, and not again until it is due."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=2)
    source = Source()
    await _settled(scheduler, manager, source)
    connection = manager.store._connection()
    with connection:
        connection.execute("DELETE FROM sync_versions")  # as restored

    scheduler.recover()
    clock.advance(3601)  # the next project-list read
    await scheduler.run_cycle(source)
    await scheduler.run_cycle(source)

    assert sorted(source.synced()) == ["a1", "b1"]
    assert {row["status"] for row in manager.sync_state.rows()} == {"synced"}
    source.calls.clear()
    clock.advance(16)
    await scheduler.run_cycle(source)
    assert source.synced() == []
    await manager.close()


async def test_the_cancel_route(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    await _settled(scheduler, manager, Source())
    client = _client(scheduler, manager)
    client.post("/api/sync/requests", json={"product": "alpha"})

    cancelled = client.post("/api/sync/cancel", json={}).json()
    assert cancelled["requests"] == ["a1"] and cancelled["pass"] is False
    assert client.post("/api/sync/cancel", json={"scope": ["everything"]}).status_code == 422
    assert _client(scheduler, manager, role="ANALYST").post(
        "/api/sync/cancel", json={}
    ).status_code == 403
    status = client.get("/api/sync/status").json()["scheduler_state"]
    assert {"progress", "recent_syncs", "last_portfolio_pass"} <= set(status)
    assert status["progress"]["paused"]["by"] == "rita"
    assert _client(scheduler, manager, role="ANALYST").post("/api/sync/resume").status_code == 403
    assert client.post("/api/sync/resume").json() == {"paused": False}
    assert client.get("/api/sync/status").json()["scheduler_state"]["progress"]["paused"] is None
    await manager.close()
