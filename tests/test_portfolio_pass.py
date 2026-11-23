"""The portfolio pass (ADR 0004, "Portfolio pass"): one portfolio-wide
findings list tells which versions changed; only those are read one by one."""

import asyncio

import httpx

from dtvp.dt_client import DTClient
from dtvp.source_sync import SourceSync
from dtvp.source_sync_state import portfolio_digest
from tests.test_source_sync import Source, _finding, _scheduler


def _bulk_shape(finding, project_uuid):
    """A finding as Dependency-Track 4.14's portfolio list gives it
    (``Finding.QUERY_ALL_FINDINGS`` through the ``Finding`` constructor):
    the analysis only as ``state`` (absent without an analysis row) and
    ``isSuppressed`` (false without one); no details, justification or
    response. The project under the component."""
    analysis = finding.get("analysis") or {}
    shaped = {"isSuppressed": bool(analysis.get("isSuppressed", False))}
    if analysis.get("analysisState"):
        shaped["state"] = analysis["analysisState"]
    return {
        "component": {**finding["component"], "project": project_uuid},
        "vulnerability": dict(finding["vulnerability"]),
        "analysis": shaped,
    }


class BulkSource(Source):
    """Many versions, and the portfolio list (ports.BulkFindings)."""

    def __init__(self, versions=20, *, page_size=None):
        super().__init__()
        self.projects = [
            {"uuid": f"p{i}", "name": f"Product{i}", "version": "1", "active": True}
            for i in range(versions)
        ]
        self.findings = {f"p{i}": [_finding(f"c{i}")] for i in range(versions)}
        self.page_size = page_size
        self.fail_portfolio = False

    async def portfolio_findings(self, *, page_size=1000, on_page=None):
        self.calls.append(("portfolio",))
        if self.fail_portfolio:
            raise httpx.ConnectError("down")
        rows = [
            _bulk_shape(finding, uuid)
            for uuid, findings in self.findings.items()
            for finding in findings
        ]
        size = self.page_size or page_size
        pages = max(1, -(-len(rows) // size))
        by_project = {}
        for row in rows:
            by_project.setdefault(row["component"]["project"], []).append(row)
        for page in range(1, pages + 1):
            if on_page:
                on_page(page, pages)
        return by_project

    def portfolio_calls(self):
        return sum(1 for call in self.calls if call[0] == "portfolio")


async def _imported(scheduler, manager, source):
    """First imports run version by version (a first import needs the
    version's own read); afterwards only requests and due reads remain."""
    for _ in range(30):
        await scheduler.run_cycle(source)
        if all(row.get("last_success_at") for row in manager.sync_state.rows()):
            break
    await manager.flush_cache_writes()
    source.calls.clear()


async def test_read_all_again_is_one_portfolio_list_when_nothing_changed(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=20)
    await _imported(scheduler, manager, source)
    assert len(manager.sync_state.rows()) == 20

    requests = scheduler.request_reads([f"p{i}" for i in range(20)], by="rita")
    await scheduler.run_cycle(source)
    await scheduler.drain()
    await scheduler.run_cycle(source)

    assert source.portfolio_calls() == 1
    assert source.synced() == []  # no version read one by one
    versions = {v["project_uuid"]: v for v in manager.sync_state.list_versions()}
    for request in requests:
        progress = versions[request["project_uuid"]]["request"]
        assert progress["id"] == request["request_id"] and progress["state"] == "done"
    assert [e["phase"] for e in hub.of("source.portfolio_pass")][-1] == "done"
    await manager.close()


async def test_only_versions_whose_findings_changed_are_read_one_by_one(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=12)
    await _imported(scheduler, manager, source)

    # In the source: an analysis changes in p3, a finding is added to p7.
    source.findings["p3"][0] = {
        **source.findings["p3"][0],
        "analysis": {"analysisState": "EXPLOITABLE", "analysisDetails": "Reachable.", "isSuppressed": False},
    }
    source.findings["p7"].append(_finding("c7", "v2"))
    scheduler.request_reads([f"p{i}" for i in range(12)], by="rita")
    for _ in range(4):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.portfolio_calls() == 1
    assert sorted(source.synced()) == ["p3", "p7"]
    assert {row["requested_at"] for row in manager.sync_state.rows()} == {None}
    await manager.close()


async def test_few_due_versions_are_read_one_by_one(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=12)
    await _imported(scheduler, manager, source)

    scheduler.request_reads(["p1", "p2"], by="rita")  # below PASS_MIN_VERSIONS
    await scheduler.run_cycle(source)
    await scheduler.drain()

    assert source.portfolio_calls() == 0
    assert sorted(source.synced()) == ["p1", "p2"]
    await manager.close()


async def test_a_source_without_a_portfolio_list_reads_one_by_one(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=8)
    source = BulkSource(versions=8)
    await _imported(scheduler, manager, source)

    class Plain(Source):
        pass

    plain = Plain()
    plain.projects, plain.findings = source.projects, source.findings
    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    await scheduler.run_cycle(plain)
    await scheduler.drain()

    assert sorted(plain.synced()) == sorted(f"p{i}" for i in range(8))
    await manager.close()


async def test_a_failed_pass_falls_back_to_reading_one_by_one(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=8)
    source = BulkSource(versions=8)
    await _imported(scheduler, manager, source)
    source.fail_portfolio = True

    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.portfolio_calls() == 1
    assert sorted(source.synced()) == sorted(f"p{i}" for i in range(8))
    assert [e["phase"] for e in hub.of("source.portfolio_pass")][-1] == "failed"
    await manager.close()


async def test_the_first_pass_after_the_upgrade_seeds_digests_from_stored_findings(tmp_path):
    """Versions read before the pass existed have no portfolio digest: the
    first pass seeds it from their stored findings, so an unchanged version
    is not read one by one even then; a changed one is."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=8)
    source = BulkSource(versions=6)
    await _imported(scheduler, manager, source)
    connection = manager.store._connection()
    with connection:
        connection.execute("UPDATE sync_versions SET portfolio_digest = NULL")  # as upgraded
    source.findings["p4"].append(_finding("c4", "v9"))  # changed in the source

    scheduler.request_reads([f"p{i}" for i in range(6)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.portfolio_calls() == 1
    assert source.synced() == ["p4"]
    assert all(row["portfolio_digest"] for row in manager.sync_state.rows())
    await manager.close()


async def test_a_version_without_stored_findings_or_digest_is_read(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=8)
    source = BulkSource(versions=6)
    await _imported(scheduler, manager, source)
    connection = manager.store._connection()
    with connection:
        connection.execute("UPDATE sync_versions SET portfolio_digest = NULL WHERE project_uuid = 'p2'")
        connection.execute(
            "DELETE FROM source_snapshots WHERE kind = 'findings' AND project_uuid = 'p2'"
        )
    # As after a restart: nothing of p2's findings left in memory either.
    with manager._memory_cache_lock:
        manager._memory_cache.pop(manager._findings_path("p2"), None)

    scheduler.request_reads([f"p{i}" for i in range(6)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.synced() == ["p2"]
    assert manager.sync_state.row("p2")["portfolio_digest"] is not None
    await manager.close()


async def test_an_analysis_hint_settled_by_the_pass_is_not_planned_again(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=8)
    source = BulkSource(versions=6)
    for project in source.projects:
        project["dtvpSourceMarks"] = {"bom": "b1", "analysis": "a1"}
    await _imported(scheduler, manager, source)

    # Dependency-Track analysed every version again; nothing changed.
    for project in source.projects:
        project["dtvpSourceMarks"] = {"bom": "b1", "analysis": "a2"}
    clock.advance(3601)  # the next project-list read sees the new hints
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    assert source.portfolio_calls() == 1 and source.synced() == []

    source.calls.clear()
    clock.advance(SourceSync.PASS_MIN_INTERVAL_SECONDS + 1)
    for _ in range(2):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    assert source.calls == [] or all(call[0] == "projects" for call in source.calls)
    await manager.close()


async def test_request_counts_for_a_large_portfolio(tmp_path):
    """300 versions, all requested: one portfolio list of a few pages
    instead of three reads per version."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=16)
    source = BulkSource(versions=300, page_size=100)
    await _imported(scheduler, manager, source)

    scheduler.request_reads([f"p{i}" for i in range(300)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    per_version = sum(1 for call in source.calls if call[0] in ("findings", "vulns", "bom"))
    assert source.portfolio_calls() == 1 and per_version == 0
    assert scheduler._pass_pages == 3  # 300 findings, 100 a page
    await manager.close()


def test_the_digest_matches_a_versions_own_read_and_its_portfolio_share():
    """The shapes Dependency-Track 4.14 really returns: a version's own read
    is the project list enriched with each assessed finding's analysis read
    (details, justification, response), the portfolio row has only state and
    isSuppressed. Production saw every assessed version differ on every pass
    while the details counted."""
    own = [
        {
            "component": {"uuid": "c1", "project": "p"},
            "vulnerability": {"uuid": "v1"},
            "analysis": {
                "analysisState": "NOT_AFFECTED",
                "analysisJustification": "CODE_NOT_REACHABLE",
                "analysisResponse": "WILL_NOT_FIX",
                "analysisDetails": " Not used. ",
                "analysisComments": [],
                "isSuppressed": False,
            },
        },
        {   # never assessed: no analysis row
            "component": {"uuid": "c2", "project": "p"},
            "vulnerability": {"uuid": "v2"},
            "analysis": {"isSuppressed": False},
        },
        {   # suppressed: in the list read, not in the project export
            "component": {"uuid": "c3", "project": "p"},
            "vulnerability": {"uuid": "v3"},
            "analysis": {"analysisState": "FALSE_POSITIVE", "analysisDetails": "x", "isSuppressed": True},
        },
    ]
    share = [
        {"component": {"uuid": "c2", "project": "p"}, "vulnerability": {"uuid": "v2"},
         "analysis": {"isSuppressed": False}},
        {"component": {"uuid": "c1", "project": "p"}, "vulnerability": {"uuid": "v1"},
         "analysis": {"state": "NOT_AFFECTED", "isSuppressed": False}},
        {"component": {"uuid": "c3", "project": "p"}, "vulnerability": {"uuid": "v3"},
         "analysis": {"state": "FALSE_POSITIVE", "isSuppressed": True}},
    ]
    export_without_suppressed = own[:2]
    assert portfolio_digest(own) == portfolio_digest(share)
    assert portfolio_digest(export_without_suppressed) == portfolio_digest(share)
    changed = [{**share[1], "analysis": {"state": "EXPLOITABLE", "isSuppressed": False}}, share[0]]
    assert portfolio_digest(changed) != portfolio_digest(own)
    suppressed_now = [share[0], {**share[1], "analysis": {"state": "NOT_AFFECTED", "isSuppressed": True}}]
    assert portfolio_digest(suppressed_now) != portfolio_digest(share)


async def test_assessed_versions_are_settled_by_the_pass(tmp_path):
    """Assessed findings with details in the version's own read are settled
    by a portfolio list that carries no details."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=8)
    for uuid, findings in source.findings.items():
        findings[0] = {
            **findings[0],
            "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": f"Not used in {uuid}.",
                         "analysisJustification": "CODE_NOT_REACHABLE", "isSuppressed": False},
        }
    await _imported(scheduler, manager, source)

    scheduler.request_reads([f"p{i}" for i in range(8)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.portfolio_calls() == 1
    assert source.synced() == []
    await manager.close()


async def test_a_digest_of_the_old_kind_is_seeded_again_and_settles(tmp_path):
    """Digests recorded before this change never match a list: they count as
    missing, are seeded from the stored findings, and the first pass
    settles the unchanged versions."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=4)
    source = BulkSource(versions=6)
    await _imported(scheduler, manager, source)
    connection = manager.store._connection()
    with connection:
        connection.execute("UPDATE sync_versions SET portfolio_digest = 'deadbeef'")

    scheduler.request_reads([f"p{i}" for i in range(6)], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()

    assert source.portfolio_calls() == 1 and source.synced() == []
    assert all(row["portfolio_digest"].startswith("p2:") for row in manager.sync_state.rows())
    await manager.close()


async def test_versions_a_pass_left_unsettled_are_not_listed_again_before_their_read(tmp_path):
    """Production listed all 59 pages every minute while only a few of the
    changed versions had been read in between."""
    scheduler, manager, hub, clock = _scheduler(tmp_path, concurrency=1)
    source = BulkSource(versions=10)
    await _imported(scheduler, manager, source)
    for i in range(6):
        source.findings[f"p{i}"].append(_finding(f"c{i}", "v9"))

    scheduler.request_reads([f"p{i}" for i in range(10)], by="rita")
    await scheduler.run_cycle(source)
    await scheduler.drain()
    assert source.portfolio_calls() == 1
    assert scheduler._pass_judged == {f"p{i}" for i in range(6)}
    # The next minute: the changed versions are still waiting for their read.
    clock.advance(SourceSync.PASS_MIN_INTERVAL_SECONDS + 1)
    scheduler._pass_ended -= SourceSync.PASS_MIN_INTERVAL_SECONDS + 1
    await scheduler.run_cycle(source)
    assert source.portfolio_calls() == 1
    for _ in range(12):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    assert sorted(source.synced()) == [f"p{i}" for i in range(6)]
    assert source.portfolio_calls() == 1
    assert scheduler._pass_judged == set()
    await manager.close()


async def test_the_dependency_track_client_pages_the_portfolio_list():
    findings = [
        {
            "component": {"uuid": f"c{i}", "project": f"p{i % 3}"},
            "vulnerability": {"uuid": f"v{i}"},
            "analysis": {"state": "NOT_SET", "isSuppressed": False},
        }
        for i in range(2500)
    ]
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/finding"
        params = dict(request.url.params)
        seen.append(params)
        assert params["showInactive"] == "false" and params["showSuppressed"] == "true"
        number, size = int(params["pageNumber"]), int(params["pageSize"])
        page = findings[(number - 1) * size : number * size]
        return httpx.Response(200, json=page, headers={"X-Total-Count": str(len(findings))})

    client = DTClient("http://dt", "key")
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tokens = []

    async def take_token(_request=None):
        tokens.append(1)

    client.add_request_hook(take_token)
    progress = []
    by_project = await client.portfolio_findings(
        page_size=1000, on_page=lambda read, total: progress.append((read, total))
    )
    await client.client.aclose()

    assert [int(p["pageNumber"]) for p in seen] == [1, 2, 3]
    assert len(tokens) == 3  # one per HTTP page
    assert progress == [(1, 3), (2, 3), (3, 3)]
    assert sum(len(v) for v in by_project.values()) == 2500
    assert set(by_project) == {"p0", "p1", "p2"}
