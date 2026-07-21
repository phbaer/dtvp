import asyncio
import os
import threading

import httpx
import pytest
from unittest.mock import AsyncMock, patch
from dtvp.dt_cache import CacheManager, PendingUpdateExistsError, get_dt_cache_path


def test_cache_is_backend_scoped_and_rejects_namespace_reuse(tmp_path, monkeypatch):
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(tmp_path / "cache"))
    monkeypatch.setenv("DTVP_VULNERABILITY_BACKEND_ID", "cybeats-eu")
    monkeypatch.setenv("DTVP_VULNERABILITY_BACKEND_TYPE", "dependency-track")

    scoped_path = get_dt_cache_path()
    manager = CacheManager(base_path=scoped_path, backend_id="cybeats-eu")

    assert manager.base_path.endswith("cache/backends/cybeats-eu")
    assert manager.get_cache_status()["backend_id"] == "cybeats-eu"
    with pytest.raises(RuntimeError, match="different or invalid"):
        CacheManager(base_path=scoped_path, backend_id="another-backend")


def test_cache_status_reuses_snapshot_until_cache_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))

    with patch("dtvp.dt_cache.os.listdir", wraps=os.listdir) as listdir:
        first = manager.get_cache_status()
        first["cached_findings"] = 999
        first_scan_calls = listdir.call_count

        second = manager.get_cache_status()
        assert listdir.call_count == first_scan_calls
        assert second["cached_findings"] == 0

        manager._touch_cache_meta()
        third = manager.get_cache_status()

    assert listdir.call_count > first_scan_calls
    assert third["last_refreshed_at"] is not None


def test_grouped_cache_revision_is_scoped_and_skips_identical_writes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    projects = [
        {"name": "App One", "uuid": "project-1", "version": "1.0"},
        {"name": "App Two", "uuid": "project-2", "version": "2.0"},
    ]
    manager._save_project_cache(manager._projects_path(), projects)

    initial = manager.get_grouped_cache_revision(name="App One")
    manager._save_project_cache(
        manager._findings_path("project-2"),
        [{"vulnerability": {"uuid": "vuln-2"}}],
    )
    assert manager.get_grouped_cache_revision(name="App One") == initial

    manager._save_project_cache(
        manager._findings_path("project-1"),
        [{"vulnerability": {"uuid": "vuln-1"}}],
    )
    relevant_change = manager.get_grouped_cache_revision(name="App One")
    assert relevant_change != initial

    global_revision = manager.get_cache_revision()
    manager._save_project_cache(
        manager._findings_path("project-1"),
        [{"vulnerability": {"uuid": "vuln-1"}}],
    )
    assert manager.get_cache_revision() == global_revision
    assert manager.get_grouped_cache_revision(name="App One") == relevant_change

    manager._save_project_cache(
        manager._projects_path(),
        [*projects, {"name": "App Three", "uuid": "project-3", "version": "3.0"}],
    )
    assert manager.get_grouped_cache_revision(name="App One") == relevant_change

    updated_projects = [dict(projects[0], version="1.1"), projects[1]]
    manager._save_project_cache(manager._projects_path(), updated_projects)
    assert manager.get_grouped_cache_revision(name="App One") != relevant_change


@pytest.mark.asyncio
async def test_cache_file_encoding_does_not_block_event_loop(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]
    writer_started = threading.Event()
    release_writer = threading.Event()

    def delayed_write(path, data):
        writer_started.set()
        assert release_writer.wait(timeout=1)

    with patch("dtvp.dt_cache._atomic_write", side_effect=delayed_write):
        load_task = asyncio.create_task(manager.get_projects(client, name="Test"))
        for _ in range(100):
            if writer_started.is_set():
                break
            await asyncio.sleep(0.005)
        assert writer_started.is_set()

        event_loop_progressed = False

        async def mark_progress():
            nonlocal event_loop_progressed
            await asyncio.sleep(0)
            event_loop_progressed = True

        await asyncio.wait_for(mark_progress(), timeout=0.1)
        assert event_loop_progressed is True
        release_writer.set()
        assert await load_task == client.get_projects.return_value


@pytest.mark.asyncio
async def test_get_projects_caches_results(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]

    first = await manager.get_projects(client, name="Test")
    assert first == client.get_projects.return_value
    assert client.get_projects.call_count == 1

    second = await manager.get_projects(client, name="Test")
    assert second == first
    assert client.get_projects.call_count == 1

    loaded = manager._load_project_cache(manager._projects_path(), [])
    assert len(loaded) == 1
    assert loaded[0]["name"] == "TestApp"


@pytest.mark.asyncio
async def test_get_all_projects_reuses_fresh_complete_list(tmp_path):
    manager = CacheManager(
        base_path=str(tmp_path),
        project_list_ttl_seconds=30,
    )
    client = AsyncMock()
    client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]

    first = await manager.get_projects(client, name="")
    second = await manager.get_projects(client, name="")

    assert second == first
    assert second is not first
    assert client.get_projects.call_count == 1
    assert manager.cache_meta["projects_refreshed_at"] is not None


@pytest.mark.asyncio
async def test_get_all_projects_refreshes_expired_complete_list(tmp_path):
    manager = CacheManager(
        base_path=str(tmp_path),
        project_list_ttl_seconds=30,
    )
    client = AsyncMock()
    client.get_projects.side_effect = [
        [{"name": "First", "uuid": "uuid1", "version": "1.0"}],
        [{"name": "Second", "uuid": "uuid2", "version": "2.0"}],
    ]

    await manager.get_projects(client, name="")
    manager.cache_meta["projects_refreshed_at"] = "2000-01-01T00:00:00+00:00"
    refreshed = await manager.get_projects(client, name="")

    assert [project["name"] for project in refreshed] == ["Second"]
    assert client.get_projects.call_count == 2


@pytest.mark.asyncio
async def test_get_projects_uses_stale_full_cache_when_dt_unavailable(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    cached = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
        {"name": "Other", "uuid": "uuid2", "version": "2.0"},
    ]
    manager._save_project_cache(manager._projects_path(), cached)
    client = AsyncMock()
    client.get_projects.side_effect = RuntimeError("dt down")

    assert await manager.get_projects(client, name="") == cached


@pytest.mark.asyncio
async def test_get_projects_uses_stale_named_matches_when_dt_search_unavailable(
    tmp_path,
):
    manager = CacheManager(base_path=str(tmp_path))
    cached = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
        {"name": "Other", "uuid": "uuid2", "version": "2.0"},
    ]
    manager._save_project_cache(manager._projects_path(), cached)
    client = AsyncMock()
    client.get_projects.side_effect = RuntimeError("dt down")

    assert await manager.get_projects(client, name="Test") == [cached[0]]


@pytest.mark.asyncio
async def test_get_vulnerabilities_caches_results(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        {
            "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
            "component": {"uuid": "c1", "name": "lib"},
        }
    ]

    first = await manager.get_vulnerabilities(client, "uuid1")
    assert first == client.get_vulnerabilities.return_value
    assert client.get_vulnerabilities.call_count == 1

    second = await manager.get_vulnerabilities(client, "uuid1")
    assert second == first
    assert client.get_vulnerabilities.call_count == 1

    loaded = manager._load_project_cache(manager._findings_path("uuid1"), None)
    assert loaded[0]["component"]["name"] == "lib"


@pytest.mark.asyncio
async def test_concurrent_cache_misses_share_fetch_but_not_mutable_results(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    fetch_started = asyncio.Event()
    release_fetch = asyncio.Event()

    async def fetch_findings(_project_uuid, cve=None):
        fetch_started.set()
        await release_fetch.wait()
        return [
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"uuid": "c1", "name": "shared-lib"},
            }
        ]

    client.get_vulnerabilities.side_effect = fetch_findings
    first_request = asyncio.create_task(
        manager.get_vulnerabilities(client, "project-1")
    )
    await fetch_started.wait()
    second_request = asyncio.create_task(
        manager.get_vulnerabilities(client, "project-1")
    )
    await asyncio.sleep(0)
    release_fetch.set()

    first, second = await asyncio.gather(first_request, second_request)
    first[0]["component"]["name"] = "changed-by-first-request"
    cached = await manager.get_vulnerabilities(client, "project-1")

    assert client.get_vulnerabilities.call_count == 1
    assert second[0]["component"]["name"] == "shared-lib"
    assert cached[0]["component"]["name"] == "shared-lib"


@pytest.mark.asyncio
async def test_failed_shared_fetch_can_be_retried_immediately(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.side_effect = [
        RuntimeError("temporarily unavailable"),
        [],
    ]

    with pytest.raises(RuntimeError, match="temporarily unavailable"):
        await manager.get_vulnerabilities(client, "project-1")

    assert await manager.get_vulnerabilities(client, "project-1") == []
    assert client.get_vulnerabilities.call_count == 2


@pytest.mark.asyncio
async def test_record_project_access_skips_redundant_persistence(tmp_path, monkeypatch):
    manager = CacheManager(base_path=str(tmp_path))
    saved: list[dict[str, float]] = []
    monkeypatch.setattr(
        manager,
        "_save_active_projects",
        lambda project_uuids: saved.append(project_uuids),
    )

    await asyncio.gather(
        manager.record_project_access("project-1"),
        manager.record_project_access("project-1"),
        manager.record_project_access("project-1"),
    )

    assert len(saved) == 1
    assert set(saved[0]) == {"project-1"}


@pytest.mark.asyncio
async def test_active_project_refresh_is_recent_and_bounded(tmp_path, monkeypatch):
    now = 10_000.0
    manager = CacheManager(
        base_path=str(tmp_path),
        active_project_ttl_seconds=60,
        active_project_limit=2,
    )
    manager._active_project_last_access = {
        "expired": now - 61,
        "older": now - 30,
        "newer": now - 10,
        "newest": now - 1,
    }
    manager.active_project_uuids = set(manager._active_project_last_access)
    monkeypatch.setattr("dtvp.dt_cache.time.time", lambda: now)
    refresh_project = AsyncMock()
    monkeypatch.setattr(manager, "refresh_project", refresh_project)

    await manager._refresh_active_projects(AsyncMock())

    assert manager.active_project_uuids == {"newer", "newest"}
    assert set(manager._load_active_projects()) == {"newer", "newest"}
    assert {call.args[0] for call in refresh_project.await_args_list} == {
        "newer",
        "newest",
    }


def test_memory_file_cache_evicts_least_recently_used_entries(tmp_path):
    manager = CacheManager(
        base_path=str(tmp_path),
        memory_cache_max_entries=2,
    )
    first = str(tmp_path / "first.json")
    second = str(tmp_path / "second.json")
    third = str(tmp_path / "third.json")

    manager._load_cache_file(first, {"id": 1})
    manager._load_cache_file(second, {"id": 2})
    manager._load_cache_file(first, {"id": 1})
    manager._load_cache_file(third, {"id": 3})

    assert list(manager._memory_cache) == [first, third]


@pytest.mark.asyncio
async def test_named_project_query_cache_is_bounded_lru(tmp_path):
    manager = CacheManager(
        base_path=str(tmp_path),
        project_query_cache_max_entries=2,
    )
    client = AsyncMock()
    client.get_projects.side_effect = lambda name: [
        {"name": name, "uuid": f"uuid-{name}"}
    ]

    await manager.get_projects(client, name="one")
    await manager.get_projects(client, name="two")
    await manager.get_projects(client, name="one")
    await manager.get_projects(client, name="three")

    assert list(manager.project_query_cache) == ["one", "three"]


def test_cached_project_snapshot_discovers_persisted_findings(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    findings = [
        {
            "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
            "component": {"uuid": "c1", "name": "lib"},
            "analysis": {"analysisState": "NOT_SET"},
        }
    ]
    project_vulnerabilities = [{"vulnId": "CVE-1", "cvssV3BaseScore": 8.1}]
    bom = {"components": [{"bom-ref": "c1", "name": "lib"}]}

    manager._save_project_cache(manager._findings_path("project-1"), findings)
    manager._save_project_cache(
        manager._project_vulns_path("project-1"),
        project_vulnerabilities,
    )
    manager._save_project_cache(manager._bom_path("project-1"), bom)

    versions = manager.get_cached_project_versions()
    snapshot = manager.get_cached_project_snapshot("project-1")

    assert versions == [
        {"uuid": "project-1", "name": "project-1", "version": ""}
    ]
    assert snapshot == (findings, project_vulnerabilities, bom)


def test_cached_project_snapshot_overlays_local_assessment(tmp_path):
    # A finding whose cached findings file predates a local DTVP assessment
    # must surface the assessed state via the snapshot, so the automatic
    # code-analysis sweep does not re-queue an already-assessed vulnerability.
    manager = CacheManager(base_path=str(tmp_path))
    findings = [
        {
            "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
            "component": {"uuid": "c1", "name": "lib"},
            "analysis": {"analysisState": "NOT_SET", "isSuppressed": False},
        }
    ]
    manager._save_project_cache(manager._findings_path("project-1"), findings)
    manager._save_project_cache(
        manager._analysis_path("project-1", "c1", "v1"),
        {
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": (
                "--- [Team: General] [State: NOT_AFFECTED] "
                "[Assessed By: reviewer] ---\nNot affected."
            ),
            "isSuppressed": False,
        },
    )

    snapshot = manager.get_cached_project_snapshot("project-1")
    assert snapshot is not None
    overlaid_analysis = snapshot[0][0]["analysis"]
    assert overlaid_analysis["analysisState"] == "NOT_AFFECTED"
    assert "NOT_AFFECTED" in overlaid_analysis["analysisDetails"]


@pytest.mark.asyncio
async def test_queue_and_flush_pending_updates(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.update_analysis = AsyncMock(return_value={"status": "updated"})

    payload = {
        "project_uuid": "puuid",
        "component_uuid": "cuuid",
        "vulnerability_uuid": "vuuid",
        "state": "NOT_AFFECTED",
        "details": "Safe",
        "comment": "Test",
        "justification": "NOT_SET",
        "suppressed": False,
    }

    update_id = await manager.queue_analysis_update(payload)
    assert update_id
    pending = manager._load_pending_updates()
    assert len(pending) == 1
    assert pending[0]["payload"]["project_uuid"] == "puuid"

    await manager.flush_pending_updates(client)
    remaining = manager._load_pending_updates()
    assert remaining == []

    analysis = manager._load_project_cache(
        manager._analysis_path("puuid", "cuuid", "vuuid"), None
    )
    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert analysis["analysisDetails"] == "Safe"


@pytest.mark.asyncio
async def test_pending_update_flush_uses_global_bounded_concurrency(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("DTVP_ASSESSMENT_SYNC_CONCURRENCY", "2")
    manager = CacheManager(base_path=str(tmp_path))
    active = 0
    max_active = 0
    active_lock = asyncio.Lock()

    async def update_analysis(**_payload):
        nonlocal active, max_active
        async with active_lock:
            active += 1
            max_active = max(max_active, active)
        await asyncio.sleep(0.01)
        async with active_lock:
            active -= 1

    client = AsyncMock()
    client.update_analysis.side_effect = update_analysis
    await manager.queue_analysis_updates(
        [
            {
                "project_uuid": "project",
                "component_uuid": f"component-{index}",
                "vulnerability_uuid": f"vulnerability-{index}",
                "state": "NOT_AFFECTED",
                "details": "Safe",
                "suppressed": False,
            }
            for index in range(8)
        ],
        replace=True,
    )

    await manager.flush_pending_updates(client)

    assert max_active == 2
    assert manager._load_pending_updates() == []


@pytest.mark.asyncio
async def test_pending_update_flush_records_retry_without_blocking(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.update_analysis.side_effect = RuntimeError("DT unavailable")
    payload = {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "state": "IN_TRIAGE",
        "details": "Reviewing",
        "suppressed": False,
    }
    await manager.queue_analysis_update(payload)

    await manager.flush_pending_updates(client)

    pending = manager._load_pending_updates()
    assert len(pending) == 1
    assert pending[0]["attempts"] == 1
    assert pending[0]["last_error"] == "DT unavailable"
    assert pending[0]["next_attempt_at"] is not None
    assert manager.assessment_outbox.list_due() == []


@pytest.mark.asyncio
async def test_pending_update_flush_drops_update_when_finding_disappeared(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    request = httpx.Request("PUT", "https://dt.example.test/api/v1/analysis")
    response = httpx.Response(404, request=request)
    client = AsyncMock()
    client.update_analysis.side_effect = httpx.HTTPStatusError(
        "finding not found",
        request=request,
        response=response,
    )
    client.finding_exists.return_value = False
    payload = {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "state": "IN_TRIAGE",
        "details": "Reviewing",
        "suppressed": False,
    }
    await manager.queue_analysis_update(payload)

    await manager.flush_pending_updates(client)

    assert manager._load_pending_updates() == []
    client.finding_exists.assert_awaited_once_with(
        project_uuid="project",
        component_uuid="component",
        vulnerability_uuid="vulnerability",
    )
    assert manager.get_assessment_overlay(
        "project", "component", "vulnerability"
    ) is None
    assert manager._load_project_cache(
        manager._analysis_path("project", "component", "vulnerability"),
        None,
    ) is None


@pytest.mark.asyncio
async def test_pending_update_flush_keeps_404_when_exact_finding_still_exists(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    request = httpx.Request("PUT", "https://dt.example.test/api/v1/analysis")
    response = httpx.Response(404, request=request)
    client = AsyncMock()
    client.update_analysis.side_effect = httpx.HTTPStatusError(
        "analysis route returned not found",
        request=request,
        response=response,
    )
    client.finding_exists.return_value = True
    payload = {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "state": "IN_TRIAGE",
        "details": "Reviewing",
        "suppressed": False,
    }
    await manager.queue_analysis_update(payload)

    await manager.flush_pending_updates(client)

    pending = manager._load_pending_updates()
    assert len(pending) == 1
    assert pending[0]["attempts"] == 1
    assert "exact finding still exists" in pending[0]["last_error"]


@pytest.mark.asyncio
async def test_pending_update_flush_keeps_404_when_dt_check_fails(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    request = httpx.Request("PUT", "https://dt.example.test/api/v1/analysis")
    response = httpx.Response(404, request=request)
    client = AsyncMock()
    client.update_analysis.side_effect = httpx.HTTPStatusError(
        "analysis route returned not found",
        request=request,
        response=response,
    )
    client.finding_exists.side_effect = httpx.ConnectError(
        "Dependency-Track unavailable",
        request=request,
    )
    payload = {
        "project_uuid": "project",
        "component_uuid": "component",
        "vulnerability_uuid": "vulnerability",
        "state": "IN_TRIAGE",
        "details": "Reviewing",
        "suppressed": False,
    }
    await manager.queue_analysis_update(payload)

    await manager.flush_pending_updates(client)

    pending = manager._load_pending_updates()
    assert len(pending) == 1
    assert pending[0]["attempts"] == 1
    assert "could not verify the exact finding" in pending[0]["last_error"]
    assert "Dependency-Track unavailable" in pending[0]["last_error"]


@pytest.mark.asyncio
async def test_save_local_analysis_updates_cache_metadata(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    assert manager.cache_meta.get("last_refreshed_at") is None

    payload = {
        "project_uuid": "puuid",
        "component_uuid": "cuuid",
        "vulnerability_uuid": "vuuid",
        "state": "EXPLOITABLE",
        "details": "Updated by DT",
        "suppressed": False,
    }

    manager._save_local_analysis(payload)

    assert manager.cache_meta.get("last_refreshed_at") is not None
    loaded_meta = manager._load_projects_meta()
    assert loaded_meta.get("last_refreshed_at") is not None


@pytest.mark.asyncio
async def test_queue_duplicate_pending_update_rejected(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.update_analysis.return_value = {"status": "updated"}

    payload = {
        "project_uuid": "puuid",
        "component_uuid": "cuuid",
        "vulnerability_uuid": "vuuid",
        "state": "NOT_AFFECTED",
        "details": "Safe",
        "comment": "Test",
        "justification": "NOT_SET",
        "suppressed": False,
    }

    update_id = await manager.queue_analysis_update(payload)
    assert update_id

    with pytest.raises(PendingUpdateExistsError):
        await manager.queue_analysis_update(payload)


@pytest.mark.asyncio
async def test_queue_analysis_updates_uses_one_outbox_transaction(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    original = {
        "project_uuid": "project",
        "component_uuid": "component-0",
        "vulnerability_uuid": "vulnerability-0",
        "state": "IN_TRIAGE",
        "details": "Old value",
        "suppressed": False,
    }
    await manager.queue_analysis_update(original)
    replacements = [
        {
            "project_uuid": "project",
            "component_uuid": f"component-{index}",
            "vulnerability_uuid": f"vulnerability-{index}",
            "state": "NOT_AFFECTED",
            "details": f"Replacement {index}",
            "suppressed": False,
        }
        for index in range(100)
    ]

    with (
        patch.object(
            manager.assessment_outbox,
            "enqueue_many",
            wraps=manager.assessment_outbox.enqueue_many,
        ) as enqueue_many,
        patch.object(
            manager,
            "_save_local_analyses",
            wraps=manager._save_local_analyses,
        ) as save_local,
    ):
        update_ids = await manager.queue_analysis_updates(
            replacements,
            replace=True,
        )

    assert len(update_ids) == 100
    assert enqueue_many.call_count == 1
    assert save_local.call_count == 0
    pending = manager._load_pending_updates()
    assert len(pending) == 100
    assert pending[0]["payload"]["details"] == "Replacement 0"
    stored = manager.get_assessment_overlay(
        "project",
        "component-99",
        "vulnerability-99",
    )
    assert stored["analysisDetails"] == "Replacement 99"
    assert stored["dtvpSyncStatus"] == "pending"


@pytest.mark.asyncio
async def test_refresh_project_updates_memory_and_disk_cache(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()

    findings = [
        {
            "component": {
                "uuid": "component-1",
                "name": "log4j-core",
                "version": "2.17.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
            },
            "vulnerability": {
                "uuid": "vuln-1",
                "vulnId": "CVE-2021-44228",
                "name": "CVE-2021-44228",
            },
            "analysis": {
                "analysisState": "NOT_SET",
                "analysisDetails": "",
                "isSuppressed": False,
            },
        }
    ]
    project_vulnerabilities = [{"uuid": "vuln-1", "source": "NVD"}]
    bom = {"components": [{"bom-ref": "component-1"}]}

    client.get_vulnerabilities.return_value = findings
    client.get_project_vulnerabilities.return_value = project_vulnerabilities
    client.get_bom.return_value = bom

    await manager.refresh_project("project-1", client)

    findings_path = manager._findings_path("project-1")
    assert manager._memory_cache[findings_path] == findings
    assert manager._load_project_cache(findings_path, None) == findings

    client.get_vulnerabilities.reset_mock()
    cached_findings = await manager.get_vulnerabilities(client, "project-1")
    assert cached_findings == findings
    client.get_vulnerabilities.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_project_marks_review_when_threadmodel_score_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    project_uuid = "project-1"

    old_finding = {
        "component": {
            "uuid": "component-old",
            "name": "log4j-core",
            "version": "2.16.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
        },
        "vulnerability": {
            "uuid": "vuln-old",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "EXPLOITABLE",
            "analysisDetails": "[Rescored: 3.5]\nPrevious TM review.",
            "isSuppressed": False,
        },
    }
    manager._save_project_cache(manager._findings_path(project_uuid), [old_finding])

    new_finding = {
        "component": {
            "uuid": "component-new",
            "name": "log4j-core",
            "version": "2.17.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
        },
        "vulnerability": {
            "uuid": "vuln-new",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "EXPLOITABLE",
            "analysisDetails": "[Rescored: 4.0]\nUpdated TM review.",
            "isSuppressed": False,
        },
    }
    client.get_vulnerabilities.return_value = [new_finding]
    client.get_project_vulnerabilities.return_value = [{"uuid": "vuln-new"}]
    client.get_bom.return_value = {"components": []}

    await manager.refresh_project(project_uuid, client)

    saved_findings = manager._load_project_cache(
        manager._findings_path(project_uuid), None
    )
    assert len(saved_findings) == 1
    saved_analysis = saved_findings[0]["analysis"]

    assert saved_analysis["analysisState"] == "EXPLOITABLE"
    assert "Updated TM review." in saved_analysis["analysisDetails"]
    assert "[Status: Pending Review]" in saved_analysis["analysisDetails"]
    assert "TM rescoring changed from 3.5 to 4.0." in saved_analysis["analysisDetails"]

    persisted_analysis = manager._load_project_cache(
        manager._analysis_path(project_uuid, "component-new", "vuln-new"), None
    )
    assert persisted_analysis == saved_analysis


@pytest.mark.asyncio
async def test_get_analysis_preserves_cached_assessment_when_dt_returns_blank_details(
    tmp_path,
):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    payload = {
        "project_uuid": "project-1",
        "component_uuid": "component-1",
        "vulnerability_uuid": "vuln-1",
        "state": "NOT_AFFECTED",
        "details": "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\nStill safe.",
        "suppressed": False,
    }

    manager._save_local_analysis(payload)
    client.get_analysis.return_value = {
        "analysisState": "NOT_SET",
        "analysisDetails": "",
        "isSuppressed": False,
    }

    analysis = await manager.get_analysis(
        client,
        project_uuid="project-1",
        component_uuid="component-1",
        vulnerability_uuid="vuln-1",
        refresh=True,
    )

    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert "Still safe." in analysis["analysisDetails"]
    assert "[Status: Pending Review]" in analysis["analysisDetails"]


@pytest.mark.asyncio
async def test_get_vulnerabilities_preserves_assessment_for_recreated_dt_finding(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    project_uuid = "project-1"

    old_finding = {
        "component": {
            "uuid": "component-old",
            "name": "log4j-core",
            "version": "2.16.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
        },
        "vulnerability": {
            "uuid": "vuln-old",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\nHistorical assessment.",
            "isSuppressed": False,
        },
    }
    manager._save_project_cache(manager._findings_path(project_uuid), [old_finding])
    manager._save_local_analysis(
        {
            "project_uuid": project_uuid,
            "component_uuid": "component-old",
            "vulnerability_uuid": "vuln-old",
            "state": "NOT_AFFECTED",
            "details": "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\nHistorical assessment.",
            "suppressed": False,
        }
    )

    new_finding = {
        "component": {
            "uuid": "component-new",
            "name": "log4j-core",
            "version": "2.17.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
        },
        "vulnerability": {
            "uuid": "vuln-new",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "NOT_SET",
            "analysisDetails": "",
            "isSuppressed": False,
        },
    }
    client.get_vulnerabilities.return_value = [new_finding]

    findings = await manager.get_vulnerabilities(client, project_uuid, refresh=True)

    assert len(findings) == 1
    analysis = findings[0]["analysis"]
    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert "Historical assessment." in analysis["analysisDetails"]
    assert "[Status: Pending Review]" in analysis["analysisDetails"]

    migrated = manager._load_project_cache(
        manager._analysis_path(project_uuid, "component-new", "vuln-new"),
        None,
    )
    assert migrated == analysis


@pytest.mark.asyncio
async def test_get_vulnerabilities_marks_review_when_threadmodel_score_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    project_uuid = "project-1"

    old_finding = {
        "component": {
            "uuid": "component-old",
            "name": "log4j-core",
            "version": "2.16.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
        },
        "vulnerability": {
            "uuid": "vuln-old",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "EXPLOITABLE",
            "analysisDetails": "[Rescored: 3.5]\nPrevious TM review.",
            "isSuppressed": False,
        },
    }
    manager._save_project_cache(manager._findings_path(project_uuid), [old_finding])

    new_finding = {
        "component": {
            "uuid": "component-new",
            "name": "log4j-core",
            "version": "2.17.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
        },
        "vulnerability": {
            "uuid": "vuln-new",
            "vulnId": "CVE-2021-44228",
            "name": "CVE-2021-44228",
        },
        "analysis": {
            "analysisState": "EXPLOITABLE",
            "analysisDetails": "[Rescored: 4.0]\nUpdated TM review.",
            "isSuppressed": False,
        },
    }
    client.get_vulnerabilities.return_value = [new_finding]

    findings = await manager.get_vulnerabilities(client, project_uuid, refresh=True)

    assert len(findings) == 1
    analysis = findings[0]["analysis"]
    assert analysis["analysisState"] == "EXPLOITABLE"
    assert "Updated TM review." in analysis["analysisDetails"]
    assert "[Status: Pending Review]" in analysis["analysisDetails"]
    assert "TM rescoring changed from 3.5 to 4.0." in analysis["analysisDetails"]
