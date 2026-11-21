import asyncio
import os
import threading
import time

import httpx
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta, timezone
from dtvp.dt_cache import (
    CacheManager,
    PendingUpdateExistsError,
    fixed_versions_due,
    fixed_versions_retry_delay,
)


def test_cache_status_reuses_snapshot_until_cache_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))

    with patch.object(
        manager.store, "counts", wraps=manager.store.counts
    ) as counts:
        first = manager.get_cache_status()
        first["cached_findings"] = 999
        first_scan_calls = counts.call_count

        second = manager.get_cache_status()
        assert counts.call_count == first_scan_calls
        assert second["cached_findings"] == 0

        manager._touch_cache_meta()
        third = manager.get_cache_status()

    assert counts.call_count > first_scan_calls
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

    with patch.object(manager, "_persist_document", side_effect=delayed_write):
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
    # The export stops, but the assessment is kept in case the finding returns.
    kept = manager.get_assessment_overlay("project", "component", "vulnerability")
    assert kept["dtvpSyncStatus"] == "inactive"
    assert kept["analysisDetails"] == "Reviewing"
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

    component = {
        "uuid": "component-1",
        "name": "log4j-core",
        "version": "2.17.0",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
    }
    vulnerability = {
        "uuid": "vuln-1",
        "vulnId": "CVE-2021-44228",
        "name": "CVE-2021-44228",
    }
    # The stored assessment of the same finding, rescored earlier.
    manager._save_local_analysis(
        {
            "project_uuid": project_uuid,
            "component_uuid": "component-1",
            "vulnerability_uuid": "vuln-1",
            "state": "EXPLOITABLE",
            "details": "[Rescored: 3.5]\nPrevious TM review.",
            "suppressed": False,
        }
    )

    new_finding = {
        "component": component,
        "vulnerability": vulnerability,
        "analysis": {
            "analysisState": "EXPLOITABLE",
            "analysisDetails": "[Rescored: 4.0]\nUpdated TM review.",
            "isSuppressed": False,
        },
    }
    client.get_vulnerabilities.return_value = [new_finding]
    client.get_project_vulnerabilities.return_value = [{"uuid": "vuln-1"}]
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
        manager._analysis_path(project_uuid, "component-1", "vuln-1"), None
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
    text = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\n"
        "Historical assessment."
    )

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
            "analysisDetails": text,
            "isSuppressed": False,
        },
    }
    client.get_vulnerabilities.return_value = [old_finding]
    await manager.get_vulnerabilities(client, project_uuid, refresh=True)

    # Recreated in another version and under a new vulnerability UUID with
    # the same identifier: the package URL without version still matches.
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
    # The BOM says the old component is gone.
    client.get_bom.return_value = {"components": [{"bom-ref": "component-new"}]}

    findings = await manager.get_vulnerabilities(client, project_uuid, refresh=True)

    assert len(findings) == 1
    analysis = findings[0]["analysis"]
    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert "Historical assessment." in analysis["analysisDetails"]
    assert "[Status: Pending Review]" in analysis["analysisDetails"]
    assert analysis["dtvpSyncStatus"] == "pending"
    history = manager.get_assessment_history(project_uuid, "component-new", "vuln-new")
    assert history[0]["origin"] == "carried-over"
    old = manager.assessment_outbox.get_overlay((project_uuid, "component-old", "vuln-old"))
    assert old["sync_status"] == "superseded"
    await manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("second_text, carried", [("Same.", True), ("Another.", False)])
async def test_recreated_findings_of_a_component_listed_twice_keep_a_shared_assessment(
    tmp_path, second_text, carried
):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    project_uuid = "project-1"

    def finding(component_uuid, state="NOT_SET", details=""):
        return {
            "component": {
                "uuid": component_uuid,
                "name": "lib-b",
                "version": "4.1.100",
                "purl": "pkg:maven/org.example/lib-b@4.1.100",
            },
            "vulnerability": {"uuid": "vuln-1", "vulnId": "CVE-2026-1", "name": "CVE-2026-1"},
            "analysis": {
                "analysisState": state, "analysisDetails": details, "isSuppressed": False,
            },
        }

    def block(text):
        return f"--- [Team: Alpha] [State: NOT_AFFECTED] [Assessed By: kim] ---\n{text}"

    # The BOM lists the component twice, each with the team's assessment.
    client.get_vulnerabilities.return_value = [
        finding("old-1", "NOT_AFFECTED", block("Same.")),
        finding("old-2", "NOT_AFFECTED", block(second_text)),
    ]
    await manager.get_vulnerabilities(client, project_uuid, refresh=True)
    # A BOM upload replaces both components; the source has no analysis.
    client.get_vulnerabilities.return_value = [finding("new-1"), finding("new-2")]
    client.get_bom.return_value = {"components": [{"bom-ref": "new-1"}, {"bom-ref": "new-2"}]}

    findings = await manager.get_vulnerabilities(client, project_uuid, refresh=True)

    for item in findings:
        details = item["analysis"]["analysisDetails"]
        if carried:
            assert item["analysis"]["analysisState"] == "NOT_AFFECTED"
            assert "[Team: Alpha]" in details and "Same." in details
            # The same name and version: recreated, not changed. No review.
            assert "[Status: Pending Review]" not in details
        else:
            # Two different assessments: which one applies is not ours to say.
            assert not details
    presence = manager.finding_lifecycle.presence(project_uuid)
    assert {presence[(c, "vuln-1")]["carry_over"] for c in ("old-1", "old-2")} == {
        "carried" if carried else "conflict"
    }
    await manager.close()


@pytest.mark.asyncio
async def test_get_vulnerabilities_marks_review_when_threadmodel_score_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    project_uuid = "project-1"

    # The stored assessment of the same finding, rescored earlier.
    manager._save_local_analysis(
        {
            "project_uuid": project_uuid,
            "component_uuid": "component-1",
            "vulnerability_uuid": "vuln-1",
            "state": "EXPLOITABLE",
            "details": "[Rescored: 3.5]\nPrevious TM review.",
            "suppressed": False,
        }
    )

    new_finding = {
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


# -- local-first merge on import --------------------------------------------


def _source_finding(state="NOT_SET", details="", suppressed=False):
    return {
        "component": {"uuid": "c1", "name": "lib-a", "version": "1.0"},
        "vulnerability": {"uuid": "v1", "vulnId": "CVE-2026-1"},
        "analysis": {
            "analysisState": state,
            "analysisDetails": details,
            "isSuppressed": suppressed,
        },
    }


def _local_payload(details="Local decision", state="NOT_AFFECTED"):
    return {
        "project_uuid": "p1",
        "component_uuid": "c1",
        "vulnerability_uuid": "v1",
        "state": state,
        "details": details,
        "suppressed": False,
    }


async def _manager_with_source(tmp_path, **source):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_source_finding(**source)]
    await manager.get_vulnerabilities(client, "p1")
    return manager, client


async def _analysis(manager, client, refresh=False):
    findings = await manager.get_vulnerabilities(client, "p1", refresh=refresh)
    return findings[0]["analysis"]


async def test_an_assessment_the_source_dropped_is_exported_again(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Carefully written")])
    await manager.flush_pending_updates(client)
    client.update_analysis.reset_mock()

    # The source recreated the finding and reports no assessment.
    client.get_vulnerabilities.return_value = [_source_finding()]
    analysis = await _analysis(manager, client, refresh=True)

    assert analysis["analysisDetails"] == "Carefully written"
    assert analysis["dtvpSyncStatus"] == "pending"
    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["details"] == "Carefully written"
    await manager.close()


async def test_a_text_without_a_state_is_read_from_the_source_and_not_exported_again(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    notes = "--- [Team: General] [State: NOT_SET] [Assessed By: rita] ---\nNotes so far."
    await manager.persist_assessment_updates([_local_payload(notes, state="NOT_SET")])
    client.get_analysis.return_value = {
        "analysisState": "NOT_SET", "analysisDetails": notes, "isSuppressed": False,
    }
    await manager.flush_pending_updates(client)
    client.update_analysis.reset_mock()
    client.get_analysis.reset_mock()

    # The findings list has the text of assessed findings only.
    listed = _source_finding()
    del listed["analysis"]["analysisDetails"]
    client.get_vulnerabilities.return_value = [listed]
    analysis = await _analysis(manager, client, refresh=True)

    client.get_analysis.assert_awaited_once_with(
        project_uuid="p1", component_uuid="c1", vulnerability_uuid="v1"
    )
    assert analysis["analysisDetails"] == notes
    assert analysis["dtvpSyncStatus"] == "synced"
    await manager.flush_pending_updates(client)
    client.update_analysis.assert_not_awaited()
    await manager.close()


async def test_a_finding_that_disappears_and_returns_keeps_its_assessment(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Kept across removal")])
    await manager.flush_pending_updates(client)
    client.update_analysis.reset_mock()

    client.get_vulnerabilities.return_value = []
    assert await manager.get_vulnerabilities(client, "p1", refresh=True) == []
    kept = manager.get_assessment_overlay("p1", "c1", "v1")
    assert kept["dtvpSyncStatus"] == "inactive"
    assert kept["analysisDetails"] == "Kept across removal"
    await manager.flush_pending_updates(client)
    client.update_analysis.assert_not_awaited()

    client.get_vulnerabilities.return_value = [_source_finding()]
    analysis = await _analysis(manager, client, refresh=True)
    assert analysis["analysisDetails"] == "Kept across removal"
    assert analysis["dtvpSyncStatus"] == "pending"
    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["details"] == "Kept across removal"
    await manager.close()


# -- regressions from the independent review (2026-11-17) -------------------


async def test_a_value_saved_again_mid_export_is_not_exported_stale(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("First")])
    sent = []

    async def write(**payload):
        sent.append(payload["details"])
        if payload["details"] == "First":
            # The user saves again while this write is in flight.
            await manager.persist_assessment_updates([_local_payload("Second")])

    client.update_analysis.side_effect = write
    client.get_analysis.side_effect = lambda **_kwargs: (
        {"analysisState": "NOT_AFFECTED", "analysisDetails": sent[-1], "isSuppressed": False}
        if sent
        else None
    )

    await manager.flush_pending_updates(client)
    await manager.flush_pending_updates(client)

    assert sent == ["First", "Second"]
    analysis = await _analysis(manager, client)
    # Our own earlier export is not mistaken for someone else's change.
    assert analysis["dtvpSyncStatus"] == "synced"
    assert analysis["analysisDetails"] == "Second"
    await manager.close()


async def test_a_batch_skips_an_entry_that_was_replaced_after_it_was_read(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Old")])
    stale_batch = manager.assessment_outbox.list_due()
    await manager.persist_assessment_updates([_local_payload("New")])

    with patch.object(manager.assessment_outbox, "list_due", return_value=stale_batch):
        await manager.flush_pending_updates(client)
    client.update_analysis.assert_not_awaited()

    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["details"] == "New"
    await manager.close()


async def test_an_assessed_finding_without_readable_details_is_not_merged(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Mine")])
    await manager.flush_pending_updates(client)

    # The per-finding read failed: a state, but no details field at all.
    finding = _source_finding()
    finding["analysis"] = {"analysisState": "NOT_AFFECTED", "isSuppressed": False}
    client.get_vulnerabilities.return_value = [finding]
    analysis = await _analysis(manager, client, refresh=True)

    assert analysis["analysisDetails"] == "Mine"
    assert analysis["dtvpSyncStatus"] == "synced"
    assert analysis["dtvpRevision"] == 1
    await manager.close()


def test_hopeless_exports_back_off_instead_of_retrying_every_minute():
    from dtvp.dt_cache import export_retry_delay_seconds

    assert [export_retry_delay_seconds(n) for n in range(1, 11)] == [
        1, 2, 4, 8, 16, 32, 60, 60, 60, 60,
    ]
    assert [export_retry_delay_seconds(n) for n in (11, 12, 13, 14, 15, 500)] == [
        120, 240, 480, 900, 900, 900,
    ]
    assert export_retry_delay_seconds(0) == 1


async def test_exports_to_a_deleted_project_stop_and_keep_the_assessment(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Written before the project was deleted")])
    request = httpx.Request("PUT", "http://dt/api/v1/analysis")
    client.update_analysis.side_effect = httpx.HTTPStatusError(
        "404", request=request, response=httpx.Response(404, request=request)
    )
    client.get_analysis.return_value = None  # a 404 there reads as no assessment
    client.finding_exists.return_value = False  # the project is gone

    await manager.flush_pending_updates(client)

    assert manager.get_cache_status()["pending_updates"] == 0
    kept = manager.get_assessment_overlay("p1", "c1", "v1")
    assert kept["dtvpSyncStatus"] == "inactive"
    assert kept["analysisDetails"] == "Written before the project was deleted"
    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_count == 1
    await manager.close()


# -- the local database is the record ---------------------------------------


async def test_source_assessments_are_adopted_and_unedited_ones_keep_all_fields(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    finding = _source_finding("NOT_AFFECTED", "From the source")
    finding["analysis"]["analysisJustification"] = "CODE_NOT_REACHABLE"
    client.get_vulnerabilities.return_value = [finding]

    analysis = (await manager.get_vulnerabilities(client, "p1"))[0]["analysis"]

    # Shown exactly as imported, including fields DTVP does not model.
    assert analysis["analysisJustification"] == "CODE_NOT_REACHABLE"
    assert analysis["analysisDetails"] == "From the source"
    # And recorded locally, so it survives the source losing it.
    record = manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))
    assert (record["revision"], record["sync_status"]) == (0, "synced")
    history = manager.get_assessment_history("p1", "c1", "v1")
    assert [(h["revision"], h["origin"]) for h in history] == [(0, "import")]
    assert manager.get_cache_status()["pending_updates"] == 0
    await manager.close()


async def test_first_local_edit_follows_the_adopted_value(tmp_path):
    manager, _client = await _manager_with_source(
        tmp_path, state="IN_TRIAGE", details="From the source"
    )

    await manager.persist_assessment_updates([_local_payload()], author="alice")

    stored = manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))
    assert stored["base"] == {
        "state": "IN_TRIAGE", "details": "From the source", "suppressed": False,
    }
    history = manager.get_assessment_history("p1", "c1", "v1")
    assert [(h["revision"], h["author"], h["origin"]) for h in history] == [
        (1, "alice", "user"),
        (0, None, "import"),
    ]
    await manager.close()


async def test_a_change_made_in_the_source_is_overwritten_by_the_local_record(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Decided in DTVP")])
    await manager.flush_pending_updates(client)
    client.update_analysis.reset_mock()

    client.get_vulnerabilities.return_value = [
        _source_finding("EXPLOITABLE", "Changed in Dependency-Track")
    ]
    analysis = await _analysis(manager, client, refresh=True)

    assert analysis["analysisDetails"] == "Decided in DTVP"
    assert analysis["dtvpSyncStatus"] == "pending"
    assert analysis["dtvpRemote"]["analysisDetails"] == "Changed in Dependency-Track"
    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["details"] == "Decided in DTVP"
    # The source is not read before the export any more.
    client.get_analysis.assert_not_awaited()
    await manager.close()


async def test_an_adopted_assessment_the_source_lost_is_exported_back(tmp_path):
    manager, client = await _manager_with_source(
        tmp_path, state="NOT_AFFECTED", details="Assessed long ago"
    )

    # The source recreated the finding and reports no assessment.
    client.get_vulnerabilities.return_value = [_source_finding()]
    analysis = await _analysis(manager, client, refresh=True)

    assert analysis["analysisDetails"] == "Assessed long ago"
    assert analysis["dtvpSyncStatus"] == "pending"
    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["details"] == "Assessed long ago"
    await manager.close()



@pytest.mark.asyncio
async def test_an_export_writes_the_response_of_the_exported_text(tmp_path):
    """Dependency-Track gets the response as its own field, read from the
    text of the very revision that is exported."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.update_analysis = AsyncMock(return_value={"status": "updated"})
    payload = {
        "project_uuid": "puuid",
        "component_uuid": "cuuid",
        "vulnerability_uuid": "vuuid",
        "state": "EXPLOITABLE",
        "details": (
            "[Response: UPDATE]\n\n--- [Team: General] [State: EXPLOITABLE] "
            "[Assessed By: rita] [Justification: NOT_SET] ---\nUpgrade to 2.0."
        ),
        "suppressed": False,
    }

    await manager.queue_analysis_update(payload)
    await manager.flush_pending_updates(client)

    sent = client.update_analysis.await_args.kwargs
    assert sent["response"] == "UPDATE"
    assert sent["details"] == payload["details"]
    assert manager._load_pending_updates() == []
    assert manager.get_assessment_fields("puuid", "cuuid", "vuuid")["response"] == "UPDATE"

    # Removed in DTVP: the next export says so.
    await manager.queue_analysis_update(
        {**payload, "details": payload["details"].replace("[Response: UPDATE]\n\n", "")},
        replace=True,
    )
    await manager.flush_pending_updates(client)

    assert client.update_analysis.await_args.kwargs["response"] is None
    assert manager.get_assessment_fields("puuid", "cuuid", "vuuid")["response"] is None


# -- version ranges for the VDR recommendation --------------------------------


class RangeSource:
    """A source with findings and the version ranges of their vulnerabilities."""

    def __init__(self, records, *, findings=None, bom=None, ranges=None, delay=0.0):
        self.records = records
        self.findings = findings or []
        self.bom = bom or {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        self.ranges = ranges or {}
        self.delay = delay
        self.reads = []
        self.fail = set()

    async def get_projects(self, name=None):
        return []

    async def get_vulnerabilities(self, project_uuid, cve=None):
        return [dict(finding) for finding in self.findings]

    async def get_project_vulnerabilities(self, project_uuid):
        return [dict(record) for record in self.records]

    async def get_bom(self, project_uuid):
        return self.bom

    async def get_analysis(self, project_uuid, component_uuid, vulnerability_uuid):
        return None

    async def get_vulnerability_affected(self, source, vuln_id):
        self.reads.append((source, vuln_id))
        if self.delay:
            await asyncio.sleep(self.delay)
        if (source, vuln_id) in self.fail:
            raise httpx.ConnectError("down")
        entries = self.ranges.get((source, vuln_id))
        return None if entries is None else {"affectedComponents": entries}


def _record(vuln_id, updated=1, **extra):
    return {"uuid": f"u-{vuln_id}", "vulnId": vuln_id, "source": "NVD",
            "updated": updated, **extra}


LIB_A_FIX = [{"identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "RANGE",
              "versionEndExcluding": "1.2.3",
              "affectedVersionAttributions": [{"source": "GITHUB"}]}]


async def test_fixed_versions_are_read_when_missing_or_stale_and_capped(tmp_path):
    manager = CacheManager(base_path=str(tmp_path), fixed_versions_reads_per_cycle=2)
    records = [
        _record("CVE-1"), _record("CVE-2"), _record("CVE-3"),
        _record("CVE-4", recommendation="Upgrade."),  # DT's own text: not read
    ]
    client = RangeSource(records, ranges={("NVD", "CVE-1"): LIB_A_FIX})

    await manager.refresh_project("p1", client)
    # The cap; the reads run concurrently, in no fixed order.
    assert sorted(client.reads) == [("NVD", "CVE-1"), ("NVD", "CVE-2")]
    await manager.refresh_project("p1", client)
    assert client.reads[2:] == [("NVD", "CVE-3")]  # only the missing one
    await manager.refresh_project("p1", client)
    assert client.reads[3:] == []  # nothing stale

    rows = manager.store.fixed_version_entries([("NVD", "CVE-1"), ("NVD", "CVE-2")])
    assert rows[("NVD", "CVE-1")]["status"] == "read"
    assert rows[("NVD", "CVE-1")]["payload"] == [{
        "identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "RANGE",
        "versionEndExcluding": "1.2.3", "sources": ["GITHUB"],
    }]
    assert rows[("NVD", "CVE-2")]["status"] == "not_found"

    # A changed record is read again at once.
    client.records = [_record("CVE-1", updated=2), *records[1:]]
    await manager.refresh_project("p1", client)
    assert client.reads[3:] == [("NVD", "CVE-1")]

    # After the TTL every entry, also a not-found one, is read again.
    manager.fixed_versions_refresh_days = 1
    old = "2020-01-01T00:00:00+00:00"
    manager.store.save_fixed_version_entry(
        "NVD", "CVE-2", status="not_found", vuln_updated="1", at=old
    )
    await manager.refresh_project("p1", client)
    assert client.reads[4:] == [("NVD", "CVE-2")]


async def test_one_cap_holds_for_a_whole_refresh_cycle(tmp_path):
    manager = CacheManager(base_path=str(tmp_path), fixed_versions_reads_per_cycle=3)
    manager.active_project_uuids = {"p1", "p2"}
    manager._active_project_last_access = {"p1": time.time(), "p2": time.time()}
    client = RangeSource([_record(f"CVE-{n}") for n in range(5)])
    await manager._refresh_active_projects(client)
    # The same five records in both projects: three reads, not six.
    assert len(client.reads) == 3


async def test_a_failed_read_keeps_the_last_good_ranges(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = RangeSource([_record("CVE-1")], ranges={("NVD", "CVE-1"): LIB_A_FIX})
    await manager.refresh_project("p1", client)
    [before] = manager.store.fixed_version_entries([("NVD", "CVE-1")]).values()

    client.records = [_record("CVE-1", updated=2)]
    client.fail.add(("NVD", "CVE-1"))
    await manager.refresh_project("p1", client)
    [after] = manager.store.fixed_version_entries([("NVD", "CVE-1")]).values()
    assert after["status"] == "failed"
    assert after["payload"] == before["payload"]
    assert after["read_at"] == before["read_at"]
    assert after["vuln_updated"] == "1"
    assert after["attempted_at"] >= before["attempted_at"]
    assert after["failures"] == 1

    # Not before the retry delay has passed; then retried.
    client.fail.clear()
    await manager.refresh_project("p1", client)
    assert client.reads.count(("NVD", "CVE-1")) == 2
    _attempted_long_ago(manager, "CVE-1")
    await manager.refresh_project("p1", client)
    assert client.reads.count(("NVD", "CVE-1")) == 3
    [again] = manager.store.fixed_version_entries([("NVD", "CVE-1")]).values()
    assert again["status"] == "read" and again["vuln_updated"] == "2"
    assert again["failures"] == 0


def _attempted_long_ago(manager, vuln_id, when="2020-01-01T00:00:00+00:00"):
    connection = manager.store._connection()
    with connection:
        connection.execute(
            "UPDATE source_vulnerability_ranges SET attempted_at = ? WHERE vuln_id = ?",
            (when, vuln_id),
        )


def test_failed_range_reads_back_off():
    now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    def failed(minutes_ago, failures):
        return {"status": "failed", "failures": failures, "vuln_updated": "1",
                "attempted_at": (now - timedelta(minutes=minutes_ago)).isoformat()}
    ttl = timedelta(days=7)
    assert fixed_versions_retry_delay(0) == timedelta(minutes=1)  # rows before the count
    assert fixed_versions_retry_delay(1) == timedelta(minutes=1)
    assert fixed_versions_retry_delay(3) == timedelta(minutes=4)
    assert fixed_versions_retry_delay(50) == timedelta(days=1)
    assert not fixed_versions_due(failed(0, 1), "1", now, ttl)
    assert fixed_versions_due(failed(1, 1), "1", now, ttl)
    assert not fixed_versions_due(failed(3, 3), "1", now, ttl)
    assert fixed_versions_due(failed(4, 3), "1", now, ttl)
    # A changed record does not skip the delay of a failing read.
    assert not fixed_versions_due(failed(0, 1), "2", now, ttl)


async def test_failing_range_reads_do_not_starve_the_others(tmp_path):
    manager = CacheManager(base_path=str(tmp_path), fixed_versions_reads_per_cycle=2)
    client = RangeSource([_record("CVE-1"), _record("CVE-2"), _record("CVE-3")])
    client.fail = {("NVD", "CVE-1"), ("NVD", "CVE-2")}
    await manager.refresh_project("p1", client)
    assert sorted(client.reads) == [("NVD", "CVE-1"), ("NVD", "CVE-2")]
    # Within the delay the failing ones wait, and the third is read.
    await manager.refresh_project("p1", client)
    assert client.reads[2:] == [("NVD", "CVE-3")]
    await manager.refresh_project("p1", client)
    assert client.reads[3:] == []
    # Due again, the failing ones come after one that was never read.
    _attempted_long_ago(manager, "CVE-1")
    _attempted_long_ago(manager, "CVE-2", "2020-01-02T00:00:00+00:00")
    client.records.append(_record("CVE-9"))
    await manager.refresh_project("p1", client)
    assert sorted(client.reads[3:]) == [("NVD", "CVE-1"), ("NVD", "CVE-9")]
    rows = manager.store.fixed_version_entries([("NVD", "CVE-1"), ("NVD", "CVE-2")])
    assert rows[("NVD", "CVE-1")]["failures"] == 2
    assert rows[("NVD", "CVE-2")]["failures"] == 1


async def test_a_vulnerability_shared_by_two_projects_is_read_once(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = RangeSource([_record("CVE-1")], ranges={("NVD", "CVE-1"): LIB_A_FIX}, delay=0.05)
    await asyncio.gather(
        manager.refresh_project("p1", client), manager.refresh_project("p2", client)
    )
    assert client.reads == [("NVD", "CVE-1")]
    await manager.refresh_project("p3", client)
    assert client.reads == [("NVD", "CVE-1")]


async def test_a_source_without_version_ranges_skips_the_step(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    class FindingsOnly:
        async def get_vulnerabilities(self, project_uuid, cve=None):
            return []

        async def get_project_vulnerabilities(self, project_uuid):
            return [_record("CVE-1")]

        async def get_bom(self, project_uuid):
            return {}

    await manager.refresh_project("p1", FindingsOnly())
    assert manager.store.fixed_version_entries([("NVD", "CVE-1")]) == {}


async def test_an_export_reads_the_stored_ranges_and_never_the_source(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    component = {"uuid": "c1", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}
    findings = [
        {"component": component,
         "vulnerability": {"uuid": "u-CVE-1", "vulnId": "CVE-1", "source": "NVD"},
         "analysis": {"analysisState": "NOT_SET", "isSuppressed": False}},
        {"component": component,
         "vulnerability": {"uuid": "u-CVE-2", "vulnId": "CVE-2", "source": "NVD"},
         "analysis": {"analysisState": "NOT_SET", "isSuppressed": False}},
    ]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"type": "library", "bom-ref": "c1", "name": "lib-a",
                           "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}]}
    client = RangeSource([_record("CVE-1"), _record("CVE-2")], findings=findings, bom=bom,
                         ranges={("NVD", "CVE-1"): LIB_A_FIX})
    manager.fixed_versions_reads_per_cycle = 1
    await manager.refresh_project("p1", client)
    assert client.reads == [("NVD", "CVE-1")]

    client.get_vulnerability_affected = AsyncMock(side_effect=AssertionError("no read"))
    document = await manager.export_cyclonedx(
        client, "p1", "vdr", assessment_source="DTVP", property_prefix="dtvp",
    )
    client.get_vulnerability_affected.assert_not_called()
    first, second = document["vulnerabilities"]
    assert first["recommendation"] == "Upgrade lib-a 1.0 to 1.2.3 or later."
    assert "recommendation" not in second
    metadata = {item["name"]: item["value"] for item in document["metadata"]["properties"]}
    assert metadata["dtvp:export_derived_recommendations"] == "1"
    assert metadata["dtvp:export_fixed_versions_unread"] == "1"  # CVE-2, over the cap


def test_the_range_table_is_added_to_an_existing_database(tmp_path):
    import shutil
    import sqlite3

    from dtvp.local_store import LocalStore, get_local_store_migrations_path
    from dtvp.sqlite_migration_services import run_sqlite_migrations

    earlier = tmp_path / "earlier"
    earlier.mkdir()
    for path in sorted(get_local_store_migrations_path().glob("*.sql"))[:2]:
        shutil.copy(path, earlier / path.name)
    database = tmp_path / "dtvp.sqlite3"
    connection = sqlite3.connect(database)
    run_sqlite_migrations(connection, namespace="local_store", migrations_path=earlier)
    connection.execute(
        "INSERT INTO known_projects VALUES ('p1', 'App', '1.0', 'then', 'then')"
    )
    connection.commit()
    connection.close()

    store = LocalStore(str(database))
    store.save_fixed_version_entry("NVD", "CVE-1", status="read", payload=[], vuln_updated="1")
    assert store.fixed_version_entries([("NVD", "CVE-1")])[("NVD", "CVE-1")]["payload"] == []
    assert store.describe_projects(["p1"])["p1"]["name"] == "App"
    store.close()


# -- following the source's findings: gone, carried over, back again --------


_ALPHA = "--- [Team: Alpha] [State: NOT_AFFECTED] [Assessed By: alex] ---\nNot reachable."
_BETA = "--- [Team: Beta] [State: EXPLOITABLE] [Assessed By: bea] ---\nReachable."


def _lib(component_uuid, version, state="NOT_SET", details="", vuln="v1"):
    return {
        "component": {
            "uuid": component_uuid,
            "name": "lib-a",
            "version": version,
            "purl": f"pkg:maven/org.example/lib-a@{version}",
        },
        "vulnerability": {"uuid": vuln, "vulnId": "CVE-2026-1" if vuln == "v1" else "CVE-2026-2"},
        "analysis": {"analysisState": state, "analysisDetails": details, "isSuppressed": False},
    }


def _bom(*component_uuids, version="1.1"):
    return {
        "components": [
            {"bom-ref": uuid, "name": "lib-a", "purl": f"pkg:maven/org.example/lib-a@{version}"}
            for uuid in component_uuids
        ]
    }


async def test_a_replaced_component_keeps_its_assessment_across_the_reanalysis(tmp_path):
    """A read taken while the source re-analyses a BOM upload is acted on;
    the next read heals it (no waiting for the source's analysis)."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()

    # Read 1: the old component with an assessment, adopted as the record.
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
    await manager.import_findings(client, "p1")
    assert manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))["sync_status"] == "synced"
    revision_before = manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))["revision"]

    # Read 2: a new BOM replaced the component; the source has not reported
    # the new one's findings yet. The finding is gone, its record inactive.
    client.get_vulnerabilities.return_value = []
    client.get_bom.return_value = _bom()
    second = await manager.import_findings(client, "p1")
    assert second.went == {"component_removed": 1}
    presence = manager.finding_lifecycle.presence("p1")
    assert presence[("c-old", "v1")]["gone_reason"] == "component_removed"
    old_record = manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))
    assert old_record["sync_status"] == "inactive"
    # Retiring changes no value, so it writes no revision.
    assert old_record["revision"] == revision_before

    # Read 3: the component is back under a new UUID and version.
    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.return_value = _bom("c-new")
    third = await manager.import_findings(client, "p1")

    assert third.carried_over == [("p1", "c-new", "v1")]
    analysis = (await manager.get_vulnerabilities(client, "p1"))[0]["analysis"]
    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert "Not reachable." in analysis["analysisDetails"]
    assert "[Status: Pending Review]" in analysis["analysisDetails"]
    assert analysis["dtvpSyncStatus"] == "pending"
    assert analysis["dtvpRevision"] == 1
    assert [entry["origin"] for entry in manager.get_assessment_history("p1", "c-new", "v1")] == [
        "carried-over"
    ]
    assert [item["component_uuid"] for item in manager.list_export_queue()] == ["c-new"]
    assert manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))["sync_status"] == "superseded"
    # The earlier gone mark is resolved: replaced, with the successor.
    old = manager.finding_lifecycle.presence("p1")[("c-old", "v1")]
    assert (old["status"], old["gone_reason"], old["successor_component_uuid"], old["carry_over"]) == (
        "gone", "replaced", "c-new", "carried",
    )
    gone = manager.get_assessment_overlay("p1", "c-old", "v1")
    assert (gone["dtvpGoneReason"], gone["dtvpSupersededBy"]) == ("replaced", "c-new")

    await manager.flush_pending_updates(client)
    assert client.update_analysis.await_args.kwargs["component_uuid"] == "c-new"
    await manager.close()


async def test_the_import_needs_nothing_but_the_source_protocol(tmp_path):
    """A source that offers only what dtvp/ports.py asks for, with no
    Dependency-Track project fields, gets the whole gone/carry-over flow."""

    class Source:
        def __init__(self):
            self.findings = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
            self.bom = _bom("c-old", version="1.0")

        async def get_projects(self, name=None):
            return [{"uuid": "p1", "name": "Product", "version": "1.0"}]

        async def get_vulnerabilities(self, project_uuid, cve=None):
            return [dict(item) for item in self.findings]

        async def get_project_vulnerabilities(self, project_uuid):
            return []

        async def get_bom(self, project_uuid):
            return self.bom

        async def get_analysis(self, project_uuid, component_uuid, vulnerability_uuid):
            return None

    manager = CacheManager(base_path=str(tmp_path))
    source = Source()
    await manager.import_findings(source, "p1")
    source.findings, source.bom = [], _bom()
    await manager.import_findings(source, "p1")
    source.findings, source.bom = [_lib("c-new", "1.1")], _bom("c-new")
    result = await manager.import_findings(source, "p1")

    assert result.carried_over == [("p1", "c-new", "v1")]
    assert manager.finding_lifecycle.presence("p1")[("c-old", "v1")]["gone_reason"] == "replaced"
    await manager.close()


def _same_version_bom(*refs):
    return {
        "components": [
            {"bom-ref": ref, "name": "lib-a", "purl": f"pkg:maven/org.example/lib-a@{version}"}
            for ref, version in refs
        ]
    }


def _lib3(component_uuid, version, state="NOT_SET", details=""):
    finding = _lib(component_uuid, version, state, details, vuln="v3")
    finding["vulnerability"]["vulnId"] = "CVE-2026-3"
    return finding


async def _carry_as_before_the_fix(manager, client, monkeypatch, findings, bom):
    """A read that carries like builds before a756a396: a recreated
    component's assessment gets the review marker too."""
    import dtvp.finding_lifecycle_services as lifecycle

    with monkeypatch.context() as patched:
        patched.setattr(lifecycle, "same_component_version", lambda row, target: False)
        client.get_vulnerabilities.return_value = findings
        client.get_bom.return_value = bom
        return await manager.import_findings(client, "p1")


async def test_an_earlier_review_marker_on_a_recreated_component_is_taken_back(
    tmp_path, monkeypatch
):
    """Sixth reading, item 1: carries of builds before the recreated rule
    keep [Status: Pending Review]. The next read takes it back where the
    component is the same, the old value was approved and nobody saved
    since; once only."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        _lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA),
        _lib("c-old", "1.0", "NOT_AFFECTED", _BETA, vuln="v2"),
        _lib3("c-up", "1.0", "NOT_AFFECTED", _ALPHA),
    ]
    await manager.import_findings(client, "p1")

    findings = [
        _lib("c-same", "1.0"),
        _lib("c-same", "1.0", vuln="v2"),
        _lib3("c-next", "1.1"),
    ]
    bom = _same_version_bom(("c-same", "1.0"), ("c-next", "1.1"))
    carried = await _carry_as_before_the_fix(manager, client, monkeypatch, findings, bom)
    assert len(carried.carried_over) == 3
    for key in (("p1", "c-same", "v1"), ("p1", "c-same", "v2"), ("p1", "c-next", "v3")):
        assert "[Status: Pending Review]" in manager.get_assessment_overlay(*key)["analysisDetails"]
    # Someone saved v2 since: it stays as it is.
    saved = {
        "project_uuid": "p1", "component_uuid": "c-same", "vulnerability_uuid": "v2",
        "state": "NOT_AFFECTED", "details": _BETA + "\n\n[Status: Pending Review]", "suppressed": False,
    }
    await manager.persist_assessment_updates([saved], author="kim")

    client.get_vulnerabilities.return_value = findings
    await manager.import_findings(client, "p1")

    same = manager.get_assessment_overlay("p1", "c-same", "v1")
    assert same["analysisDetails"] == _ALPHA
    assert [entry["origin"] for entry in manager.get_assessment_history("p1", "c-same", "v1")][:2] == [
        "carried-over-recreated", "carried-over",
    ]
    assert "[Status: Pending Review]" in manager.get_assessment_overlay("p1", "c-same", "v2")["analysisDetails"]
    # Another version: the review stays.
    assert "[Status: Pending Review]" in manager.get_assessment_overlay("p1", "c-next", "v3")["analysisDetails"]

    revisions = len(manager.get_assessment_history("p1", "c-same", "v1"))
    await manager.import_findings(client, "p1")
    assert len(manager.get_assessment_history("p1", "c-same", "v1")) == revisions
    await manager.close()


async def test_an_earlier_carry_of_a_pending_value_keeps_its_review(tmp_path, monkeypatch):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        _lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA + "\n\n[Status: Pending Review]"),
    ]
    await manager.import_findings(client, "p1")
    findings = [_lib("c-same", "1.0")]
    await _carry_as_before_the_fix(
        manager, client, monkeypatch, findings, _same_version_bom(("c-same", "1.0"))
    )

    await manager.import_findings(client, "p1")

    assert "[Status: Pending Review]" in manager.get_assessment_overlay("p1", "c-same", "v1")["analysisDetails"]
    await manager.close()


@pytest.mark.parametrize("successor_text, superseded", [(_BETA, True), (_BETA + "\n\n[Status: Pending Review]", False)])
async def test_a_gone_record_is_superseded_once_its_successor_has_an_approved_assessment(
    tmp_path, successor_text, superseded
):
    """Sixth reading, item 8: the old record of a finding whose successor
    has its own assessment is no carry candidate once that is approved."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
    await manager.import_findings(client, "p1")

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.return_value = _bom("c-new")
    # The successor is assessed in DTVP before the read that sees it.
    await manager.persist_assessment_updates(
        [{
            "project_uuid": "p1", "component_uuid": "c-new", "vulnerability_uuid": "v1",
            "state": "EXPLOITABLE", "details": successor_text, "suppressed": False,
        }],
        author="kim",
    )
    await manager.import_findings(client, "p1")

    row = manager.finding_lifecycle.presence("p1")[("c-old", "v1")]
    assert row["carry_over"] == "own_assessment"
    status = manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))["sync_status"]
    assert (status == "superseded") is superseded
    await manager.close()


async def test_a_recreated_component_keeps_its_assessment_without_review(tmp_path):
    """The source recreates the same component under a new ID (a BOM uploaded
    again): the assessment moves over as it was, an approved one stays
    approved. Another version still needs review."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        _lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA),
        _lib("c-old", "1.0", "NOT_AFFECTED", _BETA, vuln="v2"),
    ]
    await manager.import_findings(client, "p1")

    # v1 on the same version under a new ID; v2 moved to another version.
    client.get_vulnerabilities.return_value = [
        _lib("c-same", "1.0"),
        _lib("c-next", "1.1", vuln="v2"),
    ]
    client.get_bom.return_value = {
        "components": [
            {"bom-ref": "c-same", "name": "lib-a", "purl": "pkg:maven/org.example/lib-a@1.0"},
            {"bom-ref": "c-next", "name": "lib-a", "purl": "pkg:maven/org.example/lib-a@1.1"},
        ]
    }
    result = await manager.import_findings(client, "p1")

    assert sorted(result.carried_over) == [("p1", "c-next", "v2"), ("p1", "c-same", "v1")]
    same = manager.get_assessment_overlay("p1", "c-same", "v1")
    assert same["analysisState"] == "NOT_AFFECTED"
    assert same["analysisDetails"] == _ALPHA
    assert "[Status: Pending Review]" not in same["analysisDetails"]
    upgraded = manager.get_assessment_overlay("p1", "c-next", "v2")
    assert "[Status: Pending Review]" in upgraded["analysisDetails"]
    await manager.close()


async def test_a_replaced_component_whose_old_assessments_differ_is_not_carried(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        _lib("c-old-1", "1.0", "NOT_AFFECTED", _ALPHA),
        _lib("c-old-2", "1.0", "EXPLOITABLE", _BETA),
    ]
    await manager.import_findings(client, "p1")

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.return_value = _bom("c-new")
    result = await manager.import_findings(client, "p1")

    assert result.carried_over == [] and result.not_carried == 1
    assert manager.assessment_outbox.get_overlay(("p1", "c-new", "v1")) is None
    presence = manager.finding_lifecycle.presence("p1")
    for component in ("c-old-1", "c-old-2"):
        assert presence[(component, "v1")]["carry_over"] == "conflict"
        assert manager.assessment_outbox.get_overlay(("p1", component, "v1"))["sync_status"] == "inactive"
    await manager.close()


async def test_an_assessment_from_before_findings_were_recorded_is_carried_by_vulnerability(
    tmp_path,
):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    # A record whose finding DTVP never recorded; only the BOM DTVP stored
    # earlier still names its component.
    await manager.persist_assessment_updates(
        [{
            "project_uuid": "p1", "component_uuid": "c-gone", "vulnerability_uuid": "v1",
            "state": "NOT_AFFECTED", "details": _ALPHA, "suppressed": False,
        }]
    )
    await manager.flush_pending_updates(client)
    client.update_analysis.reset_mock()
    manager._save_project_cache(
        manager._bom_path("p1"), _bom("c-gone", version="1.0"), project_uuid="p1"
    )

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.return_value = _bom("c-new")
    result = await manager.import_findings(client, "p1")

    assert result.carried_over == [("p1", "c-new", "v1")]
    history = manager.get_assessment_history("p1", "c-new", "v1")
    assert history[0]["origin"] == "carried-over-by-vulnerability"
    assert manager.assessment_outbox.get_overlay(("p1", "c-gone", "v1"))["sync_status"] == "superseded"
    row = manager.finding_lifecycle.presence("p1")[("c-gone", "v1")]
    assert (row["gone_reason"], row["carry_over"]) == ("replaced", "carried")
    # What the stored BOM said of the component is kept with the finding.
    assert (row["component_name"], row["component_version"]) == ("lib-a", None)
    await manager.close()


@pytest.mark.parametrize("source_keeps_value", [True, False])
async def test_a_vulnerability_no_longer_matched_goes_and_comes_back(
    tmp_path, source_keeps_value
):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    assessed = _lib("c1", "1.0", "NOT_AFFECTED", _ALPHA)
    other = _lib("c1", "1.0", vuln="v2")
    client.get_vulnerabilities.return_value = [assessed, other]
    await manager.import_findings(client, "p1")

    # The component stays; the source no longer matches v1 against it.
    client.get_vulnerabilities.return_value = [other]
    went = await manager.import_findings(client, "p1")

    assert went.went == {"no_longer_matched": 1}
    client.get_bom.assert_not_awaited()  # the findings alone decide
    assert manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))["sync_status"] == "inactive"
    overlay = manager.get_assessment_overlay("p1", "c1", "v1")
    assert overlay["dtvpGoneReason"] == "no_longer_matched"
    gone = manager.finding_lifecycle.presence("p1")[("c1", "v1")]
    assert gone["status"] == "gone" and gone["gone_at"] and gone["last_seen_at"]

    returning = assessed if source_keeps_value else _lib("c1", "1.0")
    client.get_vulnerabilities.return_value = [returning, other]
    back = await manager.import_findings(client, "p1")

    assert back.returned == 1
    row = manager.finding_lifecycle.presence("p1")[("c1", "v1")]
    assert row["status"] == "reported" and row["returned_at"]
    assert row["gone_reason"] == "no_longer_matched"  # when and why it went stays
    record = manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))
    assert record["sync_status"] == ("synced" if source_keeps_value else "pending")
    # Active again with the same value: no new revision, the history only
    # lists changes of the value.
    assert record["revision"] == 0
    history = manager.get_assessment_history("p1", "c1", "v1")
    assert [(entry["revision"], entry["origin"]) for entry in history] == [(0, "import")]
    assert "Not reachable." in history[0]["analysisDetails"]
    if not source_keeps_value:
        assert [item["revision"] for item in manager.list_export_queue()] == [0]
    analysis = next(
        item["analysis"] for item in back.findings
        if item["vulnerability"]["uuid"] == "v1"
    )
    # It has its assessment, so it is not a new finding.
    assert analysis["analysisState"] == "NOT_AFFECTED"
    assert "dtvpGoneReason" not in analysis
    await manager.close()


async def test_a_pending_export_to_a_gone_finding_is_dropped_with_its_reason(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Never sent")])

    client.get_vulnerabilities.return_value = []
    client.get_bom.return_value = {"components": [{"bom-ref": "c-other", "name": "lib-z"}]}
    result = await manager.import_findings(client, "p1")

    assert result.went == {"component_removed": 1}
    assert manager.assessment_outbox.pending_count() == 0
    record = manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))
    assert (record["sync_status"], record["analysisDetails"]) == ("inactive", "Never sent")
    assert manager.finding_lifecycle.presence("p1")[("c1", "v1")]["gone_reason"] == "component_removed"
    assert manager.list_export_queue() == []
    await manager.flush_pending_updates(client)
    client.update_analysis.assert_not_awaited()
    await manager.close()


async def test_a_pending_export_rejected_as_missing_records_the_reason(tmp_path):
    manager, client = await _manager_with_source(tmp_path)
    await manager.persist_assessment_updates([_local_payload("Sent too late")])
    request = httpx.Request("PUT", "http://dt/api/v1/analysis")
    client.update_analysis.side_effect = httpx.HTTPStatusError(
        "404", request=request, response=httpx.Response(404, request=request)
    )
    client.finding_exists.return_value = False

    await manager.flush_pending_updates(client)

    row = manager.finding_lifecycle.presence("p1")[("c1", "v1")]
    assert (row["status"], row["gone_reason"]) == ("gone", "missing_at_export")
    assert manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))["sync_status"] == "inactive"
    await manager.close()


async def test_the_vdr_counts_recreated_components_apart_and_the_last_read(tmp_path):
    """A component recreated under a new ID (same name and version) is not a
    gone finding: it stands for an earlier generation. The last read's
    findings are counted apart, with recreated ones labelled."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0"), _lib("c-old", "1.0", vuln="v2")]
    client.get_bom.return_value = _bom("c-old", version="1.0")
    await manager.import_findings(client, "p1")
    # Recreated twice (two BOM uploads), and v2 gone at the second one.
    client.get_vulnerabilities.return_value = [_lib("c-mid", "1.0"), _lib("c-mid", "1.0", vuln="v2")]
    client.get_bom.return_value = _bom("c-mid", version="1.0")
    await manager.import_findings(client, "p1")
    client.get_vulnerabilities.return_value = [_lib("c-new", "1.0")]
    client.get_bom.return_value = _bom("c-new", version="1.0")
    await manager.import_findings(client, "p1")
    client.get_project_vulnerabilities.return_value = []

    document = await manager.export_cyclonedx(
        client, "p1", "vdr", assessment_source="DTVP", property_prefix="acme"
    )
    properties = document["metadata"]["properties"]

    def values(name):
        return [item["value"] for item in properties if item["name"] == f"acme:{name}"]

    # Only v2 on the latest generation went for a reason that matters.
    assert values("export_findings_gone") == ["no_longer_matched=1"]
    # c-old's two and c-mid's v1 stand for earlier generations.
    assert values("export_findings_recreated") == ["3"]
    last_read = manager.finding_lifecycle.last_read("p1")["read_at"]
    assert values("export_findings_gone_last_read_at") == [last_read]
    assert values("export_findings_gone_last_read") == ["no_longer_matched=1", "recreated=1"]
    assert len(values("export_findings_followed_since")) == 1
    await manager.close()


async def test_the_vdr_counts_the_findings_that_are_gone_now(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c1", "1.0"), _lib("c1", "1.0", vuln="v2")]
    client.get_bom.return_value = _bom("c1", version="1.0")
    await manager.import_findings(client, "p1")
    client.get_vulnerabilities.return_value = [_lib("c1", "1.0", vuln="v2")]
    await manager.import_findings(client, "p1")
    client.get_project_vulnerabilities.return_value = []

    for _ in range(2):  # two exports in a row agree
        document = await manager.export_cyclonedx(
            client, "p1", "vdr", assessment_source="DTVP", property_prefix="acme"
        )
        assert [
            item["value"] for item in document["metadata"]["properties"]
            if item["name"] == "acme:export_findings_gone"
        ] == ["no_longer_matched=1"]
        assert [entry["id"] for entry in document["vulnerabilities"]] == ["CVE-2026-2"]
    await manager.close()


@pytest.mark.parametrize(
    "stored_name, outcome",
    [("lib-a", "carried"), ("lib-z", None), (None, "undetermined")],
)
async def test_an_inactive_record_from_before_the_upgrade_is_carried_by_vulnerability(
    tmp_path, stored_name, outcome
):
    """Carried by vulnerability only to a component of the same name; when
    the name of the record's component is not known, a person decides."""
    from datetime import UTC, datetime, timedelta

    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    # Retired by an import before findings were recorded: inactive, and no
    # finding row of its own.
    await manager.persist_assessment_updates(
        [{
            "project_uuid": "p1", "component_uuid": "c-gone", "vulnerability_uuid": "v1",
            "state": "NOT_AFFECTED", "details": _ALPHA, "suppressed": False,
        }]
    )
    await manager.flush_pending_updates(client)
    manager.assessment_outbox.mark_inactive(
        "p1", set(), fetched_at=datetime.now(UTC) + timedelta(seconds=5)
    )
    assert manager.finding_lifecycle.presence("p1") == {}
    if stored_name:
        manager._save_project_cache(
            manager._bom_path("p1"),
            {"components": [{"bom-ref": "c-gone", "name": stored_name}]},
            project_uuid="p1",
        )

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1"), _lib("c-new", "1.1", vuln="v2")]
    client.get_bom.return_value = _bom("c-new")
    result = await manager.import_findings(client, "p1")

    assert result.went == {}  # it did not go at this read
    record = manager.assessment_outbox.get_overlay(("p1", "c-gone", "v1"))
    row = manager.finding_lifecycle.presence("p1").get(("c-gone", "v1"))
    if outcome == "carried":
        assert result.carried_over == [("p1", "c-new", "v1")]
        assert manager.get_assessment_history("p1", "c-new", "v1")[0]["origin"] == (
            "carried-over-by-vulnerability"
        )
        assert (row["status"], row["gone_reason"], row["successor_component_uuid"], row["carry_over"]) == (
            "gone", "replaced", "c-new", "carried",
        )
        assert row["vuln_id"] == "CVE-2026-1"
        assert record["sync_status"] == "superseded"
        return await manager.close()

    # Another package's assessment, or one of an unknown package: not taken.
    assert result.carried_over == []
    assert manager.assessment_outbox.get_overlay(("p1", "c-new", "v1")) is None
    assert record["sync_status"] == "inactive"
    assert manager.list_export_queue() == []
    if outcome == "undetermined":
        assert result.not_carried == 1
        assert (row["status"], row["gone_reason"], row["carry_over"]) == (
            "gone", "component_removed", "undetermined",
        )
    else:
        assert result.not_carried == 0 and row is None
    await manager.close()


async def test_a_successor_with_its_own_assessment_takes_nothing_over(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
    await manager.import_findings(client, "p1")

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1", "EXPLOITABLE", _BETA)]
    client.get_bom.return_value = _bom("c-new")
    result = await manager.import_findings(client, "p1")

    assert result.carried_over == []
    row = manager.finding_lifecycle.presence("p1")[("c-old", "v1")]
    assert (row["gone_reason"], row["carry_over"]) == ("replaced", "own_assessment")
    # The successor's own value is approved (no review marker): the old
    # record is no carry candidate any more.
    assert manager.assessment_outbox.get_overlay(("p1", "c-old", "v1"))["sync_status"] == "superseded"
    assert "Reachable." in manager.assessment_outbox.get_overlay(("p1", "c-new", "v1"))["analysisDetails"]
    await manager.close()


async def test_another_version_still_in_the_bom_does_not_take_the_assessment(tmp_path):
    """Two versions of a component in the BOM: the vulnerability moves from
    one to the other. The first was not replaced; its assessment stays."""
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [
        _lib("c1", "1.0", "NOT_AFFECTED", _ALPHA),
        _lib("c2", "2.0"),
    ]
    await manager.import_findings(client, "p1")

    client.get_vulnerabilities.return_value = [_lib("c2", "2.0")]
    client.get_bom.return_value = {
        "components": [
            {"bom-ref": "c1", "name": "lib-a", "purl": "pkg:maven/org.example/lib-a@1.0"},
            {"bom-ref": "c2", "name": "lib-a", "purl": "pkg:maven/org.example/lib-a@2.0"},
        ]
    }
    result = await manager.import_findings(client, "p1")

    assert result.went == {"no_longer_matched": 1}
    assert result.carried_over == []
    row = manager.finding_lifecycle.presence("p1")[("c1", "v1")]
    assert (row["gone_reason"], row["successor_component_uuid"], row["carry_over"]) == (
        "no_longer_matched", None, None,
    )
    assert manager.assessment_outbox.get_overlay(("p1", "c1", "v1"))["sync_status"] == "inactive"
    assert manager.assessment_outbox.get_overlay(("p1", "c2", "v1")) is None
    assert manager.list_export_queue() == []
    await manager.close()


async def test_a_replacement_the_bom_cannot_confirm_is_undetermined(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
    await manager.import_findings(client, "p1")

    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.side_effect = httpx.ConnectError("down")
    result = await manager.import_findings(client, "p1")

    assert result.went == {"undetermined": 1} and result.carried_over == []
    assert manager.assessment_outbox.get_overlay(("p1", "c-new", "v1")) is None

    # Once the BOM can be read, the replacement is confirmed and carried.
    client.get_bom.side_effect = None
    client.get_bom.return_value = _bom("c-new")
    result = await manager.import_findings(client, "p1")

    assert result.carried_over == [("p1", "c-new", "v1")]
    row = manager.finding_lifecycle.presence("p1")[("c-old", "v1")]
    assert (row["gone_reason"], row["carry_over"]) == ("replaced", "carried")
    await manager.close()


@pytest.mark.parametrize("saved", ["target", "candidate"])
async def test_a_save_during_the_read_is_not_overwritten_by_a_carry_over(
    tmp_path, monkeypatch, saved
):
    import dtvp.dt_cache as dt_cache_module

    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_lib("c-old", "1.0", "NOT_AFFECTED", _ALPHA)]
    await manager.import_findings(client, "p1")
    client.get_vulnerabilities.return_value = [_lib("c-new", "1.1")]
    client.get_bom.return_value = _bom("c-new")

    key = ("p1", "c-new", "v1") if saved == "target" else ("p1", "c-old", "v1")
    planned = dt_cache_module.follow_findings_plan

    def plan_then_save(**options):
        plan = planned(**options)
        assert [carry.target for carry in plan.carry.carries] == [("p1", "c-new", "v1")]
        # Someone saves while the plan waits to be persisted, and the
        # export worker sends it at once.
        manager.assessment_outbox.enqueue_many(
            [{
                "project_uuid": key[0], "component_uuid": key[1], "vulnerability_uuid": key[2],
                "state": "EXPLOITABLE", "details": "Saved meanwhile.", "suppressed": False,
            }]
        )
        manager.assessment_outbox.mark_synced(key, manager.assessment_outbox.get_overlay(key)["revision"])
        return plan

    monkeypatch.setattr(dt_cache_module, "follow_findings_plan", plan_then_save)
    result = await manager.import_findings(client, "p1")

    assert result.carried_over == []
    record = manager.assessment_outbox.get_overlay(key)
    assert (record["analysisState"], record["analysisDetails"]) == ("EXPLOITABLE", "Saved meanwhile.")
    assert record["sync_status"] == "synced"
    if saved == "candidate":
        assert manager.assessment_outbox.get_overlay(("p1", "c-new", "v1")) is None
    assert manager.list_export_queue() == []
    await manager.close()


# --- listener hooks for the event stream (ADR 0004) -------------------------


class _ProjectListSource:
    """A source whose project list can be swapped or made to fail."""

    def __init__(self, projects=None, error=None):
        self.projects = projects or []
        self.error = error

    async def get_projects(self, name=""):
        if self.error is not None:
            raise self.error
        if name:
            return [p for p in self.projects if name.lower() in p["name"].lower()]
        return [dict(project) for project in self.projects]


def _recording_manager(tmp_path, **kwargs):
    manager = CacheManager(base_path=str(tmp_path), **kwargs)
    calls = {"lists": [], "states": [], "status": 0}
    manager.add_project_list_listener(
        lambda previous, current: calls["lists"].append((previous, current))
    )
    manager.add_source_state_listener(
        lambda ok, exc: calls["states"].append((ok, exc))
    )

    def status_changed():
        calls["status"] += 1

    manager.add_cache_status_listener(status_changed)
    return manager, calls


@pytest.mark.asyncio
async def test_project_list_refresh_tells_listeners_previous_and_current(tmp_path):
    manager, calls = _recording_manager(tmp_path)
    one = {"name": "App", "uuid": "u1", "version": "1.0"}
    two = {"name": "App", "uuid": "u2", "version": "2.0"}
    source = _ProjectListSource([one])

    await manager._refresh_project_list(source)
    source.projects = [one, two]
    await manager._refresh_project_list(source)

    assert calls["lists"] == [([], [one]), ([one], [one, two])]
    assert calls["states"] == [(True, None), (True, None)]
    # The listener runs after the save: the stored list is the new one.
    assert manager._load_project_cache(manager._projects_path(), []) == [one, two]


@pytest.mark.asyncio
async def test_project_list_refresh_failure_reports_the_source_state(tmp_path):
    manager, calls = _recording_manager(tmp_path)
    error = httpx.ConnectError("refused")

    await manager._refresh_project_list(_ProjectListSource(error=error))

    assert calls["lists"] == []
    assert calls["states"] == [(False, error)]


@pytest.mark.asyncio
async def test_a_raising_listener_does_not_break_the_refresh(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    seen = []

    def broken(previous, current):
        raise RuntimeError("listener bug")

    manager.add_project_list_listener(broken)
    manager.add_project_list_listener(lambda previous, current: seen.append(current))
    manager.add_source_state_listener(lambda ok, exc: (_ for _ in ()).throw(ValueError()))
    project = {"name": "App", "uuid": "u1", "version": "1.0"}

    await manager._refresh_project_list(_ProjectListSource([project]))

    assert seen == [[project]]
    assert manager._load_project_cache(manager._projects_path(), []) == [project]


@pytest.mark.asyncio
async def test_unchanged_refresh_publishes_no_project_event(tmp_path):
    from dtvp.event_hub import EventHub
    from dtvp.event_producers import ProjectListEventProducer

    manager, calls = _recording_manager(tmp_path)
    hub = EventHub(boot_id="b")
    manager.add_project_list_listener(ProjectListEventProducer(hub))
    project = {"name": "App", "uuid": "u1", "version": "1.0", "lastRiskScore": 1}
    source = _ProjectListSource([project])

    await manager._refresh_project_list(source)
    assert [event.type for event in hub.events_after(0)] == ["projects.changed"]

    # Only the risk score moved, as after an export: no event.
    source.projects = [{**project, "lastRiskScore": 7}]
    await manager._refresh_project_list(source)
    await manager._refresh_project_list(source)

    assert len(calls["lists"]) == 3
    assert hub.current_seq() == 1


@pytest.mark.asyncio
async def test_get_projects_fetch_tells_listeners_and_failure_reports_state(tmp_path):
    manager, calls = _recording_manager(tmp_path, project_list_ttl_seconds=0)
    project = {"name": "App", "uuid": "u1", "version": "1.0"}
    source = _ProjectListSource([project])

    assert await manager.get_projects(source, name="") == [project]
    assert calls["lists"] == [([], [project])]
    assert calls["states"] == [(True, None)]

    error = RuntimeError("dt down")
    source.error = error
    assert await manager.get_projects(source, name="") == [project]
    assert calls["states"][-1] == (False, error)


@pytest.mark.asyncio
async def test_named_search_merge_tells_listeners(tmp_path):
    manager, calls = _recording_manager(tmp_path)
    known = {"name": "Known", "uuid": "u1", "version": "1.0"}
    found = {"name": "Found", "uuid": "u2", "version": "1.0"}
    manager._save_project_cache(manager._projects_path(), [known])

    await manager.get_projects(_ProjectListSource([found]), name="Found")

    assert calls["lists"] == [([known], [known, found])]


def test_invalidating_the_cache_status_tells_listeners(tmp_path):
    manager, calls = _recording_manager(tmp_path)
    before = calls["status"]
    manager._invalidate_cache_status()
    assert calls["status"] == before + 1
