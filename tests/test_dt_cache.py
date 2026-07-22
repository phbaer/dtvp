import asyncio

import pytest
from unittest.mock import AsyncMock, patch
from dtvp.dt_cache import CacheManager, PendingUpdateExistsError


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
    saved: list[list[str]] = []
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

    assert saved == [["project-1"]]


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
async def test_queue_analysis_updates_rewrites_pending_file_once(tmp_path):
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
            manager,
            "_save_pending_updates",
            wraps=manager._save_pending_updates,
        ) as save_pending,
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
    assert save_pending.call_count == 1
    assert save_local.call_count == 1
    pending = manager._load_pending_updates()
    assert len(pending) == 100
    assert pending[0]["payload"]["details"] == "Replacement 0"
    stored = manager._load_project_cache(
        manager._analysis_path("project", "component-99", "vulnerability-99"),
        None,
    )
    assert stored["analysisDetails"] == "Replacement 99"


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
