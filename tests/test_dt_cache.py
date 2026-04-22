import pytest
from unittest.mock import AsyncMock
from dt_cache import CacheManager, PendingUpdateExistsError


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
