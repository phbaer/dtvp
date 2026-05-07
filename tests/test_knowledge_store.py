from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from dtvp.knowledge_store import KnowledgeStore, get_knowledge_store_backend


def test_default_backend_is_json():
    with patch.dict("os.environ", {}, clear=False):
        assert get_knowledge_store_backend() == "json"


def test_sqlite_backend_persists_and_reads_assessment(tmp_path):
    store = KnowledgeStore(base_path=str(tmp_path / "knowledge"))

    payload = {
        "project_uuid": "project-1",
        "component_uuid": "component-1",
        "vulnerability_uuid": "vuln-1",
        "state": "IN_TRIAGE",
        "details": "Stored in sqlite",
        "suppressed": False,
    }
    component = {
        "uuid": "component-1",
        "name": "package-a",
        "purl": "pkg:pypi/package-a@1.2.3",
    }
    vulnerability = {
        "uuid": "vuln-1",
        "vulnId": "CVE-2026-0001",
        "aliases": [{"ghsaId": "GHSA-aaaa-bbbb-cccc"}],
    }

    with patch.dict("os.environ", {"DTVP_KNOWLEDGE_STORE_BACKEND": "sqlite"}):
        record = store.persist_assessment(
            payload=payload,
            component=component,
            vulnerability=vulnerability,
        )
        assert record is not None

        by_triplet = store.get_assessment_by_triplet(
            project_uuid="project-1",
            component_uuid="component-1",
            vulnerability_uuid="vuln-1",
        )
        assert by_triplet == {
            "analysisState": "IN_TRIAGE",
            "analysisDetails": "Stored in sqlite",
            "isSuppressed": False,
        }

        by_finding = store.get_assessment_for_finding(
            component={"uuid": "component-1", "purl": "pkg:pypi/package-a@2.0.0"},
            vulnerability={"vulnId": "GHSA-aaaa-bbbb-cccc"},
        )
        assert by_finding == by_triplet

        status = store.get_status()
        assert status["store_type"] == "sqlite"
        assert status["assessment_records"] == 1
        assert status["assessment_triplet_index_entries"] == 1
        assert status["database_path"].endswith("knowledge_store.db")


def test_sqlite_backend_bootstraps_from_existing_json_store(tmp_path):
    store = KnowledgeStore(base_path=str(tmp_path / "knowledge"))

    with patch.dict("os.environ", {"DTVP_KNOWLEDGE_STORE_BACKEND": "json"}):
        store.persist_assessment(
            payload={
                "project_uuid": "project-2",
                "component_uuid": "component-2",
                "vulnerability_uuid": "vuln-2",
                "state": "NOT_AFFECTED",
                "details": "Migrated from json",
                "suppressed": True,
            },
            component={"uuid": "component-2", "name": "package-b"},
            vulnerability={"uuid": "vuln-2", "vulnId": "CVE-2026-0002"},
        )

    store.base_path = str(tmp_path / "knowledge")

    with patch.dict("os.environ", {"DTVP_KNOWLEDGE_STORE_BACKEND": "sqlite"}):
        status = store.get_status()
        assert status["store_type"] == "sqlite"
        assert status["assessment_records"] == 1

        analysis = store.get_assessment_by_triplet(
            project_uuid="project-2",
            component_uuid="component-2",
            vulnerability_uuid="vuln-2",
        )
        assert analysis == {
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Migrated from json",
            "isSuppressed": True,
        }


def test_sqlite_backend_purges_assessments_after_project_retention_expires(tmp_path):
    store = KnowledgeStore(base_path=str(tmp_path / "knowledge"))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    payload = {
        "project_uuid": "project-3",
        "component_uuid": "component-3",
        "vulnerability_uuid": "vuln-3",
        "state": "EXPLOITABLE",
        "details": "Should be purged after retention",
        "suppressed": False,
    }

    with patch.dict("os.environ", {"DTVP_KNOWLEDGE_STORE_BACKEND": "sqlite"}):
        store.persist_assessment(
            payload=payload,
            component={"uuid": "component-3", "name": "package-c"},
            vulnerability={"uuid": "vuln-3", "vulnId": "CVE-2026-0003"},
        )

        store.synchronize_active_projects(
            ["project-3"],
            grace_period_days=1,
            now=now,
        )
        assert store.purge_expired_knowledge(now=now + timedelta(hours=12)) == 0

        store.synchronize_active_projects([], grace_period_days=1, now=now)
        assert store.purge_expired_knowledge(now=now + timedelta(hours=12)) == 0
        assert store.purge_expired_knowledge(now=now + timedelta(days=2)) == 1

        assert (
            store.get_assessment_by_triplet(
                project_uuid="project-3",
                component_uuid="component-3",
                vulnerability_uuid="vuln-3",
            )
            is None
        )
