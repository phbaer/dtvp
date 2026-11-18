"""The local database stores source data losslessly and imports the former
JSON cache exactly once."""

import json
import sqlite3
from unittest.mock import AsyncMock

import pytest

from dtvp.dt_cache import CacheManager
from dtvp.local_store import (
    KIND_ANALYSIS,
    KIND_BOM,
    KIND_FINDINGS,
    KIND_METADATA,
    KIND_PROJECT_VULNERABILITIES,
    KIND_PROJECTS,
    MISSING,
    DocumentRef,
    LocalStore,
    get_database_path,
)

FINDING = {
    "component": {"uuid": "c1", "name": "lib-a", "version": "1.0"},
    "vulnerability": {"uuid": "v1", "vulnId": "CVE-2026-1", "severity": "HIGH"},
    "analysis": {"state": "NOT_SET", "isSuppressed": False},
    "attribution": {"attributedOn": 1700000000000},
    "matrix": "p1:c1:v1",
}


@pytest.fixture
def store(tmp_path):
    return LocalStore(str(tmp_path / "db" / "dtvp.sqlite3"))


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_database_path_defaults_into_the_cache_directory(monkeypatch):
    monkeypatch.delenv("DTVP_DATABASE_PATH", raising=False)
    assert get_database_path("data/dt_cache") == "data/dt_cache/dtvp.sqlite3"
    monkeypatch.setenv("DTVP_DATABASE_PATH", "/var/lib/dtvp/main.db")
    assert get_database_path("data/dt_cache") == "/var/lib/dtvp/main.db"


@pytest.mark.parametrize(
    ("ref", "document"),
    [
        (DocumentRef(KIND_PROJECTS), [{"uuid": "p1", "name": "App", "version": "1"}]),
        (DocumentRef(KIND_PROJECTS), []),
        (DocumentRef(KIND_FINDINGS, project_uuid="p1"), [FINDING, {**FINDING, "matrix": "x"}]),
        (DocumentRef(KIND_FINDINGS, project_uuid="p1"), []),
        # Items the lookup columns cannot describe are still kept verbatim.
        (DocumentRef(KIND_FINDINGS, project_uuid="p1"), [{"odd": 1}, "text", None, 3]),
        (DocumentRef(KIND_FINDINGS, project_uuid="p1"), None),
        (DocumentRef(KIND_FINDINGS, project_uuid="p1"), {"not": "a list"}),
        (DocumentRef(KIND_PROJECT_VULNERABILITIES, project_uuid="p1"), [{"uuid": "v1", "vulnId": "CVE-2026-1", "cwes": [79]}]),
        (DocumentRef(KIND_BOM, project_uuid="p1"), {"components": [{"bom-ref": "a", "name": "ü–✓"}]}),
        (DocumentRef(KIND_BOM, project_uuid="p1"), None),
        (DocumentRef(KIND_ANALYSIS, "p1", "c1", "v1"), {"analysisState": "NOT_AFFECTED", "analysisDetails": "x", "isSuppressed": True}),
        (DocumentRef(KIND_ANALYSIS, "p1", "c1", "v1"), None),
        (DocumentRef(KIND_METADATA, name="projects_meta"), {"revision": 3, "project_revisions": {"p1": 2}}),
    ],
)
def test_documents_round_trip_unchanged(store, ref, document):
    assert store.read(ref) is MISSING
    assert store.exists(ref) is False

    store.write(ref, document)

    assert store.read(ref) == document
    assert store.exists(ref) is True


def test_a_rewrite_replaces_the_whole_collection_of_one_project_only(store):
    p1 = DocumentRef(KIND_FINDINGS, project_uuid="p1")
    p2 = DocumentRef(KIND_FINDINGS, project_uuid="p2")
    store.write(p1, [FINDING, FINDING, FINDING])
    store.write(p2, [FINDING])

    store.write(p1, [{**FINDING, "matrix": "only"}])

    assert store.read(p1) == [{**FINDING, "matrix": "only"}]
    assert store.read(p2) == [FINDING]
    assert store.project_uuids_with_findings() == ["p1", "p2"]


def test_lookup_columns_are_derived_from_the_documents(store):
    store.write(DocumentRef(KIND_FINDINGS, project_uuid="p1"), [FINDING])
    store.write(
        DocumentRef(KIND_ANALYSIS, "p1", "c1", "v1"),
        {"analysisState": "NOT_AFFECTED", "analysisDetails": "why", "isSuppressed": True},
    )
    with sqlite3.connect(store.path) as connection:
        finding = connection.execute(
            "SELECT component_uuid, vulnerability_uuid, vuln_id, severity, "
            "component_name, component_version FROM source_findings"
        ).fetchone()
        analysis = connection.execute(
            "SELECT analysis_state, analysis_details, suppressed FROM source_analyses"
        ).fetchone()
    assert finding == ("c1", "v1", "CVE-2026-1", "HIGH", "lib-a", "1.0")
    assert analysis == ("NOT_AFFECTED", "why", 1)


def test_counts_report_stored_collections(store):
    assert store.counts() == {"findings": 0, "boms": 0, "analyses": 0}
    store.write(DocumentRef(KIND_FINDINGS, project_uuid="p1"), [])
    store.write(DocumentRef(KIND_FINDINGS, project_uuid="p2"), [FINDING])
    store.write(DocumentRef(KIND_BOM, project_uuid="p1"), {})
    store.write(DocumentRef(KIND_ANALYSIS, "p1", "c1", "v1"), {})
    assert store.counts() == {"findings": 2, "boms": 1, "analyses": 1}


def test_write_many_is_one_transaction(store):
    def documents():
        yield DocumentRef(KIND_BOM, project_uuid="p1"), {"ok": True}
        raise RuntimeError("source failed")

    with pytest.raises(RuntimeError):
        store.write_many(documents())
    assert store.read(DocumentRef(KIND_BOM, project_uuid="p1")) is MISSING


# -- one-time import of the JSON cache ------------------------------------


def _legacy_cache(base):
    projects = [
        {"uuid": "p1", "name": "App", "version": "1.0"},
        {"uuid": "weird/uuid 2", "name": "App", "version": "2.0"},
    ]
    _write_json(base / "projects.json", projects)
    _write_json(base / "projects_meta.json", {"revision": 7, "fully_cached": True})
    _write_json(base / "active_projects.json", {"p1": 1700000000.0})
    _write_json(base / "findings" / "p1.json", [FINDING])
    _write_json(base / "findings" / "weird_uuid_2.json", [])
    _write_json(base / "project_vulnerabilities" / "p1.json", [{"uuid": "v1"}])
    _write_json(base / "boms" / "p1.json", {"components": []})
    _write_json(base / "analysis" / "p1__c1__v1.json", {"analysisState": "IN_TRIAGE"})
    _write_json(base / "analysis" / "unexpected.json", {"analysisState": "X"})
    (base / "findings" / "broken.json").write_text("{not json", encoding="utf-8")
    return projects


def test_legacy_json_cache_is_imported_once_and_left_in_place(tmp_path, store):
    projects = _legacy_cache(tmp_path)

    counts = store.import_legacy_json_cache(str(tmp_path))

    assert counts == {
        "projects": 2,
        "findings": 2,
        "project_vulnerabilities": 1,
        "boms": 1,
        "analyses": 1,
        "skipped": 2,
    }
    assert store.read(DocumentRef(KIND_PROJECTS)) == projects
    assert store.read(DocumentRef(KIND_FINDINGS, project_uuid="p1")) == [FINDING]
    # The sanitised file name is mapped back to the real project UUID.
    assert store.read(DocumentRef(KIND_FINDINGS, project_uuid="weird/uuid 2")) == []
    assert store.read(DocumentRef(KIND_BOM, project_uuid="p1")) == {"components": []}
    assert store.read(DocumentRef(KIND_ANALYSIS, "p1", "c1", "v1")) == {
        "analysisState": "IN_TRIAGE"
    }
    assert store.read(DocumentRef(KIND_METADATA, name="projects_meta"))["revision"] == 7
    assert (tmp_path / "findings" / "p1.json").exists()

    # A second start does not import again, even if the files changed.
    _write_json(tmp_path / "findings" / "p1.json", [])
    assert store.import_legacy_json_cache(str(tmp_path)) is None
    assert store.read(DocumentRef(KIND_FINDINGS, project_uuid="p1")) == [FINDING]


def test_an_empty_directory_still_marks_the_import_done(tmp_path, store):
    assert store.import_legacy_json_cache(str(tmp_path)) == {
        "projects": 0,
        "findings": 0,
        "project_vulnerabilities": 0,
        "boms": 0,
        "analyses": 0,
        "skipped": 0,
    }
    _write_json(tmp_path / "findings" / "late.json", [FINDING])
    assert store.import_legacy_json_cache(str(tmp_path)) is None


# -- through the cache manager -----------------------------------------------


async def test_cache_manager_serves_an_existing_json_cache_from_the_database(
    tmp_path, caplog
):
    projects = _legacy_cache(tmp_path)

    manager = CacheManager(base_path=str(tmp_path))
    with caplog.at_level("WARNING", logger="dtvp.dt_cache"):
        manager.load_persisted_runtime_state()
        manager.load_persisted_runtime_state()
    client = AsyncMock()

    # Operators are told once, when logging is available.
    reports = [r for r in caplog.records if "Imported the JSON cache" in r.message]
    assert len(reports) == 1
    assert "2 findings" in reports[0].getMessage()
    assert manager.cache_meta["revision"] == 7
    assert await manager.get_projects(client, "App") == projects
    assert await manager.get_vulnerabilities(client, "p1") == [
        {**FINDING, "analysis": {"analysisState": "IN_TRIAGE"}}
    ]
    assert await manager.get_bom(client, "p1") == {"components": []}
    assert await manager.get_project_vulnerabilities(client, "p1") == [{"uuid": "v1"}]
    client.get_vulnerabilities.assert_not_called()
    client.get_bom.assert_not_called()
    status = manager.get_cache_status()
    assert (status["cached_findings"], status["cached_boms"], status["cached_analyses"]) == (2, 1, 1)
    await manager.close()


async def test_data_survives_a_restart_without_any_json_files(tmp_path):
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [FINDING]
    client.get_bom.return_value = {"components": [{"name": "lib-a"}]}
    first = CacheManager(base_path=str(tmp_path))
    await first.get_vulnerabilities(client, "p1")
    await first.get_bom(client, "p1")
    await first.close()

    assert sorted(path.name for path in tmp_path.iterdir() if path.suffix == ".json") == []
    assert not (tmp_path / "findings").exists()

    offline = AsyncMock()
    second = CacheManager(base_path=str(tmp_path))
    assert await second.get_vulnerabilities(offline, "p1") == [FINDING]
    assert await second.get_bom(offline, "p1") == {"components": [{"name": "lib-a"}]}
    offline.get_vulnerabilities.assert_not_called()
    assert [v["uuid"] for v in second.get_cached_project_versions()] == ["p1"]
    await second.close()


# -- projects the source no longer lists -----------------------------------------


def test_projects_are_remembered_after_they_leave_the_list(store):
    projects = DocumentRef(KIND_PROJECTS)
    store.write(projects, [
        {"uuid": "p1", "name": "Imaging Suite", "version": "4.2"},
        {"uuid": "p2", "name": "Viewer", "version": "1.0"},
    ])
    store.write(projects, [{"uuid": "p2", "name": "Viewer", "version": "1.0"}])

    described = store.describe_projects(["p1", "p2", "never-seen", ""])

    assert described["p1"]["name"] == "Imaging Suite"
    assert described["p1"]["version"] == "4.2"
    assert described["p2"]["last_seen_at"] >= described["p1"]["last_seen_at"]
    assert "never-seen" not in described
    assert store.read(projects) == [{"uuid": "p2", "name": "Viewer", "version": "1.0"}]


def test_a_project_gone_before_it_was_remembered_is_named_from_its_bom(store):
    store.write(
        DocumentRef(KIND_BOM, project_uuid="gone"),
        {"metadata": {"component": {"name": "Legacy Console", "version": "9.1"}}, "components": []},
    )
    store.write(DocumentRef(KIND_BOM, project_uuid="no-root"), {"components": []})

    described = store.describe_projects(["gone", "no-root"])

    assert (described["gone"]["name"], described["gone"]["version"]) == ("Legacy Console", "9.1")
    assert described["gone"]["last_seen_at"]
    assert "no-root" not in described


def test_an_existing_database_remembers_the_projects_it_already_lists(tmp_path):
    import shutil
    import sqlite3

    from dtvp.local_store import get_local_store_migrations_path
    from dtvp.sqlite_migration_services import run_sqlite_migrations

    first = tmp_path / "first_migration"
    first.mkdir()
    shutil.copy(get_local_store_migrations_path() / "0001_initial.sql", first)
    path = str(tmp_path / "old.sqlite3")
    connection = sqlite3.connect(path)
    run_sqlite_migrations(connection, namespace="local_store", migrations_path=first)
    connection.execute(
        "INSERT INTO source_projects VALUES (0, 'p1', 'Imaging Suite', '4.2', '{}')"
    )
    connection.execute(
        "INSERT INTO source_snapshots VALUES ('projects', '', 1, NULL, '2026-11-01T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()

    described = LocalStore(path).describe_projects(["p1"])

    assert described["p1"] == {
        "name": "Imaging Suite",
        "version": "4.2",
        "last_seen_at": "2026-11-01T00:00:00+00:00",
    }
