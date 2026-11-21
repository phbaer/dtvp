"""Per-version sync state and content digests (ADR 0004, step 4)."""

from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.dt_cache import CacheManager
from dtvp.local_store import LocalStore
from dtvp.source_sync_state import (
    KIND_BOM,
    KIND_FINDINGS,
    SyncStateStore,
    bom_digest,
    classify_analysis_changes,
    findings_digests,
    vulns_digest,
)
from dtvp.sync_routes import create_sync_router


def _finding(component, vuln="v1", state="NOT_SET", details=""):
    return {
        "component": {"uuid": component, "name": "lib", "version": "1.0"},
        "vulnerability": {"uuid": vuln, "vulnId": f"CVE-{vuln}"},
        "analysis": {"analysisState": state, "analysisDetails": details, "isSuppressed": False},
    }


def _store(tmp_path):
    local = LocalStore(str(tmp_path / "store.sqlite3"))
    return local, SyncStateStore(local._connection)


# -- digests ------------------------------------------------------------------


def test_digests_ignore_order_and_separate_identity_from_analysis():
    a, b = _finding("c1"), _finding("c2", state="EXPLOITABLE")
    identity, analyses, index = findings_digests([a, b])
    assert (identity, analyses) == findings_digests([b, a])[:2]
    assert set(index) == {"c1:v1", "c2:v1"}

    changed = _finding("c2", state="NOT_AFFECTED")
    identity2, analyses2, _ = findings_digests([a, changed])
    assert identity2 == identity and analyses2 != analyses


def test_vulns_and_bom_digests_skip_volatile_fields():
    vuln = {"uuid": "v1", "severity": "HIGH", "description": "x", "lastModified": 1}
    assert vulns_digest([vuln]) == vulns_digest([{**vuln, "lastModified": 2}])
    assert vulns_digest([vuln]) != vulns_digest([{**vuln, "severity": "LOW"}])
    bom = {
        "serialNumber": "urn:1",
        "metadata": {"timestamp": "t1"},
        "components": [{"purl": "pkg:npm/a@1"}],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    }
    other = {**bom, "serialNumber": "urn:2", "metadata": {"timestamp": "t2"}}
    assert bom_digest(bom) == bom_digest(other)
    assert bom_digest(bom) != bom_digest({**bom, "dependencies": []})


def test_changed_analyses_are_echoes_when_the_source_holds_the_record():
    before = findings_digests([_finding("c1"), _finding("c2")])[2]
    findings = [_finding("c1", state="NOT_AFFECTED", details="Ours."), _finding("c2", state="EXPLOITABLE")]
    after = findings_digests(findings)[2]
    recorded = {"c1": ("NOT_AFFECTED", "Ours.", False)}

    origins = classify_analysis_changes(
        before, after, findings, lambda component, _vuln: recorded.get(component)
    )
    assert origins == {"dt": ["c2:v1"], "export_echo": ["c1:v1"]}
    assert classify_analysis_changes(None, after, findings, lambda *_: None) == {
        "dt": [], "export_echo": [],
    }


# -- the store ----------------------------------------------------------------


def test_the_project_list_adds_versions_and_marks_missing_ones_gone(tmp_path):
    local, store = _store(tmp_path)
    store.record_project_list(
        [
            {"uuid": "p1", "name": "App", "version": "1", "dtvpSourceMarks": {"bom": 5}},
            {"uuid": "p2", "name": "App", "version": "2"},
        ],
        at="2026-11-21T10:00:00+00:00",
    )
    rows = {row["project_uuid"]: row for row in store.list_versions(product="app")}
    assert rows["p1"]["status"] == "never_synced"
    assert rows["p1"]["dt_last_bom_import"] == "5"

    # A partial list (a name search) never marks anything gone.
    store.record_project_list([{"uuid": "p1", "name": "App", "version": "1"}], complete=False)
    assert {r["status"] for r in store.list_versions()} == {"never_synced"}
    store.record_project_list([{"uuid": "p1", "name": "App", "version": "1"}])
    rows = {row["project_uuid"]: row for row in store.list_versions()}
    assert rows["p2"]["status"] == "gone" and rows["p2"]["active_in_dt"] is False
    local.close()


def test_a_read_changes_the_version_only_when_a_known_digest_changes(tmp_path):
    local, store = _store(tmp_path)
    assert store.record_read("p1", KIND_BOM, ("a",), at="2026-11-21T10:00:00+00:00") is False
    [row] = store.list_versions()
    assert (row["status"], row["generation"], row["last_change_at"]) == (
        "synced", 1, "2026-11-21T10:00:00+00:00",
    )

    assert store.record_read("p1", KIND_BOM, ("a",), at="2026-11-21T11:00:00+00:00") is False
    # The first findings read stores an unknown digest without a change.
    assert store.record_read(
        "p1", KIND_FINDINGS, ("f", "x"), analyses_index={}, at="2026-11-21T11:00:00+00:00"
    ) is False
    assert store.previous_analyses_index("p1") == {}
    assert store.previous_analyses_index("p9") is None
    [row] = store.list_versions()
    assert (row["generation"], row["last_change_at"]) == (1, "2026-11-21T10:00:00+00:00")

    assert store.record_read("p1", KIND_BOM, ("b",), at="2026-11-21T12:00:00+00:00") is True
    [row] = store.list_versions(changed_since="2026-11-21T11:30:00+00:00")
    assert row["generation"] == 2
    local.close()


def test_a_failure_is_recorded_and_cleared_by_the_next_read(tmp_path):
    local, store = _store(tmp_path)
    store.record_failure("p1", TimeoutError("slow"))
    store.record_failure("p1", TimeoutError("slow"))
    [row] = store.list_versions()
    assert (row["status"], row["consecutive_failures"], row["last_error_class"]) == (
        "failed", 2, "TimeoutError",
    )
    store.record_read("p1", KIND_BOM, ("a",))
    [row] = store.list_versions()
    assert (row["status"], row["consecutive_failures"], row["last_error"]) == ("synced", 0, None)
    assert store.status()["by_status"] == {"synced": 1}
    local.close()


# -- recorded during the refresh ----------------------------------------------


async def test_the_import_records_digests_and_tells_echoes_from_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_vulnerabilities.return_value = [_finding("c1"), _finding("c2")]
    await manager.import_findings(client, "p1")
    [row] = manager.sync_state.list_versions()
    assert row["status"] == "synced" and row["generation"] == 1

    # DTVP's own value comes back from the source: an echo, not a change.
    await manager.persist_assessment_updates(
        [{"project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1",
          "state": "NOT_AFFECTED", "details": "Ours.", "suppressed": False}],
        replace=True,
    )
    client.get_vulnerabilities.return_value = [
        _finding("c1", state="NOT_AFFECTED", details="Ours."), _finding("c2"),
    ]
    await manager.import_findings(client, "p1")
    [row] = manager.sync_state.list_versions()
    assert (row["analyses_export_echoes"], row["analyses_changed_in_dt"], row["generation"]) == (1, 0, 1)

    # Someone changes an analysis in the source.
    client.get_vulnerabilities.return_value = [
        _finding("c1", state="NOT_AFFECTED", details="Ours."), _finding("c2", state="EXPLOITABLE"),
    ]
    await manager.import_findings(client, "p1")
    [row] = manager.sync_state.list_versions()
    assert (row["analyses_changed_in_dt"], row["generation"]) == (1, 2)

    client.get_vulnerabilities.side_effect = ConnectionError("down")
    try:
        await manager.import_findings(client, "p1")
    except ConnectionError:
        pass
    [row] = manager.sync_state.list_versions()
    assert (row["status"], row["last_error_class"]) == ("failed", "ConnectionError")
    await manager.close()


async def test_the_project_list_bom_and_vulnerabilities_are_recorded(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()
    client.get_projects.return_value = [{"uuid": "p1", "name": "App", "version": "1"}]
    await manager.get_projects(client)
    client.get_bom.return_value = {"components": [{"purl": "pkg:npm/a@1"}]}
    client.get_project_vulnerabilities.return_value = [{"uuid": "v1", "severity": "HIGH"}]
    await manager.get_bom(client, "p1", refresh=True)
    await manager.get_project_vulnerabilities(client, "p1", refresh=True)

    [row] = manager.sync_state.list_versions(product="App")
    assert row["bom_digest"] and row["vulns_digest"] and row["status"] == "synced"
    await manager.close()


def test_the_risk_score_is_not_part_of_the_grouped_revision(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    version = {"uuid": "p1", "name": "App", "version": "1", "lastRiskScore": 1.0}
    before = manager.get_grouped_cache_revision(versions=[version])
    after = manager.get_grouped_cache_revision(versions=[{**version, "lastRiskScore": 9.0}])
    assert before == after


# -- routes -------------------------------------------------------------------


def test_the_routes_report_versions_and_status(tmp_path):
    local, store = _store(tmp_path)
    store.record_project_list([{"uuid": "p1", "name": "App", "version": "1"}])
    store.record_read("p1", KIND_BOM, ("a",), at="2026-11-21T10:00:00+00:00")
    app = FastAPI()
    app.include_router(
        create_sync_router(lambda: store, current_user_dependency=lambda: "alice"),
        prefix="/api",
    )
    client = TestClient(app)

    versions = client.get("/api/sync/versions", params={"product": "App"}).json()["versions"]
    assert [v["project_uuid"] for v in versions] == ["p1"]
    assert client.get(
        "/api/sync/versions", params={"changed_since": "2026-11-21T11:00:00+00:00"}
    ).json() == {"versions": []}
    assert client.get("/api/sync/versions", params={"changed_since": "yesterday"}).status_code == 422
    status = client.get("/api/sync/status").json()
    assert status["versions"] == 1 and status["by_status"] == {"synced": 1}
    local.close()
