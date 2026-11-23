"""An unchanged read of a version is a no-op for its data: the findings,
the assessments, the revisions and what the grouped snapshots are built
from stay as they were. Only the read-time bookkeeping moves."""

import json
import sqlite3

from tests.test_portfolio_pass import _imported
from tests.test_source_sync import Source, _finding, _scheduler

BLOCK = "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: rita] ---\nNot reachable."
# The bookkeeping of a read: when it happened, not what the version holds.
BOOKKEEPING_TABLES = {"sync_versions", "finding_reads"}
TIMESTAMP_KEYS = {"last_refreshed_at", "projects_refreshed_at"}


class Assessed(Source):
    """DT holds an assessment; DTVP exports its own to DT on request."""

    async def update_analysis(self, project_uuid, component_uuid, vulnerability_uuid, state,
                              details, comment=None, justification=None, suppressed=False,
                              response=None, **_unused):
        self.calls.append(("update", project_uuid))
        for finding in self.findings.get(project_uuid, []):
            if (finding["component"]["uuid"], finding["vulnerability"]["uuid"]) == (
                component_uuid, vulnerability_uuid,
            ):
                finding["analysis"] = {"analysisState": state, "analysisDetails": details,
                                       "isSuppressed": suppressed}
        return {}


def _data(manager):
    """Every table but the read bookkeeping, row by row, in a fixed order."""
    connection = sqlite3.connect(manager.store.path)
    dump = {}
    for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        if name in BOOKKEEPING_TABLES or name.startswith("sqlite_"):
            continue
        rows = connection.execute(f"SELECT * FROM {name}").fetchall()
        if name == "store_metadata":
            rows = [
                (key, json.dumps({k: v for k, v in json.loads(value).items()
                                  if k not in TIMESTAMP_KEYS}, sort_keys=True), *rest)
                if key == "projects_meta" else (key, value, *rest)
                for key, value, *rest in rows
            ]
        dump[name] = sorted(repr(row) for row in rows)
    connection.close()
    return dump


async def _assess_and_export(scheduler, manager, source):
    """DTVP assesses c1/v1; the export reaches DT; the version is read again."""
    await manager.persist_assessment_updates([{
        "project_uuid": "a1", "component_uuid": "c1", "vulnerability_uuid": "v1",
        "state": "EXPLOITABLE", "details": "Reachable from the API.", "suppressed": False,
    }], replace=True, origin="user", author="carol")
    await manager.flush_cache_writes()
    scheduler.request_reads(["a1"], by="rita")
    for _ in range(3):
        await scheduler.run_cycle(source)
        await scheduler.drain()
    await manager.flush_cache_writes()


async def _read_again(scheduler, manager, source, times=2):
    for _ in range(times):
        scheduler.request_reads(["a1", "b1"], by="rita")
        for _ in range(3):
            await scheduler.run_cycle(source)
            await scheduler.drain()
        await manager.flush_cache_writes()


async def test_two_identical_reads_leave_the_data_as_it_was(tmp_path):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Assessed()
    source.findings["a1"] = [
        {**_finding("c1", "v1"), "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": BLOCK,
                                              "isSuppressed": False}},
        _finding("c3", "v3"),
    ]
    await _imported(scheduler, manager, source)
    await _assess_and_export(scheduler, manager, source)
    assert ("update", "a1") in source.calls  # the export reached the source
    before = _data(manager)
    snapshot_before = manager.get_cached_project_snapshot("a1")
    listened = []
    manager.add_assessment_change_listener(
        lambda keys, value_changed=True, origin="local": listened.append((value_changed, origin))
    )

    await _read_again(scheduler, manager, source)

    assert _data(manager) == before
    assert manager.get_cached_project_snapshot("a1") == snapshot_before
    # Nothing reported a changed value, so no live grouped snapshot is patched.
    assert all(not value_changed for value_changed, _origin in listened)
    await manager.close()


async def _variant(tmp_path, change):
    scheduler, manager, hub, clock = _scheduler(tmp_path)
    source = Assessed()
    source.findings["a1"] = [
        {**_finding("c1", "v1"), "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": BLOCK,
                                              "isSuppressed": False}},
        _finding("c3", "v3"),
    ]
    await _imported(scheduler, manager, source)
    await _assess_and_export(scheduler, manager, source)
    before = _data(manager)
    change(source.findings["a1"])
    await _read_again(scheduler, manager, source, times=1)
    after = _data(manager)
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    await manager.close()
    return changed


def _reorder(findings):
    findings.reverse()


def _risk(findings):
    for finding in findings:
        finding["lastRiskScore"] = 4.5


def _trailing_space(findings):
    findings[0]["analysis"] = {**findings[0]["analysis"], "analysisDetails": BLOCK + " "}


async def test_reordered_findings_change_no_data(tmp_path):
    assert await _variant(tmp_path / "order", _reorder) == []


async def test_a_moving_risk_score_changes_no_data(tmp_path):
    assert await _variant(tmp_path / "risk", _risk) == []


async def test_trailing_space_in_the_source_text(tmp_path):
    print("\nRESPELL", await _variant(tmp_path / "space", _trailing_space))
