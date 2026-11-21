"""A grouped snapshot outlives the assessment writes that are patched into it,
and no others."""

import asyncio
import logging

import pytest

from dtvp import main
from dtvp.general_api_routes import (
    _apply_bulk_workflow_payloads,
    _assessment_payload_from_analysis,
    _refresh_grouped_vuln_task_snapshots,
    start_grouped_vuln_task,
)
from tests.test_mcp_server import ARGS, _token, project, service  # noqa: F401

READ = {"project": "TestApp", "vulnerability_id": "CVE-2026-0001"}
KEYS = [("p1", "component-1", "vuln-1"), ("p2", "component-2", "vuln-1")]
F1 = "p1:component-1:vuln-1"


def _payload(state, details, project_uuid="p1", component_uuid="component-1"):
    return {
        "project_uuid": project_uuid,
        "component_uuid": component_uuid,
        "vulnerability_uuid": "vuln-1",
        "state": state,
        "details": details,
        "suppressed": False,
    }


def _snapshot_states(task_id=None, field="analysis_state") -> dict:
    """What the live snapshot itself holds per finding (MCP reads the
    assessment from the record, so its answers cannot show a stale
    snapshot)."""
    tasks = [
        task
        for task in main.tasks.values()
        if task_id in (None, task.get("id"))
    ]
    task = tasks[-1]
    return {
        component.get("finding_uuid"): component.get(field)
        for group in task.get("_full_result") or []
        for version in group.get("affected_versions") or []
        for component in version.get("components") or []
    }


def _builds() -> int:
    """How many grouping computations were started."""
    return sum(1 for task in main.tasks.values() if "_task_key" in task)


async def _save(service, token, **overrides):
    preview = await service.preview_assessment(token, **{**ARGS, **overrides})
    return await service.save_assessment(
        token, **{**ARGS, **overrides}, expected_revisions=preview["expected_revisions"]
    )


def _team_a(view) -> dict:
    return next(b for b in view["assessments"][0]["blocks"] if b["team"] == "Team A")


async def test_preview_save_and_read_build_the_snapshot_once(service, caplog):
    token = _token()
    caplog.set_level(logging.INFO)

    await _save(service, token)
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 1
    assert _team_a(after)["state"] == "NOT_AFFECTED"
    assert {finding["revision"] for finding in after["findings"]} == {1}
    assert {finding["sync_status"] for finding in after["findings"]} == {"pending"}
    lines = [r.getMessage() for r in caplog.records if "Grouped snapshot of" in r.getMessage()]
    assert sum("building a new one (no snapshot yet)" in line for line in lines) == 1
    assert sum("reused task" in line for line in lines) >= 2


async def test_several_saves_in_a_row_keep_the_snapshot(service):
    token = _token()
    await _save(service, token)
    await _save(service, token, state="EXPLOITABLE", details="Reachable after all.")
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 1
    assert _team_a(after)["state"] == "EXPLOITABLE"
    assert _snapshot_states()[F1] == "EXPLOITABLE"


async def test_the_export_of_a_save_keeps_the_snapshot(service, mock_dt_client):
    token = _token()
    await _save(service, token)
    mock_dt_client.update_analysis.return_value = {}

    await main.cache_manager.flush_pending_updates(mock_dt_client)
    after = await service.get_vulnerability(token, **READ)

    assert mock_dt_client.update_analysis.call_count == 2
    assert _builds() == 1
    assert {finding["sync_status"] for finding in after["findings"]} == {"synced"}
    assert set(_snapshot_states(field="sync_status").values()) == {"synced"}


async def test_imported_data_builds_the_snapshot_again(service, caplog):
    token = _token()
    await service.get_vulnerability(token, **READ)
    caplog.set_level(logging.INFO)

    # What an import, a carry-over or a restored archive does.
    main.cache_manager._touch_cache_meta(project_uuids={"p2"})
    await service.get_vulnerability(token, **READ)

    assert _builds() == 2
    assert "building a new one (the stored source data changed)" in caplog.text


async def test_a_save_racing_with_an_import_builds_the_snapshot_again(service):
    token = _token()
    await service.get_vulnerability(token, **READ)

    main.cache_manager._touch_cache_meta(project_uuids={"p1"})
    await _save(service, token)  # joins nothing: the import came first
    builds = _builds()
    main.cache_manager._touch_cache_meta(project_uuids={"p1"})
    after = await service.get_vulnerability(token, **READ)

    assert builds == 2 and _builds() == 3
    assert _team_a(after)["state"] == "NOT_AFFECTED"


async def test_a_save_that_is_not_patched_in_builds_the_snapshot_again(service, caplog):
    """Between the record and the patch, and when the patch never comes."""
    token = _token()
    before = await service.get_vulnerability(token, **READ)
    caplog.set_level(logging.INFO)

    await main.cache_manager.persist_assessment_updates(
        [
            {
                "project_uuid": "p1",
                "component_uuid": "component-1",
                "vulnerability_uuid": "vuln-1",
                "state": "EXPLOITABLE",
                "details": "Written without telling the snapshots.",
                "suppressed": False,
            }
        ],
        replace=True,
    )
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 2
    assert "an assessment was saved that the snapshot does not show yet" in caplog.text
    assert before["findings"][0]["analysis_state"] != "EXPLOITABLE"
    states = {f["finding_uuid"]: f["analysis_state"] for f in after["findings"]}
    assert states["p1:component-1:vuln-1"] == "EXPLOITABLE"


async def test_a_partial_patch_does_not_make_the_snapshot_current(service):
    token = _token()
    await service.get_vulnerability(token, **READ)
    payloads = [
        {
            "project_uuid": project_uuid,
            "component_uuid": component_uuid,
            "vulnerability_uuid": vulnerability_uuid,
            "state": "EXPLOITABLE",
            "details": "Both versions.",
            "suppressed": False,
        }
        for project_uuid, component_uuid, vulnerability_uuid in KEYS
    ]
    await main.cache_manager.persist_assessment_updates(payloads, replace=True)

    # Only the first finding reaches the snapshots.
    _refresh_grouped_vuln_task_snapshots(
        main.tasks, [(payloads[0], payloads[0])], main.load_team_mapping()
    )
    assert main.cache_manager.has_unapplied_assessment_writes({"p2"}, after_seq=0)
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 2
    assert {finding["analysis_state"] for finding in after["findings"]} == {"EXPLOITABLE"}


@pytest.mark.parametrize("newer_first", [False, True])
async def test_patches_in_any_order_leave_the_recorded_value(service, newer_first):
    """Patches run in threads and can land in any order; the snapshot ends
    with the value on record either way, and stays reusable."""
    token = _token()
    await service.get_vulnerability(token, **READ)
    older, newer = _payload("IN_TRIAGE", "First."), _payload("EXPLOITABLE", "Second.")
    await main.cache_manager.persist_assessment_updates([older], replace=True)
    await main.cache_manager.persist_assessment_updates([newer], replace=True)

    order = [newer, older] if newer_first else [older, newer]
    for payload in order:
        _refresh_grouped_vuln_task_snapshots(
            main.tasks, [(payload, payload)], main.load_team_mapping()
        )
    after = await service.get_vulnerability(token, **READ)
    search = await service.search_vulnerabilities(token, project="TestApp")

    assert _builds() == 1
    assert _snapshot_states()[F1] == "EXPLOITABLE"
    assert {f["finding_uuid"]: f["analysis_state"] for f in after["findings"]}[F1] == "EXPLOITABLE"
    # The patched summary row is the one a fresh build makes.
    main.cache_manager._touch_cache_meta(project_uuids={"p1"})
    rebuilt = await service.search_vulnerabilities(token, project="TestApp")
    assert _builds() == 2
    assert search["items"] == rebuilt["items"]


async def test_a_listener_patch_read_before_a_save_does_not_undo_it(service):
    """The listener reads the stored value before taking the lock; a save
    and its patch can come in between."""
    token = _token()
    await service.get_vulnerability(token, **READ)
    first, second = _payload("IN_TRIAGE", "First."), _payload("EXPLOITABLE", "Second.")
    await main.cache_manager.persist_assessment_updates([first], replace=True)
    stale = _assessment_payload_from_analysis(
        main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    )
    await main.cache_manager.persist_assessment_updates([second], replace=True)
    _refresh_grouped_vuln_task_snapshots(
        main.tasks, [(second, second)], main.load_team_mapping()
    )
    _refresh_grouped_vuln_task_snapshots(
        main.tasks, [(first, stale)], main.load_team_mapping()
    )
    await service.get_vulnerability(token, **READ)

    assert _builds() == 1
    assert _snapshot_states()[F1] == "EXPLOITABLE"


async def test_a_save_during_a_build_does_not_leave_that_build_current(service):
    """The build may have read the finding before the save and assemble its
    result after the patch."""
    token = _token()
    await service.get_vulnerability(token, **READ)
    [task] = list(main.tasks.values())
    payload = {
        "project_uuid": "p1",
        "component_uuid": "component-1",
        "vulnerability_uuid": "vuln-1",
        "state": "EXPLOITABLE",
        "details": "Saved while the snapshot was being built.",
        "suppressed": False,
    }

    task["status"] = "running"
    await main.cache_manager.persist_assessment_updates([payload], replace=True)
    _refresh_grouped_vuln_task_snapshots(
        main.tasks, [(payload, payload)], main.load_team_mapping()
    )
    task["status"] = "completed"

    started = start_grouped_vuln_task(
        main.general_api_route_deps,
        name="TestApp", cve=None, response_mode="summary", user="alice",
    )
    assert started["reused"] is False


async def test_a_bulk_apply_keeps_the_snapshot(service, mock_dt_client):
    token = _token()
    await service.get_vulnerability(token, **READ)
    payloads = [
        (
            {
                "project_uuid": project_uuid,
                "component_uuid": component_uuid,
                "vulnerability_uuid": vulnerability_uuid,
            },
            {
                "project_uuid": project_uuid,
                "component_uuid": component_uuid,
                "vulnerability_uuid": vulnerability_uuid,
                "state": "FALSE_POSITIVE",
                "details": "Bulk decision.",
                "suppressed": False,
            },
        )
        for project_uuid, component_uuid, vulnerability_uuid in KEYS
    ]

    await _apply_bulk_workflow_payloads(
        main.general_api_route_deps, mock_dt_client, payloads, author="rita"
    )
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 1
    assert {finding["analysis_state"] for finding in after["findings"]} == {"FALSE_POSITIVE"}
    assert set(_snapshot_states().values()) == {"FALSE_POSITIVE"}


async def test_a_discarded_export_keeps_the_snapshot(service):
    token = _token()
    await _save(service, token)
    pending = main.cache_manager._load_pending_updates()

    await main.cache_manager.discard_exports([entry["id"] for entry in pending])
    after = await service.get_vulnerability(token, **READ)

    assert _builds() == 1
    assert {finding["analysis_state"] for finding in after["findings"]} == {"IN_TRIAGE"}
    assert set(_snapshot_states().values()) == {"IN_TRIAGE"}


def _reuse(user="alice"):
    return start_grouped_vuln_task(
        main.general_api_route_deps,
        name="TestApp", cve=None, response_mode="summary", user=user,
    )


def _hold_p2(mock_dt_client, project):
    """Let a build read p1, then hold it until the returned event is set."""
    release, p1_read = asyncio.Event(), asyncio.Event()

    async def get_vulnerabilities(project_uuid, cve=None):
        if project_uuid == "p1":
            p1_read.set()
        if project_uuid == "p2":
            await p1_read.wait()
            await release.wait()
        return project[project_uuid]

    mock_dt_client.get_vulnerabilities.side_effect = get_vulnerabilities
    return release, p1_read


async def _finalized(task_id):
    for _ in range(200):
        task = main.tasks[task_id]
        if task["status"] == "completed" and task.get("_task_key_finalized"):
            return task
        await asyncio.sleep(0.05)
    raise AssertionError("the build did not finish")


async def _save_and_patch(payload):
    await main.cache_manager.persist_assessment_updates([payload], replace=True)
    await asyncio.to_thread(
        _refresh_grouped_vuln_task_snapshots,
        main.tasks, [(payload, payload)], main.load_team_mapping(),
    )


async def test_a_request_after_a_save_does_not_join_a_build_that_missed_it(
    service, project, mock_dt_client
):
    """A real build that has read p1 when the save lands: whoever asks after
    the save gets a new build, not the one that missed it."""
    token = _token()
    release, p1_read = _hold_p2(mock_dt_client, project)
    first = asyncio.create_task(service.get_vulnerability(token, **READ))
    await p1_read.wait()
    await asyncio.sleep(0.2)
    await _save_and_patch(_payload("EXPLOITABLE", "Saved during the build."))

    joiner = asyncio.create_task(service.get_vulnerability(token, **READ))
    await asyncio.sleep(0.1)
    release.set()
    await first
    await joiner

    assert _builds() == 2
    assert _snapshot_states()[F1] == "EXPLOITABLE"


async def test_a_built_but_unfinalized_snapshot_that_missed_a_save_is_not_served(service):
    token = _token()
    await service.get_vulnerability(token, **READ)
    [task] = list(main.tasks.values())

    task["status"] = "running"
    await _save_and_patch(_payload("EXPLOITABLE", "Saved during the build."))
    while_running = _reuse()
    # Only the flagged task is under test, not the build just started.
    main.tasks.pop(while_running["task_id"])
    task.update(status="completed", _task_key_finalized=False)
    while_unfinalized = _reuse()

    assert while_running["reused"] is False
    assert while_unfinalized["reused"] is False
    assert task["id"] not in {while_running["task_id"], while_unfinalized["task_id"]}


async def test_a_build_that_did_not_know_its_versions_is_marked_by_a_save(
    project, mock_dt_client
):
    """Started before the project list was loaded: its key names no versions
    when the save lands."""
    release, p1_read = _hold_p2(mock_dt_client, project)
    started = _reuse()
    await p1_read.wait()
    await asyncio.sleep(0.2)
    await _save_and_patch(_payload("EXPLOITABLE", "Saved during the build."))
    release.set()
    await _finalized(started["task_id"])

    assert _reuse("bob")["reused"] is False


async def test_a_build_that_learned_its_versions_late_is_not_reused_after_saves(
    project, mock_dt_client
):
    """The same, when the save's patch did not reach the build (for example a
    version added after the list was read): finalization finds versions the
    build did not know at the start and writes since then."""
    release, p1_read = _hold_p2(mock_dt_client, project)
    started = _reuse()
    await p1_read.wait()
    await asyncio.sleep(0.2)
    await main.cache_manager.persist_assessment_updates(
        [_payload("EXPLOITABLE", "Saved, patch lost.")], replace=True
    )
    main.cache_manager.confirm_assessment_writes_applied(
        [(KEYS[0], _payload("EXPLOITABLE", "Saved, patch lost."))]
    )
    release.set()
    task = await _finalized(started["task_id"])

    assert task["_assessment_patch_missed"] is True
    assert _reuse("bob")["reused"] is False


async def test_requests_during_an_export_batch_reuse_the_snapshot(
    service, mock_dt_client
):
    token = _token()
    await _save(service, token)
    seen = {}

    async def update_analysis(**kwargs):
        if kwargs.get("project_uuid") == "p2":
            # p1 is exported and stored by now.
            await asyncio.sleep(0.3)
            await service.get_vulnerability(token, **READ)
            seen["builds"] = _builds()
        return {}

    mock_dt_client.update_analysis.side_effect = update_analysis
    await main.cache_manager.flush_pending_updates(mock_dt_client)
    await service.get_vulnerability(token, **READ)

    assert seen["builds"] == 1
    assert _builds() == 1
    assert set(_snapshot_states(field="sync_status").values()) == {"synced"}


async def test_an_export_does_not_mark_a_running_build(service, mock_dt_client):
    token = _token()
    await _save(service, token)
    [task] = list(main.tasks.values())
    mock_dt_client.update_analysis.return_value = {}

    task["status"] = "running"
    await main.cache_manager.flush_pending_updates(mock_dt_client)
    task["status"] = "completed"

    assert not task.get("_assessment_patch_missed")
    assert _reuse()["reused"] is True


def test_the_summary_index_still_follows_every_save():
    """Saves no longer change what a grouped snapshot is keyed on, but they
    do change the revision the summary index is built for."""
    before = main.cache_manager.get_grouped_cache_revision(versions=[{"uuid": "p1"}])
    source = main.cache_manager.get_grouped_source_revision(versions=[{"uuid": "p1"}])

    main.cache_manager._touch_cache_meta(
        project_uuids={"p1"}, assessment_keys=[KEYS[0]]
    )

    assert main.cache_manager.get_grouped_cache_revision(
        versions=[{"uuid": "p1"}]
    ) != before
    assert main.cache_manager.get_grouped_source_revision(
        versions=[{"uuid": "p1"}]
    ) == source
    assert main.cache_manager.has_unapplied_assessment_writes({"p1"}, after_seq=0)
    assert not main.cache_manager.has_unapplied_assessment_writes({"p1"}, after_seq=1)
    assert not main.cache_manager.has_unapplied_assessment_writes({"p2"}, after_seq=0)
