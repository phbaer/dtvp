"""Restore team assessments from the source's assessment history: the texts
a finding held over time (Dependency-Track: the "Details: ..." comments of
its audit trail)."""

from unittest.mock import AsyncMock, patch

from dtvp import main
from dtvp.bulk_workflows.team_assessment_restore import (
    build_team_assessment_restore_payloads,
    build_team_assessment_restore_preview,
)
from dtvp.dt_client import DTClient
from dtvp.ports import AssessmentHistorySource
from dtvp.team_assessment_restore_services import (
    HISTORY_TOOL,
    read_assessment_history,
)
from tests.test_team_assessment_restore import (  # noqa: F401
    DAY1,
    DAY2,
    PROJECT,
    _block,
    _context,
    _group,
    _instance,
    _store,
    _task,
    _wait,
    reviewer,
)

# What Dependency-Track 4.x returns from GET /api/v1/analysis: the comments
# its AnalysisCommentUtil wrote, oldest first.
REMOVED = _block("R-Web", "NOT_AFFECTED", "Not reachable from the web tier.",
                 Assessed_By="rosa", Date=DAY1, Ticket="VP-66089")
KEPT = _block("TeamA", Assessed_By="alice", Date=DAY2)


def _analysis(*details, current):
    comments = [{"timestamp": DAY1 - 1000, "comment": "Analysis: NOT_SET → IN_TRIAGE",
                 "commenter": "rosa"}]
    for index, text in enumerate(details):
        comments.append({"timestamp": DAY1 + index, "comment": f"Details: {text}",
                         "commenter": "rosa"})
    comments.append({"timestamp": DAY2, "comment": "Looks fine.", "commenter": "alice"})
    comments.append({"timestamp": DAY2 + 1, "comment": "Suppressed", "commenter": "alice"})
    return {"analysisState": "NOT_AFFECTED", "analysisDetails": current,
            "analysisComments": comments, "isSuppressed": False}


async def test_the_adapter_reads_the_texts_from_the_details_comments():
    client = DTClient("http://dt.example")
    with patch.object(
        DTClient, "get_analysis",
        AsyncMock(return_value=_analysis(f"{KEPT}\n\n{REMOVED}", current=KEPT)),
    ):
        history = await client.get_assessment_history("p", "c", "v")
    await client.close()

    assert isinstance(client, AssessmentHistorySource)
    # State, free-text and suppression comments are not texts.
    assert history == [
        {"at": DAY1, "author": "rosa", "details": f"{KEPT}\n\n{REMOVED}"},
        {"at": None, "author": None, "details": KEPT},
    ]


async def test_no_analysis_is_no_history():
    client = DTClient("http://dt.example")
    with patch.object(DTClient, "get_analysis", AsyncMock(return_value=None)):
        assert await client.get_assessment_history("p", "c", "v") == []
    await client.close()


def _history_source(instance, *texts, failed=0):
    return read_assessment_history(
        [(instance, [{"at": None, "author": None, "details": text} for text in texts])],
        read_at="2030-01-03T00:00:00+00:00",
        failed=failed,
    )


def test_a_team_block_the_finding_no_longer_has_is_restored_with_its_ticket():
    instance = _instance("c-1", "v-1", state="NOT_AFFECTED", details=KEPT)
    source = _history_source(instance, f"{KEPT}\n\n{REMOVED}", KEPT)
    assert source.tool == HISTORY_TOOL and source.team_blocks == 2

    preview = build_team_assessment_restore_preview(
        _context(source, [_group("GHSA-qxh6-94w6-9r5p", instance)])
    )

    [item] = preview["items"]
    [block] = item["blocks"]
    assert (block["team"], block["state"], block["ticket"], block["assessed_by"]) == (
        "R-Web", "NOT_AFFECTED", "VP-66089", "rosa",
    )
    assert block["match"] == "uuid"
    payloads, _skipped = build_team_assessment_restore_payloads(
        _context(source, [_group("GHSA-qxh6-94w6-9r5p", instance)]), [item["group_id"]]
    )
    [(_, payload)] = payloads
    assert payload["state"] == "NOT_AFFECTED"
    assert payload["details"].startswith(KEPT)
    assert "[Team: R-Web]" in payload["details"] and "[Historical: yes]" in payload["details"]


def test_a_team_still_there_is_not_restored_and_older_texts_of_it_are_ignored():
    older_a = _block("TeamA", "IN_TRIAGE", "Looking.", Assessed_By="alice", Date=DAY1)
    instance = _instance("c-1", "v-1", state="NOT_AFFECTED", details=KEPT)
    source = _history_source(instance, older_a, KEPT)

    preview = build_team_assessment_restore_preview(_context(source, [_group("CVE-1", instance)]))

    assert preview["items"] == []
    assert preview["summary"]["skipped"]["present"] == 1


def test_an_entry_matches_only_its_own_finding():
    """The same component and vulnerability in another project version is
    another finding."""
    instance = _instance("c-1", "v-1", details=KEPT)
    other_version = _instance("c-1", "v-1", details=KEPT, project="proj-2")
    source = _history_source(instance, f"{KEPT}\n\n{REMOVED}")

    preview = build_team_assessment_restore_preview(
        _context(source, [_group("CVE-1", other_version)])
    )

    assert preview["items"] == []
    assert preview["summary"]["unmatched"]["no_finding_in_view"] == 1


def test_unreadable_histories_are_a_warning():
    instance = _instance("c-1", "v-1", details=KEPT)
    source = _history_source(instance, KEPT, failed=2)
    assert source.warnings == ("The history of 2 findings could not be read.",)


def _source_client(monkeypatch, mock_dt_client):
    """The background task opens its own client; give it the mock."""
    mock_dt_client.__aenter__.return_value = mock_dt_client
    monkeypatch.setattr(main, "DTClient", lambda *args, **kwargs: mock_dt_client)


def test_the_history_task_reads_every_finding_in_view(
    client, reviewer, mock_dt_client, monkeypatch
):
    _source_client(monkeypatch, mock_dt_client)
    removed_instance = _instance("c-1", "v-1", state="NOT_AFFECTED", details=KEPT)
    failing_instance = _instance("c-2", "v-2", state="NOT_AFFECTED", details=KEPT)
    groups = [_group("GHSA-qxh6-94w6-9r5p", removed_instance), _group("CVE-2", failing_instance)]
    _store(removed_instance)
    task_id = _task(groups)

    async def history(project_uuid, component_uuid, vulnerability_uuid):
        if component_uuid == "c-2":
            raise RuntimeError("source unavailable")
        return [{"at": DAY1, "author": "rosa", "details": f"{KEPT}\n\n{REMOVED}"}]

    mock_dt_client.get_assessment_history.side_effect = history
    started = client.post(
        "/api/bulk-workflows/sources/history-task", json={"task_id": task_id, "filters": {}}
    )
    assert started.status_code == 200, started.text
    status = _wait(client, started.json()["task_id"])
    assert status["status"] == "completed", status
    body = status["result"]
    assert body["entries"] == 1 and body["team_blocks"] == 2
    assert body["summary"]["tool"] == HISTORY_TOOL
    assert body["summary"]["warnings"] == ["The history of 1 finding could not be read."]

    preview_task = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview-task",
        json={"task_id": task_id, "filters": {}, "source_id": body["source_id"]},
    )
    preview = _wait(client, preview_task.json()["task_id"])["result"]
    assert preview["selectable_group_ids"] == ["GHSA-qxh6-94w6-9r5p"]

    applied = client.post(
        "/api/bulk-workflows/team-assessment-restore/apply",
        json={"task_id": task_id, "filters": {}, "source_id": body["source_id"],
              "group_ids": ["GHSA-qxh6-94w6-9r5p"], "preview_token": preview["preview_token"]},
    )
    assert applied.status_code == 200, applied.text
    [pending] = main.cache_manager._load_pending_updates()
    assert "[Team: R-Web]" in pending["payload"]["details"]
    assert "VP-66089" in pending["payload"]["details"]
    main.tasks.pop(task_id, None)


def test_the_history_task_is_for_reviewers_only(client, mock_dt_client):
    task_id = _task([_group("CVE-1", _instance("c-1", "v-1"))])
    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    try:
        with patch("dtvp.main.get_user_role", return_value="ANALYST"):
            response = client.post(
                "/api/bulk-workflows/sources/history-task", json={"task_id": task_id}
            )
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)
        main.tasks.pop(task_id, None)
    assert response.status_code == 403
    mock_dt_client.get_assessment_history.assert_not_called()


def test_too_many_findings_are_refused(client, reviewer, monkeypatch):
    from dtvp import general_api_routes

    monkeypatch.setattr(general_api_routes, "HISTORY_SOURCE_MAX_FINDINGS", 1)
    task_id = _task([_group("CVE-1", _instance("c-1", "v-1"), _instance("c-2", "v-1"))])
    response = client.post(
        "/api/bulk-workflows/sources/history-task", json={"task_id": task_id}
    )
    main.tasks.pop(task_id, None)
    assert response.status_code == 413
