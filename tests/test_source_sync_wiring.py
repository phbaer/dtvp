"""How the app wires the sync scheduler (ADR 0004 step 5): interest from a
user's reads, the breaker on list reads, and the echo filter."""

import dataclasses
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.general_api_routes import start_grouped_vuln_task


@pytest.fixture(autouse=True)
def fresh_interest():
    main.product_interest._leases.clear()
    main.app.dependency_overrides[main.get_current_user] = lambda: "reader"
    yield
    main.product_interest._leases.clear()


def test_the_app_hands_reads_to_the_interest_and_list_reads_to_the_breaker():
    assert main.general_api_route_deps.note_interest == main.product_interest.touch
    assert main.cache_manager.scheduler is main.source_sync
    assert main.source_sync.interest is main.product_interest
    assert main.source_sync.breaker.observe in main.cache_manager._source_state_listeners


def test_opening_a_project_makes_it_watched(client):
    # The app's deps, without starting the computation itself.
    deps = dataclasses.replace(
        main.general_api_route_deps, create_tracked_task=lambda coro: coro.close()
    )
    started = start_grouped_vuln_task(
        deps, name="Opened", cve=None, response_mode="summary", user="reader",
    )
    main.tasks.pop(started["task_id"], None)
    assert "Opened" in main.product_interest.watched()


def test_polling_a_task_keeps_its_product_watched(client):
    task_id = "interest-task"
    main.tasks[task_id] = {
        "_owner": "reader", "id": task_id, "status": "completed", "result": [],
        "_project_name": "Polled", "completed_at": datetime.now(timezone.utc),
    }
    try:
        assert client.get(f"/api/tasks/{task_id}").status_code == 200
    finally:
        main.tasks.pop(task_id, None)
    assert "Polled" in main.product_interest.watched()


def test_an_export_echo_does_not_refresh_open_views():
    listener = main.cache_manager._assessment_change_listeners[0]
    with patch.object(main, "refresh_task_snapshots_for_assessments") as refresh:
        listener([("p", "c", "v")], value_changed=False, origin="export_echo")
        refresh.assert_not_called()
        listener([("p", "c", "v")], origin="dt")
        refresh.assert_called_once()
