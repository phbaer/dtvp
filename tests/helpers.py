"""Helpers shared by tests that drive the application through its API."""

import time

from dtvp import main


def wait_for_grouped_task(test_client, task_id: str, *, timeout: float = 30.0) -> dict:
    """Wait until a grouped-vulnerability task has finished and everything it
    imported is stored.

    The task runs in the background and the cache writes through a separate
    thread. Polling a fixed number of times only works on a fast machine;
    this waits on the actual conditions with a deadline.
    """
    deadline = time.monotonic() + timeout
    status: dict = {}
    while time.monotonic() < deadline:
        status = test_client.get(f"/api/tasks/{task_id}?include_result=false").json()
        if status.get("status") == "failed":
            raise AssertionError(f"Grouped task failed: {status}")
        if status.get("status") == "completed":
            stats = main.cache_manager.get_runtime_stats()
            if not stats["write_pending"] and stats["dirty_entries"] == 0:
                return status
        time.sleep(0.02)
    raise AssertionError(f"Grouped task did not finish in {timeout}s: {status}")


def wait_for_bulk_workflow_task(test_client, task_id: str, *, timeout: float = 30.0) -> dict:
    """Wait until a bulk workflow task (preview or apply) has finished.

    It runs in the background; a fixed number of polls is not enough on a
    slow machine, so this waits with a deadline.
    """
    deadline = time.monotonic() + timeout
    status: dict = {}
    while time.monotonic() < deadline:
        response = test_client.get(f"/api/bulk-workflows/tasks/{task_id}")
        assert response.status_code == 200
        status = response.json()
        if status.get("status") in {"completed", "failed"}:
            return status
        time.sleep(0.02)
    raise AssertionError(f"Bulk workflow task did not finish in {timeout}s: {status}")
