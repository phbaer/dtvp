from datetime import datetime, timedelta, timezone

from dtvp.grouped_vuln_task_services import prune_grouped_vuln_tasks


def test_prune_grouped_vuln_tasks_removes_expired_terminal_tasks():
    now = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    tasks = {
        "old-completed": {
            "status": "completed",
            "completed_at": now - timedelta(seconds=120),
        },
        "old-failed": {
            "status": "failed",
            "updated_at": now - timedelta(seconds=120),
        },
        "fresh-completed": {
            "status": "completed",
            "completed_at": now - timedelta(seconds=10),
        },
        "running": {
            "status": "running",
            "updated_at": now - timedelta(seconds=120),
        },
    }

    removed = prune_grouped_vuln_tasks(tasks, ttl_seconds=60, now=now)

    assert removed == ["old-completed", "old-failed"]
    assert set(tasks) == {"fresh-completed", "running"}


def test_prune_grouped_vuln_tasks_keeps_legacy_tasks_without_timestamps():
    tasks = {
        "legacy": {
            "status": "completed",
            "result": [],
        },
    }

    removed = prune_grouped_vuln_tasks(
        tasks,
        ttl_seconds=60,
        now=datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
    )

    assert removed == []
    assert "legacy" in tasks
