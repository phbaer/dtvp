from datetime import datetime, timezone
from typing import Any


TERMINAL_GROUPED_VULN_TASK_STATUSES = {"completed", "failed"}


def _task_timestamp_seconds(task: dict[str, Any]) -> float | None:
    value = (
        task.get("_last_accessed_at")
        or task.get("completed_at")
        or task.get("updated_at")
        or task.get("created_at")
    )
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return None


def prune_grouped_vuln_tasks(
    tasks: dict[str, dict[str, Any]],
    *,
    ttl_seconds: int,
    max_terminal_tasks: int = 0,
    now: datetime | None = None,
) -> list[str]:
    if ttl_seconds <= 0:
        return []

    now_seconds = (now or datetime.now(timezone.utc)).timestamp()
    removed: list[str] = []
    for task_id, task in list(tasks.items()):
        status = str(task.get("status") or "").lower()
        if status not in TERMINAL_GROUPED_VULN_TASK_STATUSES:
            continue

        timestamp = _task_timestamp_seconds(task)
        if timestamp is None or now_seconds - timestamp < ttl_seconds:
            continue

        tasks.pop(task_id, None)
        removed.append(task_id)

    if max_terminal_tasks > 0:
        terminal_tasks = []
        for task_id, task in tasks.items():
            status = str(task.get("status") or "").lower()
            if status not in TERMINAL_GROUPED_VULN_TASK_STATUSES:
                continue
            timestamp = _task_timestamp_seconds(task)
            if timestamp is not None:
                terminal_tasks.append((timestamp, task_id))

        overflow = len(terminal_tasks) - max_terminal_tasks
        for _timestamp, task_id in sorted(terminal_tasks)[: max(0, overflow)]:
            tasks.pop(task_id, None)
            removed.append(task_id)

    return removed
