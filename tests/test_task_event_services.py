import asyncio

import pytest

from dtvp.task_event_services import TaskEventHub


@pytest.mark.asyncio
async def test_task_event_hub_wakes_all_waiters_on_one_update():
    hub = TaskEventHub()
    waiters = [
        asyncio.create_task(hub.wait("task-1", 0, timeout_seconds=1))
        for _ in range(3)
    ]
    await asyncio.sleep(0)

    assert hub.notify("task-1") == 1
    assert await asyncio.gather(*waiters) == [1, 1, 1]


def test_task_event_hub_serializes_payload_once_per_version():
    hub = TaskEventHub()
    builds = 0

    def build():
        nonlocal builds
        builds += 1
        return f"payload-{builds}"

    assert hub.serialized_payload("task-1", 0, build) == "payload-1"
    assert hub.serialized_payload("task-1", 0, build) == "payload-1"
    hub.notify("task-1")
    assert hub.serialized_payload("task-1", 1, build) == "payload-2"
    assert builds == 2
