import asyncio
import threading

import pytest

from dtvp.query_execution_services import (
    BoundedQueryExecutor,
    QueryCapacityError,
    QuerySupersededError,
)


async def _wait_until(predicate, timeout: float = 1.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise TimeoutError("condition was not reached")
        await asyncio.sleep(0.005)


@pytest.mark.asyncio
async def test_bounded_query_executor_supersedes_queued_generations():
    executor = BoundedQueryExecutor(
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 2,
    )
    started = threading.Event()
    release = threading.Event()

    def blocking_query():
        started.set()
        assert release.wait(timeout=1)
        return "first"

    first = asyncio.create_task(
        executor.run(blocking_query, key=("user", "task"), generation=1)
    )
    await _wait_until(started.is_set)
    second = asyncio.create_task(
        executor.run(lambda: "second", key=("user", "task"), generation=2)
    )
    await asyncio.sleep(0)
    third = asyncio.create_task(
        executor.run(lambda: "third", key=("user", "task"), generation=3)
    )
    await asyncio.sleep(0)

    release.set()

    with pytest.raises(QuerySupersededError):
        await first
    with pytest.raises(QuerySupersededError):
        await second
    assert await third == "third"
    executor.shutdown()


@pytest.mark.asyncio
async def test_bounded_query_executor_rejects_requests_above_capacity():
    executor = BoundedQueryExecutor(
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 1,
    )
    release = threading.Event()

    def blocking_query():
        assert release.wait(timeout=1)
        return "done"

    first = asyncio.create_task(executor.run(blocking_query, key="first"))
    second = asyncio.create_task(executor.run(blocking_query, key="second"))
    await asyncio.sleep(0)

    with pytest.raises(QueryCapacityError):
        await executor.run(lambda: "overflow", key="third")

    release.set()
    assert await first == "done"
    assert await second == "done"
    executor.shutdown()
