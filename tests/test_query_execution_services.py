import asyncio
import threading

import pytest

from dtvp.query_execution_services import (
    BoundedQueryExecutor,
    BoundedWorkExecutor,
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


@pytest.mark.asyncio
async def test_cancelled_query_keeps_capacity_until_worker_finishes():
    executor = BoundedQueryExecutor(
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 0,
    )
    started = threading.Event()
    release = threading.Event()

    def blocking_query():
        started.set()
        assert release.wait(timeout=1)

    request = asyncio.create_task(executor.run(blocking_query, key="cancelled"))
    await _wait_until(started.is_set)
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request

    assert executor.stats()["outstanding"] == 1
    with pytest.raises(QueryCapacityError):
        await executor.run(lambda: None, key="overflow")

    release.set()
    await _wait_until(lambda: executor.stats()["outstanding"] == 0)
    assert executor.stats()["rejected_total"] == 1
    executor.shutdown()


@pytest.mark.asyncio
async def test_cancelled_queued_query_releases_capacity_after_worker_runs():
    executor = BoundedQueryExecutor(
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 1,
    )
    started = threading.Event()
    release = threading.Event()

    def blocking_query():
        started.set()
        assert release.wait(timeout=1)

    first = asyncio.create_task(executor.run(blocking_query, key="first"))
    await _wait_until(started.is_set)
    queued = asyncio.create_task(executor.run(lambda: "queued", key="queued"))
    await _wait_until(lambda: executor.stats()["queued"] == 1)

    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued
    assert executor.stats()["outstanding"] == 2

    release.set()
    await first
    await _wait_until(lambda: executor.stats()["outstanding"] == 0)
    assert await executor.run(lambda: "next", key="next") == "next"
    executor.shutdown()


@pytest.mark.asyncio
async def test_bounded_work_executor_applies_async_backpressure():
    executor = BoundedWorkExecutor(
        name="test-work",
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 1,
    )
    started = threading.Event()
    release = threading.Event()

    def first_job():
        started.set()
        assert release.wait(timeout=1)
        return "first"

    first = asyncio.create_task(executor.run(first_job))
    await _wait_until(started.is_set)
    second = asyncio.create_task(executor.run(lambda: "second"))
    third = asyncio.create_task(executor.run(lambda: "third"))
    await _wait_until(lambda: executor.stats()["waiting"] == 1)

    stats = executor.stats()
    assert stats["outstanding"] == 2
    assert stats["active"] == 1
    assert stats["queued"] == 1

    release.set()
    assert await asyncio.gather(first, second, third) == [
        "first",
        "second",
        "third",
    ]
    stats = executor.stats()
    assert stats["completed_total"] == 3
    assert stats["max_outstanding"] == 2
    executor.shutdown()


@pytest.mark.asyncio
async def test_cancelled_queued_work_releases_semaphore_after_worker_runs():
    executor = BoundedWorkExecutor(
        name="test-work-cancel",
        workers_provider=lambda: 1,
        max_pending_provider=lambda: 1,
    )
    started = threading.Event()
    release = threading.Event()

    def blocking_job():
        started.set()
        assert release.wait(timeout=1)

    first = asyncio.create_task(executor.run(blocking_job))
    await _wait_until(started.is_set)
    queued = asyncio.create_task(executor.run(lambda: "queued"))
    await _wait_until(lambda: executor.stats()["queued"] == 1)

    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued
    assert executor.stats()["outstanding"] == 2

    release.set()
    await first
    await _wait_until(lambda: executor.stats()["outstanding"] == 0)
    assert await executor.run(lambda: "next") == "next"
    executor.shutdown()
