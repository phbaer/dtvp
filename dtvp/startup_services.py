import asyncio
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Coroutine


@dataclass(frozen=True)
class StartupServiceDeps:
    logger: Any
    version: str
    build_commit: str
    analysis_queue: Any
    tmrescore_project_cache: dict[str, dict[str, Any]]
    load_tmrescore_project_cache: Callable[[], dict[str, dict[str, Any]]]
    initialize_cache_manager: Callable[[], Awaitable[None]]
    run_background_sync_loop: Callable[[], Awaitable[None]]
    run_analysis_queue_worker: Callable[[], Awaitable[None]]
    run_analysis_queue_cleanup_loop: Callable[[], Awaitable[None]]
    create_task: Callable[..., asyncio.Task[Any]]


@dataclass(frozen=True)
class StartupRuntimeTasks:
    sync_task: asyncio.Task[Any]
    queue_task: asyncio.Task[Any]
    queue_cleanup_task: asyncio.Task[Any]


def create_tracked_task(
    background_tasks: set[asyncio.Task[Any]],
    create_task: Callable[..., asyncio.Task[Any]],
    coro: Coroutine[Any, Any, Any],
) -> asyncio.Task[Any]:
    task = create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return task


async def start_application_runtime(
    deps: StartupServiceDeps,
) -> StartupRuntimeTasks:
    deps.analysis_queue.reset_runtime_state()
    deps.logger.info(
        "Starting DTVP version %s (build %s)",
        deps.version,
        deps.build_commit,
    )
    deps.tmrescore_project_cache.clear()
    deps.tmrescore_project_cache.update(deps.load_tmrescore_project_cache())
    await deps.initialize_cache_manager()
    return StartupRuntimeTasks(
        sync_task=deps.create_task(deps.run_background_sync_loop()),
        queue_task=deps.create_task(deps.run_analysis_queue_worker()),
        queue_cleanup_task=deps.create_task(deps.run_analysis_queue_cleanup_loop()),
    )


async def stop_application_runtime(
    runtime_tasks: StartupRuntimeTasks,
    analysis_queue: Any,
    background_tasks: set[asyncio.Task[Any]],
) -> None:
    analysis_queue.shutdown()
    runtime_tasks.queue_task.cancel()
    runtime_tasks.queue_cleanup_task.cancel()
    runtime_tasks.sync_task.cancel()
    for task in tuple(background_tasks):
        task.cancel()

    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_cleanup_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.sync_task

    for task in tuple(background_tasks):
        with suppress(asyncio.CancelledError):
            await task
