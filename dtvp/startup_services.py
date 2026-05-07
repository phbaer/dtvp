import asyncio
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Coroutine, Iterable


@dataclass(frozen=True)
class StartupServiceDeps:
    logger: Any
    version: str
    build_commit: str
    analysis_queue: Any
    tmrescore_project_cache: dict[str, dict[str, Any]]
    load_tmrescore_project_cache: Callable[[], dict[str, dict[str, Any]]]
    initialize_knowledge_store: Callable[[], None]
    get_active_project_uuids: Callable[[], Iterable[str]]
    synchronize_knowledge_store_projects: Callable[..., None]
    purge_expired_knowledge_store: Callable[[], int]
    get_knowledge_store_retention_days: Callable[[], int]
    get_knowledge_store_maintenance_interval_seconds: Callable[[], int]
    initialize_cache_manager: Callable[[], Awaitable[None]]
    run_background_sync_loop: Callable[[], Awaitable[None]]
    run_knowledge_store_write_loop: Callable[[], Awaitable[None]]
    run_analysis_queue_worker: Callable[[], Awaitable[None]]
    run_analysis_queue_cleanup_loop: Callable[[], Awaitable[None]]
    create_task: Callable[..., asyncio.Task[Any]]
    sleep: Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class StartupRuntimeTasks:
    sync_task: asyncio.Task[Any]
    knowledge_store_write_task: asyncio.Task[Any]
    queue_task: asyncio.Task[Any]
    queue_cleanup_task: asyncio.Task[Any]
    knowledge_store_task: asyncio.Task[Any]


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
    if hasattr(deps.analysis_queue, "load_persisted_state"):
        deps.analysis_queue.load_persisted_state()
    deps.analysis_queue.reset_runtime_state()
    deps.logger.info(
        "Starting DTVP version %s (build %s)",
        deps.version,
        deps.build_commit,
    )
    deps.initialize_knowledge_store()
    deps.tmrescore_project_cache.clear()
    deps.tmrescore_project_cache.update(deps.load_tmrescore_project_cache())
    await deps.initialize_cache_manager()
    deps.analysis_queue.prune_finished()
    perform_knowledge_store_maintenance(deps)
    return StartupRuntimeTasks(
        sync_task=deps.create_task(deps.run_background_sync_loop()),
        knowledge_store_write_task=deps.create_task(
            deps.run_knowledge_store_write_loop()
        ),
        queue_task=deps.create_task(deps.run_analysis_queue_worker()),
        queue_cleanup_task=deps.create_task(deps.run_analysis_queue_cleanup_loop()),
        knowledge_store_task=deps.create_task(
            run_knowledge_store_maintenance_loop(deps)
        ),
    )


def perform_knowledge_store_maintenance(deps: StartupServiceDeps) -> int:
    deps.synchronize_knowledge_store_projects(
        deps.get_active_project_uuids(),
        grace_period_days=deps.get_knowledge_store_retention_days(),
    )
    purged_records = deps.purge_expired_knowledge_store()
    if purged_records:
        deps.logger.info(
            "Purged %s expired knowledge-store assessments", purged_records
        )
    return purged_records


async def run_knowledge_store_maintenance_loop(deps: StartupServiceDeps) -> None:
    interval_seconds = deps.get_knowledge_store_maintenance_interval_seconds()
    while True:
        try:
            perform_knowledge_store_maintenance(deps)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            deps.logger.warning("Knowledge-store maintenance failed: %s", exc)
        await deps.sleep(interval_seconds)


async def stop_application_runtime(
    runtime_tasks: StartupRuntimeTasks,
    analysis_queue: Any,
    background_tasks: set[asyncio.Task[Any]],
) -> None:
    analysis_queue.shutdown()
    runtime_tasks.knowledge_store_task.cancel()
    runtime_tasks.knowledge_store_write_task.cancel()
    runtime_tasks.queue_task.cancel()
    runtime_tasks.queue_cleanup_task.cancel()
    runtime_tasks.sync_task.cancel()
    for task in tuple(background_tasks):
        task.cancel()

    with suppress(asyncio.CancelledError):
        await runtime_tasks.knowledge_store_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.knowledge_store_write_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_cleanup_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.sync_task

    for task in tuple(background_tasks):
        with suppress(asyncio.CancelledError):
            await task
