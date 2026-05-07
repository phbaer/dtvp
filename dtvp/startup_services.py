import asyncio
import json
import os
import socket
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable, Coroutine, Iterable


@dataclass(frozen=True)
class KnowledgeStoreRuntimeDeps:
    initialize_knowledge_store: Callable[[], None]
    get_knowledge_store_status: Callable[[], dict[str, Any]]
    get_active_project_uuids: Callable[[], Iterable[str]]
    synchronize_knowledge_store_projects: Callable[..., None]
    purge_expired_knowledge_store: Callable[[], int]
    get_knowledge_store_retention_days: Callable[[], int]
    get_knowledge_store_maintenance_interval_seconds: Callable[[], int]
    run_knowledge_store_write_loop: Callable[[], Awaitable[None]]


@dataclass(frozen=True)
class StartupInstanceGuardDeps:
    acquire_instance_guard: Callable[[], Any]
    release_instance_guard: Callable[[Any], None]


@dataclass(frozen=True)
class StartupServiceDeps:
    logger: Any
    version: str
    build_commit: str
    analysis_queue: Any
    tmrescore_project_cache: dict[str, dict[str, Any]]
    load_tmrescore_project_cache: Callable[[], dict[str, dict[str, Any]]]
    instance_guard: StartupInstanceGuardDeps
    knowledge_store_runtime: KnowledgeStoreRuntimeDeps
    initialize_cache_manager: Callable[[], Awaitable[None]]
    run_background_sync_loop: Callable[[], Awaitable[None]]
    run_analysis_queue_worker: Callable[[], Awaitable[None]]
    run_analysis_queue_cleanup_loop: Callable[[], Awaitable[None]]
    create_task: Callable[..., asyncio.Task[Any]]
    sleep: Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class StartupRuntimeTasks:
    instance_guard_token: Any
    release_instance_guard: Callable[[Any], None]
    sync_task: asyncio.Task[Any]
    knowledge_store_write_task: asyncio.Task[Any]
    queue_task: asyncio.Task[Any]
    queue_cleanup_task: asyncio.Task[Any]
    knowledge_store_task: asyncio.Task[Any]


def _is_truthy_env_value(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_single_instance_enforcement_enabled() -> bool:
    return _is_truthy_env_value(os.getenv("DTVP_ENFORCE_SINGLE_INSTANCE", "true"))


def get_single_instance_lock_path() -> str:
    return os.getenv("DTVP_SINGLE_INSTANCE_LOCK_PATH", "data/dtvp.instance.lock")


def _get_env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        return max(0, int(raw_value))
    except (TypeError, ValueError):
        return default


def get_knowledge_store_orphan_warning_threshold() -> int:
    return _get_env_int("DTVP_KNOWLEDGE_STORE_ORPHAN_WARNING_THRESHOLD", 100)


def get_knowledge_store_maintenance_warning_age_seconds() -> int:
    return _get_env_int(
        "DTVP_KNOWLEDGE_STORE_MAINTENANCE_WARNING_AGE_SECONDS",
        7200,
    )


def acquire_single_instance_guard(logger: Any) -> Any:
    if not get_single_instance_enforcement_enabled():
        logger.info("Single-instance enforcement disabled")
        return None

    lock_path = get_single_instance_lock_path()
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    metadata = {
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "started_at": datetime.now(UTC).isoformat(),
    }

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        file_descriptor = os.open(lock_path, flags, 0o644)
    except FileExistsError as exc:
        raise RuntimeError(
            f"Another DTVP instance may already be using {lock_path}. "
            "If this is a stale lock, remove it or set DTVP_ENFORCE_SINGLE_INSTANCE=false."
        ) from exc

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle)
            handle.write("\n")
    except Exception:
        try:
            os.remove(lock_path)
        except OSError:
            pass
        raise

    logger.info("Acquired single-instance lock at %s", lock_path)
    return lock_path


def release_single_instance_guard(lock_token: Any) -> None:
    if not lock_token:
        return

    try:
        os.remove(str(lock_token))
    except FileNotFoundError:
        return


def create_tracked_task(
    background_tasks: set[asyncio.Task[Any]],
    create_task: Callable[..., asyncio.Task[Any]],
    coro: Coroutine[Any, Any, Any],
) -> asyncio.Task[Any]:
    task = create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return task


def _warn_on_knowledge_store_maintenance_health(
    deps: StartupServiceDeps,
    *,
    check_staleness: bool,
    check_orphans: bool,
) -> None:
    status = deps.knowledge_store_runtime.get_knowledge_store_status()
    if check_orphans:
        orphaned_assessment_records = int(
            status.get("orphaned_assessment_records") or 0
        )
        orphan_warning_threshold = get_knowledge_store_orphan_warning_threshold()
        if (
            orphan_warning_threshold > 0
            and orphaned_assessment_records >= orphan_warning_threshold
        ):
            deps.logger.warning(
                "Knowledge-store has %s orphaned assessment record(s)",
                orphaned_assessment_records,
            )

    if not check_staleness:
        return

    maintenance_warning_age_seconds = (
        get_knowledge_store_maintenance_warning_age_seconds()
    )
    last_maintenance_at = status.get("last_maintenance_at")
    if (
        maintenance_warning_age_seconds <= 0
        or not isinstance(last_maintenance_at, str)
        or not last_maintenance_at
    ):
        return

    try:
        maintenance_time = datetime.fromisoformat(last_maintenance_at)
    except ValueError:
        return
    if maintenance_time.tzinfo is None:
        maintenance_time = maintenance_time.replace(tzinfo=UTC)
    maintenance_age_seconds = max(
        0.0,
        (datetime.now(UTC) - maintenance_time).total_seconds(),
    )
    if maintenance_age_seconds >= maintenance_warning_age_seconds:
        deps.logger.warning(
            "Knowledge-store maintenance last ran %.1f second(s) ago",
            maintenance_age_seconds,
        )


async def start_application_runtime(
    deps: StartupServiceDeps,
) -> StartupRuntimeTasks:
    instance_guard_token = deps.instance_guard.acquire_instance_guard()
    try:
        if hasattr(deps.analysis_queue, "load_persisted_state"):
            deps.analysis_queue.load_persisted_state()
        deps.analysis_queue.reset_runtime_state()
        deps.logger.info(
            "Starting DTVP version %s (build %s)",
            deps.version,
            deps.build_commit,
        )
        deps.knowledge_store_runtime.initialize_knowledge_store()
        deps.tmrescore_project_cache.clear()
        deps.tmrescore_project_cache.update(deps.load_tmrescore_project_cache())
        await deps.initialize_cache_manager()
        deps.analysis_queue.prune_finished()
        perform_knowledge_store_maintenance(deps)
        return StartupRuntimeTasks(
            instance_guard_token=instance_guard_token,
            release_instance_guard=deps.instance_guard.release_instance_guard,
            sync_task=deps.create_task(deps.run_background_sync_loop()),
            knowledge_store_write_task=deps.create_task(
                deps.knowledge_store_runtime.run_knowledge_store_write_loop()
            ),
            queue_task=deps.create_task(deps.run_analysis_queue_worker()),
            queue_cleanup_task=deps.create_task(deps.run_analysis_queue_cleanup_loop()),
            knowledge_store_task=deps.create_task(
                run_knowledge_store_maintenance_loop(deps)
            ),
        )
    except Exception:
        deps.instance_guard.release_instance_guard(instance_guard_token)
        raise


def perform_knowledge_store_maintenance(deps: StartupServiceDeps) -> int:
    _warn_on_knowledge_store_maintenance_health(
        deps,
        check_staleness=True,
        check_orphans=False,
    )
    deps.knowledge_store_runtime.synchronize_knowledge_store_projects(
        deps.knowledge_store_runtime.get_active_project_uuids(),
        grace_period_days=deps.knowledge_store_runtime.get_knowledge_store_retention_days(),
    )
    purged_records = deps.knowledge_store_runtime.purge_expired_knowledge_store()
    if purged_records:
        deps.logger.info(
            "Purged %s expired knowledge-store assessments", purged_records
        )
    _warn_on_knowledge_store_maintenance_health(
        deps,
        check_staleness=False,
        check_orphans=True,
    )
    return purged_records


async def run_knowledge_store_maintenance_loop(deps: StartupServiceDeps) -> None:
    interval_seconds = (
        deps.knowledge_store_runtime.get_knowledge_store_maintenance_interval_seconds()
    )
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
    try:
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
    finally:
        runtime_tasks.release_instance_guard(runtime_tasks.instance_guard_token)
