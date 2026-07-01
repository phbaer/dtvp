import asyncio
import os
import platform
import socket
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Coroutine, Mapping


def _configured(value: str | None) -> str:
    return "configured" if value else "unset"


def _safe_read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as file_handle:
            return file_handle.read()
    except OSError:
        return ""


def detect_container_environment() -> str:
    markers: list[str] = []
    if os.path.exists("/.dockerenv"):
        markers.append("docker")
    if os.path.exists("/run/.containerenv"):
        markers.append("containerenv")
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        markers.append("kubernetes")
    if os.getenv("container"):
        markers.append(f"container={os.getenv('container')}")

    cgroup = _safe_read_text("/proc/1/cgroup").lower()
    for name in ("docker", "containerd", "kubepods", "podman"):
        if name in cgroup:
            markers.append(name)

    return ", ".join(sorted(set(markers))) if markers else "not detected"


def build_startup_runtime_details() -> dict[str, dict[str, Any]]:
    return {
        "runtime": {
            "python": platform.python_version(),
            "executable": os.path.basename(sys.executable),
            "platform": platform.platform(),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "cwd": os.getcwd(),
            "container": detect_container_environment(),
        },
        "environment": {
            "context_path": os.getenv("DTVP_CONTEXT_PATH", "/"),
            "frontend_url": os.getenv("DTVP_FRONTEND_URL", "http://localhost:8000"),
            "cors_origins": _configured(os.getenv("DTVP_CORS_ORIGINS")),
            "dependency_track": _configured(
                os.getenv("DTVP_DT_API_URL")
                or os.getenv("DEPENDENCY_TRACK_URL")
            ),
            "oidc": _configured(
                os.getenv("DTVP_OIDC_AUTHORITY")
                or os.getenv("ISSUER_URL")
            ),
            "dev_disable_auth": os.getenv("DTVP_DEV_DISABLE_AUTH", "false"),
            "tmrescore": _configured(os.getenv("DTVP_TMRESCORE_URL")),
            "code_analysis": _configured(os.getenv("DTVP_CODE_ANALYSIS_URL")),
            "auto_code_analysis": os.getenv(
                "DTVP_AUTO_CODE_ANALYSIS_ENABLED",
                "false",
            ),
        },
    }


def format_startup_details(details: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{key}={value}"
        for key, value in details.items()
    )


def write_startup_console_line(line: str) -> None:
    print(line, flush=True)


def build_startup_console_lines(
    *,
    version: str,
    build_commit: str,
    details: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    lines = [f"DTVP startup: name=DTVP, version={version}, build={build_commit}"]
    runtime_details = details.get("runtime", {})
    environment_details = details.get("environment", {})
    if runtime_details:
        lines.append(f"DTVP runtime: {format_startup_details(runtime_details)}")
    if environment_details:
        lines.append(f"DTVP environment: {format_startup_details(environment_details)}")
    return lines


@dataclass(frozen=True)
class StartupServiceDeps:
    logger: Any
    version: str
    build_commit: str
    analysis_queue: Any
    tmrescore_project_cache: dict[str, dict[str, Any]]
    load_tmrescore_project_cache: Callable[[], dict[str, dict[str, Any]]]
    runtime_details_provider: Callable[[], Mapping[str, Mapping[str, Any]]]
    initialize_cache_manager: Callable[[], Awaitable[None]]
    run_background_sync_loop: Callable[[], Awaitable[None]]
    run_auto_analysis_sweep_loop: Callable[[], Awaitable[None]]
    run_analysis_queue_worker: Callable[[], Awaitable[None]]
    run_analysis_queue_cleanup_loop: Callable[[], Awaitable[None]]
    create_task: Callable[..., asyncio.Task[Any]]
    console_writer: Callable[[str], None] = write_startup_console_line


@dataclass(frozen=True)
class StartupRuntimeTasks:
    sync_task: asyncio.Task[Any]
    auto_analysis_task: asyncio.Task[Any]
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
    details = deps.runtime_details_provider()
    for line in build_startup_console_lines(
        version=deps.version,
        build_commit=deps.build_commit,
        details=details,
    ):
        deps.console_writer(line)

    deps.logger.info(
        "Starting DTVP version %s (build %s)",
        deps.version,
        deps.build_commit,
    )
    runtime_details = details.get("runtime", {})
    environment_details = details.get("environment", {})
    if runtime_details:
        deps.logger.info("DTVP runtime: %s", format_startup_details(runtime_details))
    if environment_details:
        deps.logger.info(
            "DTVP environment: %s",
            format_startup_details(environment_details),
        )
    deps.tmrescore_project_cache.clear()
    deps.tmrescore_project_cache.update(deps.load_tmrescore_project_cache())
    await deps.initialize_cache_manager()
    return StartupRuntimeTasks(
        sync_task=deps.create_task(deps.run_background_sync_loop()),
        auto_analysis_task=deps.create_task(deps.run_auto_analysis_sweep_loop()),
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
    runtime_tasks.auto_analysis_task.cancel()
    for task in tuple(background_tasks):
        task.cancel()

    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.queue_cleanup_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.sync_task
    with suppress(asyncio.CancelledError):
        await runtime_tasks.auto_analysis_task

    for task in tuple(background_tasks):
        with suppress(asyncio.CancelledError):
            await task
