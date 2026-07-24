import asyncio

import pytest

from dtvp.startup_services import (
    StartupServiceDeps,
    start_application_runtime,
    stop_application_runtime,
)


class FakeLogger:
    def __init__(self):
        self.messages = []

    def info(self, message, *args):
        self.messages.append(message % args if args else message)


class FakeAnalysisQueue:
    def __init__(self):
        self.reset = False
        self.stopped = False

    def reset_runtime_state(self):
        self.reset = True

    def shutdown(self):
        self.stopped = True


async def _idle_loop():
    await asyncio.sleep(3600)


@pytest.mark.asyncio
async def test_start_application_runtime_logs_runtime_and_environment_details():
    logger = FakeLogger()
    analysis_queue = FakeAnalysisQueue()
    cache = {"old": {"session": "stale"}}
    console_lines = []

    deps = StartupServiceDeps(
        logger=logger,
        version="1.2.3",
        build_commit="abc123",
        analysis_queue=analysis_queue,
        tmrescore_project_cache=cache,
        load_tmrescore_project_cache=lambda: {"Project": {"session": "fresh"}},
        runtime_details_provider=lambda: {
            "runtime": {
                "python": "3.14.0",
                "hostname": "dtvp-test",
                "container": "docker",
            },
            "environment": {
                "context_path": "/dtvp",
                "vulnerability_backend": "configured",
            },
        },
        initialize_cache_manager=lambda: asyncio.sleep(0),
        run_background_sync_loop=_idle_loop,
        run_auto_analysis_sweep_loop=_idle_loop,
        run_analysis_queue_worker=_idle_loop,
        run_analysis_queue_cleanup_loop=_idle_loop,
        create_task=asyncio.create_task,
        console_writer=console_lines.append,
    )

    runtime_tasks = await start_application_runtime(deps)
    try:
        assert console_lines[:3] == [
            "DTVP startup: name=DTVP, version=1.2.3, build=abc123",
            "DTVP runtime: python=3.14.0, hostname=dtvp-test, container=docker",
            "DTVP environment: context_path=/dtvp, vulnerability_backend=configured",
        ]
        assert any(
            line.startswith("DTVP startup step completed: tmrescore cache loaded")
            for line in console_lines
        )
        assert any(
            line.startswith(
                "DTVP startup step completed: vulnerability backend cache initialized"
            )
            for line in console_lines
        )
        assert any(
            line.startswith("DTVP startup ready: runtime tasks starting")
            for line in console_lines
        )
        joined_logs = "\n".join(logger.messages)
        assert "Starting DTVP version 1.2.3 (build abc123)" in joined_logs
        assert "DTVP runtime: python=3.14.0, hostname=dtvp-test, container=docker" in joined_logs
        assert (
            "DTVP environment: context_path=/dtvp, vulnerability_backend=configured"
            in joined_logs
        )
        assert "DTVP startup step completed: tmrescore cache loaded" in joined_logs
        assert (
            "DTVP startup step completed: vulnerability backend cache initialized"
            in joined_logs
        )
        assert "DTVP startup ready: runtime tasks starting" in joined_logs
        assert analysis_queue.reset is True
        assert cache == {"Project": {"session": "fresh"}}
    finally:
        await stop_application_runtime(runtime_tasks, analysis_queue, set())

    assert analysis_queue.stopped is True
