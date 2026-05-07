import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from dtvp.startup_services import (
    StartupServiceDeps,
    start_application_runtime,
    stop_application_runtime,
)


class DummyAnalysisQueue:
    def __init__(self) -> None:
        self.loaded = False
        self.reset = False
        self.pruned = False
        self.shutdown_called = False

    def load_persisted_state(self) -> None:
        self.loaded = True

    def reset_runtime_state(self) -> None:
        self.reset = True

    def prune_finished(self) -> None:
        self.pruned = True

    def shutdown(self) -> None:
        self.shutdown_called = True


async def _block_forever() -> None:
    await asyncio.Future()


@pytest.mark.asyncio
async def test_start_application_runtime_initializes_knowledge_store_and_runs_maintenance_once():
    analysis_queue = DummyAnalysisQueue()
    initialize_knowledge_store = Mock()
    synchronize_projects = Mock()
    purge_expired_knowledge_store = Mock(return_value=0)
    initialize_cache_manager = AsyncMock()
    logger = Mock()

    deps = StartupServiceDeps(
        logger=logger,
        version="1.2.3",
        build_commit="abc123",
        analysis_queue=analysis_queue,
        tmrescore_project_cache={},
        load_tmrescore_project_cache=lambda: {},
        initialize_knowledge_store=initialize_knowledge_store,
        get_active_project_uuids=lambda: ["project-1", "project-2"],
        synchronize_knowledge_store_projects=synchronize_projects,
        purge_expired_knowledge_store=purge_expired_knowledge_store,
        get_knowledge_store_retention_days=lambda: 14,
        get_knowledge_store_maintenance_interval_seconds=lambda: 3600,
        initialize_cache_manager=initialize_cache_manager,
        run_background_sync_loop=_block_forever,
        run_knowledge_store_write_loop=_block_forever,
        run_analysis_queue_worker=_block_forever,
        run_analysis_queue_cleanup_loop=_block_forever,
        create_task=asyncio.create_task,
        sleep=_block_forever,
    )

    runtime_tasks = await start_application_runtime(deps)

    initialize_knowledge_store.assert_called_once_with()
    initialize_cache_manager.assert_awaited_once_with()
    synchronize_projects.assert_called_once_with(
        ["project-1", "project-2"],
        grace_period_days=14,
    )
    purge_expired_knowledge_store.assert_called_once_with()
    assert analysis_queue.loaded is True
    assert analysis_queue.reset is True
    assert analysis_queue.pruned is True

    await stop_application_runtime(runtime_tasks, analysis_queue, set())
    assert analysis_queue.shutdown_called is True
