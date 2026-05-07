import asyncio
import os
from unittest.mock import AsyncMock, Mock
from unittest.mock import patch

import pytest

from dtvp.startup_services import (
    KnowledgeStoreRuntimeDeps,
    StartupInstanceGuardDeps,
    StartupServiceDeps,
    acquire_single_instance_guard,
    get_single_instance_lock_path,
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
    acquire_instance_guard = Mock(return_value="lock-token")
    release_instance_guard = Mock()
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
        instance_guard=StartupInstanceGuardDeps(
            acquire_instance_guard=acquire_instance_guard,
            release_instance_guard=release_instance_guard,
        ),
        knowledge_store_runtime=KnowledgeStoreRuntimeDeps(
            initialize_knowledge_store=initialize_knowledge_store,
            get_active_project_uuids=lambda: ["project-1", "project-2"],
            synchronize_knowledge_store_projects=synchronize_projects,
            purge_expired_knowledge_store=purge_expired_knowledge_store,
            get_knowledge_store_retention_days=lambda: 14,
            get_knowledge_store_maintenance_interval_seconds=lambda: 3600,
            run_knowledge_store_write_loop=_block_forever,
        ),
        initialize_cache_manager=initialize_cache_manager,
        run_background_sync_loop=_block_forever,
        run_analysis_queue_worker=_block_forever,
        run_analysis_queue_cleanup_loop=_block_forever,
        create_task=asyncio.create_task,
        sleep=_block_forever,
    )

    runtime_tasks = await start_application_runtime(deps)

    acquire_instance_guard.assert_called_once_with()
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
    release_instance_guard.assert_called_once_with("lock-token")


@pytest.mark.asyncio
async def test_start_application_runtime_releases_instance_guard_on_failure():
    analysis_queue = DummyAnalysisQueue()
    acquire_instance_guard = Mock(return_value="lock-token")
    release_instance_guard = Mock()
    initialize_cache_manager = AsyncMock(side_effect=RuntimeError("boom"))

    deps = StartupServiceDeps(
        logger=Mock(),
        version="1.2.3",
        build_commit="abc123",
        analysis_queue=analysis_queue,
        tmrescore_project_cache={},
        load_tmrescore_project_cache=lambda: {},
        instance_guard=StartupInstanceGuardDeps(
            acquire_instance_guard=acquire_instance_guard,
            release_instance_guard=release_instance_guard,
        ),
        knowledge_store_runtime=KnowledgeStoreRuntimeDeps(
            initialize_knowledge_store=Mock(),
            get_active_project_uuids=lambda: [],
            synchronize_knowledge_store_projects=Mock(),
            purge_expired_knowledge_store=Mock(return_value=0),
            get_knowledge_store_retention_days=lambda: 14,
            get_knowledge_store_maintenance_interval_seconds=lambda: 3600,
            run_knowledge_store_write_loop=_block_forever,
        ),
        initialize_cache_manager=initialize_cache_manager,
        run_background_sync_loop=_block_forever,
        run_analysis_queue_worker=_block_forever,
        run_analysis_queue_cleanup_loop=_block_forever,
        create_task=asyncio.create_task,
        sleep=_block_forever,
    )

    with pytest.raises(RuntimeError, match="boom"):
        await start_application_runtime(deps)

    release_instance_guard.assert_called_once_with("lock-token")


def test_acquire_single_instance_guard_creates_and_releases_lock_file(tmp_path):
    lock_path = tmp_path / "dtvp.instance.lock"
    logger = Mock()

    with patch.dict(
        "os.environ",
        {
            "DTVP_SINGLE_INSTANCE_LOCK_PATH": str(lock_path),
            "DTVP_ENFORCE_SINGLE_INSTANCE": "true",
        },
        clear=False,
    ):
        token = acquire_single_instance_guard(logger)
        assert token == str(lock_path)
        assert get_single_instance_lock_path() == str(lock_path)
        assert lock_path.exists()

        with pytest.raises(RuntimeError, match="Another DTVP instance"):
            acquire_single_instance_guard(logger)

        os.remove(token)
