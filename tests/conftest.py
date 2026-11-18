import os
import tempfile
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Importing dtvp opens the local database at the configured path and imports
# an existing JSON cache into it. Point it at a throwaway directory first so
# a test run never touches the developer's real data directory.
_IMPORT_TIME_DATA = tempfile.TemporaryDirectory(prefix="dtvp-test-import-")
os.environ["DTVP_DT_CACHE_PATH"] = os.path.join(_IMPORT_TIME_DATA.name, "dt_cache")

from dtvp import dt_cache, main  # noqa: E402
from dtvp.access_token_services import access_token_store  # noqa: E402
from dtvp.dt_client import DTClient  # noqa: E402


@pytest.fixture(autouse=True)
def reset_cache_manager(tmp_path, monkeypatch):
    monkeypatch.setenv("DTVP_SSVC_ENRICHMENT_ENABLED", "false")
    cache_dir = tmp_path / "dt_cache"
    analysis_results_path = tmp_path / "code_analysis_results.json"
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(cache_dir))
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", str(analysis_results_path))
    monkeypatch.setenv(
        "DTVP_ACCESS_TOKENS_PATH", str(tmp_path / "access_tokens.sqlite")
    )
    monkeypatch.delenv("DTVP_ACCESS_TOKENS_ENABLED", raising=False)
    access_token_store.reset()
    # A project load left over from the previous test must not be joined by
    # this one: it read that test's source and may still be writing.
    main.tasks.clear()
    dt_cache.cache_manager.reset(str(cache_dir))
    main.code_analysis_result_store.reset()
    yield
    _wait_for_project_loads()
    main.code_analysis_result_store.reset()


def _wait_for_project_loads(timeout: float = 5.0) -> None:
    """Let project loads started by a test finish before the next test gets a
    new store. On a slow machine they otherwise write into it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        unfinished = [
            task
            for task in list(main.tasks.values())
            if isinstance(task, dict)
            and task.get("status") not in ("completed", "failed")
        ]
        if not unfinished:
            return
        time.sleep(0.02)


# Mock Dependency Track Client
class MockDTClient:
    async def get_projects(self, name: str = None):
        return []

    async def get_vulnerabilities(self, project_uuid: str):
        return []

    async def update_analysis(self, **kwargs):
        pass


@pytest.fixture
def mock_dt_client():
    client = AsyncMock(spec=DTClient)
    client.get_projects.return_value = []
    client.get_vulnerabilities.return_value = []
    client.update_analysis.return_value = None
    return client


@pytest.fixture
def client(mock_dt_client):
    # Override dependencies
    main.app.dependency_overrides[main.get_client] = lambda: mock_dt_client

    # Disable background sync loop during tests to prevent race conditions
    async def _noop_sync():
        pass

    with (
        patch.object(dt_cache.cache_manager, "background_sync_loop", _noop_sync),
        patch.object(dt_cache.cache_manager, "initialize", _noop_sync),
    ):
        with TestClient(main.app) as test_client:
            yield test_client

    main.app.dependency_overrides.clear()
