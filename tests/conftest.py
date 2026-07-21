import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Authentication settings are instantiated while the application modules are
# imported, so establish a complete, non-production test configuration first.
os.environ["DTVP_ENVIRONMENT"] = "test"
os.environ["DTVP_OIDC_AUTHORITY"] = "https://auth.example.com"
os.environ["DTVP_OIDC_CLIENT_ID"] = "test-client"
os.environ["DTVP_OIDC_CLIENT_SECRET"] = "test-client-secret"
os.environ["DTVP_OIDC_REDIRECT_URI"] = "http://localhost:8000/auth/callback"
os.environ["DTVP_FRONTEND_URL"] = "http://localhost:8000"
os.environ["DTVP_SESSION_SECRET_KEY"] = (
    "test-only-session-secret-that-is-long-enough-1234567890"
)
os.environ["DTVP_DT_IMPORT_API_KEY"] = "test-import-key"

from dtvp import dt_cache, main
from dtvp.dt_client import DTClient


@pytest.fixture(autouse=True)
def reset_cache_manager(tmp_path, monkeypatch):
    cache_dir = tmp_path / "dt_cache"
    analysis_results_path = tmp_path / "code_analysis_results.json"
    analysis_queue_path = tmp_path / "analysis_queue.sqlite"
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(cache_dir))
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", str(analysis_results_path))
    monkeypatch.setenv("DTVP_ANALYSIS_QUEUE_STATE_PATH", str(analysis_queue_path))
    dt_cache.cache_manager.reset(str(cache_dir))
    main.code_analysis_result_store.reset()
    yield
    main.code_analysis_result_store.reset()


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
