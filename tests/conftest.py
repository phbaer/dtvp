import os

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch
from main import app, get_client, get_current_user
from dt_client import DTClient
import dt_cache


@pytest.fixture(autouse=True)
def reset_cache_manager(tmp_path, monkeypatch):
    cache_dir = tmp_path / "dt_cache"
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(cache_dir))
    dt_cache.cache_manager.reset(str(cache_dir))
    yield


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
    app.dependency_overrides[get_client] = lambda: mock_dt_client

    # Disable background sync loop during tests to prevent race conditions
    async def _noop_sync():
        pass

    with patch.object(dt_cache.cache_manager, "background_sync_loop", _noop_sync), \
         patch.object(dt_cache.cache_manager, "initialize", _noop_sync):
        with TestClient(app) as test_client:
            yield test_client

    app.dependency_overrides.clear()
