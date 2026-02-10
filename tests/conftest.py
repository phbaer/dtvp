import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock
from main import app
from dt_client import DTClient


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
    from main import get_user_client, get_current_user_token_payload

    async def override_get_user_client(token_payload: dict = None):
        yield mock_dt_client

    def override_get_token_payload():
        return {"sub": "testuser", "dt_url": "http://mock", "dt_key": "mock"}

    app.dependency_overrides[get_user_client] = override_get_user_client
    app.dependency_overrides[get_current_user_token_payload] = (
        override_get_token_payload
    )

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
