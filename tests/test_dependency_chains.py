import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from main import app, get_user_client
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def mock_dt_client():
    # We now override get_user_client instead of get_client
    # because endpoints use get_user_client
    pass


@pytest.fixture
def mock_bom_analysis_cache():
    with patch("main.BOMAnalysisCache") as mock:
        yield mock


def test_get_dependency_chains_success(mock_bom_analysis_cache):
    # Setup mock
    mock_client_instance = AsyncMock()

    # Mock dependency injection for get_user_client
    # It must yield the client
    async def mock_get_user_client():
        yield mock_client_instance

    app.dependency_overrides[get_user_client] = mock_get_user_client
    app.dependency_overrides["get_current_user"] = lambda: "test_user"

    # Mock BOM response
    mock_client_instance.get_bom.return_value = {
        "components": [{"uuid": "comp1", "name": "comp1"}]
    }

    # Mock Cache behavior
    mock_processor = MagicMock()
    mock_processor.get_target_ref.return_value = "ref1"
    mock_processor.comp_map = {"ref1": {"name": "comp1"}}
    mock_processor.get_dependency_paths.return_value = ["Root -> B -> comp1"]
    mock_bom_analysis_cache.return_value = mock_processor

    response = client.get("/api/project/proj1/component/comp1/dependency-chains")

    assert response.status_code == 200
    data = response.json()
    assert data == ["Root -> B -> comp1"]

    # Verify calls
    mock_client_instance.get_bom.assert_called_with("proj1")
    mock_processor.get_dependency_paths.assert_called_with("comp1", component_name="")

    # Cleanup
    app.dependency_overrides = {}


def test_get_dependency_chains_no_bom():
    mock_client_instance = AsyncMock()

    async def mock_get_user_client():
        yield mock_client_instance

    app.dependency_overrides[get_user_client] = mock_get_user_client
    app.dependency_overrides["get_current_user"] = lambda: "test_user"

    mock_client_instance.get_bom.return_value = None

    response = client.get("/api/project/proj1/component/comp1/dependency-chains")

    assert response.status_code == 200
    data = response.json()
    assert data == []
