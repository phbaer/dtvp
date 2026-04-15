import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from main import app, get_client
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def mock_dt_client():
    with patch("main.get_client") as mock:
        yield mock


@pytest.fixture
def mock_bom_analysis_cache():
    with patch("main.BOMAnalysisCache") as mock:
        yield mock


def test_get_dependency_chains_success(mock_dt_client, mock_bom_analysis_cache):
    # Setup mock
    mock_client_instance = AsyncMock()
    # Mock dependency injection
    app.dependency_overrides[get_client] = lambda: mock_client_instance
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
    mock_processor.get_dependency_paths.assert_called_with(
        "comp1",
        component_name="",
        max_paths=100,
    )


def test_get_dependency_chains_no_bom(mock_dt_client):
    mock_client_instance = AsyncMock()
    app.dependency_overrides[get_client] = lambda: mock_client_instance
    app.dependency_overrides["get_current_user"] = lambda: "test_user"

    mock_client_instance.get_bom.return_value = None

    response = client.get("/api/project/proj1/component/comp1/dependency-chains")

    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_get_dependency_chains_limit_query(mock_dt_client, mock_bom_analysis_cache):
    mock_client_instance = AsyncMock()
    app.dependency_overrides[get_client] = lambda: mock_client_instance
    app.dependency_overrides["get_current_user"] = lambda: "test_user"

    mock_client_instance.get_bom.return_value = {
        "components": [{"uuid": "comp1", "name": "comp1"}]
    }

    mock_processor = MagicMock()
    mock_processor.get_target_ref.return_value = "ref1"
    mock_processor.comp_map = {"ref1": {"name": "comp1"}}
    mock_processor.get_dependency_paths.return_value = ["Root -> B -> comp1"]
    mock_bom_analysis_cache.return_value = mock_processor

    response = client.get("/api/project/proj1/component/comp1/dependency-chains?limit=10")

    assert response.status_code == 200
    data = response.json()
    assert data == ["Root -> B -> comp1"]
    mock_processor.get_dependency_paths.assert_called_with(
        "comp1",
        component_name="",
        max_paths=10,
    )
