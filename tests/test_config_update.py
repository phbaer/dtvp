import pytest
from main import app, get_current_user, get_current_user_roles
from unittest.mock import patch, mock_open


# Mock auth
@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    # Default roles to ADMIN so mapping updates succeed
    app.dependency_overrides[get_current_user_roles] = lambda: ["ADMIN"]
    yield
    app.dependency_overrides = {}


def test_update_team_mapping(client):
    new_mapping = {"comp1": "team1", "comp2": "team2"}

    with patch(
        "main.get_team_mapping_path", return_value="/tmp/test_mapping_update.json"
    ):
        with patch("builtins.open", mock_open()) as mocked_file:
            response = client.put("/api/settings/mapping", json=new_mapping)

            assert response.status_code == 200
            assert response.json()["status"] == "success"

            # Verify file write
            mocked_file.assert_called_with("/tmp/test_mapping_update.json", "w")
            handle = mocked_file()
            # We can't easily check full json dump content with mock_open, but we can verify write was called
            assert handle.write.called


def test_update_team_mapping_failure(client):
    new_mapping = {"comp": "team"}

    with patch(
        "main.get_team_mapping_path", return_value="/tmp/test_mapping_update.json"
    ):
        with patch("builtins.open", side_effect=Exception("Write error")):
            response = client.put("/api/settings/mapping", json=new_mapping)

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Write error" in data["message"]


def test_update_team_mapping_forbidden_non_admin(client):
    # Override roles to just ANALYST/REVIEWER (no ADMIN)
    app.dependency_overrides[get_current_user_roles] = lambda: ["REVIEWER"]
    new_mapping = {"comp": "team"}

    response = client.put("/api/settings/mapping", json=new_mapping)
    assert response.status_code == 403
    assert "Only administrators" in response.json()["detail"]
