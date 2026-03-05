import pytest
from fastapi.testclient import TestClient
from main import app, get_current_user, get_user_role
from unittest.mock import patch, mock_open


# Mock auth
@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides = {}


def test_update_team_mapping(client):
    new_mapping = {"comp1": "team1", "comp2": "team2"}

    with patch(
        "main.get_team_mapping_path", return_value="/tmp/test_mapping_update.json"
    ):
        with patch("main.get_user_role", return_value="REVIEWER"):
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
        with patch("main.get_user_role", return_value="REVIEWER"):
            with patch("builtins.open", side_effect=Exception("Write error")):
                response = client.put("/api/settings/mapping", json=new_mapping)

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Write error" in data["message"]


def test_update_roles_reviewer(client):
    new_roles = {"alice": "REVIEWER", "bob": "ANALYST"}

    # Mock user role to be REVIEWER
    with patch("main.get_user_role", return_value="REVIEWER"):
        with patch(
            "main.get_user_roles_path", return_value="/tmp/test_roles_update.json"
        ):
            with patch("builtins.open", mock_open()) as mocked_file:
                response = client.put("/api/settings/roles", json=new_roles)

                assert response.status_code == 200
                assert response.json()["status"] == "success"

                mocked_file.assert_called_with("/tmp/test_roles_update.json", "w")


def test_update_roles_analyst_forbidden(client):
    new_roles = {"alice": "REVIEWER"}

    # Mock user role to be ANALYST (default for 'testuser' if not mapped, but we force it)
    with patch("main.get_user_role", return_value="ANALYST"):
        response = client.put("/api/settings/roles", json=new_roles)

        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]


def test_update_team_mapping_analyst_forbidden(client):
    new_mapping = {"comp1": "team1"}

    with patch("main.get_user_role", return_value="ANALYST"):
        response = client.put("/api/settings/mapping", json=new_mapping)

        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]
