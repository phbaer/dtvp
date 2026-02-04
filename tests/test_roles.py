import pytest
from unittest.mock import patch, mock_open
from main import app, get_current_user


# Override auth
@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides = {}


def test_roles_missing_file_defaults_reviewer(client):
    # Mock os.path.exists to return False
    with patch("os.path.exists", return_value=False):
        # get_roles should return None/null
        # And get_user_role should return REVIEWER

        # We can test via get_roles endpoint
        resp = client.get("/api/settings/roles")
        assert resp.status_code == 200
        assert resp.json() is None

        # If file missing, current user (testuser) should be REVIEWER
        # We can verify this via /auth/me
        resp = client.get("/auth/me")
        assert resp.json()["role"] == "REVIEWER"


def test_roles_empty_file_defaults_analyst(client):
    # Mock os.path.exists to true, and open to return {}
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="{}")):
            # If file empty, unmapped user (testuser) should be ANALYST
            resp = client.get("/auth/me")
            assert resp.status_code == 200
            assert resp.json()["role"] == "ANALYST"


def test_roles_corrupted_file_defaults_empty(client):
    # Mock os.path.exists to true, and open to raise Exception or return bad json
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="{invalid_json")):
            with patch("json.load", side_effect=Exception("JSON Decode Error")):
                # load_user_roles returns {} on exception
                # get_user_role returns ANALYST
                resp = client.get("/auth/me")
                assert resp.json()["role"] == "ANALYST"
