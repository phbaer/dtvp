from unittest.mock import mock_open, patch

import pytest

from dtvp import main


# Override auth
@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides = {}


def test_roles_missing_file_defaults_analyst(client):
    # Mock os.path.exists to return False
    with patch("os.path.exists", return_value=False):
        # A missing authorization policy must fail closed.
        resp = client.get("/api/settings/roles")
        assert resp.status_code == 403

        resp = client.get("/auth/me")
        assert resp.status_code == 200
        assert resp.json()["role"] == "ANALYST"


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
