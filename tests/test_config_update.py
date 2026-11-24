import json
from unittest.mock import patch

import pytest

from dtvp import main


# Mock auth
@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides = {}


def test_update_team_mapping(client, tmp_path):
    new_mapping = {"comp1": "team1", "comp2": "team2"}
    target = tmp_path / "test_mapping_update.json"

    with patch("dtvp.main.get_team_mapping_path", return_value=str(target)):
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            response = client.put("/api/settings/mapping", json=new_mapping)

            assert response.status_code == 200
            assert response.json()["status"] == "success"

    # Written organised by team (ADR 0012).
    stored = {"team1": {"components": ["comp1"]}, "team2": {"components": ["comp2"]}}
    assert json.loads(target.read_text()) == stored
    assert target.read_text() == json.dumps(stored, indent=2)


def test_update_team_mapping_failure(client, tmp_path):
    new_mapping = {"comp": "team"}
    settings_dir = tmp_path / "settings"
    settings_dir.mkdir()
    target = settings_dir / "test_mapping_update.json"

    with patch("dtvp.main.get_team_mapping_path", return_value=str(target)):
        with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
            with patch("os.replace", side_effect=OSError("Write error")):
                response = client.put("/api/settings/mapping", json=new_mapping)

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Write error" in data["message"]
    assert not target.exists()
    assert list(settings_dir.iterdir()) == []


def test_update_team_groups_reviewer(client, tmp_path):
    groups = {
        "Core-MUC": {
            "teams": ["Core-MUC", "3rd Party"],
            "groups": [],
        }
    }
    team_mapping = {
        "core": "Core-MUC",
        "vendor": "3rd Party",
    }
    target = tmp_path / "test_team_groups.json"

    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch("dtvp.main.load_team_mapping", return_value=team_mapping),
        patch("dtvp.main.load_team_mapping_document", return_value=team_mapping),
        patch("dtvp.main.get_team_groups_path", return_value=str(target)),
    ):
        response = client.put("/api/settings/team-groups", json=groups)

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert json.loads(target.read_text()) == groups


def test_update_team_groups_rejects_unknown_team(client, tmp_path):
    groups = {
        "Core-MUC": {
            "teams": ["Unknown"],
            "groups": [],
        }
    }
    target = tmp_path / "test_team_groups.json"

    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch(
            "dtvp.main.load_team_mapping",
            return_value={"core": "Core-MUC"},
        ),
        patch("dtvp.main.get_team_groups_path", return_value=str(target)),
    ):
        response = client.put("/api/settings/team-groups", json=groups)

    assert response.status_code == 200
    assert response.json()["status"] == "error"
    assert "unknown configured team Unknown" in response.json()["message"]
    assert not target.exists()


def test_update_team_groups_analyst_forbidden(client):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.put(
            "/api/settings/team-groups",
            json={"Core-MUC": {"teams": ["Core-MUC"], "groups": []}},
        )

    assert response.status_code == 403
    assert "Only reviewers" in response.json()["detail"]


def test_update_roles_reviewer(client, tmp_path):
    new_roles = {"alice": "REVIEWER", "bob": "ANALYST"}
    target = tmp_path / "test_roles_update.json"

    # Mock user role to be REVIEWER
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        with patch("dtvp.main.get_user_roles_path", return_value=str(target)):
            response = client.put("/api/settings/roles", json=new_roles)

            assert response.status_code == 200
            assert response.json()["status"] == "success"

    assert json.loads(target.read_text()) == new_roles


def test_update_roles_analyst_forbidden(client):
    new_roles = {"alice": "REVIEWER"}

    # Mock user role to be ANALYST (default for 'testuser' if not mapped, but we force it)
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.put("/api/settings/roles", json=new_roles)

        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]


def test_update_auto_analysis_guidance_reviewer(client, tmp_path):
    guidance = {"components": {"keycloak-extension": "Check upstream Keycloak too."}}
    target = tmp_path / "test_auto_guidance.json"

    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        with patch(
            "dtvp.main.get_auto_analysis_guidance_path",
            return_value=str(target),
        ):
            response = client.put(
                "/api/settings/auto-analysis-guidance",
                json=guidance,
            )

            assert response.status_code == 200
            assert response.json()["status"] == "success"
    assert json.loads(target.read_text()) == guidance


def test_update_auto_analysis_guidance_analyst_forbidden(client):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.put(
            "/api/settings/auto-analysis-guidance",
            json={"components": {}},
        )

        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]


def test_update_team_mapping_analyst_forbidden(client):
    new_mapping = {"comp1": "team1"}

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.put("/api/settings/mapping", json=new_mapping)

        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]
