"""Each settings upload is validated with the rules of its own file."""

import json
from unittest.mock import patch

import pytest

from dtvp import main


@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides = {}


def _upload(client, route: str, content: bytes):
    return client.post(
        f"/api/settings/{route}",
        files={"file": ("upload.json", content, "application/json")},
    )


VALID_RESCORE_RULES = {
    "metric_rules": {
        "3.1": {
            "undefined_values": ["X"],
            "base_metrics": ["AV"],
            "metric_order": ["AV", "MAV"],
            "relationships": [{"base": "AV", "modified": "MAV"}],
        }
    },
    "transitions": [],
}


def test_roles_upload_accepts_a_role_map(client, tmp_path):
    target = tmp_path / "user_roles.json"
    content = json.dumps({"alice": "REVIEWER", "bob": "ANALYST"}).encode()
    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch("dtvp.main.get_user_roles_path", return_value=str(target)),
    ):
        response = _upload(client, "roles", content)

    assert response.json()["status"] == "success"
    assert target.read_bytes() == content


@pytest.mark.parametrize(
    "content, message",
    [
        (b"[]", "must be a JSON object"),
        (b'{"alice": 1}', "Role of 'alice' must be a string"),
        (b"{nope", "Invalid JSON"),
    ],
)
def test_roles_upload_rejects_what_is_not_a_role_map(client, tmp_path, content, message):
    target = tmp_path / "user_roles.json"
    target.write_bytes(b'{"keep": "REVIEWER"}')
    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch("dtvp.main.get_user_roles_path", return_value=str(target)),
    ):
        response = _upload(client, "roles", content)

    assert response.json()["status"] == "error"
    assert message in response.json()["message"]
    assert target.read_bytes() == b'{"keep": "REVIEWER"}'


def test_rescore_rules_upload_accepts_valid_rules(client, tmp_path):
    target = tmp_path / "rescore_rules.json"
    content = json.dumps(VALID_RESCORE_RULES).encode()
    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch("dtvp.main.get_rescore_rules_path", return_value=str(target)),
    ):
        response = _upload(client, "rescore-rules", content)

    assert response.json()["status"] == "success", response.json()
    assert target.read_bytes() == content


@pytest.mark.parametrize(
    "content, message",
    [
        (b'{"alice": "REVIEWER"}', "metric_rules must be a non-empty object"),
        (b"[1]", "must be a JSON object"),
        (b"{nope", "Invalid JSON"),
    ],
)
def test_rescore_rules_upload_validates_the_rules(client, tmp_path, content, message):
    target = tmp_path / "rescore_rules.json"
    with (
        patch("dtvp.main.get_user_role", return_value="REVIEWER"),
        patch("dtvp.main.get_rescore_rules_path", return_value=str(target)),
    ):
        response = _upload(client, "rescore-rules", content)

    assert response.json()["status"] == "error"
    assert message in response.json()["message"]
    assert not target.exists()
