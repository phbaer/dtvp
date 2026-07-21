import pytest
from fastapi import HTTPException

from dtvp.authorization import (
    Role,
    can_access_owned_resource,
    normalize_role,
    require_owned_resource_access,
    require_reviewer,
    resolve_user_role,
    validate_user_roles_config,
)


def test_role_resolution_fails_closed():
    assert resolve_user_role("alice", None) is Role.ANALYST
    assert resolve_user_role("alice", {}) is Role.ANALYST
    assert resolve_user_role("alice", {"alice": "unexpected"}) is Role.ANALYST
    assert normalize_role(None) is Role.ANALYST


def test_role_config_validation_normalizes_known_roles():
    assert validate_user_roles_config(
        {" alice ": "reviewer", "bob": "ANALYST"}
    ) == {"alice": "REVIEWER", "bob": "ANALYST"}


@pytest.mark.parametrize(
    "config",
    [[], {"": "REVIEWER"}, {"alice": "ADMIN"}, {"alice": None}],
)
def test_role_config_validation_rejects_invalid_policy(config):
    with pytest.raises(ValueError):
        validate_user_roles_config(config)


def test_reviewer_permission_requires_explicit_reviewer_role():
    require_reviewer("REVIEWER")
    with pytest.raises(HTTPException) as exc_info:
        require_reviewer("ANALYST")
    assert exc_info.value.status_code == 403


def test_owned_resources_allow_owner_or_reviewer_only():
    assert can_access_owned_resource(
        username="alice", owner="alice", role="ANALYST"
    )
    assert can_access_owned_resource(
        username="reviewer", owner="alice", role="REVIEWER"
    )
    assert not can_access_owned_resource(
        username="bob", owner="alice", role="ANALYST"
    )

    with pytest.raises(HTTPException) as exc_info:
        require_owned_resource_access(
            username="bob",
            owner="alice",
            role="ANALYST",
            not_found_detail="Resource not found",
        )
    assert exc_info.value.status_code == 404
