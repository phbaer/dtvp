from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from fastapi import HTTPException


class Role(StrEnum):
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    role: Role


def normalize_role(value: Any) -> Role:
    try:
        return Role(str(value).strip().upper())
    except (TypeError, ValueError):
        return Role.ANALYST


def validate_user_roles_config(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("User roles JSON must be an object")

    normalized: dict[str, str] = {}
    for username, configured_role in value.items():
        if not isinstance(username, str) or not username.strip():
            raise ValueError("User role names must be non-empty strings")
        role_text = str(configured_role).strip().upper()
        if role_text not in Role._value2member_map_:
            allowed = ", ".join(role.value for role in Role)
            raise ValueError(
                f"Invalid role for {username!r}: expected one of {allowed}"
            )
        normalized[username.strip()] = role_text
    return normalized


def resolve_user_role(
    username: str,
    roles: Mapping[str, Any] | None,
) -> Role:
    if not isinstance(roles, Mapping):
        return Role.ANALYST
    return normalize_role(roles.get(username, Role.ANALYST))


def is_reviewer(role: Any) -> bool:
    return normalize_role(role) is Role.REVIEWER


def require_reviewer(
    role: Any,
    detail: str = "Reviewer role required",
) -> None:
    if not is_reviewer(role):
        raise HTTPException(status_code=403, detail=detail)


def can_access_owned_resource(*, username: str, owner: Any, role: Any) -> bool:
    return is_reviewer(role) or (
        isinstance(owner, str) and owner != "" and owner == username
    )


def require_owned_resource_access(
    *,
    username: str,
    owner: Any,
    role: Any,
    not_found_detail: str,
) -> None:
    if not can_access_owned_resource(username=username, owner=owner, role=role):
        # Return 404 so callers cannot use object IDs to enumerate other users' work.
        raise HTTPException(status_code=404, detail=not_found_detail)
