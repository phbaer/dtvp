"""Service-to-service authentication and caller identity for Agentyzer."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.configuration import AgentyzerRuntimeSettings


MINIMUM_SERVICE_TOKEN_LENGTH = 32
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ServiceCaller:
    owner: str
    is_admin: bool = False

    @property
    def can_access_all_jobs(self) -> bool:
        return self.is_admin and self.owner == "*"


def _read_token(direct_setting: str, file_setting: str) -> str:
    direct = os.environ.get(direct_setting, "").strip()
    if direct:
        return direct
    token_file = os.environ.get(file_setting, "").strip()
    if not token_file:
        return ""
    return Path(token_file).read_text(encoding="utf-8").strip()


def _read_service_token() -> str:
    return _read_token(
        "AGENTYZER_SERVICE_TOKEN",
        "AGENTYZER_SERVICE_TOKEN_FILE",
    )


def _read_previous_service_token() -> str:
    return _read_token(
        "AGENTYZER_SERVICE_TOKEN_PREVIOUS",
        "AGENTYZER_SERVICE_TOKEN_PREVIOUS_FILE",
    )


def _read_admin_token() -> str:
    return _read_token(
        "AGENTYZER_ADMIN_TOKEN",
        "AGENTYZER_ADMIN_TOKEN_FILE",
    )


def _read_previous_admin_token() -> str:
    return _read_token(
        "AGENTYZER_ADMIN_TOKEN_PREVIOUS",
        "AGENTYZER_ADMIN_TOKEN_PREVIOUS_FILE",
    )


def _configured_tokens(current: str, previous: str) -> tuple[str, ...]:
    return tuple(token for token in (current, previous) if token)


def _matches_token(provided: str, expected_tokens: tuple[str, ...]) -> bool:
    matched = False
    for expected in expected_tokens:
        matched |= secrets.compare_digest(provided, expected)
    return matched


def _validated_auth_tokens() -> tuple[tuple[str, ...], tuple[str, ...]]:
    service_token = _read_service_token()
    previous_service_token = _read_previous_service_token()
    admin_token = _read_admin_token()
    previous_admin_token = _read_previous_admin_token()

    if len(service_token) < MINIMUM_SERVICE_TOKEN_LENGTH:
        raise RuntimeError(
            "AGENTYZER_SERVICE_TOKEN or AGENTYZER_SERVICE_TOKEN_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    if (
        previous_service_token
        and len(previous_service_token) < MINIMUM_SERVICE_TOKEN_LENGTH
    ):
        raise RuntimeError(
            "AGENTYZER_SERVICE_TOKEN_PREVIOUS or "
            "AGENTYZER_SERVICE_TOKEN_PREVIOUS_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    if admin_token and len(admin_token) < MINIMUM_SERVICE_TOKEN_LENGTH:
        raise RuntimeError(
            "AGENTYZER_ADMIN_TOKEN or AGENTYZER_ADMIN_TOKEN_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    if (
        previous_admin_token
        and len(previous_admin_token) < MINIMUM_SERVICE_TOKEN_LENGTH
    ):
        raise RuntimeError(
            "AGENTYZER_ADMIN_TOKEN_PREVIOUS or "
            "AGENTYZER_ADMIN_TOKEN_PREVIOUS_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    if previous_admin_token and not admin_token:
        raise RuntimeError(
            "AGENTYZER_ADMIN_TOKEN_PREVIOUS requires a current admin token"
        )

    service_tokens = _configured_tokens(service_token, previous_service_token)
    admin_tokens = _configured_tokens(admin_token, previous_admin_token)
    if len(service_tokens) != len(set(service_tokens)):
        raise RuntimeError("Current and previous Agentyzer service tokens must differ")
    if len(admin_tokens) != len(set(admin_tokens)):
        raise RuntimeError("Current and previous Agentyzer admin tokens must differ")
    if any(
        secrets.compare_digest(service, admin)
        for service in service_tokens
        for admin in admin_tokens
    ):
        raise RuntimeError("Agentyzer admin tokens must differ from all service tokens")
    return service_tokens, admin_tokens


def _allow_unauthenticated() -> bool:
    return AgentyzerRuntimeSettings.from_env().allow_unauthenticated


def validate_service_auth_configuration() -> None:
    settings = AgentyzerRuntimeSettings.from_env()
    environment = settings.environment
    if environment not in {"development", "production", "test"}:
        raise RuntimeError(
            "AGENTYZER_ENVIRONMENT must be development, production, or test"
        )
    if _allow_unauthenticated():
        if environment == "production":
            raise RuntimeError(
                "AGENTYZER_ALLOW_UNAUTHENTICATED cannot be enabled in production"
            )
        return

    if environment == "production" and settings.allow_external_focus_path:
        raise RuntimeError(
            "AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH cannot be enabled in production"
        )

    _validated_auth_tokens()


def validate_focus_path(value: str | None) -> str | None:
    """Resolve a local checkout path and keep production scans in the repo root."""
    if value is None:
        return None
    raw_path = value.strip()
    if not raw_path:
        return None
    try:
        path = Path(raw_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail="Focus path does not exist") from exc
    if not path.is_dir():
        raise HTTPException(status_code=400, detail="Focus path must be a directory")

    settings = AgentyzerRuntimeSettings.from_env()
    allow_external = (
        settings.environment in {"development", "test"}
        and settings.allow_external_focus_path
    )
    repo_root = Path(settings.repos_dir).resolve(strict=False)
    if not allow_external and not path.is_relative_to(repo_root):
        raise HTTPException(
            status_code=400,
            detail="Focus path must be inside the configured Agentyzer repository root",
        )
    return str(path)


def _normalized_owner(value: str | None) -> str:
    owner = " ".join(str(value or "service").split()).strip()
    if not owner or len(owner) > 200:
        raise HTTPException(status_code=400, detail="Invalid Agentyzer caller owner")
    return owner


async def require_service_caller(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(_bearer),
    ],
    x_agentyzer_owner: Annotated[
        str | None,
        Header(alias="X-Agentyzer-Owner"),
    ] = None,
) -> ServiceCaller:
    if not _allow_unauthenticated():
        try:
            service_tokens, admin_tokens = _validated_auth_tokens()
        except (OSError, RuntimeError, UnicodeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Agentyzer service credentials are unavailable",
            ) from exc
        provided = credentials.credentials if credentials else ""
        is_service = _matches_token(provided, service_tokens)
        is_admin = _matches_token(provided, admin_tokens)
        if not is_service and not is_admin:
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing Agentyzer service credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        is_admin = False

    owner = _normalized_owner(x_agentyzer_owner)
    if owner == "*" and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Agentyzer service-wide owner scope requires admin credentials",
        )
    return ServiceCaller(owner=owner, is_admin=is_admin)
