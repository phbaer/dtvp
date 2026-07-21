"""Service-to-service authentication and caller identity for Agentyzer."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


MINIMUM_SERVICE_TOKEN_LENGTH = 32
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ServiceCaller:
    owner: str
    is_admin: bool = False

    @property
    def can_access_all_jobs(self) -> bool:
        return self.is_admin and self.owner == "*"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


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


def _read_admin_token() -> str:
    return _read_token(
        "AGENTYZER_ADMIN_TOKEN",
        "AGENTYZER_ADMIN_TOKEN_FILE",
    )


def _allow_unauthenticated() -> bool:
    return _truthy(os.environ.get("AGENTYZER_ALLOW_UNAUTHENTICATED"))


def validate_service_auth_configuration() -> None:
    environment = os.environ.get("AGENTYZER_ENVIRONMENT", "production").strip().lower()
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

    if environment == "production" and _truthy(
        os.environ.get("AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH")
    ):
        raise RuntimeError(
            "AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH cannot be enabled in production"
        )

    token = _read_service_token()
    if len(token) < MINIMUM_SERVICE_TOKEN_LENGTH:
        raise RuntimeError(
            "AGENTYZER_SERVICE_TOKEN or AGENTYZER_SERVICE_TOKEN_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    admin_token = _read_admin_token()
    if admin_token and len(admin_token) < MINIMUM_SERVICE_TOKEN_LENGTH:
        raise RuntimeError(
            "AGENTYZER_ADMIN_TOKEN or AGENTYZER_ADMIN_TOKEN_FILE must provide "
            f"at least {MINIMUM_SERVICE_TOKEN_LENGTH} characters"
        )
    if admin_token and secrets.compare_digest(admin_token, token):
        raise RuntimeError("AGENTYZER_ADMIN_TOKEN must differ from the service token")


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

    environment = os.environ.get("AGENTYZER_ENVIRONMENT", "production").strip().lower()
    allow_external = environment in {"development", "test"} and _truthy(
        os.environ.get("AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH")
    )
    repo_root = Path(os.environ.get("AGENTYZER_REPOS_DIR", "repos")).resolve(
        strict=False
    )
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
        expected = _read_service_token()
        admin_expected = _read_admin_token()
        provided = credentials.credentials if credentials else ""
        is_service = bool(expected) and secrets.compare_digest(provided, expected)
        is_admin = bool(admin_expected) and secrets.compare_digest(
            provided,
            admin_expected,
        )
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
