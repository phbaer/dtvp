"""Shared service-auth helpers for outbound backend integrations."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional


def read_secret(direct: Optional[str], file_path: Optional[str]) -> str:
    value = str(direct or "").strip()
    if value:
        return value
    path = str(file_path or "").strip()
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def service_request_headers(
    token: str,
    *,
    owner: Optional[str] = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    normalized_owner = " ".join(str(owner or "service").split()).strip()
    if normalized_owner:
        headers["X-Agentyzer-Owner"] = normalized_owner
    return headers


def validate_service_token(
    *,
    enabled: bool,
    environment: str,
    token: str,
    setting_name: str,
) -> None:
    if enabled and environment.strip().lower() == "production" and len(token) < 32:
        raise RuntimeError(
            f"{setting_name} must contain at least 32 characters when the "
            "integration is enabled in production"
        )


def validate_distinct_service_tokens(
    service_token: str,
    admin_token: str,
    *,
    setting_name: str,
) -> None:
    if service_token and admin_token and secrets.compare_digest(
        service_token,
        admin_token,
    ):
        raise RuntimeError(f"{setting_name} must differ from the service token")
