"""Compatibility facade for the former misspelled Agentyzer integration.

New code must import :mod:`dtvp.code_analysis_integration`.  This module keeps
the old public names and environment variables working without maintaining a
second HTTP client implementation.
"""

import os
import warnings
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import code_analysis_integration as _canonical
from .integration_auth import read_secret, validate_service_token

# Some external tests and callers patched this module-level dependency.  It is
# the same module object used by the canonical client.
httpx = _canonical.httpx

warnings.warn(
    "dtvp.agentizer_integration is deprecated and will be removed in DTVP 2.0; "
    "use dtvp.code_analysis_integration and DTVP_CODE_ANALYSIS_* settings",
    DeprecationWarning,
    stacklevel=2,
)


class AgenyzerSettings(BaseSettings):
    """Legacy settings names adapted to the canonical client contract."""

    DTVP_AGENYZER_URL: str = Field(alias="DTVP_AGENYZER_URL", default="")
    DTVP_AGENYZER_TIMEOUT_SECONDS: float = Field(
        alias="DTVP_AGENYZER_TIMEOUT_SECONDS",
        default=300.0,
    )
    DTVP_AGENYZER_MODEL: str = Field(alias="DTVP_AGENYZER_MODEL", default="")
    DTVP_AGENYZER_LLM_BACKEND: str = Field(
        alias="DTVP_AGENYZER_LLM_BACKEND",
        default="",
    )
    DTVP_AGENYZER_LLM_PROVIDER: str = Field(
        alias="DTVP_AGENYZER_LLM_PROVIDER",
        default="",
    )
    DTVP_AGENYZER_SERVICE_TOKEN: str = Field(
        alias="DTVP_AGENYZER_SERVICE_TOKEN",
        default="",
    )
    DTVP_AGENYZER_SERVICE_TOKEN_FILE: str = Field(
        alias="DTVP_AGENYZER_SERVICE_TOKEN_FILE",
        default="",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def base_url(self) -> str:
        return self.DTVP_AGENYZER_URL.rstrip("/")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    @property
    def service_token(self) -> str:
        return read_secret(
            self.DTVP_AGENYZER_SERVICE_TOKEN,
            self.DTVP_AGENYZER_SERVICE_TOKEN_FILE,
        )

    @property
    def DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS(self) -> float:
        return self.DTVP_AGENYZER_TIMEOUT_SECONDS

    @property
    def DTVP_CODE_ANALYSIS_MODEL(self) -> str:
        return self.DTVP_AGENYZER_MODEL

    @property
    def DTVP_CODE_ANALYSIS_LLM_BACKEND(self) -> str:
        return self.DTVP_AGENYZER_LLM_BACKEND

    @property
    def DTVP_CODE_ANALYSIS_LLM_PROVIDER(self) -> str:
        return self.DTVP_AGENYZER_LLM_PROVIDER

    def token_for_owner(self, owner: Optional[str]) -> str:
        # The legacy contract exposed no administrator credential.  Its token
        # therefore remains service-scoped even when an owner is supplied.
        return self.service_token


def validate_agenyzer_configuration(
    settings: Optional[AgenyzerSettings] = None,
) -> None:
    """Validate the legacy service-only configuration."""
    resolved = settings or AgenyzerSettings()
    validate_service_token(
        enabled=resolved.enabled,
        environment=os.environ.get("DTVP_ENVIRONMENT", "production"),
        token=resolved.service_token,
        setting_name=(
            "DTVP_AGENYZER_SERVICE_TOKEN or DTVP_AGENYZER_SERVICE_TOKEN_FILE"
        ),
    )


class AgenyzerClient(_canonical.CodeAnalysisClient):
    """Deprecated name backed entirely by the canonical analysis client."""

    def __init__(
        self,
        settings: Optional[AgenyzerSettings] = None,
        *,
        owner: Optional[str] = None,
    ):
        resolved = settings or AgenyzerSettings()
        if not resolved.enabled:
            raise RuntimeError("Agenyzer integration is not configured")
        super().__init__(settings=resolved, owner=owner)  # type: ignore[arg-type]
