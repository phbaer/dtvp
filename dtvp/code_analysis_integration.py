import logging
import os
from typing import Any, Dict, Optional

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .integration_auth import (
    read_secret,
    service_request_headers,
    validate_distinct_service_tokens,
    validate_service_token,
)

logger = logging.getLogger("dtvp.code_analysis")


class CodeAnalysisSettings(BaseSettings):
    DTVP_CODE_ANALYSIS_URL: str = Field(alias="DTVP_CODE_ANALYSIS_URL", default="")
    DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS: float = Field(
        alias="DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS",
        default=300.0,
    )
    DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS: float = Field(
        alias="DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS",
        default=5.0,
    )
    DTVP_CODE_ANALYSIS_MODEL: str = Field(
        alias="DTVP_CODE_ANALYSIS_MODEL",
        default="",
    )
    DTVP_CODE_ANALYSIS_LLM_BACKEND: str = Field(
        alias="DTVP_CODE_ANALYSIS_LLM_BACKEND",
        default="",
    )
    DTVP_CODE_ANALYSIS_LLM_PROVIDER: str = Field(
        alias="DTVP_CODE_ANALYSIS_LLM_PROVIDER",
        default="",
    )
    DTVP_CODE_ANALYSIS_SERVICE_TOKEN: str = Field(
        alias="DTVP_CODE_ANALYSIS_SERVICE_TOKEN",
        default="",
    )
    DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE: str = Field(
        alias="DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE",
        default="",
    )
    DTVP_CODE_ANALYSIS_ADMIN_TOKEN: str = Field(
        alias="DTVP_CODE_ANALYSIS_ADMIN_TOKEN",
        default="",
    )
    DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE: str = Field(
        alias="DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE",
        default="",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def base_url(self) -> str:
        return self.DTVP_CODE_ANALYSIS_URL.rstrip("/")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    @property
    def service_token(self) -> str:
        return read_secret(
            self.DTVP_CODE_ANALYSIS_SERVICE_TOKEN,
            self.DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE,
        )

    @property
    def admin_token(self) -> str:
        return read_secret(
            self.DTVP_CODE_ANALYSIS_ADMIN_TOKEN,
            self.DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE,
        )

    def token_for_owner(self, owner: Optional[str]) -> str:
        if owner == "*":
            return self.admin_token
        return self.service_token


def validate_code_analysis_configuration(
    settings: Optional[CodeAnalysisSettings] = None,
) -> None:
    resolved = settings or CodeAnalysisSettings()
    validate_service_token(
        enabled=resolved.enabled,
        environment=os.environ.get("DTVP_ENVIRONMENT", "production"),
        token=resolved.service_token,
        setting_name=(
            "DTVP_CODE_ANALYSIS_SERVICE_TOKEN or "
            "DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE"
        ),
    )
    validate_service_token(
        enabled=resolved.enabled,
        environment=os.environ.get("DTVP_ENVIRONMENT", "production"),
        token=resolved.admin_token,
        setting_name=(
            "DTVP_CODE_ANALYSIS_ADMIN_TOKEN or "
            "DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE"
        ),
    )
    validate_distinct_service_tokens(
        resolved.service_token,
        resolved.admin_token,
        setting_name="DTVP_CODE_ANALYSIS_ADMIN_TOKEN",
    )


class CodeAnalysisClient:
    def __init__(
        self,
        settings: Optional[CodeAnalysisSettings] = None,
        *,
        owner: Optional[str] = None,
    ):
        self.settings = settings or CodeAnalysisSettings()
        if not self.settings.enabled:
            raise RuntimeError("Code analysis integration is not configured")
        self.client = httpx.AsyncClient(
            timeout=self.settings.DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS,
            headers=service_request_headers(
                self.settings.token_for_owner(owner),
                owner=owner,
            ),
        )

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def health(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.settings.base_url}/health")
        response.raise_for_status()
        return response.json()

    async def get_prompts(
        self,
        *,
        include_values: bool = False,
        system_only: bool = True,
    ) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/prompts",
            params={
                "include_values": str(include_values).lower(),
                "system_only": str(system_only).lower(),
            },
        )
        response.raise_for_status()
        return response.json()

    async def start_assessment(
        self,
        vuln_id: str,
        component_name: str,
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
        model: Optional[str] = None,
        llm_backend: Optional[str] = None,
        llm_provider: Optional[str] = None,
        focus_path: Optional[str] = None,
        dependency_paths: Optional[list] = None,
        affected_product_versions: Optional[list[str]] = None,
        debug: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"component_name": component_name}
        if vuln_id:
            payload["vuln_id"] = vuln_id
        if cvss_vector:
            payload["cvss_vector"] = cvss_vector
        if user_guidance:
            payload["user_guidance"] = user_guidance
        selected_model = model or self.settings.DTVP_CODE_ANALYSIS_MODEL
        selected_backend = (
            llm_backend or self.settings.DTVP_CODE_ANALYSIS_LLM_BACKEND
        )
        selected_provider = (
            llm_provider or self.settings.DTVP_CODE_ANALYSIS_LLM_PROVIDER
        )
        if selected_model:
            payload["model"] = selected_model
        if selected_backend:
            payload["llm_backend"] = selected_backend
        if selected_provider:
            payload["llm_provider"] = selected_provider
        if focus_path:
            payload["focus_path"] = focus_path
        if dependency_paths:
            payload["dependency_paths"] = dependency_paths
        if affected_product_versions:
            payload["affected_product_versions"] = affected_product_versions
        payload["debug"] = debug

        response = await self.client.post(
            f"{self.settings.base_url}/assess",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def compact_job(self, job_id: str) -> Dict[str, Any]:
        response = await self.client.post(
            f"{self.settings.base_url}/jobs/{job_id}/compact"
        )
        response.raise_for_status()
        return response.json()

    async def start_follow_up(
        self,
        job_id: str,
        question: str,
        user_guidance: Optional[str] = None,
        component_name: Optional[str] = None,
        vuln_id: Optional[str] = None,
        cvss_vector: Optional[str] = None,
        model: Optional[str] = None,
        llm_backend: Optional[str] = None,
        llm_provider: Optional[str] = None,
        debug: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"question": question}
        if user_guidance:
            payload["user_guidance"] = user_guidance
        if component_name:
            payload["component_name"] = component_name
        if vuln_id:
            payload["vuln_id"] = vuln_id
        if cvss_vector:
            payload["cvss_vector"] = cvss_vector
        selected_model = model or self.settings.DTVP_CODE_ANALYSIS_MODEL
        selected_backend = (
            llm_backend or self.settings.DTVP_CODE_ANALYSIS_LLM_BACKEND
        )
        selected_provider = (
            llm_provider or self.settings.DTVP_CODE_ANALYSIS_LLM_PROVIDER
        )
        if selected_model:
            payload["model"] = selected_model
        if selected_backend:
            payload["llm_backend"] = selected_backend
        if selected_provider:
            payload["llm_provider"] = selected_provider
        payload["debug"] = debug

        response = await self.client.post(
            f"{self.settings.base_url}/jobs/{job_id}/follow-up",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def compare_benchmark(
        self,
        benchmark: Dict[str, Any],
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"benchmark": benchmark}
        selected_model = model or self.settings.DTVP_CODE_ANALYSIS_MODEL
        if selected_model:
            payload["model"] = selected_model
        response = await self.client.post(
            f"{self.settings.base_url}/benchmark/compare",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def start_assessment_sync(
        self,
        vuln_id: str,
        component_name: str,
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
        model: Optional[str] = None,
        llm_backend: Optional[str] = None,
        llm_provider: Optional[str] = None,
        focus_path: Optional[str] = None,
        dependency_paths: Optional[list] = None,
        affected_product_versions: Optional[list[str]] = None,
        debug: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"component_name": component_name}
        if vuln_id:
            payload["vuln_id"] = vuln_id
        if cvss_vector:
            payload["cvss_vector"] = cvss_vector
        if user_guidance:
            payload["user_guidance"] = user_guidance
        selected_model = model or self.settings.DTVP_CODE_ANALYSIS_MODEL
        selected_backend = (
            llm_backend or self.settings.DTVP_CODE_ANALYSIS_LLM_BACKEND
        )
        selected_provider = (
            llm_provider or self.settings.DTVP_CODE_ANALYSIS_LLM_PROVIDER
        )
        if selected_model:
            payload["model"] = selected_model
        if selected_backend:
            payload["llm_backend"] = selected_backend
        if selected_provider:
            payload["llm_provider"] = selected_provider
        if focus_path:
            payload["focus_path"] = focus_path
        if dependency_paths:
            payload["dependency_paths"] = dependency_paths
        if affected_product_versions:
            payload["affected_product_versions"] = affected_product_versions
        payload["debug"] = debug

        response = await self.client.post(
            f"{self.settings.base_url}/assess",
            json=payload,
            params={"sync": "true"},
        )
        response.raise_for_status()
        return response.json()

    async def get_job_status(self, job_id: str) -> Dict[str, Any]:
        response = await self.client.get(f"{self.settings.base_url}/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    async def list_jobs(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.settings.base_url}/jobs")
        response.raise_for_status()
        return response.json()

    async def get_job_result(self, job_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/jobs/{job_id}/result"
        )
        response.raise_for_status()
        return response.json()

    async def delete_job(self, job_id: str) -> None:
        response = await self.client.delete(f"{self.settings.base_url}/jobs/{job_id}")
        response.raise_for_status()
