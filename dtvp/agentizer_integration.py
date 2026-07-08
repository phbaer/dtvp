import logging
from typing import Any, Dict, Optional

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("dtvp.agenyzer")


class AgenyzerSettings(BaseSettings):
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


class AgenyzerClient:
    def __init__(self, settings: Optional[AgenyzerSettings] = None):
        self.settings = settings or AgenyzerSettings()
        if not self.settings.enabled:
            raise RuntimeError("Agenyzer integration is not configured")
        self.client = httpx.AsyncClient(
            timeout=self.settings.DTVP_AGENYZER_TIMEOUT_SECONDS
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
        selected_model = model or self.settings.DTVP_AGENYZER_MODEL
        selected_backend = llm_backend or self.settings.DTVP_AGENYZER_LLM_BACKEND
        selected_provider = llm_provider or self.settings.DTVP_AGENYZER_LLM_PROVIDER
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
        selected_model = model or self.settings.DTVP_AGENYZER_MODEL
        selected_backend = llm_backend or self.settings.DTVP_AGENYZER_LLM_BACKEND
        selected_provider = llm_provider or self.settings.DTVP_AGENYZER_LLM_PROVIDER
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
