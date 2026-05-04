import logging
from typing import Any, Dict, Optional

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("dtvp.code_analysis")


class CodeAnalysisSettings(BaseSettings):
    DTVP_CODE_ANALYSIS_URL: str = Field(alias="DTVP_CODE_ANALYSIS_URL", default="")
    DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS: float = Field(
        alias="DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS",
        default=300.0,
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


class CodeAnalysisClient:
    def __init__(self, settings: Optional[CodeAnalysisSettings] = None):
        self.settings = settings or CodeAnalysisSettings()
        if not self.settings.enabled:
            raise RuntimeError("Code analysis integration is not configured")
        self.client = httpx.AsyncClient(
            timeout=self.settings.DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS
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
        focus_path: Optional[str] = None,
        dependency_paths: Optional[list] = None,
        debug: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"component_name": component_name}
        if vuln_id:
            payload["vuln_id"] = vuln_id
        if cvss_vector:
            payload["cvss_vector"] = cvss_vector
        if user_guidance:
            payload["user_guidance"] = user_guidance
        if focus_path:
            payload["focus_path"] = focus_path
        if dependency_paths:
            payload["dependency_paths"] = dependency_paths
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
        focus_path: Optional[str] = None,
        dependency_paths: Optional[list] = None,
        debug: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"component_name": component_name}
        if vuln_id:
            payload["vuln_id"] = vuln_id
        if cvss_vector:
            payload["cvss_vector"] = cvss_vector
        if user_guidance:
            payload["user_guidance"] = user_guidance
        if focus_path:
            payload["focus_path"] = focus_path
        if dependency_paths:
            payload["dependency_paths"] = dependency_paths
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

    async def get_job_result(self, job_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/jobs/{job_id}/result"
        )
        response.raise_for_status()
        return response.json()

    async def delete_job(self, job_id: str) -> None:
        response = await self.client.delete(f"{self.settings.base_url}/jobs/{job_id}")
        response.raise_for_status()
