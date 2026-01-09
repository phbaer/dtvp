import httpx
import asyncio
from typing import List, Dict, Any, Optional, AsyncGenerator
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DTClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Create a persistent client with increased timeout and connection limits
        self.client = httpx.AsyncClient(
            headers=self.headers,
            timeout=60.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def get_projects(self, name: str) -> List[Dict[str, Any]]:
        """
        Search for projects by name.
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/project",
            params={"name": name, "excludeInactive": "true"},
        )
        response.raise_for_status()
        return response.json()

    async def get_project_versions(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all versions for a project.
        """
        # Placeholder as per original code
        pass

    async def get_vulnerabilities(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a specific project version.
        Enriches findings with analysis data from the analysis endpoint.
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/finding/project/{project_uuid}",
        )
        response.raise_for_status()
        findings = response.json()

        # Gather analysis tasks to run in parallel
        # Use a list of tuples (finding, task) to map results back
        analysis_tasks = []
        findings_to_enrich = []

        for finding in findings:
            component_uuid = finding.get("component", {}).get("uuid")
            vulnerability_uuid = finding.get("vulnerability", {}).get("uuid")

            if component_uuid and vulnerability_uuid:
                findings_to_enrich.append(finding)
                analysis_tasks.append(
                    self.get_analysis(project_uuid, component_uuid, vulnerability_uuid)
                )

        if analysis_tasks:
            # Execute all analysis requests in parallel
            # httpx limits will handle connection pooling/queuing
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)

            # Merge results
            for finding, analysis_result in zip(findings_to_enrich, results):
                if isinstance(analysis_result, Exception):
                    # Log or ignore error? Original code passed on exception
                    continue

                if analysis_result:
                    finding["analysis"] = analysis_result

        return findings

    async def get_project_vulnerabilities(
        self, project_uuid: str
    ) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a specific project version with full details (including vectors).
        Uses /api/v1/vulnerability/project/{project_uuid}
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/vulnerability/project/{project_uuid}",
        )
        response.raise_for_status()
        return response.json()

    async def get_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Get analysis for a specific finding.
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/analysis",
            params={
                "project": project_uuid,
                "component": component_uuid,
                "vulnerability": vulnerability_uuid,
            },
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    async def update_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        state: str,
        details: str,
        comment: Optional[str] = None,
        suppressed: bool = False,
    ):
        """
        Update analysis for a finding.
        """
        payload = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
            "analysisState": state,
            "isSuppressed": suppressed,
            "analysisDetails": details,
        }
        if comment:
            payload["comment"] = comment

        response = await self.client.put(
            f"{self.base_url}/api/v1/analysis", json=payload
        )
        response.raise_for_status()
        return response.json()


class DTSettings(BaseSettings):
    DTVP_DT_API_URL: str = Field(
        alias="DTVP_DT_API_URL", default="http://localhost:8081"
    )
    DTVP_DT_API_KEY: str = Field(alias="DTVP_DT_API_KEY", default="change_me")

    # Support aliases from docker-compose.yml
    DEPENDENCY_TRACK_URL: Optional[str] = Field(default=None)
    DEPENDENCY_TRACK_API_KEY: Optional[str] = Field(default=None)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def api_url(self) -> str:
        return (
            self.DTVP_DT_API_URL or self.DEPENDENCY_TRACK_URL or "http://localhost:8081"
        )

    @property
    def api_key(self) -> str:
        return self.DTVP_DT_API_KEY or self.DEPENDENCY_TRACK_API_KEY or "change_me"


async def get_client() -> AsyncGenerator[DTClient, None]:
    settings = DTSettings()
    async with DTClient(settings.api_url, settings.api_key) as client:
        yield client
