import httpx
from typing import List, Dict, Any, Optional
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

    async def get_projects(self, name: str) -> List[Dict[str, Any]]:
        """
        Search for projects by name.
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/project",
                params={"name": name, "excludeInactive": "true"},
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_project_versions(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all versions for a project.
        Note: The project_uuid passed here might be one version,
        we usually want to find the parent or all with same name.
        Actually, in DT, versions are just projects with the same name/classifier but different version string.
        Typically we search by name to get all versions.
        """
        # If we have a name, we can just search by name to get all versions
        # But this function takes a UUID.
        # For simplicity in this vertical slice, we'll assume the caller uses get_projects(name)
        # to get all versions directly if the name is exact.
        pass

    async def get_vulnerabilities(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a specific project version.
        Enriches findings with analysis data from the analysis endpoint.
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/finding/project/{project_uuid}",
                headers=self.headers,
            )
            response.raise_for_status()
            findings = response.json()

            # Enrich each finding with analysis data from the analysis endpoint
            for finding in findings:
                component_uuid = finding.get("component", {}).get("uuid")
                vulnerability_uuid = finding.get("vulnerability", {}).get("uuid")

                if component_uuid and vulnerability_uuid:
                    try:
                        analysis = await self.get_analysis(
                            project_uuid, component_uuid, vulnerability_uuid
                        )
                        # Merge analysis data into finding
                        if analysis:
                            finding["analysis"] = analysis
                    except Exception:
                        # If analysis doesn't exist or fails, continue with existing data
                        pass

            return findings

    async def get_project_vulnerabilities(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a specific project version with full details (including vectors).
        Uses /api/v1/vulnerability/project/{project_uuid}
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/vulnerability/project/{project_uuid}",
                headers=self.headers,
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
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/analysis",
                params={
                    "project": project_uuid,
                    "component": component_uuid,
                    "vulnerability": vulnerability_uuid,
                },
                headers=self.headers,
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

        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}/api/v1/analysis", json=payload, headers=self.headers
            )
            # 404 is sometimes returned if analysis doesn't exist yet? No, PUT creates/updates.
            response.raise_for_status()
            return response.json()


class DTSettings(BaseSettings):
    DTVP_API_URL: str = Field(alias="DTVP_API_URL", default="http://localhost:8081")
    DTVP_API_KEY: str = Field(alias="DTVP_API_KEY", default="change_me")

    # Support aliases from docker-compose.yml
    DEPENDENCY_TRACK_URL: Optional[str] = Field(default=None)
    DEPENDENCY_TRACK_API_KEY: Optional[str] = Field(default=None)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def api_url(self) -> str:
        return self.DTVP_API_URL or self.DEPENDENCY_TRACK_URL or "http://localhost:8081"

    @property
    def api_key(self) -> str:
        return self.DTVP_API_KEY or self.DEPENDENCY_TRACK_API_KEY or "change_me"


def get_client() -> DTClient:
    settings = DTSettings()
    return DTClient(settings.api_url, settings.api_key)
