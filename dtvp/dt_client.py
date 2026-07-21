import asyncio
import json
import logging
import os
import threading
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .integration_auth import read_secret
from .vulnerability_backend import (
    BackendCapability,
    BackendDescriptor,
)

logger = logging.getLogger(__name__)


def _normalize_finding_analysis(finding: Dict[str, Any]) -> Dict[str, Any]:
    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        return finding

    normalized = dict(analysis)
    if "analysisState" not in normalized and normalized.get("state") is not None:
        normalized["analysisState"] = normalized["state"]
    if "analysisDetails" not in normalized and normalized.get("detail") is not None:
        normalized["analysisDetails"] = normalized["detail"]
    finding["analysis"] = normalized
    return finding


def _finding_matches_cve(finding: Dict[str, Any], cve_upper: str) -> bool:
    vulnerability = finding.get("vulnerability", {})
    if cve_upper in (vulnerability.get("vulnId") or "").upper():
        return True
    if cve_upper in (vulnerability.get("name") or "").upper():
        return True
    return any(
        isinstance(alias, str) and cve_upper in alias.upper()
        for alias_obj in vulnerability.get("aliases", [])
        if isinstance(alias_obj, dict)
        for alias in alias_obj.values()
    )


class DTClient:
    """Dependency-Track adapter for the vendor-neutral backend contract."""

    DEFAULT_CAPABILITIES = frozenset(
        {
            BackendCapability.PROJECT_SEARCH,
            BackendCapability.FINDING_READ,
            BackendCapability.SBOM_READ,
            BackendCapability.ASSESSMENT_READ,
            BackendCapability.ASSESSMENT_WRITE,
            BackendCapability.SBOM_UPLOAD,
            BackendCapability.PROJECT_CREATE,
            BackendCapability.DEPENDENCY_GRAPH,
            BackendCapability.AUDIT_HISTORY,
            BackendCapability.VEX_EXCHANGE,
        }
    )

    def __init__(
        self,
        base_url: str,
        api_key: str = None,
        *,
        backend_id: str = "dependency-track",
        label: str = "Dependency-Track",
    ):
        self.base_url = base_url.rstrip("/")
        self.descriptor = BackendDescriptor(
            id=backend_id,
            type="dependency-track",
            label=label,
            capabilities=self.DEFAULT_CAPABILITIES,
        )
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["X-Api-Key"] = api_key

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
        if self.client:
            await self.client.aclose()

    async def get_current_user_profile(self) -> Dict[str, Any]:
        """
        Get the profile of the currently authenticated user in DT.
        """
        response = await self.client.get(f"{self.base_url}/api/v1/user/me")
        response.raise_for_status()
        return response.json()

    async def get_projects(self, name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for projects by name.
        Handles pagination to retrieve ALL matching projects.

        If no name is provided, this will retrieve all projects (no name filter).
        """
        all_projects = []
        page_number = 1
        page_size = 100

        normalized = (name or "").strip()

        while True:
            params = {
                "excludeInactive": "true",
                "pageSize": page_size,
                "pageNumber": page_number,
            }
            if normalized:
                params["name"] = normalized

            response = await self.client.get(
                f"{self.base_url}/api/v1/project",
                params=params,
            )
            response.raise_for_status()
            projects = response.json()

            if not projects:
                break

            all_projects.extend(projects)

            # If we got fewer than page_size, we reached the end
            if len(projects) < page_size:
                break

            page_number += 1

        return all_projects

    async def get_project_versions(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all versions for a project.
        """
        # Placeholder as per original code
        pass

    async def find_project_by_name_version(
        self,
        name: str,
        version: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Find one active project version by exact name and version.
        """
        projects = await self.get_projects(name)
        for project in projects:
            if project.get("name") == name and (project.get("version") or "") == (
                version or ""
            ):
                return project
        return None

    async def upload_bom(
        self,
        bom: Dict[str, Any],
        *,
        project_uuid: Optional[str] = None,
        project_name: Optional[str] = None,
        project_version: Optional[str] = None,
        auto_create: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload a CycloneDX BOM to Dependency-Track.

        When project_uuid is omitted, projectName/projectVersion and autoCreate
        let Dependency-Track create the missing project version.
        """
        data: Dict[str, str] = {}
        if project_uuid:
            data["project"] = project_uuid
        else:
            if not project_name:
                raise ValueError("project_name is required when project_uuid is omitted")
            data["projectName"] = project_name
            data["projectVersion"] = project_version or ""
            data["autoCreate"] = "true" if auto_create else "false"

        bom_bytes = json.dumps(bom).encode("utf-8")
        response = await self.client.post(
            f"{self.base_url}/api/v1/bom",
            data=data,
            files={"bom": ("bom.json", bom_bytes, "application/json")},
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    async def wait_for_project_version(
        self,
        name: str,
        version: Optional[str],
        *,
        timeout_seconds: float = 30.0,
        interval_seconds: float = 1.0,
    ) -> Optional[Dict[str, Any]]:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while True:
            project = await self.find_project_by_name_version(name, version)
            if project:
                return project
            if asyncio.get_running_loop().time() >= deadline:
                return None
            await asyncio.sleep(interval_seconds)

    async def wait_for_project_findings(
        self,
        project_uuid: str,
        *,
        expected_min_findings: int = 0,
        timeout_seconds: float = 60.0,
        interval_seconds: float = 2.0,
    ) -> List[Dict[str, Any]]:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        latest: List[Dict[str, Any]] = []
        while True:
            latest = await self.get_vulnerabilities(project_uuid)
            if len(latest) >= expected_min_findings:
                return latest
            if asyncio.get_running_loop().time() >= deadline:
                return latest
            await asyncio.sleep(interval_seconds)

    async def get_vulnerabilities(
        self, project_uuid: str, cve: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all findings for a project version, including analysis data.

        Current Dependency-Track releases expose the complete audit snapshot as
        one Finding Packaging Format response. Older releases fall back to the
        list endpoint and enrich only findings whose assessment may have
        additional details.
        """
        export_url = f"{self.base_url}/api/v1/finding/project/{project_uuid}/export"
        try:
            export_response = await self.client.get(export_url)
            export_response.raise_for_status()
            export_payload = export_response.json()
            if not isinstance(export_payload, dict) or not isinstance(
                export_payload.get("findings"), list
            ):
                raise ValueError("Unexpected Dependency-Track findings export")
            findings = [
                _normalize_finding_analysis(finding)
                for finding in export_payload["findings"]
                if isinstance(finding, dict)
            ]
            if any(
                (
                    finding.get("analysis", {}).get("analysisState")
                    not in (None, "NOT_SET")
                )
                and "analysisDetails" not in finding.get("analysis", {})
                for finding in findings
                if isinstance(finding.get("analysis"), dict)
            ):
                raise ValueError(
                    "Dependency-Track findings export omits assessed finding details"
                )
            if cve:
                cve_upper = cve.upper()
                findings = [
                    finding
                    for finding in findings
                    if _finding_matches_cve(finding, cve_upper)
                ]
            return findings
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            logger.debug(
                "Dependency-Track findings export unavailable for %s; "
                "falling back to legacy findings API: %s",
                project_uuid,
                exc,
            )

        response = await self.client.get(
            f"{self.base_url}/api/v1/finding/project/{project_uuid}",
            params={"suppressed": "true"},
        )
        response.raise_for_status()
        payload = response.json()
        findings = payload if isinstance(payload, list) else []

        analysis_tasks = []
        findings_to_enrich = []
        filtered_findings = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding = _normalize_finding_analysis(finding)
            vulnerability = finding.get("vulnerability", {})
            if cve and not _finding_matches_cve(finding, cve.upper()):
                continue

            filtered_findings.append(finding)

            component_uuid = finding.get("component", {}).get("uuid")
            vulnerability_uuid = vulnerability.get("uuid")
            analysis = finding.get("analysis")
            analysis_state = (
                analysis.get("analysisState") or analysis.get("state")
                if isinstance(analysis, dict)
                else None
            )
            analysis_details_present = isinstance(analysis, dict) and any(
                key in analysis for key in ("analysisDetails", "detail")
            )
            needs_enrichment = not isinstance(analysis, dict) or (
                analysis_state not in (None, "NOT_SET") and not analysis_details_present
            )

            if component_uuid and vulnerability_uuid and needs_enrichment:
                findings_to_enrich.append(finding)
                analysis_tasks.append(
                    self.get_analysis(project_uuid, component_uuid, vulnerability_uuid)
                )

        if analysis_tasks:
            # Execute analysis requests in batches to avoid overloading the client/connection pool
            # The client has a limit of 100 connections, so we batch safely below that.
            batch_size = 50
            results = []

            for i in range(0, len(analysis_tasks), batch_size):
                batch = analysis_tasks[i : i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                results.extend(batch_results)

            # Merge results
            for finding, analysis_result in zip(findings_to_enrich, results):
                if isinstance(analysis_result, Exception):
                    # Log error to help debugging
                    logger.error(
                        f"Error fetching analysis for finding {finding.get('uuid')}: {analysis_result}"
                    )
                    continue

                if analysis_result:
                    finding["analysis"] = analysis_result

        return filtered_findings

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

    async def finding_exists(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> bool:
        """Check an exact finding through a healthy Dependency-Track read."""
        response = await self.client.get(
            f"{self.base_url}/api/v1/finding/project/{project_uuid}",
            params={"suppressed": "true"},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("Unexpected Dependency-Track findings response")

        for finding in payload:
            if not isinstance(finding, dict):
                raise ValueError("Unexpected Dependency-Track finding entry")
            component = finding.get("component")
            vulnerability = finding.get("vulnerability")
            if not isinstance(component, dict) or not isinstance(
                vulnerability, dict
            ):
                raise ValueError("Dependency-Track finding identity is missing")
            found_component_uuid = str(component.get("uuid") or "").strip()
            found_vulnerability_uuid = str(
                vulnerability.get("uuid") or ""
            ).strip()
            if not found_component_uuid or not found_vulnerability_uuid:
                raise ValueError("Dependency-Track finding identity is missing")
            if (
                found_component_uuid == component_uuid
                and found_vulnerability_uuid == vulnerability_uuid
            ):
                return True
        return False

    async def get_bom(self, project_uuid: str) -> Dict[str, Any]:
        """
        Get project BOM in CycloneDX JSON format.
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/bom/cyclonedx/project/{project_uuid}",
            headers={"accept": "application/vnd.cyclonedx+json"},
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
        import time
        import random

        response = await self.client.get(
            f"{self.base_url}/api/v1/analysis",
            params={
                "project": project_uuid,
                "component": component_uuid,
                "vulnerability": vulnerability_uuid,
                "_t": f"{int(time.time() * 1000)}_{random.randint(0, 10000)}",  # Cache buster
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
        justification: Optional[str] = None,
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
        if justification:
            payload["analysisJustification"] = justification
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
    DTVP_DT_API_KEY: str = Field(alias="DTVP_DT_API_KEY", default="")
    DTVP_DT_API_KEY_FILE: Optional[str] = Field(
        alias="DTVP_DT_API_KEY_FILE", default=None
    )
    DTVP_DT_IMPORT_API_KEY: str = Field(
        alias="DTVP_DT_IMPORT_API_KEY",
        default="",
    )
    DTVP_DT_IMPORT_API_KEY_FILE: Optional[str] = Field(
        alias="DTVP_DT_IMPORT_API_KEY_FILE",
        default=None,
    )

    # Support aliases from the deployment compose file
    DEPENDENCY_TRACK_URL: Optional[str] = Field(default=None)
    DEPENDENCY_TRACK_API_KEY: Optional[str] = Field(default=None)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def api_url(self) -> str:
        # Priority: DTVP_DT_API_URL > DEPENDENCY_TRACK_URL > default
        return (
            self.DTVP_DT_API_URL or self.DEPENDENCY_TRACK_URL or "http://localhost:8081"
        )

    @property
    def api_key(self) -> str:
        # Direct values remain supported for local use; production Compose
        # mounts secret files so credentials are absent from container metadata.
        direct = str(self.DTVP_DT_API_KEY or "").strip()
        if direct.lower() in {"change_me", "changeme", "changeit"}:
            direct = ""
        return read_secret(direct, self.DTVP_DT_API_KEY_FILE) or str(
            self.DEPENDENCY_TRACK_API_KEY or ""
        ).strip()

    @property
    def import_api_key(self) -> str:
        return read_secret(
            self.DTVP_DT_IMPORT_API_KEY,
            self.DTVP_DT_IMPORT_API_KEY_FILE,
        )


class SharedDTClientProvider:
    """Own the API-key client used by request dependencies for one app lifetime."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._client: DTClient | None = None
        self._settings_key: tuple[str, str] | None = None

    async def get(self, base_url: str, api_key: str) -> DTClient:
        settings_key = (base_url.rstrip("/"), api_key)
        previous: DTClient | None = None
        with self._lock:
            if self._client is not None and self._settings_key == settings_key:
                return self._client
            previous = self._client
            self._client = DTClient(base_url, api_key=api_key)
            self._settings_key = settings_key
            client = self._client
        if previous is not None:
            await previous.close()
        return client

    async def close(self) -> None:
        with self._lock:
            client = self._client
            self._client = None
            self._settings_key = None
        if client is not None:
            await client.close()


_shared_dt_client_provider = SharedDTClientProvider()


def validate_dependency_track_configuration(
    settings: DTSettings | None = None,
    *,
    environment: str | None = None,
) -> None:
    active = settings or DTSettings()
    profile = (environment or os.getenv("DTVP_ENVIRONMENT", "production")).lower()
    if profile != "production":
        return
    key = active.api_key
    if not key or key.lower() in {"change_me", "changeme", "changeit"}:
        raise RuntimeError(
            "DTVP_DT_API_KEY or DTVP_DT_API_KEY_FILE is required in production"
        )
    if len(key) < 16:
        raise RuntimeError(
            "The production Dependency-Track service API key is unexpectedly short"
        )


async def get_client() -> AsyncGenerator[DTClient, None]:
    settings = DTSettings()
    yield await _shared_dt_client_provider.get(
        settings.api_url,
        settings.api_key,
    )


async def close_shared_dt_client() -> None:
    await _shared_dt_client_provider.close()
