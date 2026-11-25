import httpx
import asyncio
import os
import logging
import json
import threading
from typing import List, Dict, Any, Optional, AsyncGenerator, Callable
from urllib.parse import quote
from fastapi import Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .fixed_versions import slim_affected_components

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
    # How the UI names this source (ports.AnalysisTrigger).
    source_display_name = "Dependency-Track"

    @staticmethod
    def vulnerability_ids(item: Any) -> set:
        """Every id of a finding's or vulnerability record's vulnerability,
        upper case: ``vulnId``, ``name`` and the values of ``aliases``
        (``VulnerabilityIdentifiers`` in ``ports``)."""
        if not isinstance(item, dict):
            return set()
        vulnerability = item.get("vulnerability") if "vulnerability" in item else item
        if not isinstance(vulnerability, dict):
            return set()
        ids = {
            value.strip().upper()
            for value in (vulnerability.get("vulnId"), vulnerability.get("name"))
            if isinstance(value, str) and value.strip()
        }
        for alias in vulnerability.get("aliases") or []:
            if isinstance(alias, dict):
                ids.update(
                    value.strip().upper()
                    for value in alias.values()
                    if isinstance(value, str) and value.strip()
                )
        return ids

    @staticmethod
    def vulnerability_reference(item: Any):
        """The vulnerability UUID and ``vulnId`` of a finding or a
        vulnerability record (``VulnerabilityIdentifiers`` in ``ports``)."""
        if not isinstance(item, dict):
            return None
        vulnerability = item.get("vulnerability") if "vulnerability" in item else item
        if not isinstance(vulnerability, dict):
            return None
        uuid, vuln_id = vulnerability.get("uuid"), vulnerability.get("vulnId")
        if isinstance(uuid, str) and uuid and isinstance(vuln_id, str) and vuln_id:
            return uuid, vuln_id
        return None

    @staticmethod
    def vulnerability_facts(item: Any):
        """What a finding or vulnerability record tells of its vulnerability
        for telling two records of one issue apart: ``uuid``, ``vuln_id``,
        ``source``, ``description`` and the CWE ids (``VulnerabilityFacts``
        in ``ports``)."""
        if not isinstance(item, dict):
            return None
        vulnerability = item.get("vulnerability") if "vulnerability" in item else item
        if not isinstance(vulnerability, dict) or not vulnerability.get("uuid"):
            return None
        cwes = []
        for cwe in vulnerability.get("cwes") or []:
            value = cwe.get("cweId") if isinstance(cwe, dict) else cwe
            if str(value or "").isdigit():
                cwes.append(int(value))
        return {
            "uuid": str(vulnerability["uuid"]),
            "vuln_id": vulnerability.get("vulnId"),
            "source": vulnerability.get("source"),
            "description": vulnerability.get("description") or "",
            "cwes": cwes,
        }

    def __init__(
        self,
        base_url: str,
        api_key: str = None,
        token: str = None,
        cookies: dict = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["X-Api-Key"] = api_key
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        # Create a persistent client with increased timeout and connection limits
        self.client = httpx.AsyncClient(
            headers=self.headers,
            cookies=cookies,
            timeout=60.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )

    async def close(self):
        await self.client.aclose()

    def add_request_hook(self, hook) -> None:
        """Run ``await hook()`` before every HTTP request, pages and retries
        included: the sync scheduler's request budget (ADR 0004, "Limits")
        counts requests, not method calls."""

        async def before(_request: httpx.Request) -> None:
            await hook()

        self.client.event_hooks["request"] = [
            *self.client.event_hooks.get("request", []),
            before,
        ]

    async def ping(self) -> bool:
        """One cheap request: whether Dependency-Track answers. The circuit
        breaker's probe."""
        response = await self.client.get(f"{self.base_url}/api/version")
        response.raise_for_status()
        return True

    async def request_analysis(self, project_uuid: str) -> Optional[str]:
        """Ask Dependency-Track to analyse a project version again
        (``POST /api/v1/finding/project/{uuid}/analyze``, Dependency-Track
        4.x ``FindingResource.analyzeProject``; needs the
        ``VIEW_VULNERABILITY`` permission in 4.14.x). Returns the event token
        Dependency-Track answers with (``{"token": ...}``), or ``None``."""
        response = await self.client.post(
            f"{self.base_url}/api/v1/finding/project/{project_uuid}/analyze"
        )
        response.raise_for_status()
        try:
            token = response.json().get("token")
        except (ValueError, AttributeError):
            return None
        return str(token) if token else None

    async def analysis_running(self, token: str) -> bool:
        """Whether the analysis behind ``token`` is still being processed
        (``GET /api/v1/event/token/{token}`` answers ``{"processing": ...}``,
        ``EventResource.isTokenBeingProcessed``)."""
        response = await self.client.get(f"{self.base_url}/api/v1/event/token/{token}")
        response.raise_for_status()
        try:
            return bool(response.json().get("processing"))
        except (ValueError, AttributeError):
            return False

    async def portfolio_findings(
        self,
        *,
        page_size: int = 1000,
        on_page: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """``BulkFindings`` (dtvp/ports.py): every finding of every active
        project version, by project UUID, from ``GET /api/v1/finding``
        (Dependency-Track 4.x ``FindingResource.getAllFindings``, permission
        ``VIEW_VULNERABILITY``; Alpine paging with ``pageNumber`` and
        ``pageSize``, the total in ``X-Total-Count``). Inactive projects are
        left out (``showInactive=false``, the default), suppressed findings
        are included. Each finding is ``Finding.QUERY_ALL_FINDINGS``'s shape:
        the component (with its project UUID under ``project``), the
        vulnerability, the attribution and the analysis (``state``,
        ``isSuppressed``, ``detail``). Every page is one HTTP request, so a
        budget hook pays for each."""
        by_project: Dict[str, List[Dict[str, Any]]] = {}
        page_number = 1
        read = 0
        total: Optional[int] = None
        while True:
            response = await self.client.get(
                f"{self.base_url}/api/v1/finding",
                params={
                    "pageNumber": page_number,
                    "pageSize": page_size,
                    "showInactive": "false",
                    "showSuppressed": "true",
                },
            )
            response.raise_for_status()
            page = response.json()
            if total is None:
                try:
                    total = int(response.headers.get("X-Total-Count"))
                except (TypeError, ValueError):
                    total = None
            if not isinstance(page, list):
                raise TypeError("Unexpected findings page")
            for finding in page:
                component = finding.get("component") if isinstance(finding, dict) else None
                project = (component or {}).get("project")
                if project:
                    by_project.setdefault(str(project), []).append(finding)
            read += len(page)
            if on_page is not None:
                pages = (
                    max(1, -(-total // page_size)) if total is not None else page_number
                )
                on_page(page_number, pages)
            if not page or len(page) < page_size or (total is not None and read >= total):
                break
            page_number += 1
        return by_project

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

    def change_hint_kinds(self) -> tuple[str, ...]:
        """``ChangeHints`` (dtvp/ports.py): the last BOM import and the last
        vulnerability analysis of each project version."""
        return ("bom", "analysis")

    @staticmethod
    def _with_source_marks(project: Dict[str, Any]) -> Dict[str, Any]:
        """Add ``dtvpSourceMarks``: a value that changes whenever
        Dependency-Track's data for the version changes (a BOM upload or a
        new analysis). Generic code compares it without knowing the fields."""
        if isinstance(project, dict):
            project["dtvpSourceMarks"] = {
                "bom": project.get("lastBomImport"),
                "analysis": project.get("lastVulnerabilityAnalysis"),
            }
        return project

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

            all_projects.extend(self._with_source_marks(project) for project in projects)

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
        self,
        project_uuid: str,
        cve: Optional[str] = None,
        *,
        analysis_details: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Get all findings for a project version, including analysis data.

        With ``analysis_details=False`` only the findings list is read: each
        analysis then holds its state and suppression, and the caller reads
        the details of the findings it needs (``get_analysis``). The sync
        does this, so an unchanged assessed finding costs no request.

        Current Dependency-Track releases expose the complete audit snapshot as
        one Finding Packaging Format response. Older releases fall back to the
        list endpoint and enrich only findings whose assessment may have
        additional details.
        """
        export_url = f"{self.base_url}/api/v1/finding/project/{project_uuid}/export"
        try:
            if not analysis_details:
                raise ValueError("details not wanted; the findings list suffices")
            if getattr(self, "_export_lacks_details", False):
                # Known from an earlier read: this server's export never
                # carries the details (Dependency-Track 4.x builds it from
                # ``Finding``, whose analysis is only state and suppression),
                # so asking for it again only costs a request.
                raise ValueError("Dependency-Track findings export omits details")
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
                self._export_lacks_details = True
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

        analysis_keys: list[tuple[str, str]] = []
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

            if analysis_details and component_uuid and vulnerability_uuid and needs_enrichment:
                findings_to_enrich.append(finding)
                analysis_keys.append((component_uuid, vulnerability_uuid))

        if analysis_keys:
            # Execute analysis requests in batches to avoid overloading the client/connection pool
            # The client has a limit of 100 connections, so we batch safely below that.
            batch_size = 50
            results = []

            # The requests of a batch are created only when it runs: created
            # all up front, those of later batches were never awaited when an
            # earlier one was cancelled (RuntimeWarning "coroutine
            # 'DTClient.get_analysis' was never awaited").
            for i in range(0, len(analysis_keys), batch_size):
                batch = [
                    self.get_analysis(project_uuid, component_uuid, vulnerability_uuid)
                    for component_uuid, vulnerability_uuid in analysis_keys[i : i + batch_size]
                ]
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

    async def get_vulnerability_affected(
        self, source: str, vuln_id: str
    ) -> Optional[Dict[str, Any]]:
        """The affected version ranges Dependency-Track holds for one
        vulnerability, as ``{"affectedComponents": [...]}``, or None when it
        does not know the vulnerability.

        Uses ``/api/v1/vulnerability/source/{source}/vuln/{vulnId}``
        (permission VIEW_PORTFOLIO). Its answer also lists the components of
        every project the vulnerability affects; only the slim
        ``affectedComponents`` leave this method.
        """
        response = await self.client.get(
            f"{self.base_url}/api/v1/vulnerability/source/"
            f"{quote(str(source), safe='')}/vuln/{quote(str(vuln_id), safe='')}",
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("Unexpected Dependency-Track vulnerability response")
        return {"affectedComponents": slim_affected_components(body.get("affectedComponents"))}

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
        if response.status_code == 404 and await self._project_is_gone(project_uuid):
            # The whole project was deleted, and its findings with it.
            return False
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

    async def _project_is_gone(self, project_uuid: str) -> bool:
        """Whether Dependency-Track positively reports that a project does
        not exist.

        A 404 alone could also come from a wrong base URL or a proxy. It
        only counts when the project lookup answers 404 as well while the
        same API answers an unrelated request normally.
        """
        project = await self.client.get(f"{self.base_url}/api/v1/project/{project_uuid}")
        if project.status_code != 404:
            return False
        control = await self.client.get(f"{self.base_url}/api/version")
        if control.status_code != 200:
            return False
        try:
            body = control.json()
        except ValueError:
            return False
        return isinstance(body, dict) and "version" in body

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

    # Dependency-Track records a changed analysis text as a comment
    # "Details: <new text>" (AnalysisCommentUtil.makeDetailsCommentIfChanged,
    # 4.x); the comments come with the analysis, oldest first.
    _DETAILS_COMMENT_PREFIX = "Details: "

    async def get_assessment_history(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> list[Dict[str, Any]]:
        """The texts the finding's analysis held, from its audit trail."""
        analysis = await self.get_analysis(project_uuid, component_uuid, vulnerability_uuid)
        if not isinstance(analysis, dict):
            return []
        history: list[Dict[str, Any]] = []
        for comment in analysis.get("analysisComments") or []:
            if not isinstance(comment, dict):
                continue
            text = comment.get("comment")
            if not isinstance(text, str) or not text.startswith(self._DETAILS_COMMENT_PREFIX):
                continue
            timestamp = comment.get("timestamp")
            history.append({
                "at": int(timestamp) if isinstance(timestamp, (int, float)) else None,
                "author": comment.get("commenter") or None,
                "details": text[len(self._DETAILS_COMMENT_PREFIX):],
            })
        current = analysis.get("analysisDetails")
        if isinstance(current, str) and current.strip():
            history.append({"at": None, "author": None, "details": current})
        return history

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
        response: Optional[str] = None,
    ):
        """
        Update analysis for a finding.

        ``response`` is always written: without one Dependency-Track is told
        ``NOT_SET``, so a response removed in River is removed there as well.
        """
        payload = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
            "analysisState": state,
            "isSuppressed": suppressed,
            "analysisDetails": details,
            "analysisResponse": response or "NOT_SET",
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
    DTVP_DT_API_KEY: str = Field(alias="DTVP_DT_API_KEY", default="change_me")
    DTVP_DT_API_KEY_FILE: Optional[str] = Field(
        alias="DTVP_DT_API_KEY_FILE", default=None
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
        # Priority: DTVP_DT_API_KEY > DTVP_DT_API_KEY_FILE > DEPENDENCY_TRACK_API_KEY > default
        key = self.DTVP_DT_API_KEY
        if key == "change_me" and self.DTVP_DT_API_KEY_FILE:
            if os.path.exists(self.DTVP_DT_API_KEY_FILE):
                with open(self.DTVP_DT_API_KEY_FILE, "r") as f:
                    key = f.read().strip()

        if key == "change_me":
            key = self.DEPENDENCY_TRACK_API_KEY or "change_me"

        return key


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


async def get_shared_client() -> DTClient:
    """The application-lifetime API-key client, for callers without a request."""
    settings = DTSettings()
    return await _shared_dt_client_provider.get(
        settings.api_url,
        settings.api_key,
    )


async def get_client(request: Request) -> AsyncGenerator[DTClient, None]:
    yield await get_shared_client()


async def close_shared_dt_client() -> None:
    await _shared_dt_client_provider.close()
