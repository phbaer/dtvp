"""What DTVP needs from the systems it exchanges data with (ADR 0002).

The local database is the system of record. A *source* is imported from; a
*sink* is exported to. Dependency-Track is both, through ``DTClient``. The
cache manager is written against these protocols, so another source or sink
only has to provide these methods; nothing else in DTVP depends on
Dependency-Track's API.

Assessments are exchanged as three fields per finding: state, details, and
whether the finding is suppressed. A finding is identified by the UUIDs of
its project, component, and vulnerability.
"""

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class VulnerabilitySource(Protocol):
    """Read access to projects, their findings, and current assessments."""

    async def get_projects(self, name: Optional[str] = None) -> list[dict[str, Any]]:
        """Project versions, optionally filtered by name."""

    async def get_vulnerabilities(
        self, project_uuid: str, cve: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Findings of one project version, each with its component,
        vulnerability, and current assessment under ``analysis``."""

    async def get_project_vulnerabilities(
        self, project_uuid: str
    ) -> list[dict[str, Any]]:
        """Full vulnerability records of one project version."""

    async def get_bom(self, project_uuid: str) -> Optional[dict[str, Any]]:
        """The CycloneDX BOM of one project version."""

    async def get_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[dict[str, Any]]:
        """The current assessment of one finding, or ``None`` if it has none."""


@runtime_checkable
class AffectedVersionSource(Protocol):
    """The affected version ranges a source holds per vulnerability.

    Kept apart from ``VulnerabilitySource``: a source without it still
    serves findings, and its VDR has no derived recommendation.
    """

    async def get_vulnerability_affected(
        self, source: str, vuln_id: str
    ) -> Optional[dict[str, Any]]:
        """``{"affectedComponents": [...]}`` with identity, version or
        bounds, and attribution sources per entry; ``None`` when the
        vulnerability is unknown. Raises on other failures."""


@runtime_checkable
class AssessmentSink(Protocol):
    """Write access for assessments made in DTVP."""

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
    ) -> Any:
        """Store an assessment. Raises on failure. ``response`` is the
        finding's analysis response; ``None`` means not set."""

    async def get_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> Optional[dict[str, Any]]:
        """Read back the assessment a write would replace."""

    async def finding_exists(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> bool:
        """Whether the finding still exists, checked after a rejected write."""


@runtime_checkable
class SourceAndSink(VulnerabilitySource, AssessmentSink, Protocol):
    """A system DTVP both imports from and exports to."""
