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
        """Project versions, optionally filtered by name.

        Each version may carry ``dtvpSourceMarks``, an opaque value that
        changes whenever the source's data for the version changes (for
        Dependency-Track: a BOM upload or a new analysis). Without it,
        changes are only noticed by reading the version again.
        """

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
class AssessmentHistorySource(Protocol):
    """The texts a finding's assessment held over time, where the source
    records them. Optional, like ``AffectedVersionSource``: used to restore
    team assessments that DTVP no longer has (docs/review-workflows.md)."""

    async def get_assessment_history(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> list[dict[str, Any]]:
        """``[{"at": epoch ms or None, "author": str or None, "details": str}]``,
        oldest first, the current text last; empty when the source has no
        assessment of the finding. Raises on other failures."""


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
class BudgetedTransport(Protocol):
    """Optional: a source that lets the sync scheduler count every HTTP
    request against its budget, and answer a cheap health probe (ADR 0004,
    "Limits"). Without it, the scheduler counts method calls and probes
    with ``get_projects``."""

    def add_request_hook(self, hook: Any) -> None:
        """Run ``await hook()`` before every request."""

    async def ping(self) -> bool:
        """One cheap request; raises when the source does not answer."""


@runtime_checkable
class VulnerabilityIdentifiers(Protocol):
    """Optional: the ids under which one vulnerability is known (its own id
    and its aliases, for example a CVE and its GitHub advisory), read from a
    finding or a vulnerability record as the source stores them."""

    @staticmethod
    def vulnerability_ids(item: Any) -> set[str]:
        """Every id of the item's vulnerability, upper case; empty when the
        item is not one of the source's findings or records."""

    @staticmethod
    def vulnerability_reference(item: Any) -> tuple[str, str] | None:
        """The item's vulnerability UUID and its own id (as the source names
        it), or ``None``."""


class VulnerabilityFacts(Protocol):
    """Optional: what a stored finding or vulnerability record tells of its
    vulnerability, so DTVP can guess that two records without an alias are
    one issue (``dtvp/same_issue.py``): the same description, or the same
    affected range and CWE. A source without it gets no such guesses."""

    @staticmethod
    def vulnerability_facts(item: Any) -> dict[str, Any] | None:
        """``uuid``, ``vuln_id``, ``source``, ``description`` and ``cwes``
        (CWE ids as integers) of the item's vulnerability; ``None`` when the
        item is not one of the source's findings or records."""


@runtime_checkable
class ChangeHints(Protocol):
    """Optional: the source tells, per project version, when its data
    changed, so unchanged versions are not read again (ADR 0004, "Change
    hints are optional"). It puts the hints under ``dtvpSourceMarks`` in
    ``get_projects`` and names their kinds here:

    - ``"bom"``: the components changed; every kind is read again;
    - ``"analysis"``: the findings or vulnerability records may have changed.

    Without it, versions are read again on a regular schedule and changes
    are found by comparing content digests."""

    def change_hint_kinds(self) -> tuple[str, ...]:
        """The hint kinds this source provides."""


def change_hint(project: Any, kind: str) -> Any:
    """One change hint of a project version (``ChangeHints``), or ``None``
    when the source gives none."""
    marks = project.get("dtvpSourceMarks") if isinstance(project, dict) else None
    return marks.get(kind) if isinstance(marks, dict) else None


@runtime_checkable
class SourceAndSink(VulnerabilitySource, AssessmentSink, Protocol):
    """A system DTVP both imports from and exports to."""
