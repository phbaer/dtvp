"""Pure filters over attributed v3 reviewer rows, before counts and pagination.

These filters describe evidence and workflow; missing information never becomes
an applicability conclusion, a low severity or proof of independent corroboration.
"""

import math
from collections import defaultdict
from typing import Literal

from pydantic import Field, field_validator

from dtvp.schemas import RequestModel

Band = Literal["", "critical", "high", "medium", "low", "none", "unknown"]
EvidenceFilter = Literal["", "missing", "current", "historical_only", "eligible"]
VERSIONS = {
    "CVSS:4.0/": "4.0",
    "CVSS:3.1/": "3.1",
    "CVSS:3.0/": "3.0",
    "CVSS:2.0/": "2.0",
    "CVSS2#": "2.0",
}
METHODS = {
    "CVSSv4": "4.0",
    "CVSSv40": "4.0",
    "CVSSv31": "3.1",
    "CVSSv3": "3.0",
    "CVSSv30": "3.0",
    "CVSSv2": "2.0",
    "CVSSv20": "2.0",
}


def numeric_score(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 10
    )


def severity(score):
    if not numeric_score(score):
        return "unknown"
    return (
        "critical"
        if score >= 9
        else "high"
        if score >= 7
        else "medium"
        if score >= 4
        else "low"
        if score > 0
        else "none"
    )


def source_severity(row):
    ratings = row.get("source_ratings", [])
    scores = [item["score"] for item in ratings if numeric_score(item.get("score"))]
    if scores:
        return severity(max(scores))
    bands = ("unknown", "none", "low", "medium", "high", "critical")
    return max(
        (
            str(item.get("severity", "unknown")).lower()
            for item in ratings
            if str(item.get("severity", "unknown")).lower() in bands
        ),
        key=bands.index,
        default="unknown",
    )


def scoring_status(row):
    score = row.get("published_score")
    if score is None:
        return "not_published"
    return (
        "published"
        if score.get("current") is True
        else "outdated"
        if score.get("current") is False
        else "unknown"
    )


def current_applicability(row):
    coverage = row.get("coverage", {})
    if coverage.get("status") == "unassessed":
        return "unassessed"
    if coverage.get("status") not in {"approved", "draft", "submitted"}:
        return "unknown"
    if coverage.get("approved"):
        record = coverage.get("approved_assessment")
        if not record:
            candidate = coverage.get("assessment") or {}
            record = (
                candidate
                if coverage.get("assessment_revision") is not None
                and candidate.get("revision") == coverage.get("assessment_revision")
                else None
            )
    else:
        record = coverage.get("assessment")
    state = (record or {}).get("payload", {}).get("state")
    return (
        state
        if state in {"affected", "not_affected", "fixed", "under_investigation"}
        else "unknown"
    )


def rating_versions(rating):
    """Reported method/prefix, not validation of a vector or its score."""
    versions = set()
    vector = rating.get("vector", "")
    if isinstance(vector, str):
        versions.update(
            version for prefix, version in VERSIONS.items() if vector.startswith(prefix)
        )
        # CVSS v2 commonly has an unprefixed vector. Require its explicit method.
    method = rating.get("method")
    if isinstance(method, str) and (version := METHODS.get(method)):
        versions.add(version)
    return versions


def source_conflict(row):
    """Discrepancies within comparable source CVSS ratings, never contextual scores.

    Versions are separate scales. Different versions alone do not establish a
    contradiction; absent comparable evidence stays unknown.
    """
    groups = defaultdict(lambda: {"scores": set(), "vectors": set()})
    observed = False
    for rating in row.get("source_ratings", []):
        versions = rating_versions(rating)
        if len(versions) > 1:
            return "yes"  # Method and vector prefix disagree within one rating.
        if not versions:
            continue
        observed |= numeric_score(rating.get("score")) or bool(
            isinstance(rating.get("vector"), str) and rating["vector"].strip()
        )
        group = groups[next(iter(versions))]
        if numeric_score(rating.get("score")):
            group["scores"].add(rating["score"])
        if isinstance(rating.get("vector"), str) and rating["vector"].strip():
            # Metric ordering does not create a source discrepancy.
            group["vectors"].add(tuple(sorted(rating["vector"].split("/"))))
    if any(len(group["scores"]) > 1 or len(group["vectors"]) > 1 for group in groups.values()):
        return "yes"
    return "no" if observed else "unknown"


def provider_names(row):
    names = set()

    def add(value):
        if isinstance(value, str) and value.strip():
            names.add(value.strip().casefold())
        elif isinstance(value, dict):
            add(value.get("name"))
            add(value.get("url"))

    for rating in row.get("source_ratings", []):
        add(rating.get("source"))
        add(rating.get("observed_source"))
    for fact in row.get("sourcefacts", []):
        add(fact.get("source"))
        add(fact.get("advisory", {}).get("source"))
    for proposal in [*row.get("scoring_proposals", []), *row.get("code_analysis", [])]:
        add(proposal.get("provider"))
        add(proposal.get("source_label"))
    for claim in row.get("legacy_evidence", []):
        add(claim.get("source"))
    return names


def team_review_matches(row, value):
    coverage = row.get("coverage", {})
    status = coverage.get("status")
    if value == "missing":
        return not coverage.get("recorded")
    if value == "recorded":
        return bool(coverage.get("recorded"))
    if value == "current":
        return status in {"draft", "submitted", "approved"}
    if value == "approved":
        return bool(coverage.get("approved"))
    if value == "pending":
        return bool(coverage.get("pending_revision")) or (
            status == "submitted" and not coverage.get("approved")
        )
    if value == "needs_revalidation":
        return status == "reassessment_needed"
    if value == "changes_requested":
        review = coverage.get("review") or {}
        return (
            review.get("status") == "changes_requested"
            and review.get("target", {}).get("fingerprint") == coverage.get("fingerprint")
            and coverage.get("fingerprint") is not None
        )
    return status == value


def metadata_status(row):
    record = row.get("curated_metadata")
    if not record:
        return "missing"
    status = record.get("status")
    return status if status in {"current", "stale", "absent", "out_of_scope"} else "unknown"


def current_annotation(row, section, field, values):
    """Only an applicable annotation supplies a current fact; no date inference."""
    record = row.get("curated_metadata") or {}
    if metadata_status(row) != "current" or record.get("applicable") is not True:
        return "unknown"
    value = record.get("payload", {}).get("annotations", {}).get(section, {}).get(field)
    return value if value in values else "unknown"


def received_evidence_matches(row, provider, selected):
    key = "code_analysis" if provider == "agentyzer" else "scoring_proposals"
    records = row.get(key, [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        return False
    if provider == "vscorer":
        records = [item for item in records if item.get("provider") == "vscorer"]
    if selected == "missing":
        return not records
    if selected == "historical_only":
        return bool(records) and all(item.get("current") is False for item in records)
    if selected == "current":
        return any(item.get("current") is True for item in records)
    flag = "application_eligible" if provider == "agentyzer" else "eligible"
    return any(item.get("current") is True and item.get(flag) is True for item in records)


class KnowledgeFilters(RequestModel):
    ssvc_status: Literal["", "missing", "draft", "submitted", "approved", "pending", "stale"] = ""
    ssvc_action: Literal["", "DEFER", "SCHEDULED", "OUT_OF_CYCLE", "IMMEDIATE"] = ""
    agentyzer_evidence: EvidenceFilter = ""
    vscorer_evidence: EvidenceFilter = ""
    source_severity: Band = ""
    contextual_severity: Band = ""
    applicability: Literal[
        "", "affected", "not_affected", "fixed", "under_investigation", "unassessed", "unknown"
    ] = ""
    scoring_status: Literal["", "published", "outdated", "not_published", "unknown"] = ""
    team_review: Literal[
        "",
        "missing",
        "recorded",
        "current",
        "draft",
        "submitted",
        "pending",
        "approved",
        "needs_revalidation",
        "changes_requested",
    ] = ""
    provider: str = Field(default="", max_length=200)
    cvss_version: Literal["", "2.0", "3.0", "3.1", "4.0", "unknown"] = ""
    dependency: Literal["", "direct", "transitive", "root", "unknown"] = ""
    source_conflict: Literal["", "yes", "no", "unknown"] = ""
    component: str = Field(default="", max_length=500)
    criticality: Literal["", "unknown", "low", "moderate", "high", "critical"] = ""
    exposure: Literal["", "unknown", "not_exposed", "internal", "external"] = ""
    support_status: Literal["", "unknown", "supported", "unsupported", "internally_maintained"] = ""
    metadata_status: Literal[
        "", "missing", "current", "stale", "absent", "out_of_scope", "unknown"
    ] = ""

    @field_validator("dependency", mode="before")
    @classmethod
    def normalize_direct(cls, value):
        return "direct" if value == "known_direct" else value

    def matches(self, row):
        from dtvp.knowledge.ssvc import action

        ssvc = row.get("ssvc", {})
        if self.ssvc_status and ssvc.get("status", "missing") != self.ssvc_status:
            return False
        if self.ssvc_action and action(ssvc) != self.ssvc_action:
            return False
        for provider, selected in (
            ("agentyzer", self.agentyzer_evidence),
            ("vscorer", self.vscorer_evidence),
        ):
            if selected and not received_evidence_matches(row, provider, selected):
                return False
        if self.metadata_status and metadata_status(row) != self.metadata_status:
            return False
        for value, section, field, allowed in (
            (
                self.criticality,
                "cybersecurity",
                "criticality",
                {"low", "moderate", "high", "critical"},
            ),
            (self.exposure, "cybersecurity", "exposure", {"not_exposed", "internal", "external"}),
            (
                self.support_status,
                "support",
                "status",
                {"supported", "unsupported", "internally_maintained"},
            ),
        ):
            if value and current_annotation(row, section, field, allowed) != value:
                return False
        if self.source_severity and source_severity(row) != self.source_severity:
            return False
        current = row.get("published_score")
        contextual = (
            severity(current.get("score")) if scoring_status(row) == "published" else "unknown"
        )
        if self.contextual_severity and contextual != self.contextual_severity:
            return False
        if self.scoring_status and scoring_status(row) != self.scoring_status:
            return False
        if self.applicability and current_applicability(row) != self.applicability:
            return False
        if self.team_review and not team_review_matches(row, self.team_review):
            return False
        if self.provider and self.provider.casefold() not in provider_names(row):
            return False
        if self.cvss_version:
            versions = set().union(
                *(rating_versions(rating) for rating in row.get("source_ratings", []))
            )
            if (self.cvss_version == "unknown" and versions) or (
                self.cvss_version != "unknown" and self.cvss_version not in versions
            ):
                return False
        if self.dependency:
            relation = row.get("dependency_relation", "unknown")
            if (
                relation in {"direct", "transitive"}
                and row.get("context", {}).get("dependency_graph") != "reported"
            ):
                relation = "unknown"
            if relation != self.dependency:
                return False
        if self.source_conflict and source_conflict(row) != self.source_conflict:
            return False
        if self.component:
            component = row.get("component", {})
            values = [component.get(key) for key in ("name", "group", "purl", "version", "bom-ref")]
            if not any(
                self.component.casefold() in str(value).casefold()
                for value in values
                if value is not None
            ):
                return False
        return True


def filter_rows(rows, filters):
    """Retain row order/identity; never infer permissions or mutate input evidence."""
    filters = (
        filters
        if isinstance(filters, KnowledgeFilters)
        else KnowledgeFilters.model_validate(filters)
    )
    return [row for row in rows if filters.matches(row)]
