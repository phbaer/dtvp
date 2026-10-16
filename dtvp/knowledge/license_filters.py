"""Presentation selection over pinned source facts and current human approvals."""

from typing import Literal

from pydantic import Field

from dtvp.schemas import RequestModel


class LicenseFilters(RequestModel):
    q: str = Field(default="", max_length=500)
    evidence_status: Literal[
        "", "reported", "explicit_none", "unknown", "not_reported", "malformed"
    ] = ""
    review_status: Literal[
        "",
        "unassessed",
        "absent",
        "approved",
        "out_of_scope",
        "stale",
        "changes_requested",
        "draft",
        "submitted",
        "pending",
    ] = ""
    approved_disposition: Literal[
        "", "allowed", "restricted", "prohibited", "unresolved", "missing"
    ] = ""

    def matches(self, row):
        review = row["license_review"]
        approved = review.get("approved_assessment") if review.get("approved") else None
        disposition = approved["payload"].get("disposition", "missing") if approved else "missing"
        if self.evidence_status and row["evidence"]["status"] != self.evidence_status:
            return False
        if self.review_status == "pending":
            if not review.get("pending"):
                return False
        elif self.review_status and review["status"] != self.review_status:
            return False
        if self.approved_disposition and disposition != self.approved_disposition:
            return False

        # Search attributed values, never schema field names or inferred terms.
        def text(value):
            if isinstance(value, str):
                return value
            if isinstance(value, dict):
                return " ".join(text(item) for item in value.values())
            if isinstance(value, list):
                return " ".join(text(item) for item in value)
            return ""

        return (
            not self.q.strip()
            or self.q.strip().casefold()
            in text(
                {
                    key: row.get(key)
                    for key in (
                        "component_ref",
                        "component",
                        "origin",
                        "source",
                        "evidence",
                        "license_review",
                    )
                }
            ).casefold()
        )
