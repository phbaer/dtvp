"""User/CI declarations bind inputs; they never establish provider authenticity."""

from typing import Literal

from pydantic import field_validator

from dtvp.knowledge.journal import Name, Sha
from dtvp.schemas import RequestModel


class SubjectDeclaration(RequestModel):
    """Same-build declaration tied to exact original SBOM bytes, not binary hashes.

    The caller must authorize the supplied product/version against its intake
    target. Model fields are declared metadata, never authenticated actor identity.
    """

    format: Literal["dtvp.subject-declaration/1"] = "dtvp.subject-declaration/1"
    product_id: Name
    version: Name
    part_id: Name | None = None
    subject_id: Name
    build_id: Name
    authority_sbom_sha256: Sha
    observation_sbom_sha256: Sha

    @field_validator("product_id", "version", "part_id", "subject_id", "build_id")
    @classmethod
    def meaningful(cls, value):
        if value is not None and not value.strip():
            raise ValueError("Subject declaration identifiers must be meaningful")
        return value


def declaration_reasons(declaration, baselines):
    """Validate observable bindings; external intake supplies product authorization."""
    reasons = []
    for baseline, expected in zip(
        baselines,
        (declaration.authority_sbom_sha256, declaration.observation_sbom_sha256),
        strict=True,
    ):
        if baseline.get("artifact_sha") != expected:
            reasons.append("subject_declaration_sbom_changed")
        if baseline.get("part_id") != declaration.part_id:
            reasons.append("subject_declaration_part_changed")
        if baseline.get("product_version") not in (None, declaration.version):
            reasons.append("subject_declaration_version_changed")
    return sorted(set(reasons))
