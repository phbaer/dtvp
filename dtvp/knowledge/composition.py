"""Producer-declared collection scope, distinct from verified coverage."""

from typing import Annotated, Literal

from pydantic import Field

from dtvp.knowledge.journal import Name
from dtvp.schemas import RequestModel

Coverage = Literal["unknown", "partial", "reported_complete"]
ArtifactDigest = Annotated[str, Field(pattern=r"^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$")]
NORMALIZER_VERSION = "dtvp.composition/1"


class CollectionContext(RequestModel):
    subject_kind: Literal[
        "unknown", "source", "build", "binary", "container", "filesystem", "assembly"
    ] = "unknown"
    subject_digest: ArtifactDigest | None = None
    target: Name | None = None
    platform: Name | None = None
    configuration: Name | None = None
    source_revision: Name | None = None
    pipeline_run: Name | None = None
    collector: Name | None = None
    collector_version: Name | None = None
    method: Literal[
        "unknown",
        "manifest",
        "build",
        "source_scan",
        "binary_scan",
        "container_scan",
        "combined",
        "assembly",
    ] = "unknown"
    package_coverage: Coverage = "unknown"
    dependency_coverage: Coverage = "unknown"
    license_coverage: Coverage = "unknown"
    limitations: list[Annotated[str, Field(min_length=1, max_length=2000)]] = Field(
        default_factory=list, max_length=100
    )

    def boundary(self):
        """Artifact/run change per build; these fields identify its declared scope."""
        return (self.subject_kind, self.target, self.platform, self.configuration)


def collection_summary(document, context):
    original = document.get("source_document", document["bom"])
    if document["format"] == "spdx-2.3-json":
        graph_reported = any(
            relation.get("relationshipType") in {"DEPENDS_ON", "DEPENDENCY_OF"}
            for relation in original.get("relationships", [])
        )
    else:
        graph_reported = "dependencies" in original
    return {
        "normalizer": NORMALIZER_VERSION,
        "snapshot_completeness": "producer_declared_complete_within_scope",
        "collection": context.model_dump(mode="json"),
        # Empty and absent graphs have different evidence semantics. Even a
        # present graph does not prove it includes every dependency edge.
        "dependency_graph": "reported" if graph_reported else "not_reported",
        "coverage_verification": "not_verified",
    }


def relationships(document):
    """Keep source relationship kinds; containment is not a dependency edge."""
    if document["format"] == "spdx-2.3-json":
        return [
            {
                "from": item["spdxElementId"],
                "to": item["relatedSpdxElement"],
                "kind": item["relationshipType"],
                "origin": "spdx",
            }
            for item in document["source_document"].get("relationships", [])
            if all(
                item.get(key) for key in ("spdxElementId", "relatedSpdxElement", "relationshipType")
            )
        ]
    result = [
        {"from": item["ref"], "to": child, "kind": "DEPENDS_ON", "origin": "cyclonedx"}
        for item in document["bom"].get("dependencies", [])
        for child in item.get("dependsOn", [])
    ]

    def visit(items):
        for parent in items:
            for child in parent.get("components", []):
                result.append(
                    {
                        "from": parent["bom-ref"],
                        "to": child["bom-ref"],
                        "kind": "CONTAINS",
                        "origin": "cyclonedx",
                    }
                )
            visit(parent.get("components", []))

    visit(document["bom"].get("components", []))
    return result


def dependency_edges(document, relations):
    if document["format"] != "spdx-2.3-json":
        return document["bom"].get("dependencies", [])
    by_parent = {}
    for item in relations:
        left, right = item["from"], item["to"]
        if item["kind"] == "DEPENDENCY_OF":
            left, right = right, left
        elif item["kind"] != "DEPENDS_ON":
            continue
        by_parent.setdefault(left, set()).add(right)
    return [
        {"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(by_parent.items())
    ]
