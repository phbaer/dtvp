"""Producer-qualified source inputs for an external Agentyzer orchestrator."""

import re
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.composition import AnalysisSource
from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

ComponentRef = Annotated[str, Field(min_length=1, max_length=4096)]


class AgentyzerSourceReceipt(RequestModel):
    format: Literal["dtvp.agentyzer-source/1"] = "dtvp.agentyzer-source/1"
    state: Sha
    project_id: Name
    version: Name
    context_id: Sha
    vulnerability_id: Name
    component_ref: ComponentRef
    root_ref: ComponentRef
    assessment_fingerprint: Sha
    focal_component: dict
    source_state: Sha | None = None
    part_id: Name | None = None
    sbom_sha256: Sha | None = None
    subject_digest: str | None = None
    analysis_source: AnalysisSource | None = None
    request_sha256: Sha | None = None
    source_verification: Literal["producer_declared_only"] = "producer_declared_only"
    repository_authorization: Literal["not_checked"] = "not_checked"
    build_binding_verified: Literal[False] = False
    binary_binding_verified: Literal[False] = False


def _components(inventory):
    values = {
        value["bom-ref"]: value
        for key, value in inventory.items()
        if key.startswith(("component:", "part-root:")) and value.get("bom-ref")
    }
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        values.setdefault(root["bom-ref"], root)
    return values


def _source(journal, revision, state, inventory, root, focal):
    baseline = inventory.get("baseline", {})
    if baseline.get("kind") != "assembly":
        origins = [root.get("dtvp_origin"), focal.get("dtvp_origin")]
        if any(origin is not None and not isinstance(origin, dict) for origin in origins):
            return None, None, None, ["component_origin_malformed"]
        if any(origin and origin.get("part_id") for origin in origins):
            return None, None, None, ["constituent_origin_without_assembly"]
        return baseline, state, None, []
    origins = [root.get("dtvp_origin"), focal.get("dtvp_origin")]
    if any(
        not isinstance(origin, dict) or not origin.get("part_id") or not origin.get("state")
        for origin in origins
    ):
        return None, None, None, ["consuming_root_or_focal_constituent_origin_missing"]
    root_origin, focal_origin = origins
    if any(root_origin.get(key) != focal_origin.get(key) for key in ("part_id", "state")):
        return None, None, None, ["consuming_root_and_focal_constituent_sources_differ"]
    parts = [
        part
        for part in inventory.get("assembly", {}).get("parts", [])
        if part.get("part_id") == root_origin["part_id"]
    ]
    if len(parts) != 1 or parts[0].get("state") != root_origin["state"]:
        return None, None, None, ["constituent_selection_missing_or_ambiguous"]
    part = parts[0]
    source_state = part["state"]
    if (
        not isinstance(source_state, str)
        or not re.fullmatch(r"[a-f0-9]{64}", source_state)
        or not journal.objects.path(source_state).is_file()
    ):
        return None, None, None, ["constituent_source_state_unavailable"]
    source_revision = journal.verify_state(source_state)
    if (
        source_revision.project_id != revision.project_id
        or source_revision.version != revision.version
    ):
        return None, None, None, ["constituent_source_product_version_mismatch"]
    source_inventory = load_sections(journal, source_state)["inventory"]
    source_baseline = source_inventory.get("baseline", {})
    if source_baseline != part.get("baseline") or source_baseline.get("part_id") != part["part_id"]:
        return None, None, None, ["constituent_manifest_source_mismatch"]
    originals = _components(source_inventory)
    for origin, component in ((root_origin, root), (focal_origin, focal)):
        original_ref = origin.get("ref")
        original = originals.get(original_ref) if isinstance(original_ref, str) else None
        if not original or any(
            original.get(key) != component.get(key) for key in ("name", "version", "purl")
        ):
            return None, None, None, ["constituent_component_origin_mismatch"]
    return source_baseline, source_state, part["part_id"], []


def derive_analysis_input(journal, state, context_id, vulnerability_id):
    """Prepare exact source inputs; do not authorize or submit an external run."""
    revision = journal.verify_state(state)
    sections = load_sections(journal, state)
    context = sections["ownership"].get("context:" + context_id)
    fingerprint = target_fingerprint(sections, revision.version, context_id, vulnerability_id)
    if not context or fingerprint is None:
        raise ValueError("Agentyzer target is absent from the selected consuming context")
    inventory = sections["inventory"]
    components = _components(inventory)
    root, focal = components.get(context["root_ref"]), components.get(context["component_ref"])
    if not root or not focal:
        raise ValueError("Agentyzer target inventory is missing its root or focal component")
    baseline, source_state, part_id, reasons = _source(
        journal, revision, state, inventory, root, focal
    )
    collection = baseline.get("collection", {}) if baseline else {}
    if not isinstance(collection, dict):
        collection = {}
        reasons.append("source_collection_metadata_invalid")
    qualified, sbom_sha = None, None
    if baseline is not None:
        candidate_sha = baseline.get("artifact_sha")
        if (
            not isinstance(candidate_sha, str)
            or not re.fullmatch(r"[a-f0-9]{64}", candidate_sha)
            or not journal.objects.path(candidate_sha).is_file()
        ):
            reasons.append("source_sbom_artifact_unavailable")
        else:
            sbom_sha = candidate_sha
            journal.objects.read(sbom_sha)
        try:
            qualified = AnalysisSource.model_validate(collection.get("analysis_source"))
        except ValidationError:
            reasons.append("qualified_analysis_source_missing_or_invalid")
    if not focal.get("version"):
        reasons.append("focal_component_version_unknown")
    if context.get("dependency_graph") != "reported":
        reasons.append("consuming_dependency_topology_unknown")
    request = None
    if qualified and not reasons:
        request = {
            "component_name": qualified.repository_name,
            "vuln_id": vulnerability_id,
            "project_versions": [revision.version],
            "assessment_scope": "repository",
            "source_commit": qualified.source_commit,
        }
    focal_identity = {
        key: focal.get(key) for key in ("name", "group", "version", "purl", "bom-ref", "hashes")
    }
    receipt = AgentyzerSourceReceipt(
        state=state,
        project_id=revision.project_id,
        version=revision.version,
        context_id=context_id,
        vulnerability_id=vulnerability_id,
        component_ref=context["component_ref"],
        root_ref=context["root_ref"],
        assessment_fingerprint=fingerprint,
        focal_component=focal_identity,
        source_state=source_state,
        part_id=part_id,
        sbom_sha256=sbom_sha,
        subject_digest=collection.get("subject_digest"),
        analysis_source=qualified,
        request_sha256=digest(canonical(request)) if request else None,
    )
    return {
        "format": "dtvp.agentyzer-input/1",
        "ready_to_submit": request is not None,
        "request": request,
        "receipt": receipt.model_dump(mode="json"),
        "target": {
            "version": revision.version,
            "context_id": context_id,
            "vulnerability_id": vulnerability_id,
            "component": focal_identity,
            "consuming_root": {
                key: root.get(key) for key in ("name", "version", "bom-ref", "purl")
            },
        },
        "coverage": {
            "reasons": reasons,
            "source_verification": "producer_declared_only",
            "repository_authorization": "not_checked",
            "artifact_binding_verified": False,
            "limitations": [
                "An external orchestrator must authorize the configured repository before submission.",
                "A producer-supplied commit identifies source, not the contents of a built binary or container.",
                "This request neither creates a human assessment nor grants approval or contextual score adoption.",
            ],
        },
    }
