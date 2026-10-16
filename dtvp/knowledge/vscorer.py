"""Explicit, context-scoped conversion into VScorer's existing native inputs."""

import copy
import re

from dtvp.knowledge.exports import build_bundle, contextual_pipeline_metadata, export_bytes
from dtvp.rescoring import base_fact
from dtvp.storage import canonical, digest

SOURCE_FORMAT = "dtvp.vscorer-source/1"
CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def _validate_cdx(document):
    from cyclonedx.output import OutputFormat
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation import make_schemabased_validator

    errors = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_6).validate_str(
        canonical(document).decode()
    )
    if errors:
        raise ValueError("Source component facts cannot form a valid CycloneDX 1.6 input")


def derive_context_inputs(journal, state, context_id, component_ref, base_selections):
    """Prepare files and a self-asserted source receipt, never an assessment.

    Full consuming-tree topology and placement properties remain available, while
    the CVE file focuses exactly one component occurrence. Non-CVEs and unresolved
    Base choices remain explicit exclusions, not clean findings or approvals.
    """
    bundle = build_bundle(journal, state)
    inventory = bundle["inventory"]
    context = bundle["ownership"].get("context:" + context_id)
    if not context or context["component_ref"] != component_ref:
        raise ValueError("Context must match the exact selected component occurrence")
    if context.get("dependency_graph") != "reported":
        raise ValueError("VScorer derivation requires reported dependency topology")
    components = {component["bom-ref"]: component for component in inventory["components"]}
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        components.setdefault(root["bom-ref"], root)
    graph = {ref: set() for ref in components}
    for edge in inventory["dependencies"].get("edges", []):
        if edge["ref"] not in graph or any(ref not in graph for ref in edge.get("dependsOn", [])):
            raise ValueError("Dependency topology has unresolved references")
        graph[edge["ref"]].update(edge.get("dependsOn", []))
    seen, pending = set(), [context["root_ref"]]
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if ref not in components:
            raise ValueError("Consuming root is absent from the selected inventory")
        seen.add(ref)
        pending.extend(graph[ref] - seen)
    if any(len(ref) > 1024 for ref in seen):
        raise ValueError("VScorer component references must not exceed 1024 characters")
    if component_ref not in seen:
        raise ValueError("Selected component is outside its consuming tree")
    conversions = []

    def native_component(component):
        value = copy.deepcopy(component)
        for key in ("dtvp_origin", "dtvp_observations", "dtvp_observation_conflicts", "components"):
            if key in value:
                value.pop(key)
                conversions.append(
                    {
                        "component_ref": component["bom-ref"],
                        "field": key,
                        "handling": "retained_in_native_bundle",
                    }
                )
        value.setdefault(
            "type", "application" if component["bom-ref"] == context["root_ref"] else "library"
        )
        return value

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": native_component(components[context["root_ref"]])},
        "components": [
            native_component(components[ref]) for ref in sorted(seen) if ref != context["root_ref"]
        ],
        "dependencies": [{"ref": ref, "dependsOn": sorted(graph[ref])} for ref in sorted(seen)],
    }
    _validate_cdx(sbom)
    findings = [finding for finding in bundle["findings"] if finding["context_id"] == context_id]
    if set(base_selections) - {finding["vulnerability_id"] for finding in findings}:
        raise ValueError("Base selections name vulnerabilities outside the selected context")
    rows, selected, excluded = [], {}, []
    for finding in findings:
        identifier = finding["vulnerability_id"]
        if not CVE.fullmatch(identifier):
            excluded.append({"vulnerability_id": identifier, "reason": "non_cve_identifier"})
            continue
        vector = base_selections.get(identifier)
        if vector is None:
            excluded.append(
                {"vulnerability_id": identifier, "reason": "explicit_base_selection_required"}
            )
            continue
        chosen = base_fact(vector)
        facts = [
            base_fact(rating.get("vector", ""), rating.get("score"))
            for rating in finding["source_ratings"]
        ]
        if not chosen or chosen not in facts:
            raise ValueError("Selected Base must match a validated original source assertion")
        if chosen["version"] not in {"3.0", "3.1", "4.0"}:
            excluded.append({"vulnerability_id": identifier, "reason": "unsupported_cvss_version"})
            continue
        cwes, references = set(), set()
        for observation in finding["sourcefacts"]:
            advisory = observation.get("advisory", {})
            cwes.update(
                "CWE-" + str(value).removeprefix("CWE-") for value in advisory.get("cwes", [])
            )
            references.update(
                value["url"]
                for value in advisory.get("references", [])
                if isinstance(value, dict) and isinstance(value.get("url"), str)
            )
        if any(not re.fullmatch(r"CWE-\d+", value) for value in cwes):
            raise ValueError("Source CWE assertions cannot form a native VScorer worklist")
        rows.append(
            {
                "cve_id": identifier,
                "component_refs": [component_ref],
                "cvss_vector": chosen["vector"],
                "base_score": chosen["score"],
                "description": finding["description"],
                "cwe_ids": sorted(cwes),
                "cpe": "",
                "references": sorted(references),
            }
        )
        selected[identifier] = {
            "finding_id": finding["id"],
            "vector": chosen["vector"],
            "score": chosen["score"],
        }
    if len(rows) > 1000:
        raise ValueError("VScorer intake permits at most 1000 selected CVEs per assessment")
    cves = {"cves": rows}
    raw_bundle, _ = export_bytes(journal, state)
    receipt = (
        {
            "format": SOURCE_FORMAT,
            "state": state,
            "project_id": bundle["project_id"],
            "version": bundle["version"],
            "context_id": context_id,
            "component_ref": component_ref,
            "root_ref": context["root_ref"],
            "bundle_sha256": digest(raw_bundle),
            "artifacts": {
                "sbom_sha256": digest(canonical(sbom)),
                "cves_sha256": digest(canonical(cves)),
            },
            "selected_source_base": selected,
        }
        if selected
        else None
    )
    result = {
        "sbom": sbom,
        "cves": cves,
        "dtvp_source": receipt,
        "eligible": bool(selected),
        "coverage": {
            "included": sorted(selected),
            "excluded": excluded,
            "all_context_vulnerabilities_included": len(rows) == len(findings),
            "consuming_component_refs": sorted(seen),
            "conversions": conversions,
            "relationships": "typed source relationships remain in the native bundle; only dependency edges are converted",
            "verification": "source_receipt_requires_consumer_artifact_consistency_check",
            "remote_authenticity": "not_verified",
        },
    }
    pipeline_context = contextual_pipeline_metadata(bundle, context_id)
    if pipeline_context is not None:
        result["pipeline_context"] = pipeline_context
        if receipt is not None:
            receipt["artifacts"]["pipeline_context_sha256"] = digest(canonical(pipeline_context))
    return result
