"""Pinned input observations; missing facts are not proof of collection correctness."""

from collections import Counter

from packageurl import PackageURL

from dtvp.knowledge.comparison import page
from dtvp.knowledge.licenses import component_licenses
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

FORMAT = "dtvp.input-quality/1"
LIMITATIONS = [
    "Coverage and provenance are producer declarations; no correctness, completeness or authenticity is verified.",
    "Counts describe this pinned imported model, not components or dependencies omitted by its producer.",
    "Missing facts, NOASSERTION, explicit NONE and malformed license evidence remain distinct; no license clearance is inferred.",
    "Metadata and constituent roots are counted separately from inventory components; roles may overlap for one source-local occurrence.",
    "Unresolved source relationships may denote external elements; they are not invented dependency edges or proof of invalid source data.",
    "Issue classes are observations for explicit downstream policy, not a quality score or automatic release gate.",
]


def input_quality(journal, state, *, q="", code="", offset=0, limit=50):
    revision = journal.verify_state(state)
    inventory = load_sections(journal, state)["inventory"]
    assembly = inventory.get("assembly", {})
    baseline = inventory.get("baseline", {})
    sources = []
    if assembly:
        for part in assembly.get("parts", []):
            sources.append(
                {
                    "id": "part:" + part["part_id"],
                    "part_id": part["part_id"],
                    "state": part.get("state"),
                    "required": part.get("required", False),
                    "availability": part.get("availability", "unknown"),
                    "baseline": part.get("baseline", {}),
                }
            )
    elif baseline:
        sources.append(
            {
                "id": "baseline",
                "part_id": baseline.get("part_id"),
                "state": state,
                "availability": "withdrawn" if baseline.get("withdrawn") else "selected",
                "baseline": baseline,
            }
        )
    sources.sort(key=lambda source: source["id"])
    by_source = {source["id"]: source for source in sources}
    issues = []

    def issue(kind, *, source_id=None, component_ref=None, roles=None, **details):
        value = {
            "code": kind,
            "source_id": source_id,
            "component_ref": component_ref,
            "roles": roles or [],
            "details": details,
        }
        issues.append({"id": digest(canonical(value)), **value})

    if baseline.get("withdrawn"):
        issue("baseline_withdrawn")
    if assembly and assembly.get("readiness") != "producer_declared_ready":
        issue("assembly_not_declared_ready", readiness=assembly.get("readiness", "unknown"))

    for source in sources:
        facts = source.pop("baseline")
        source["source"] = {
            key: facts.get(key)
            for key in (
                "source",
                "artifact_sha",
                "format",
                "representation",
                "normalizer",
                "build_number",
                "occurred_at",
            )
        }
        source["collection"] = facts.get("collection", {})
        source["dependency_graph"] = facts.get("dependency_graph", "unknown")
        source["snapshot_completeness"] = facts.get("snapshot_completeness", "unknown")
        source["coverage_verification"] = "not_verified"
        # Retain this private format lookup only during this pure synthesis pass.
        source["_baseline"] = facts
        if source.get("required") and not source.get("state"):
            issue("required_part_unavailable", source_id=source["id"])
        for dimension in ("package_coverage", "dependency_coverage", "license_coverage"):
            if source["collection"].get(dimension, "unknown") == "unknown":
                issue("declared_coverage_unknown", source_id=source["id"], dimension=dimension)
        if source["dependency_graph"] != "reported":
            issue("dependency_graph_not_reported", source_id=source["id"])
        for loss in facts.get("losses", []):
            issue("normalization_loss_reported", source_id=source["id"], loss=loss)

    occurrences = {}
    for key, component in sorted(inventory.items()):
        role = (
            "inventory_component"
            if key.startswith("component:")
            else "constituent_root"
            if key.startswith("part-root:")
            else "metadata_root"
            if key == "root"
            else None
        )
        if role and component.get("bom-ref"):
            ref = component["bom-ref"]
            item = occurrences.setdefault(ref, {"component": component, "roles": []})
            if role not in item["roles"]:
                item["roles"].append(role)
    license_counts, role_counts = Counter(), Counter()
    package_counts = Counter(components=0)
    source_counts = {
        source["id"]: {
            "occurrences": 0,
            "inventory_components": 0,
            "license_evidence": Counter(),
            "by_code": Counter(),
        }
        for source in sources
    }
    for ref, occurrence in sorted(occurrences.items()):
        component, roles = occurrence["component"], sorted(occurrence["roles"])
        role_counts.update(roles)
        origin = component.get("dtvp_origin", {})
        source_id = "part:" + origin["part_id"] if origin.get("part_id") else "baseline"
        source = by_source.get(source_id)
        if source is None:
            source_id = None
            issue("source_attribution_unresolved", component_ref=ref, roles=roles)
        source_baseline = source["_baseline"] if source else {}
        evidence = (
            component_licenses(component, source_baseline)
            if source_baseline.get("format") in {"cyclonedx-json", "cyclonedx-xml", "spdx-2.3-json"}
            else {
                "status": "source_format_unknown",
                "facts": [],
                "limitations": [
                    "Pinned source format unavailable; license fields were not interpreted."
                ],
            }
        )
        license_counts[evidence["status"]] += 1
        if source_id in source_counts:
            source_counts[source_id]["occurrences"] += 1
            source_counts[source_id]["inventory_components"] += int("inventory_component" in roles)
            source_counts[source_id]["license_evidence"][evidence["status"]] += 1
        if "inventory_component" in roles:
            package_counts["components"] += 1
            package_counts["license_" + evidence["status"]] += 1
        for field in ("name", "version"):
            if not isinstance(component.get(field), str) or not component[field].strip():
                issue(field + "_not_reported", source_id=source_id, component_ref=ref, roles=roles)
                if "inventory_component" in roles:
                    package_counts[field + "_not_reported"] += 1
        if not component.get("purl") and not component.get("cpe"):
            issue(
                "package_identifier_not_reported",
                source_id=source_id,
                component_ref=ref,
                roles=roles,
            )
            if "inventory_component" in roles:
                package_counts["package_identifier_not_reported"] += 1
        if component.get("purl"):
            try:
                package = PackageURL.from_string(component["purl"])
            except TypeError, ValueError:
                issue("purl_malformed", source_id=source_id, component_ref=ref, roles=roles)
            else:
                if (
                    package.version
                    and component.get("version")
                    and package.version != component["version"]
                ):
                    issue(
                        "declared_version_conflicts_with_purl",
                        source_id=source_id,
                        component_ref=ref,
                        roles=roles,
                    )
        if evidence["status"] != "reported":
            issue(
                "license_" + evidence["status"],
                source_id=source_id,
                component_ref=ref,
                roles=roles,
                limitations=evidence["limitations"],
            )
        if any(fact.get("value") == "NOASSERTION" for fact in evidence["facts"]):
            issue(
                "license_noassertion_reported", source_id=source_id, component_ref=ref, roles=roles
            )

    if not occurrences:
        issue("no_inventory_occurrences_reported")

    def edge_source(parent):
        if not assembly:
            return "baseline" if sources else None
        origin = occurrences.get(parent, {}).get("component", {}).get("dtvp_origin", {})
        return "part:" + origin["part_id"] if origin.get("part_id") else None

    edges = inventory.get("dependencies", {}).get("edges", [])
    dependency_pairs = {
        (edge["ref"], child) for edge in edges for child in edge.get("dependsOn", [])
    }
    unresolved_dependency_refs = set()
    for parent, child in sorted(dependency_pairs):
        missing = sorted({parent, child} - occurrences.keys())
        if missing:
            unresolved_dependency_refs.update(missing)
            issue(
                "dependency_reference_unresolved",
                source_id=edge_source(parent),
                parent=parent,
                child=child,
                missing_refs=missing,
            )
    for edge in edges:
        if edge["ref"] not in occurrences and not edge.get("dependsOn"):
            unresolved_dependency_refs.add(edge["ref"])
            issue(
                "dependency_reference_unresolved",
                source_id=edge_source(edge["ref"]),
                parent=edge["ref"],
                missing_refs=[edge["ref"]],
            )
    relationships = inventory.get("relationships", {}).get("items", [])
    for relationship in relationships:
        missing = sorted({relationship["from"], relationship["to"]} - occurrences.keys())
        if missing:
            issue(
                "relationship_reference_external_or_unresolved",
                source_id="part:" + relationship["part_id"]
                if relationship.get("part_id")
                else "baseline"
                if not assembly
                else None,
                relationship=relationship,
                missing_refs=missing,
            )
    for source in sources:
        source.pop("_baseline")
    # Count identical declarations once while retaining multiplicity in graph claim totals.
    issues = sorted(
        {item["id"]: item for item in issues}.values(), key=lambda item: (item["code"], item["id"])
    )
    for item in issues:
        if item["source_id"] in source_counts:
            source_counts[item["source_id"]]["by_code"][item["code"]] += 1
    for counts in source_counts.values():
        counts["license_evidence"] = dict(sorted(counts["license_evidence"].items()))
        counts["by_code"] = dict(sorted(counts["by_code"].items()))
    content = {
        "format": FORMAT,
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "baseline_status": "withdrawn"
        if baseline.get("withdrawn")
        else "assembly"
        if assembly
        else "imported"
        if baseline
        else "absent",
        "sources": sources,
        "statistics": {
            "occurrences": len(occurrences),
            "by_role": dict(sorted(role_counts.items())),
            "inventory_components": dict(sorted(package_counts.items())),
            "license_evidence_all_roles": dict(sorted(license_counts.items())),
            "by_source": source_counts,
            "dependency_edge_claims": sum(len(edge.get("dependsOn", [])) for edge in edges),
            "unique_dependency_edges": len(dependency_pairs),
            "unresolved_dependency_refs": len(unresolved_dependency_refs),
            "relationship_claims": len(relationships),
            "issues": len(issues),
            "by_code": dict(sorted(Counter(item["code"] for item in issues).items())),
        },
        "limitations": list(LIMITATIONS),
    }
    report_digest = digest(canonical({**content, "items": issues}))
    selected = [
        item
        for item in issues
        if (not code or item["code"] == code)
        and q.casefold() in canonical(item).decode().casefold()
    ]
    return {
        **content,
        "report_digest": report_digest,
        "selection": {"q": q, "code": code},
        **page(selected, offset, limit),
    }
