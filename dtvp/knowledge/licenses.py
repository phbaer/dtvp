"""Attributed license evidence, never a legal conclusion or clearance decision."""

import json
from collections import Counter

from dtvp.knowledge.comparison import components, page
from dtvp.knowledge.workspace import load_sections

LIMITATIONS = [
    "Reported license evidence is producer-supplied, not DTVP license clearance.",
    "Expressions are retained verbatim; compatibility and obligations are not evaluated.",
    "Missing or NOASSERTION evidence stays unknown; NONE is a source claim, not permission to distribute.",
    "Document-level custom license text and files remain in pinned original source artifacts.",
]


def component_licenses(component, baseline):
    """Use the pinned parser format; a lookalike property cannot change format."""
    facts, problems = [], []
    if baseline.get("format") == "spdx-2.3-json":
        properties = component.get("properties", [])
        sources = (
            [
                item.get("value")
                for item in properties
                if isinstance(item, dict) and item.get("name") == "dtvp:spdx-source"
            ]
            if isinstance(properties, list)
            else []
        )
        package = None
        if len(sources) == 1 and isinstance(sources[0], str):
            try:
                package = json.loads(sources[0])
            except ValueError:
                pass
        if not isinstance(package, dict):
            problems.append("SPDX package evidence unavailable or malformed")
        else:
            for field in ("licenseDeclared", "licenseConcluded", "licenseInfoFromFiles"):
                if field not in package:
                    continue
                values = package[field] if field == "licenseInfoFromFiles" else [package[field]]
                if not isinstance(values, list) or not all(
                    isinstance(value, str) and value for value in values
                ):
                    problems.append(field + " is malformed")
                    continue
                for value in values:
                    facts.append(
                        {
                            "source_field": field,
                            "value": value,
                            "status": "unknown"
                            if value == "NOASSERTION"
                            else "explicit_none"
                            if value == "NONE"
                            else "reported",
                        }
                    )
            if "licenseComments" in package:
                facts.append(
                    {
                        "source_field": "licenseComments",
                        "value": package["licenseComments"],
                        "status": "comment",
                    }
                )
    else:
        licenses = component.get("licenses")
        if licenses is not None:
            if not isinstance(licenses, list):
                problems.append("CycloneDX licenses is not a list")
            else:
                for item in licenses:
                    if not isinstance(item, dict):
                        problems.append("CycloneDX license entry is malformed")
                        continue
                    expression, license = item.get("expression"), item.get("license")
                    valid = isinstance(expression, str) and bool(expression.strip())
                    valid |= isinstance(license, dict) and any(
                        isinstance(license.get(key), str) and license[key].strip()
                        for key in ("id", "name")
                    )
                    if not valid:
                        problems.append("CycloneDX license entry has no expression or identity")
                    else:
                        facts.append(
                            {"source_field": "licenses", "value": item, "status": "reported"}
                        )
    evidence = [fact for fact in facts if fact["status"] != "comment"]
    status = (
        "malformed"
        if problems
        else "reported"
        if any(fact["status"] == "reported" for fact in evidence)
        else "explicit_none"
        if any(fact["status"] == "explicit_none" for fact in evidence)
        else "unknown"
        if evidence
        else "not_reported"
    )
    return {"status": status, "facts": facts, "limitations": problems}


def license_worklist(journal, state, offset=0, limit=50, *, paginate=True):
    revision = journal.verify_state(state)
    sections = load_sections(journal, state)
    inventory = sections["inventory"]
    from dtvp.knowledge.license_reviews import inventory_fingerprint, license_status

    fingerprint = inventory_fingerprint(sections, revision.version)
    baseline = inventory.get("baseline", {})
    parts = {item["part_id"]: item for item in inventory.get("assembly", {}).get("parts", [])}
    rows = []
    for ref, component in sorted(components(inventory).items()):
        origin = component.get("dtvp_origin", {})
        part = parts.get(origin.get("part_id"))
        source = part.get("baseline", {}) if part else baseline
        reviewed = license_status(
            journal, sections, revision.version, ref, source_fingerprint=fingerprint
        )
        rows.append(
            {
                "component_ref": ref,
                "component": {
                    key: component.get(key) for key in ("name", "group", "version", "purl")
                },
                "origin": origin or None,
                "source": {
                    key: source.get(key)
                    for key in ("source", "artifact_sha", "format", "representation")
                },
                "declared_license_coverage": source.get("collection", {}).get(
                    "license_coverage", "unknown"
                ),
                "evidence": component_licenses(component, source),
                "clearance": "organization_reviewed" if reviewed["approved"] else "not_assessed",
                "license_review": reviewed,
            }
        )
    return {
        "format": "dtvp.license-worklist/1",
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "statistics": {
            "components": len(rows),
            "by_evidence_status": dict(Counter(row["evidence"]["status"] for row in rows)),
            "by_review_status": dict(Counter(row["license_review"]["status"] for row in rows)),
        },
        "limitations": list(LIMITATIONS),
        **page(rows, offset, limit),
        **({"items": rows, "next_offset": None} if not paginate else {}),
    }
