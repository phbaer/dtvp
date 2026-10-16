"""Attributed license evidence, never a legal conclusion or clearance decision."""

import json
from collections import Counter

from dtvp.knowledge.comparison import components, page
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical

MAX_SUPPLEMENTAL_BYTES = 32 * 1024 * 1024
MAX_SUPPLEMENTAL_CLAIMS = 100_000

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


def _reported_values(evidence):
    categories = {}
    for fact in evidence["facts"]:
        if fact["status"] == "comment":
            continue
        field, value = fact["source_field"], fact["value"]
        category = {
            "licenseDeclared": "declared",
            "licenseConcluded": "concluded",
            "licenseInfoFromFiles": "from_files",
        }.get(field, "reported")
        if field == "licenses":
            value = (
                value.get("expression")
                or value.get("license", {}).get("id")
                or value.get("license", {}).get("name")
            )
        if isinstance(value, str):
            categories.setdefault(category, set()).add(value)
    return categories


def document_license_material(journal, baseline):
    """Pinned format's document licensing fields, including unknown definition attributes."""
    artifact = baseline.get("artifact_sha")
    if not artifact:
        return None
    if journal.objects.path(artifact).stat().st_size > 32 * 1024 * 1024:
        raise ValueError("License source document exceeds 32 MiB")
    raw = journal.objects.read(artifact)
    if baseline.get("format") == "cyclonedx-xml":
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw)
        namespace = root.tag.rsplit("}", 1)[0] + "}" if "}" in root.tag else ""

        def project(node, *, top=False, metadata=False):
            excluded = {
                namespace + name
                for name in (
                    ("components", "dependencies", "vulnerabilities")
                    if top
                    else ("component", "timestamp")
                    if metadata
                    else ()
                )
            }
            children = [
                project(child, metadata=top and child.tag == namespace + "metadata")
                for child in node
                if child.tag not in excluded
            ]
            return {
                "tag": node.tag,
                "attributes": {
                    key: item
                    for key, item in node.attrib.items()
                    if not (top and key in {"serialNumber", "version"})
                },
                "text": node.text if not children or (node.text and node.text.strip()) else None,
                "children": children,
            }

        document = project(root, top=True)
    else:
        from dtvp.knowledge.legacy_archive import strict_json

        value = strict_json(raw)
        if not isinstance(value, dict):
            raise ValueError("License source document must be an object")
        if baseline.get("format") == "spdx-2.3-json":
            if value.get("spdxVersion") != "SPDX-2.3":
                raise ValueError("Original document differs from its pinned SPDX format")
            document = {
                key: item
                for key, item in value.items()
                if key
                not in {
                    "packages",
                    "SPDXID",
                    "documentNamespace",
                    "name",
                    "creationInfo",
                    "documentDescribes",
                    "relationships",
                }
            }
            creation = value.get("creationInfo", {})
            if not isinstance(creation, dict):
                raise ValueError("Malformed SPDX document creation information")
            remaining = {
                key: item for key, item in creation.items() if key not in {"created", "creators"}
            }
            if remaining:
                document["creationInfo"] = remaining
            # Known topology fields are normalized already; extra relationship
            # assertions/attributes stay material rather than disappearing.
            unrepresented = [
                item
                for item in value.get("relationships", [])
                if not isinstance(item, dict)
                or set(item) - {"spdxElementId", "relationshipType", "relatedSpdxElement"}
                or item.get("relationshipType")
                not in {"DEPENDS_ON", "DEPENDENCY_OF", "DESCRIBES", "CONTAINS"}
            ]
            if unrepresented:
                document["relationships"] = unrepresented
        elif baseline.get("format") == "cyclonedx-json":
            if value.get("bomFormat") != "CycloneDX" or not isinstance(
                value.get("metadata", {}), dict
            ):
                raise ValueError("Original document differs from its pinned CycloneDX format")
            document = {
                key: item
                for key, item in value.items()
                if key
                not in {
                    "components",
                    "dependencies",
                    "vulnerabilities",
                    "serialNumber",
                    "version",
                    "metadata",
                }
            }
            metadata = {
                key: item
                for key, item in value.get("metadata", {}).items()
                if key not in {"component", "timestamp"}
            }
            if metadata:
                document["metadata"] = metadata
        else:
            raise ValueError("Unsupported source format for document license material")
    result = {"format": baseline.get("format"), "document": document}
    if len(canonical(result)) > MAX_SUPPLEMENTAL_BYTES:
        raise ValueError("Document licensing definitions exceed 32 MiB")
    return result


class SupplementalLicenses:
    """Request-local source-format/proof index; component lookalikes are ignored."""

    def __init__(self, journal, sections, *, project_id=None, version=None):
        self.journal, self.sections = journal, sections
        self.project_id, self.version = project_id, version
        self.sources, self.claims, self.bytes = {}, 0, 0
        self.input_bytes, self.checked_artifacts = 0, set()
        self.documents = {}

    def _source(self, assertion):
        state = assertion["state"]
        if state not in self.sources:
            revision = self.journal.state(state)
            if revision.version != "@observation" or (
                self.project_id and revision.project_id != self.project_id
            ):
                raise ValueError("Pinned observation source scope differs")
            pointers = self.journal.records(state, "inventory")
            metadata = self.journal.load(
                self.journal.records(state, "history")["observation-import"]
            )
            baseline = self.journal.load(pointers["baseline"])
            if baseline.get("format") not in {"cyclonedx-json", "cyclonedx-xml", "spdx-2.3-json"}:
                raise ValueError("Pinned observation license format is unsupported")
            artifact = baseline.get("artifact_sha")
            if artifact not in revision.artifacts:
                raise ValueError("Pinned observation original artifact is not retained")
            if artifact not in self.checked_artifacts:
                size = self.journal.objects.path(artifact).stat().st_size
                if size > 32 * 1024 * 1024 or self.input_bytes + size > 64 * 1024 * 1024:
                    raise ValueError("Supplemental original source bytes exceed bounds")
                self.journal.objects.read(artifact)
                self.checked_artifacts.add(artifact)
                self.input_bytes += size
            self.bytes += len(canonical([pointers, metadata, baseline]))
            if len(self.sources) >= 2000 or self.bytes > MAX_SUPPLEMENTAL_BYTES:
                raise ValueError("Supplemental license source index exceeds bounds")
            self.sources[state] = (pointers, metadata, baseline)
        pointers, metadata, baseline = self.sources[state]
        if (
            metadata.get("source") != assertion["source"]
            or metadata.get("part_id") != assertion.get("part_id")
            or (self.version and metadata.get("version") != self.version)
        ):
            raise ValueError("Pinned observation attribution differs")
        from dtvp.knowledge.service import component_key

        root = self.journal.load(pointers["root"]) if "root" in pointers else {}
        original = (
            root
            if root.get("bom-ref") == assertion["ref"]
            else self.journal.load(pointers[component_key(assertion["ref"])])
        )
        if original != assertion["component"]:
            raise ValueError("Supplemental component differs from its pinned observation")
        return baseline

    def evidence(self, component_ref, authority_evidence):
        claims, values, signatures = [], {}, set()

        # CDX's generic reported token can be compared with SPDX declared values;
        # concluded and file observations remain separate claim categories.
        def signature(evidence):
            categories = _reported_values(evidence)
            return {
                ("declared" if category == "reported" else category): tuple(sorted(items))
                for category, items in categories.items()
            }

        primary = signature(authority_evidence)
        for assertion in (
            self.sections["inventory"]
            .get("observation_assertions", {})
            .get("components", {})
            .get(component_ref, [])
        ):
            self.claims += 1
            if self.claims > MAX_SUPPLEMENTAL_CLAIMS:
                raise ValueError("Supplemental license claims exceed bound")
            try:
                baseline = self._source(assertion)
                evidence = component_licenses(assertion["component"], baseline)
                source_format = baseline.get("format")
                artifact_sha = baseline.get("artifact_sha")
            except (ValueError, KeyError, OSError) as error:
                evidence = {"status": "malformed", "facts": [], "limitations": [str(error)]}
                source_format = None
                artifact_sha = None
            claim = {key: assertion.get(key) for key in ("source", "part_id", "state", "ref")}
            claim.update(source_format=source_format, artifact_sha=artifact_sha, evidence=evidence)
            self.bytes += len(canonical(claim))
            if self.bytes > MAX_SUPPLEMENTAL_BYTES:
                raise ValueError("Supplemental license evidence exceeds 32 MiB")
            claims.append(claim)
            current = signature(evidence)
            for category, tokens in _reported_values(evidence).items():
                values.setdefault(category, set()).update(tokens)
            for category, tokens in current.items():
                if tokens:
                    signatures.add((category, tokens))
        for category, tokens in primary.items():
            if tokens:
                signatures.add((category, tokens))
        statuses = {claim["evidence"]["status"] for claim in claims}
        status = next(
            (
                item
                for item in ("malformed", "reported", "explicit_none", "unknown", "not_reported")
                if item in statuses
            ),
            "not_reported",
        )
        differ = any(
            len({tokens for label, tokens in signatures if label == category}) > 1
            for category, _ in signatures
        )
        return {
            "status": status,
            "claims": claims,
            "reported_values": [
                {"category": category, "values": sorted(tokens)}
                for category, tokens in sorted(values.items())
            ],
            "source_claims_differ": differ,
            "limitations": [
                "Distinct source values are not a determination of license incompatibility or legal clearance."
            ],
        }


def license_worklist(journal, state, offset=0, limit=50, *, paginate=True, filters=None):
    revision = journal.verify_state(state)
    sections = load_sections(journal, state)
    inventory = sections["inventory"]
    from dtvp.knowledge.license_reviews import (
        DISPOSITION_FORMAT,
        inventory_fingerprint,
        license_status,
        material_fingerprint,
    )

    fingerprint = inventory_fingerprint(sections, revision.version)
    modern = any(
        record.get("payload", {}).get("format") == DISPOSITION_FORMAT
        for key, record in sections["history"].items()
        if key.startswith(("license-disposition:", "license-review:"))
    )
    material = material_fingerprint(journal, sections, revision.version) if modern else None
    baseline = inventory.get("baseline", {})
    parts = {item["part_id"]: item for item in inventory.get("assembly", {}).get("parts", [])}
    rows = []
    supplemental = SupplementalLicenses(
        journal, sections, project_id=revision.project_id, version=revision.version
    )
    for ref, component in sorted(components(inventory).items()):
        origin = component.get("dtvp_origin", {})
        part = parts.get(origin.get("part_id"))
        source = part.get("baseline", {}) if part else baseline
        reviewed = license_status(
            journal,
            sections,
            revision.version,
            ref,
            source_fingerprint=fingerprint,
            material_source_fingerprint=material,
        )
        selected_source = next(
            (
                item
                for item in inventory.get("observations", {}).get("sources", {}).values()
                if item.get("source") == origin.get("source")
                and item.get("part_id") == origin.get("part_id")
                and item.get("state") == origin.get("state")
                and origin.get("ref") in item.get("accepted_components", [])
            ),
            None,
        )
        adopted = ref.startswith("observation:") and selected_source is not None
        evidence = (
            {
                "status": "not_reported",
                "facts": [],
                "limitations": [
                    "This occurrence was explicitly adopted from an observation and is absent from authority inventory."
                ],
            }
            if adopted
            else component_licenses(component, source)
        )
        additional = supplemental.evidence(ref, evidence)
        rows.append(
            {
                "component_ref": ref,
                "inventory_role": "adopted_observation" if adopted else "authority",
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
                "evidence": evidence,
                "supplemental_evidence": additional,
                "clearance": "organization_reviewed" if reviewed["approved"] else "not_assessed",
                "license_review": reviewed,
            }
        )
    if filters is not None:
        rows = [row for row in rows if filters.matches(row)]
    return {
        "format": "dtvp.license-worklist/1",
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "statistics": {
            "components": len(rows),
            "by_evidence_status": dict(Counter(row["evidence"]["status"] for row in rows)),
            "by_review_status": dict(Counter(row["license_review"]["status"] for row in rows)),
            "supplemental_by_status": dict(
                Counter(row["supplemental_evidence"]["status"] for row in rows)
            ),
            "source_claims_differ": sum(
                row["supplemental_evidence"]["source_claims_differ"] for row in rows
            ),
        },
        "limitations": list(LIMITATIONS),
        **page(rows, offset, limit),
        **({"items": rows, "next_offset": None} if not paginate else {}),
    }
