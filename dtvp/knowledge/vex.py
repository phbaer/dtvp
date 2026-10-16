"""Bounded VDR/VEX evidence adapters, deliberately separate from human decisions.

Supported semantic subsets: CycloneDX JSON 1.5/1.6, OpenVEX 0.2.x and
CSAF 2.0 VEX full-product names. This is not complete schema/signature validation.
No network dereferencing, version-range evaluation or publisher trust inference.
"""

import copy
import json
import re

from packageurl import PackageURL

from dtvp.storage import canonical, digest

MAX_BYTES = 32 * 1024 * 1024
MAX_STATEMENTS = 10_000
CDX_STATUS = {
    "exploitable": "affected",
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "in_triage": "under_investigation",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
}
CDX_REASONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
OPEN_REASONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
STATUSES = {"affected", "not_affected", "fixed", "under_investigation"}
CSAF_STATUS = {
    "known_affected": "affected",
    "known_not_affected": "not_affected",
    "fixed": "fixed",
    "first_fixed": "fixed",
    "under_investigation": "under_investigation",
}


def exact_purl(value):
    """Versionless coordinates are not an exact product/version identity."""
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None
    try:
        package = PackageURL.from_string(value)
        return package.to_string() if package.version else None
    except ValueError:
        return None


def objects(value, field):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{field} must be an array of objects")
    if len(value) > MAX_STATEMENTS:
        raise ValueError(f"{field} exceeds the supported item limit")
    return value


def strings(value, field):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field} must be an array of identifiers")
    if len(value) > MAX_STATEMENTS:
        raise ValueError(f"{field} exceeds the supported item limit")
    return value


def text(value):
    return value.strip() if isinstance(value, str) else ""


def statement(
    identifier,
    *,
    status,
    raw,
    product_ids=(),
    purls=(),
    source_refs=(),
    justification=None,
    rationale="",
    normalized=None,
    reasons=(),
):
    issues = list(reasons)
    if not text(identifier):
        issues.append("missing_vulnerability_identifier")
    if not product_ids and not purls and not source_refs:
        issues.append("missing_product_scope")
    normalized = normalized or (status if status in STATUSES else None)
    if normalized is None and status != "reported":
        issues.append("unsupported_status")
    if normalized == "not_affected" and not justification and not text(rationale):
        issues.append("missing_not_affected_reason")
    return {
        "vulnerability_id": identifier,
        "product_ids": list(product_ids),
        "purls": list(purls),
        "source_refs": list(source_refs),
        "status": status,
        "normalized_status": normalized,
        "justification": justification,
        "rationale": rationale,
        "raw": raw,
        "unresolved_reasons": sorted(set(issues)),
    }


def cdx(document):
    version = document.get("specVersion")
    if version not in {"1.5", "1.6"}:
        raise ValueError("Supported CycloneDX evidence versions are 1.5 and 1.6 JSON")
    components = {}
    pending = list(objects(document.get("components", []), "components"))
    root = document.get("metadata", {}).get("component")
    if isinstance(root, dict):
        pending.append(root)
    count = 0
    while pending:
        item = pending.pop()
        count += 1
        if count > MAX_STATEMENTS:
            raise ValueError("Embedded component mapping exceeds the supported item limit")
        if item.get("bom-ref"):
            components.setdefault(item["bom-ref"], []).append(item)
        pending.extend(objects(item.get("components", []), "nested components"))
    statements = []
    for vulnerability in objects(document.get("vulnerabilities", []), "vulnerabilities"):
        analysis = vulnerability.get("analysis", {})
        if not isinstance(analysis, dict):
            raise ValueError("CycloneDX analysis must be an object")
        status = analysis.get("state", "reported")
        justification = analysis.get("justification")
        reasons = []
        if justification and justification not in CDX_REASONS:
            reasons.append("unsupported_justification")
        scopes = []
        for affected in objects(vulnerability.get("affects", []), "affects"):
            ref = affected.get("ref")
            matches = components.get(ref, []) if isinstance(ref, str) else []
            versions = affected.get("versions", [])
            issues = []
            # A version/range-scoped statement cannot safely be expanded to the
            # embedded component without evaluating the format's range semantics.
            if versions:
                issues.append("version_constraints_not_evaluated")
            if len(matches) > 1:
                issues.append("ambiguous_document_component_reference")
            scopes.append(
                {
                    "ref": ref,
                    "component": {"bom-ref": ref, "purl": matches[0].get("purl")}
                    if len(matches) == 1
                    else None,
                    "unresolved_reasons": issues,
                }
            )
        statements.append(
            statement(
                vulnerability.get("id"),
                status=status,
                raw=vulnerability,
                source_refs=scopes,
                justification=justification,
                rationale=text(analysis.get("detail")),
                normalized=CDX_STATUS.get(status),
                reasons=reasons,
            )
        )
    return {
        "format": "cyclonedx-" + version,
        "document_id": document.get("serialNumber"),
        "revision": document.get("version"),
        "publisher": document.get("metadata", {}).get("supplier")
        or document.get("metadata", {}).get("authors"),
        "statements": statements,
        "losses": ["Version/range constraints and BOM-Link resolution are not evaluated."],
    }


def openvex(document):
    context = document.get("@context")
    if not isinstance(context, str) or not re.fullmatch(
        r"https://openvex\.dev/ns/v0\.2\.\d+", context
    ):
        raise ValueError("Supported OpenVEX namespace versions are 0.2.x")
    statements = []
    for item in objects(document.get("statements", []), "statements"):
        vulnerability = item.get("vulnerability", {})
        if not isinstance(vulnerability, dict):
            raise ValueError("OpenVEX vulnerability must be an object")
        products = objects(item.get("products", []), "products")
        justification = item.get("justification")
        reasons = []
        if justification and justification not in OPEN_REASONS:
            reasons.append("unsupported_justification")
        # A subcomponent changes the scope of the product claim. Do not turn it
        # into a global package assertion by dropping the product context.
        if any(product.get("subcomponents") for product in products):
            reasons.append("subcomponent_context_not_supported")
        statements.append(
            statement(
                vulnerability.get("name") or vulnerability.get("@id"),
                status=item.get("status"),
                raw=item,
                product_ids=[
                    product.get("@id") for product in products if text(product.get("@id"))
                ],
                purls=[product["@id"] for product in products if exact_purl(product.get("@id"))],
                justification=justification,
                rationale=text(item.get("impact_statement"))
                or (
                    text(item.get("action_statement"))
                    if item.get("status") != "not_affected"
                    else ""
                ),
                reasons=reasons,
            )
        )
    return {
        "format": "openvex-0.2",
        "document_id": document.get("@id"),
        "revision": document.get("version"),
        "publisher": document.get("author"),
        "statements": statements,
        "losses": [
            "Only exact versioned product @id PURLs are resolved; inheritance and subcomponents are not applied."
        ],
    }


def csaf(document):
    header = document.get("document", {})
    if header.get("csaf_version") != "2.0" or header.get("category") != "csaf_vex":
        raise ValueError("Supported CSAF evidence profile is CSAF 2.0 csaf_vex")
    tree = document.get("product_tree", {})
    products = {}
    from dtvp.knowledge.evidence_conformance import csaf_products

    for item in csaf_products(tree):
        products.setdefault(item.get("product_id"), []).append(item)
    statements = []
    for vulnerability in objects(document.get("vulnerabilities", []), "vulnerabilities"):
        identifiers = objects(vulnerability.get("ids", []), "vulnerability ids")
        identifier = vulnerability.get("cve") or next(
            (item.get("text") for item in identifiers if text(item.get("text"))), None
        )
        statuses = vulnerability.get("product_status", {})
        if not isinstance(statuses, dict):
            raise ValueError("CSAF product_status must be an object")
        for status, ids in statuses.items():
            for product_id in strings(ids, "product_status"):
                matches = products.get(product_id, [])
                reasons = []
                if len(matches) != 1:
                    reasons.append("unknown_or_ambiguous_product_id")
                product = matches[0] if len(matches) == 1 else {}
                purl = product.get("product_identification_helper", {}).get("purl") or product_id
                flags = [
                    item.get("label")
                    for item in objects(vulnerability.get("flags", []), "flags")
                    if product_id in item.get("product_ids", [])
                    and item.get("label") in OPEN_REASONS
                ]
                impacts = [
                    text(item.get("details"))
                    for item in objects(vulnerability.get("threats", []), "threats")
                    if item.get("category") == "impact"
                    and product_id in item.get("product_ids", [])
                ]
                rationale = "\n".join(filter(None, impacts))
                normalized = CSAF_STATUS.get(status)
                if normalized is None:
                    reasons.append("unsupported_product_status_semantics")
                statements.append(
                    statement(
                        identifier,
                        status=status,
                        raw={"vulnerability": vulnerability, "product": product},
                        product_ids=[product_id],
                        purls=[purl] if exact_purl(purl) else [],
                        justification=flags[0] if len(flags) == 1 else None,
                        rationale=rationale,
                        normalized=normalized,
                        reasons=reasons,
                    )
                )
                statements[-1]["product_ids_are_document_local"] = True
                if len(statements) > MAX_STATEMENTS:
                    raise ValueError("Evidence statement count exceeds the supported limit")
    tracking = header.get("tracking", {})
    return {
        "format": "csaf-2.0-vex",
        "document_id": tracking.get("id"),
        "revision": tracking.get("version"),
        "publisher": header.get("publisher"),
        "statements": statements,
        "losses": [
            "Nested branch and full_product_names identities with exact PURLs are resolved; relationships, groups, and version boundaries are not evaluated."
            if tree.get("branches")
            else "Only full_product_names with exact PURLs are resolved; branches, relationships, groups, and version boundaries are not evaluated."
        ],
    }


def parse_evidence(raw, *, validation_profile=None):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Evidence must be JSON bytes within the 32 MiB limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object keys are unsupported")
            result[key] = value
        return result

    try:

        def invalid_constant(value):
            raise ValueError("Non-finite JSON numbers are unsupported")

        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Evidence must be unambiguous UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ValueError("Evidence document must be an object")
    conformance = None
    if validation_profile is not None:
        from dtvp.knowledge.evidence_conformance import require_conformance

        conformance = require_conformance(document, validation_profile)
    try:
        if document.get("format") == "dtvp.advisory-feed/1":
            from dtvp.knowledge.advisory_documents import advisory_document

            result = advisory_document(document)
        elif document.get("format") == "dtvp.package-matching/1":
            from dtvp.knowledge.osv_matching import matching_document

            result = matching_document(document)
        elif document.get("bomFormat") == "CycloneDX":
            result = cdx(document)
        elif "@context" in document and "statements" in document:
            result = openvex(document)
        elif "document" in document:
            result = csaf(document)
        else:
            raise ValueError("Unsupported evidence document format")
    except (TypeError, AttributeError, KeyError) as error:
        raise ValueError("Malformed evidence document structure") from error
    if not result["statements"] and result["format"] not in {
        "dtvp.advisory-feed/1",
        "dtvp.package-matching/1",
    }:
        raise ValueError("Evidence document contains no supported statement records")
    if conformance is not None:
        if any(item["unresolved_reasons"] for item in result["statements"]):
            raise ValueError("DTVP evidence profile rejected unresolved statement semantics")
        result["conformance"] = conformance
    result.update(
        original_sha=digest(raw),
        signature_verification="not_performed",
        schema_validation="dtvp_supported_subset_only"
        if conformance
        else "supported_semantic_subset",
        raw=document,
    )
    if len(canonical(result)) > MAX_BYTES * 2:
        raise ValueError("Normalized evidence exceeds the supported 64 MiB limit")
    return result


def components(sections):
    result = {
        item["bom-ref"]: item
        for key, item in sections["inventory"].items()
        if key.startswith("component:") and item.get("bom-ref")
    }
    root = sections["inventory"].get("root", {})
    if root.get("bom-ref"):
        result.setdefault(root["bom-ref"], root)
    return result


def resolve_statement(item, document_sha, inventory, indexed):
    matches, unresolved = set(), []
    if item["unresolved_reasons"]:
        return matches, item["unresolved_reasons"]
    subjects = [("purl", value) for value in item["purls"]]
    subjects += [
        ("product_id", value)
        for value in item["product_ids"]
        if value not in item["purls"]
        and not (item.get("product_ids_are_document_local") and item["purls"])
    ]
    for kind, value in subjects:
        purl = exact_purl(value)
        found = {
            ref
            for ref, component in indexed.items()
            if purl and exact_purl(component.get("purl")) == purl
        }
        if found:
            matches.update(found)
        else:
            unresolved.append(f"unresolved_{kind}:{value}")
    for scope in item["source_refs"]:
        if scope["unresolved_reasons"]:
            unresolved.extend(scope["unresolved_reasons"])
            continue
        ref = scope.get("ref")
        component = scope.get("component") or {}
        purl = exact_purl(component.get("purl"))
        found = {
            key for key, value in indexed.items() if purl and exact_purl(value.get("purl")) == purl
        }
        if (
            not purl
            and inventory.get("baseline", {}).get("artifact_sha") == document_sha
            and ref in indexed
        ):
            found.add(ref)
        if found:
            matches.update(found)
        else:
            unresolved.append(f"unresolved_document_ref:{ref}")
    return matches, sorted(set(unresolved))


def reconcile_evidence(sections):
    """Rebuild only imported assertions; preserve inventory and human records."""
    findings = sections["vulnerabilities"]
    for key in list(findings):
        if key.startswith("external-evidence:"):
            del findings[key]
    indexed = components(sections)
    package_index = package_match_index(sections)
    # Snapshot baseline pairs before applying documents: feeds cannot amplify
    # themselves or VEX-only claims across reapplication/nightly imports.
    baseline_refs = {}
    for key, item in findings.items():
        if (
            not key.startswith(("evidence-document:", "external-evidence:"))
            and item.get("ref") in indexed
            and item.get("identifier")
        ):
            baseline_refs.setdefault(item["identifier"], set()).add(item["ref"])
    for identifier, references in matching_source_refs(sections).items():
        baseline_refs.setdefault(identifier, set()).update(references)
    for key, record in list(findings.items()):
        if not key.startswith("evidence-document:"):
            continue
        document = record["document"]
        sha = record["artifact_sha"]
        if record.get("active", True) is False:
            record["application"] = {
                "selection": "inactive",
                "matched": 0,
                "unresolved": 0,
                "statements": [],
            }
            continue
        applications = []
        for index, item in enumerate(document["statements"]):
            advisory_only = document["format"] == "dtvp.advisory-feed/1"
            if advisory_only:
                matches = set(baseline_refs.get(item["vulnerability_id"], ()))
                unresolved = [] if matches else ["identifier_not_claimed_by_baseline"]
            elif document["format"] == "dtvp.package-matching/1":
                matches, unresolved = resolve_package_match(item, package_index)
            else:
                matches, unresolved = resolve_statement(item, sha, sections["inventory"], indexed)
            applications.append(
                {
                    "statement_index": index,
                    "vulnerability_id": item["vulnerability_id"],
                    "matched": sorted(matches),
                    "unresolved": unresolved,
                }
            )
            for ref in sorted(matches):
                identity = digest(canonical([sha, index, ref]))
                raw_advisory = item["raw"].get("vulnerability", item["raw"])
                findings["external-evidence:" + identity] = {
                    "kind": "external-match"
                    if document["format"] == "dtvp.package-matching/1"
                    else "external-advisory"
                    if advisory_only
                    else "external-status",
                    **(
                        {
                            "package_matching": {
                                "format": document["format"],
                                "purl": document["matching_coverage"]["purl"],
                                "verification": "provider_claim_unverified",
                            }
                        }
                        if document["format"] == "dtvp.package-matching/1"
                        else {}
                    ),
                    "identifier": item["vulnerability_id"],
                    "ref": ref,
                    "source": text(record.get("source")) or "imported-evidence",
                    "advisory": {
                        **raw_advisory,
                        "description": text(raw_advisory.get("description"))
                        or text(raw_advisory.get("title"))
                        or item["rationale"],
                        "status": item["status"],
                        "normalized_status": item["normalized_status"],
                        "justification": item["justification"],
                    },
                    "statement": item,
                    "publisher": document.get("publisher"),
                    "document_sha": sha,
                    "trust": "unverified",
                    "source_scope": "package_occurrence_all_usage_contexts",
                    "context_conditions": "not_verified",
                }
        record["application"] = {
            "matched": sum(len(item["matched"]) for item in applications),
            "unresolved": sum(bool(item["unresolved"]) for item in applications),
            "statements": applications,
        }
    return sections


def preview_evidence(sections, document_record):
    candidate = copy.deepcopy(sections)
    sha = document_record["artifact_sha"]
    candidate["vulnerabilities"]["evidence-document:" + sha] = copy.deepcopy(document_record)
    reconcile_evidence(candidate)
    assertions = [
        item
        for key, item in candidate["vulnerabilities"].items()
        if key.startswith("external-evidence:")
    ]
    statuses = {}
    for item in assertions:
        statuses.setdefault((item["identifier"], item["ref"]), set()).add(
            item["advisory"]["normalized_status"]
        )
    contradictions = [
        {"vulnerability_id": identifier, "ref": ref, "statuses": sorted(values - {None})}
        for (identifier, ref), values in sorted(statuses.items())
        if len(values - {None}) > 1
    ]
    application = candidate["vulnerabilities"]["evidence-document:" + sha]["application"]
    return {
        "application": application,
        "would_apply": [item for item in assertions if item["document_sha"] == sha],
        "unmatched": [item for item in application["statements"] if item["unresolved"]],
        "contradictions": contradictions,
        "trust": "unverified",
    }


def matching_source_refs(sections):
    """Preindex only active package-match sources against actual current inventory.

    VEX and advisory-only documents never grow this known-identifier set.
    """
    result = {}
    indexed = package_match_index(sections)
    for key, record in sections["vulnerabilities"].items():
        if not key.startswith("evidence-document:") or record.get("active", True) is False:
            continue
        document = record.get("document", {})
        if document.get("format") != "dtvp.package-matching/1":
            continue
        for item in document["statements"]:
            matches, _ = resolve_package_match(item, indexed)
            if matches:
                result.setdefault(item["vulnerability_id"], set()).update(matches)
    return result


def package_match_index(sections):
    """Index eligible current coordinates once, preserving distinct occurrences."""
    indexed = {}
    for key, component in sections["inventory"].items():
        if key != "root" and not key.startswith(("component:", "part-root:")):
            continue
        raw = component.get("purl")
        try:
            package = PackageURL.from_string(raw) if isinstance(raw, str) else None
        except ValueError:
            continue
        if not package or not package.version or package.qualifiers or package.subpath:
            continue
        if component.get("version") and component["version"] != package.version:
            continue
        if component.get("bom-ref"):
            indexed.setdefault(package.to_string(), set()).add(component["bom-ref"])
    return indexed


def resolve_package_match(item, indexed):
    if item["unresolved_reasons"]:
        return set(), item["unresolved_reasons"]
    matches = set()
    for purl in item["purls"]:
        matches.update(indexed.get(purl, ()))
    return matches, [] if matches else ["matching_package_not_present_or_ineligible"]
