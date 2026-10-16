"""DTVP consumed-field contracts, never full-schema or signature certification."""

from datetime import datetime
from typing import Literal

ValidationProfile = Literal[
    "dtvp-cyclonedx-1.5-exact/1",
    "dtvp-cyclonedx-1.6-exact/1",
    "dtvp-openvex-0.2.0-exact/1",
    "dtvp-csaf-2.0-vex-exact/1",
]
PROFILES = tuple(ValidationProfile.__args__)
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_ISSUES = 64
LIMITATIONS = [
    "DTVP consumed-field subset validation only; complete schema conformance is not established.",
    "No signature, publisher identity, timestamp authenticity or consuming-context applicability verification.",
    "Only explicit exact versioned PURL identities are resolved; no range, group, relationship or inheritance expansion.",
]


def bounded_tree(value):
    pending = [(value, 0)]
    count = 0
    signatures = False
    while pending:
        item, depth = pending.pop()
        count += 1
        if isinstance(item, dict) and any(
            key in item for key in ("signature", "signatures", "proof")
        ):
            signatures = True
        children = (
            item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        )
        size = len(children)
        if count + len(pending) + size > MAX_NODES or size and depth >= MAX_DEPTH:
            raise ValueError("Evidence conformance tree exceeds the supported node/depth budget")
        pending.extend((child, depth + 1) for child in children)
    return signatures


def csaf_products(tree):
    """Document-local identities include nested branch products, never relationships."""
    if not isinstance(tree, dict):
        raise ValueError("CSAF product_tree must be an object")
    bounded_tree(tree)
    products = tree.get("full_product_names", [])
    if not isinstance(products, list) or any(not isinstance(item, dict) for item in products):
        raise ValueError("CSAF full_product_names must be objects")
    if len(products) > 10_000:
        raise ValueError("CSAF full_product_names exceeds the supported item limit")
    result = list(products)
    branches = tree.get("branches", [])
    if not isinstance(branches, list):
        raise ValueError("CSAF branches must be an array")
    pending = list(branches)
    while pending:
        branch = pending.pop()
        if not isinstance(branch, dict):
            raise ValueError("CSAF branch must be an object")
        if "product" in branch:
            if not isinstance(branch["product"], dict):
                raise ValueError("CSAF branch product must be an object")
            result.append(branch["product"])
        nested = branch.get("branches", [])
        if not isinstance(nested, list):
            raise ValueError("CSAF nested branches must be an array")
        if len(result) + len(pending) + len(nested) > 10_000:
            raise ValueError("CSAF product tree exceeds the supported item limit")
        pending.extend(nested)
    return result


def conformance(document, profile):
    from dtvp.knowledge.vex import CDX_REASONS, CDX_STATUS, OPEN_REASONS, STATUSES, exact_purl

    if profile not in PROFILES:
        raise ValueError("Unknown DTVP evidence validation profile")
    if not isinstance(document, dict):
        raise ValueError("Evidence conformance requires a document object")
    signatures = bounded_tree(document)
    issues = []

    def issue(path, code):
        if len(issues) < MAX_ISSUES:
            issues.append({"path": path, "code": code})

    def obj(value, path):
        if not isinstance(value, dict):
            issue(path, "object_required")
            return {}
        return value

    def string(value, path):
        if not isinstance(value, str) or not value.strip():
            issue(path, "nonempty_string_required")
            return ""
        return value

    def rows(value, path):
        if not isinstance(value, list) or not 1 <= len(value) <= 10_000:
            issue(path, "bounded_nonempty_array_required")
            return []
        return [obj(item, f"{path}/{index}") for index, item in enumerate(value)]

    def enum(value, choices, path):
        if not isinstance(value, str) or value not in choices:
            issue(path, "unsupported_value")

    def stamp(value, path):
        try:
            parsed = datetime.fromisoformat(string(value, path).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except ValueError:
            issue(path, "timezone_timestamp_required")

    def purl(value, path):
        if not exact_purl(value):
            issue(path, "exact_versioned_purl_required")

    def unsupported(value, path):
        if value:
            issue(path, "scope_semantics_unsupported")

    if profile.startswith("dtvp-openvex"):
        if document.get("@context") != "https://openvex.dev/ns/v0.2.0":
            issue("/@context", "profile_version_mismatch")
        for field in ("@id", "author"):
            string(document.get(field), "/" + field)
        if type(document.get("version")) is not int or document["version"] < 1:
            issue("/version", "positive_integer_required")
        stamp(document.get("timestamp"), "/timestamp")
        for index, row in enumerate(rows(document.get("statements"), "/statements")):
            path = f"/statements/{index}"
            string(
                obj(row.get("vulnerability"), path + "/vulnerability").get("name"),
                path + "/vulnerability/name",
            )
            enum(row.get("status"), STATUSES, path + "/status")
            if "timestamp" in row:
                stamp(row["timestamp"], path + "/timestamp")
            if "justification" in row:
                enum(row["justification"], OPEN_REASONS, path + "/justification")
            if row.get("status") == "not_affected" and not row.get("justification"):
                string(row.get("impact_statement"), path + "/impact_statement")
            if row.get("status") == "affected":
                string(row.get("action_statement"), path + "/action_statement")
            for field in ("impact_statement", "action_statement"):
                if field in row:
                    string(row[field], path + "/" + field)
            for number, product in enumerate(rows(row.get("products"), path + "/products")):
                scope = f"{path}/products/{number}"
                purl(product.get("@id"), scope + "/@id")
                unsupported(product.get("subcomponents"), scope + "/subcomponents")
    elif profile.startswith("dtvp-cyclonedx"):
        version = profile.split("-")[2]
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != version:
            issue("/specVersion", "profile_version_mismatch")
        components = {}
        pending = rows(document.get("components"), "/components")
        metadata = obj(document.get("metadata", {}), "/metadata")
        if "component" in metadata:
            pending.append(obj(metadata["component"], "/metadata/component"))
        while pending:
            component = pending.pop()
            ref = string(component.get("bom-ref"), "/components/bom-ref")
            if ref in components:
                issue("/components/bom-ref", "duplicate_component_reference")
            components[ref] = component
            if component.get("components"):
                pending.extend(rows(component["components"], "/components/components"))
        for index, row in enumerate(rows(document.get("vulnerabilities"), "/vulnerabilities")):
            path = f"/vulnerabilities/{index}"
            string(row.get("id"), path + "/id")
            analysis = obj(row.get("analysis", {}), path + "/analysis")
            if "state" in analysis:
                enum(analysis["state"], CDX_STATUS, path + "/analysis/state")
            if "justification" in analysis:
                enum(analysis["justification"], CDX_REASONS, path + "/analysis/justification")
            if (
                isinstance(analysis.get("state"), str)
                and analysis.get("state") in {"not_affected", "false_positive"}
                and not analysis.get("justification")
            ):
                string(analysis.get("detail"), path + "/analysis/detail")
            if "detail" in analysis:
                string(analysis["detail"], path + "/analysis/detail")
            for scope in rows(row.get("affects"), path + "/affects"):
                ref = string(scope.get("ref"), path + "/affects/ref")
                if ref not in components:
                    issue(path + "/affects/ref", "unresolved_document_component_reference")
                else:
                    purl(components[ref].get("purl"), path + "/affects/ref/purl")
                unsupported(scope.get("versions"), path + "/affects/versions")
    else:
        header = obj(document.get("document"), "/document")
        if header.get("csaf_version") != "2.0" or header.get("category") != "csaf_vex":
            issue("/document", "profile_version_mismatch")
        tracking = obj(header.get("tracking"), "/document/tracking")
        for field in ("id", "version"):
            string(tracking.get(field), "/document/tracking/" + field)
        tree = obj(document.get("product_tree"), "/product_tree")
        unsupported(tree.get("relationships"), "/product_tree/relationships")
        unsupported(tree.get("product_groups"), "/product_tree/product_groups")
        products = {}
        for product in csaf_products(tree):
            identifier = string(product.get("product_id"), "/product_tree/product_id")
            if identifier in products:
                issue("/product_tree/product_id", "duplicate_product_identifier")
            helper = obj(
                product.get("product_identification_helper"),
                "/product_tree/product_identification_helper",
            )
            purl(helper.get("purl"), "/product_tree/product_identification_helper/purl")
            products[identifier] = product
        for index, row in enumerate(rows(document.get("vulnerabilities"), "/vulnerabilities")):
            path = f"/vulnerabilities/{index}"
            if not row.get("cve"):
                ids = rows(row.get("ids"), path + "/ids")
                for identity in ids:
                    string(identity.get("text"), path + "/ids/text")
            else:
                string(row["cve"], path + "/cve")
            statuses = obj(row.get("product_status"), path + "/product_status")
            if not statuses:
                issue(path + "/product_status", "nonempty_status_scope_required")
            seen = set()
            for status, identifiers in statuses.items():
                enum(
                    status,
                    {"known_affected", "known_not_affected", "fixed", "under_investigation"},
                    path + "/product_status",
                )
                if not isinstance(identifiers, list) or not identifiers:
                    issue(path + "/product_status", "nonempty_identifier_array_required")
                    continue
                for identifier in identifiers:
                    if not isinstance(identifier, str) or identifier not in products:
                        issue(path + "/product_status", "unknown_product_identifier")
                        continue
                    if identifier in seen:
                        issue(path + "/product_status", "conflicting_product_status")
                    seen.add(identifier)
            for field in ("threats", "flags"):
                details = row.get(field, [])
                if not isinstance(details, list):
                    issue(path + "/" + field, "array_required")
                    continue
                for number, detail in enumerate(details):
                    detail = obj(detail, f"{path}/{field}/{number}")
                    unsupported(detail.get("group_ids"), f"{path}/{field}/{number}/group_ids")
                    if field == "flags":
                        enum(detail.get("label"), OPEN_REASONS, f"{path}/{field}/{number}/label")
                    if field == "threats" and detail.get("category") == "impact":
                        string(detail.get("details"), f"{path}/{field}/{number}/details")
                    if "product_ids" in detail:
                        refs = detail["product_ids"]
                        if not isinstance(refs, list) or any(
                            not isinstance(ref, str) or ref not in products for ref in refs
                        ):
                            issue(
                                f"{path}/{field}/{number}/product_ids",
                                "known_product_identifiers_required",
                            )
            for product_id in (
                statuses.get("known_not_affected", [])
                if isinstance(statuses.get("known_not_affected", []), list)
                else []
            ):
                reasons = (
                    [
                        detail
                        for detail in row.get("flags", [])
                        if isinstance(detail, dict)
                        and isinstance(detail.get("product_ids"), list)
                        and product_id in detail["product_ids"]
                        and isinstance(detail.get("label"), str)
                        and detail.get("label") in OPEN_REASONS
                    ]
                    if isinstance(row.get("flags", []), list)
                    else []
                )
                impacts = (
                    [
                        detail
                        for detail in row.get("threats", [])
                        if isinstance(detail, dict)
                        and detail.get("category") == "impact"
                        and isinstance(detail.get("product_ids"), list)
                        and product_id in detail["product_ids"]
                        and isinstance(detail.get("details"), str)
                        and detail["details"].strip()
                    ]
                    if isinstance(row.get("threats", []), list)
                    else []
                )
                if not reasons and not impacts:
                    issue(
                        path + "/product_status/known_not_affected",
                        "product_scoped_not_affected_reason_required",
                    )
    return {
        "profile": profile,
        "valid": not issues,
        "diagnostics": issues,
        "diagnostics_limit": MAX_ISSUES,
        "schema_validation": "dtvp_supported_subset_only",
        "signature_verification": "not_performed",
        "warnings": (
            [{"path": "/", "code": "signature_present_not_verified"}] if signatures else []
        ),
        "limitations": LIMITATIONS,
    }


def require_conformance(document, profile):
    report = conformance(document, profile)
    if not report["valid"]:
        first = report["diagnostics"][0]
        raise ValueError(f"DTVP evidence profile rejected {first['path']}: {first['code']}")
    return report
