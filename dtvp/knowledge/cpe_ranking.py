"""Bounded offline dictionary-candidate ranking; no identity adoption or network IO."""

import copy
import re
from urllib.parse import unquote, urlsplit

from pydantic import Field, StrictBool

from dtvp.knowledge.cpe import parse_purl, propose_for_component, validate_cpe
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

ALGORITHM = "dtvp.cpe-offline-ranking/1"
LIMITATIONS = [
    "Supplied dictionary, publisher, URL and mapping claims are not independently verified.",
    "Ordering is identification evidence, not confidence, adoption, approval or vulnerability applicability.",
    "This bounded subset omits live registry/NVD acquisition, Java vendor inference, deprecated replacement traversal and fuzzy matching.",
    "Registry URLs describe package coordinates, not build, qualifier, binary or distribution identity.",
    "A matching source repository does not establish independently versioned subpackage identity.",
]


class Reference(RequestModel):
    ref: str = Field(min_length=1, max_length=2048)
    type: str = Field(default="", max_length=200)


class DictionaryRecord(RequestModel):
    cpeName: str = Field(min_length=1, max_length=3000)
    cpeNameId: str | None = Field(default=None, max_length=200)
    deprecated: StrictBool = False
    refs: list[Reference] = Field(default_factory=list, max_length=50)
    source: str = Field(min_length=1, max_length=200)
    publisher: str = Field(default="", max_length=200)


def token(value):
    return re.sub(r"[\s._-]+", "", re.sub(r"\\(.)", r"\1", value).lower())


def url(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or parsed.username or parsed.password:
            return "", ""
        if parsed.port not in {None, 80, 443}:
            return "", ""
        return (parsed.hostname or "").lower().removeprefix("www."), unquote(parsed.path).strip("/")
    except ValueError:
        return "", ""


def repository(value):
    host, path = url(value)
    parts = path.split("/")
    if host not in {"github.com", "gitlab.com", "bitbucket.org"} or len(parts) < 2:
        return ""
    # Nested GitLab groups are ambiguous without supplied project metadata.
    if host == "gitlab.com":
        return host + "/" + path.removesuffix(".git")
    return host + "/" + "/".join(parts[:2]).removesuffix(".git").lower()


def registry_match(value, package):
    host, path = url(value)
    bits = path.split("/")
    if package.type == "npm" and host in {"npmjs.com", "npmjs.org"}:
        coordinate = (package.namespace + "/" if package.namespace else "") + package.name
        return path == "package/" + coordinate or path.startswith("package/" + coordinate + "/v/")
    if package.type == "pypi" and host in {"pypi.org", "pypi.python.org"}:

        def normalize(name):
            return re.sub(r"[-_.]+", "-", name).lower()

        return (
            len(bits) >= 2
            and bits[0] in {"project", "pypi"}
            and normalize(bits[1]) == normalize(package.name)
        )
    if package.type == "maven" and host in {"mvnrepository.com", "central.sonatype.com"}:
        return len(bits) >= 3 and bits[:3] == ["artifact", package.namespace, package.name]
    return False


def attributes(cpe):
    parsed = validate_cpe(cpe)
    if parsed["binding"] == "formatted_string":
        return parsed["fields"][2:]
    fields = [unquote(item) or "*" for item in parsed["fields"]]
    return (fields + ["*"] * 11)[:11]


def compatible(fields, package):
    if fields[0] != "a":
        return False
    target = fields[8].lower()
    languages = {
        "npm": {"node.js", "nodejs", "javascript"},
        "pypi": {"python"},
        "maven": {"java"},
        "cargo": {"rust"},
        "gem": {"ruby"},
        "nuget": {".net", "dotnet"},
    }
    if package.type == "npm" and package.namespace == "@types" and fields[1] != "types":
        return False
    if target in {"*", "-"}:
        return True
    if package.type in languages:
        return target in languages[package.type]
    if package.type in {"generic", "conan", "github"}:
        return target not in set().union(
            *languages.values(), {"go", "lua", "php", "wordpress", "visual_studio_code"}
        )
    return False  # No inferred target-platform compatibility for unsupported ecosystems.


def rank_candidates(component, records, catalog=(), rules=None, *, offset=0, limit=50):
    """Rank all bounded records before paging; preserve original bindings/versions.

    The caller supplies a component from an authorized committed inventory state.
    Mapping and dictionary source claims remain attributed and unverified.
    """
    if len(records) > 2000 or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Dictionary ranking supports 2,000 records and pages of 1..200")
    records = [DictionaryRecord.model_validate(item).model_dump(mode="json") for item in records]
    if len(canonical(records)) > 2 * 1024 * 1024:
        raise ValueError("Dictionary candidate input exceeds 2 MiB")
    proposal = propose_for_component(component, list(catalog), rules or {})
    package = parse_purl(proposal["resolved_purl"]) if proposal["resolved_purl"] else None
    mapped = {tuple(attributes(item["source_cpe"])[:3]) for item in proposal["candidates"]}
    source_repos = {
        repository(ref.get("url", ""))
        for ref in component.get("externalReferences", [])
        if isinstance(ref, dict) and ref.get("type") == "vcs" and isinstance(ref.get("url"), str)
    } - {""}
    candidates, rejected = [], []
    for record in sorted(records, key=canonical):
        reasons, rejection = [], None
        try:
            fields = attributes(record["cpeName"])
        except ValueError:
            rejection, fields = "unsupported_or_malformed_cpe_binding", None
        if record["deprecated"]:
            rejection = "deprecated_dictionary_claim"
        if not package:
            rejection = "component_has_no_explicit_purl"
        elif fields and not compatible(fields, package):
            rejection = "incompatible_part_or_ecosystem"
        if fields and package and package.version and fields[3] != "*":
            if re.sub(r"\\(.)", r"\1", fields[3]) != package.version:
                rejection = "explicit_cpe_version_conflicts_with_package_version"
        direct = bool(
            package and any(registry_match(ref["ref"], package) for ref in record["refs"])
        )
        repos = {repository(ref["ref"]) for ref in record["refs"]} - {""}
        product = bool(package and fields and token(fields[2]) == token(package.name))
        source = bool(source_repos & repos) and product
        mapping = bool(fields and tuple(fields[:3]) in mapped)
        vendor = bool(
            package
            and package.namespace
            and fields
            and token(fields[1]) == token(package.namespace.lstrip("@"))
        )
        if source_repos and repos and not source_repos & repos and not direct:
            rejection = "conflicting_supplied_repository_claims"
        if not rejection and not (direct or source or mapping or (product and vendor)):
            rejection = "insufficient_package_identity_evidence"
        for matched, reason in [
            (direct, "exact_registry_package_reference"),
            (source, "supplied_repository_and_product_match"),
            (mapping, "existing_explicit_identity_candidate"),
            (product and vendor, "namespace_vendor_and_product_match"),
        ]:
            if matched:
                reasons.append(reason)
        version_comparison = "not_checked"
        if package and fields:
            version_comparison = (
                "component_version_unknown"
                if not package.version
                else "catalog_version_unspecified"
                if fields[3] == "*"
                else "exact_match"
                if re.sub(r"\\(.)", r"\1", fields[3]) == package.version
                else "conflict"
            )
        row = {
            "version_comparison": version_comparison,
            "cpe": record["cpeName"],
            "record": copy.deepcopy(record),
            "reasons": reasons,
            "applicability": "not_assessed",
            "basis_verification": "supplied_claim_not_verified",
        }
        if rejection:
            rejected.append({**row, "rejection": rejection})
        else:
            row["ranking_evidence"] = [
                int(direct),
                int(source),
                int(mapping),
                int(product and vendor),
                int(product),
                int(bool(package.version and fields[3] == package.version)),
            ]
            candidates.append(row)
    candidates.sort(
        key=lambda row: (tuple(-part for part in row["ranking_evidence"]), canonical(row))
    )
    best = candidates[0]["ranking_evidence"] if candidates else None
    top = [item for item in candidates if item["ranking_evidence"] == best]
    identities = {tuple(attributes(item["cpe"])[:3]) for item in top}
    report = {
        "format": ALGORITHM,
        "ranking_evidence_order": [
            "registry_coordinate",
            "repository_and_product",
            "explicit_mapping",
            "namespace_and_product",
            "product_name",
            "exact_version",
        ],
        "requested_purl": proposal["requested_purl"],
        "resolved_purl": proposal["resolved_purl"],
        "input_digest": digest(canonical(records)),
        "policy_proposal": proposal,
        "candidates": candidates,
        "rejected": rejected,
        "ambiguity": "cross_identity_tie"
        if len(identities) > 1
        else "none_observed"
        if candidates
        else "no_candidate",
        "selection": None,
        "applicability": "not_assessed",
        "limitations": list(LIMITATIONS),
    }
    report["content_digest"] = digest(canonical(report))
    return {
        **report,
        "candidates": candidates[offset : offset + limit],
        "rejected": rejected[offset : offset + limit],
        "counts": {
            "supplied": len(records),
            "candidates": len(candidates),
            "rejected": len(rejected),
        },
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit
        if offset + limit < max(len(candidates), len(rejected))
        else None,
    }
