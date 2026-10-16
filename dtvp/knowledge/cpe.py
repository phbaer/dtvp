"""Internal offline CPE identification proposals, separate from applicability.

First module, not full standalone-service parity: explicit package aliases,
reviewed mappings, supplied exact catalog records and source-reported CPEs.
No name heuristics, NVD queries, database/cache, automatic adoption or approval.
"""

import copy
import re
from urllib.parse import quote, unquote

from packageurl import PackageURL
from pydantic import Field, model_validator

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

ALGORITHM_VERSION = "dtvp.cpe-discovery/1"
BASES = {
    "official": "dictionary_supported_identity",
    "purl2cpe": "community_mapping",
    "internal": "internal_mapping",
    "generated": "generated_guess",
}
LIMITATIONS = [
    "Offline explicit-identity subset; standalone network ranking, name heuristics and refresh are not ported.",
    "Imported source/basis claims are not independently verified; candidates are not approved mappings.",
    "CPE identity does not establish vulnerability applicability or affected version ranges.",
    "CPE validation covers a conservative binding-syntax subset, not dictionary existence or name-matching semantics.",
]


class CatalogEntry(RequestModel):
    purl: str = Field(min_length=1, max_length=3000)
    cpe: str = Field(min_length=1, max_length=3000)
    source: Name
    identification_basis: str = Field(default="community_mapping", min_length=1, max_length=200)
    reason: str = Field(default="", max_length=6000)


class DiscoveryRule(RequestModel):
    target_purl: str | None = Field(default=None, max_length=3000)
    cpe: str | None = Field(default=None, max_length=3000)
    status: str = Field(default="internal", max_length=200)
    source: Name
    reason: str = Field(default="", max_length=6000)

    @model_validator(mode="after")
    def one_action(self):
        if bool(self.target_purl) == bool(self.cpe):
            raise ValueError("A CPE rule requires exactly one target_purl or cpe")
        return self


class DiscoveryInput(RequestModel):
    request_id: Name
    expected: Sha | None
    catalog: list[CatalogEntry] = Field(default_factory=list, max_length=50_000)
    rules: dict[str, DiscoveryRule] = Field(default_factory=dict, max_length=50_000)


def parse_purl(value):
    if not isinstance(value, str) or not value.startswith("pkg:"):
        raise ValueError("CPE mappings require an explicit valid PURL")
    try:
        return PackageURL.from_string(value)
    except ValueError as error:
        raise ValueError("CPE mappings require an explicit valid PURL") from error


def purl_family(package):
    return PackageURL(
        type=package.type,
        namespace=package.namespace,
        name=package.name,
        qualifiers=package.qualifiers,
        subpath=package.subpath,
    ).to_string()


def split_formatted(value):
    fields, current, escaped = [], [], False
    for char in value:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise ValueError("CPE has an unterminated escape")
    fields.append("".join(current))
    return fields


def validate_cpe(value):
    """Validate a conservative CPE URI/formatted-string binding subset.

    Return original binding and parsed fields; never silently convert a URI or
    repair missing identity fields. Escaped separators stay within a field.
    """
    if (
        not isinstance(value, str)
        or len(value) > 3000
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError("CPE must be bounded printable ASCII without whitespace")
    if value.startswith("cpe:2.3:"):
        fields = split_formatted(value)
        if len(fields) != 13 or fields[2] not in {"a", "h", "o", "*", "-"}:
            raise ValueError("CPE 2.3 requires eleven well-formed attributes")
        for token in fields[3:]:
            if not token or not re.fullmatch(r"(?:[A-Za-z0-9._?*-]|\\[^A-Za-z0-9])+", token):
                raise ValueError("Unsupported CPE 2.3 attribute binding")
            literal = re.sub(r"\\.", "x", token).strip("*?")
            if "*" in literal or "?" in literal:
                raise ValueError("CPE wildcards must be confined to attribute boundaries")
        return {"binding": "formatted_string", "fields": fields}
    if value.startswith("cpe:/"):
        fields = value[5:].split(":")
        if (
            not 3 <= len(fields) <= 7
            or fields[0] not in {"a", "h", "o"}
            or not fields[1]
            or not fields[2]
        ):
            raise ValueError("CPE URI requires part, vendor and product")
        if any(
            not re.fullmatch(r"(?:[A-Za-z0-9._~!*'()-]|%[A-Fa-f0-9]{2})*", token)
            for token in fields[1:]
        ):
            raise ValueError("Unsupported CPE URI attribute binding")
        if any(
            any(ord(char) < 32 or ord(char) > 126 for char in unquote(token)) for token in fields
        ):
            raise ValueError("Unsupported encoded CPE URI characters")
        return {"binding": "uri", "fields": fields}
    raise ValueError("Supported CPE bindings are cpe:2.3 and cpe:/ URI")


def cpe_version(value, version):
    parsed = validate_cpe(value)
    fields = list(parsed["fields"])
    index = 5 if parsed["binding"] == "formatted_string" else 3
    current = fields[index] if len(fields) > index else ""
    if not version:
        return value
    decoded = (
        re.sub(r"\\(.)", r"\1", current)
        if parsed["binding"] == "formatted_string"
        else unquote(current)
    )
    if current not in {"", "*"} and decoded != version:
        return None
    if current in {"", "*"}:
        while len(fields) <= index:
            fields.append("")
        fields[index] = (
            "".join(
                char if re.fullmatch(r"[A-Za-z0-9._-]", char) else "\\" + char for char in version
            )
            if parsed["binding"] == "formatted_string"
            else quote(version, safe="._-")
        )
    candidate = (
        ":".join(fields) if parsed["binding"] == "formatted_string" else "cpe:/" + ":".join(fields)
    )
    validate_cpe(candidate)
    return candidate


def normalize_inputs(catalog, rules):
    if len(catalog) > 50_000 or len(rules) > 50_000:
        raise ValueError("CPE inputs exceed the supported 50,000 record limit")
    catalog = [CatalogEntry.model_validate(item).model_dump() for item in catalog]
    normalized = {}
    for key, value in rules.items():
        package = parse_purl(key)
        identity = package.to_string()
        if identity in normalized:
            raise ValueError("Duplicate normalized package rule")
        rule = DiscoveryRule.model_validate(value).model_dump(exclude_none=True)
        if rule.get("target_purl"):
            rule["target_purl"] = parse_purl(rule["target_purl"]).to_string()
        if rule.get("cpe"):
            validate_cpe(rule["cpe"])
        normalized[identity] = rule
    for entry in catalog:
        entry["purl"] = parse_purl(entry["purl"]).to_string()
        validate_cpe(entry["cpe"])
    return sorted(catalog, key=canonical), normalized


def propose_for_component(component, catalog, rules):
    catalog, rules = normalize_inputs(catalog, rules)
    raw_purl = component.get("purl")
    requested = parse_purl(raw_purl) if raw_purl else None
    if (
        requested
        and requested.version
        and component.get("version")
        and requested.version != component["version"]
    ):
        raise ValueError("Component version contradicts its PURL")
    if requested and not requested.version and component.get("version"):
        requested = PackageURL(
            type=requested.type,
            namespace=requested.namespace,
            name=requested.name,
            version=component["version"],
            qualifiers=requested.qualifiers,
            subpath=requested.subpath,
        )
    resolved, selected, seen, candidates, rejected = requested, [], set(), [], []

    def add(cpe, basis, provenance):
        adjusted = cpe_version(cpe, resolved.version if resolved else component.get("version"))
        if adjusted is None:
            rejected.append(
                {
                    "cpe": cpe,
                    "reason": "explicit_cpe_version_conflicts_with_package_version",
                    "provenance": provenance,
                }
            )
            return
        candidates.append(
            {
                "cpe": adjusted,
                "source_cpe": cpe,
                "identification_basis": basis,
                "provenance": provenance,
                "applicability": "not_assessed",
                "basis_verification": "imported_claim_not_verified",
            }
        )

    if component.get("cpe"):
        add(
            component["cpe"],
            "source_reported_identity",
            {"kind": "component", "source": "imported_component", "ref": component.get("bom-ref")},
        )
    while resolved:
        identity = resolved.to_string()
        family = purl_family(resolved)
        key = identity if identity in rules else family
        rule = rules.get(key)
        if not rule:
            break
        if identity in seen:
            raise ValueError("Cyclic package alias")
        seen.add(identity)
        selected.append({"identity": key, **copy.deepcopy(rule)})
        if rule.get("cpe"):
            add(
                rule["cpe"],
                BASES.get(rule["status"], "imported_mapping"),
                {"kind": "mapping_rule", "identity": key, **copy.deepcopy(rule)},
            )
            break
        target = parse_purl(rule["target_purl"])
        if target.version and resolved.version and target.version != resolved.version:
            raise ValueError("Package alias must not silently change the package version")
        resolved = PackageURL(
            type=target.type,
            namespace=target.namespace,
            name=target.name,
            version=target.version or resolved.version,
            qualifiers=target.qualifiers or resolved.qualifiers,
            subpath=target.subpath or resolved.subpath,
        )
    if resolved:
        for entry in catalog:
            package = parse_purl(entry["purl"])
            if purl_family(package) != purl_family(resolved) or (
                package.version and package.version != resolved.version
            ):
                continue
            add(entry["cpe"], entry["identification_basis"], {"kind": "supplied_catalog", **entry})
    result = {
        "algorithm_version": ALGORITHM_VERSION,
        "requested_purl": requested.to_string() if requested else None,
        "resolved_purl": resolved.to_string() if resolved else None,
        "reviewed_rules": selected,
        "candidates": sorted(candidates, key=canonical),
        "rejected_candidates": sorted(rejected, key=canonical),
        "applicability": "not_assessed",
        "limitations": list(LIMITATIONS),
        "catalog_content_digest": digest(canonical(catalog)),
        "rules_content_digest": digest(canonical(rules)),
    }
    result["content_digest"] = digest(canonical(result))
    return result


def policy_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="cpe")


def current_discovery_policy(journal, project_id):
    state = journal.resolve(policy_ref(project_id))
    if not state:
        return None, {"algorithm_version": ALGORITHM_VERSION, "catalog": [], "rules": {}}
    return state, journal.load(journal.records(state, "inventory")["cpe:configuration"])


def import_discovery_policy(journal, *, project_id, actor_id, data):
    fingerprint = digest(
        canonical(["cpe.configure/1", project_id, actor_id, data.model_dump(mode="json")])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    if journal.resolve(policy_ref(project_id)) != data.expected:
        raise Conflict("CPE discovery configuration changed; reload before importing")
    catalog, rules = normalize_inputs(
        [entry.model_dump() for entry in data.catalog],
        {key: value.model_dump(exclude_none=True) for key, value in data.rules.items()},
    )
    config = {
        "algorithm_version": ALGORITHM_VERSION,
        "catalog": catalog,
        "rules": rules,
        "catalog_content_digest": digest(canonical(catalog)),
        "rules_content_digest": digest(canonical(rules)),
        "limitations": list(LIMITATIONS),
    }
    # Catalog/rule edits do not implicitly replace separately captured offline sources.
    if data.expected:
        previous = journal.load(journal.records(data.expected, "inventory")["cpe:configuration"])
        for key in (
            "offline_sources",
            "retained_dictionary",
            "retained_mapping_history",
            "offline_source_limitations",
        ):
            if key in previous:
                config[key] = copy.deepcopy(previous[key])
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {"cpe:configuration": config}
    state = journal.snapshot(
        project_id=project_id,
        version="@cpe",
        actor_id=actor_id,
        reason="Import CPE identification inputs",
        sections=sections,
        parents=[data.expected] if data.expected else [],
        artifacts=journal.state(data.expected).artifacts if data.expected else [],
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=policy_ref(project_id), expected=data.expected, target=state)],
    )
