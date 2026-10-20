"""Versioned SBOM adapters. Never match packages using a name alone."""

import copy
import json

from defusedxml import ElementTree
from packageurl import PackageURL

from dtvp.storage import canonical, digest

PARSER_VERSION = "sbom/1"


def validate_advisory(value):
    if not isinstance(value, dict):
        raise ValueError("Advisory must be an object")
    ratings = value.get("ratings", [])
    if not isinstance(ratings, list):
        raise ValueError("Advisory ratings must be an array")
    for rating in ratings:
        if not isinstance(rating, dict):
            raise ValueError("Invalid advisory rating")
        score = rating.get("score")
        if score is not None and (
            isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10
        ):
            raise ValueError("Original severity score must be between zero and ten")
        if rating.get("vector") is not None and not isinstance(rating["vector"], str):
            raise ValueError("CVSS vector must be text")
    if not isinstance(value.get("description", ""), str):
        raise ValueError("Advisory description must be text")
    aliases = value.get("aliases", [])
    if not isinstance(aliases, list) or any(
        not isinstance(a, dict) or not isinstance(a.get("id", ""), str) for a in aliases
    ):
        raise ValueError("Advisory aliases must contain identifier objects")
    if not isinstance(value.get("references", []), list) or not isinstance(
        value.get("cwes", []), list
    ):
        raise ValueError("Advisory references and CWEs must be arrays")


def identity(component: dict, source: str):
    purl = component.get("purl", "")
    hashes = sorted((h.get("alg", ""), h.get("content", "")) for h in component.get("hashes", []))
    if purl:
        parsed = PackageURL.from_string(purl)
        if not parsed.version or parsed.version != component.get("version"):
            # Do not merge an unversioned or contradictory coordinate across sources.
            return "ref:" + digest(canonical([source, component["bom-ref"], component]))
        return "pkg:" + digest(canonical([parsed.to_string(), hashes]))
    return "ref:" + digest(
        canonical([source, component["bom-ref"], component.get("version", ""), hashes])
    )


def parse(raw: bytes) -> dict:
    try:
        return _parse(raw)
    except (TypeError, KeyError, AttributeError, RecursionError) as error:
        raise ValueError("Malformed SBOM structure") from error


def _parse(raw: bytes) -> dict:
    if raw.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"<"):
        value = cdx_xml(raw)
        result = cdx(value)
        result["format"] = "cyclonedx-xml"
    else:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("SBOM must be an object")
        if value.get("bomFormat") == "CycloneDX":
            result = cdx(value)
        elif value.get("spdxVersion") == "SPDX-2.3":
            result = spdx(value)
        else:
            raise ValueError("Supported: CycloneDX 1.5/1.6 JSON/XML or SPDX 2.3 JSON")
    result["parser"] = PARSER_VERSION
    return result


def cdx(value):
    if value.get("specVersion") not in {"1.5", "1.6"}:
        raise ValueError("Unsupported CycloneDX version; expected 1.5 or 1.6")
    bom = copy.deepcopy(value)
    components = []

    def visit(values):
        for component in values:
            if not isinstance(component, dict):
                raise ValueError("Invalid component")
            components.append(component)
            visit(component.get("components", []))

    visit(bom.get("components", []))
    refs = set()
    root = bom.get("metadata", {}).get("component", {})
    root_ref = root.get("bom-ref")
    for component in components:
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in refs or ref == root_ref:
            raise ValueError("Every component needs a unique bom-ref")
        if not isinstance(component.get("name"), str) or not component["name"]:
            raise ValueError("Every component needs a name")
        if (
            len(component["name"]) > 500
            or not isinstance(component.get("version", ""), str)
            or len(component.get("version", "")) > 200
        ):
            raise ValueError("Component name/version exceeds supported bounds")
        component.setdefault("version", "")
        if component.get("purl"):
            PackageURL.from_string(component["purl"])
        refs.add(ref)
    graph_refs = refs | ({root_ref} if root_ref else set())
    for edge in bom.get("dependencies", []):
        if edge.get("ref") not in graph_refs or any(
            child not in graph_refs for child in edge.get("dependsOn", [])
        ):
            raise ValueError("Dependency contains an unknown reference")
    findings = []
    for vulnerability in bom.get("vulnerabilities", []):
        identifier = vulnerability.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 200:
            raise ValueError("Vulnerability identifier required")
        validate_advisory(vulnerability)
        for affected in vulnerability.get("affects", []):
            if affected.get("ref") not in refs:
                raise ValueError("Vulnerability affects an unknown component")
            findings.append(
                {
                    "ref": affected["ref"],
                    "identifier": identifier,
                    "advisory": vulnerability,
                    "match": affected,
                }
            )
    return {
        "format": "cyclonedx-json",
        "bom": bom,
        "components": components,
        "findings": findings,
        "losses": [],
    }


def spdx(value):
    packages = value.get("packages", [])
    root_ref = value.get("SPDXID", "SPDXRef-DOCUMENT")
    components = []
    losses = ["SPDX-specific fields retained in the original artifact and source document"]
    for package in packages:
        purls = [
            x.get("referenceLocator")
            for x in package.get("externalRefs", [])
            if x.get("referenceType") == "purl"
        ]
        if len(purls) > 1:
            raise ValueError("Ambiguous SPDX package PURL")
        components.append(
            {
                "type": "library",
                "bom-ref": package.get("SPDXID"),
                "name": package.get("name"),
                "version": package.get("versionInfo", ""),
                **({"purl": purls[0]} if purls else {}),
                "properties": [{"name": "dtvp:spdx-source", "value": json.dumps(package)}],
                "hashes": [
                    {"alg": x["algorithm"], "content": x["checksumValue"]}
                    for x in package.get("checksums", [])
                ],
            }
        )
    edges = {component["bom-ref"]: set() for component in components}
    edges[root_ref] = set()
    for relation in value.get("relationships", []):
        left, right, kind = (
            relation.get("spdxElementId"),
            relation.get("relatedSpdxElement"),
            relation.get("relationshipType"),
        )
        if kind == "DEPENDENCY_OF":
            left, right, kind = right, left, "DEPENDS_ON"
        if kind in {"DEPENDS_ON", "DESCRIBES", "CONTAINS"}:
            if left not in edges or right not in edges:
                raise ValueError("SPDX dependency contains an unknown reference")
            edges[left].add(right)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": value.get("name", "SPDX document"),
                "bom-ref": root_ref,
            }
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(children)} for ref, children in edges.items()
        ],
    }
    result = cdx(bom)
    result.update(format="spdx-2.3-json", source_document=value, losses=losses)
    return result


def cdx_xml(raw):
    from defusedxml.common import DefusedXmlException

    try:
        root = ElementTree.fromstring(raw)
    except (DefusedXmlException, ElementTree.ParseError) as error:
        raise ValueError("Invalid or unsafe XML") from error
    namespace = root.tag.split("}")[0].removeprefix("{")
    version = namespace.rsplit("/", 1)[-1]
    if namespace != f"http://cyclonedx.org/schema/bom/{version}":
        raise ValueError("Unsupported XML namespace")

    def tag(node):
        return node.tag.rsplit("}", 1)[-1]

    def convert(node):
        result = dict(node.attrib)
        lists = {
            "components": "component",
            "properties": "property",
            "hashes": "hash",
            "ratings": "rating",
            "affects": "target",
            "references": "reference",
        }
        for child in node:
            name = tag(child)
            if name in lists:
                result[name] = [convert(item) for item in child]
            elif name == "dependencies":
                result[name] = [
                    {"ref": item.get("ref"), "dependsOn": [x.get("ref") for x in item]}
                    for item in child
                ]
            elif len(child) or child.attrib:
                result[name] = convert(child)
            else:
                result[name] = child.text or ""
        if tag(node) == "hash":
            result["content"] = node.text or ""
        if tag(node) == "property":
            result["value"] = node.text or ""
        return result

    value = convert(root)
    value.update(bomFormat="CycloneDX", specVersion=version, version=int(root.get("version", "1")))
    vulnerabilities = root.find(f"{{{namespace}}}vulnerabilities")
    if vulnerabilities is not None:
        value["vulnerabilities"] = [convert(item) for item in vulnerabilities]
    return value
