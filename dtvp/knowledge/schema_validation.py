"""Opt-in official JSON Schema checks; no network, scope expansion or trust claims."""

import json
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from dtvp.knowledge.evidence_conformance import bounded_tree
from dtvp.storage import canonical, digest

PROFILES = (
    "cyclonedx-1.5-json-schema/1",
    "cyclonedx-1.6-json-schema/1",
    "openvex-0.2.0-json-schema/1",
    "csaf-2.0-json-schema/1",
)
ROOT = Path(__file__).with_name("schema_resources")
MAX_BYTES = 32 * 1024 * 1024
MAX_STRING = 64 * 1024
MAX_DIAGNOSTICS = 64
LIMITATIONS = [
    "JSON Schema validation only; additional normative, semantic and VEX profile tests are not performed.",
    "Schema-valid data may remain unsupported by DTVP's consumed-field intake profiles; intake semantics are unchanged.",
    "Signature presence/structure is not cryptographic verification, authenticated authorship or publisher trust.",
    "No assertion of completeness, product/context applicability, human approval or regulatory compliance.",
    "Only local pinned schema resources are resolved; no document URLs or schema references are fetched.",
]


def _deny_remote(uri):
    raise NoSuchResource(ref=uri)


def _pointer(parts):
    value = "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return value if len(value) <= 512 else value[:512] + "…"


@lru_cache(maxsize=1)
def _resources():
    """Verify bundled bytes and build an explicitly closed reference registry."""
    manifest = json.loads((ROOT / "sources.json").read_bytes())
    if manifest.get("format") != "dtvp.official-schema-resources/1":
        raise ValueError("Unsupported bundled schema resource manifest")
    resources = {}
    metadata = []
    for item in manifest["resources"]:
        name = item["file"]
        if Path(name).name != name:
            raise ValueError("Invalid bundled schema filename")
        raw = (ROOT / name).read_bytes()
        if digest(raw) != item["sha256"]:
            raise ValueError("Bundled schema bytes differ from their pinned digest")
        schema = json.loads(raw)
        resources[name] = schema
        metadata.append({**item, "provider": "vendored_official_resource"})
    # The locked CycloneDX dependency supplies versioned official-schema snapshots.
    # Read exact resources rather than its validator's implicit reference registry.
    from cyclonedx.schema import SchemaVersion, _res

    installed = [
        _res.BOM_JSON[SchemaVersion.V1_5],
        _res.BOM_JSON[SchemaVersion.V1_6],
        _res.SPDX_JSON,
        _res.JSF,
        _res.CRYPTOGRAPHY_DEFS,
    ]
    for path in installed:
        raw = Path(path).read_bytes()
        name = Path(path).name
        schema = json.loads(raw)
        resources[name] = schema
        metadata.append(
            {
                "file": name,
                "sha256": digest(raw),
                "schema_id": schema["$id"],
                "provider": "cyclonedx-python-lib",
                "package_version": version("cyclonedx-python-lib"),
                "source": "https://github.com/CycloneDX/cyclonedx-python-lib",
                "license": "Apache-2.0; retained in installed distribution",
            }
        )
    registry = Registry(retrieve=_deny_remote)
    for name, schema in resources.items():
        resource = Resource.from_contents(schema)
        identifier = schema.get("$id", schema.get("id"))
        if not identifier:
            raise ValueError("Bundled schema lacks its identifier")
        registry = registry.with_resource(identifier, resource)
        if "SNAPSHOT" in name:
            registry = registry.with_resource("http://cyclonedx.org/schema/" + name, resource)
        if name.startswith("cvss-"):
            registry = registry.with_resource("https://www.first.org/cvss/" + name, resource)
    return resources, metadata, registry


def validate_schema(document, profile):
    """Report exact local schema conformance without altering any imported evidence."""
    if profile not in PROFILES:
        raise ValueError("Unknown official JSON Schema validation profile")
    if not isinstance(document, dict):
        raise ValueError("Schema validation requires a document object")
    signatures = bounded_tree(document)
    pending = [document]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if any(not isinstance(key, str) or len(key.encode()) > MAX_STRING for key in item):
                raise ValueError("Schema validation object key exceeds 64 KiB")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and len(item.encode()) > MAX_STRING:
            raise ValueError("Schema validation text value exceeds 64 KiB")
    raw = canonical(document)
    if len(raw) > MAX_BYTES:
        raise ValueError("Evidence exceeds the 32 MiB schema validation limit")
    resources, metadata, registry = _resources()
    names = {
        "cyclonedx-1.5-json-schema/1": "bom-1.5.SNAPSHOT.schema.json",
        "cyclonedx-1.6-json-schema/1": "bom-1.6.SNAPSHOT.schema.json",
        "openvex-0.2.0-json-schema/1": "openvex-0.2.0.schema.json",
        "csaf-2.0-json-schema/1": "csaf-2.0.schema.json",
    }
    schema = resources[names[profile]]
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema, registry=registry, format_checker=FormatChecker())
    diagnostics = []
    truncated = False
    try:
        for error in validator.iter_errors(document):
            if len(diagnostics) == MAX_DIAGNOSTICS:
                truncated = True
                break
            diagnostics.append(
                {
                    "path": _pointer(error.absolute_path),
                    "code": str(error.validator),
                    "schema_path": _pointer(error.absolute_schema_path),
                }
            )
    except RecursionError:
        raise ValueError("JSON Schema evaluation exceeded supported recursion bounds") from None
    # The resource manifest covers the whole locally available closure, so a
    # dependency/library update remains visible even if that branch was not exercised.
    resource_digest = digest(canonical(metadata))
    content = {
        "format": "dtvp.official-schema-validation/1",
        "validation_profile": profile,
        "document_sha256": digest(raw),
        "schema_id": schema.get("$id", schema.get("id")),
        "schema_dialect": schema["$schema"],
        "schema_resources": metadata,
        "schema_resources_digest": resource_digest,
        "valid": not diagnostics,
        "diagnostics": diagnostics,
        "diagnostics_truncated": truncated,
        "schema_validation": "pinned_official_json_schema_only",
        "signature_verification": "not_performed",
        "signatures_present": signatures,
        "semantic_validation": "not_performed",
        "committed": False,
        "limitations": LIMITATIONS,
    }
    return {**content, "report_digest": digest(canonical(content))}
