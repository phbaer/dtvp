"""The manifest of an instance dump: building it on export and checking it
(rules F1-F9) before anything else is read."""

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import schemas
from .errors import DumpError, Finding
from .upcasters import Upcast, upcast_chain

MANIFEST_NAME = "manifest.json"


def sanitize_dependency_track_url(url: str | None) -> str | None:
    """scheme://host[:port]/path: no user information, query or fragment."""
    if not url:
        return None
    try:
        parts = urlsplit(str(url).strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, "", ""))


@dataclass
class CheckedManifest:
    """A manifest that passed F1-F5 and F7-F9, with the upcaster chain of
    every entity and what a newer minor version added (F6)."""

    manifest: dict[str, Any]
    raw: dict[str, Any]
    newer_minor: bool
    unknown_entities: list[str] = field(default_factory=list)
    unknown_fields: list[str] = field(default_factory=list)
    chains: dict[str, list[Upcast]] = field(default_factory=dict)
    warnings: list[Finding] = field(default_factory=list)

    @property
    def dump_id(self) -> str:
        return str(self.manifest["dump_id"])

    def listed_members(self) -> set[str]:
        """Every member the manifest lists, including parts of entities this
        reader does not know."""
        listed = {MANIFEST_NAME}
        for spec in (self.raw.get("entities") or {}).values():
            for part in (spec or {}).get("parts") or []:
                if isinstance(part, dict) and isinstance(part.get("path"), str):
                    listed.add(part["path"])
        for spec in (self.raw.get("config") or {}).values():
            if isinstance(spec, dict) and not spec.get("absent") and isinstance(spec.get("path"), str):
                listed.add(spec["path"])
        return listed


def parse_manifest_bytes(data: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DumpError("F5", f"manifest.json is not JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise DumpError("F5", "manifest.json is not a JSON object")
    return manifest


def check_manifest(
    raw: dict[str, Any],
    *,
    allow_unknown: bool = True,
) -> CheckedManifest:
    """Check a parsed manifest.

    Under a newer minor version, unknown entities and fields (F6) are
    stripped and reported as warnings when ``allow_unknown`` is true, and
    refused otherwise.
    """
    if raw.get("format") != schemas.FORMAT:
        raise DumpError("F1", f"Not a DTVP instance dump (format {raw.get('format')!r})")
    version = raw.get("format_version")
    if version != schemas.FORMAT_VERSION:
        raise DumpError(
            "F2",
            f"Dump format version {version!r} is not supported; this DTVP reads "
            f"version {schemas.FORMAT_VERSION}",
        )
    features = raw.get("required_features")
    if not isinstance(features, list):
        raise DumpError("F5", "required_features must be a list")
    unknown_features = sorted({str(item) for item in features} - schemas.KNOWN_FEATURES)
    if unknown_features:
        raise DumpError(
            "F3",
            "The dump requires features this DTVP does not know: "
            + ", ".join(unknown_features),
        )
    scope = raw.get("scope")
    if not isinstance(scope, dict) or scope.get("kind") != schemas.SCOPE_INSTANCE:
        kind = scope.get("kind") if isinstance(scope, dict) else scope
        raise DumpError("F4", f"Only whole-instance dumps can be read (scope {kind!r})")
    contains = raw.get("contains_credentials")
    if contains is not (schemas.FEATURE_CREDENTIALS in features):
        raise DumpError(
            "F9",
            "contains_credentials does not match the required feature 'credentials'",
        )

    minor = raw.get("format_minor")
    newer_minor = isinstance(minor, int) and minor > schemas.FORMAT_MINOR
    checked = CheckedManifest(manifest=raw, raw=raw, newer_minor=newer_minor)
    manifest = raw
    if newer_minor:
        known = set(schemas.ENTITY_ORDER)
        entities = raw.get("entities")
        if isinstance(entities, dict):
            checked.unknown_entities = sorted(name for name in entities if name not in known)
        stripped = schemas.strip_unknown_properties("manifest", raw)
        if stripped is not None:
            manifest, removed = stripped
            checked.unknown_fields = [
                path for path in removed if not path.startswith("entities/")
            ]
    problems = schemas.errors("manifest", manifest)
    if problems:
        raise DumpError(
            "F5",
            "The manifest does not match its schema: "
            + "; ".join(schemas.describe(problem) for problem in problems[:5]),
        )
    if checked.unknown_entities or checked.unknown_fields:
        message = (
            f"The dump is format minor version {minor}; this DTVP knows "
            f"{schemas.FORMAT_MINOR}. Unknown entities: "
            f"{', '.join(checked.unknown_entities) or 'none'}; unknown manifest "
            f"fields: {', '.join(checked.unknown_fields) or 'none'}"
        )
        if not allow_unknown:
            raise DumpError("F6", message + ". Use --allow-unknown to drop them.")
        checked.warnings.append(Finding("F6", message + "; they are dropped"))
    checked.manifest = manifest

    for name in schemas.ENTITY_ORDER:
        spec = manifest["entities"][name]
        version = schemas.parse_entity_schema_id(spec["schema"], name)
        if version is None:
            raise DumpError("F5", f"Invalid schema id for {name}: {spec['schema']!r}")
        checked.chains[name] = upcast_chain(name, version)
    if (
        "access_tokens" in manifest["excluded"]
        and manifest["entities"]["access_token"]["records"]
    ):
        raise DumpError("F5", "access_token records are listed although excluded")
    if (
        "source" in manifest["excluded"]
        and any(
            manifest["entities"][name]["records"]
            for name in (
                "source_snapshot",
                "source_project",
                "source_finding",
                "source_project_vulnerability",
                "source_bom",
                "source_analysis",
            )
        )
    ):
        raise DumpError("F5", "Source records are listed although excluded")
    if manifest["entities"]["access_token"]["records"] and not manifest["contains_credentials"]:
        raise DumpError("F9", "access_token records without the feature 'credentials'")
    return checked
