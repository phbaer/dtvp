"""The published JSON Schemas of ``dtvp.dump/1`` and their validators.

The schemas live in ``dtvp/resources/dump-schemas/1``; restore, verify and
the tests validate against the same files.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

FORMAT = "dtvp.dump"
FORMAT_VERSION = 1
# The highest minor version this reader knows.
FORMAT_MINOR = 2
FEATURE_CREDENTIALS = "credentials"
FEATURE_EVIDENCE_MATERIAL = "evidence-supporting-material"
KNOWN_FEATURES = frozenset({FEATURE_CREDENTIALS, FEATURE_EVIDENCE_MATERIAL})
SCOPE_INSTANCE = "instance"

# The fixed order of the entities in a dump.
ENTITY_ORDER: tuple[str, ...] = (
    "assessment",
    "revision",
    "outbox_entry",
    "known_project",
    "source_snapshot",
    "source_project",
    "source_finding",
    "source_project_vulnerability",
    "source_bom",
    "source_analysis",
    "token_audit",
    "access_token",
    "code_analysis_result",
    "code_analysis_application",
    "code_evidence",
    "code_evidence_application",
    "finding_presence",
    "finding_read",
    "session_version",
    "saved_view",
    "saved_view_default",
    "tmrescore_proposal",
    "instance_metadata",
)

# The current schema version of each entity (``dtvp.dump.<entity>/<n>``).
ENTITY_SCHEMA_VERSIONS: dict[str, int] = {name: 1 for name in ENTITY_ORDER}

# Entities added within dump version 1: a dump of an older minor version
# does not list them and holds none.
OPTIONAL_ENTITIES: frozenset[str] = frozenset({"saved_view", "saved_view_default"})

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "resources" / "dump-schemas" / "1"
SCHEMA_ID_PREFIX = "urn:dtvp:dump:1:"


def entity_schema_id(name: str, version: int | None = None) -> str:
    """The manifest form, for example ``dtvp.dump.assessment/1``."""
    return f"dtvp.dump.{name}/{ENTITY_SCHEMA_VERSIONS[name] if version is None else version}"


def parse_entity_schema_id(value: str, name: str) -> int | None:
    prefix = f"dtvp.dump.{name}/"
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    number = value[len(prefix) :]
    return int(number) if number.isdigit() else None


def schema_names() -> list[str]:
    return sorted(path.name[: -len(".schema.json")] for path in SCHEMA_DIR.glob("*.schema.json"))


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    with open(SCHEMA_DIR / f"{name}.schema.json", "r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def registry() -> Registry:
    resources = [
        (load_schema(name)["$id"], Resource.from_contents(load_schema(name)))
        for name in schema_names()
    ]
    return Registry().with_resources(resources)


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    """A compiled validator for ``manifest`` or an entity."""
    return Draft202012Validator(load_schema(name), registry=registry())


def errors(name: str, document: Any) -> list[ValidationError]:
    return sorted(validator(name).iter_errors(document), key=lambda error: list(error.path))


def describe(error: ValidationError) -> str:
    location = "/".join(str(part) for part in error.absolute_path)
    return f"{location or '(record)'}: {error.message}"


def strip_unknown_properties(name: str, document: Any) -> tuple[Any, list[str]] | None:
    """For a dump of a newer minor version: when every error of a document is
    an unknown property, return a copy without those properties and their
    paths. Otherwise ``None``."""
    found = errors(name, document)
    if not found or any(error.validator != "additionalProperties" for error in found):
        return None
    stripped = json.loads(json.dumps(document))
    removed: list[str] = []
    for error in found:
        target = stripped
        for part in error.absolute_path:
            target = target[part]
        if not isinstance(target, dict):
            return None
        allowed = set(error.schema.get("properties", {}))
        for key in [key for key in target if key not in allowed]:
            del target[key]
            removed.append("/".join([*map(str, error.absolute_path), key]))
    if errors(name, stripped):
        return None
    return stripped, sorted(set(removed))
