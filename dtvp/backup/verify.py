"""Checking a dump without a target: the container, the manifest, every
record against its schema, and the referential and semantic rules."""

import json
from dataclasses import dataclass, field
from typing import Any

from ..settings_files import SETTINGS_FILE_NAMES, validate_settings_document
from . import schemas
from .checks import RecordChecker
from .container import DumpReader
from .errors import DumpError, Finding


@dataclass
class VerifyResult:
    manifest: dict[str, Any]
    errors: list[Finding]
    warnings: list[Finding]
    records: dict[str, int] = field(default_factory=dict)
    stripped_fields: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def config_warnings(config: dict[str, bytes | None]) -> list[Finding]:
    """W7: the semantic rules of each settings file. Team groups are checked
    against the team mapping in the same dump."""
    parsed: dict[str, Any] = {}
    for name, data in config.items():
        if data is not None:
            try:
                parsed[name] = json.loads(data)
            except ValueError:
                parsed[name] = None
    warnings = []
    context = {"team_mapping": parsed.get("team_mapping") or {}}
    for name in SETTINGS_FILE_NAMES:
        if name not in parsed:
            continue
        for problem in validate_settings_document(name, parsed[name], context):
            warnings.append(Finding("W7", f"{name}: {problem}"))
    return warnings


def read_all(reader: DumpReader, *, allow_unknown: bool) -> VerifyResult:
    """Stream every record once (C6-C11, S1, R, W). Raises ``DumpError`` on
    the first container, format or schema refusal; referential errors are
    collected."""
    checker = RecordChecker()
    stripped: list[str] = []
    records: dict[str, int] = {}
    for name in schemas.ENTITY_ORDER:
        count = 0
        for record in reader.iter_records(name, stripped=stripped):
            checker.add(name, record)
            count += 1
        records[name] = count
    for name in reader.checked.unknown_entities:
        for _line in reader.iter_unknown_entity_lines(name):
            pass
    config = {name: reader.read_config(name) for name in SETTINGS_FILE_NAMES}
    checker.finish(
        reader.manifest["cut_point"]["sequences"],
        config_warnings=config_warnings(config),
    )
    warnings = list(reader.warnings)
    if stripped:
        finding = Finding(
            "F6",
            "Fields unknown to this DTVP version: " + ", ".join(sorted(set(stripped))[:10]),
        )
        if not allow_unknown:
            raise DumpError(finding.code, finding.message + ". Use --allow-unknown to drop them.")
        warnings.append(finding)
    warnings.extend(checker.warnings)
    return VerifyResult(
        manifest=reader.manifest,
        errors=list(checker.errors),
        warnings=warnings,
        records=records,
        stripped_fields=sorted(set(stripped)),
    )


def verify_dump(path: str, *, allow_unknown: bool = True) -> VerifyResult:
    """Verify a dump. Unknown entities and fields of a newer minor version
    are warnings (F6) unless ``allow_unknown`` is false."""
    with DumpReader(path, allow_unknown=allow_unknown) as reader:
        return read_all(reader, allow_unknown=allow_unknown)


def inspect_dump(path: str) -> dict[str, Any]:
    """The container limits and the manifest only; no record is read."""
    with DumpReader(path, allow_unknown=True) as reader:
        manifest = reader.manifest
        return {
            "path": path,
            "dump_id": manifest["dump_id"],
            "created_at": manifest["created_at"],
            "created_by": manifest["created_by"],
            "reason": manifest["reason"],
            "dtvp": manifest["dtvp"],
            "source": manifest["source"],
            "format": f"{manifest['format']}/{manifest['format_version']}.{manifest['format_minor']}",
            "contains_credentials": manifest["contains_credentials"],
            "excluded": manifest["excluded"],
            "records": {name: manifest["entities"][name]["records"] for name in schemas.ENTITY_ORDER},
            "config": {
                name: ("absent" if spec["absent"] else f"{spec['bytes']} bytes")
                for name, spec in manifest["config"].items()
            },
            "stores": [
                {
                    "name": store["name"],
                    "namespaces": store["namespaces"],
                    "snapshot_method": store["snapshot_method"],
                    "migrations": len(store["migrations"]),
                }
                for store in manifest["stores"]
            ],
            "warnings": [str(item) for item in reader.warnings] + list(manifest["warnings"]),
        }
