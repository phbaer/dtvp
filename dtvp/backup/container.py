"""Reading and writing the ZIP container of ``dtvp.dump/1`` on top of
``dtvp.bundle_io``."""

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import IO, Any, Iterable, Iterator

from ..bundle_io import (
    BundleError,
    ZipBundleReader,
    ZipBundleWriter,
    jsonl_line,
    sha256_hex,
    stable_json_bytes,
)
from . import schemas
from .errors import DumpError, Finding
from .manifest import MANIFEST_NAME, CheckedManifest, check_manifest, parse_manifest_bytes
from .upcasters import apply_chain

MAX_MEMBERS = 10_000
DEFAULT_MAX_UNCOMPRESSED_BYTES = 16 * 1024**3
MAX_RECORD_BYTES = 256 * 1024**2
PART_MAX_RECORDS = 100_000
PART_MAX_BYTES = 64 * 1024**2


def get_max_uncompressed_bytes() -> int:
    raw = os.getenv("DTVP_DUMP_MAX_UNCOMPRESSED_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_UNCOMPRESSED_BYTES
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_MAX_UNCOMPRESSED_BYTES


def part_path(entity: str, number: int) -> str:
    return f"records/{entity}/{entity}-{number:04d}.jsonl"


def config_path(name: str) -> str:
    return f"config/{name}.json"


class DumpWriter:
    """Writes entities into record parts, the settings files and the
    manifest, in that order."""

    def __init__(
        self,
        fileobj: IO[bytes],
        *,
        part_max_records: int | None = None,
        part_max_bytes: int | None = None,
        max_record_bytes: int | None = None,
    ) -> None:
        self._bundle = ZipBundleWriter(fileobj)
        self.part_max_records = part_max_records or PART_MAX_RECORDS
        self.part_max_bytes = part_max_bytes or PART_MAX_BYTES
        self.max_record_bytes = max_record_bytes or MAX_RECORD_BYTES

    def write_entity(
        self,
        name: str,
        records: Iterable[dict[str, Any]],
        *,
        describe: Any = None,
    ) -> dict[str, Any]:
        """Stream the records of an entity into parts. Returns the manifest
        entry of the entity."""
        parts: list[dict[str, Any]] = []
        total = 0
        member = None
        context = None
        count = 0
        try:
            for record in records:
                line = jsonl_line(record)
                if len(line) > self.max_record_bytes:
                    label = describe(record) if describe else ""
                    raise DumpError(
                        "E4",
                        f"A {name} record {label} is {len(line)} bytes; at most "
                        f"{self.max_record_bytes} are allowed",
                    )
                if member is not None and (
                    count >= self.part_max_records
                    or member.bytes + len(line) > self.part_max_bytes
                ):
                    context.__exit__(None, None, None)
                    parts.append(_part(member.stats, count))
                    member = None
                if member is None:
                    context = self._bundle.member(part_path(name, len(parts) + 1))
                    member = context.__enter__()
                    count = 0
                member.write(line)
                count += 1
                total += 1
        except BaseException as exc:
            if member is not None:
                context.__exit__(type(exc), exc, exc.__traceback__)
            raise
        if member is not None:
            context.__exit__(None, None, None)
            parts.append(_part(member.stats, count))
        return {"schema": schemas.entity_schema_id(name), "records": total, "parts": parts}

    def write_config(self, name: str, data: bytes | None) -> dict[str, Any]:
        if data is None:
            return {"absent": True}
        stats = self._bundle.write_member(config_path(name), data)
        return {
            "absent": False,
            "path": config_path(name),
            "sha256": stats.sha256,
            "bytes": stats.bytes,
        }

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        self._bundle.write_member(MANIFEST_NAME, stable_json_bytes(manifest))

    def close(self) -> None:
        self._bundle.close()

    def abort(self) -> None:
        self._bundle.abort()


def _part(stats: Any, records: int) -> dict[str, Any]:
    return {"path": stats.name, "sha256": stats.sha256, "bytes": stats.bytes, "records": records}


@dataclass
class PartCheck:
    path: str
    digest: Any = field(default_factory=hashlib.sha256)
    bytes: int = 0
    records: int = 0


class DumpReader:
    """Opens a dump and checks the container and the manifest (C1-C5, C10,
    F1-F9); ``iter_records`` streams an entity with C6-C11 and S1."""

    def __init__(
        self,
        path: str,
        *,
        allow_unknown: bool = True,
        max_uncompressed: int | None = None,
    ) -> None:
        self.path = path
        self.warnings: list[Finding] = []
        try:
            self._zip = ZipBundleReader(
                path,
                max_members=MAX_MEMBERS,
                max_total_uncompressed=(
                    get_max_uncompressed_bytes()
                    if max_uncompressed is None
                    else max_uncompressed
                ),
                max_ratio=None,
                max_line_bytes=MAX_RECORD_BYTES,
            )
        except BundleError as exc:
            raise DumpError(exc.code, str(exc)) from exc
        try:
            if MANIFEST_NAME not in self._zip:
                raise DumpError("C3", "The dump has no manifest.json")
            try:
                raw = parse_manifest_bytes(self._zip.read_bytes(MANIFEST_NAME))
            except BundleError as exc:
                raise DumpError(exc.code, str(exc)) from exc
            self.checked: CheckedManifest = check_manifest(raw, allow_unknown=allow_unknown)
            self.warnings.extend(self.checked.warnings)
            listed = self.checked.listed_members()
            present = set(self._zip.names())
            extra = sorted(present - listed)
            if extra:
                raise DumpError("C2", f"Members not listed in the manifest: {', '.join(extra[:5])}")
            missing = sorted(listed - present)
            if missing:
                raise DumpError("C3", f"Listed members are missing: {', '.join(missing[:5])}")
        except BaseException:
            self._zip.close()
            raise

    @property
    def declared_bytes(self) -> int:
        """The declared uncompressed size of all members."""
        return self._zip.total_declared

    @property
    def manifest(self) -> dict[str, Any]:
        return self.checked.manifest

    def entity_parts(self, name: str) -> list[dict[str, Any]]:
        return list(self.manifest["entities"][name]["parts"])

    def iter_records(
        self,
        name: str,
        *,
        validate: bool = True,
        stripped: list[str] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """The records of an entity: parsed, upcast and validated. Part
        digests, sizes and counts are checked at the end of each part.
        Unknown fields of a newer minor version are dropped and their paths
        added to ``stripped``."""
        chain = self.checked.chains[name]
        for part in self.entity_parts(name):
            check = PartCheck(part["path"])
            try:
                for line in self._zip.iter_lines(part["path"]):
                    check.digest.update(line)
                    check.bytes += len(line)
                    check.records += 1
                    record = _parse_line(line, part["path"], check.records)
                    record = apply_chain(chain, record)
                    if validate:
                        record = self._validated(name, record, stripped)
                    yield record
            except BundleError as exc:
                raise DumpError(exc.code, str(exc)) from exc
            _finish_part(part, check)

    def _validated(
        self, name: str, record: dict[str, Any], stripped: list[str] | None
    ) -> dict[str, Any]:
        problems = schemas.errors(name, record)
        if not problems:
            return record
        if self.checked.newer_minor:
            result = schemas.strip_unknown_properties(name, record)
            if result is not None:
                if stripped is not None:
                    stripped.extend(result[1])
                return result[0]
        raise DumpError(
            "S1",
            f"A {name} record does not match its schema: "
            + "; ".join(schemas.describe(problem) for problem in problems[:3]),
        )

    def iter_unknown_entity_lines(self, name: str) -> Iterator[bytes]:
        for part in (self.checked.raw.get("entities") or {}).get(name, {}).get("parts") or []:
            check = PartCheck(part["path"])
            try:
                for line in self._zip.iter_lines(part["path"]):
                    check.digest.update(line)
                    check.bytes += len(line)
                    check.records += 1
                    _parse_line(line, part["path"], check.records)
                    yield line
            except BundleError as exc:
                raise DumpError(exc.code, str(exc)) from exc
            _finish_part(part, check)

    def read_config(self, name: str) -> bytes | None:
        spec = self.manifest["config"][name]
        if spec["absent"]:
            return None
        try:
            data = self._zip.read_bytes(spec["path"])
        except BundleError as exc:
            raise DumpError(exc.code, str(exc)) from exc
        if sha256_hex(data) != spec["sha256"]:
            raise DumpError("C6", f"{spec['path']} does not match its digest")
        if len(data) != spec["bytes"]:
            raise DumpError("C7", f"{spec['path']} does not match its size")
        return data

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> "DumpReader":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


def _parse_line(line: bytes, path: str, number: int) -> dict[str, Any]:
    try:
        record = json.loads(line, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DumpError("C11", f"Line {number} of {path} is not JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise DumpError("C11", f"Line {number} of {path} is not a JSON object")
    return record


def _reject_constant(value: str) -> Any:
    raise ValueError(f"{value} is not JSON")


def _finish_part(part: dict[str, Any], check: PartCheck) -> None:
    if check.digest.hexdigest() != part["sha256"]:
        raise DumpError("C6", f"{part['path']} does not match its digest")
    if check.bytes != part["bytes"]:
        raise DumpError("C7", f"{part['path']} is {check.bytes} bytes, not {part['bytes']}")
    if check.records != part["records"]:
        raise DumpError(
            "C8", f"{part['path']} holds {check.records} records, not {part['records']}"
        )
