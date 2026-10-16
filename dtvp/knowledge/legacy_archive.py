"""Bounded read-only inspection of exported v1 archives. No extraction or restoration."""

import io
import json
import math
import stat
import struct
import unicodedata
import zipfile
import zlib
from collections import Counter

from dtvp.legacy_dt import KNOWN_TAGS, STATES
from dtvp.parsers import PARSER_VERSION, parse
from dtvp.storage import canonical, digest

SCHEMA = "dtvp.project-archive/v1"
FORMAT = "dtvp.legacy-archive-preview/1"
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_DIRECTORY = 4 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_VERSIONS = 100
MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 64
ROLES = ("project", "bom", "findings", "vulnerabilities", "assessments")
LIMITATIONS = [
    "Dry run only: no archive, member or model is persisted; no SQL, journal, upstream source or Git state changes.",
    "Exact uploaded ZIP and exported-member hashes do not establish original pipeline byte fidelity, publisher identity or archive authenticity.",
    "V1 exports are point-in-time source captures, not complete backups or assessment event histories; comments may be stripped from exported assessments.",
    "Legacy tagged and metadata-free documentation remains source evidence; author, team, approval, suppression and contextual score claims grant no native permissions or approvals.",
    "Git-friendly trees may lack capture/author/build provenance; this reader does not infer Git commits, chronology or missing origins.",
    "The summary omits raw names, URLs, personal documentation and credentials. Original values remain only in the caller's input bytes.",
]


def invalid():
    raise ValueError("Invalid or unsupported bounded v1 project archive")


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 1024:
        invalid()
    if name.startswith(("/", "\\")) or "\\" in name or ":" in name:
        invalid()
    value = name[:-1] if name.endswith("/") else name
    if any(part in {"", ".", ".."} for part in value.split("/")):
        invalid()
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        invalid()
    return name


def _extra(raw):
    offset = 0
    while offset < len(raw):
        if offset + 4 > len(raw):
            invalid()
        field, length = struct.unpack_from("<HH", raw, offset)
        offset += 4
        if offset + length > len(raw) or field in {0x0001, 0x7075}:
            invalid()  # ZIP64 and alternate Unicode path interpretations are unsupported.
        offset += length


def directory(raw):
    """Admit the actual central directory before ZipFile allocates its member table."""
    if len(raw) > MAX_COMPRESSED or len(raw) < 22:
        invalid()
    end = len(raw)
    while True:
        end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557), end)
        if end < 0:
            invalid()
        if end + 22 <= len(raw):
            values = struct.unpack_from("<4s4H2LH", raw, end)
            if end + 22 + values[7] == len(raw):
                break
    if raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557)) != end:
        invalid()
    _, disk, start_disk, entries_disk, entries, size, start, _ = values
    if disk or start_disk or entries_disk != entries or not 1 <= entries <= MAX_ENTRIES:
        invalid()
    if entries == 0xFFFF or size > MAX_DIRECTORY or start + size != end:
        invalid()
    cursor, expanded, names, aliases, spans = start, 0, {}, set(), []
    for _ in range(entries):
        if cursor + 46 > end:
            invalid()
        item = struct.unpack_from("<4s6H3L5H2L", raw, cursor)
        if item[0] != b"PK\x01\x02":
            invalid()
        flags, compression = item[3], item[4]
        compressed, uncompressed = item[8], item[9]
        name_size, extra_size, comment_size = item[10:13]
        mode, local = item[15] >> 16, item[16]
        stop = cursor + 46 + name_size + extra_size + comment_size
        if stop > end or item[13] or flags & 0x41 or compression not in {0, 8}:
            invalid()
        if compressed == 0xFFFFFFFF or uncompressed > MAX_MEMBER or local >= start:
            invalid()
        encoded = raw[cursor + 46 : cursor + 46 + name_size]
        try:
            name = safe_name(encoded.decode("utf-8" if flags & 0x800 else "cp437"))
        except UnicodeError:
            invalid()
        alias = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
        if name in names or alias in aliases:
            invalid()
        aliases.add(alias)
        if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
            invalid()
        is_directory = name.endswith("/")
        if stat.S_ISDIR(mode) != is_directory and stat.S_IFMT(mode):
            invalid()
        if is_directory and (uncompressed or compressed):
            invalid()
        expanded += uncompressed
        if expanded > MAX_EXPANDED:
            invalid()
        _extra(raw[cursor + 46 + name_size : cursor + 46 + name_size + extra_size])
        if local + 30 > start:
            invalid()
        header = struct.unpack_from("<4s5H3L2H", raw, local)
        if header[0] != b"PK\x03\x04" or header[2] != flags or header[3] != compression:
            invalid()
        if not flags & 8 and (header[6], header[7], header[8]) != (
            item[7],
            compressed,
            uncompressed,
        ):
            invalid()
        data_start = local + 30 + header[9] + header[10]
        if data_start + compressed > start or raw[local + 30 : local + 30 + header[9]] != encoded:
            invalid()
        _extra(raw[local + 30 + header[9] : data_start])
        spans.append((local, data_start + compressed))
        names[name] = {"size": uncompressed, "directory": is_directory}
        cursor = stop
    if cursor != end or not spans or min(left for left, _ in spans) != 0:
        invalid()
    file_aliases = {
        unicodedata.normalize("NFC", name).casefold()
        for name, metadata in names.items()
        if not metadata["directory"]
    }
    for name in names:
        parts = name.rstrip("/").split("/")
        if any(
            unicodedata.normalize("NFC", "/".join(parts[:index])).casefold() in file_aliases
            for index in range(1, len(parts))
        ):
            invalid()
    ordered = sorted(spans)
    if any(previous[1] > following[0] for previous, following in zip(ordered, ordered[1:])):
        invalid()
    return names


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                invalid()
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: invalid()
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid bounded archive JSON") from error
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            invalid()
        if isinstance(item, float) and not math.isfinite(item):
            invalid()
        children = (
            item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        )
        if nodes + len(pending) + len(children) > MAX_JSON_NODES:
            invalid()
        if children and depth + 1 > MAX_JSON_DEPTH:
            invalid()
        pending.extend((child, depth + 1) for child in children)
    return value


def members(raw):
    admitted = directory(raw)
    result, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if [info.filename for info in archive.infolist()] != list(admitted):
                invalid()
            for name, metadata in admitted.items():
                if metadata["directory"]:
                    continue
                chunks, size = [], 0
                with archive.open(name) as stream:
                    while chunk := stream.read(64 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_MEMBER or total > MAX_EXPANDED:
                            invalid()
                        chunks.append(chunk)
                if size != metadata["size"]:
                    invalid()
                result[name] = b"".join(chunks)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as error:
        raise ValueError("Invalid bounded project archive container") from error
    return result, admitted


def _hash(value):
    return digest(canonical(value))


def tagged_documentation(text):
    # Scan each bracket-delimited segment once. A regex over unclosed tag bodies
    # can otherwise backtrack quadratically on large imported documentation.
    start = text.find("[")
    while start >= 0:
        following = text.find("[", start + 1)
        stop = following if following >= 0 else len(text)
        end = text.find("]", start + 1, stop)
        colon = text.find(":", start + 1, end) if end >= 0 else -1
        if (
            colon >= 0
            and colon - start <= 64
            and text[start + 1 : colon].strip().casefold() in KNOWN_TAGS
        ):
            return True
        start = following
    return False


def _version(entry, payloads, index):
    data = {role: strict_json(payloads[path]) for role, path in entry["paths"].items()}
    if any(not isinstance(data[role], dict) for role in ("project", "bom")) or any(
        not isinstance(data[role], list) for role in ("findings", "vulnerabilities", "assessments")
    ):
        invalid()
    if any(
        not isinstance(item, dict)
        for role in ("findings", "vulnerabilities", "assessments")
        for item in data[role]
    ):
        invalid()
    source = entry["project"]
    if any(source.get(key) != data["project"].get(key) for key in ("name", "version", "uuid")):
        invalid()
    losses, counts = [], {}
    for key, code in (
        ("uuid", "source_project_identity_unknown"),
        ("version", "source_version_label_unknown"),
    ):
        if not isinstance(source.get(key), str) or not source[key].strip():
            losses.append(code)
    for role in ("findings", "vulnerabilities", "assessments"):
        counts[role] = len(data[role])
    counts["bom_components"] = (
        len(data["bom"].get("components", []))
        if isinstance(data["bom"].get("components", []), list)
        else None
    )
    if not isinstance(entry.get("counts"), dict) or any(
        isinstance(entry["counts"].get(key), bool)
        or not isinstance(entry["counts"].get(key), int)
        or entry["counts"].get(key) != count
        for key, count in counts.items()
    ):
        invalid()
    try:
        parsed = parse(payloads[entry["paths"]["bom"]])
        normalized = {
            "status": "supported",
            "format": parsed["format"],
            "parser": PARSER_VERSION,
            "components": len(parsed["components"]),
            "findings": len(parsed["findings"]),
        }
    except ValueError, TypeError, KeyError, AttributeError, RecursionError:
        normalized = {"status": "unsupported", "parser": PARSER_VERSION}
        losses.append("native_sbom_normalization_unsupported_no_upgrade_inferred")
    component_refs = {}
    metadata = data["bom"].get("metadata", {})
    pending = [metadata.get("component", {}) if isinstance(metadata, dict) else {}]
    values = data["bom"].get("components", [])
    if isinstance(values, list):
        pending.extend(values)
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        identifier, reference = component.get("uuid"), component.get("bom-ref")
        if isinstance(identifier, str) and identifier:
            component_refs.setdefault(identifier, []).append(reference)
        children = component.get("components", [])
        if isinstance(children, list):
            pending.extend(children)
    mapping = {}
    for role in ("findings", "assessments"):
        mapped = unresolved = ambiguous = 0
        for record in data[role]:
            component = record.get("component", {})
            identifier = component.get("uuid") if isinstance(component, dict) else None
            references = component_refs.get(identifier, []) if isinstance(identifier, str) else []
            if len(references) > 1:
                ambiguous += 1
            elif len(references) == 1 and isinstance(references[0], str) and references[0]:
                mapped += 1
            else:
                unresolved += 1
        mapping[role] = {
            "exact_source_uuid_refs": mapped,
            "unresolved": unresolved,
            "ambiguous": ambiguous,
        }
        if unresolved or ambiguous:
            losses.append("legacy_component_mapping_unresolved_no_name_or_purl_guess")
    documentation = Counter()
    imported_states = Counter()
    for record in data["assessments"]:
        analysis = record.get("analysis", {})
        if not isinstance(analysis, dict):
            invalid()
        text = analysis.get(
            "analysisDetails", analysis.get("analysis_details", analysis.get("details", ""))
        )
        if text is None:
            text = ""
        if not isinstance(text, str):
            documentation["unparsed"] += 1
            losses.append("legacy_documentation_nontext_unparsed")
        else:
            tagged = tagged_documentation(text)
            documentation["tagged" if tagged else "plain" if text.strip() else "missing"] += 1
        state = analysis.get("analysisState", analysis.get("analysis_state", analysis.get("state")))
        imported_states[STATES.get(state, "unknown") if isinstance(state, str) else "unknown"] += 1
        if record.get("analysis_fetch_error"):
            losses.append("legacy_analysis_fetch_failed")
    losses.extend(
        [
            "complete_assessment_event_history_not_exported",
            "assessment_comments_may_have_been_stripped",
            "source_authorship_team_and_approval_unverified",
        ]
    )
    pins = {
        role: {"sha256": digest(payloads[path]), "bytes": len(payloads[path])}
        for role, path in entry["paths"].items()
    }
    return {
        "source_entry_id": _hash([index, source, entry["paths"]]),
        "entry_index": index,
        "source_project_uuid_digest": _hash(source.get("uuid")),
        "source_version_digest": _hash(source.get("version")),
        "counts": counts,
        "member_pins": pins,
        "normalization": normalized,
        "component_reference_coverage": mapping,
        "documentation": dict(documentation),
        "source_states": dict(imported_states),
        "losses": sorted(set(losses)),
    }


def preview_archive(raw, *, offset=0, limit=25):
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Invalid archive preview page bounds")
    payloads, admitted = members(raw)
    if "manifest.json" not in payloads:
        invalid()
    manifest = strict_json(payloads["manifest.json"])
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA:
        invalid()
    files, project = manifest.get("files"), manifest.get("project")
    if not isinstance(files, dict) or not isinstance(project, dict):
        invalid()
    versions = project.get("versions")
    if not isinstance(versions, list) or not 1 <= len(versions) <= MAX_VERSIONS:
        invalid()
    if set(payloads) != {"manifest.json", *files}:
        invalid()
    for path, metadata in files.items():
        safe_name(path)
        if not isinstance(metadata, dict) or set(metadata) != {"sha256", "size"}:
            invalid()
        if (
            isinstance(metadata["size"], bool)
            or not isinstance(metadata["size"], int)
            or metadata["size"] != len(payloads[path])
            or metadata["sha256"] != digest(payloads[path])
        ):
            invalid()
    used, rows = set(), []
    for index, entry in enumerate(versions, 1):
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("project"), dict)
            or not isinstance(entry.get("paths"), dict)
            or set(entry["paths"]) != set(ROLES)
        ):
            invalid()
        for path in entry["paths"].values():
            if not isinstance(path, str) or path not in files or path in used:
                invalid()
            used.add(path)
        rows.append(_version(entry, payloads, index))
    if used != set(files):
        invalid()
    for name, metadata in admitted.items():
        if metadata["directory"] and not any(path.startswith(name) for path in used):
            invalid()
    missing = [key for key in ("created_at", "created_by", "reason", "dtvp") if key not in manifest]
    duplicate_ids = len(versions) - len({_hash(entry["project"].get("uuid")) for entry in versions})
    duplicate_labels = len(versions) - len(
        {_hash(entry["project"].get("version")) for entry in versions}
    )
    report = {
        "format": FORMAT,
        "schema": SCHEMA,
        "archive_sha256": digest(raw),
        "archive_bytes": len(raw),
        "manifest_sha256": digest(payloads["manifest.json"]),
        "expanded_bytes": sum(map(len, payloads.values())),
        "representation": "diffable_tree_export"
        if len(missing) == 4
        else "snapshot_export"
        if not missing
        else "partial_provenance_export",
        "missing_provenance_fields": missing,
        "statistics": {
            "versions": len(rows),
            "members": len(payloads),
            "duplicate_source_uuids": duplicate_ids,
            "duplicate_source_version_labels": duplicate_labels,
            "by_normalization": dict(Counter(row["normalization"]["status"] for row in rows)),
            "source_records": {
                role: sum(row["counts"][role] for row in rows)
                for role in ("findings", "vulnerabilities", "assessments")
            },
        },
        "dry_run": True,
        "writes": False,
        "history_complete": False,
        "creates_native_approvals": False,
        "limitations": list(LIMITATIONS),
    }
    return {
        **report,
        "preview_digest": digest(canonical([report, rows])),
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }
