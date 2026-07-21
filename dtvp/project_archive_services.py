import asyncio
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from .dt_client import DTClient


ARCHIVE_SCHEMA_VERSION = "dtvp.project-archive/v1"
ARCHIVE_FILE_SUFFIX = ".dtvp-project-archive.zip"
DEFAULT_ARCHIVE_MAX_FILES = 10_000
DEFAULT_ARCHIVE_MAX_MEMBER_BYTES = 100 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
DEFAULT_ARCHIVE_MAX_COMPRESSION_RATIO = 200
_ALLOWED_ZIP_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


class ProjectArchiveError(Exception):
    pass


class ProjectArchiveVersionError(ProjectArchiveError):
    pass


class ProjectArchiveChecksumError(ProjectArchiveError):
    pass


class ProjectArchiveValidationError(ProjectArchiveError):
    pass


@dataclass(frozen=True)
class ProjectArchiveServiceDeps:
    cache_manager: Any
    logger: Any
    sort_projects_by_version: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    version: str
    build_commit: str
    archive_path_provider: Callable[[], str]
    now_provider: Callable[[], datetime] = lambda: datetime.now(UTC)
    sleep: Callable[[float], Any] = asyncio.sleep


def get_project_archive_path() -> str:
    return os.getenv("DTVP_PROJECT_ARCHIVE_PATH", "data/project_archives")


def project_archive_expanded_exports_enabled() -> bool:
    return os.getenv("DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_project_archive_expanded_path() -> str:
    return os.getenv("DTVP_PROJECT_ARCHIVE_EXPANDED_PATH", "data/project_archives_git")


def project_archive_snapshots_enabled() -> bool:
    return os.getenv("DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_project_archive_interval_seconds() -> int:
    value = os.getenv("DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS", "86400")
    try:
        return max(60, int(value))
    except ValueError:
        return 86400


def get_project_archive_retention_count() -> int:
    value = os.getenv("DTVP_PROJECT_ARCHIVE_RETENTION_COUNT", "30")
    try:
        return max(1, int(value))
    except ValueError:
        return 30


def get_project_archive_include_names() -> list[str]:
    raw = os.getenv("DTVP_PROJECT_ARCHIVE_INCLUDE", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _archive_limit(setting: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(setting, str(default))))
    except (TypeError, ValueError):
        return default


def _utc_now_iso(now_provider: Callable[[], datetime]) -> str:
    now = now_provider()
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now.astimezone(UTC).isoformat()


def _safe_filename(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return normalized.strip("._") or "project"


def _safe_project_tree_name(project_name: str) -> str:
    digest = hashlib.sha256(project_name.encode("utf-8")).hexdigest()[:12]
    return f"{_safe_filename(project_name)}-{digest}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(data: Any) -> bytes:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    ) + b"\n"


def _write_zip_file(path: str, files: dict[str, bytes]) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=directory or ".",
        prefix=".tmp-project-archive-",
        suffix=".zip",
    )
    os.close(fd)
    try:
        with zipfile.ZipFile(
            tmp_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _diffable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    stable_manifest = json.loads(json.dumps(manifest))
    stable_manifest.pop("created_at", None)
    stable_manifest.pop("created_by", None)
    stable_manifest.pop("reason", None)
    stable_manifest.pop("dtvp", None)
    return stable_manifest


def _write_expanded_archive_tree(
    base_dir: str,
    project_name: str,
    files: dict[str, bytes],
    manifest: dict[str, Any],
) -> str:
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    target_dir = base / _safe_project_tree_name(project_name)
    tmp_dir = Path(
        tempfile.mkdtemp(
            dir=base,
            prefix=f".tmp-{target_dir.name}-",
        )
    )

    try:
        stable_files = dict(files)
        stable_files["manifest.json"] = _json_bytes(_diffable_manifest(manifest))
        for name, data in stable_files.items():
            _assert_safe_zip_name(name)
            target_path = (tmp_dir / Path(*name.split("/"))).resolve()
            tmp_root = tmp_dir.resolve()
            if os.path.commonpath([str(tmp_root), str(target_path)]) != str(tmp_root):
                raise ProjectArchiveValidationError(f"Unsafe archive path: {name!r}")
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)

        if target_dir.exists():
            shutil.rmtree(target_dir)
        os.replace(tmp_dir, target_dir)
        return str(target_dir)
    finally:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _assert_safe_zip_name(name: str) -> None:
    if len(name) > 500:
        raise ProjectArchiveValidationError("Archive member path is too long")
    if not name or name.startswith("/") or name.startswith("\\"):
        raise ProjectArchiveValidationError(f"Unsafe archive path: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized != name or normalized == ".":
        raise ProjectArchiveValidationError(f"Unsafe archive path: {name!r}")
    if any(part in {"", ".", ".."} for part in name.split("/")):
        raise ProjectArchiveValidationError(f"Unsafe archive path: {name!r}")


def _validate_zip_limits(zip_file: zipfile.ZipFile) -> None:
    members = zip_file.infolist()
    max_files = _archive_limit(
        "DTVP_PROJECT_ARCHIVE_MAX_FILES",
        DEFAULT_ARCHIVE_MAX_FILES,
    )
    if len(members) > max_files:
        raise ProjectArchiveValidationError(
            f"Archive contains more than {max_files} members"
        )

    names: set[str] = set()
    total_size = 0
    max_member_size = _archive_limit(
        "DTVP_PROJECT_ARCHIVE_MAX_MEMBER_BYTES",
        DEFAULT_ARCHIVE_MAX_MEMBER_BYTES,
    )
    max_total_size = _archive_limit(
        "DTVP_PROJECT_ARCHIVE_MAX_UNCOMPRESSED_BYTES",
        DEFAULT_ARCHIVE_MAX_UNCOMPRESSED_BYTES,
    )
    max_ratio = _archive_limit(
        "DTVP_PROJECT_ARCHIVE_MAX_COMPRESSION_RATIO",
        DEFAULT_ARCHIVE_MAX_COMPRESSION_RATIO,
    )

    for member in members:
        _assert_safe_zip_name(member.filename.rstrip("/"))
        if member.filename in names:
            raise ProjectArchiveValidationError(
                f"Archive contains duplicate member: {member.filename}"
            )
        names.add(member.filename)
        if member.flag_bits & 0x1:
            raise ProjectArchiveValidationError("Encrypted archives are not supported")
        if member.compress_type not in _ALLOWED_ZIP_COMPRESSION:
            raise ProjectArchiveValidationError(
                f"Unsupported ZIP compression for {member.filename}"
            )
        if member.file_size > max_member_size:
            raise ProjectArchiveValidationError(
                f"Archive member exceeds {max_member_size} bytes: {member.filename}"
            )
        total_size += member.file_size
        if total_size > max_total_size:
            raise ProjectArchiveValidationError(
                f"Archive expands beyond {max_total_size} bytes"
            )
        if member.file_size > 1024 * 1024:
            ratio = member.file_size / max(1, member.compress_size)
            if ratio > max_ratio:
                raise ProjectArchiveValidationError(
                    f"Archive member compression ratio is unsafe: {member.filename}"
                )


def _read_json_member(
    zip_file: zipfile.ZipFile,
    path: str,
) -> Any:
    _assert_safe_zip_name(path)
    try:
        return json.loads(zip_file.read(path))
    except KeyError as exc:
        raise ProjectArchiveValidationError(f"Missing archive file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProjectArchiveValidationError(f"Invalid JSON file: {path}") from exc


def _analysis_state(analysis: dict[str, Any] | None) -> str:
    if not analysis:
        return "NOT_SET"
    return str(
        analysis.get("analysisState")
        or analysis.get("analysis_state")
        or analysis.get("state")
        or "NOT_SET"
    )


def _analysis_details(analysis: dict[str, Any] | None) -> str:
    if not analysis:
        return ""
    return str(
        analysis.get("analysisDetails")
        or analysis.get("analysis_details")
        or analysis.get("details")
        or ""
    )


def _analysis_suppressed(analysis: dict[str, Any] | None) -> bool:
    if not analysis:
        return False
    if "isSuppressed" in analysis:
        return bool(analysis.get("isSuppressed"))
    return bool(analysis.get("is_suppressed") or analysis.get("suppressed") or False)


def _analysis_justification(analysis: dict[str, Any] | None) -> str | None:
    if not analysis:
        return None
    value = (
        analysis.get("analysisJustification")
        or analysis.get("analysis_justification")
        or analysis.get("justification")
    )
    return str(value) if value else None


def _is_empty_analysis(analysis: dict[str, Any] | None) -> bool:
    return (
        _analysis_state(analysis).upper() == "NOT_SET"
        and not _analysis_details(analysis)
        and not _analysis_suppressed(analysis)
        and not _analysis_justification(analysis)
    )


def _archive_analysis_payload(analysis: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(analysis, dict):
        return {}
    sanitized = dict(analysis)
    for key in ("analysisComments", "analysis_comments", "comments"):
        sanitized.pop(key, None)
    return sanitized


def _normalize_purl_without_qualifiers(value: str) -> str:
    return value.strip().lower()


def _component_keys(component: dict[str, Any] | None) -> set[str]:
    if not component:
        return set()
    keys: set[str] = set()

    purl = component.get("purl")
    if isinstance(purl, str) and purl.strip():
        keys.add(f"purl:{_normalize_purl_without_qualifiers(purl)}")

    name = component.get("name")
    version = component.get("version")
    if isinstance(name, str) and name.strip():
        normalized_name = name.strip().lower()
        keys.add(f"name:{normalized_name}")
        if isinstance(version, str) and version.strip():
            keys.add(f"namever:{normalized_name}\0{version.strip().lower()}")

    for key in ("bom-ref", "bom_ref"):
        bom_ref = component.get(key)
        if isinstance(bom_ref, str) and bom_ref.strip():
            keys.add(f"bomref:{bom_ref.strip().lower()}")

    return keys


def _vulnerability_keys(vulnerability: dict[str, Any] | None) -> set[str]:
    if not vulnerability:
        return set()
    keys: set[str] = set()
    for key in ("vulnId", "vuln_id", "name"):
        value = vulnerability.get(key)
        if isinstance(value, str) and value.strip():
            keys.add(f"vuln:{value.strip().upper()}")

    aliases = vulnerability.get("aliases") or []
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, dict):
                values = alias.values()
            else:
                values = [alias]
            for value in values:
                if isinstance(value, str) and value.strip():
                    keys.add(f"vuln:{value.strip().upper()}")
    return keys


def _bom_components_by_uuid(bom: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not bom:
        return result
    for component in bom.get("components") or []:
        if not isinstance(component, dict):
            continue
        uuid = component.get("uuid")
        if isinstance(uuid, str) and uuid:
            result[uuid] = component
    metadata_component = (bom.get("metadata") or {}).get("component") or {}
    if isinstance(metadata_component, dict):
        uuid = metadata_component.get("uuid")
        if isinstance(uuid, str) and uuid:
            result[uuid] = metadata_component
    return result


def _merge_component_with_bom(
    component: dict[str, Any],
    bom_components_by_uuid: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    uuid = component.get("uuid")
    if isinstance(uuid, str) and uuid in bom_components_by_uuid:
        merged = dict(bom_components_by_uuid[uuid])
        merged.update(component)
        if "bom-ref" in bom_components_by_uuid[uuid]:
            merged["bom-ref"] = bom_components_by_uuid[uuid].get("bom-ref")
        return merged
    return component


async def _collect_assessments(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
    project: dict[str, Any],
    findings: list[dict[str, Any]],
    bom: dict[str, Any] | None,
    *,
    refresh: bool,
) -> list[dict[str, Any]]:
    bom_by_uuid = _bom_components_by_uuid(bom)
    analysis_tasks: list[Any] = []
    task_findings: list[dict[str, Any]] = []
    for finding in findings:
        component = finding.get("component") or {}
        vulnerability = finding.get("vulnerability") or {}
        component_uuid = component.get("uuid")
        vulnerability_uuid = vulnerability.get("uuid")
        if not component_uuid or not vulnerability_uuid:
            continue
        analysis_tasks.append(
            deps.cache_manager.get_analysis(
                client,
                project_uuid=project["uuid"],
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
                refresh=refresh,
            )
        )
        task_findings.append(finding)

    analyses: list[Any] = []
    batch_size = 50
    for index in range(0, len(analysis_tasks), batch_size):
        analyses.extend(
            await asyncio.gather(
                *analysis_tasks[index : index + batch_size],
                return_exceptions=True,
            )
        )

    records: list[dict[str, Any]] = []
    for finding, analysis_result in zip(task_findings, analyses):
        component = _merge_component_with_bom(finding.get("component") or {}, bom_by_uuid)
        vulnerability = finding.get("vulnerability") or {}
        analysis = (
            analysis_result
            if isinstance(analysis_result, dict)
            else finding.get("analysis") or {}
        )
        archived_analysis = _archive_analysis_payload(analysis)
        records.append(
            {
                "project_uuid": project.get("uuid"),
                "project_name": project.get("name"),
                "project_version": project.get("version"),
                "finding_uuid": finding.get("uuid") or finding.get("matrix"),
                "component": component,
                "vulnerability": vulnerability,
                "analysis": archived_analysis,
                "analysis_fetch_error": (
                    str(analysis_result)
                    if isinstance(analysis_result, BaseException)
                    else None
                ),
            }
        )
    return records


async def export_project_archive(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
    *,
    project_name: str,
    versions: list[str] | None = None,
    refresh: bool = True,
    created_by: str | None = None,
    reason: Literal["manual", "snapshot"] = "manual",
) -> dict[str, Any]:
    normalized_name = project_name.strip()
    if not normalized_name:
        raise ProjectArchiveValidationError("project_name is required")

    projects = await deps.cache_manager.get_projects(client, normalized_name)
    selected = [project for project in projects if project.get("name") == normalized_name]
    if versions:
        requested = set(versions)
        selected = [project for project in selected if project.get("version") in requested]
    if not selected:
        raise ProjectArchiveValidationError(
            f"No Dependency-Track project versions found for {normalized_name!r}"
        )

    selected = deps.sort_projects_by_version(selected)
    created_at = _utc_now_iso(deps.now_provider)
    files: dict[str, bytes] = {}
    version_entries: list[dict[str, Any]] = []

    for index, project in enumerate(selected, start=1):
        project_uuid = project.get("uuid")
        version_label = str(project.get("version") or "")
        version_dir = (
            f"versions/{index:04d}-"
            f"{_safe_filename(version_label or project_uuid or str(index))}"
        )

        findings = await deps.cache_manager.get_vulnerabilities(
            client,
            project_uuid,
            refresh=refresh,
        )
        vulnerabilities = await deps.cache_manager.get_project_vulnerabilities(
            client,
            project_uuid,
            refresh=refresh,
        )
        bom = await deps.cache_manager.get_bom(
            client,
            project_uuid,
            refresh=refresh,
        )
        assessments = await _collect_assessments(
            deps,
            client,
            project,
            findings,
            bom,
            refresh=refresh,
        )

        project_path = f"{version_dir}/project.json"
        bom_path = f"{version_dir}/bom.json"
        findings_path = f"{version_dir}/findings.json"
        vulnerabilities_path = f"{version_dir}/vulnerabilities.json"
        assessments_path = f"{version_dir}/assessments.json"

        files[project_path] = _json_bytes(project)
        files[bom_path] = _json_bytes(bom or {})
        files[findings_path] = _json_bytes(findings)
        files[vulnerabilities_path] = _json_bytes(vulnerabilities)
        files[assessments_path] = _json_bytes(assessments)

        version_entries.append(
            {
                "project": {
                    "name": project.get("name"),
                    "version": project.get("version"),
                    "uuid": project_uuid,
                    "classifier": project.get("classifier"),
                    "active": project.get("active"),
                },
                "paths": {
                    "project": project_path,
                    "bom": bom_path,
                    "findings": findings_path,
                    "vulnerabilities": vulnerabilities_path,
                    "assessments": assessments_path,
                },
                "counts": {
                    "findings": len(findings),
                    "vulnerabilities": len(vulnerabilities),
                    "assessments": len(assessments),
                    "bom_components": len((bom or {}).get("components") or []),
                },
            }
        )

    checksums = {
        name: {"sha256": _sha256(data), "size": len(data)}
        for name, data in sorted(files.items())
    }
    manifest = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "created_at": created_at,
        "created_by": created_by,
        "reason": reason,
        "dtvp": {
            "version": deps.version,
            "build_commit": deps.build_commit,
        },
        "source": {
            "dependency_track_url": client.base_url,
            "project_name": normalized_name,
        },
        "project": {
            "name": normalized_name,
            "versions": version_entries,
        },
        "files": checksums,
    }
    files["manifest.json"] = _json_bytes(manifest)

    timestamp = created_at.replace("+00:00", "Z").replace(":", "").replace(".", "")
    filename = f"{_safe_filename(normalized_name)}-{timestamp}{ARCHIVE_FILE_SUFFIX}"
    archive_path = os.path.join(deps.archive_path_provider(), filename)
    await asyncio.to_thread(_write_zip_file, archive_path, files)
    expanded_path = None
    if project_archive_expanded_exports_enabled():
        expanded_path = await asyncio.to_thread(
            _write_expanded_archive_tree,
            get_project_archive_expanded_path(),
            normalized_name,
            files,
            manifest,
        )

    return {
        "filename": filename,
        "archive_path": archive_path,
        "expanded_path": expanded_path,
        "created_at": created_at,
        "project_name": normalized_name,
        "version_count": len(version_entries),
        "versions": [
            entry["project"].get("version") for entry in version_entries
        ],
        "size": os.path.getsize(archive_path),
        "manifest": manifest,
    }


def load_project_archive(path: str) -> dict[str, Any]:
    try:
        zip_file_context = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ProjectArchiveValidationError("Uploaded file is not a valid ZIP archive") from exc

    with zip_file_context as zip_file:
        _validate_zip_limits(zip_file)

        manifest = _read_json_member(zip_file, "manifest.json")
        schema_version = manifest.get("schema_version")
        if schema_version != ARCHIVE_SCHEMA_VERSION:
            if isinstance(schema_version, str) and schema_version.startswith(
                "dtvp.project-archive/v"
            ):
                raise ProjectArchiveVersionError(
                    f"Unsupported project archive schema: {schema_version}"
                )
            raise ProjectArchiveValidationError("Not a DTVP project archive")

        for file_path, metadata in (manifest.get("files") or {}).items():
            _assert_safe_zip_name(file_path)
            try:
                data = zip_file.read(file_path)
            except KeyError as exc:
                raise ProjectArchiveChecksumError(
                    f"Missing checksummed archive file: {file_path}"
                ) from exc
            expected = (metadata or {}).get("sha256")
            actual = _sha256(data)
            if expected != actual:
                raise ProjectArchiveChecksumError(
                    f"Checksum mismatch for {file_path}: expected {expected}, got {actual}"
                )

        versions: list[dict[str, Any]] = []
        for entry in (manifest.get("project") or {}).get("versions") or []:
            paths = entry.get("paths") or {}
            versions.append(
                {
                    "entry": entry,
                    "project": _read_json_member(zip_file, paths.get("project", "")),
                    "bom": _read_json_member(zip_file, paths.get("bom", "")),
                    "findings": _read_json_member(zip_file, paths.get("findings", "")),
                    "vulnerabilities": _read_json_member(
                        zip_file,
                        paths.get("vulnerabilities", ""),
                    ),
                    "assessments": _read_json_member(
                        zip_file,
                        paths.get("assessments", ""),
                    ),
                }
            )

    return {"manifest": manifest, "versions": versions}


async def preview_project_archive(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
    *,
    archive_path: str,
) -> dict[str, Any]:
    archive = await asyncio.to_thread(load_project_archive, archive_path)
    manifest = archive["manifest"]
    project_name = (manifest.get("project") or {}).get("name") or (
        manifest.get("source") or {}
    ).get("project_name")

    version_previews: list[dict[str, Any]] = []
    warnings: list[str] = []
    for version in archive["versions"]:
        source_project = version["project"]
        version_label = source_project.get("version") or ""
        existing = await client.find_project_by_name_version(project_name, version_label)
        assessment_count = len(version.get("assessments") or [])
        empty_assessment_count = sum(
            1
            for assessment in version.get("assessments") or []
            if _is_empty_analysis(assessment.get("analysis") or {})
        )
        version_previews.append(
            {
                "project_name": project_name,
                "version": version_label,
                "source_uuid": source_project.get("uuid"),
                "target_uuid": existing.get("uuid") if existing else None,
                "target_exists": bool(existing),
                "finding_count": len(version.get("findings") or []),
                "vulnerability_count": len(version.get("vulnerabilities") or []),
                "assessment_count": assessment_count,
                "restorable_assessment_count": assessment_count - empty_assessment_count,
                "bom_component_count": len((version.get("bom") or {}).get("components") or []),
            }
        )

    if any(item["target_exists"] for item in version_previews):
        warnings.append("Existing project versions require update mode to be touched.")

    return {
        "schema_version": manifest.get("schema_version"),
        "created_at": manifest.get("created_at"),
        "project_name": project_name,
        "versions": version_previews,
        "total_versions": len(version_previews),
        "total_assessments": sum(item["assessment_count"] for item in version_previews),
        "total_restorable_assessments": sum(
            item["restorable_assessment_count"] for item in version_previews
        ),
        "warnings": warnings,
    }


def _target_finding_entries(
    findings: list[dict[str, Any]],
    bom: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    bom_by_uuid = _bom_components_by_uuid(bom)
    entries: list[dict[str, Any]] = []
    for finding in findings:
        component = _merge_component_with_bom(finding.get("component") or {}, bom_by_uuid)
        vulnerability = finding.get("vulnerability") or {}
        entries.append(
            {
                "finding": finding,
                "component": component,
                "vulnerability": vulnerability,
                "component_keys": _component_keys(component),
                "vulnerability_keys": _vulnerability_keys(vulnerability),
            }
        )
    return entries


def _find_target_finding(
    target_entries: list[dict[str, Any]],
    assessment: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    component_keys = _component_keys(assessment.get("component") or {})
    vulnerability_keys = _vulnerability_keys(assessment.get("vulnerability") or {})
    if not component_keys or not vulnerability_keys:
        return "unmatched", None

    matches = [
        entry
        for entry in target_entries
        if component_keys.intersection(entry["component_keys"])
        and vulnerability_keys.intersection(entry["vulnerability_keys"])
    ]
    if len(matches) == 1:
        return "matched", matches[0]
    if len(matches) > 1:
        return "ambiguous", None
    return "unmatched", None


async def _restore_version_assessments(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
    *,
    project_uuid: str,
    target_findings: list[dict[str, Any]],
    target_bom: dict[str, Any] | None,
    assessments: list[dict[str, Any]],
) -> dict[str, Any]:
    target_entries = _target_finding_entries(target_findings, target_bom)
    restored = 0
    skipped_empty = 0
    unmatched = 0
    ambiguous = 0
    queued = 0
    failed: list[dict[str, Any]] = []

    for assessment in assessments:
        analysis = assessment.get("analysis") or {}
        if _is_empty_analysis(analysis):
            skipped_empty += 1
            continue

        match_status, target = _find_target_finding(target_entries, assessment)
        if match_status == "ambiguous":
            ambiguous += 1
            continue
        if not target:
            unmatched += 1
            continue

        component_uuid = (target.get("component") or {}).get("uuid")
        vulnerability_uuid = (target.get("vulnerability") or {}).get("uuid")
        if not component_uuid or not vulnerability_uuid:
            unmatched += 1
            continue

        payload = {
            "project_uuid": project_uuid,
            "component_uuid": component_uuid,
            "vulnerability_uuid": vulnerability_uuid,
            "state": _analysis_state(analysis),
            "details": _analysis_details(analysis),
            "justification": _analysis_justification(analysis),
            "suppressed": _analysis_suppressed(analysis),
        }

        try:
            await client.update_analysis(**payload)
            deps.cache_manager._save_local_analysis(payload)
            restored += 1
        except Exception as exc:
            try:
                await deps.cache_manager.queue_analysis_update(payload, replace=True)
                queued += 1
            except Exception:
                failed.append(
                    {
                        "component": (assessment.get("component") or {}).get("name"),
                        "vulnerability": (
                            assessment.get("vulnerability") or {}
                        ).get("vulnId"),
                        "error": str(exc),
                    }
                )

    return {
        "restored": restored,
        "queued": queued,
        "skipped_empty": skipped_empty,
        "unmatched": unmatched,
        "ambiguous": ambiguous,
        "failed": failed,
    }


async def apply_project_archive(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
    *,
    archive_path: str,
    mode: Literal["create_missing", "update"],
) -> dict[str, Any]:
    if mode not in {"create_missing", "update"}:
        raise ProjectArchiveValidationError("mode must be create_missing or update")

    archive = await asyncio.to_thread(load_project_archive, archive_path)
    manifest = archive["manifest"]
    project_name = (manifest.get("project") or {}).get("name") or (
        manifest.get("source") or {}
    ).get("project_name")

    version_results: list[dict[str, Any]] = []
    for version in archive["versions"]:
        source_project = version["project"]
        version_label = source_project.get("version") or ""
        existing = await client.find_project_by_name_version(project_name, version_label)

        if existing and mode != "update":
            version_results.append(
                {
                    "version": version_label,
                    "status": "skipped_existing",
                    "target_uuid": existing.get("uuid"),
                    "assessment_result": None,
                }
            )
            continue

        target_uuid = existing.get("uuid") if existing else None
        await client.upload_bom(
            version.get("bom") or {},
            project_uuid=target_uuid,
            project_name=project_name,
            project_version=version_label,
            auto_create=True,
        )
        target_project = await client.wait_for_project_version(
            project_name,
            version_label,
        )
        if not target_project:
            raise ProjectArchiveValidationError(
                f"Dependency-Track did not expose restored version {project_name} {version_label}"
            )

        target_uuid = target_project["uuid"]
        expected_findings = len(version.get("findings") or [])
        target_findings = await client.wait_for_project_findings(
            target_uuid,
            expected_min_findings=1 if expected_findings else 0,
        )
        try:
            target_bom = await client.get_bom(target_uuid)
        except Exception:
            target_bom = {}

        assessment_result = await _restore_version_assessments(
            deps,
            client,
            project_uuid=target_uuid,
            target_findings=target_findings,
            target_bom=target_bom,
            assessments=version.get("assessments") or [],
        )
        try:
            await deps.cache_manager.refresh_project(target_uuid, client)
        except Exception as exc:
            deps.logger.debug("Failed to refresh restored archive project: %s", exc)

        version_results.append(
            {
                "version": version_label,
                "status": "updated" if existing else "created",
                "target_uuid": target_uuid,
                "assessment_result": assessment_result,
            }
        )

    return {
        "project_name": project_name,
        "mode": mode,
        "versions": version_results,
        "summary": {
            "created": sum(1 for item in version_results if item["status"] == "created"),
            "updated": sum(1 for item in version_results if item["status"] == "updated"),
            "skipped_existing": sum(
                1 for item in version_results if item["status"] == "skipped_existing"
            ),
            "restored_assessments": sum(
                (item.get("assessment_result") or {}).get("restored", 0)
                for item in version_results
            ),
            "queued_assessments": sum(
                (item.get("assessment_result") or {}).get("queued", 0)
                for item in version_results
            ),
            "unmatched_assessments": sum(
                (item.get("assessment_result") or {}).get("unmatched", 0)
                for item in version_results
            ),
            "ambiguous_assessments": sum(
                (item.get("assessment_result") or {}).get("ambiguous", 0)
                for item in version_results
            ),
        },
    }


def store_uploaded_archive(
    archive_dir: str,
    task_id: str,
    filename: str,
    content: bytes,
) -> str:
    if not content:
        raise ProjectArchiveValidationError("Uploaded archive is empty")
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
            _validate_zip_limits(archive)
    except zipfile.BadZipFile as exc:
        raise ProjectArchiveValidationError(
            "Uploaded file is not a valid ZIP archive"
        ) from exc
    uploads_dir = os.path.join(archive_dir, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    safe_name = _safe_filename(Path(filename or "upload.zip").stem)
    target = os.path.join(uploads_dir, f"{task_id}-{safe_name}.zip")
    fd, tmp_path = tempfile.mkstemp(dir=uploads_dir, prefix=".tmp-upload-", suffix=".zip")
    try:
        with os.fdopen(fd, "wb") as file_handle:
            file_handle.write(content)
        os.replace(tmp_path, target)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    return target


def list_project_archives(archive_dir: str) -> list[dict[str, Any]]:
    base = Path(archive_dir)
    if not base.exists():
        return []
    archives: list[dict[str, Any]] = []
    for path in base.glob(f"*{ARCHIVE_FILE_SUFFIX}"):
        if not path.is_file():
            continue
        stat = path.stat()
        item = {
            "filename": path.name,
            "size": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
            "project_name": None,
            "created_at": None,
            "version_count": None,
        }
        try:
            archive = load_project_archive(str(path))
            manifest = archive["manifest"]
            item.update(
                {
                    "project_name": (manifest.get("project") or {}).get("name"),
                    "created_at": manifest.get("created_at"),
                    "version_count": len(
                        (manifest.get("project") or {}).get("versions") or []
                    ),
                }
            )
        except Exception:
            pass
        archives.append(item)
    return sorted(archives, key=lambda item: item["modified_at"], reverse=True)


def resolve_archive_download_path(archive_dir: str, filename: str) -> str:
    if filename != os.path.basename(filename) or not filename.endswith(
        ARCHIVE_FILE_SUFFIX
    ):
        raise ProjectArchiveValidationError("Invalid archive filename")
    path = os.path.abspath(os.path.join(archive_dir, filename))
    base = os.path.abspath(archive_dir)
    if os.path.commonpath([base, path]) != base or not os.path.exists(path):
        raise ProjectArchiveValidationError("Archive not found")
    return path


def enforce_project_archive_retention(archive_dir: str, retention_count: int) -> None:
    base = Path(archive_dir)
    if not base.exists():
        return
    by_project: dict[str, list[Path]] = {}
    for path in base.glob(f"*{ARCHIVE_FILE_SUFFIX}"):
        project_key = path.stem
        try:
            archive = load_project_archive(str(path))
            project_key = (archive["manifest"].get("project") or {}).get(
                "name",
            ) or project_key
        except Exception:
            pass
        by_project.setdefault(project_key, []).append(path)
    for paths in by_project.values():
        ordered = sorted(paths, key=lambda item: item.stat().st_mtime, reverse=True)
        for stale in ordered[retention_count:]:
            try:
                stale.unlink()
            except OSError:
                pass


async def run_project_archive_snapshot_once(
    deps: ProjectArchiveServiceDeps,
    client: DTClient,
) -> list[dict[str, Any]]:
    include_names = get_project_archive_include_names()
    if not include_names:
        include_names = sorted(
            {
                project.get("name")
                for project in deps.cache_manager.get_cached_project_versions()
                if project.get("name")
            }
        )

    results: list[dict[str, Any]] = []
    for project_name in include_names:
        try:
            result = await export_project_archive(
                deps,
                client,
                project_name=project_name,
                refresh=True,
                created_by="snapshot",
                reason="snapshot",
            )
            results.append({"project_name": project_name, "status": "success", **result})
        except Exception as exc:
            deps.logger.warning("Project archive snapshot failed for %s: %s", project_name, exc)
            results.append(
                {
                    "project_name": project_name,
                    "status": "error",
                    "error": str(exc),
                }
            )

    enforce_project_archive_retention(
        deps.archive_path_provider(),
        get_project_archive_retention_count(),
    )
    return results
