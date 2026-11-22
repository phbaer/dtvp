"""Names for the components of gone findings DTVP only knows by UUID.

Rows created from assessment records that predate finding tracking have no
component name. When gone findings are shown, the name, version and package
URL are looked up locally, once, and stored in the row: in the stored BOM of
the project version, then in project archives, newest first. Nothing is
asked of the source.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

from .finding_lifecycle_services import (
    STATUS_GONE,
    FindingLifecycleStore,
    component_identity,
    index_bom,
)
from .project_archive_services import ARCHIVE_FILE_SUFFIX, load_project_archive

logger = logging.getLogger(__name__)

Fields = dict[str, Optional[str]]

# Lookups that found nothing, per project: not repeated while the missing
# components and the archives stay the same.
_attempted: dict[str, tuple[frozenset[str], tuple[tuple[str, float], ...]]] = {}
_attempted_lock = threading.Lock()


def _fields(component: Mapping[str, Any]) -> Fields:
    def text(value: Any) -> Optional[str]:
        return str(value) if isinstance(value, str) and value else None

    return {
        "component_name": text(component.get("name")),
        "component_version": text(component.get("version")),
        "component_purl": text(component.get("purl")),
        "component_identity": component_identity(component),
    }


def _from_bom(bom: Any) -> dict[str, Fields]:
    index = index_bom(bom)
    return dict(index.components) if index is not None else {}


def _from_findings(findings: Any) -> dict[str, Fields]:
    found: dict[str, Fields] = {}
    for finding in findings if isinstance(findings, list) else []:
        component = finding.get("component") if isinstance(finding, dict) else None
        if isinstance(component, dict) and component.get("uuid"):
            found[str(component["uuid"])] = _fields(component)
    return found


def _archives(archive_dir: Optional[str]) -> list[Path]:
    if not archive_dir:
        return []
    base = Path(archive_dir)
    if not base.is_dir():
        return []
    paths = [path for path in base.glob(f"*{ARCHIVE_FILE_SUFFIX}") if path.is_file()]
    return sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)


# Parsed archives, by path: their modification time and, per project
# version, the components their findings and BOM name. Shared by every
# project, so an archive is read once per process however many versions ask.
_archive_cache: dict[str, tuple[float, dict[str, dict[str, Fields]]]] = {}
_archive_cache_lock = threading.Lock()


def _parse_archive(path: Path) -> dict[str, dict[str, Fields]]:
    archive = load_project_archive(str(path))
    by_project: dict[str, dict[str, Fields]] = {}
    for version in archive.get("versions") or []:
        entry = version.get("entry") or {}
        project_uuid = str((entry.get("project") or {}).get("uuid") or "")
        if not project_uuid:
            continue
        components = by_project.setdefault(project_uuid, {})
        # The BOM first, the findings over it: what a finding said wins.
        components.update(_from_bom(version.get("bom")))
        for uuid, fields in _from_findings(version.get("findings")).items():
            if fields.get("component_name"):
                components[uuid] = fields
    return by_project


def _archive_components(
    path: Path, mtime: float, budget: list[int]
) -> Optional[dict[str, dict[str, Fields]]]:
    """The parsed archive, from the cache or read now while ``budget``
    allows (``budget[0]`` archives left to read). ``None`` when the budget
    is spent; ``{}`` for an archive that cannot be read."""
    key = str(path)
    with _archive_cache_lock:
        cached = _archive_cache.get(key)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    if budget[0] <= 0:
        return None
    budget[0] -= 1
    try:
        parsed = _parse_archive(path)
    except Exception as exc:  # a broken archive is skipped, not fatal
        logger.debug("Skipping archive %s: %s", path.name, exc)
        parsed = {}
    with _archive_cache_lock:
        _archive_cache[key] = (mtime, parsed)
    return parsed


def resolve_gone_component_names(
    lifecycle: FindingLifecycleStore,
    project_uuid: str,
    *,
    stored_bom: Callable[[], Any],
    archive_dir: Optional[str],
    max_archive_reads: Optional[int] = None,
) -> int:
    """Fill in the components of the project's gone findings that have no
    name, from local sources. Returns how many rows were filled.

    ``max_archive_reads`` bounds how many archives not yet parsed are read
    in this call (a read passes a small number; the rest follows at the
    next read). Parsed archives are kept for every project."""
    missing = frozenset(
        row["component_uuid"]
        for row in lifecycle.presence(project_uuid).values()
        if row.get("status") == STATUS_GONE and not row.get("component_name")
    )
    if not missing:
        return 0
    archives = _archives(archive_dir)
    signature = tuple((path.name, path.stat().st_mtime) for path in archives)
    with _attempted_lock:
        if _attempted.get(project_uuid) == (missing, signature):
            return 0

    found: dict[str, Fields] = {}

    def take(source: Mapping[str, Fields]) -> bool:
        for uuid in missing - found.keys():
            fields = source.get(uuid)
            if fields and fields.get("component_name"):
                found[uuid] = dict(fields)
        return found.keys() >= missing

    try:
        done = take(_from_bom(stored_bom()))
    except Exception as exc:
        logger.debug("Stored BOM of %s unreadable: %s", project_uuid, exc)
        done = False
    complete = True  # every archive was consulted
    if not done:
        budget = [max_archive_reads if max_archive_reads is not None else len(archives)]
        for path, (_name, mtime) in zip(archives, signature):
            parsed = _archive_components(path, mtime, budget)
            if parsed is None:
                complete = False
                break
            if take(parsed.get(project_uuid) or {}):
                break

    filled = lifecycle.fill_components(project_uuid, found) if found else 0
    with _attempted_lock:
        if found.keys() >= missing:
            _attempted.pop(project_uuid, None)
        elif complete:
            # Nothing more to find until the rows or the archives change.
            _attempted[project_uuid] = (missing - found.keys(), signature)
    return filled
