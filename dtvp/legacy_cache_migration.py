"""Resumable migration of legacy JSON inventory caches into DTVP storage."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from .artifact_store import ArtifactStore
from .catalog_repository import (
    get_latest_source_snapshot,
)
from .database_migrations import run_database_migrations
from .source_connectors.legacy_cache import LegacyCacheConnector
from .source_import_service import (
    _state_sha256,
    discover_source_projects,
    import_source_scope,
)

logger = logging.getLogger(__name__)


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read legacy cache file {path}: {exc}") from exc


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _load_legacy_projects(cache_path: Path) -> list[dict[str, Any]]:
    raw_projects = _read_json(cache_path / "projects.json", [])
    if not isinstance(raw_projects, list):
        raise ValueError("Legacy project cache must contain a JSON array")
    projects: list[dict[str, Any]] = []
    for raw in raw_projects:
        if not isinstance(raw, dict):
            continue
        project_id = str(raw.get("uuid") or "").strip()
        project_name = str(raw.get("name") or "").strip()
        if not project_id or not project_name:
            continue
        filename = cache_path / "findings" / f"{_safe_filename(project_id)}.json"
        findings = _read_json(filename, None)
        if findings is None:
            continue
        if not isinstance(findings, list) or any(
            not isinstance(finding, dict) for finding in findings
        ):
            raise ValueError(f"Legacy findings cache for project {project_id} is invalid")
        project = {
            **raw,
            "uuid": project_id,
            "name": project_name,
            "version": str(raw.get("version") or ""),
            "bom": _read_json(
                cache_path / "boms" / f"{_safe_filename(project_id)}.json", {}
            ) or {},
            "findings": findings,
            "advisories": _read_json(
                cache_path
                / "project_vulnerabilities"
                / f"{_safe_filename(project_id)}.json",
                [],
            ) or [],
        }
        if not isinstance(project["bom"], dict) or not isinstance(project["advisories"], list):
            raise ValueError(f"Legacy cache data for project {project_id} is invalid")
        projects.append(project)
    return projects


async def migrate_legacy_inventory(*, apply: bool, cache_path: str | None = None) -> dict[str, Any]:
    await asyncio.to_thread(run_database_migrations)
    resolved_cache_path = Path(
        cache_path or os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache")
    ).expanduser()
    projects = _load_legacy_projects(resolved_cache_path)
    report: dict[str, Any] = {
        "mode": "apply" if apply else "dry-run",
        "cache_path": str(resolved_cache_path.resolve()),
        "projects_found": len(projects),
        "imported": [],
        "unchanged": [],
        "failed": [],
    }
    candidates = []
    catalog_projects = []
    unchanged_projects = []
    connector = LegacyCacheConnector(projects)
    for project in projects:
        project_id = project["uuid"]
        try:
            normalized = await connector.fetch_snapshot(
                None, {"project_id": project_id}
            )
            desired_state = _state_sha256(normalized)
            latest_legacy = await asyncio.to_thread(
                get_latest_source_snapshot,
                "legacy-cache",
                "dtvp-cache://local",
                project_id,
            )
        except Exception as exc:
            logger.exception("Could not inspect legacy cache for %s", project_id)
            report["failed"].append({"project_id": project_id, "error": str(exc)})
            continue
        if latest_legacy and latest_legacy.get("state_sha256") == desired_state:
            report["unchanged"].append(project_id)
            unchanged_projects.append(project)
            catalog_projects.append(project)
        else:
            candidates.append(project)
    report["eligible"] = len(candidates)
    if not apply:
        return report

    # Import lazily because CacheManager initializes the legacy SQLite outbox
    # and its local directories as part of application startup.
    os.environ["DTVP_DT_CACHE_PATH"] = str(resolved_cache_path)
    from .dt_cache import CacheManager

    cache = CacheManager(base_path=str(resolved_cache_path))
    for project in unchanged_projects:
        project_id = project["uuid"]
        try:
            migrated = await cache._migrate_pending_local_assessments(
                project_id, source_type="legacy-cache"
            )
            if not migrated:
                raise RuntimeError("Legacy assessment migration was incomplete")
            report.setdefault("assessment_migration_checked", []).append(project_id)
        except Exception as exc:
            logger.exception("Legacy assessment migration failed for %s", project_id)
            report["failed"].append({"project_id": project_id, "error": str(exc)})

    connector = LegacyCacheConnector(candidates)
    for project in candidates:
        project_id = project["uuid"]
        try:
            payload_digest = hashlib.sha256(
                ArtifactStore.encode_json(project)
            ).hexdigest()
            run = await import_source_scope(
                connector=connector,
                client=None,
                source_base_url="dtvp-cache://local",
                request_id=f"legacy-cache:{project_id}:{payload_digest[:24]}:{uuid4()}",
                initiated_by="system:legacy-cache-migration",
                scope={"project_id": project_id},
            )
            if run.get("status") != "succeeded":
                raise RuntimeError(run.get("error_summary") or "Import did not succeed")
            catalog_projects.append(project)
            report["imported"].append({
                "project_id": project_id,
                "snapshot_id": run.get("snapshot_id"),
            })
            migrated = await cache._migrate_pending_local_assessments(
                project_id, source_type=connector.source_type
            )
            if not migrated:
                raise RuntimeError("Legacy assessment migration was incomplete")
        except Exception as exc:
            logger.exception("Legacy cache migration failed for %s", project_id)
            report["failed"].append({"project_id": project_id, "error": str(exc)})

    if catalog_projects:
        try:
            imported_connector = LegacyCacheConnector(catalog_projects)
            await discover_source_projects(
                connector=imported_connector,
                client=None,
                source_base_url="dtvp-cache://local",
                complete=False,
            )
        except Exception as exc:
            logger.exception("Could not publish migrated legacy project catalog")
            report["catalog_error"] = str(exc)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import pre-DTVP JSON inventory caches into the DTVP catalog."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="publish eligible legacy projects; without this flag, only report",
    )
    parser.add_argument("--cache-path", default=None, help="override DTVP_DT_CACHE_PATH")
    args = parser.parse_args()
    logging.basicConfig(level=os.getenv("DTVP_LOG_LEVEL", "INFO"))
    report = asyncio.run(
        migrate_legacy_inventory(apply=args.apply, cache_path=args.cache_path)
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["failed"] or report.get("catalog_error"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
