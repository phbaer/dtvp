"""Source adapter for validated DTVP project archives."""

from __future__ import annotations

import hashlib
from typing import Any

from .dependency_track import build_normalized_snapshot


class ProjectArchiveConnector:
    source_type = "project-archive"

    def __init__(self, archive: dict[str, Any]):
        self.archive = archive
        self._versions: dict[str, dict[str, Any]] = {}
        for version in archive.get("versions") or []:
            project = version.get("project") or {}
            product_name = str(project.get("name") or "").strip()
            version_name = str(project.get("version") or "")
            external_version_id = str(project.get("uuid") or "").strip()
            if not external_version_id:
                fingerprint = hashlib.sha256(
                    f"{product_name}\0{version_name}".encode("utf-8")
                ).hexdigest()
                external_version_id = f"archive-version:{fingerprint}"
            if external_version_id in self._versions:
                raise ValueError("Archive contains duplicate project version identities")
            if not product_name:
                raise ValueError("Archive version is missing its product name")
            self._versions[external_version_id] = {
                **version,
                "project": {
                    **project,
                    "uuid": external_version_id,
                    "name": product_name,
                    "version": version_name,
                },
            }

    def version_ids(self) -> list[str]:
        return list(self._versions)

    async def discover_projects(self, client: Any) -> list[dict[str, Any]]:
        return [
            {
                "external_id": source_id,
                "product_name": version["project"]["name"],
                "version_name": version["project"]["version"],
                "active": True,
                "source_artifacts": version["project"],
            }
            for source_id, version in self._versions.items()
        ]

    async def fetch_snapshot(self, client: Any, scope: dict[str, Any]) -> dict[str, Any]:
        source_id = str(scope.get("project_id") or "").strip()
        version = self._versions.get(source_id)
        if version is None:
            raise LookupError("Archive project version was not found")
        project = version["project"]
        snapshot = build_normalized_snapshot(
            project=project,
            bom=version.get("bom") or {},
            findings=version.get("findings") or [],
            advisories=version.get("vulnerabilities") or [],
            source_type=self.source_type,
            source_version_id=source_id,
        )
        snapshot["source_artifacts"]["archive_assessments"] = (
            version.get("assessments") or []
        )
        snapshot["source_artifacts"]["archive_manifest"] = (
            self.archive.get("manifest") or {}
        )
        snapshot["provenance"]["archive_schema"] = (
            self.archive.get("manifest") or {}
        ).get("schema_version")
        return snapshot
