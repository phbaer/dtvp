"""Connector for importing pre-DTVP JSON inventory caches."""

from __future__ import annotations

from typing import Any

from .dependency_track import build_normalized_snapshot


class LegacyCacheConnector:
    """Expose saved project cache files through the shared import contract."""

    source_type = "legacy-cache"

    def __init__(self, projects: list[dict[str, Any]]):
        self.projects = {
            str(project["uuid"]): project
            for project in projects
            if str(project.get("uuid") or "").strip()
        }

    async def discover_projects(self, client: Any) -> list[dict[str, Any]]:
        return [
            {
                "external_id": project_id,
                "product_name": str(project.get("name") or project_id),
                "version_name": str(project.get("version") or ""),
                "active": bool(project.get("active", True)),
                "source_artifacts": {
                    key: value
                    for key, value in project.items()
                    if key not in {"bom", "findings", "advisories"}
                },
            }
            for project_id, project in self.projects.items()
        ]

    async def fetch_snapshot(self, client: Any, scope: dict[str, Any]) -> dict[str, Any]:
        project_id = str(scope.get("project_id") or "").strip()
        project = self.projects.get(project_id)
        if project is None:
            raise LookupError("Legacy cached project was not found")
        return build_normalized_snapshot(
            project=project,
            bom=project["bom"],
            findings=project["findings"],
            advisories=project["advisories"],
            source_type=self.source_type,
            source_product_id=f"name:{project.get('name') or project_id}",
            source_version_id=project_id,
        )
