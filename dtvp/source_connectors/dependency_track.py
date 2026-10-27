"""Dependency-Track source adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .base import SourceConnector


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _component_identity(component: dict[str, Any], ordinal: int) -> str:
    for key in ("bom-ref", "uuid", "purl"):
        value = str(component.get(key) or "").strip()
        if value:
            return value
    group = str(component.get("group") or "")
    name = str(component.get("name") or "")
    version = str(component.get("version") or "")
    return f"anonymous:{group}:{name}:{version}:{ordinal}"


def _flatten_components(components: Any) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []

    def visit(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            ordinal = len(flattened)
            flattened.append(
                {
                    "external_id": _component_identity(item, ordinal),
                    "identity": {
                        "purl": item.get("purl"),
                        "group": item.get("group"),
                        "name": item.get("name"),
                        "version": item.get("version"),
                    },
                    "source_ids": {
                        "bom_ref": item.get("bom-ref"),
                        "uuid": item.get("uuid"),
                    },
                    "purl": item.get("purl"),
                    "group": item.get("group"),
                    "name": item.get("name"),
                    "version": item.get("version"),
                    "type": item.get("type"),
                    "scope": item.get("scope"),
                    "hashes": item.get("hashes") or [],
                    "licenses": item.get("licenses") or [],
                    "properties": item.get("properties") or [],
                    "metadata": {
                        key: item[key]
                        for key in ("publisher", "description", "externalReferences", "evidence")
                        if key in item
                    },
                }
            )
            visit(item.get("components"))

    visit(components)
    return flattened


def _normalize_finding(
    finding: dict[str, Any], ordinal: int, captured_at: datetime
) -> dict[str, Any]:
    component = _as_mapping(finding.get("component"))
    vulnerability = _as_mapping(finding.get("vulnerability"))
    source_analysis = _as_mapping(finding.get("analysis"))
    component_id = str(component.get("uuid") or component.get("bom-ref") or "")
    component_identity = {
        "purl": component.get("purl"),
        "group": component.get("group"),
        "name": component.get("name"),
        "version": component.get("version"),
    }
    vulnerability_id = str(
        vulnerability.get("vulnId")
        or vulnerability.get("name")
        or vulnerability.get("uuid")
        or "unknown"
    )
    external_id = str(finding.get("uuid") or f"{component_id}:{vulnerability_id}:{ordinal}")
    return {
        "external_id": external_id,
        "component_external_id": component_id,
        "component_identity": component_identity,
        "vulnerability": {
            "external_id": str(vulnerability.get("uuid") or ""),
            "id": vulnerability_id,
            "name": vulnerability.get("name"),
            "source": vulnerability.get("source"),
            "aliases": vulnerability.get("aliases") or [],
            "severity": vulnerability.get("severity"),
            "cvss_v2": vulnerability.get("cvssV2BaseScore"),
            "cvss_v3": vulnerability.get("cvssV3BaseScore"),
            "cvss_v4": vulnerability.get("cvssV4BaseScore"),
            "metadata": {
                key: vulnerability[key]
                for key in ("description", "recommendation", "references", "cwe")
                if key in vulnerability
            },
        },
        "source_analysis": source_analysis,
        "attribution": {
            "source_type": "dependency-track",
            "observed_at": captured_at.isoformat(),
        },
    }


def build_normalized_snapshot(
    *,
    project: dict[str, Any],
    bom: dict[str, Any],
    findings: list[dict[str, Any]],
    advisories: list[dict[str, Any]],
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    captured_at = captured_at or datetime.now(UTC)
    metadata = _as_mapping(bom.get("metadata"))
    root_components = _flatten_components([_as_mapping(metadata.get("component"))])
    root_component = root_components[0] if root_components else {}
    components = _flatten_components(bom.get("components"))
    dependencies: list[dict[str, Any]] = []
    for dependency in bom.get("dependencies", []) or []:
        if not isinstance(dependency, dict):
            continue
        dependencies.append(
            {
                "source_external_id": str(dependency.get("ref") or ""),
                "target_external_ids": [
                    str(item)
                    for item in dependency.get("dependsOn", []) or []
                    if item is not None
                ],
                "provides": dependency.get("provides") or [],
            }
        )
    source_project_id = str(project.get("uuid") or "").strip()
    if not source_project_id:
        raise ValueError("Dependency-Track project is missing its stable UUID")
    product_name = str(project.get("name") or "").strip()
    if not product_name:
        raise ValueError("Dependency-Track project is missing its name")

    normalized_advisories = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        normalized_advisories.append(
            {
                "external_id": str(advisory.get("uuid") or ""),
                "id": str(advisory.get("vulnId") or advisory.get("name") or "unknown"),
                "source": advisory.get("source"),
                "severity": advisory.get("severity"),
                "aliases": advisory.get("aliases") or [],
                "metadata": {
                    key: advisory[key]
                    for key in ("description", "recommendation", "references", "cwe")
                    if key in advisory
                },
            }
        )

    return {
        "schema": "dtvp.inventory-snapshot/v1",
        "captured_at": captured_at.isoformat(),
        "product": {"name": product_name},
        "version": {"name": str(project.get("version") or "")},
        "inventory": {
            "root_component": root_component,
            "components": components,
            "dependencies": dependencies,
        },
        "security": {
            "findings": [
                _normalize_finding(finding, ordinal, captured_at)
                for ordinal, finding in enumerate(findings)
                if isinstance(finding, dict)
            ],
            "advisories": normalized_advisories,
        },
        "provenance": {
            "source_type": "dependency-track",
            "source_product_id": f"name:{product_name}",
            "source_version_id": source_project_id,
            "source_project_name": product_name,
            "captured_at": captured_at.isoformat(),
        },
        "source_artifacts": {
            "project": project,
            "bom": bom,
            "findings": findings,
            "advisories": advisories,
        },
    }


class DependencyTrackConnector:
    source_type = "dependency-track"

    async def fetch_snapshot(self, client: Any, scope: dict[str, Any]) -> dict[str, Any]:
        project_id = str(scope.get("project_id") or "").strip()
        if not project_id:
            raise ValueError("A Dependency-Track project UUID is required")

        projects = await client.get_projects("")
        matches = [
            project
            for project in projects
            if isinstance(project, dict)
            and str(project.get("uuid") or "").strip() == project_id
        ]
        if not matches:
            raise LookupError("Dependency-Track project was not found or is inactive")
        if len(matches) > 1:
            raise ValueError("Dependency-Track returned duplicate project UUIDs")
        project = matches[0]

        bom = await client.get_bom(project_id)
        findings = await client.get_vulnerabilities(project_id)
        advisories = await client.get_project_vulnerabilities(project_id)
        if not isinstance(bom, dict):
            raise ValueError("Dependency-Track returned an invalid BOM")
        if not isinstance(findings, list):
            raise ValueError("Dependency-Track returned an invalid findings snapshot")
        if not isinstance(advisories, list):
            raise ValueError("Dependency-Track returned an invalid advisory snapshot")

        return build_normalized_snapshot(
            project=project,
            bom=bom,
            findings=findings,
            advisories=advisories,
        )
