"""Project normalized DTVP snapshots into existing inventory API shapes."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def project_component(component: dict[str, Any]) -> dict[str, Any]:
    source_ids = component.get("source_ids") or {}
    identity = component.get("identity") or {}
    result = {
        "uuid": source_ids.get("uuid") or component.get("external_id"),
        "bom-ref": source_ids.get("bom_ref") or component.get("external_id"),
        "purl": component.get("purl") or identity.get("purl"),
        "group": component.get("group") or identity.get("group"),
        "name": component.get("name") or identity.get("name"),
        "version": component.get("version") or identity.get("version"),
        "type": component.get("type"),
        "scope": component.get("scope"),
        "hashes": deepcopy(_list(component.get("hashes"))),
        "licenses": deepcopy(_list(component.get("licenses"))),
        "properties": deepcopy(_list(component.get("properties"))),
    }
    result.update(deepcopy(component.get("metadata") or {}))
    return result


def project_findings(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    inventory_components = {
        str(component.get("external_id") or ""): component
        for component in _list((snapshot.get("inventory") or {}).get("components"))
        if isinstance(component, dict)
    }
    results = []
    for finding in _list((snapshot.get("security") or {}).get("findings")):
        if not isinstance(finding, dict):
            continue
        component_id = str(finding.get("component_external_id") or "")
        component = inventory_components.get(component_id, {})
        identity = finding.get("component_identity") or {}
        source_ids = finding.get("component_source_ids") or {}
        vulnerability = finding.get("vulnerability") or {}
        metadata = deepcopy(vulnerability.get("metadata") or {})
        projected_vulnerability = {
            "uuid": vulnerability.get("external_id") or "",
            "vulnId": vulnerability.get("id") or "unknown",
            "name": vulnerability.get("name"),
            "source": vulnerability.get("source"),
            "severity": vulnerability.get("severity"),
            "aliases": deepcopy(_list(vulnerability.get("aliases"))),
            "cvssV2BaseScore": vulnerability.get("cvss_v2"),
            "cvssV2Vector": vulnerability.get("cvss_v2_vector"),
            "cvssV3BaseScore": vulnerability.get("cvss_v3"),
            "cvssV3Vector": vulnerability.get("cvss_v3_vector"),
            "cvssV4BaseScore": vulnerability.get("cvss_v4"),
            "cvssV4Vector": vulnerability.get("cvss_v4_vector"),
            **metadata,
        }
        if vulnerability.get("title") is not None:
            projected_vulnerability["title"] = vulnerability["title"]
        projected_component = project_component(component) if component else {
            "uuid": source_ids.get("uuid") or component_id,
            "bom-ref": source_ids.get("bom_ref") or component_id,
            **identity,
        }
        results.append({
            "uuid": finding.get("external_id"),
            "component": projected_component,
            "vulnerability": projected_vulnerability,
            "analysis": deepcopy(finding.get("source_analysis") or {}),
            "attribution": deepcopy(finding.get("attribution") or {}),
        })
    return results


def project_advisories(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for advisory in _list((snapshot.get("security") or {}).get("advisories")):
        if not isinstance(advisory, dict):
            continue
        metadata = deepcopy(advisory.get("metadata") or {})
        results.append({
            "uuid": advisory.get("external_id") or "",
            "vulnId": advisory.get("id") or "unknown",
            "name": advisory.get("name"),
            "source": advisory.get("source"),
            "severity": advisory.get("severity"),
            "aliases": deepcopy(_list(advisory.get("aliases"))),
            "cvssV2BaseScore": advisory.get("cvss_v2"),
            "cvssV2Vector": advisory.get("cvss_v2_vector"),
            "cvssV3BaseScore": advisory.get("cvss_v3"),
            "cvssV3Vector": advisory.get("cvss_v3_vector"),
            "cvssV4BaseScore": advisory.get("cvss_v4"),
            "cvssV4Vector": advisory.get("cvss_v4_vector"),
            **metadata,
        })
    return results


def project_bom(snapshot: dict[str, Any]) -> dict[str, Any]:
    inventory = snapshot.get("inventory") or {}
    root_component = inventory.get("root_component") or {}
    bom: dict[str, Any] = {
        "components": [
            project_component(component)
            for component in _list(inventory.get("components"))
            if isinstance(component, dict)
        ],
        "dependencies": [
            {
                "ref": dependency.get("source_external_id"),
                "dependsOn": deepcopy(
                    _list(dependency.get("target_external_ids"))
                ),
                "provides": deepcopy(_list(dependency.get("provides"))),
            }
            for dependency in _list(inventory.get("dependencies"))
            if isinstance(dependency, dict)
        ],
    }
    if root_component:
        bom["metadata"] = {"component": project_component(root_component)}
    return bom
