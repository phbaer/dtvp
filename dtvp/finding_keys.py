"""DTVP's key for one finding.

Dependency-Track's findings have no UUID of their own. A finding is the
pair of a component and a vulnerability in a project version, and
Dependency-Track names it with its ``matrix``:
``<project uuid>:<component uuid>:<vulnerability uuid>``. DTVP uses that
composite as the finding key (``finding_uuid`` in the API and MCP). It is
an internal key and is never sent to Dependency-Track.
"""

from __future__ import annotations

from typing import Any, Optional


def composite_finding_key(
    project_uuid: Any, component_uuid: Any, vulnerability_uuid: Any
) -> Optional[str]:
    """``<project>:<component>:<vulnerability>``; ``None`` without all three."""
    parts = [str(part or "").strip() for part in (project_uuid, component_uuid, vulnerability_uuid)]
    return ":".join(parts) if all(parts) else None


def finding_key(project_uuid: Any, finding: Any) -> Optional[str]:
    """The key of a finding as a source reports it: its own ``uuid`` where a
    source has one, else Dependency-Track's ``matrix``, else the composite of
    the project, component and vulnerability UUIDs."""
    if not isinstance(finding, dict):
        return None
    for name in ("uuid", "matrix"):
        value = str(finding.get(name) or "").strip()
        if value:
            return value
    return composite_finding_key(
        project_uuid,
        (finding.get("component") or {}).get("uuid"),
        (finding.get("vulnerability") or {}).get("uuid"),
    )


def instance_finding_key(instance: Any) -> Optional[str]:
    """The key of a grouped finding (a component entry of a vulnerability
    group): its ``finding_uuid``, else the composite of its UUIDs. Fills the
    gap of snapshots built before the key was derived."""
    if not isinstance(instance, dict):
        return None
    value = str(instance.get("finding_uuid") or "").strip()
    if value:
        return value
    return composite_finding_key(
        instance.get("project_uuid"),
        instance.get("component_uuid"),
        instance.get("vulnerability_uuid"),
    )


# Before findings had a key, the automatic-assessment workflow recorded its
# code-analysis applications under "finding:<project>:<component>:<vuln>".
_LEGACY_PREFIX = "finding:"


def stored_finding_key(value: Any) -> str:
    """A finding key as stored by older versions, in today's form."""
    text = str(value or "")
    return text[len(_LEGACY_PREFIX):] if text.startswith(_LEGACY_PREFIX) else text
