"""Assessment scopes of a vulnerability group (ADR 0010).

A group keeps one *base* assessment. Project versions whose findings carry a
``[Version Override: L]`` marker form the override scope ``L``; all versions
with the same label share it. Scopes are derived from the findings' texts on
every read, never stored. The lifecycle rules run inside each scope and are
combined (``combine_lifecycles``).

The web client derives scopes the same way (``assessmentScopes.ts``); both are
tested against ``frontend/src/lib/__tests__/fixtures/assessment_scope_cases.json``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .assessment_model import version_override
from .inconsistency import (  # noqa: F401 (re-exported)
    INCONSISTENCY_REASON_VERSION_OVERRIDE_LABEL_MISMATCH,
    INCONSISTENCY_REASON_VERSION_OVERRIDE_PARTIAL,
)

BASE = "base"
AMBIGUOUS = "ambiguous"

_IGNORED_FOR_UNTOUCHED = re.compile(
    r"\[(?:Version Override|Override Reason|Status: Pending Review)[^\]]*\]"
)


def _state(instance: Mapping[str, Any]) -> str:
    return str(instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET")


def _details(instance: Mapping[str, Any]) -> str:
    return str(instance.get("analysis_details") or instance.get("analysisDetails") or "")


def is_untouched(instance: Mapping[str, Any]) -> bool:
    """No state and no text other than the override and pending tags: a
    finding nobody assessed yet (a new or inherited finding)."""
    if _state(instance) != "NOT_SET":
        return False
    return not _IGNORED_FOR_UNTOUCHED.sub("", _details(instance)).strip()


def _label_key(label: str) -> str:
    return label.casefold()


def _version_key(version: Mapping[str, Any], instance: Mapping[str, Any]) -> str:
    return str(
        instance.get("project_uuid")
        or version.get("project_uuid")
        or version.get("project_version")
        or version.get("version")
        or ""
    )


def finding_key(instance: Mapping[str, Any]) -> str:
    return ":".join(
        str(instance.get(name) or "")
        for name in ("project_uuid", "component_uuid", "vulnerability_uuid")
    )


@dataclass
class Scope:
    name: str
    label: Optional[str] = None
    # The reason the tagged findings agree on; None without one.
    reason: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    versions: list[dict[str, Any]] = field(default_factory=list)
    instances: list[dict[str, Any]] = field(default_factory=list)
    # Untagged findings with an assessment in an overridden version.
    partial: list[str] = field(default_factory=list)
    # Untagged untouched findings in an overridden version: coverage missing.
    gaps: list[str] = field(default_factory=list)

    @property
    def pending(self) -> bool:
        return any("[Status: Pending Review]" in _details(i) for i in self.instances)

    @property
    def reason_mismatch(self) -> bool:
        return len(set(self.reasons)) > 1


@dataclass
class ScopeView:
    scopes: list[Scope]
    # Findings of versions with more than one label: compared in no scope.
    ambiguous: list[dict[str, Any]]
    version_scopes: dict[str, str]

    @property
    def has_overrides(self) -> bool:
        return bool(self.ambiguous) or any(s.name != BASE for s in self.scopes)

    @property
    def primary(self) -> Optional[Scope]:
        """``base`` when it has findings, else the scope with the most
        findings (label order breaks ties)."""
        base = next((s for s in self.scopes if s.name == BASE and s.instances), None)
        if base is not None:
            return base
        ranked = sorted(
            (s for s in self.scopes if s.instances),
            key=lambda s: (-len(s.instances), _label_key(s.label or "")),
        )
        return ranked[0] if ranked else None


def _labels(markers: Iterable[Optional[dict[str, Any]]]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for marker in markers:
        if marker and marker.get("label"):
            labels.setdefault(_label_key(marker["label"]), marker["label"])
    return labels


def version_scope(
    group: Mapping[str, Any],
    version: str,
    extra_records: Iterable[Mapping[str, Any]] = (),
) -> str:
    """The scope ``version`` maps to, counting ``extra_records`` (records not
    active in the group, with their texts) next to its active findings."""
    markers = [
        version_override(_details(instance))
        for affected in group.get("affected_versions") or []
        for instance in affected.get("components") or []
        if _version_key(affected, instance) == version
    ]
    markers += [version_override(_details(record)) for record in extra_records]
    labels = _labels(markers)
    if not labels:
        return BASE
    if len(labels) > 1:
        return AMBIGUOUS
    return next(iter(labels.values()))


def assessment_scopes(group: Mapping[str, Any]) -> ScopeView:
    """The scopes of ``group``: per version, the labels its findings carry
    decide its scope (none: base; one: that label; more: ambiguous)."""
    by_version: dict[str, tuple[dict[str, Any], list[tuple[dict[str, Any], Any]]]] = {}
    for affected in group.get("affected_versions") or []:
        for instance in affected.get("components") or []:
            if not isinstance(instance, dict):
                continue
            key = _version_key(affected, instance)
            entry = by_version.setdefault(key, (affected, []))
            entry[1].append((instance, version_override(_details(instance))))

    scopes: dict[str, Scope] = {BASE: Scope(name=BASE)}
    ambiguous: list[dict[str, Any]] = []
    version_scopes: dict[str, str] = {}
    for key, (affected, findings) in by_version.items():
        labels = _labels(marker for _instance, marker in findings)
        version = {
            "project_uuid": key,
            "version": affected.get("project_version") or affected.get("version"),
        }
        if len(labels) > 1:
            version_scopes[key] = AMBIGUOUS
            ambiguous.extend(instance for instance, _marker in findings)
            continue
        if not labels:
            scope = scopes[BASE]
        else:
            label_key, label = next(iter(labels.items()))
            scope = scopes.setdefault(label_key, Scope(name=label, label=label))
        version_scopes[key] = scope.name
        scope.versions.append(version)
        for instance, marker in findings:
            scope.instances.append(instance)
            if scope.name == BASE:
                continue
            if marker:
                scope.reasons.append(marker.get("reason") or "")
            elif is_untouched(instance):
                scope.gaps.append(finding_key(instance))
            else:
                scope.partial.append(finding_key(instance))

    ordered = [scopes.pop(BASE)] + sorted(
        scopes.values(), key=lambda s: _label_key(s.label or "")
    )
    for scope in ordered:
        agreed = set(scope.reasons)
        scope.reason = next(iter(agreed)) or None if len(agreed) == 1 else None
    return ScopeView(scopes=ordered, ambiguous=ambiguous, version_scopes=version_scopes)


def resolved_marker(scope: Scope) -> Optional[dict[str, Any]]:
    """The marker a writer gives the findings of ``scope``: none for base,
    ``{label, reason}`` for an override with an agreed reason. A writer must
    not write into an ambiguous scope or one whose findings disagree on the
    reason."""
    if scope.name == BASE:
        return None
    if scope.name == AMBIGUOUS or scope.reason_mismatch:
        raise ValueError(f"scope {scope.name!r} has no agreed marker")
    return {"label": scope.label, "reason": scope.reason}


def scoped_group(group: Mapping[str, Any], instances: list[dict[str, Any]]) -> dict[str, Any]:
    """``group`` with only ``instances``, for rules that run per scope."""
    wanted = {id(instance) for instance in instances}
    versions = []
    for affected in group.get("affected_versions") or []:
        components = [c for c in affected.get("components") or [] if id(c) in wanted]
        if components:
            versions.append({**affected, "components": components})
    return {**group, "affected_versions": versions}


# Combined in this order (ADR 0010 section 5): a pending override is never
# ASSESSED, and is never Conflicting only because it differs from base.
def combine_lifecycles(lifecycles: list[str], *, ambiguous: bool = False) -> str:
    if ambiguous or "INCONSISTENT" in lifecycles:
        return "INCONSISTENT"
    if "INCOMPLETE" in lifecycles or (
        "OPEN" in lifecycles and any(value != "OPEN" for value in lifecycles)
    ):
        return "INCOMPLETE"
    if "NEEDS_APPROVAL" in lifecycles:
        return "NEEDS_APPROVAL"
    if all(value == "OPEN" for value in lifecycles):
        return "OPEN"
    if "ASSESSED_LEGACY" in lifecycles:
        return "ASSESSED_LEGACY"
    return "ASSESSED"
