"""The team mapping report: which findings fall to the catch-all ``*`` and
under which project roots and top-level components, how many findings each
saved entry owns, and an inventory of the stored components for the
Settings editor (autocomplete and a live preview of entries being typed).

Built from the stored BOMs and findings of the versions active in the
source, in a background thread; cached until the mapping or the stored data
change. See docs/assessment-model.md#team-mapping-report.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional

from .logic import BOMAnalysisCache
from .team_mapping import (
    ComponentIdentity,
    compile_team_mapping,
    parse_team_mapping_key,
    project_fallback_match,
    purl_package_identity,
    selector_matches_identity,
)

logger = logging.getLogger(__name__)

# Inventory entries (distinct name, group and package) sent to the browser.
INVENTORY_LIMIT = 40000
# Rows of the unmapped list.
UNMAPPED_LIMIT = 500

FLAG_ROOT = 1
FLAG_TOP_LEVEL = 2

ReportVersion = dict[str, Any]  # project_uuid, project, version


def purl_base(purl: Optional[str]) -> str:
    """A package URL without version, qualifiers and subpath."""
    text = str(purl or "").strip()
    if not text:
        return ""
    text = text.split("#", 1)[0].split("?", 1)[0]
    head, _, last = text.rpartition("/")
    if "@" in last:
        last = last.rsplit("@", 1)[0]
        return f"{head}/{last}" if head else last
    return text


def _identity_key(name: str, group: str, purl: str) -> tuple[str, str, str]:
    return (name.strip().lower(), group.strip().lower(), purl_base(purl).lower())


@dataclass
class _Row:
    kind: str  # "root" | "component"
    name: str
    group: str = ""
    purl: str = ""
    in_bom: bool = True
    findings: int = 0
    projects: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, project: str, version: str, count: int = 1) -> None:
        self.findings += count
        entry = self.projects.setdefault(project, {"findings": 0, "versions": set()})
        entry["findings"] += count
        if version:
            entry["versions"].add(version)


def suggest_key(
    row: _Row,
    mapping: tuple,
    inventory_projects: dict[tuple[str, str, str], set[str]],
) -> tuple[str, str]:
    """A mapping key that would own the row, and why this form."""
    top_project = max(row.projects.items(), key=lambda item: item[1]["findings"])[0]
    if row.kind == "root":
        return f"project::{top_project}", "Owns every finding of the project no component owns"
    identity = ComponentIdentity(
        name=row.name, group=row.group or None, purl=row.purl or None, group_known=row.in_bom
    )
    package = purl_package_identity(identity) if row.purl else None
    if row.purl:
        candidate_identity = package or identity
        name = candidate_identity.name
        group = candidate_identity.group or ""
        key = f"{group}:{name}" if group else name
        selector = parse_team_mapping_key(key)
        if not selector.error and (
            selector_matches_identity(selector, identity, project=top_project)
            or (package is not None and selector_matches_identity(selector, package, project=top_project))
        ):
            return key, "The package name its purl names"
        return f"purl::{purl_base(row.purl)}", "Its package URL"
    if row.group:
        return f"{row.group}:{row.name}", "Its group and name"
    projects = inventory_projects.get(_identity_key(row.name, "", ""), set())
    reason = (
        "A name without purl or group; scoped to the project"
        if len(projects) <= 1
        else f"The name {row.name!r} also occurs in {len(projects) - 1} other project(s)"
    )
    return f"project:{top_project}::{row.name}", reason


class _VersionAnalysis:
    """One version: owners of its findings and the components above them."""

    def __init__(self, bom: dict[str, Any], mapping: tuple, project: str) -> None:
        self.processor = BOMAnalysisCache(bom or {}, mapping, project)
        meta = ((bom or {}).get("metadata") or {}).get("component") or {}
        self.root_ref = meta.get("bom-ref") or None
        self.root = meta
        self._ancestors: dict[str, frozenset[str]] = {}

    def parents(self, ref: str) -> list[str]:
        return self.processor._get_parent_refs(ref)

    def ancestors(self, ref: str) -> frozenset[str]:
        """``ref`` and every component above it."""
        cached = self._ancestors.get(ref)
        if cached is not None:
            return cached
        seen = {ref}
        stack = [ref]
        while stack:
            for parent in self.parents(stack.pop()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        result = self._ancestors[ref] = frozenset(seen)
        return result

    def topmost(self, ref: str) -> set[str]:
        """The components right below the project root on the chains above
        ``ref``, or a chain's topmost component when it does not reach the
        root. Empty when ``ref`` is the root."""
        if ref == self.root_ref:
            return set()
        tops = set()
        for candidate in self.ancestors(ref):
            if candidate == self.root_ref:
                continue
            parents = self.parents(candidate)
            if not parents or (self.root_ref and self.root_ref in parents):
                tops.add(candidate)
        return tops

    def identity(self, ref: str) -> tuple[str, str, str]:
        processor = self.processor
        return (
            str(processor._get_component_name(ref) or ""),
            str(processor._get_component_group(ref) or ""),
            str(processor._get_component_purl(ref) or ""),
        )


def _loose_token(selector) -> str:
    """A selector's name with case, separators and the purl's type and
    namespace ignored: ``VPStatsApp``, ``vp-stats-app`` and
    ``purl::pkg:npm/vp-stats-app`` all read ``vpstatsapp``."""
    name = selector.name
    if selector.purl is not None:
        package = purl_package_identity(
            ComponentIdentity(name="", purl=selector.purl, group_known=True)
        )
        name = package.name if package is not None else ""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def near_duplicate_disagreements(mapping: Any) -> list[dict[str, Any]]:
    """Selectors that name nearly the same component (``_loose_token``) in
    the same project scope but give it to different teams."""
    groups: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for entry in compile_team_mapping(mapping or {}):
        selector = entry.selector
        if selector.wildcard or selector.project_fallback or selector.error:
            continue
        token = _loose_token(selector)
        if token:
            groups[((selector.project or "").lower(), token)].append((entry.key, entry.tags[0]))
    result = []
    for (_scope, token), entries in sorted(groups.items()):
        teams = sorted({team for _key, team in entries}, key=str.lower)
        if len(teams) > 1:
            result.append(
                {
                    "token": token,
                    "teams": teams,
                    "entries": [{"key": key, "team": team} for key, team in sorted(entries)],
                }
            )
    return result


def build_mapping_report(
    mapping: dict[str, Any],
    versions: Iterable[ReportVersion],
    load_bom: Callable[[str], Optional[dict[str, Any]]],
    load_findings: Callable[[str], Optional[list[dict[str, Any]]]],
    *,
    inventory_limit: int = INVENTORY_LIMIT,
    unmapped_limit: int = UNMAPPED_LIMIT,
) -> dict[str, Any]:
    compiled = compile_team_mapping(mapping or {})
    wildcard_key = next((entry.key for entry in compiled if entry.selector.wildcard), None)

    project_stats: dict[str, dict[str, Any]] = {}
    entry_stats: dict[str, dict[str, Any]] = {}
    roots: dict[str, _Row] = {}
    components: dict[tuple[str, str, str], _Row] = {}
    # (project, identity key) -> [display name, group, purl, below, unmapped below, flags]
    inventory: dict[tuple[str, tuple[str, str, str]], list[Any]] = {}
    inventory_projects: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    missing: list[dict[str, str]] = []
    totals = {"findings": 0, "component": 0, "project": 0, "wildcard": 0, "none": 0}

    for version in versions:
        project_uuid = str(version.get("project_uuid") or "")
        project = str(version.get("project") or "").strip() or project_uuid
        version_name = str(version.get("version") or "")
        findings = load_findings(project_uuid)
        bom = load_bom(project_uuid)
        if findings is None and not bom:
            missing.append({"project_uuid": project_uuid, "project": project, "version": version_name})
            continue
        findings = findings or []
        analysis = _VersionAnalysis(bom or {}, compiled, project)
        stats = project_stats.setdefault(
            project,
            {
                "name": project,
                "versions": [],
                "findings": 0,
                "unmapped": 0,
                "by_kind": defaultdict(int),
                "root": {
                    "name": analysis.root.get("name") or "",
                    "group": analysis.root.get("group") or "",
                    "purl": analysis.root.get("purl") or "",
                },
            },
        )
        stats["versions"].append({"uuid": project_uuid, "version": version_name})

        # Inventory: every component of the BOM, the root included.
        processor = analysis.processor
        top_level = {
            ref
            for ref in processor.comp_map
            if analysis.root_ref and analysis.root_ref in analysis.parents(ref)
        }
        for ref in processor.comp_map:
            name, group, purl = analysis.identity(ref)
            if not name and not purl:
                continue
            key = (project, _identity_key(name, group, purl))
            item = inventory.get(key)
            if item is None:
                item = inventory[key] = [name, group, purl_base(purl), 0, 0, 0]
                inventory_projects[key[1]].add(project)
                inventory_projects[_identity_key(name, "", "")].add(project)
            if ref == analysis.root_ref:
                item[5] |= FLAG_ROOT
            if ref in top_level:
                item[5] |= FLAG_TOP_LEVEL

        below: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for finding in findings:
            component_uuid = finding.get("uuid") or ""
            component_name = finding.get("name") or ""
            component_purl = finding.get("purl")
            kind, _tags, target_ref = processor.resolve_owner(
                component_uuid, component_name, component_purl
            )
            totals["findings"] += 1
            totals[kind] += 1
            stats["findings"] += 1
            stats["by_kind"][kind] += 1
            if kind == "component" or kind == "project":
                keys = processor.get_owner_mapping_keys(
                    component_uuid, component_name, component_purl
                )
            elif kind == "wildcard" and wildcard_key is not None:
                keys = [wildcard_key]
            else:
                keys = []
            for key in keys:
                entry = entry_stats.setdefault(key, {"findings": 0, "projects": {}})
                entry["findings"] += 1
                entry["projects"][project] = entry["projects"].get(project, 0) + 1

            unmapped = kind in ("wildcard", "none")
            if target_ref:
                counts = below[target_ref]
                counts[0] += 1
                counts[1] += 1 if unmapped else 0
            if not unmapped:
                continue
            stats["unmapped"] += 1
            root_row = roots.get(project.lower())
            if root_row is None:
                root_row = roots[project.lower()] = _Row(
                    kind="root",
                    name=project,
                    group=stats["root"]["group"],
                    purl=purl_base(stats["root"]["purl"]),
                )
            root_row.add(project, version_name)
            if target_ref:
                tops = analysis.topmost(target_ref)
                identities = [analysis.identity(ref) for ref in tops]
                in_bom = True
            else:
                identities = [
                    (component_name, str(finding.get("group") or ""), str(component_purl or ""))
                ]
                in_bom = False
            seen: set[tuple[str, str, str]] = set()
            for name, group, purl in identities:
                key = _identity_key(name, group, purl)
                if key in seen:
                    continue
                seen.add(key)
                row = components.get(key)
                if row is None:
                    row = components[key] = _Row(
                        kind="component",
                        name=name,
                        group=group,
                        purl=purl_base(purl),
                        in_bom=in_bom,
                    )
                row.add(project, version_name)

        for ref, (count, unmapped_count) in below.items():
            for ancestor in analysis.ancestors(ref):
                name, group, purl = analysis.identity(ancestor)
                item = inventory.get((project, _identity_key(name, group, purl)))
                if item is not None:
                    item[3] += count
                    item[4] += unmapped_count

    # The unmapped list, by findings.
    rows = sorted(
        list(roots.values()) + list(components.values()),
        key=lambda row: (-row.findings, row.kind != "root", row.name.lower()),
    )
    unmapped_rows = []
    for row in rows[:unmapped_limit]:
        suggested, reason = suggest_key(row, compiled, inventory_projects)
        unmapped_rows.append(
            {
                "kind": row.kind,
                "name": row.name,
                "group": row.group,
                "purl": row.purl,
                "in_bom": row.in_bom,
                "findings": row.findings,
                "projects": [
                    {
                        "name": name,
                        "findings": data["findings"],
                        "versions": sorted(data["versions"]),
                    }
                    for name, data in sorted(
                        row.projects.items(), key=lambda item: (-item[1]["findings"], item[0])
                    )
                ],
                "suggested_key": suggested,
                "suggestion_reason": reason,
            }
        )

    # The inventory, grouped by identity across projects; components with
    # findings below them first when it has to be cut.
    project_names = sorted(project_stats, key=str.lower)
    project_index = {name: index for index, name in enumerate(project_names)}
    grouped: dict[tuple[str, str, str], list[Any]] = {}
    for (project, key), (name, group, purl, below_count, unmapped_count, flags) in inventory.items():
        item = grouped.get(key)
        if item is None:
            item = grouped[key] = [name, group, purl, [], 0]
        item[3].append([project_index[project], below_count, unmapped_count, flags])
        item[4] += below_count
    ordered = sorted(grouped.values(), key=lambda item: (-item[4], item[0].lower(), item[1].lower(), item[2]))
    inventory_rows = [
        [name, group, purl, sorted(per_project)]
        for name, group, purl, per_project, _below in ordered[:inventory_limit]
    ]

    projects_payload = []
    for name in project_names:
        stats = project_stats[name]
        fallback = project_fallback_match(compiled, name)
        projects_payload.append(
            {
                "name": name,
                "versions": sorted(stats["versions"], key=lambda item: item["version"]),
                "findings": stats["findings"],
                "unmapped": stats["unmapped"],
                "owned_by": dict(stats["by_kind"]),
                "fallback_key": fallback.key if fallback else None,
                "root": stats["root"],
            }
        )

    return {
        "totals": {
            "versions": sum(len(item["versions"]) for item in projects_payload),
            "projects": len(projects_payload),
            "findings": totals["findings"],
            "owned_by_component": totals["component"],
            "owned_by_project": totals["project"],
            "unmapped": totals["wildcard"] + totals["none"],
        },
        "projects": projects_payload,
        "entries": {
            key: {
                "findings": data["findings"],
                "projects": [
                    {"name": name, "findings": count}
                    for name, count in sorted(data["projects"].items(), key=lambda item: (-item[1], item[0]))
                ],
            }
            for key, data in entry_stats.items()
        },
        "unmapped": unmapped_rows,
        "unmapped_total": len(rows),
        "near_duplicates": near_duplicate_disagreements(compiled),
        "missing_versions": missing,
        "inventory": {
            "projects": project_names,
            "components": inventory_rows,
            "total": len(grouped),
            "truncated": len(grouped) > inventory_limit,
        },
    }


def mapping_fingerprint(mapping: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(mapping or {}, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def slim_bom(bom: Any) -> dict[str, Any]:
    """A BOM with only what ownership needs: refs, names, groups, purls
    and the dependency graph; a fraction of the stored size."""
    if not isinstance(bom, dict):
        return {}

    def slim(component: Any) -> dict[str, Any]:
        component = component if isinstance(component, dict) else {}
        return {
            key: component[key]
            for key in ("bom-ref", "uuid", "name", "group", "purl")
            if component.get(key)
        }

    meta = ((bom.get("metadata") or {}).get("component")) or None
    return {
        "metadata": {"component": slim(meta)} if meta else {},
        "components": [slim(item) for item in bom.get("components") or [] if isinstance(item, dict)],
        "dependencies": [
            {"ref": item.get("ref"), "dependsOn": list(item.get("dependsOn") or [])}
            for item in bom.get("dependencies") or []
            if isinstance(item, dict)
        ],
    }


@dataclass
class VersionModel:
    """One version as the report, the tree and the preview read it."""

    project_uuid: str
    project: str
    version: str
    stamp: Any
    bom: dict[str, Any]
    findings: Optional[list[dict[str, Any]]]


def _owner_of_finding(processor: BOMAnalysisCache, finding: dict[str, Any]) -> str:
    kind, tags, _ref = processor.resolve_owner(
        finding.get("uuid") or "", finding.get("name") or "", finding.get("purl")
    )
    return tags[0] if tags else ""


def preview_mapping_change(
    current: dict[str, Any],
    draft: dict[str, Any],
    models: Iterable[VersionModel],
    *,
    wildcard_team: Optional[str] = None,
) -> dict[str, Any]:
    """How many findings change owner between two selector mappings, by
    (from team, to team) and by project. An empty team is no owner."""
    current_compiled = compile_team_mapping(current or {})
    draft_compiled = compile_team_mapping(draft or {})
    moves: dict[tuple[str, str], int] = defaultdict(int)
    projects: dict[str, int] = defaultdict(int)
    findings = 0
    for model in models:
        if not model.findings:
            continue
        before = BOMAnalysisCache(model.bom, current_compiled, model.project)
        after = BOMAnalysisCache(model.bom, draft_compiled, model.project)
        for finding in model.findings:
            findings += 1
            old, new = _owner_of_finding(before, finding), _owner_of_finding(after, finding)
            if old != new:
                moves[(old, new)] += 1
                projects[model.project] += 1
    return {
        "findings": findings,
        "changed": sum(moves.values()),
        "moves": [
            {"from": old, "to": new, "findings": count}
            for (old, new), count in sorted(moves.items(), key=lambda item: (-item[1], item[0]))
        ],
        "projects": [
            {"name": name, "changed": count}
            for name, count in sorted(projects.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


TREE_CHILD_LIMIT = 500


def _owner_resolver(analysis: _VersionAnalysis, compiled: tuple, project: str):
    """The owner of a node: the team and why (its own entry, inherited
    from mapped components above it, the project's entry, or ``*``)."""
    processor = analysis.processor
    fallback = project_fallback_match(compiled, project)
    wildcard = next((entry for entry in compiled if entry.selector.wildcard), None)

    def owner(node: str) -> dict[str, Any]:
        tags = processor._get_tags_for_ref(node)
        owners = processor.owner_refs_cache.get(node, ())
        if tags and node in owners:
            match = processor.get_owner_mapping_keys(node, processor._get_component_name(node))
            return {"team": tags[0], "kind": "component", "key": match[0] if match else None}
        if tags:
            keys = processor.get_owner_mapping_keys(node, processor._get_component_name(node))
            return {
                "team": tags[0],
                "kind": "inherited",
                "key": keys[0] if keys else None,
                "from": [processor._get_component_name(item) for item in owners],
            }
        if fallback is not None:
            return {"team": fallback.tags[0], "kind": "project", "key": fallback.key}
        if wildcard is not None:
            return {"team": wildcard.tags[0], "kind": "wildcard", "key": wildcard.key}
        return {"team": "", "kind": "none", "key": None}

    return owner


def version_tree(
    model: VersionModel,
    mapping: dict[str, Any],
    ref: Optional[str] = None,
    *,
    limit: int = TREE_CHILD_LIMIT,
    draft: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """The BOM tree of a version, one level at a time: the root (``ref``
    left out) or the children of ``ref``. Every node carries its finding
    counts (on it and below it, and how many of those no team owns) and
    its owner: the team and why (its own entry, inherited from mapped
    components above it, the project's entry, or ``*``). Components no
    dependency links to are listed under the root, marked ``unlinked``
    (flat BOMs).

    With ``draft`` (a selector mapping not saved yet) owners and counts
    are those of the draft, and a node whose owner differs under the saved
    ``mapping`` carries that one as ``saved_owner``."""
    saved_owner = None
    if draft is not None:
        saved_compiled = compile_team_mapping(mapping or {})
        saved_owner = _owner_resolver(
            _VersionAnalysis(model.bom, saved_compiled, model.project), saved_compiled, model.project
        )
        mapping = draft
    compiled = compile_team_mapping(mapping or {})
    analysis = _VersionAnalysis(model.bom, compiled, model.project)
    processor = analysis.processor
    root_ref = analysis.root_ref
    children: dict[str, list[str]] = defaultdict(list)
    for child, parents in processor.parent_map.items():
        for parent in dict.fromkeys(parents):
            children[parent].append(child)
    unlinked = [
        item
        for item in processor.comp_map
        if item != root_ref and not analysis.parents(item)
    ]

    here: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    loose = [0, 0]
    for finding in model.findings or []:
        kind, _tags, target = processor.resolve_owner(
            finding.get("uuid") or "", finding.get("name") or "", finding.get("purl")
        )
        unowned = 1 if kind in ("wildcard", "none") else 0
        if target:
            here[target][0] += 1
            here[target][1] += unowned
        else:
            loose[0] += 1
            loose[1] += unowned
    below: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for target, (count, unowned) in here.items():
        for ancestor in analysis.ancestors(target):
            below[ancestor][0] += count
            below[ancestor][1] += unowned
    owner = _owner_resolver(analysis, compiled, model.project)

    def node(item: str, *, is_unlinked: bool = False) -> dict[str, Any]:
        name, group, purl = analysis.identity(item)
        count = len(children.get(item, ())) + (len(unlinked) if item == root_ref else 0)
        result = {
            "ref": item,
            "name": name,
            "group": group,
            "purl": purl_base(purl),
            "root": item == root_ref,
            "unlinked": is_unlinked,
            "children": count,
            "findings_here": here[item][0] if item in here else 0,
            "findings": below[item][0] if item in below else 0,
            "unowned": below[item][1] if item in below else 0,
            "owner": owner(item),
        }
        if saved_owner is not None:
            before = saved_owner(item)
            if (before["team"], before["kind"]) != (result["owner"]["team"], result["owner"]["kind"]):
                result["saved_owner"] = before
        return result

    result: dict[str, Any] = {
        "project_uuid": model.project_uuid,
        "project": model.project,
        "version": model.version,
        "findings": len(model.findings or []),
        "findings_outside_bom": loose[0],
    }
    if ref is None:
        if root_ref is None:
            # No root: the unlinked components are the top.
            items = [node(item, is_unlinked=True) for item in unlinked]
            result["root"] = None
            result["nodes"] = items
        else:
            result["root"] = node(root_ref)
            return result
    else:
        if ref not in processor.comp_map:
            raise KeyError(ref)
        items = [node(item) for item in children.get(ref, ())]
        if ref == root_ref:
            items += [node(item, is_unlinked=True) for item in unlinked]
        result["parent"] = ref
    items.sort(key=lambda item: (-item["unowned"], -item["findings"], item["name"].lower()))
    result["total"] = len(items)
    result["nodes"] = items[:limit]
    return result


class TeamMappingReportService:
    """Builds the report in the background and keeps the last one, with
    the slim per-version models it was built from (``VersionModel``) for
    the tree and the preview.

    ``fingerprint`` describes the inputs (mapping, active versions and when
    their BOMs and findings were stored); a report is current while it is
    unchanged. A request never waits for a build: it gets the last report,
    marked stale, while the new one is built. A version's model is read
    again only when its BOM or findings were stored again.
    """

    def __init__(
        self,
        *,
        load_team_mapping: Callable[[], dict[str, Any]],
        list_versions: Callable[[], list[ReportVersion]],
        source_fingerprint: Callable[[list[ReportVersion]], Any],
        load_bom: Callable[[str], Optional[dict[str, Any]]],
        load_findings: Callable[[str], Optional[list[dict[str, Any]]]],
        run_in_thread: Callable[..., Awaitable[Any]] = asyncio.to_thread,
        create_task: Callable[[Awaitable[Any]], asyncio.Task] = asyncio.create_task,
    ) -> None:
        self._load_team_mapping = load_team_mapping
        self._list_versions = list_versions
        self._source_fingerprint = source_fingerprint
        self._load_bom = load_bom
        self._load_findings = load_findings
        self._run_in_thread = run_in_thread
        self._create_task = create_task
        self._lock = threading.Lock()
        self._models_lock = threading.Lock()
        self._models: dict[str, VersionModel] = {}
        self._report: Optional[dict[str, Any]] = None
        self._report_fingerprint: Optional[str] = None
        self._built_at: Optional[str] = None
        self._building: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._error: Optional[tuple[str, str]] = None  # (fingerprint, message)

    def _inputs(self) -> tuple[str, dict[str, Any], list[ReportVersion], list[Any]]:
        mapping = self._load_team_mapping() or {}
        versions = self._list_versions()
        stamps = self._source_fingerprint(versions)
        if not isinstance(stamps, list) or len(stamps) != len(versions):
            stamps = [stamps] * len(versions)
        digest = hashlib.sha256(
            json.dumps(
                [mapping_fingerprint(mapping), versions, stamps],
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        return digest, mapping, versions, stamps

    def _models_for(self, versions: list[ReportVersion], stamps: list[Any]) -> list[VersionModel]:
        """The models of these versions; read again where the stamp changed.
        Models of versions no longer listed are dropped."""
        models: list[VersionModel] = []
        with self._models_lock:
            wanted = {str(version.get("project_uuid") or "") for version in versions}
            for uuid in [uuid for uuid in self._models if uuid not in wanted]:
                del self._models[uuid]
            for version, stamp in zip(versions, stamps):
                uuid = str(version.get("project_uuid") or "")
                model = self._models.get(uuid)
                stamp_text = json.dumps(stamp, sort_keys=True, default=str)
                if model is None or model.stamp != stamp_text:
                    model = VersionModel(
                        project_uuid=uuid,
                        project=str(version.get("project") or "").strip() or uuid,
                        version=str(version.get("version") or ""),
                        stamp=stamp_text,
                        bom=slim_bom(self._load_bom(uuid)),
                        findings=self._load_findings(uuid),
                    )
                    self._models[uuid] = model
                models.append(model)
        return models

    def _build(
        self,
        fingerprint: str,
        mapping: dict[str, Any],
        versions: list[ReportVersion],
        stamps: list[Any],
    ) -> None:
        try:
            models = {model.project_uuid: model for model in self._models_for(versions, stamps)}
            report = build_mapping_report(
                mapping,
                versions,
                lambda uuid: models[uuid].bom if uuid in models else None,
                lambda uuid: models[uuid].findings if uuid in models else None,
            )
        except Exception as exc:  # reported to the client, kept for this input
            logger.exception("Team mapping report failed")
            with self._lock:
                self._error = (fingerprint, str(exc) or exc.__class__.__name__)
                self._building = None
            return
        with self._lock:
            self._report = report
            self._report_fingerprint = fingerprint
            self._built_at = datetime.now(timezone.utc).isoformat()
            self._building = None
            self._error = None

    async def current(self, *, refresh: bool = False) -> dict[str, Any]:
        """The report for the current inputs, or the last one while that is
        built. ``refresh`` builds again even when nothing changed."""
        fingerprint, mapping, versions, stamps = await self._run_in_thread(self._inputs)
        if refresh:
            with self._models_lock:
                self._models.clear()
        with self._lock:
            ready = self._report_fingerprint == fingerprint and not refresh
            failed = self._error is not None and self._error[0] == fingerprint and not refresh
            start = not ready and not failed and self._building is None
            if start:
                self._building = fingerprint
                self._error = None
        if start:
            self._task = self._create_task(
                self._run_in_thread(self._build, fingerprint, mapping, versions, stamps)
            )
        with self._lock:
            if ready:
                status = "ready"
            elif failed:
                status = "failed"
            else:
                status = "building"
            return {
                "status": status,
                "stale": self._report is not None and self._report_fingerprint != fingerprint,
                "built_at": self._built_at,
                "error": self._error[1] if self._error else None,
                "report": self._report,
            }

    def _tree(
        self, project_uuid: str, ref: Optional[str], draft: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        _fingerprint, mapping, versions, stamps = self._inputs()
        for version, stamp in zip(versions, stamps):
            if str(version.get("project_uuid") or "") == project_uuid:
                model = self._model(version, stamp)
                return version_tree(model, mapping, ref, draft=draft)
        raise LookupError(project_uuid)

    def _model(self, version: ReportVersion, stamp: Any) -> VersionModel:
        """The model of one version, read when missing or outdated."""
        uuid = str(version.get("project_uuid") or "")
        with self._models_lock:
            model = self._models.get(uuid)
            if model is not None and model.stamp == json.dumps(stamp, sort_keys=True, default=str):
                return model
        return self._load_one(version, stamp)

    def _load_one(self, version: ReportVersion, stamp: Any) -> VersionModel:
        uuid = str(version.get("project_uuid") or "")
        model = VersionModel(
            project_uuid=uuid,
            project=str(version.get("project") or "").strip() or uuid,
            version=str(version.get("version") or ""),
            stamp=json.dumps(stamp, sort_keys=True, default=str),
            bom=slim_bom(self._load_bom(uuid)),
            findings=self._load_findings(uuid),
        )
        with self._models_lock:
            self._models[uuid] = model
        return model

    async def tree(
        self,
        project_uuid: str,
        ref: Optional[str] = None,
        draft: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """One level of a version's BOM tree with owners and finding counts
        (``version_tree``), with the saved mapping or a ``draft`` selector
        mapping. Raises ``LookupError`` for a version not active,
        ``KeyError`` for an unknown ref."""
        return await self._run_in_thread(self._tree, project_uuid, ref, draft)

    def _preview(self, draft: dict[str, Any], projects: Optional[list[str]]) -> dict[str, Any]:
        _fingerprint, mapping, versions, stamps = self._inputs()
        if projects:
            wanted = {name.strip().lower() for name in projects}
            pairs = [
                (version, stamp)
                for version, stamp in zip(versions, stamps)
                if str(version.get("project") or "").strip().lower() in wanted
            ]
        else:
            pairs = list(zip(versions, stamps))
        models = [self._model(version, stamp) for version, stamp in pairs]
        return preview_mapping_change(mapping, draft, models)

    async def preview(
        self, draft: dict[str, Any], projects: Optional[list[str]] = None
    ) -> dict[str, Any]:
        """Findings that change owner from the saved selector mapping to
        ``draft`` (``preview_mapping_change``), in all active versions or
        those of ``projects``."""
        return await self._run_in_thread(self._preview, draft, projects)


def active_versions(cache_manager: Any) -> list[ReportVersion]:
    """The versions active in the source (``sync_versions.active_in_dt``,
    not gone); the stored project list when the sync state lists none."""
    rows: list[dict[str, Any]] = []
    sync_state = getattr(cache_manager, "sync_state", None)
    if sync_state is not None:
        rows = sync_state.list_versions()
    if rows:
        return [
            {
                "project_uuid": row["project_uuid"],
                "project": row.get("product_name") or "",
                "version": row.get("version") or "",
            }
            for row in rows
            if row.get("active_in_dt") and row.get("status") != "gone"
        ]
    return [
        {
            "project_uuid": project.get("uuid"),
            "project": project.get("name") or "",
            "version": project.get("version") or "",
        }
        for project in cache_manager.get_cached_project_versions()
        if project.get("uuid")
    ]


def create_report_service(
    cache_manager: Any,
    load_team_mapping: Callable[[], dict[str, Any]],
) -> TeamMappingReportService:
    """The report service over the cache manager's local store."""
    from .local_store import KIND_BOM, KIND_FINDINGS, MISSING, DocumentRef

    def source_fingerprint(versions: list[ReportVersion]) -> Any:
        store = cache_manager.store
        boms = store.bom_times()
        findings = store.snapshot_times(KIND_FINDINGS)
        return [
            (version["project_uuid"], boms.get(version["project_uuid"]), findings.get(version["project_uuid"]))
            for version in versions
        ]

    def load_bom(project_uuid: str) -> Optional[dict[str, Any]]:
        value = cache_manager.store.read(DocumentRef(KIND_BOM, project_uuid))
        return value if isinstance(value, dict) and value is not MISSING else None

    return TeamMappingReportService(
        load_team_mapping=load_team_mapping,
        list_versions=lambda: active_versions(cache_manager),
        source_fingerprint=source_fingerprint,
        load_bom=load_bom,
        load_findings=lambda project_uuid: cache_manager.store.finding_components(project_uuid),
    )
