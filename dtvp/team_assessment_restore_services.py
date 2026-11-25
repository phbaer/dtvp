"""Team assessments read back from a Dependency-Track export.

Dependency-Track keeps the text River wrote into each analysis, team blocks
included. When a block was lost in River, a CycloneDX VDR that
Dependency-Track exported before the loss still has it. This module reads
such an export, matches its entries to River's findings, and works out which
team blocks a finding has today in no form. Those come back as historical
blocks: the record keeps them, and no state changes (ADR 0003).

Everything here is pure: no I/O, no clock. The uploaded export is held in
memory by ``RestoreSourceStore`` only.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .assessment_model import (
    FORMER_TEAM_NOTE,
    SEE_GLOBAL_ASSESSMENT,
    render_assessment,
    team_from_block,
)
from .grouped_vuln_services import _normalize_group_tags
from .logic import _deduplicate_assessment_blocks, parse_assessment_blocks

TEAM_RESTORE_MAX_UPLOAD_BYTES = 128 * 1024 * 1024
SOURCE_KIND_DEPENDENCY_TRACK_VDR = "dependency-track-vdr"
# The texts each finding held over time, read from the source
# (``ports.AssessmentHistorySource``); same workflow, another input.
HISTORY_TOOL = "Assessment history"
SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")
DTVP_EXPORT_MESSAGE = (
    "This is a River export; restoring needs a Dependency-Track export."
)

MATCH_UUID = "uuid"
MATCH_PURL = "purl"
MATCH_NAME_VERSION = "name_version"
MATCH_PROJECT_NAME_VERSION = "project_name_version"

UNMATCHED_NO_FINDING = "no_finding_in_view"
UNMATCHED_AMBIGUOUS = "ambiguous"
UNMATCHED_OTHER_PROJECT = "other_project"
UNMATCHED_REASONS = (UNMATCHED_NO_FINDING, UNMATCHED_AMBIGUOUS, UNMATCHED_OTHER_PROJECT)

SKIP_PRESENT = "present"
SKIP_EMPTY = "empty"
SKIP_REFERENCE = "reference"
SKIP_GENERAL = "general"

NOTE_PRESENT_TICKET_MISSING = "present_ticket_missing"
NOTE_COPIED_FROM = "copied_from"

# The decision list of a note: everything up to the last ")" of the line
# that is followed by ":" or "." (team names can hold ")" themselves).
_FORMER_NOTE = re.compile(rf"{re.escape(FORMER_TEAM_NOTE)} \((.*)\)[:.]")
_PENDING_TAIL = re.compile(r"\s*\[Status: Pending Review\]\s*$", re.IGNORECASE)


class RestoreSourceError(ValueError):
    """An upload that cannot be read as a Dependency-Track VDR."""


@dataclass(frozen=True)
class RestoreEntry:
    """One affected component of one vulnerability of the export."""

    vuln_id: str
    vuln_ref: str
    component_ref: str
    component: dict[str, str]
    analysis_state: str
    # Team fields (``team_from_block``): one live block per team name, and
    # every distinct historical block of the team.
    blocks: tuple[dict[str, Any], ...]
    # Set for entries read per finding from a history: the finding's
    # project UUID. Such an entry matches its exact finding only.
    project_ref: str = ""


@dataclass(frozen=True)
class RestoreSource:
    spec_version: str
    tool: str
    tool_version: str
    project_uuid: str
    project_name: str
    project_version: str
    timestamp: str
    serial_number: str
    sha256: str
    warnings: tuple[str, ...]
    entries: tuple[RestoreEntry, ...]
    # Vulnerabilities with an analysis text.
    analyses: int
    # Of those, texts without any team block.
    no_team_blocks: int
    team_blocks: int

    def summary(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "spec_version": self.spec_version,
            "project_uuid": self.project_uuid,
            "project_name": self.project_name,
            "project_version": self.project_version,
            "timestamp": self.timestamp,
            "serial_number": self.serial_number,
            "sha256": self.sha256,
            "warnings": list(self.warnings),
            "analyses": self.analyses,
            "no_team_blocks": self.no_team_blocks,
        }


# -- reading the export -------------------------------------------------------


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def _first_tool(tools: Any) -> tuple[str, str]:
    candidates: list[Any] = []
    if isinstance(tools, list):
        candidates = tools
    elif isinstance(tools, dict):
        candidates = [
            *(tools.get("components") or []),
            *(tools.get("services") or []),
        ]
    for tool in candidates:
        if isinstance(tool, dict) and _text(tool.get("name")):
            return _text(tool.get("name")), _text(tool.get("version"))
    return "", ""


def _is_dtvp_export(metadata: dict[str, Any]) -> bool:
    for item in metadata.get("properties") or []:
        name = _text(item.get("name")) if isinstance(item, dict) else ""
        if name.endswith(":export_property_prefix") or name.endswith(":export"):
            return True
    return False


def _component_index(components: Any) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    pending = list(components or []) if isinstance(components, list) else []
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        ref = _text(component.get("bom-ref"))
        if ref:
            index[ref] = {
                key: _text(component.get(key))
                for key in ("purl", "group", "name", "version")
            }
        nested = component.get("components")
        if isinstance(nested, list):
            pending.extend(nested)
    return index


def _source_blocks(detail: str) -> list[dict[str, Any]]:
    """The team blocks of an analysis text as River reads such a text: per
    team name the newest live block (by ``Date``, then the longer text),
    and every distinct historical block."""
    _shared, blocks = parse_assessment_blocks(detail)
    return [team_from_block(block) for block in _deduplicate_assessment_blocks(blocks)]


def read_dependency_track_vdr(content: bytes) -> RestoreSource:
    """The entries and team blocks of a CycloneDX VDR of Dependency-Track.

    Raises ``RestoreSourceError`` for anything else, River's own export
    included: that one carries the rationale, not the team blocks.
    """
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RestoreSourceError("The file is not JSON.") from exc
    if not isinstance(document, dict):
        raise RestoreSourceError("The file is not a CycloneDX document.")
    if document.get("bomFormat") != "CycloneDX":
        raise RestoreSourceError("The file is not a CycloneDX document.")
    spec_version = _text(document.get("specVersion"))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise RestoreSourceError(
            f"CycloneDX {spec_version or '(no version)'} is not supported; "
            f"expected {', '.join(SUPPORTED_SPEC_VERSIONS)}."
        )
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise RestoreSourceError("The document has no vulnerabilities.")
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    if _is_dtvp_export(metadata):
        raise RestoreSourceError(DTVP_EXPORT_MESSAGE)

    warnings: list[str] = []
    tool, tool_version = _first_tool(metadata.get("tools"))
    if tool != "Dependency-Track":
        warnings.append(
            f"The document was written by {tool or 'an unnamed tool'}, "
            "not Dependency-Track."
        )
    project = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    project_uuid = _text(project.get("bom-ref"))
    if not project_uuid:
        warnings.append("The document names no project; no finding can match it.")

    components = _component_index(document.get("components"))
    entries: list[RestoreEntry] = []
    analyses = 0
    no_team_blocks = 0
    team_blocks = 0
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        analysis = vulnerability.get("analysis")
        if not isinstance(analysis, dict):
            continue
        detail = analysis.get("detail")
        if not isinstance(detail, str) or not detail.strip():
            continue
        analyses += 1
        blocks = tuple(_source_blocks(detail))
        if not blocks:
            no_team_blocks += 1
        team_blocks += len(blocks)
        for affected in vulnerability.get("affects") or []:
            ref = _text(affected.get("ref")) if isinstance(affected, dict) else ""
            if not ref:
                continue
            entries.append(
                RestoreEntry(
                    vuln_id=_text(vulnerability.get("id")),
                    vuln_ref=_text(vulnerability.get("bom-ref")),
                    component_ref=ref,
                    component=dict(
                        components.get(ref)
                        or {"purl": "", "group": "", "name": "", "version": ""}
                    ),
                    analysis_state=_text(analysis.get("state")),
                    blocks=blocks,
                )
            )

    return RestoreSource(
        spec_version=spec_version,
        tool=tool,
        tool_version=tool_version,
        project_uuid=project_uuid,
        project_name=_text(project.get("name")),
        project_version=_text(project.get("version")),
        timestamp=_text(metadata.get("timestamp")),
        serial_number=_text(document.get("serialNumber")),
        sha256=hashlib.sha256(content).hexdigest(),
        warnings=tuple(warnings),
        entries=tuple(entries),
        analyses=analyses,
        no_team_blocks=no_team_blocks,
        team_blocks=team_blocks,
    )


# -- reading the source's history ---------------------------------------------


def history_blocks(texts: list[str]) -> tuple[dict[str, Any], ...]:
    """The team blocks of all texts a finding held, read as one text would
    be: per team the newest live block (by ``Date``, then the longer text),
    and every distinct historical block."""
    blocks = []
    for text in texts:
        if isinstance(text, str) and text.strip():
            blocks.extend(parse_assessment_blocks(text)[1])
    return tuple(team_from_block(block) for block in _deduplicate_assessment_blocks(blocks))


def read_assessment_history(
    histories: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    *,
    read_at: str,
    failed: int = 0,
) -> RestoreSource:
    """A restore source from the history of each finding.

    ``histories`` pairs a finding (its UUIDs, ids and component) with the
    texts the source recorded for it (``AssessmentHistorySource``). Only
    the team blocks of those texts count; a person decides on each one.
    """
    entries: list[RestoreEntry] = []
    analyses = no_team_blocks = team_blocks = 0
    digest = hashlib.sha256()
    for instance, history in histories:
        texts = [str(item.get("details") or "") for item in history if isinstance(item, dict)]
        texts = [text for text in texts if text.strip()]
        if not texts:
            continue
        analyses += 1
        blocks = history_blocks(texts)
        if not blocks:
            no_team_blocks += 1
        team_blocks += len(blocks)
        key = (
            str(instance.get("project_uuid") or ""),
            str(instance.get("component_uuid") or ""),
            str(instance.get("vulnerability_uuid") or ""),
        )
        digest.update(json.dumps([key, texts], ensure_ascii=False).encode("utf-8"))
        entries.append(RestoreEntry(
            vuln_id=str(instance.get("vuln_id") or ""),
            vuln_ref=key[2],
            component_ref=key[1],
            component={
                "purl": str(instance.get("component_purl") or ""),
                "group": str(instance.get("component_group") or ""),
                "name": str(instance.get("component_name") or ""),
                "version": str(instance.get("component_version") or ""),
            },
            analysis_state="",
            blocks=blocks,
            project_ref=key[0],
        ))
    warnings = (
        (f"The history of {failed} finding{'s' if failed != 1 else ''} could not be read.",)
        if failed else ()
    )
    return RestoreSource(
        spec_version="",
        tool=HISTORY_TOOL,
        tool_version="",
        project_uuid="",
        project_name="",
        project_version="",
        timestamp=read_at,
        serial_number="",
        sha256=digest.hexdigest(),
        warnings=warnings,
        entries=tuple(entries),
        analyses=analyses,
        no_team_blocks=no_team_blocks,
        team_blocks=team_blocks,
    )


# -- matching entries to findings ---------------------------------------------


@dataclass
class RestoreMatch:
    entry: RestoreEntry
    group: dict[str, Any]
    instance: dict[str, Any]
    match: str
    # The matching level, also when ``match`` names the project fallback.
    level: str = MATCH_UUID


@dataclass
class RestoreUnmatched:
    entry: RestoreEntry
    reason: str
    candidates: int = 0


def _instances(groups: list[dict[str, Any]]):
    for group in groups:
        for version in group.get("affected_versions") or []:
            for instance in version.get("components") or []:
                if isinstance(instance, dict):
                    yield group, instance


def _vuln_keys(group: dict[str, Any], instance: dict[str, Any]) -> set[str]:
    values = [group.get("id"), *(group.get("aliases") or []), instance.get("vulnerability_uuid")]
    return {str(value).strip().upper() for value in values if str(value or "").strip()}


def _name_version(group: Any, name: Any, version: Any) -> str:
    # Case-sensitive, as the export's own component lookup.
    return f"{group or ''}|{name or ''}|{version or ''}"


def match_entries(
    source: RestoreSource,
    groups: list[dict[str, Any]],
    team_mapping: dict[str, Any] | None = None,
) -> tuple[list[RestoreMatch], list[RestoreUnmatched]]:
    """Each entry's finding among ``groups``, or the reason it has none.

    Projects match by UUID, else by name and version (a project created
    again). Within the project, a finding matches by component and
    vulnerability UUID, then by package URL, then by group, name and
    version, each with any id or alias of the vulnerability. A level with
    more than one candidate is ambiguous; nothing is guessed.
    """
    del team_mapping  # matching does not depend on teams
    instances = list(_instances(groups))
    if any(entry.project_ref for entry in source.entries):
        return _match_exact(source, instances)
    project_match = MATCH_UUID
    in_project = [
        (group, instance) for group, instance in instances
        if source.project_uuid and instance.get("project_uuid") == source.project_uuid
    ]
    if not in_project and (source.project_name or source.project_version):
        in_project = [
            (group, instance) for group, instance in instances
            if (str(instance.get("project_name") or ""), str(instance.get("project_version") or ""))
            == (source.project_name, source.project_version)
        ]
        project_match = MATCH_PROJECT_NAME_VERSION
    if not in_project:
        return [], [
            RestoreUnmatched(entry, UNMATCHED_OTHER_PROJECT)
            for entry in source.entries if entry.blocks
        ]

    by_uuid: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    by_purl: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    by_name: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    for group, instance in in_project:
        pair = (group, instance)
        by_uuid.setdefault(
            (str(instance.get("component_uuid") or ""), str(instance.get("vulnerability_uuid") or "")),
            [],
        ).append(pair)
        purl = str(instance.get("component_purl") or "").strip()
        name = str(instance.get("component_name") or "").strip()
        for key in _vuln_keys(group, instance):
            if purl:
                by_purl.setdefault((key, purl), []).append(pair)
            if name:
                by_name.setdefault(
                    (key, _name_version(
                        instance.get("component_group"), name, instance.get("component_version")
                    )),
                    [],
                ).append(pair)

    def distinct(pairs: list[tuple[dict, dict]]) -> list[tuple[dict, dict]]:
        seen: dict[int, tuple[dict, dict]] = {}
        for pair in pairs:
            seen.setdefault(id(pair[1]), pair)
        return list(seen.values())

    found: list[RestoreMatch] = []
    unmatched: list[RestoreUnmatched] = []
    for entry in source.entries:
        if not entry.blocks:
            continue
        keys = {value.upper() for value in (entry.vuln_ref, entry.vuln_id) if value}
        purl = entry.component.get("purl") or ""
        name = entry.component.get("name") or ""
        levels = [
            (MATCH_UUID, by_uuid.get((entry.component_ref, entry.vuln_ref), [])),
            (MATCH_PURL, [p for key in keys for p in by_purl.get((key, purl), [])] if purl else []),
            (
                MATCH_NAME_VERSION,
                [
                    p for key in keys
                    for p in by_name.get(
                        (key, _name_version(entry.component.get("group"), name, entry.component.get("version"))),
                        [],
                    )
                ] if name else [],
            ),
        ]
        result: RestoreMatch | RestoreUnmatched = RestoreUnmatched(entry, UNMATCHED_NO_FINDING)
        for level, pairs in levels:
            candidates = distinct(pairs)
            if len(candidates) > 1:
                result = RestoreUnmatched(entry, UNMATCHED_AMBIGUOUS, len(candidates))
                break
            if candidates:
                group, instance = candidates[0]
                label = MATCH_PROJECT_NAME_VERSION if project_match != MATCH_UUID else level
                result = RestoreMatch(entry, group, instance, label, level)
                break
        if isinstance(result, RestoreMatch):
            found.append(result)
        else:
            unmatched.append(result)

    # One finding, more than one entry: only an exact UUID match decides.
    by_finding: dict[int, list[RestoreMatch]] = {}
    for item in found:
        by_finding.setdefault(id(item.instance), []).append(item)
    matches: list[RestoreMatch] = []
    for item in found:
        claims = by_finding[id(item.instance)]
        if len(claims) == 1:
            matches.append(item)
            continue
        exact = [claim for claim in claims if claim.level == MATCH_UUID]
        if len(exact) == 1 and exact[0] is item:
            matches.append(item)
        else:
            # The other claims on a finding an exact match decided, or all
            # claims when none is exact.
            unmatched.append(RestoreUnmatched(item.entry, UNMATCHED_AMBIGUOUS, len(claims)))
    return matches, unmatched


def _match_exact(
    source: RestoreSource,
    instances: list[tuple[dict[str, Any], dict[str, Any]]],
) -> tuple[list[RestoreMatch], list[RestoreUnmatched]]:
    """Entries read per finding: each matches its own finding, by UUIDs."""
    by_key = {
        (
            str(instance.get("project_uuid") or ""),
            str(instance.get("component_uuid") or ""),
            str(instance.get("vulnerability_uuid") or ""),
        ): (group, instance)
        for group, instance in instances
    }
    matches: list[RestoreMatch] = []
    unmatched: list[RestoreUnmatched] = []
    for entry in source.entries:
        if not entry.blocks:
            continue
        pair = by_key.get((entry.project_ref, entry.component_ref, entry.vuln_ref))
        if pair is None:
            unmatched.append(RestoreUnmatched(entry, UNMATCHED_NO_FINDING))
        else:
            matches.append(RestoreMatch(entry, pair[0], pair[1], MATCH_UUID))
    return matches, unmatched


# -- which blocks a finding lacks ---------------------------------------------


def _team_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def canonical_team_key(team: str, team_mapping: dict[str, Any] | None) -> str:
    """A team name with its aliases folded in, as the repair compares them."""
    return _team_key((_normalize_group_tags([team], team_mapping or {}) or [team])[0])


def former_note_decisions(text: str) -> list[str]:
    """The decision lists of the ``Former team assessment (...)`` notes of a
    text, as Repair Assessments writes them: ``teams; STATE; ...`` per
    decision, decisions separated by `` | ``, teams by ``, ``."""
    return [match.group(1) for match in _FORMER_NOTE.finditer(text or "")]


def _note_names_team(decisions: str, name: str) -> bool:
    """Whether a note's decision list names ``name`` as one of the teams.

    The name is matched as a literal, never split out of the free text: a
    team name can hold ``)``, ``, `` or `` | `` itself. It names a team when
    it starts a decision or follows another team (``, ``), and is followed by
    another team (``, ``) or the end of the team list (``; ``).
    """
    if not name:
        return False
    pattern = rf"(?:^| \| )(?:(?:(?!; ).)*?, )?{re.escape(name)}(?=, |; )"
    return re.search(pattern, decisions, re.IGNORECASE) is not None


def _team_names(team: str, team_mapping: dict[str, Any] | None) -> set[str]:
    """``team`` and every name the mapping gives the same team."""
    key = canonical_team_key(team, team_mapping)
    names = {team.strip()}
    for value in (team_mapping or {}).values():
        values = value if isinstance(value, list) else [value]
        for name in values:
            text = str(name or "").strip()
            if text and canonical_team_key(text, team_mapping) == key:
                names.add(text)
    return {name for name in names if name}


def ticket_keys(value: Any) -> list[str]:
    return list(dict.fromkeys(
        key for key in (part.strip() for part in str(value or "").split(",")) if key
    ))


def _names_ticket(text: str, key: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(key)}(?![\w-])", text or "") is not None


def _is_empty(block: dict[str, Any]) -> bool:
    return (
        str(block.get("state") or "NOT_SET") == "NOT_SET"
        and not str(block.get("details") or "").strip()
        and not block.get("ticket")
    )


def _is_reference(block: dict[str, Any]) -> bool:
    return (
        " ".join(str(block.get("details") or "").split()).casefold()
        == SEE_GLOBAL_ASSESSMENT.casefold()
        and not block.get("ticket")
    )


def missing_blocks(
    instance_details: str,
    source_blocks: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    team_mapping: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The source blocks a finding has in no form, and what was left out.

    A team is there when the current text has a block of it (live or
    historical, under the team's name or an alias) or a former-team note
    naming it. A live block that only refers to the global assessment or is
    an empty placeholder (no state, text or ticket) does not count. The comparison is by team: what a finding has of a team in
    any form already records it. Returns ``(to_restore, report)``;
    ``report`` counts what was skipped (``present``, ``empty``,
    ``reference``, ``general``) and lists informational ``notes``, which
    are never written.
    """
    text = str(instance_details or "")
    _shared, current = parse_assessment_blocks(text)
    # A reference to the global assessment or an empty placeholder records
    # nothing of a team's assessment: it does not make the team present.
    present_keys = {
        canonical_team_key(block.get("team") or "", team_mapping)
        for block in current
        if block.get("historical") or not (_is_empty(block) or _is_reference(block))
    }
    notes = former_note_decisions(text)
    copied_keys = {
        canonical_team_key(block["copied_from"], team_mapping): block.get("team")
        for block in current
        if block.get("copied_from") and not block.get("historical")
    }
    report: dict[str, Any] = {
        SKIP_PRESENT: 0, SKIP_EMPTY: 0, SKIP_REFERENCE: 0, SKIP_GENERAL: 0, "notes": [],
    }
    to_restore: list[dict[str, Any]] = []
    for block in source_blocks:
        team = str(block.get("team") or "")
        key = canonical_team_key(team, team_mapping)
        if not key:
            continue
        if key == "general":
            # The finding's own decision, never a historical team's: a
            # historical General block would still be read as General.
            report[SKIP_GENERAL] += 1
            continue
        if _is_empty(block):
            report[SKIP_EMPTY] += 1
            continue
        if _is_reference(block):
            report[SKIP_REFERENCE] += 1
            continue
        noted = bool(notes) and any(
            _note_names_team(decisions, name)
            for decisions in notes
            for name in _team_names(team, team_mapping)
        )
        if key in present_keys or noted:
            report[SKIP_PRESENT] += 1
            missing = [ticket for ticket in ticket_keys(block.get("ticket")) if not _names_ticket(text, ticket)]
            if missing:
                report["notes"].append({
                    "kind": NOTE_PRESENT_TICKET_MISSING, "team": team, "tickets": missing,
                })
            continue
        if key in copied_keys:
            report["notes"].append({
                "kind": NOTE_COPIED_FROM, "team": team, "copied_to": copied_keys[key],
            })
        to_restore.append(block)
    return to_restore, report


def restored_block(fields: dict[str, Any]) -> dict[str, Any]:
    """A source team block as it is restored: historical, without assignees.

    Everything else is kept as the export has it. A block without a date
    stays undated; neither the export time nor the time of restoring is a
    date of the assessment.
    """
    assessed_by = fields.get("assessed_by")
    return {
        **fields,
        "assessed_by": None if assessed_by in (None, "", "unknown") else assessed_by,
        "assessed_at_ms": fields.get("assessed_at_ms") or None,
        "historical": True,
        "assigned": [],
    }


def _date_order(block: dict[str, Any]) -> tuple[int, int]:
    moment = block.get("assessed_at_ms")
    return (0, int(moment)) if moment else (1, 0)


def render_restored_block(block: dict[str, Any]) -> str:
    """One team block as text; its values cannot open another block."""
    return render_assessment({"teams": [block]})


def append_blocks(details: str, blocks: list[dict[str, Any]]) -> str:
    """``details`` with ``blocks`` after its last block.

    Everything already there stays as it is, byte for byte: the rescoring,
    the response and free text ahead of the blocks, the SSVC record, and a
    trailing pending-review marker, which stays last. The added blocks are
    ordered by date, oldest first, undated last.
    """
    if not blocks:
        return details
    text = str(details or "")
    rendered = "\n\n".join(
        render_restored_block(block) for block in sorted(blocks, key=_date_order)
    )
    pending = _PENDING_TAIL.search(text)
    head, tail = (text[: pending.start()], text[pending.start():]) if pending else (text, "")
    head = head.rstrip()
    combined = f"{head}\n\n{rendered}" if head else rendered
    if tail:
        combined += tail if tail.startswith("\n") else f"\n\n{tail.lstrip()}"
    return combined


# -- holding uploads ----------------------------------------------------------


@dataclass
class _StoredSource:
    owner: str
    created_at: float
    source: RestoreSource


@dataclass
class RestoreSourceStore:
    """Uploaded exports, in memory only and per user.

    Keys are random. A user keeps up to ``per_user`` uploads (the oldest goes
    first); an upload expires after ``ttl_seconds``. Nothing is written to
    disk or logged: after a restart the file is uploaded again.
    """

    per_user: int = 4
    ttl_seconds: float = 6 * 60 * 60
    clock: Any = time.monotonic
    _entries: dict[str, _StoredSource] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _expire(self, now: float) -> None:
        for key in [
            key for key, item in self._entries.items()
            if now - item.created_at > self.ttl_seconds
        ]:
            del self._entries[key]

    def put(self, owner: str, source: RestoreSource) -> str:
        with self._lock:
            now = self.clock()
            self._expire(now)
            own = sorted(
                (item.created_at, key) for key, item in self._entries.items()
                if item.owner == owner
            )
            while len(own) >= self.per_user:
                _created, key = own.pop(0)
                del self._entries[key]
            key = str(uuid.uuid4())
            self._entries[key] = _StoredSource(owner, now, source)
            return key

    def get(self, owner: str, source_id: str) -> RestoreSource | None:
        with self._lock:
            self._expire(self.clock())
            item = self._entries.get(str(source_id or ""))
            if item is None or item.owner != owner:
                return None
            return item.source
