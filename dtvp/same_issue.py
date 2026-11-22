"""Findings that are probably the same issue under two ids no source links.

Some vulnerabilities are recorded twice, for example as a CVE (from NVD) and
as a GitHub advisory, without either record naming the other as an alias.
DTVP can only guess that they are one issue: from the same description, or,
failing that, from the same affected version range and the same CWE, on the
same component. Such a guess is shown as "probably the same as <id>", never
as an alias and never exported as one; a person confirms it before anything
is applied, and only a confirmed match is exported (``<prefix>:same_issue_as``).

Everything here is a pure function over what DTVP stores: the vulnerability
records and findings (read through the source adapter's
``VulnerabilityFacts``), the stored version ranges, and the finding rows.
See docs/review-workflows.md, "Gone findings".
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Mapping, Optional

from .fixed_versions import compare_versions, range_contains, range_text

REASON_DESCRIPTION = "same description"
REASON_RANGE_AND_CWE = "same affected range and CWE"

# A description this short says too little to tell two issues apart.
MIN_DESCRIPTION_LENGTH = 40

_ID_PATTERN = re.compile(
    r"\b(?:CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}|[A-Z][A-Z0-9]+-\d{4}-[0-9A-Z-]+)\b",
    re.IGNORECASE,
)
_NON_WORD = re.compile(r"[^0-9a-z]+")


def description_key(text: Any, ids: Iterable[str] = ()) -> Optional[str]:
    """A description reduced to what two records of one issue share: lower
    case, ids removed (its own and any vulnerability id), punctuation and
    whitespace collapsed. ``None`` when too short to compare."""
    value = str(text or "")
    for own in ids:
        if own:
            value = re.sub(re.escape(str(own)), " ", value, flags=re.IGNORECASE)
    value = _ID_PATTERN.sub(" ", value)
    value = _NON_WORD.sub(" ", value.lower()).strip()
    return value if len(value) >= MIN_DESCRIPTION_LENGTH else None


def facts_by_uuid(
    facts_of: Callable[[Any], Optional[Mapping[str, Any]]], *sources: Iterable[Any]
) -> dict[str, dict[str, Any]]:
    """Each vulnerability UUID to what is known of it: its id, source,
    description key and CWEs. ``facts_of`` reads one stored finding or
    vulnerability record (the source adapter's ``vulnerability_facts``).
    Later sources fill what earlier ones left empty."""
    result: dict[str, dict[str, Any]] = {}
    for source in sources:
        for item in source or []:
            facts = facts_of(item)
            if not facts or not facts.get("uuid"):
                continue
            known = result.setdefault(
                str(facts["uuid"]),
                {"vuln_id": None, "source": None, "description": None, "cwes": frozenset()},
            )
            vuln_id = facts.get("vuln_id")
            if vuln_id and not known["vuln_id"]:
                known["vuln_id"] = str(vuln_id)
            if facts.get("source") and not known["source"]:
                known["source"] = str(facts["source"])
            if not known["description"]:
                known["description"] = description_key(
                    facts.get("description"), [vuln_id or ""]
                )
            if facts.get("cwes") and not known["cwes"]:
                known["cwes"] = frozenset(int(cwe) for cwe in facts["cwes"])
    return result


def affected_ranges(entries: Iterable[Mapping[str, Any]], version: Any) -> frozenset[str]:
    """The ranges of a vulnerability's affected components that contain the
    installed version, written like ``>=3.0.0 <3.0.2``; an exact version as
    ``=1.2``. Whatever package the entry names: the two records of one issue
    name it differently (a CPE and a package URL)."""
    installed = str(version or "").strip()
    if not installed:
        return frozenset()
    found = set()
    for entry in entries or []:
        if not isinstance(entry, Mapping):
            continue
        text = range_text(entry)
        if text:
            if range_contains(entry, installed):
                found.add(text)
        elif entry.get("version") and compare_versions(str(entry["version"]), installed) == 0:
            found.add(f"={entry['version']}")
    return frozenset(found)


def same_issue_reason(
    left: Optional[Mapping[str, Any]],
    right: Optional[Mapping[str, Any]],
    left_ranges: frozenset[str] = frozenset(),
    right_ranges: frozenset[str] = frozenset(),
) -> Optional[str]:
    """Why two vulnerabilities on one component are probably one issue, or
    ``None``. Their facts come from ``facts_by_uuid``; the ranges from
    ``affected_ranges`` for the component's version."""
    if not left or not right:
        return None
    if left.get("description") and left["description"] == right.get("description"):
        return REASON_DESCRIPTION
    if (
        left_ranges
        and left_ranges == right_ranges
        and left.get("cwes")
        and left["cwes"] == right.get("cwes")
    ):
        return REASON_RANGE_AND_CWE
    return None


def _state(record: Optional[Mapping[str, Any]]) -> str:
    return str((record or {}).get("analysisState") or "NOT_SET")


class SameIssueIndex:
    """Probable same-issue matches of one project version.

    ``facts`` maps a vulnerability UUID to its facts; ``ranges_of(uuid,
    version)`` gives the ranges containing that version (empty when none are
    stored). Matches are looked for on the same component, or on a
    component with the same package URL and version (one the source
    recreated); aliases are left out, they have their own view."""

    def __init__(
        self,
        rows: Mapping[tuple[str, str], Mapping[str, Any]],
        facts: Mapping[str, Mapping[str, Any]],
        ranges_of: Callable[[str, Any], frozenset[str]] = lambda _uuid, _version: frozenset(),
        aliases: Optional[Mapping[str, set[str]]] = None,
    ) -> None:
        self.facts = facts
        self.ranges_of = ranges_of
        self.aliases = aliases or {}
        self.reported_by_component: dict[str, list[Mapping[str, Any]]] = {}
        self.reported_by_package: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        for row in rows.values():
            if row.get("status") != "reported":
                continue
            self.reported_by_component.setdefault(row["component_uuid"], []).append(row)
            package = _package_key(row)
            if package:
                self.reported_by_package.setdefault(package, []).append(row)

    def _is_alias(self, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_id = str(left.get("vuln_id") or "").strip().upper()
        right_id = str(right.get("vuln_id") or "").strip().upper()
        return bool(left_id and right_id) and right_id in self.aliases.get(left_id, set())

    def reason(self, left: Mapping[str, Any], right: Mapping[str, Any]) -> Optional[str]:
        """Why two finding rows are probably the same issue, or ``None``."""
        if left["vulnerability_uuid"] == right["vulnerability_uuid"]:
            return None
        if self._is_alias(left, right):
            return None
        version = left.get("component_version")
        return same_issue_reason(
            self.facts.get(left["vulnerability_uuid"]),
            self.facts.get(right["vulnerability_uuid"]),
            self.ranges_of(left["vulnerability_uuid"], version),
            self.ranges_of(right["vulnerability_uuid"], right.get("component_version")),
        )

    def candidates(self, row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """Reported findings a gone finding may be the same issue as: on its
        own component, or on one with the same package URL and version."""
        found = list(self.reported_by_component.get(row["component_uuid"], []))
        package = _package_key(row)
        if package:
            found += [
                other for other in self.reported_by_package.get(package, [])
                if other["component_uuid"] != row["component_uuid"]
            ]
        return found

    def match(self, row: Mapping[str, Any]) -> Optional[tuple[Mapping[str, Any], str]]:
        """The first reported finding a gone finding is probably the same
        issue as, with the reason; a description match before a range one."""
        best: Optional[tuple[Mapping[str, Any], str]] = None
        for other in sorted(
            self.candidates(row), key=lambda item: str(item.get("vuln_id") or "")
        ):
            reason = self.reason(row, other)
            if reason == REASON_DESCRIPTION:
                return other, reason
            if reason and best is None:
                best = (other, reason)
        return best

    def disagreements(
        self, record_of: Callable[[Mapping[str, Any]], Optional[Mapping[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Reported findings on one component that are probably the same
        issue and whose assessments have different states."""
        found = []
        for rows in self.reported_by_component.values():
            ordered = sorted(rows, key=lambda item: str(item.get("vuln_id") or ""))
            for index, left in enumerate(ordered):
                for right in ordered[index + 1:]:
                    reason = self.reason(left, right)
                    if not reason:
                        continue
                    states = [_state(record_of(item)) for item in (left, right)]
                    if "NOT_SET" in states or states[0] == states[1]:
                        continue
                    found.append({
                        "component_uuid": left["component_uuid"],
                        "component_name": left.get("component_name"),
                        "component_version": left.get("component_version"),
                        "reason": reason,
                        "findings": [
                            {
                                "vulnerability_uuid": item["vulnerability_uuid"],
                                "vuln_id": item.get("vuln_id"),
                                "state": state,
                            }
                            for item, state in zip((left, right), states)
                        ],
                    })
        return found


def _package_key(row: Mapping[str, Any]) -> Optional[tuple[str, str]]:
    purl = str(row.get("component_purl") or "").strip().lower()
    version = str(row.get("component_version") or "").strip()
    return (purl, version) if purl and version else None


def confirmed_pairs(
    rows: Iterable[Mapping[str, Any]],
) -> dict[tuple[str, str], set[str]]:
    """Each finding (component, vulnerability UUID) to the vulnerability ids
    a person confirmed it to be the same issue as, in both directions."""
    by_key = {
        (row["component_uuid"], row["vulnerability_uuid"]): row for row in rows
    }
    result: dict[tuple[str, str], set[str]] = {}
    for key, row in by_key.items():
        other_key = (row.get("same_issue_component_uuid"), row.get("same_issue_vulnerability_uuid"))
        if not row.get("same_issue_confirmed_by") or not all(other_key):
            continue
        other = by_key.get(other_key)  # type: ignore[arg-type]
        if other is not None and other.get("vuln_id"):
            result.setdefault(key, set()).add(str(other["vuln_id"]))
        if row.get("vuln_id"):
            result.setdefault(other_key, set()).add(str(row["vuln_id"]))  # type: ignore[arg-type]
    return result
