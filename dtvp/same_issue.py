"""Findings that are probably the same issue under two ids no source links.

Some vulnerabilities are recorded twice, for example as a CVE (from NVD) and
as a GitHub advisory, without either record naming the other as an alias.
DTVP can only guess that they are one issue: from the same description on
the same component. (An earlier fallback on the same affected range and CWE
matched far too many different vulnerabilities of one package and was
removed.) A description several ids on one component share is a template,
not an issue, and matches nothing. Such a guess is shown as "probably the same as <id>", never
as an alias and never exported as one; a person confirms it before anything
is applied, and only a confirmed match is exported (``<prefix>:same_issue_as``).

Everything here is a pure function over what DTVP stores: the vulnerability
records and findings (read through the source adapter's
``VulnerabilityFacts``) and the finding rows.
See docs/review-workflows.md, "Gone findings".
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Mapping, Optional

REASON_DESCRIPTION = "same description"
# A gone finding whose component DTVP never knew (a row made for a record
# from before tracking, on a component the source has since recreated) and a
# reported finding of the same vulnerability in the same version: probably
# the same finding on a recreated component. Only a person can tell; nothing
# is exported for it, the vulnerability id is the same.
REASON_UNKNOWN_COMPONENT = "same vulnerability, the gone finding's component is unknown"

# A description this short says too little to tell two issues apart.
MIN_DESCRIPTION_LENGTH = 40
# A description more ids than this share on one component is a template
# (boilerplate of a distribution or a scanner), not one issue.
MAX_IDS_SHARING_A_DESCRIPTION = 2

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


def same_issue_reason(
    left: Optional[Mapping[str, Any]],
    right: Optional[Mapping[str, Any]],
) -> Optional[str]:
    """Why two vulnerabilities on one component are probably one issue, or
    ``None``: the same description (see ``description_key``). Their facts
    come from ``facts_by_uuid``."""
    if not left or not right:
        return None
    if left.get("description") and left["description"] == right.get("description"):
        return REASON_DESCRIPTION
    return None


def _state(record: Optional[Mapping[str, Any]]) -> str:
    return str((record or {}).get("analysisState") or "NOT_SET")


class SameIssueIndex:
    """Probable same-issue matches of one project version.

    ``facts`` maps a vulnerability UUID to its facts. Matches are looked for
    on the same component, or on a component with the same package URL and
    version (one the source recreated); aliases are left out, they have
    their own view. A description that more than
    ``MAX_IDS_SHARING_A_DESCRIPTION`` ids share on one component matches
    nothing there."""

    def __init__(
        self,
        rows: Mapping[tuple[str, str], Mapping[str, Any]],
        facts: Mapping[str, Mapping[str, Any]],
        aliases: Optional[Mapping[str, set[str]]] = None,
    ) -> None:
        self.facts = facts
        self.aliases = aliases or {}
        self.reported_by_component: dict[str, list[Mapping[str, Any]]] = {}
        self.reported_by_package: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        self.reported_by_vulnerability: dict[str, list[Mapping[str, Any]]] = {}
        for row in rows.values():
            if row.get("status") != "reported":
                continue
            self.reported_by_component.setdefault(row["component_uuid"], []).append(row)
            self.reported_by_vulnerability.setdefault(
                str(row["vulnerability_uuid"]), []
            ).append(row)
            package = _package_key(row)
            if package:
                self.reported_by_package.setdefault(package, []).append(row)
        # Per component, the ids of every finding (reported or gone) that
        # carry one description.
        self.ids_by_description: dict[tuple[str, str], set[str]] = {}
        for row in rows.values():
            description = (facts.get(row["vulnerability_uuid"]) or {}).get("description")
            if description:
                self.ids_by_description.setdefault(
                    (row["component_uuid"], description), set()
                ).add(str(row["vulnerability_uuid"]))

    def _is_template(self, row: Mapping[str, Any], description: str) -> bool:
        return (
            len(self.ids_by_description.get((row["component_uuid"], description), ()))
            > MAX_IDS_SHARING_A_DESCRIPTION
        )

    def _is_alias(self, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_id = str(left.get("vuln_id") or "").strip().upper()
        right_id = str(right.get("vuln_id") or "").strip().upper()
        return bool(left_id and right_id) and right_id in self.aliases.get(left_id, set())

    def reason(self, left: Mapping[str, Any], right: Mapping[str, Any]) -> Optional[str]:
        """Why two finding rows are probably the same issue, or ``None``."""
        if left["vulnerability_uuid"] == right["vulnerability_uuid"]:
            if (
                _component_unknown(left)
                and left.get("status") == "gone"
                and right.get("status") == "reported"
                and left["component_uuid"] != right["component_uuid"]
            ):
                return REASON_UNKNOWN_COMPONENT
            return None
        if self._is_alias(left, right):
            return None
        left_facts = self.facts.get(left["vulnerability_uuid"])
        reason = same_issue_reason(left_facts, self.facts.get(right["vulnerability_uuid"]))
        if reason and (
            self._is_template(left, left_facts["description"])
            or self._is_template(right, left_facts["description"])
        ):
            return None
        return reason

    def candidates(self, row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """Reported findings a gone finding may be the same issue as: on its
        own component, or on one with the same package URL and version."""
        found = list(self.reported_by_component.get(row["component_uuid"], []))
        if _component_unknown(row) and row.get("status") == "gone":
            # The component is unknown: any reported finding of the same
            # vulnerability in this version may be its successor.
            found += [
                other
                for other in self.reported_by_vulnerability.get(
                    str(row["vulnerability_uuid"]), []
                )
                if other["component_uuid"] != row["component_uuid"]
            ]
        package = _package_key(row)
        if package:
            found += [
                other for other in self.reported_by_package.get(package, [])
                if other["component_uuid"] != row["component_uuid"]
            ]
        return found

    def match(self, row: Mapping[str, Any]) -> Optional[tuple[Mapping[str, Any], str]]:
        """The first reported finding a gone finding is probably the same
        issue as, with the reason."""
        for other in sorted(
            self.candidates(row),
            key=lambda item: (
                str(item.get("vuln_id") or ""),
                str(item.get("component_name") or ""),
                str(item.get("component_version") or ""),
                str(item.get("component_uuid") or ""),
            ),
        ):
            reason = self.reason(row, other)
            if reason:
                return other, reason
        return None

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


def _component_unknown(row: Mapping[str, Any]) -> bool:
    """Whether DTVP never learned which component a finding row was on."""
    return not any(
        str(row.get(name) or "").strip()
        for name in ("component_identity", "component_purl", "component_name")
    )


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
        if other_key[1] == row["vulnerability_uuid"]:
            # The same vulnerability on a recreated component: nothing to
            # name, it is the same id.
            continue
        if other is not None and other.get("vuln_id"):
            result.setdefault(key, set()).add(str(other["vuln_id"]))
        if row.get("vuln_id"):
            result.setdefault(other_key, set()).add(str(row["vuln_id"]))  # type: ignore[arg-type]
    return result


# -- gone records whose component is unknown, per vulnerability ---------------

UNKNOWN_READY = "ready"
UNKNOWN_AMBIGUOUS = "ambiguous"
UNKNOWN_CONFLICTING = "conflicting"


def _blank(record: Optional[Mapping[str, Any]]) -> bool:
    return (
        record is None
        or str(record.get("analysisState") or "NOT_SET") == "NOT_SET"
        and not str(record.get("analysisDetails") or "").strip()
    )


def unknown_component_records(
    rows: Mapping[tuple[str, str], Mapping[str, Any]],
    record_of: Callable[[Mapping[str, Any]], Optional[Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Per vulnerability UUID of one project version: its gone findings whose
    component DTVP never knew and that hold an assessment, and the findings of
    the same vulnerability reported now (the candidates to carry it to).
    Records that were superseded or cancelled are left out."""
    result: dict[str, dict[str, Any]] = {}
    for row in rows.values():
        if row.get("status") != "gone" or not _component_unknown(row):
            continue
        record = record_of(row)
        if _blank(record) or (record or {}).get("sync_status") in ("superseded", "cancelled"):
            continue
        entry = result.setdefault(str(row["vulnerability_uuid"]), {
            "vuln_id": row.get("vuln_id"), "gone": [], "candidates": [],
        })
        entry["gone"].append({
            "component_uuid": row["component_uuid"],
            "state": str(record["analysisState"]),
            "details": str(record.get("analysisDetails") or ""),
            "suppressed": bool(record.get("isSuppressed")),
            "updated_at": record.get("updated_at"),
            "record": dict(record),
            "row": dict(row),
        })
    for vulnerability, entry in result.items():
        gone = {item["component_uuid"] for item in entry["gone"]}
        entry["candidates"] = sorted(
            (
                {
                    "component_uuid": row["component_uuid"],
                    "component_name": row.get("component_name"),
                    "component_version": row.get("component_version"),
                    "component_purl": row.get("component_purl"),
                    "record": record_of(row),
                }
                for row in rows.values()
                if row.get("status") == "reported"
                and str(row["vulnerability_uuid"]) == vulnerability
                and row["component_uuid"] not in gone
            ),
            key=lambda item: (
                str(item["component_name"] or ""), str(item["component_version"] or ""),
                str(item["component_uuid"]),
            ),
        )
        entry["gone"].sort(key=lambda item: str(item["updated_at"] or ""), reverse=True)
    return result


def _exported_value(item: Mapping[str, Any]) -> tuple[str, bool, str]:
    """What a gone record exports: state, suppression and text. The
    justification and response are tags in the text, so the stripped text
    covers them."""
    return (item["state"], bool(item["suppressed"]), str(item["details"] or "").strip())


def classify_unknown_component(entry: Mapping[str, Any]) -> dict[str, Any]:
    """What can be done with one vulnerability's gone records of unknown
    component in a version:

    - ``conflicting`` when they hold different states;
    - ``ready`` with every candidate as a target when all records agree on
      every exported field (state, justification, response, suppression and
      text): it does not matter which component each was on;
    - ``ready`` with the one target when the vulnerability is reported on one
      component (or exactly one shares a package name or URL a gone record
      knows, which a row of unknown component normally does not), copying
      the newest record;
    - else ``ambiguous``."""
    states = {item["state"] for item in entry["gone"]}
    candidates = list(entry["candidates"])
    base = {
        "vuln_id": entry.get("vuln_id"), "candidates": candidates, "gone": entry["gone"],
        "agreeing": 0,
    }
    if len(states) > 1:
        return {**base, "kind": UNKNOWN_CONFLICTING, "states": sorted(states)}
    if not candidates:
        return {**base, "kind": None}
    agree = len({_exported_value(item) for item in entry["gone"]}) == 1
    if len(candidates) > 1:
        if agree:
            return {
                **base, "kind": UNKNOWN_READY, "targets": candidates,
                "source": entry["gone"][0], "agreeing": len(entry["gone"]),
            }
        names = {
            str(item["row"].get(name) or "").strip().lower()
            for item in entry["gone"]
            for name in ("component_name", "component_purl")
        } - {""}
        sharing = [
            candidate for candidate in candidates
            if names & {
                str(candidate.get("component_name") or "").strip().lower(),
                str(candidate.get("component_purl") or "").strip().lower(),
            }
        ]
        if len(sharing) != 1:
            return {**base, "kind": UNKNOWN_AMBIGUOUS}
        candidates = sharing
    return {
        **base, "kind": UNKNOWN_READY, "targets": candidates[:1], "source": entry["gone"][0],
        "agreeing": len(entry["gone"]) if agree else 0,
    }
