"""CycloneDX documents of one project version, built from DTVP's records.

``inventory`` is the stored BOM. ``vdr`` adds the findings with their
assessments in standard fields, so a consumer does not have to parse DTVP's
markup out of an analysis text:

- ``analysis``: state, justification, response, the rationale as ``detail``,
  and the date of the General assessment as ``lastUpdated``;
- ``ratings``: one rating per CVSS version of the advisory, each with its
  score, plus DTVP's own rescoring as a rating whose ``source.name`` is the
  configured assessment source, with its vector and the rationale as
  ``justification``;
- BOM ``annotations``: one per team assessment, with the vulnerability's
  ``bom-ref`` as subject, the team as annotator and the assessor as its
  contact. Its timestamp is the team's date, else the date of the
  assessment, else the export time; the vulnerability names a borrowed
  date by ``annotation_dated_by_assessment`` and the export time by
  ``undated_annotation``;
- ``properties``: assessor, reviewer, tickets, review status, team states,
  states of assessments without a team, SSVC, former team assessments,
  annotations not dated by their team;
- ``recommendation``: Dependency-Track's own, else one derived from the
  version ranges it holds (see ``fixed_versions``), with its provenance.

Every finding is included, also those in triage or without an assessment.
See docs/cyclonedx-export.md and ADR 0003.
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from .assessment_model import (
    ANALYSIS_RESPONSES,
    FORMER_TEAM_NOTE,
    SEE_GLOBAL_ASSESSMENT,
    render_assessment,
)
from .assessment_scopes import AMBIGUOUS, BASE, assessment_scopes
from .fixed_versions import grouped_recommendation

VARIANT_INVENTORY = "inventory"
VARIANT_VDR = "vdr"
VARIANTS = (VARIANT_INVENTORY, VARIANT_VDR)

DEFAULT_ASSESSMENT_SOURCE = "DTVP"
DEFAULT_PROPERTY_PREFIX = "dtvp"
MINIMUM_SPEC_VERSION = (1, 5)  # annotations

_STATES = {
    "EXPLOITABLE": "exploitable",
    "IN_TRIAGE": "in_triage",
    "RESOLVED": "resolved",
    "FALSE_POSITIVE": "false_positive",
    "NOT_AFFECTED": "not_affected",
}
_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
# CycloneDX names the responses as Dependency-Track does, in lower case.
_RESPONSES = {name: name.lower() for name in ANALYSIS_RESPONSES}
_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_TICKET_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# The former way of naming people: tags inside a text instead of a block header.
_PEOPLE = re.compile(r"\[(Reviewed|Assessed)\s+by:\s*([^\]]*)\]", re.IGNORECASE)
_FORMER = re.compile(rf"^{re.escape(FORMER_TEAM_NOTE)} \(", re.MULTILINE)
# What the complete vulnerability record adds to the one inside a finding.
_ADVISORY_KEYS = (
    "cvssV4", "cvssV4BaseScore", "cvssV4Vector",
    "cvssV3", "cvssV3BaseScore", "cvssV3Vector",
    "cvssV2", "cvssV2BaseScore", "cvssV2Vector",
    "published", "updated", "description", "recommendation", "cwes", "aliases",
    "patchedVersions",
)


def valid_property_prefix(value: str) -> bool:
    return bool(_PREFIX.match(value))


def valid_ticket_prefix(value: str) -> bool:
    return bool(_TICKET_PREFIX.match(value))


def _method(vector: Any) -> str | None:
    text = str(vector or "").strip()
    if text.startswith("CVSS:4."):
        return "CVSSv4"
    if text.startswith("CVSS:3.1"):
        return "CVSSv31"
    if text.startswith("CVSS:3."):
        return "CVSSv3"
    if text.startswith("CVSS:2.") or re.match(r"^\(?AV:[NAL]", text):
        return "CVSSv2"
    return None


def _severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _computed_score(vector: Any) -> float | None:
    """The base score a CVSS vector states, or None when it cannot be read."""
    text = str(vector or "").strip()
    method = _method(text)
    try:
        if method == "CVSSv4":
            return float(CVSS4(text).base_score)
        if method in ("CVSSv31", "CVSSv3"):
            return float(CVSS3(text).base_score)
        if method == "CVSSv2":
            bare = re.sub(r"^CVSS:2\.\d/", "", text.strip("()"))
            return float(CVSS2(bare).base_score)
    except (CVSSError, ValueError, TypeError, ArithmeticError, KeyError):
        return None
    return None


def _number(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


def _date_time(value: Any) -> str | None:
    """A CycloneDX ``date-time`` in UTC.

    Dependency-Track delivers milliseconds since 1970; an ISO 8601 text is
    accepted as well. None for anything else: no value instead of a wrong one.
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d+", str(value).strip()):
            number = float(value)
            # Twelve digits and more are milliseconds (seconds reach that in
            # the year 5138).
            moment = datetime.fromtimestamp(
                number / 1000 if number >= 1e11 else number, UTC
            )
        else:
            moment = datetime.fromisoformat(str(value).strip())
            moment = (
                moment.replace(tzinfo=UTC) if moment.tzinfo is None
                else moment.astimezone(UTC)
            )
    except (ValueError, OverflowError, OSError):
        return None
    return moment.isoformat()


def _advisory_ratings(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    """One rating per CVSS version the advisory has, each with its own score.

    A version that has a vector and no score gets the score the vector
    states. Without any CVSS data the advisory's severity is the one rating.
    """
    source = (
        {"source": {"name": str(vulnerability["source"])}}
        if vulnerability.get("source") else {}
    )
    ratings: list[dict[str, Any]] = []
    for score_keys, vector_key, fallback_method in (
        (("cvssV4", "cvssV4BaseScore"), "cvssV4Vector", "CVSSv4"),
        (("cvssV3", "cvssV3BaseScore"), "cvssV3Vector", "CVSSv3"),
        (("cvssV2", "cvssV2BaseScore"), "cvssV2Vector", "CVSSv2"),
    ):
        vector = str(vulnerability.get(vector_key) or "").strip()
        score = next(
            (
                number for key in score_keys
                if (number := _number(vulnerability.get(key))) is not None
            ),
            None,
        )
        if score is None and not vector:
            continue
        if score is None:
            score = _computed_score(vector)
        rating: dict[str, Any] = dict(source)
        if score is not None:
            rating["score"] = score
            rating["severity"] = _severity(score)
        rating["method"] = _method(vector) or fallback_method
        if vector:
            rating["vector"] = vector
        ratings.append(rating)
    if ratings:
        return ratings
    severity = str(vulnerability.get("severity") or "").lower()
    if severity in {"critical", "high", "medium", "low", "info", "none"}:
        return [{**source, "severity": severity}]
    return []


def complete_findings(
    findings: list[dict[str, Any]], vulnerabilities: Iterable[Any]
) -> list[dict[str, Any]]:
    """``findings`` with what the complete vulnerability records add.

    The vulnerability inside a finding is a summary. The records of the
    project's vulnerabilities carry every CVSS version, the dates, and the
    recommendation. A value the finding has is kept.
    """
    by_uuid: dict[str, dict[str, Any]] = {}
    by_id: dict[tuple[str, str], dict[str, Any]] = {}
    for record in vulnerabilities or []:
        if not isinstance(record, dict):
            continue
        if record.get("uuid"):
            by_uuid.setdefault(str(record["uuid"]), record)
        if record.get("vulnId"):
            by_id.setdefault(
                (str(record.get("source") or ""), str(record["vulnId"])), record
            )
    if not by_uuid and not by_id:
        return findings
    completed = []
    for finding in findings:
        vulnerability = finding.get("vulnerability") or {}
        record = by_uuid.get(str(vulnerability.get("uuid") or "")) or by_id.get(
            (str(vulnerability.get("source") or ""), str(vulnerability.get("vulnId") or ""))
        )
        added = {
            key: record[key] for key in _ADVISORY_KEYS
            if record and record.get(key) not in (None, "", [])
            and vulnerability.get(key) in (None, "", [])
        }
        completed.append(
            {**finding, "vulnerability": {**vulnerability, **added}} if added else finding
        )
    return completed


_ALIAS_SOURCES = {
    "cveId": "NVD", "ghsaId": "GITHUB", "osvId": "OSV", "sonatypeId": "OSSINDEX",
    "snykId": "SNYK", "gsdId": "GSD", "vulnDbId": "VULNDB", "internalId": "INTERNAL",
}


def _source_of(identifier: str) -> str | None:
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return "NVD"
    if upper.startswith("GHSA-"):
        return "GITHUB"
    return None


def _identifiers(vulnerability: dict[str, Any]) -> dict[str, str | None]:
    """The vulnerability's own id and its aliases, each with its source."""
    found: dict[str, str | None] = {}
    vuln_id = str(vulnerability.get("vulnId") or "").strip()
    if vuln_id:
        found[vuln_id] = str(vulnerability.get("source") or "") or _source_of(vuln_id)
    for alias in vulnerability.get("aliases") or []:
        if not isinstance(alias, dict):
            continue
        for key, source in _ALIAS_SOURCES.items():
            value = str(alias.get(key) or "").strip()
            if value:
                found.setdefault(value, source)
    return found


def _alias_groups(findings: Iterable[dict[str, Any]]) -> dict[str, dict[str, str | None]]:
    """Every identifier with all identifiers it is an alias of, across the
    findings: a CVE whose own record names no GHSA still gets the one
    whose record names the CVE. Keyed by the upper-case identifier."""
    parent: dict[str, str] = {}
    sources: dict[str, tuple[str, str | None]] = {}

    def root(key: str) -> str:
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for finding in findings:
        found = _identifiers(finding.get("vulnerability") or {})
        keys = []
        for identifier, source in found.items():
            key = identifier.upper()
            known = sources.get(key)
            if known is None or (known[1] is None and source):
                sources[key] = (identifier, source)
            keys.append(key)
        for key in keys[1:]:
            parent[root(key)] = root(keys[0])
    members: dict[str, dict[str, str | None]] = {}
    for key in sources:
        identifier, source = sources[key]
        members.setdefault(root(key), {})[identifier] = source
    return {key: members[root(key)] for key in sources}


def _references(
    vulnerability: dict[str, Any],
    vuln_id: str,
    aliases: Mapping[str, Mapping[str, str | None]] | None = None,
) -> list[dict[str, Any]]:
    """The vulnerability's aliases: those its record names, and those DTVP
    knows from the other findings' records."""
    seen = {
        identifier: source
        for identifier, source in _identifiers(vulnerability).items()
    }
    for identifier, source in ((aliases or {}).get(vuln_id.upper()) or {}).items():
        seen.setdefault(identifier, source)
    references = []
    for identifier, source in sorted(seen.items()):
        if identifier.upper() == vuln_id.upper():
            continue
        reference: dict[str, Any] = {"id": identifier}
        if source:
            reference["source"] = {"name": source}
        else:
            reference["source"] = {}
        references.append(reference)
    return references


def _component_refs(bom: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Look-ups from a finding's component to the ``bom-ref`` in the BOM."""
    by_ref: dict[str, str] = {}
    by_purl: dict[str, str] = {}
    by_name: dict[str, str] = {}

    def visit(components: Iterable[Any]) -> None:
        for component in components or []:
            if not isinstance(component, dict):
                continue
            ref = str(component.get("bom-ref") or "")
            if ref:
                by_ref[ref] = ref
                if component.get("purl"):
                    by_purl.setdefault(str(component["purl"]), ref)
                by_name.setdefault(
                    f"{component.get('group') or ''}|{component.get('name') or ''}|"
                    f"{component.get('version') or ''}",
                    ref,
                )
            visit(component.get("components") or [])

    visit(bom.get("components") or [])
    return {"ref": by_ref, "purl": by_purl, "name": by_name}


def _component_ref(component: dict[str, Any], refs: dict[str, dict[str, str]]) -> str:
    uuid_ = str(component.get("uuid") or "")
    if uuid_ in refs["ref"]:
        return uuid_
    purl = str(component.get("purl") or "")
    if purl and purl in refs["purl"]:
        return refs["purl"][purl]
    name = (
        f"{component.get('group') or ''}|{component.get('name') or ''}|"
        f"{component.get('version') or ''}"
    )
    # A component the BOM does not list still gets a stable reference.
    return refs["name"].get(name) or uuid_ or name


def _general(fields: dict[str, Any]) -> dict[str, Any]:
    return next(
        (
            team for team in fields["teams"]
            if team["team"] == "General" and not team["historical"]
        ),
        {},
    )


def _without_people(text: str) -> tuple[str, list[str], list[str]]:
    """``text`` without ``[Assessed by: …]`` and ``[Reviewed by: …]`` tags,
    and the assessors and reviewers they name.

    Texts from before the team blocks name people this way, and such a text
    is kept whole as the General assessment.
    """
    assessors: list[str] = []
    reviewers: list[str] = []

    def take(match: re.Match[str]) -> str:
        name = match.group(2).strip()
        if name and name.casefold() != "unknown":
            (reviewers if match.group(1).casefold() == "reviewed" else assessors).append(name)
        return ""

    cleaned = _PEOPLE.sub(take, text)
    if cleaned == text:
        return text.strip(), [], []  # a text without tags is exported as written
    cleaned = re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+\n", "\n", cleaned)).strip()
    return cleaned, assessors, reviewers


def _without_former(text: str) -> tuple[str, list[str]]:
    """``text`` up to its first former-team note, and the notes.

    The repair appends these notes to the General assessment and nothing
    marks where one ends, so a note runs to the next note or the end.
    """
    starts = [match.start() for match in _FORMER.finditer(text)]
    if not starts:
        return text.strip(), []
    notes = [
        text[start:end].strip()
        for start, end in zip(starts, [*starts[1:], len(text)])
    ]
    return text[:starts[0]].strip(), notes


def _refers_to_general(text: str) -> bool:
    return " ".join(text.split()).casefold() == SEE_GLOBAL_ASSESSMENT.casefold()


def _distinct(values: Iterable[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))


def _read(
    fields: dict[str, Any],
    unowned_teams: frozenset[str],
    ticket_pattern: re.Pattern[str] | None,
) -> dict[str, Any]:
    """What the export states about one assessment, read from its fields."""
    general = _general(fields)
    own, former = _without_former(general.get("details") or fields["free_text"] or "")
    rationale, text_assessors, text_reviewers = _without_people(own)
    live = [team for team in fields["teams"] if not team["historical"]]
    teams = []  # live teams other than General, with their cleaned text
    for team in live:
        if team["team"] == "General":
            continue
        text, _assessors, reviewers = _without_people(team["details"])
        text_reviewers += reviewers
        teams.append(
            {
                **team,
                "text": "" if _refers_to_general(text) else text,
                "unowned": team["team"].casefold() in unowned_teams,
            }
        )

    # Team assessments of teams that no longer own the component. They are
    # part of the record, and a ticket is about the vulnerability in the
    # product, not about who owned the component.
    historical = [team for team in fields["teams"] if team["historical"]]
    recorded = _distinct(team["ticket"] for team in [*live, *historical])
    mentioned: list[str] = []
    if ticket_pattern is not None:
        texts = [
            rationale,
            *(team["text"] for team in teams),
            *former,
            *(team["details"] for team in historical),
        ]
        if general.get("details"):
            texts.append(fields["free_text"])
        mentioned = _distinct(
            f"{prefix}-{number}"
            for text in texts
            for prefix, number in ticket_pattern.findall(text or "")
        )
    known = {key.strip() for ticket in recorded for key in ticket.split(",")}
    text_only = [key for key in mentioned if key not in known]
    # When a team last wrote its assessment; the General one may have no date.
    latest_team_date = max(
        (
            team["assessed_at_ms"] for team in live
            if team["team"] != "General" and team["assessed_at_ms"]
        ),
        default=None,
    )
    return {
        "general": general,
        "rationale": rationale,
        "former": former,
        "historical": historical,
        "teams": teams,
        "latest_team_date": latest_team_date,
        # When the assessment as a whole was last written: the date of the
        # General assessment, else the latest date of the live teams. A
        # reviewer's approval keeps it, so it is not when it was first made.
        "assessment_date": _date_time(general.get("assessed_at_ms") or latest_team_date),
        # Everyone who wrote a current block: the General assessment's
        # assessor first, then the teams'. Taking the General one alone made
        # the list shrink to one name when a save wrote the General block.
        "assessors": _distinct(
            [
                *([general["assessed_by"]] if general.get("assessed_by") else []),
                *(team["assessed_by"] for team in live),
                *text_assessors,
            ]
        ),
        "reviewers": _distinct([*(team["reviewed_by"] for team in live), *text_reviewers]),
        "tickets": [*recorded, *text_only],
        "text_only_tickets": text_only,
    }


def _own_rating(
    fields: dict[str, Any], read: dict[str, Any], source: str
) -> dict[str, Any] | None:
    score, vector = fields["rescored_score"], fields["rescored_vector"]
    if score is None and not vector:
        return None
    if score is None:
        score = _computed_score(vector)
    rating: dict[str, Any] = {"source": {"name": source}}
    if score is not None:
        rating["score"] = float(score)
        rating["severity"] = _severity(float(score))
    # A rescoring without a CVSS vector says so instead of leaving the
    # method open.
    rating["method"] = _method(vector) or "other"
    if vector:
        rating["vector"] = str(vector)
    if read["rationale"]:
        rating["justification"] = read["rationale"]
    return rating


def _analysis(fields: dict[str, Any], read: dict[str, Any]) -> dict[str, Any] | None:
    state = _STATES.get(str(fields["state"]).upper())
    if state is None:
        return None  # not set: the finding is listed without an analysis
    analysis: dict[str, Any] = {"state": state}
    justification = next(
        (
            str(team["justification"]).lower()
            for team in [read["general"], *fields["teams"]]
            if team and not team.get("historical")
            and str(team.get("justification") or "").lower() in _JUSTIFICATIONS
        ),
        None,
    )
    if justification and state == "not_affected":
        analysis["justification"] = justification
    # One response per finding in DTVP; CycloneDX takes a list.
    if response := _RESPONSES.get(str(fields.get("response") or "").upper()):
        analysis["response"] = [response]
    if read["rationale"]:
        analysis["detail"] = read["rationale"]
    # The date of the General assessment, else the latest date of the live
    # team assessments: the state then comes from them.
    if read["assessment_date"]:
        analysis["lastUpdated"] = read["assessment_date"]
    return analysis


def _properties(
    fields: dict[str, Any],
    read: dict[str, Any],
    prefix: str,
    *,
    borrowed: Iterable[str] = (),
    undated: Iterable[str] = (),
) -> list[dict[str, str]]:
    general = read["general"]
    properties: list[tuple[str, str]] = []
    if read["assessors"]:
        properties.append(("assessed_by", ", ".join(read["assessors"])))
    if read["reviewers"]:
        properties.append(("reviewed_by", ", ".join(read["reviewers"])))
    if read["tickets"]:
        properties.append(("spr", ", ".join(read["tickets"])))
    if fields["pending_review"]:
        properties.append(("pending_review", "true"))
    if fields["suppressed"]:
        properties.append(("suppressed", "true"))
    for team in read["teams"]:
        if not team["unowned"]:
            properties.append(("team_state", f"{team['team']}={team['state']}"))
    for team in read["teams"]:
        if team["unowned"]:
            # Keyed by the assessor, who annotates its text, or ``-`` when
            # there is none and the text is ``unassigned_assessment``. Never
            # the fallback team name: it is no team's.
            key = team["assessed_by"] or "-"
            properties.append(("unassigned_state", f"{key}={team['state']}"))
    if general.get("ssvc"):
        properties.append(("ssvc", str(general["ssvc"])))
    if fields["free_text"] and general.get("details"):
        # Otherwise the free text already is the rationale.
        properties.append(("free_text", fields["free_text"]))
    for team in read["teams"]:
        if team["unowned"] and team["text"] and not team["assessed_by"]:
            # No team and no assessor to annotate as.
            properties.append(("unassigned_assessment", team["text"]))
    for note in read["former"]:
        properties.append(("former_assessment", note))
    for team in read["historical"]:
        properties.append(("historical_assessment", _historical(team)))
    for name in borrowed:
        # The annotation carries the assessment's latest date, not the team's.
        properties.append(("annotation_dated_by_assessment", name))
    for name in undated:
        # An annotation must have a timestamp; this one carries the export time.
        properties.append(("undated_annotation", name))
    return [{"name": f"{prefix}:{name}", "value": value} for name, value in properties]


def _scope_properties(
    fields_of_vulnerability: list[dict[str, Any]], prefix: str
) -> list[dict[str, str]]:
    """The version override of a vulnerability in this project version, from
    the scope its findings put the version in (ADR 0010 section 11): none
    for base; label, reason and status for an override, on every finding of
    the version, inherited ones included."""
    if not any(fields.get("version_override") for fields in fields_of_vulnerability):
        return []
    # The same scope rule as everywhere else: the findings of this version,
    # as texts, through ``assessment_scopes``.
    view = assessment_scopes(
        {
            "affected_versions": [
                {
                    "project_uuid": "version",
                    "components": [
                        {
                            "analysis_state": fields["state"],
                            "analysis_details": render_assessment(fields),
                        }
                        for fields in fields_of_vulnerability
                    ],
                }
            ]
        }
    )
    name = view.version_scopes.get("version", BASE)
    if name == BASE:
        return []
    if name == AMBIGUOUS:
        properties = [("assessment_scope", AMBIGUOUS)]
    else:
        scope = next(scope for scope in view.scopes if scope.name == name)
        properties = [("assessment_scope", "version_override"), ("version_override", str(scope.label))]
        if scope.reason:
            properties.append(("version_override_reason", scope.reason))
        properties.append(("version_override_status", "pending" if scope.pending else "approved"))
    return [{"name": f"{prefix}:{name}", "value": value} for name, value in properties]


def _historical(team: dict[str, Any]) -> str:
    """A team assessment of a former owner, as a JSON object.

    A property value is one string; the parts stay apart this way.
    """
    text, _assessors, _reviewers = _without_people(team["details"])
    record = {
        "team": team["team"],
        "state": team["state"],
        "justification": team["justification"],
        "assessed_by": team["assessed_by"],
        "reviewed_by": team["reviewed_by"],
        "date": _date_time(team["assessed_at_ms"]),
        "ticket": team["ticket"],
        "text": text,
    }
    return json.dumps(
        {name: value for name, value in record.items() if value},
        ensure_ascii=False,
    )


def _annotations(
    read: dict[str, Any], subject: str, generated_at: str
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """The annotations of the team assessments, who annotates those dated by
    the assessment, and who annotates those without any date.

    An annotation needs a timestamp: the team's date, else the date of the
    assessment, else the export time. Neither of the last two is the team's
    own date (the assessment's can be earlier than the team wrote), so the
    annotator is named: the team, or the assessor of an assessment without
    a team (never the fallback team name).
    """
    annotations = []
    borrowed: list[str] = []
    undated: list[str] = []
    for team in read["teams"]:
        if not team["text"]:
            continue  # a state without a text of its own is ``team_state`` only
        if team["unowned"]:
            # The component has no team: the assessor annotates as a person.
            if not team["assessed_by"]:
                continue
            annotator: dict[str, Any] = {"individual": {"name": team["assessed_by"]}}
            name = team["assessed_by"]
        else:
            # CycloneDX allows one annotator per annotation: the team, with
            # the assessor as its contact.
            organization: dict[str, Any] = {"name": team["team"]}
            if team["assessed_by"]:
                organization["contact"] = [{"name": team["assessed_by"]}]
            annotator = {"organization": organization}
            name = team["team"]
        timestamp = _date_time(team["assessed_at_ms"])
        if not timestamp and read["assessment_date"]:
            timestamp = read["assessment_date"]
            borrowed.append(name)
        elif not timestamp:
            timestamp = generated_at
            undated.append(name)
        annotations.append(
            {
                "subjects": [subject],
                "annotator": annotator,
                "timestamp": timestamp,
                "text": team["text"],
            }
        )
    return annotations, borrowed, undated


def _add_missing_components(
    document: dict[str, Any],
    findings: Iterable[dict[str, Any]],
    property_prefix: str,
) -> None:
    """List components that findings name but the BOM does not.

    Every ``affects`` reference has to resolve in the same document, and in
    the inventory a consumer reads beside it. Such a component is added with
    what the finding knows about it and marked as added.
    """
    refs = _component_refs(document)
    known = set(refs["ref"])
    for finding in findings:
        component = finding.get("component") or {}
        ref = _component_ref(component, refs)
        if not ref or ref in known:
            continue
        known.add(ref)
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": str(component.get("name") or ref),
        }
        for key in ("group", "version", "purl"):
            if component.get(key):
                entry[key] = str(component[key])
        entry["properties"] = [
            {"name": f"{property_prefix}:added_from_finding", "value": "true"}
        ]
        document.setdefault("components", []).append(entry)


class _Recommendations:
    """The recommendation of each entry and what the document says about them.

    Dependency-Track's own text is kept and marked ``advisory``. Otherwise
    each affected component gets the sentence its version ranges give
    (``fixed_version``); a component without a fix gets none, and an entry
    without any sentence has no recommendation.
    """

    def __init__(
        self,
        fixed_versions: Mapping[tuple[str, str], dict[str, Any]] | None,
        prefix: str,
    ) -> None:
        self.rows = fixed_versions
        self.prefix = prefix
        self.derived = 0
        self.unread = 0
        self.read_at: list[str] = []

    def of(
        self, vulnerability: dict[str, Any], components: list[dict[str, Any]]
    ) -> tuple[str, list[dict[str, str]]]:
        own = str(vulnerability.get("recommendation") or "").strip()
        if own:
            return str(vulnerability["recommendation"]), [
                {"name": f"{self.prefix}:recommendation_source", "value": "advisory"}
            ]
        key = (str(vulnerability.get("source") or ""), str(vulnerability.get("vulnId") or ""))
        row = (self.rows or {}).get(key)
        entries = None
        if row is not None and (row.get("status") != "failed" or row.get("payload") is not None):
            entries = row.get("payload") or []
            if row.get("read_at"):
                self.read_at.append(str(row["read_at"]))
        elif self.rows is not None:
            self.unread += 1  # never read: the background read has not come to it yet
        # Trivy's vulnerability-wide value, from whichever package created
        # the record: a hint, never the recommendation.
        patched = str(vulnerability.get("patchedVersions") or "").strip()
        hint = (
            [{"name": f"{self.prefix}:patched_versions", "value": patched}]
            if patched else []
        )
        # One sentence per fix target, naming the installed packages and
        # versions it applies to; every affected package is named, one the
        # ranges give no fix for in a sentence of its own.
        derived = grouped_recommendation(components, entries)
        if derived is None:
            return "", hint
        self.derived += 1
        sources = list(derived.sources)
        return derived.text, [
            {"name": f"{self.prefix}:recommendation_source", "value": "fixed_version"},
            *(
                {"name": f"{self.prefix}:recommendation_fixed_by", "value": source}
                for source in sources
            ),
            *hint,
        ]

    def metadata(self) -> list[dict[str, str]]:
        properties = [
            {"name": f"{self.prefix}:export_derived_recommendations", "value": str(self.derived)}
        ]
        if self.unread:
            properties.append(
                {"name": f"{self.prefix}:export_fixed_versions_unread", "value": str(self.unread)}
            )
        if self.read_at:
            properties.append(
                {"name": f"{self.prefix}:export_fixed_versions_read_at", "value": min(self.read_at)}
            )
        return properties


# Names of this application's inventories; fixed, so an identity can be
# derived again from the same content.
_INVENTORY_NAMESPACE = uuid.UUID("6f1d3c0a-5b0e-5d2f-9a57-2f1c8d3e4b6a")
# A changed inventory is a new BOM with a new serial number, not a new
# version of the old one: nothing has to remember a counter.
INVENTORY_VERSION = 1
_INVENTORY_CONTENT = ("components", "services", "dependencies", "compositions")


def _canonical(value: Any) -> Any:
    """``value`` with every list in an order that depends on its content only."""
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted(
            (_canonical(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
        )
    return value


def inventory_serial_number(document: dict[str, Any]) -> str:
    """The serial number of an inventory, derived from what it lists.

    Dependency-Track gives every export of a BOM a new serial number. An
    inventory is identified here by its content instead: the described
    component, the components, services, dependencies and compositions.
    The same content has the same serial number in every export, in any
    order, and under any property prefix; a changed inventory has another.
    """
    def unmarked(component: Any) -> Any:
        # The mark of an added component carries the requested prefix.
        if not isinstance(component, dict) or "properties" not in component:
            return component
        properties = [
            item for item in component["properties"]
            if not str((item or {}).get("name", "")).endswith(":added_from_finding")
        ]
        rest = {key: item for key, item in component.items() if key != "properties"}
        return {**rest, "properties": properties} if properties else rest

    content: dict[str, Any] = {
        "subject": (document.get("metadata") or {}).get("component"),
        **{name: document.get(name) or [] for name in _INVENTORY_CONTENT},
    }
    content["components"] = [unmarked(item) for item in content["components"]]
    digest = json.dumps(
        _canonical(content), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return f"urn:uuid:{uuid.uuid5(_INVENTORY_NAMESPACE, digest)}"


def inventory_bom_link(document: dict[str, Any]) -> str:
    """The BOM-Link of an inventory built by ``build_inventory``."""
    serial = str(document["serialNumber"]).removeprefix("urn:uuid:")
    return f"urn:cdx:{serial}/{document['version']}"


def build_inventory(
    bom: dict[str, Any],
    findings: Iterable[dict[str, Any]] = (),
    *,
    property_prefix: str = DEFAULT_PROPERTY_PREFIX,
) -> dict[str, Any]:
    """The stored BOM without vulnerability data, completed by the components
    that ``findings`` name but the BOM does not list."""
    document = copy.deepcopy(bom)
    document.pop("vulnerabilities", None)
    _add_missing_components(document, findings, property_prefix)
    # The same inventory is the same BOM, whenever it is exported.
    document["serialNumber"] = inventory_serial_number(document)
    document["version"] = INVENTORY_VERSION
    return document


def _gone_properties(
    summary: Mapping[str, Any] | None, prefix: str
) -> list[dict[str, str]]:
    if not summary:
        return []
    if all(isinstance(value, int) for value in summary.values()):
        summary = {"gone": summary}

    def counts(name: str, values: Mapping[str, Any] | None) -> list[dict[str, str]]:
        return [
            {"name": f"{prefix}:{name}", "value": f"{reason}={count}"}
            for reason, count in sorted((values or {}).items())
            if int(count) > 0
        ]

    properties = counts("export_findings_gone", summary.get("gone"))
    if int(summary.get("recreated") or 0) > 0:
        properties.append(
            {"name": f"{prefix}:export_findings_recreated", "value": str(summary["recreated"])}
        )
    if not properties:
        return []  # nothing went: an export says nothing about it
    if int(summary.get("attention") or 0) > 0:
        properties.append(
            {"name": f"{prefix}:export_findings_gone_attention", "value": str(summary["attention"])}
        )
    last_read = summary.get("last_read") or {}
    if last_read.get("at"):
        properties.append(
            {"name": f"{prefix}:export_findings_gone_last_read_at", "value": str(last_read["at"])}
        )
        properties += counts("export_findings_gone_last_read", last_read.get("went"))
    if summary.get("since"):
        properties.append(
            {"name": f"{prefix}:export_findings_followed_since", "value": str(summary["since"])}
        )
    return properties


def build_vdr(
    bom: dict[str, Any],
    findings: list[dict[str, Any]],
    assessments: list[dict[str, Any]],
    *,
    assessment_source: str = DEFAULT_ASSESSMENT_SOURCE,
    property_prefix: str = DEFAULT_PROPERTY_PREFIX,
    generated_at: datetime | None = None,
    tool_version: str = "",
    unowned_teams: Iterable[str] = (),
    ticket_prefixes: Iterable[str] = (),
    findings_read_at: str = "",
    fixed_versions: Mapping[tuple[str, str], dict[str, Any]] | None = None,
    findings_gone: Mapping[str, Any] | None = None,
    same_issue_as: Mapping[tuple[str, str], Iterable[str]] | None = None,
) -> dict[str, Any]:
    """The BOM with its findings and their assessments.

    ``assessments[i]`` holds the atomic fields of ``findings[i]``. Findings of
    one vulnerability that share the same assessment become one entry with
    several ``affects``; differing assessments become separate entries.

    ``unowned_teams`` are the names the team mapping gives to components no
    team owns: an assessment under such a name is not a team's.
    ``ticket_prefixes`` are the project keys of ticket references
    (``<prefix>-<number>``) to recognise in the texts.
    ``findings_read_at`` is when the findings were last read from the source.
    ``fixed_versions`` are the stored version ranges per (source, vuln ID),
    as ``LocalStore.fixed_version_entries`` returns them; ``None`` when they
    were not looked up, so that no entry counts as unread.
    ``findings_gone`` says what became of findings of the project version
    the source no longer reports (they are not listed), as
    ``FindingLifecycleStore.export_gone_summary`` returns it; a plain
    mapping of reason to count stands for its ``gone`` part.
    ``same_issue_as`` maps a finding (component UUID, vulnerability UUID) to
    the vulnerability ids a person confirmed it to be the same issue as,
    although no source names them as aliases; exported as
    ``<prefix>:same_issue_as``, never as ``references`` (it is DTVP's
    record, not a source's).
    """
    moment = (generated_at or datetime.now(UTC)).astimezone(UTC).isoformat()
    document = build_inventory(bom, findings, property_prefix=property_prefix)
    try:
        spec = tuple(int(part) for part in str(document.get("specVersion", "")).split("."))
    except ValueError:
        spec = ()
    if spec < MINIMUM_SPEC_VERSION:
        document["specVersion"] = ".".join(str(part) for part in MINIMUM_SPEC_VERSION)
    document.setdefault("bomFormat", "CycloneDX")
    # The report is a document of its own, issued anew with every export. It
    # says which inventory it describes: the one ``build_inventory`` gives
    # for the same project version at this moment.
    inventory = inventory_bom_link(document)
    document["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    document["version"] = 1
    document["externalReferences"] = [
        *[
            item for item in document.get("externalReferences") or []
            if not (item.get("type") == "bom" and str(item.get("url", "")).startswith("urn:cdx:"))
        ],
        {
            "type": "bom",
            "url": inventory,
            "comment": "The inventory this report describes",
        },
    ]
    metadata = document.setdefault("metadata", {})
    metadata["timestamp"] = moment
    metadata["properties"] = [
        *[
            item for item in metadata.get("properties") or []
            if not str(item.get("name", "")).startswith(f"{property_prefix}:export")
        ],
        {"name": f"{property_prefix}:export", "value": VARIANT_VDR},
        {"name": f"{property_prefix}:export_assessment_source", "value": assessment_source},
        {"name": f"{property_prefix}:export_inventory", "value": inventory},
        # The prefix of every property of this document, stated outright.
        {"name": f"{property_prefix}:export_property_prefix", "value": property_prefix},
        *(
            [{"name": f"{property_prefix}:export_tool", "value": f"DTVP {tool_version}"}]
            if tool_version else []
        ),
        # The findings are those of the last import. Advisories the source
        # has reported since are not in the document.
        *(
            [{"name": f"{property_prefix}:export_findings_read_at", "value": findings_read_at}]
            if findings_read_at else []
        ),
    ]

    unowned = frozenset(str(name).strip().casefold() for name in unowned_teams if name)
    prefixes = _distinct(str(prefix).strip() for prefix in ticket_prefixes)
    ticket_pattern = (
        re.compile(rf"\b({'|'.join(re.escape(prefix) for prefix in prefixes)})-(\d+)\b")
        if prefixes else None
    )
    text_only_tickets = 0
    historical_assessments = 0

    refs = _component_refs(document)
    aliases = _alias_groups(findings)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    fields_by_vulnerability: dict[str, list[dict[str, Any]]] = {}
    for finding, fields in zip(findings, assessments):
        vulnerability = finding.get("vulnerability") or {}
        component = finding.get("component") or {}
        vuln_id = str(vulnerability.get("vulnId") or vulnerability.get("uuid") or "")
        if not vuln_id:
            continue
        fields_by_vulnerability.setdefault(vuln_id, []).append(fields)
        signature = (
            vuln_id,
            fields["state"], fields["suppressed"], fields["pending_review"],
            fields["rescored_score"], fields["rescored_vector"], fields["free_text"],
            fields.get("response"),
            tuple(
                (team["team"], team["state"], team["justification"], team["details"],
                 team["historical"])
                for team in fields["teams"]
            ),
        )
        group = groups.setdefault(
            signature,
            {"vulnerability": vulnerability, "fields": fields, "refs": [], "components": []},
        )
        ref = _component_ref(component, refs)
        if ref not in group["refs"]:
            group["refs"].append(ref)
            group["components"].append(component)

    recommendations = _Recommendations(fixed_versions, property_prefix)
    per_id: dict[str, int] = {}
    scope_properties: dict[str, list[dict[str, str]]] = {}
    vulnerabilities: list[dict[str, Any]] = []
    annotations: list[dict[str, Any]] = list(document.get("annotations") or [])
    # A stable order, so the same split gives each entry the same bom-ref in
    # every export: by vulnerability, then by the identity of the components
    # it affects (package URL, else name and version: a component the source
    # recreated under a new ID keeps its place), then by the assessment
    # without its review state (approving one group does not swap it with
    # the other); never by the order the source listed the findings.
    def component_identity(component: dict[str, Any]) -> str:
        purl = str(component.get("purl") or "").strip().lower()
        if purl:
            return purl
        return f"{component.get('group') or ''}/{component.get('name') or ''}@{component.get('version') or ''}".lower()

    def order(item: tuple[tuple[Any, ...], dict[str, Any]]) -> tuple[Any, ...]:
        signature, group = item
        assessment = signature[:3] + signature[4:]  # without pending_review
        return (
            signature[0],
            sorted(component_identity(component) for component in group["components"]),
            repr(assessment),
            repr(signature),
        )

    ordered = sorted(groups.items(), key=order)
    for signature, group in ordered:
        vuln_id = signature[0]
        vulnerability, fields = group["vulnerability"], group["fields"]
        index = per_id.get(vuln_id, 0)
        per_id[vuln_id] = index + 1
        base_ref = str(vulnerability.get("uuid") or vuln_id)
        bom_ref = base_ref if index == 0 else f"{base_ref}#{index + 1}"
        entry: dict[str, Any] = {"bom-ref": bom_ref, "id": vuln_id}
        if vulnerability.get("source"):
            entry["source"] = {"name": str(vulnerability["source"])}
        if references := _references(vulnerability, vuln_id, aliases):
            entry["references"] = references
        read = _read(fields, unowned, ticket_pattern)
        ratings = _advisory_ratings(vulnerability)
        if own := _own_rating(fields, read, assessment_source):
            ratings.append(own)
        if ratings:
            entry["ratings"] = ratings
        cwes = [
            int(cwe["cweId"]) for cwe in vulnerability.get("cwes") or []
            if isinstance(cwe, dict) and str(cwe.get("cweId", "")).isdigit()
        ]
        if cwes:
            entry["cwes"] = cwes
        if vulnerability.get("description"):
            entry["description"] = str(vulnerability["description"])
        recommendation, provenance = recommendations.of(vulnerability, group["components"])
        if recommendation:
            entry["recommendation"] = recommendation
        for name in ("published", "updated"):
            if stated := _date_time(vulnerability.get(name)):
                entry[name] = stated
        if analysis := _analysis(fields, read):
            entry["analysis"] = analysis
        entry["affects"] = [{"ref": ref} for ref in group["refs"]]
        own_annotations, borrowed, undated = _annotations(read, bom_ref, moment)
        if vuln_id not in scope_properties:
            scope_properties[vuln_id] = _scope_properties(
                fields_by_vulnerability[vuln_id], property_prefix
            )
        same_issue = sorted({
            str(other)
            for component in group["components"]
            for other in (same_issue_as or {}).get(
                (str(component.get("uuid") or ""), str(vulnerability.get("uuid") or "")), ()
            )
            if str(other) != vuln_id
        })
        if properties := [
            *_properties(
                fields, read, property_prefix, borrowed=borrowed, undated=undated
            ),
            *scope_properties[vuln_id],
            *provenance,
            *(
                [{"name": f"{property_prefix}:same_issue_as", "value": ", ".join(same_issue)}]
                if same_issue else []
            ),
        ]:
            entry["properties"] = properties
        vulnerabilities.append(entry)
        annotations.extend(own_annotations)
        if read["text_only_tickets"]:
            text_only_tickets += 1
        historical_assessments += len(read["historical"])

    metadata["properties"] += recommendations.metadata()

    if prefixes:
        metadata["properties"] += [
            {"name": f"{property_prefix}:export_ticket_prefixes", "value": ", ".join(prefixes)},
            # Entries with a ticket key that only a text mentions: their
            # records lack the ticket field.
            {
                "name": f"{property_prefix}:export_text_only_tickets",
                "value": str(text_only_tickets),
            },
        ]

    if historical_assessments:
        # Assessments of former owners, exported as ``historical_assessment``.
        metadata["properties"].append(
            {
                "name": f"{property_prefix}:export_historical_assessments",
                "value": str(historical_assessments),
            }
        )

    # Findings the source stopped reporting are not listed; say how many
    # went and why, so a reader need not compare exports to notice.
    metadata["properties"] += _gone_properties(findings_gone, property_prefix)

    document["vulnerabilities"] = vulnerabilities
    if annotations:
        document["annotations"] = annotations
    return document
