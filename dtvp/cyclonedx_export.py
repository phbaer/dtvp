"""CycloneDX documents of one project version, built from DTVP's records.

``inventory`` is the stored BOM. ``vdr`` adds the findings with their
assessments in standard fields, so a consumer does not have to parse DTVP's
markup out of an analysis text:

- ``analysis``: state, justification, and the rationale as ``detail``;
- ``ratings``: the advisory's rating, plus DTVP's own rescoring as a rating
  whose ``source.name`` is the configured assessment source, with its vector
  and the rationale as ``justification``;
- BOM ``annotations``: one per team assessment, with the vulnerability's
  ``bom-ref`` as subject, the team as annotator and the assessor as its
  contact;
- ``properties``: assessor, reviewer, tickets, review status, team states,
  SSVC.

Every finding is included, also those in triage or without an assessment.
See docs/cyclonedx-export.md and ADR 0003.
"""

from __future__ import annotations

import copy
import re
import uuid
from datetime import UTC, datetime
from typing import Any, Iterable

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
_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def valid_property_prefix(value: str) -> bool:
    return bool(_PREFIX.match(value))


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


def _advisory_rating(vulnerability: dict[str, Any]) -> dict[str, Any] | None:
    for score_keys, vector_key in (
        (("cvssV4", "cvssV4BaseScore"), "cvssV4Vector"),
        (("cvssV3", "cvssV3BaseScore"), "cvssV3Vector"),
        (("cvssV2", "cvssV2BaseScore"), "cvssV2Vector"),
    ):
        score = next(
            (vulnerability[key] for key in score_keys if vulnerability.get(key) is not None),
            None,
        )
        vector = vulnerability.get(vector_key)
        if score is None and not vector:
            continue
        rating: dict[str, Any] = {}
        if vulnerability.get("source"):
            rating["source"] = {"name": str(vulnerability["source"])}
        if score is not None:
            rating["score"] = float(score)
        severity = str(vulnerability.get("severity") or "").lower()
        if severity in {"critical", "high", "medium", "low", "info", "none", "unknown"}:
            rating["severity"] = severity
        if method := _method(vector) or {
            "cvssV4Vector": "CVSSv4", "cvssV3Vector": "CVSSv3", "cvssV2Vector": "CVSSv2",
        }[vector_key]:
            rating["method"] = method
        if vector:
            rating["vector"] = str(vector)
        return rating
    severity = str(vulnerability.get("severity") or "").lower()
    if severity in {"critical", "high", "medium", "low", "info", "none"}:
        return {
            **({"source": {"name": str(vulnerability["source"])}} if vulnerability.get("source") else {}),
            "severity": severity,
        }
    return None


def _references(vulnerability: dict[str, Any], vuln_id: str) -> list[dict[str, Any]]:
    sources = {
        "cveId": "NVD", "ghsaId": "GITHUB", "osvId": "OSV", "sonatypeId": "OSSINDEX",
        "snykId": "SNYK", "gsdId": "GSD", "vulnDbId": "VULNDB", "internalId": "INTERNAL",
    }
    seen: dict[str, str] = {}
    for alias in vulnerability.get("aliases") or []:
        if not isinstance(alias, dict):
            continue
        for key, source in sources.items():
            value = str(alias.get(key) or "").strip()
            if value and value.upper() != vuln_id.upper():
                seen.setdefault(value, source)
    return [{"id": value, "source": {"name": source}} for value, source in sorted(seen.items())]


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


def _rationale(fields: dict[str, Any]) -> str:
    general = next(
        (
            team for team in fields["teams"]
            if team["team"] == "General" and not team["historical"]
        ),
        None,
    )
    return ((general or {}).get("details") or fields["free_text"] or "").strip()


def _general(fields: dict[str, Any]) -> dict[str, Any]:
    return next(
        (
            team for team in fields["teams"]
            if team["team"] == "General" and not team["historical"]
        ),
        {},
    )


def _own_rating(fields: dict[str, Any], source: str) -> dict[str, Any] | None:
    score, vector = fields["rescored_score"], fields["rescored_vector"]
    if score is None and not vector:
        return None
    rating: dict[str, Any] = {"source": {"name": source}}
    if score is not None:
        rating["score"] = float(score)
        rating["severity"] = _severity(float(score))
    if method := _method(vector):
        rating["method"] = method
    if vector:
        rating["vector"] = str(vector)
    if rationale := _rationale(fields):
        rating["justification"] = rationale
    return rating


def _analysis(fields: dict[str, Any]) -> dict[str, Any] | None:
    state = _STATES.get(str(fields["state"]).upper())
    if state is None:
        return None  # not set: the finding is listed without an analysis
    analysis: dict[str, Any] = {"state": state}
    justification = next(
        (
            str(team["justification"]).lower()
            for team in [_general(fields), *fields["teams"]]
            if team and not team.get("historical")
            and str(team.get("justification") or "").lower() in _JUSTIFICATIONS
        ),
        None,
    )
    if justification and state == "not_affected":
        analysis["justification"] = justification
    if rationale := _rationale(fields):
        analysis["detail"] = rationale
    return analysis


def _properties(fields: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    def distinct(values: Iterable[Any]) -> list[str]:
        return list(dict.fromkeys(str(value) for value in values if value))

    live = [team for team in fields["teams"] if not team["historical"]]
    general = _general(fields)
    properties: list[tuple[str, str]] = []
    assessors = distinct(
        [general.get("assessed_by")] if general.get("assessed_by")
        else [team["assessed_by"] for team in live]
    )
    if assessors:
        properties.append(("assessed_by", ", ".join(assessors)))
    reviewers = distinct(team["reviewed_by"] for team in live)
    if reviewers:
        properties.append(("reviewed_by", ", ".join(reviewers)))
    tickets = distinct(team["ticket"] for team in live)
    if tickets:
        properties.append(("spr", ", ".join(tickets)))
    if fields["pending_review"]:
        properties.append(("pending_review", "true"))
    if fields["suppressed"]:
        properties.append(("suppressed", "true"))
    for team in live:
        if team["team"] != "General":
            properties.append(("team_state", f"{team['team']}={team['state']}"))
    if general.get("ssvc"):
        properties.append(("ssvc", str(general["ssvc"])))
    if fields["free_text"] and general.get("details"):
        # Otherwise the free text already is the rationale.
        properties.append(("free_text", fields["free_text"]))
    return [{"name": f"{prefix}:{name}", "value": value} for name, value in properties]


def _annotations(
    fields: dict[str, Any], subject: str, generated_at: str
) -> list[dict[str, Any]]:
    annotations = []
    for team in fields["teams"]:
        if team["historical"] or team["team"] == "General" or not team["details"].strip():
            continue
        # CycloneDX allows one annotator per annotation: the team, with the
        # assessor as its contact.
        organization: dict[str, Any] = {"name": team["team"]}
        if team["assessed_by"]:
            organization["contact"] = [{"name": team["assessed_by"]}]
        annotator: dict[str, Any] = {"organization": organization}
        annotations.append(
            {
                "subjects": [subject],
                "annotator": annotator,
                "timestamp": (
                    datetime.fromtimestamp(team["assessed_at_ms"] / 1000, UTC).isoformat()
                    if team["assessed_at_ms"]
                    else generated_at
                ),
                "text": team["details"].strip(),
            }
        )
    return annotations


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
    return document


def build_vdr(
    bom: dict[str, Any],
    findings: list[dict[str, Any]],
    assessments: list[dict[str, Any]],
    *,
    assessment_source: str = DEFAULT_ASSESSMENT_SOURCE,
    property_prefix: str = DEFAULT_PROPERTY_PREFIX,
    generated_at: datetime | None = None,
    tool_version: str = "",
) -> dict[str, Any]:
    """The BOM with its findings and their assessments.

    ``assessments[i]`` holds the atomic fields of ``findings[i]``. Findings of
    one vulnerability that share the same assessment become one entry with
    several ``affects``; differing assessments become separate entries.
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
    document["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    document["version"] = 1
    metadata = document.setdefault("metadata", {})
    metadata["timestamp"] = moment
    metadata["properties"] = [
        *[
            item for item in metadata.get("properties") or []
            if not str(item.get("name", "")).startswith(f"{property_prefix}:export")
        ],
        {"name": f"{property_prefix}:export", "value": VARIANT_VDR},
        {"name": f"{property_prefix}:export_assessment_source", "value": assessment_source},
        *(
            [{"name": f"{property_prefix}:export_tool", "value": f"DTVP {tool_version}"}]
            if tool_version else []
        ),
    ]

    refs = _component_refs(document)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding, fields in zip(findings, assessments):
        vulnerability = finding.get("vulnerability") or {}
        component = finding.get("component") or {}
        vuln_id = str(vulnerability.get("vulnId") or vulnerability.get("uuid") or "")
        if not vuln_id:
            continue
        signature = (
            vuln_id,
            fields["state"], fields["suppressed"], fields["pending_review"],
            fields["rescored_score"], fields["rescored_vector"], fields["free_text"],
            tuple(
                (team["team"], team["state"], team["justification"], team["details"],
                 team["historical"])
                for team in fields["teams"]
            ),
        )
        group = groups.setdefault(
            signature, {"vulnerability": vulnerability, "fields": fields, "refs": []}
        )
        ref = _component_ref(component, refs)
        if ref not in group["refs"]:
            group["refs"].append(ref)

    per_id: dict[str, int] = {}
    vulnerabilities: list[dict[str, Any]] = []
    annotations: list[dict[str, Any]] = list(document.get("annotations") or [])
    for signature, group in groups.items():
        vuln_id = signature[0]
        vulnerability, fields = group["vulnerability"], group["fields"]
        index = per_id.get(vuln_id, 0)
        per_id[vuln_id] = index + 1
        base_ref = str(vulnerability.get("uuid") or vuln_id)
        bom_ref = base_ref if index == 0 else f"{base_ref}#{index + 1}"
        entry: dict[str, Any] = {"bom-ref": bom_ref, "id": vuln_id}
        if vulnerability.get("source"):
            entry["source"] = {"name": str(vulnerability["source"])}
        if references := _references(vulnerability, vuln_id):
            entry["references"] = references
        ratings = [
            rating for rating in (
                _advisory_rating(vulnerability), _own_rating(fields, assessment_source)
            ) if rating
        ]
        if ratings:
            entry["ratings"] = ratings
        cwes = [
            int(cwe["cweId"]) for cwe in vulnerability.get("cwes") or []
            if isinstance(cwe, dict) and str(cwe.get("cweId", "")).isdigit()
        ]
        if cwes:
            entry["cwes"] = cwes
        for target, source in (
            ("description", "description"), ("recommendation", "recommendation"),
            ("published", "published"), ("updated", "updated"),
        ):
            if vulnerability.get(source):
                entry[target] = str(vulnerability[source])
        if analysis := _analysis(fields):
            entry["analysis"] = analysis
        entry["affects"] = [{"ref": ref} for ref in group["refs"]]
        if properties := _properties(fields, property_prefix):
            entry["properties"] = properties
        vulnerabilities.append(entry)
        annotations.extend(_annotations(fields, bom_ref, moment))

    document["vulnerabilities"] = vulnerabilities
    if annotations:
        document["annotations"] = annotations
    return document
