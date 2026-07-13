"""Verdict assembly — view builders, DT mapping, and structured report.

All functions that transform raw pipeline state into the final assessment
payload live here.  ``graph.py`` calls these after the graph completes.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _unique_nonempty(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = _clean_text(value)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _bullet_list(values: list[Any], fallback: str) -> list[str]:
    cleaned = _unique_nonempty(values)
    if not cleaned:
        return [f"- {fallback}"]
    return [f"- {value}" for value in cleaned]


def _developer_ticket_values(values: list[Any]) -> list[str]:
    internal_markers = (
        "repository clone",
        "cloned repo",
        "using local path",
        "repo_path",
        "worktree",
        "files sent",
        "source files provided",
        "analyzer runtime",
    )
    return [
        value
        for value in _unique_nonempty(values)
        if not any(marker in value.lower() for marker in internal_markers)
    ]


def _checked_version_affected_value(row: Dict[str, Any]) -> bool | None:
    version = _clean_text(row.get("component_version"))
    notes = _clean_text(row.get("notes")).lower()
    if version in {"", "-"} and (
        "not found" in notes or "no matching tag or branch" in notes
    ):
        return None
    return row.get("affected") == "YES"


def _vulnerable_dependency_name(
    *,
    final_state: Dict[str, Any],
    dep_info: Dict[str, Any],
    fallback_component: str,
) -> str:
    scan_targets = final_state.get("scan_targets") or []
    return _clean_text(
        dep_info.get("component_name")
        or (scan_targets[0] if scan_targets else "")
        or fallback_component
        or "the vulnerable dependency"
    )


# ----------------------------------------------------------------------- #
# Dependency presence helpers
# ----------------------------------------------------------------------- #


def dependency_presence_summary(dep_info: Dict[str, Any]) -> str:
    basis = dep_info.get("presence_basis")
    if basis == "direct":
        return "found as a direct dependency"
    if basis == "transitive":
        return "found as a transitive dependency"
    if basis == "sbom_attributed":
        return "present via SBOM attribution, but not rediscovered in local manifests or lock files"
    return "vulnerable component not found in the assessed project"


def dependency_presence_detail(dep_info: Dict[str, Any]) -> str:
    basis = dep_info.get("presence_basis")
    if basis == "direct":
        return "found (direct)"
    if basis == "transitive":
        return "found (transitive)"
    if basis == "sbom_attributed":
        return "found (sbom-attributed; not rediscovered locally)"
    return "NOT found (not_found)"


def dependency_presence_payload(dep_info: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "found": bool(dep_info.get("found", False)),
        "repo_found": bool(dep_info.get("repo_found", False)),
        "sbom_attributed": bool(dep_info.get("sbom_attributed", False)),
        "presence_basis": dep_info.get("presence_basis", "not_found"),
        "direct": bool(dep_info.get("direct", False)),
        "transitive": bool(dep_info.get("transitive", False)),
        "declared_in": list(dep_info.get("declared_in", [])),
        "lock_files": list(dep_info.get("lock_files", [])),
        "locked_version": dep_info.get("locked_version"),
    }


# ----------------------------------------------------------------------- #
# Dependency-Track mapping
# ----------------------------------------------------------------------- #


def map_to_dependency_track(
    verdict: str,
    affected: bool,
    exposure: str,
    adj_cvss: dict,
) -> tuple[str, str, str]:
    """Map an agentyzer verdict to Dependency-Track analysis/justification/response."""
    if verdict == "Affected":
        analysis = "EXPLOITABLE"
    elif verdict == "Probably Affected":
        analysis = "IN_TRIAGE"
    elif verdict == "Not Affected":
        analysis = "NOT_AFFECTED"
    elif verdict == "Inconclusive":
        analysis = "IN_TRIAGE"
    else:
        analysis = "NOT_SET"

    justification = "NOT_SET"
    if analysis == "NOT_AFFECTED":
        if exposure == "none":
            justification = "CODE_NOT_PRESENT"
        else:
            justification = "CODE_NOT_REACHABLE"

    if analysis == "EXPLOITABLE":
        response = "UPDATE"
    elif analysis == "IN_TRIAGE":
        response = "NOT_SET"
    else:
        response = "NOT_SET"

    return analysis, justification, response


# ----------------------------------------------------------------------- #
# Summary builders
# ----------------------------------------------------------------------- #


def build_advisory_relevance_summary(
    step_reports: Dict[str, Any],
) -> Dict[str, Any] | None:
    """Extract a stable advisory relevance summary from the filter step report."""
    filter_report = step_reports.get("filter_advisory") or {}
    findings = filter_report.get("findings") or {}
    relevant = findings.get("relevant")
    if not isinstance(relevant, bool):
        return None

    reasons = [
        str(reason).strip()
        for reason in findings.get("reasons", [])
        if str(reason).strip()
    ]
    source = (
        "llm"
        if any("LLM relevance decision" in reason for reason in reasons)
        else "rules"
    )
    return {
        "relevant": relevant,
        "status": filter_report.get("status", "unknown"),
        "source": source,
        "reasons": reasons,
    }


def build_version_analysis_summary(result: Dict[str, Any]) -> Dict[str, Any] | None:
    """Extract structured version evidence for the final assessment payload."""
    version_ctx = result.get("version_context") or {}
    version_inventory = result.get("version_inventory") or {}
    if not version_ctx and not version_inventory:
        return None

    checked_versions = []
    for row in version_inventory.get("version_table", []):
        checked_versions.append(
            {
                "ref": row.get("ref"),
                "ref_type": row.get("ref_type"),
                "product_version": row.get("product_version"),
                "version": row.get("component_version"),
                "source": row.get("source"),
                "affected": _checked_version_affected_value(row),
                "notes": row.get("notes", ""),
            }
        )

    if not checked_versions:
        detected_version = version_ctx.get("detected_version") or (
            version_inventory.get("worst_case", {}) or {}
        ).get("locked_version")
        if detected_version:
            checked_versions.append(
                {
                    "ref": "DETECTED",
                    "ref_type": "resolved",
                    "product_version": None,
                    "version": detected_version,
                    "source": version_ctx.get("version_source"),
                    "affected": version_ctx.get("affected"),
                    "notes": version_ctx.get("note", ""),
                }
            )

    return {
        "detected_version": version_ctx.get("detected_version"),
        "version_source": version_ctx.get("version_source"),
        "affected": version_ctx.get("affected"),
        "current_workspace_affected": version_ctx.get("current_workspace_affected"),
        "note": version_ctx.get("note", ""),
        "workspace_note": version_ctx.get("workspace_note", ""),
        "affected_ranges_summary": version_ctx.get("affected_ranges_summary", []),
        "comparison_inputs": version_ctx.get("comparison_inputs", {}),
        "comparison_trace": version_ctx.get("comparison_trace", []),
        "affected_product_versions": version_ctx.get("affected_product_versions", []),
        "affected_product_version_refs": version_ctx.get(
            "affected_product_version_refs", {}
        ),
        "checked_versions": checked_versions,
        "historical_affected": version_inventory.get("worst_case", {}).get(
            "historical_affected", []
        ),
    }


def _score_severity_bucket(score: float | None) -> str | None:
    if score is None:
        return None
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


_VERSION_TOKEN_RE = re.compile(r"\bv?\d+(?:\.\d+){1,5}\b", re.IGNORECASE)
_REMEDIATION_FLOOR_RE = re.compile(
    r"\b(?:upgrade|update|bump|pin|move)\b[^.:\n]{0,120}?\b(?:to|at least)\s+"
    r"(?:version\s+)?(v?\d+(?:\.\d+){1,5})\s*"
    r"(?:\+|or\s+(?:higher|newer|later)|and\s+(?:higher|newer|later))?",
    re.IGNORECASE,
)
_FIXED_VERSION_RE = re.compile(
    r"\b(?:fixed|patched|resolved)\s+(?:in|by)\s+(?:version\s+)?"
    r"(v?\d+(?:\.\d+){1,5})\b",
    re.IGNORECASE,
)


def _version_parts(value: Any) -> tuple[int, ...] | None:
    text = _clean_text(value)
    match = _VERSION_TOKEN_RE.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).lstrip("vV").split("."))


def _compare_versions(left: Any, right: Any) -> int | None:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    if not left_parts or not right_parts:
        return None
    length = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (length - len(left_parts))
    padded_right = right_parts + (0,) * (length - len(right_parts))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def _detected_version_from_reasoning(text: str) -> str | None:
    patterns = (
        re.compile(
            r"\b(?:project\s+uses|uses|detected|resolved)\b[^.:\n]{0,80}?"
            r"(v?\d+(?:\.\d+){1,5})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bversion\s+(v?\d+(?:\.\d+){1,5})\b",
            re.IGNORECASE,
        ),
    )
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _fixed_version_text_candidates(text: str) -> list[str]:
    candidates: list[Any] = []
    candidates.extend(match.group(1) for match in _REMEDIATION_FLOOR_RE.finditer(text))
    candidates.extend(match.group(1) for match in _FIXED_VERSION_RE.finditer(text))
    return _unique_nonempty(candidates)


def _claims_detected_version_affected(text: str) -> bool:
    lowered = text.lower()
    return any(
        phrase in lowered
        for phrase in (
            "within the affected range",
            "inside the affected range",
            "in the affected range",
            "is affected",
            "is vulnerable",
        )
    )


def _final_claim_text(
    result: Dict[str, Any],
    reasoning: str | None = None,
) -> str:
    return " ".join(
        _clean_text(value)
        for value in (
            reasoning,
            result.get("reasoning"),
            result.get("summary"),
        )
        if value
    )


def _has_successful_upstream_platform_research(
    final_state: Dict[str, Any] | None,
    result: Dict[str, Any] | None,
) -> bool:
    """Return whether the mandatory upstream-platform lookup produced results.

    ``required=True`` is retained as a compatibility marker for assessments
    created before research entries gained an explicit ``scope`` field.
    """
    state_result = ((final_state or {}).get("result") or {})
    research_log = (result or {}).get("research_log") or state_result.get(
        "research_log"
    )
    if not isinstance(research_log, list):
        return False

    failure_markers = (
        "--- fetch failed:",
        "--- search failed:",
        "--- package lookup failed:",
        "--- source fetch failed:",
        "--- tool call failed:",
    )
    supported_directives = {"search", "url", "package", "source"}

    for entry in research_log:
        if not isinstance(entry, dict):
            continue
        scope = _clean_text(entry.get("scope")).lower()
        is_upstream_lookup = scope == "upstream_platform" or (
            not scope and entry.get("required") is True
        )
        if not is_upstream_lookup:
            continue
        directives = entry.get("directives") or []
        if not any(
            isinstance(directive, dict)
            and _clean_text(directive.get("type")).lower()
            in supported_directives
            for directive in directives
        ):
            continue
        summary = _clean_text(entry.get("results_summary"))
        if summary and not any(marker in summary.lower() for marker in failure_markers):
            return True

    return False


def _build_evidence_claims(
    version_analysis: Dict[str, Any] | None,
    final_state: Dict[str, Any] | None,
    result: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    state = final_state or {}
    dep_info = state.get("dep_info") or {}
    llm_analysis = state.get("llm_analysis") or {}
    deep_analysis = state.get("deep_analysis") or {}
    transitive_analysis = state.get("transitive_analysis") or {}
    deep_exploitable = str(deep_analysis.get("exploitable", "")).upper()
    transitive_reachable = str(transitive_analysis.get("reachable", "")).upper()
    any_version_affected = bool(version_analysis and version_analysis.get("affected"))
    current_workspace_affected = (
        (version_analysis or {}).get("current_workspace_affected")
        if version_analysis
        else None
    )
    historical_only_affected = bool(
        any_version_affected and current_workspace_affected is False
    )
    version_excludes_all = bool(
        version_analysis
        and version_analysis.get("affected") is False
        and current_workspace_affected is False
    )
    direct_reachable = bool(llm_analysis.get("reachable"))
    deep_conflict = deep_exploitable in {"YES", "LIKELY"}
    transitive_positive = transitive_reachable in {"YES", "LIKELY"}
    transitive_unexcluded = transitive_reachable in {"YES", "LIKELY", "UNCERTAIN"}
    workspace_exclusion_evidence = (
        llm_analysis.get("reachable") is False
        and not deep_conflict
        and not transitive_unexcluded
    )
    upstream_platform_research = _has_successful_upstream_platform_research(
        final_state,
        result,
    )
    upstream_platform_support = bool(
        dep_info.get("sbom_attributed") and upstream_platform_research
    )
    confirmed_affected_path = bool(
        direct_reachable
        or (deep_analysis.get("confirmed") and deep_conflict)
        or transitive_positive
    )

    return {
        "detected_version": _clean_text(
            (version_analysis or {}).get("detected_version")
            or ((result or {}).get("version_context") or {}).get("detected_version")
        ),
        "any_version_affected": any_version_affected,
        "current_workspace_affected": current_workspace_affected,
        "historical_only_affected": historical_only_affected,
        "version_excludes_all": version_excludes_all,
        "direct_reachable": direct_reachable,
        "deep_confirmed": bool(deep_analysis.get("confirmed")),
        "deep_conflict": deep_conflict,
        "transitive_positive": transitive_positive,
        "transitive_unexcluded": transitive_unexcluded,
        "confirmed_affected_path": confirmed_affected_path,
        "workspace_exclusion_evidence": workspace_exclusion_evidence,
        "dependency_evidence": bool(
            dep_info.get("found") or dep_info.get("sbom_attributed")
        ),
        "upstream_platform_research": upstream_platform_research,
        "upstream_platform_support": upstream_platform_support,
    }


def _build_verdict_claims(result: Dict[str, Any]) -> Dict[str, Any]:
    verdict = _clean_text(result.get("verdict")) or "Inconclusive"
    return {
        "verdict": verdict,
        "affected": bool(result.get("affected")),
        "claims_affected": verdict in {"Affected", "Probably Affected"}
        or bool(result.get("affected")),
        "claims_not_affected": verdict == "Not Affected",
        "confidence": _clean_text(result.get("confidence")),
        "exposure": _clean_text(result.get("exposure")),
    }


def _build_text_claims(
    result: Dict[str, Any],
    reasoning: str | None = None,
) -> Dict[str, Any]:
    text = _final_claim_text(result, reasoning)
    return {
        "current_version_affected": _claims_detected_version_affected(text),
        "detected_version": _clean_text(_detected_version_from_reasoning(text)),
        "fixed_version_floors": _fixed_version_text_candidates(text),
    }


def _claim_issue(
    *,
    kind: str,
    severity: str,
    claim: Dict[str, Any],
    evidence: Dict[str, Any],
    detail: str,
) -> Dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "claim": claim,
        "evidence": evidence,
        "detail": detail,
    }


def _not_affected_guardrail_reasons(evidence: Dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if evidence["direct_reachable"]:
        reasons.append("direct reachability was reported")
    if evidence["deep_conflict"]:
        reasons.append("deep analysis reported a still-exploitable path")
    if evidence["current_workspace_affected"] is True:
        reasons.append("the current detected version is in the affected range")
    elif evidence["historical_only_affected"]:
        reasons.append("tracked historical releases shipped an affected version")
    elif evidence["any_version_affected"]:
        reasons.append("version analysis still includes affected releases")
    if evidence["transitive_unexcluded"]:
        reasons.append("transitive reachability was not fully excluded")
    return reasons


def _validate_final_claims(
    *,
    evidence: Dict[str, Any],
    verdict: Dict[str, Any],
    text: Dict[str, Any],
) -> list[Dict[str, Any]]:
    issues: list[Dict[str, Any]] = []

    if (
        text["current_version_affected"]
        and evidence["current_workspace_affected"] is False
        and not (
            evidence["upstream_platform_support"]
            and not text.get("detected_version")
        )
    ):
        issues.append(
            _claim_issue(
                kind="text_affected_conflicts_with_version_evidence",
                severity="fail",
                claim={
                    "current_version_affected": True,
                    "source": "final_reasoning",
                },
                evidence={
                    "current_workspace_affected": False,
                    "detected_version": evidence.get("detected_version")
                    or text.get("detected_version"),
                },
                detail=(
                    "final reasoning claims the current version is affected, "
                    "but structured version evidence says the current workspace "
                    "is outside the affected range"
                ),
            )
        )

    if text["current_version_affected"] or evidence["current_workspace_affected"] is True:
        detected_version = _clean_text(
            evidence.get("detected_version") or text.get("detected_version")
        )
        for fixed_version in text["fixed_version_floors"]:
            comparison = _compare_versions(detected_version, fixed_version)
            if comparison is not None and comparison >= 0:
                issues.append(
                    _claim_issue(
                        kind="fixed_version_floor_contradiction",
                        severity="fail",
                        claim={
                            "current_version_affected": True,
                            "fixed_version_floor": fixed_version,
                        },
                        evidence={"detected_version": detected_version},
                        detail=(
                            f"detected version {detected_version} is already at "
                            f"or above the stated fixed version floor {fixed_version}"
                        ),
                    )
                )

    if verdict["claims_not_affected"]:
        reasons = _not_affected_guardrail_reasons(evidence)
        if evidence["workspace_exclusion_evidence"]:
            version_reasons = {
                "the current detected version is in the affected range",
                "tracked historical releases shipped an affected version",
                "version analysis still includes affected releases",
            }
            reasons = [
                reason
                for reason in reasons
                if reason not in version_reasons
            ]
        if reasons:
            issues.append(
                _claim_issue(
                    kind="unsupported_not_affected",
                    severity="fail",
                    claim={
                        "verdict": verdict["verdict"],
                        "affected": verdict["affected"],
                    },
                    evidence={"reasons": reasons},
                    detail="; ".join(reasons),
                )
            )

    if (
        verdict["claims_affected"]
        and not evidence["confirmed_affected_path"]
        and not evidence["upstream_platform_support"]
        and (
            evidence["version_excludes_all"]
            or not evidence["any_version_affected"]
        )
    ):
        if evidence["version_excludes_all"]:
            detail = (
                "version evidence excludes the affected range and no "
                "reachability, deep-analysis, or transitive-path evidence "
                "supports an affected verdict"
            )
        else:
            detail = (
                "no affected version, direct reachability, confirmed deep "
                "exploitability, or positive transitive path supports an "
                "affected verdict"
            )
        issues.append(
            _claim_issue(
                kind="unsupported_affected",
                severity="fail",
                claim={"verdict": verdict["verdict"], "affected": verdict["affected"]},
                evidence={
                    "version_excludes_all": evidence["version_excludes_all"],
                    "any_version_affected": evidence["any_version_affected"],
                    "direct_reachable": False,
                    "deep_conflict": False,
                    "transitive_unexcluded": evidence["transitive_unexcluded"],
                },
                detail=detail,
            )
        )

    if (
        verdict["claims_affected"]
        and evidence["any_version_affected"]
        and evidence["dependency_evidence"]
        and not evidence["confirmed_affected_path"]
        and (
            verdict["verdict"] == "Affected"
            or verdict["confidence"] == "High"
        )
    ):
        issues.append(
            _claim_issue(
                kind="affected_without_confirmed_path",
                severity="fail",
                claim={
                    "verdict": verdict["verdict"],
                    "affected": verdict["affected"],
                    "confidence": verdict["confidence"],
                },
                evidence={
                    "any_version_affected": True,
                    "dependency_evidence": True,
                    "direct_reachable": False,
                    "deep_confirmed_exploitable": False,
                    "transitive_positive": False,
                },
                detail=(
                    "an affected-range dependency version is present, but no "
                    "direct reachability, confirmed deep exploitability, or "
                    "positive transitive path establishes use of the vulnerable "
                    "surface"
                ),
            )
        )

    return issues


def build_final_claims(
    *,
    result: Dict[str, Any],
    version_analysis: Dict[str, Any] | None,
    final_state: Dict[str, Any] | None = None,
    reasoning: str | None = None,
) -> Dict[str, Any]:
    """Normalize final verdict, prose, and pipeline evidence into comparable claims."""
    evidence_claims = _build_evidence_claims(version_analysis, final_state, result)
    verdict_claims = _build_verdict_claims(result)
    text_claims = _build_text_claims(result, reasoning)
    if not evidence_claims.get("detected_version"):
        evidence_claims["detected_version"] = text_claims.get("detected_version")
    issues = _validate_final_claims(
        evidence=evidence_claims,
        verdict=verdict_claims,
        text=text_claims,
    )
    return {
        "evidence": evidence_claims,
        "verdict": verdict_claims,
        "text": text_claims,
        "issues": issues,
    }


def _claim_issue_check(issue: Dict[str, Any]) -> str:
    detail = _clean_text(issue.get("detail"))
    kind = issue.get("kind")
    if kind == "fixed_version_floor_contradiction":
        return "Concern: final claims are inconsistent: " + detail + "."
    if kind == "text_affected_conflicts_with_version_evidence":
        return "Concern: final reasoning conflicts with version evidence: " + detail + "."
    if kind == "unsupported_not_affected":
        return "Concern: final Not Affected claim is unsupported by evidence: " + detail + "."
    if kind == "unsupported_affected":
        return "Concern: final affected claim is unsupported by evidence: " + detail + "."
    if kind == "affected_without_confirmed_path":
        return "Concern: final Affected claim overstates version-only evidence: " + detail + "."
    return "Concern: final claim issue: " + detail + "."


def _claim_issue_details(
    issues: list[Dict[str, Any]],
    *kinds: str,
) -> list[str]:
    wanted = set(kinds)
    return _unique_nonempty(
        [
            issue.get("detail")
            for issue in issues
            if not wanted or issue.get("kind") in wanted
        ]
    )


def _claim_issues_from_audit_view(
    audit_view: Dict[str, Any] | None,
) -> list[Dict[str, Any]]:
    final_claims = (audit_view or {}).get("final_claims") or {}
    issues = (
        final_claims.get("issues") or (audit_view or {}).get("claim_issues") or []
    )
    return [issue for issue in issues if isinstance(issue, dict)]


def _final_claims_from_audit_view(
    audit_view: Dict[str, Any] | None,
    *,
    result: Dict[str, Any],
    version_analysis: Dict[str, Any] | None,
    final_state: Dict[str, Any] | None,
) -> Dict[str, Any]:
    final_claims = (audit_view or {}).get("final_claims")
    if isinstance(final_claims, dict) and "issues" in final_claims:
        return final_claims
    return build_final_claims(
        result=result,
        version_analysis=version_analysis,
        final_state=final_state,
    )


# ----------------------------------------------------------------------- #
# View builders
# ----------------------------------------------------------------------- #


def build_researcher_view(
    *,
    final_state: Dict[str, Any],
    advisory_relevance: Dict[str, Any] | None,
    version_analysis: Dict[str, Any] | None,
    verdict_label: str,
    reasoning: str,
) -> Dict[str, Any]:
    """Summarize the initial researcher / analyst pass."""
    dep_info = final_state.get("dep_info") or {}
    llm_analysis = final_state.get("llm_analysis") or {}
    deep_analysis = final_state.get("deep_analysis") or {}
    transitive_analysis = final_state.get("transitive_analysis") or {}

    findings: list[str] = []

    if advisory_relevance:
        findings.append(
            "Advisory relevance: "
            + (
                f"relevant via {advisory_relevance.get('source', 'rules')}"
                if advisory_relevance.get("relevant", True)
                else f"filtered out via {advisory_relevance.get('source', 'rules')}"
            )
        )

    findings.append("Dependency presence: " + dependency_presence_summary(dep_info))

    if version_analysis and version_analysis.get("detected_version"):
        if version_analysis.get("affected") and not version_analysis.get(
            "current_workspace_affected", version_analysis.get("affected")
        ):
            findings.append(
                f"Version check: workspace version {version_analysis['detected_version']} "
                f"({version_analysis.get('version_source', 'unknown')}) is outside the advisory range, "
                "but one or more tracked releases shipped an affected version"
            )
        else:
            findings.append(
                f"Version check: {version_analysis['detected_version']} "
                f"({version_analysis.get('version_source', 'unknown')}) is "
                + (
                    "inside"
                    if version_analysis.get(
                        "current_workspace_affected", version_analysis.get("affected")
                    )
                    else "outside"
                )
                + " the advisory range"
            )

    if llm_analysis:
        findings.append(
            "Direct reachability: "
            + (
                "reachable from production code"
                if llm_analysis.get("reachable")
                else "no direct production reachability confirmed"
            )
        )

    if deep_analysis and not deep_analysis.get("skipped"):
        findings.append(
            "Deep analysis: confirmed="
            f"{deep_analysis.get('confirmed', 'N/A')}, exploitable="
            f"{deep_analysis.get('exploitable', 'N/A')}"
        )

    if transitive_analysis and not transitive_analysis.get("skipped"):
        findings.append(
            f"Transitive path review: {transitive_analysis.get('reachable', 'N/A')}"
        )

    conclusion = reasoning or f"Research conclusion: {verdict_label}."
    return {
        "objective": "Find the weakness, determine exposure, and check whether the assessed application is actually affected.",
        "target_outcome": "Prefer an evidence-backed Not Affected / low-info outcome when the current codebase can be excluded.",
        "findings": findings,
        "conclusion": conclusion,
    }


def build_remediation_view(
    *,
    final_state: Dict[str, Any],
    verdict_label: str,
    adjusted_cvss: Dict[str, Any],
    version_analysis: Dict[str, Any] | None,
    exposure: str,
    audit_view: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Summarize the remediation pass with focus on reaching low/info."""
    what_if = final_state.get("what_if") or {}
    dep_info = final_state.get("dep_info") or {}
    vulnerable_dependency = _vulnerable_dependency_name(
        final_state=final_state,
        dep_info=dep_info,
        fallback_component=final_state.get("component_name", ""),
    )
    score = adjusted_cvss.get("adjusted_score")
    severity = _score_severity_bucket(score)
    recommendations: list[str] = []

    audit_status = (audit_view or {}).get("status")

    if verdict_label == "Not Affected" and audit_status == "fail":
        status = "action_needed"
        summary = (
            "The current Not Affected downgrade is not sufficiently supported by the "
            "available evidence. Treat the downgrade as failed until stronger exclusion "
            "evidence or a code/configuration fix is available."
        )
        recommendations.extend(
            [
                "Collect affirmative exclusion evidence for the current codebase, such as a non-affected version, unreachable code path, or effective runtime guard.",
                "If that evidence cannot be produced, avoid relying on the downgrade and remediate the dependency or code path instead.",
            ]
        )
    elif verdict_label == "Not Affected":
        status = "already_not_affected"
        summary = (
            "Current evidence already supports Not Affected. Preserve the exclusion "
            "conditions and re-run the assessment after dependency or code changes."
        )
    elif severity in {"info", "low"}:
        status = "already_low_or_info"
        summary = (
            f"Current rescored severity is already {severity}. Additional remediation "
            "is optional unless policy requires a full Not Affected disposition."
        )
    else:
        status = "action_needed"
        if what_if and not what_if.get("component_not_found", True):
            for option in what_if.get("remediation", []):
                change = option.get("change", "").strip()
                target = option.get("target_version") or "a fixed version"
                recommendation = f"Upgrade {vulnerable_dependency} to {target}"
                if change:
                    recommendation += f" ({change})"
                recommendations.append(recommendation)

        if (
            not recommendations
            and version_analysis
            and version_analysis.get("affected")
        ):
            recommendations.append(
                f"Move the resolved {vulnerable_dependency} version outside the advisory's affected range and rerun the analysis."
            )
        if exposure == "transitive":
            recommendations.append(
                f"Upgrade or replace the direct parent/intermediary dependency that resolves {vulnerable_dependency}, then verify that the transitive call path disappears."
            )
        elif exposure == "direct":
            recommendations.append(
                f"Upgrade, remove, or isolate {vulnerable_dependency} and verify the vulnerable path is no longer reachable."
            )
        recommendations.append(
            "Rerun Agentyzer after remediation to confirm a Not Affected or low/info rescoring outcome."
        )
        summary = (
            "The current assessment does not yet justify a low/info outcome. Use the "
            "recommended changes to eliminate reachability or move the assessed version "
            "outside the affected range."
        )

    return {
        "objective": "Reduce the finding to low/info when supportable, ideally by proving the current codebase is Not Affected.",
        "status": status,
        "summary": summary,
        "recommendations": list(dict.fromkeys(recommendations)),
    }


def build_developer_ticket_text(
    *,
    vuln_id: str,
    component_name: str,
    final_state: Dict[str, Any],
    verdict_label: str,
    confidence: str,
    affected: bool,
    exposure: str,
    reasoning: str,
    advisories: Dict[str, Any],
    dep_info: Dict[str, Any],
    version_analysis: Dict[str, Any] | None,
    researcher_view: Dict[str, Any] | None,
    remediation_view: Dict[str, Any] | None,
    audit_view: Dict[str, Any] | None,
    adjusted_cvss: Dict[str, Any] | None = None,
) -> str:
    """Build a developer-focused ticket without pipeline/runtime internals."""
    component = _clean_text(component_name) or "the assessed component"
    vulnerable_dependency = _vulnerable_dependency_name(
        final_state=final_state,
        dep_info=dep_info,
        fallback_component=component,
    )
    advisory_summary = _clean_text(advisories.get("summary"))
    detected_version = _clean_text(
        dep_info.get("locked_version")
        or (version_analysis or {}).get("detected_version")
    )
    version_note = _clean_text(
        (version_analysis or {}).get("workspace_note")
        or (version_analysis or {}).get("note")
    )
    affected_ranges = _unique_nonempty(
        (version_analysis or {}).get("affected_ranges_summary", [])
    )
    affected_product_versions = _unique_nonempty(
        (version_analysis or {}).get("affected_product_versions", [])
    )
    llm_analysis = final_state.get("llm_analysis") or {}
    deep_analysis = final_state.get("deep_analysis") or {}
    transitive_analysis = final_state.get("transitive_analysis") or {}

    attack_evidence = _developer_ticket_values(
        [
            *list(llm_analysis.get("invocation_paths") or [])[:3],
            *list(transitive_analysis.get("dependency_chains") or [])[:3],
            deep_analysis.get("reasoning"),
            transitive_analysis.get("reasoning"),
            llm_analysis.get("reasoning"),
            reasoning,
        ]
    )[:5]

    findings = _unique_nonempty((researcher_view or {}).get("findings", []))[:5]
    audit_checks = _unique_nonempty((audit_view or {}).get("checks", []))[:3]
    recommendations = _unique_nonempty(
        (remediation_view or {}).get("recommendations", [])
    )
    if not recommendations:
        if exposure == "transitive":
            recommendations = [
                f"Upgrade or replace the direct parent/intermediary dependency that resolves {vulnerable_dependency}.",
                f"Pin or override {vulnerable_dependency} to a fixed version if the package manager and product policy allow it.",
            ]
        elif exposure == "direct":
            recommendations = [
                f"Upgrade, remove, or isolate {vulnerable_dependency}.",
                "Add input validation, configuration guards, or a safe wrapper if the dependency cannot be upgraded immediately.",
            ]
        else:
            recommendations = [
                f"Confirm whether {component} resolves {vulnerable_dependency}; remediate the dependency path if it does.",
            ]

    if exposure == "transitive" and not any(
        "parent" in recommendation.lower() or "intermediary" in recommendation.lower()
        for recommendation in recommendations
    ):
        recommendations.append(
            f"Prioritize the direct parent/intermediary dependency that resolves {vulnerable_dependency}; {component} itself only needs code/configuration changes if mitigation is required."
        )
    elif exposure == "direct" and not any(
        vulnerable_dependency.lower() in recommendation.lower()
        for recommendation in recommendations
    ):
        recommendations.append(
            f"Target the vulnerable dependency {vulnerable_dependency}; {component} itself only needs code/configuration changes if mitigation is required."
        )

    validation = [
        f"Verify the dependency tree for {component} no longer resolves an affected {vulnerable_dependency} version.",
        "Rerun the code analysis or equivalent regression test for the cited call path or dependency chain.",
        "Attach the updated dependency tree/SBOM and validation result before closing the ticket.",
    ]

    cvss = adjusted_cvss or {}
    priority = []
    if cvss.get("adjusted_score") is not None:
        priority.append(f"CVSS after environment review: {cvss.get('adjusted_score')}")
    if cvss.get("summary"):
        priority.append(cvss.get("summary"))

    lines = [
        f"Title: Remediate {vuln_id or 'the vulnerability'} in {component} via {vulnerable_dependency}",
        "",
        "Description",
        f"{component} is assessed as {verdict_label} ({confidence} confidence) for {vuln_id or 'the vulnerability'} because it includes or reaches {vulnerable_dependency}.",
    ]
    if advisory_summary:
        lines.append(f"Advisory summary: {advisory_summary}")

    lines.extend(
        [
            "",
            "Affected Surface",
            f"- Component/application: {component}",
            f"- Vulnerable dependency: {vulnerable_dependency}",
            f"- Exposure: {exposure or 'unknown'}",
            f"- Resolved version: {detected_version or 'not reported'}",
        ]
    )
    if version_note:
        lines.append(f"- Version assessment: {version_note}")
    if affected_product_versions:
        shown_versions = ", ".join(affected_product_versions[:12])
        suffix = " ..." if len(affected_product_versions) > 12 else ""
        lines.append(f"- Product versions checked: {shown_versions}{suffix}")
    if priority:
        lines.extend(_bullet_list(priority, "No CVSS adjustment reported"))

    lines.extend(["", "Evidence"])
    lines.extend(_bullet_list(findings, "No summarized findings were reported"))
    if affected_ranges:
        lines.extend(_bullet_list(affected_ranges[:3], "No affected range reported"))
    if attack_evidence:
        lines.append("- Attack path or dependency chain: " + " | ".join(attack_evidence))
    if audit_checks:
        lines.extend(_bullet_list(audit_checks, "No audit checks were reported"))

    lines.extend(["", "Remediation"])
    lines.extend(_bullet_list(recommendations, "No remediation recommendation reported"))

    lines.extend(["", "Validation"])
    lines.extend(_bullet_list(validation, "Rerun dependency and reachability analysis"))

    if not affected:
        lines.extend(
            [
                "",
                "Closure Note",
                "- The current assessment is not affected; preserve the evidence that supports that conclusion and rerun analysis after dependency or code changes.",
            ]
        )

    return "\n".join(lines)


def build_audit_view(
    *,
    final_state: Dict[str, Any],
    verdict_label: str,
    affected: bool,
    reasoning: str,
    version_analysis: Dict[str, Any] | None,
    adjusted_cvss: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Summarize the final critical review of the evidence and verdict."""
    dep_info = final_state.get("dep_info") or {}
    llm_analysis = final_state.get("llm_analysis") or {}
    deep_analysis = final_state.get("deep_analysis") or {}
    transitive_analysis = final_state.get("transitive_analysis") or {}

    checks: list[str] = []
    strengths = 0
    concerns = 0
    score_bucket = _score_severity_bucket((adjusted_cvss or {}).get("adjusted_score"))
    downgrade_target = verdict_label == "Not Affected" or score_bucket in {
        "info",
        "low",
    }
    historical_only_affected = bool(
        version_analysis
        and version_analysis.get("affected")
        and version_analysis.get("current_workspace_affected") is False
    )
    workspace_exclusion_evidence = (
        llm_analysis.get("reachable") is False
        and transitive_analysis.get("reachable") not in {"YES", "LIKELY", "UNCERTAIN"}
        and str(deep_analysis.get("exploitable", "")).upper() not in {"YES", "LIKELY"}
    )
    final_claims = build_final_claims(
        result={
            "verdict": verdict_label,
            "affected": affected,
            "reasoning": reasoning,
        },
        version_analysis=version_analysis,
        final_state=final_state,
        reasoning=reasoning,
    )
    claim_issues = _claim_issues_from_audit_view({"final_claims": final_claims})

    if verdict_label == "Not Affected":
        if not dep_info.get("found", False) and not dep_info.get(
            "sbom_attributed", False
        ):
            checks.append(
                "Supports verdict: the vulnerable component was not found in the assessed project."
            )
            strengths += 1
        if (
            version_analysis
            and version_analysis.get("affected") is False
            and version_analysis.get("current_workspace_affected") is False
        ):
            checks.append(
                "Supports verdict: the current detected version is outside the advisory range."
            )
            strengths += 1
        elif historical_only_affected:
            if workspace_exclusion_evidence:
                checks.append(
                    "Supports verdict: tracked historical releases were affected, but the current workspace affirmatively excludes reachability of the affected functionality."
                )
                strengths += 1
            else:
                checks.append(
                    "Concern: the current workspace is patched, but tracked historical releases still shipped an affected version."
                )
                concerns += 1
        elif (
            version_analysis
            and version_analysis.get("current_workspace_affected")
            and workspace_exclusion_evidence
        ):
            checks.append(
                "Supports verdict: the current workspace version is within the "
                "affected range, but reachability and deep analysis affirmatively "
                "exclude the vulnerable code path in this codebase."
            )
            strengths += 1
        if transitive_analysis.get("reachable") in {"YES", "LIKELY", "UNCERTAIN"}:
            checks.append(
                "Concern: transitive analysis did not fully exclude an intermediary path, so the downgrade remains weaker."
            )
            concerns += 1
        if llm_analysis.get("reachable"):
            checks.append(
                "Concern: direct reachability was reported, which conflicts with a Not Affected outcome."
            )
            concerns += 1
        if str(deep_analysis.get("exploitable", "")).upper() in {"YES", "LIKELY"}:
            checks.append(
                "Concern: deep analysis still describes an exploitable path, which conflicts with Not Affected."
            )
            concerns += 1
    else:
        upstream_platform_support = bool(
            final_claims.get("evidence", {}).get("upstream_platform_support")
        )
        if upstream_platform_support:
            checks.append(
                "Supports verdict scope: the vulnerable dependency is SBOM-attributed even though it was not rediscovered in the local codebase."
            )
            strengths += 1
            checks.append(
                "Supports verdict: mandatory external research returned evidence about the analyst-identified upstream platform/runtime."
            )
            strengths += 1
        if version_analysis and version_analysis.get("affected"):
            if version_analysis.get("current_workspace_affected", True):
                checks.append(
                    "Supports verdict: the current detected version remains within the affected range."
                )
            else:
                checks.append(
                    "Supports verdict: tracked historical releases shipped an affected version even though the current workspace is patched."
                )
            strengths += 1
        if llm_analysis.get("reachable"):
            checks.append(
                "Supports verdict: direct production reachability was identified."
            )
            strengths += 1
        if transitive_analysis.get("reachable") in {"YES", "LIKELY", "UNCERTAIN"}:
            checks.append(
                "Supports verdict: transitive analysis found a plausible intermediary path."
            )
            strengths += 1
        if version_analysis and version_analysis.get("affected") is False and affected:
            if upstream_platform_support:
                checks.append(
                    "Scope note: local version analysis excludes the checked codebase, but it does not exclude the separately researched upstream platform/runtime."
                )
            else:
                checks.append(
                    "Concern: the version analysis says the current codebase is outside range, so the impact verdict may be overstated."
                )
                concerns += 1

    for issue in claim_issues:
        checks.append(_claim_issue_check(issue))
        concerns += 1

    if strengths >= 2 and concerns == 0:
        consistency = "strong"
    elif concerns <= 1:
        consistency = "mixed"
    else:
        consistency = "weak"

    if verdict_label == "Not Affected":
        downgrade_supported = strengths > 0 and concerns == 0
        status = "pass" if downgrade_supported else "fail"
    elif consistency == "strong":
        downgrade_supported = not downgrade_target or concerns == 0
        status = "pass"
    elif consistency == "mixed":
        downgrade_supported = False
        status = "review"
    else:
        downgrade_supported = False
        status = "fail"

    conclusion = (
        "The available evidence is internally consistent with the current verdict."
        if consistency == "strong"
        else "The verdict is plausible but still depends on assumptions or incomplete exclusion evidence."
        if consistency == "mixed"
        else "The verdict has meaningful contradictions and should be reviewed before relying on the downgrade."
    )
    if reasoning:
        conclusion = f"{conclusion} {reasoning}".strip()

    return {
        "objective": "Challenge the assessment and verify that the conclusion really matches the available evidence.",
        "status": status,
        "consistency": consistency,
        "downgrade_target": downgrade_target,
        "downgrade_supported": downgrade_supported,
        "checks": checks,
        "final_claims": final_claims,
        "claim_issues": claim_issues,
        "conclusion": conclusion,
    }


def build_audit_summary_emphasis(
    audit_view: Dict[str, Any] | None,
    base_summary: str,
) -> str:
    """Make weak downgrade states impossible to miss in the top-level summary."""
    if not audit_view or not audit_view.get("downgrade_target"):
        return base_summary

    status = audit_view.get("status")
    conclusion = audit_view.get("conclusion", "").strip()
    if status == "fail":
        lead = (
            "AUDIT FAILURE: the downgrade to Not Affected / low-info is not "
            "supported by the available evidence."
        )
    elif status == "review":
        lead = (
            "AUDIT REVIEW REQUIRED: the downgrade to Not Affected / low-info "
            "remains provisional."
        )
    else:
        return base_summary

    tail = base_summary or conclusion
    return f"{lead} {tail}".strip()


def _prepend_guardrail_reasoning(
    result: Dict[str, Any],
    note: str,
) -> None:
    original_reasoning = str(result.get("reasoning", "")).strip()
    result["reasoning"] = (
        f"{note} {original_reasoning}".strip()
        if original_reasoning
        else note
    )


def _restore_original_cvss(result: Dict[str, Any], reason: str) -> None:
    adjusted_cvss = result.get("adjusted_cvss") or {}
    original_score = adjusted_cvss.get("original_score")
    if adjusted_cvss and original_score is not None:
        restored = dict(adjusted_cvss)
        restored["adjusted_score"] = original_score
        restored["adjusted_vector"] = restored.get("original_vector")
        reasons = list(restored.get("reasons") or [])
        reasons.insert(
            0,
            reason,
        )
        restored["reasons"] = reasons
        restored["summary"] = (
            f"{restored.get('original_score')} → {restored.get('adjusted_score')} "
            f"({'; '.join(reasons)})"
        )
        result["adjusted_cvss"] = restored


def apply_audit_guardrail(
    result: Dict[str, Any],
    audit_view: Dict[str, Any] | None,
    version_analysis: Dict[str, Any] | None,
    final_state: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run the final contradiction/consistency guard before emitting a verdict."""
    final_claims = _final_claims_from_audit_view(
        audit_view,
        result=result,
        version_analysis=version_analysis,
        final_state=final_state,
    )
    claim_issues = final_claims.get("issues") or []
    evidence = final_claims.get("evidence") or {}
    fixed_version_contradictions = _claim_issue_details(
        claim_issues,
        "fixed_version_floor_contradiction",
        "text_affected_conflicts_with_version_evidence",
    )
    if (
        result.get("verdict") in {"Affected", "Probably Affected"}
        and fixed_version_contradictions
    ):
        guarded = dict(result)
        guarded["verdict"] = "Inconclusive"
        guarded["affected"] = False
        guarded["confidence"] = "Low"
        guarded["summary"] = (
            "Final sanity check found a version contradiction in the final "
            "reasoning: "
            + "; ".join(fixed_version_contradictions)
            + "."
        )
        _prepend_guardrail_reasoning(
            guarded,
            "[AUDIT GUARDRAIL / FINAL SANITY CHECK: "
            + "; ".join(fixed_version_contradictions)
            + "]",
        )
        return guarded

    upstream_platform_only = bool(
        evidence.get("upstream_platform_support")
        and evidence.get("version_excludes_all")
        and not evidence.get("direct_reachable")
        and not evidence.get("deep_conflict")
        and not evidence.get("transitive_positive")
    )
    if upstream_platform_only and (
        result.get("verdict") == "Affected"
        or (
            result.get("verdict") == "Probably Affected"
            and result.get("confidence") == "High"
        )
    ):
        guarded = dict(result)
        guarded["verdict"] = "Probably Affected"
        guarded["affected"] = True
        guarded["confidence"] = "Medium"
        if guarded.get("exposure") in {None, "", "none"}:
            guarded["exposure"] = "transitive"
        guarded["summary"] = (
            "Mandatory upstream-platform research supports possible transitive "
            "exposure, while local version and reachability analysis cannot "
            "confirm the deployed upstream runtime."
        )
        _prepend_guardrail_reasoning(
            guarded,
            "[AUDIT GUARDRAIL / UPSTREAM PLATFORM SCOPE: external research "
            "supports a Probably Affected platform verdict, but local evidence "
            "does not support a confirmed Affected verdict]",
        )
        return guarded

    version_only_reasons = _claim_issue_details(
        claim_issues,
        "affected_without_confirmed_path",
    )
    if version_only_reasons:
        guarded = dict(result)
        guarded["verdict"] = "Probably Affected"
        guarded["affected"] = True
        guarded["confidence"] = "Medium"
        guarded["summary"] = (
            "An affected-range dependency version is present, but confirmed "
            "use of the vulnerability-specific surface is still missing."
        )
        _prepend_guardrail_reasoning(
            guarded,
            "[AUDIT GUARDRAIL / VERSION-ONLY EVIDENCE: the affected version "
            "supports Probably Affected, but Affected requires confirmed "
            "reachability or exploitability]",
        )
        return guarded

    if not audit_view or audit_view.get("status") not in {"fail", "review"}:
        return result

    verdict = result.get("verdict")

    if verdict == "Not Affected" and audit_view.get("status") == "fail":
        reasons = _claim_issue_details(claim_issues, "unsupported_not_affected")
        if not reasons:
            reasons = _not_affected_guardrail_reasons(evidence)
        if not reasons:
            reasons = ["the final audit found the Not Affected downgrade unsupported"]

        guarded = dict(result)
        target_verdict = (
            "Affected"
            if evidence["deep_confirmed"] and evidence["deep_conflict"]
            else "Probably Affected"
        )
        guarded["verdict"] = target_verdict
        guarded["affected"] = True
        guarded["confidence"] = "High" if target_verdict == "Affected" else "Medium"
        if evidence["direct_reachable"]:
            guarded["exposure"] = "direct"
        elif evidence["transitive_unexcluded"] or guarded.get("exposure") == "none":
            guarded["exposure"] = "transitive"
        guarded["summary"] = (
            "Final sanity check found contradictions in the Not Affected "
            "downgrade: "
            + "; ".join(reasons)
            + "."
        )
        _prepend_guardrail_reasoning(
            guarded,
            "[AUDIT GUARDRAIL / FINAL SANITY CHECK: "
            + "; ".join(reasons)
            + "]",
        )
        _restore_original_cvss(
            guarded,
            "final sanity check removed the unsupported not-affected downgrade",
        )
        return guarded

    if (
        verdict in {"Affected", "Probably Affected"}
        and _claim_issue_details(claim_issues, "unsupported_affected")
    ):
        reasons = _claim_issue_details(claim_issues, "unsupported_affected")
        guarded = dict(result)
        guarded["verdict"] = "Inconclusive"
        guarded["affected"] = False
        guarded["confidence"] = "Low"
        guarded["summary"] = (
            "Final sanity check found that the affected verdict was not "
            "supported by version, reachability, deep-analysis, or transitive "
            "evidence: "
            + "; ".join(reasons)
            + "."
        )
        _prepend_guardrail_reasoning(
            guarded,
            "[AUDIT GUARDRAIL / FINAL SANITY CHECK: "
            + "; ".join(reasons)
            + "]",
        )
        return guarded

    return result


def _append_audit_details_emphasis(
    lines: list[str],
    audit_view: Dict[str, Any] | None,
) -> None:
    """Insert a prominent banner for downgrade failures/reviews near the top of DT details."""
    if not audit_view or not audit_view.get("downgrade_target"):
        return

    status = audit_view.get("status")
    if status not in {"fail", "review"}:
        return

    if status == "fail":
        lines.append("AUDIT STATUS:   FAIL")
        lines.append(
            "REVIEW NOTE:    Do not rely on the downgrade to Not Affected / low-info until stronger exclusion evidence or remediation is available."
        )
    else:
        lines.append("AUDIT STATUS:   REVIEW REQUIRED")
        lines.append(
            "REVIEW NOTE:    The downgrade to Not Affected / low-info is still provisional and needs stronger exclusion evidence."
        )

    conclusion = audit_view.get("conclusion")
    if conclusion:
        lines.append(f"AUDIT BASIS:    {conclusion}")
    lines.append("")


# ----------------------------------------------------------------------- #
# Structured report builder
# ----------------------------------------------------------------------- #


def build_structured_details(
    *,
    vuln_id: str,
    component_name: str,
    repo_url: str,
    repo_path: str,
    verdict_label: str,
    confidence: str,
    affected: bool,
    exposure: str,
    reasoning: str,
    adj_cvss: dict,
    cvss_vec: str | None,
    cvss_score: float | None,
    advisory_relevance: Dict[str, Any] | None,
    advisories: Dict[str, Any],
    dep_info: Dict[str, Any],
    result: Dict[str, Any],
    researcher_view: Dict[str, Any] | None = None,
    remediation_view: Dict[str, Any] | None = None,
    audit_view: Dict[str, Any] | None = None,
) -> str:
    """Build a structured, audit-grade assessment report."""
    lines: list[str] = []

    # Section 1 — Scope
    lines.append("=" * 60)
    lines.append("VULNERABILITY ASSESSMENT REPORT")
    lines.append("=" * 60)
    lines.append("")
    _append_audit_details_emphasis(lines, audit_view)
    lines.append(
        f"Date:            {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    lines.append(f"Vulnerability:   {vuln_id or 'N/A'}")
    lines.append(f"Component:       {component_name or 'N/A'}")

    advisory_summary = advisories.get("summary", "")
    if advisory_summary:
        lines.append(f"Advisory:        {advisory_summary}")

    affected_pkgs = advisories.get("affected_packages", [])
    if affected_pkgs:
        lines.append(f"Affected pkgs:   {', '.join(affected_pkgs)}")

    affected_ranges = advisories.get("affected_ranges", [])
    if affected_ranges:
        range_strs = []
        for r in affected_ranges:
            ev = r.get("event", {})
            intro = ev.get("introduced", "?")
            fixed = ev.get("fixed", "none")
            range_strs.append(f"{r.get('type', '?')}: {intro} .. {fixed}")
        lines.append(f"Affected ranges: {'; '.join(range_strs)}")

    cwes = advisories.get("cwe", [])
    if cwes:
        lines.append(f"CWE(s):          {', '.join(cwes)}")

    if advisory_relevance:
        lines.append(
            f"Filter decision:  {'relevant' if advisory_relevance.get('relevant') else 'filtered out'}"
        )
        lines.append(
            f"Decision source:  {str(advisory_relevance.get('source', 'rules')).upper()}"
        )
        reasons = advisory_relevance.get("reasons", [])
        if reasons:
            lines.append("Filter reasons:")
            for reason in reasons:
                lines.append(f"  - {reason}")

    # Section 2 — Repository & versions checked
    lines.append("")
    lines.append("-" * 60)
    lines.append("REPOSITORY & VERSIONS CHECKED")
    lines.append("-" * 60)

    if repo_url:
        lines.append(f"Repository URL:  {repo_url}")
    if repo_path:
        lines.append(f"Local path:      {repo_path}")

    declared_in = dep_info.get("declared_in", [])
    lock_files = dep_info.get("lock_files", [])
    locked_version = dep_info.get("locked_version")

    lines.append(f"Dependency:      {dependency_presence_detail(dep_info)}")
    if declared_in:
        lines.append(f"Declared in:     {', '.join(declared_in)}")
    if lock_files:
        lines.append(f"Lock files:      {', '.join(lock_files)}")
    if locked_version:
        lines.append(f"Locked version:  {locked_version}")

    version_inv = result.get("version_inventory", {})
    version_table = version_inv.get("version_table", [])
    if version_table:
        lines.append("")
        lines.append(
            "Ref/Version                          Type      Product    Dependency       Source    Status     Notes"
        )
        lines.append(
            "-----------------------------------  --------  ---------  ---------------  --------  ---------  -----"
        )
        for row in version_table:
            ref = row.get("ref", "?")
            ref_type = row.get("ref_type", "?")
            product_version = row.get("product_version", "") or "-"
            ver = row.get("component_version", "-")
            source = row.get("source", "")
            aff = row.get("affected", "?")
            notes = row.get("notes", "")
            lowered_notes = str(notes).lower()
            unknown = ver in ("", "-") and (
                "not found" in lowered_notes
                or "no matching tag or branch" in lowered_notes
            )
            aff_status = "AFFECTED" if aff == "YES" else "unknown" if unknown else "ok"
            lines.append(
                f"{ref:<37s} {ref_type:<9s} {product_version:<10s} {ver:<16s} {source:<9s} {aff_status:<10s} {notes}"
            )
    else:
        lines.append("")
        lines.append("No version/branch data available.")

    what_if = result.get("what_if", {})
    if what_if and not what_if.get("component_not_found", True):
        lines.append("")
        lines.append("REMEDIATION (what-if)")
        summary_line = what_if.get("summary", "")
        if summary_line:
            lines.append(f"  {summary_line}")
        for opt in what_if.get("remediation", []):
            change = opt.get("change", "")
            lines.append(
                f"  → Upgrade to {opt['target_version']}"
                + (f"  {change}" if change else "")
            )

    # Section 3 — Assessment
    lines.append("")
    lines.append("-" * 60)
    lines.append("ASSESSMENT")
    lines.append("-" * 60)
    lines.append(f"Verdict:         {verdict_label}")
    lines.append(f"Confidence:      {confidence}")
    lines.append(f"Affected:        {'YES' if affected else 'NO'}")
    lines.append(f"Exposure:        {exposure}")

    if cvss_vec:
        score_str = f" (score: {cvss_score})" if cvss_score is not None else ""
        lines.append(f"CVSS:            {cvss_vec}{score_str}")
    if adj_cvss.get("reasons"):
        lines.append(f"CVSS rescoring:  {'; '.join(adj_cvss['reasons'])}")

    if reasoning:
        lines.append("")
        lines.append("Rationale:")
        lines.append(reasoning)

    if researcher_view or remediation_view or audit_view:
        lines.append("")
        lines.append("-" * 60)
        lines.append("MULTI-ROLE REVIEW")
        lines.append("-" * 60)

    if researcher_view:
        lines.append("Researcher / Analyst")
        lines.append(f"  Objective: {researcher_view.get('objective', '')}")
        for finding in researcher_view.get("findings", []):
            lines.append(f"  - {finding}")
        if researcher_view.get("conclusion"):
            lines.append(f"  Conclusion: {researcher_view['conclusion']}")

    if remediation_view:
        lines.append("Remediation Strategist")
        lines.append(f"  Objective: {remediation_view.get('objective', '')}")
        if remediation_view.get("summary"):
            lines.append(f"  Summary: {remediation_view['summary']}")
        for recommendation in remediation_view.get("recommendations", []):
            lines.append(f"  - {recommendation}")

    if audit_view:
        lines.append("Critical Reviewer")
        lines.append(f"  Objective: {audit_view.get('objective', '')}")
        if audit_view.get("status"):
            lines.append(f"  Status: {audit_view['status']}")
        if audit_view.get("consistency"):
            lines.append(f"  Consistency: {audit_view['consistency']}")
        if audit_view.get("downgrade_target"):
            lines.append(
                "  Downgrade supported: "
                + ("yes" if audit_view.get("downgrade_supported") else "no")
            )
        for check in audit_view.get("checks", []):
            lines.append(f"  - {check}")
        if audit_view.get("conclusion"):
            lines.append(f"  Conclusion: {audit_view['conclusion']}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)
