"""Verdict assembly — view builders, DT mapping, and structured report.

All functions that transform raw pipeline state into the final assessment
payload live here.  ``graph.py`` calls these after the graph completes.
"""

from __future__ import annotations

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
            checks.append(
                "Concern: the version analysis says the current codebase is outside range, so the impact verdict may be overstated."
            )
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


def apply_audit_guardrail(
    result: Dict[str, Any],
    audit_view: Dict[str, Any] | None,
    version_analysis: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Promote unsupported Not Affected downgrades before emitting the response."""
    if result.get("verdict") != "Not Affected":
        return result
    if not audit_view or audit_view.get("status") != "fail":
        return result
    if not version_analysis:
        return result

    historical_only_affected = bool(
        version_analysis.get("affected")
        and version_analysis.get("current_workspace_affected") is False
    )
    if not historical_only_affected:
        return result

    guarded = dict(result)
    original_reasoning = str(guarded.get("reasoning", "")).strip()
    guardrail_note = (
        "[AUDIT GUARDRAIL: tracked historical releases shipped an affected "
        "version and the Not Affected downgrade is not sufficiently supported]"
    )
    guarded["verdict"] = "Probably Affected"
    guarded["affected"] = True
    guarded["confidence"] = "Medium"
    guarded["summary"] = (
        "Tracked historical releases shipped an affected version. The current "
        "workspace may be patched, but the downgrade to Not Affected is not "
        "supported without stronger workspace-only exclusion evidence."
    )
    guarded["reasoning"] = (
        f"{guardrail_note} {original_reasoning}".strip()
        if original_reasoning
        else guardrail_note
    )

    adjusted_cvss = guarded.get("adjusted_cvss") or {}
    original_score = adjusted_cvss.get("original_score")
    if adjusted_cvss and original_score is not None:
        restored = dict(adjusted_cvss)
        restored["adjusted_score"] = original_score
        restored["adjusted_vector"] = restored.get("original_vector")
        reasons = list(restored.get("reasons") or [])
        reasons.insert(
            0,
            "audit guardrail removed the unsupported not-affected downgrade",
        )
        restored["reasons"] = reasons
        restored["summary"] = (
            f"{restored.get('original_score')} → {restored.get('adjusted_score')} "
            f"({'; '.join(reasons)})"
        )
        guarded["adjusted_cvss"] = restored

    return guarded


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
