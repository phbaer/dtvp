"""Verdict agent — produces the final vulnerability assessment.

Combines heuristic signals (version matching, dependency presence) with
the LLM's analysis of code reachability to produce a reasoned verdict.
When the LLM is available it gets the final say; otherwise the heuristic
rules act as a fallback.
"""

import json
import logging
import re
from typing import Any, Dict

from src.agents.code_scanner import classify_reachability
from src.agents.cvss_scoring import CvssResult, rescore_for_not_affected, rescore_vector
from src.agents.web_research import fulfill_directives, generate_with_research
from src.llm.prompt_registry import get_prompt_value

logger = logging.getLogger(__name__)

_VERDICT_RESPONSE_CONTRACT = get_prompt_value("verdict", "response_contract")
_VERDICT_REASONING_CONTRACT = get_prompt_value("verdict", "reasoning_contract")


# ----------------------------------------------------------------------- #
# CVSS rescoring
# ----------------------------------------------------------------------- #


def rescore_cvss(
    cvss_list: list[Any],
    *,
    dep_found: bool,
    dep_direct: bool,
    llm_reachable: bool,
    deep_confirmed: bool,
    deep_exploitable: str,
    transitive_reachable: str,
    version_context: Dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Rescore CVSS data using proper vector-based environmental metrics.

    Iterates over *cvss_list* looking for CVSS vector strings.  When a
    vector string is found it is rescored by applying environmental
    modifications and recomputing the score.  Bare numeric scores are
    ignored — without a vector there is nothing to rescore.

    Returns a dict with:
        original_score  — numeric base score
        adjusted_score  — numeric adjusted (environmental) score
        original_vector — original CVSS vector string
        adjusted_vector — modified vector string
        version         — CVSS version string
        reasons         — list of human-readable modification reasons
        summary         — one-line human-readable summary
        version_context — dict with detected_version / version_source / note
    Or ``None`` if no usable CVSS vector is found.
    """
    if not cvss_list:
        return None

    findings = dict(
        dep_found=dep_found,
        dep_direct=dep_direct,
        llm_reachable=llm_reachable,
        deep_confirmed=deep_confirmed,
        deep_exploitable=deep_exploitable,
        transitive_reachable=transitive_reachable,
    )

    # Only consider vector strings — bare numeric scores are not usable.
    best_result: CvssResult | None = None

    for entry in cvss_list:
        if isinstance(entry, str):
            result = rescore_vector(entry, **findings)
            if result is not None:
                if (
                    best_result is None
                    or result.original_score > best_result.original_score
                ):
                    best_result = result

    if best_result is not None:
        reasons = best_result.reasons or ["no adjustment"]
        # Prepend a version info line when a concrete component version
        # was detected, for traceability.
        if version_context:
            comp_ver = version_context.get("detected_version")
            ver_src = version_context.get("version_source")
            ver_note = version_context.get("note", "")

            if comp_ver:
                ver_label = f"{comp_ver} ({ver_src})" if ver_src else comp_ver
                ver_reason = f"detected version {ver_label}"
                if ver_note:
                    ver_reason += f" — {ver_note}"
                reasons = [ver_reason] + reasons
        summary = (
            f"{best_result.original_score} → {best_result.adjusted_score} "
            f"({'; '.join(reasons)})"
        )
        return {
            "original_score": best_result.original_score,
            "adjusted_score": best_result.adjusted_score,
            "original_vector": best_result.original_vector,
            "adjusted_vector": best_result.modified_vector,
            "version": best_result.version,
            "reasons": reasons,
            "summary": summary,
            "version_context": version_context or {},
        }

    return None


def _extract_version_context(
    version_inventory: Dict[str, Any],
    dep_info: Dict[str, Any],
    include_debug: bool = False,
) -> Dict[str, Any]:
    """Extract version information used for the affected-range decision.

    Returns a dict with:
        detected_version  — the version that was actually checked
        version_source    — where it came from (lock file, manifest, …)
        affected          — whether that version is in the affected range
        note              — human-readable explanation from the range check
        affected_ranges   — summary of ranges checked against
    """
    worst = version_inventory.get("worst_case", {})
    table = version_inventory.get("version_table", [])
    trace = version_inventory.get("trace", [])
    comparison_inputs = version_inventory.get("comparison_inputs", {})

    ctx: Dict[str, Any] = {
        "detected_version": None,
        "version_source": None,
        "affected": worst.get("affected", False),
        "current_workspace_affected": worst.get(
            "current_workspace_affected", worst.get("affected", False)
        ),
        "note": worst.get("note", ""),
        "workspace_note": "",
        "historical_affected": worst.get("historical_affected", []),
        "affected_ranges_summary": [],
        "affected_product_versions": comparison_inputs.get(
            "affected_product_versions", []
        ),
        "affected_product_version_refs": comparison_inputs.get(
            "affected_product_version_refs", {}
        ),
        "comparison_inputs": {},
        "comparison_trace": [],
    }

    # Prefer locked version (authoritative)
    locked = dep_info.get("locked_version") or worst.get("locked_version")
    if locked:
        ctx["detected_version"] = locked
        ctx["version_source"] = "lock file"
        # Find the matching row for details
        for row in table:
            if row.get("ref") == "LOCKED":
                ctx["workspace_note"] = row.get("notes", "")
                break
    else:
        # Fall back to worktree row
        for row in table:
            if (
                row.get("ref") == "WORKTREE"
                and row.get("component_version", "-") != "-"
            ):
                ctx["detected_version"] = row["component_version"]
                ctx["version_source"] = row.get("source", "manifest")
                ctx["workspace_note"] = row.get("notes", "")
                break

    # Summarise the affected ranges from the trace
    for line in trace:
        if line.strip().startswith("SEMVER range:") or line.strip().startswith(
            "GIT range:"
        ):
            ctx["affected_ranges_summary"].append(line.strip())

    if include_debug:
        ctx["comparison_inputs"] = comparison_inputs
        ctx["comparison_trace"] = trace

    return ctx


async def aggregate(
    ollama: Any,
    vuln_id: str,
    advisories: Dict[str, Any],
    dep_info: Dict[str, Any],
    usage: Any,
    version_inventory: Dict[str, Any] | None = None,
    llm_analysis: Dict[str, Any] | None = None,
    deep_analysis: Dict[str, Any] | None = None,
    transitive_analysis: Dict[str, Any] | None = None,
    user_guidance: str = "",
    cvss_vector: str = "",
    debug: bool = False,
    vulnerable_component: str = "",
) -> Dict[str, Any]:
    """Produce the final verdict, using the LLM when available."""
    if version_inventory is None:
        # Version check disabled — assume affected
        version_inventory = {"version_table": [], "worst_case": {"affected": True}}

    # ---- gather heuristic signals ----
    dep_found = dep_info.get("found", False)
    dep_direct = dep_info.get("direct", False)
    dep_transitive = dep_info.get("transitive", False)
    reach_heuristic = classify_reachability(usage if isinstance(usage, list) else [])
    worst_affected = bool(version_inventory.get("worst_case", {}).get("affected"))
    has_advisory_data = bool(advisories.get("affected_ranges"))
    llm_reachable = bool((llm_analysis or {}).get("reachable"))
    transitive_reachable = (transitive_analysis or {}).get("reachable", "")

    # ---- gather deep-analysis signals (used by both CVSS and verdict) ----
    deep = deep_analysis or {}
    deep_confirmed = bool(deep.get("confirmed"))
    deep_exploitable = str(deep.get("exploitable", "")).upper()

    # ---- build CVSS vector list: caller-provided first, then advisory ----
    # Caller-provided vector takes priority over advisory vectors.
    cvss_list: list[Any] = []
    if cvss_vector:
        cvss_list.append(cvss_vector)
    cvss_list.extend(advisories.get("cvss") or [])

    adjusted_cvss = None
    version_ctx = _extract_version_context(
        version_inventory,
        dep_info,
        include_debug=debug,
    )
    if cvss_list:
        adjusted_cvss = rescore_cvss(
            cvss_list,
            dep_found=dep_found,
            dep_direct=dep_direct,
            llm_reachable=llm_reachable,
            deep_confirmed=deep_confirmed,
            deep_exploitable=deep_exploitable,
            transitive_reachable=str(transitive_reachable),
            version_context=version_ctx,
        )
        logger.info(
            "rescore_cvss: detected_version=%s (%s), ranges=%s",
            version_ctx.get("detected_version"),
            version_ctx.get("version_source"),
            version_ctx.get("affected_ranges_summary"),
        )

    logger.info(
        "Verdict inputs: dep_found=%s, reach_heuristic=%s, worst_affected=%s, "
        "has_advisory=%s, llm_reachable=%s, transitive_reachable=%s",
        dep_found,
        reach_heuristic,
        worst_affected,
        has_advisory_data,
        llm_reachable,
        transitive_reachable,
    )

    # ---- try LLM-driven verdict ----
    try:
        llm_verdict = await _llm_verdict(
            ollama,
            vuln_id,
            advisories,
            dep_info,
            usage,
            version_inventory,
            llm_analysis,
            deep_analysis,
            transitive_analysis,
            user_guidance=user_guidance,
            vulnerable_component=vulnerable_component,
        )
        if llm_verdict:
            llm_verdict["version_inventory"] = version_inventory
            llm_verdict.setdefault("adjusted_cvss", adjusted_cvss)
            llm_verdict.setdefault("exposure", "none")
            llm_verdict["version_context"] = _extract_version_context(
                version_inventory,
                dep_info,
                include_debug=debug,
            )

            # ---- contradiction safeguard ----
            llm_verdict = _fix_contradictions(
                llm_verdict,
                llm_reachable=llm_reachable,
                deep_confirmed=deep_confirmed,
                deep_exploitable=deep_exploitable,
                dep_found=dep_found,
                dep_direct=dep_direct,
                dep_info=dep_info,
                transitive_reachable=transitive_reachable,
                worst_affected=worst_affected,
                current_workspace_affected=bool(
                    version_inventory.get("worst_case", {}).get(
                        "current_workspace_affected"
                    )
                ),
                version_unknown=not bool(version_ctx.get("detected_version")),
            )

            logger.info(
                "LLM verdict: %s (%s, exposure=%s)",
                llm_verdict["verdict"],
                llm_verdict["confidence"],
                llm_verdict.get("exposure"),
            )
            return _post_verdict_rescore(llm_verdict, cvss_list, version_ctx)
    except Exception as e:
        logger.warning("LLM verdict failed, falling back to heuristics: %s", e)

    # ---- heuristic fallback ----
    heuristic = _heuristic_verdict(
        dep_found,
        dep_direct,
        dep_transitive,
        reach_heuristic,
        worst_affected,
        has_advisory_data,
        llm_reachable,
        transitive_reachable,
        adjusted_cvss,
        version_inventory,
        dep_info,
        debug,
    )
    return _post_verdict_rescore(heuristic, cvss_list, version_ctx)


# ----------------------------------------------------------------------- #
# Post-verdict CVSS rescoring
# ----------------------------------------------------------------------- #


def _post_verdict_rescore(
    verdict_dict: Dict[str, Any],
    cvss_list: list[Any],
    version_ctx: Dict[str, Any],
) -> Dict[str, Any]:
    """Re-rescore CVSS when the final verdict is "Not Affected".

    The initial CVSS rescoring happens before the verdict is known and
    uses only intermediate analysis signals.  When the final verdict
    is "Not Affected", the score should reflect that the vulnerability
    has no effective impact — zero out modified impact metrics and mark
    the exploit maturity as unreported.
    """
    if verdict_dict.get("verdict") != "Not Affected":
        return verdict_dict

    if not cvss_list:
        return verdict_dict

    # Find the best vector to re-rescore (same logic as rescore_cvss).
    best: CvssResult | None = None
    for entry in cvss_list:
        if isinstance(entry, str):
            result = rescore_for_not_affected(entry)
            if result is not None:
                if best is None or result.original_score > best.original_score:
                    best = result

    if best is None:
        return verdict_dict

    reasons = list(best.reasons)
    if version_ctx:
        comp_ver = version_ctx.get("detected_version")
        ver_src = version_ctx.get("version_source")
        ver_note = version_ctx.get("note", "")
        if comp_ver:
            ver_label = f"{comp_ver} ({ver_src})" if ver_src else comp_ver
            ver_reason = f"detected version {ver_label}"
            if ver_note:
                ver_reason += f" — {ver_note}"
            reasons = [ver_reason] + reasons

    summary = f"{best.original_score} → {best.adjusted_score} ({'; '.join(reasons)})"

    verdict_dict["adjusted_cvss"] = {
        "original_score": best.original_score,
        "adjusted_score": best.adjusted_score,
        "original_vector": best.original_vector,
        "adjusted_vector": best.modified_vector,
        "version": best.version,
        "reasons": reasons,
        "summary": summary,
        "version_context": version_ctx or {},
    }
    logger.info(
        "Post-verdict rescore (Not Affected): %.1f → %.1f",
        best.original_score,
        best.adjusted_score,
    )
    return verdict_dict


_VERDICT_SYSTEM_PROMPT = get_prompt_value("verdict", "system")
_VERDICT_RESEARCH_ADDENDUM = get_prompt_value("common", "web_research_addendum")
_VERDICT_SYSTEM_WITH_RESEARCH = (
    f"{_VERDICT_SYSTEM_PROMPT}\n\n{_VERDICT_RESEARCH_ADDENDUM}"
)

_VERDICT_ANALYSIS_PROTOCOL = get_prompt_value("verdict", "analysis_protocol")


def _format_transitive_evidence(transitive_analysis: Dict[str, Any] | None) -> str:
    """Build a detailed transitive-evidence block for the final verdict prompt."""
    trans = transitive_analysis or {}
    if not trans or trans.get("skipped"):
        return ""

    lines = [
        "- TRANSITIVE CALL-PATH ANALYSIS:",
        f"    Reachable through intermediary: {trans.get('reachable', 'N/A')}",
        f"    Confidence: {trans.get('confidence', 'N/A')}",
        f"    Intermediary package(s): {trans.get('intermediary', 'N/A')}",
        f"    Code references to intermediaries: {trans.get('usage_hits', 0)}",
        f"    Transitive reasoning: {trans.get('reasoning', 'N/A')}",
    ]

    chains = trans.get("dependency_chains", [])
    if chains:
        lines.append("    Dependency chains:")
        for chain in chains[:10]:
            lines.append(f"      {chain}")
        if len(chains) > 10:
            lines.append(f"      … and {len(chains) - 10} more")

    snippets = trans.get("snippets", [])
    if snippets:
        lines.append("    Project snippets using intermediary packages:")
        for snippet in snippets[:4]:
            lines.append(f"      --- {snippet.get('file')}:{snippet.get('line')} ---")
            for snippet_line in (
                str(snippet.get("snippet", "")).strip().splitlines()[:12]
            ):
                lines.append(f"      {snippet_line}")

    structure_excerpt = str(trans.get("structure_excerpt", "")).strip()
    if structure_excerpt:
        lines.append("    Structural context:")
        for line in structure_excerpt.splitlines()[:20]:
            lines.append(f"      {line}")

    research_log = trans.get("research_log", [])
    if research_log:
        lines.append("    Intermediary/source research results:")
        for entry in research_log[:2]:
            summary = str(entry.get("results_summary", "")).strip().replace("\n", " ")
            if len(summary) > 400:
                summary = summary[:400] + "..."
            lines.append(f"      Round {entry.get('round', '?')}: {summary}")

    return "\n" + "\n".join(lines)


def _dependency_presence_label(dep_info: Dict[str, Any]) -> str:
    basis = dep_info.get("presence_basis")
    if basis == "direct":
        return "direct"
    if basis == "transitive":
        return "transitive (lock file only)"
    if basis == "sbom_attributed":
        return "sbom-attributed (not rediscovered locally)"
    return "not found"


_UPSTREAM_GUIDANCE_PATTERNS = (
    re.compile(r"\bextends\s+([A-Za-z][A-Za-z0-9_.+-]{1,60})", re.IGNORECASE),
    re.compile(r"\bupstream\s+([A-Za-z][A-Za-z0-9_.+-]{1,60})", re.IGNORECASE),
    re.compile(
        r"\b(?:plugin|extension|adapter|provider)\s+for\s+"
        r"([A-Za-z][A-Za-z0-9_.+-]{1,60})",
        re.IGNORECASE,
    ),
)

_UPSTREAM_GUIDANCE_STOP_WORDS = {
    "component",
    "dependency",
    "evidence",
    "extension",
    "framework",
    "itself",
    "platform",
    "project",
    "runtime",
    "source",
}


def _extract_upstream_platforms_from_guidance(user_guidance: str) -> list[str]:
    """Extract likely upstream platform names from analyst guidance text."""
    platforms: list[str] = []
    seen: set[str] = set()

    for pattern in _UPSTREAM_GUIDANCE_PATTERNS:
        for match in pattern.finditer(user_guidance or ""):
            name = match.group(1).strip(" .,:;()[]{}")
            name = re.sub(r"[^A-Za-z0-9_.+-].*$", "", name)
            if len(name) < 2:
                continue
            key = name.lower()
            if key in _UPSTREAM_GUIDANCE_STOP_WORDS or key in seen:
                continue
            seen.add(key)
            platforms.append(name)
            if len(platforms) >= 3:
                return platforms

    return platforms


def _bare_package_name(package: Any) -> str:
    value = str(package or "").strip()
    return value.split(":", 1)[-1].strip() if ":" in value else value


def _has_prior_research(*analyses: Dict[str, Any] | None) -> bool:
    return any(bool((analysis or {}).get("research_log")) for analysis in analyses)


def _mandatory_upstream_research_query(
    *,
    vuln_id: str,
    advisory_packages: list[Any],
    dep_info: Dict[str, Any],
    version_ctx: Dict[str, Any],
    llm_analysis: Dict[str, Any] | None,
    transitive_analysis: Dict[str, Any] | None,
    user_guidance: str,
    vulnerable_component: str,
) -> str:
    """Build a required search query for SBOM-only upstream-platform uncertainty."""
    platforms = _extract_upstream_platforms_from_guidance(user_guidance)
    if not platforms:
        return ""
    if not dep_info.get("sbom_attributed") or dep_info.get("repo_found", False):
        return ""
    if dep_info.get("locked_version") or version_ctx.get("detected_version"):
        return ""
    if (llm_analysis or {}).get("reachable"):
        return ""
    if _has_prior_research(llm_analysis, transitive_analysis):
        return ""

    dependency = vulnerable_component or next(
        (
            _bare_package_name(pkg)
            for pkg in advisory_packages
            if _bare_package_name(pkg)
        ),
        "",
    )
    query_parts = [platforms[0], dependency, vuln_id, "dependency version"]
    return " ".join(part for part in query_parts if part).strip()


async def _llm_verdict(
    ollama: Any,
    vuln_id: str,
    advisories: Dict[str, Any],
    dep_info: Dict[str, Any],
    usage: Any,
    version_inventory: Dict[str, Any],
    llm_analysis: Dict[str, Any] | None,
    deep_analysis: Dict[str, Any] | None = None,
    transitive_analysis: Dict[str, Any] | None = None,
    user_guidance: str = "",
    vulnerable_component: str = "",
) -> Dict[str, Any] | None:
    """Ask the LLM for a final verdict with all evidence."""
    if ollama is None:
        return None

    advisory_pkgs = advisories.get("affected_packages", [])
    advisory_ranges = advisories.get("affected_ranges", [])
    code_reasoning = (llm_analysis or {}).get("reasoning", "N/A")
    code_reachable = (llm_analysis or {}).get("reachable", False)
    risk_areas = (llm_analysis or {}).get("risk_areas", [])
    invocation_paths = (llm_analysis or {}).get("invocation_paths", [])
    usage_hits = usage if isinstance(usage, list) else []
    version_table = version_inventory.get("version_table", [])

    # Dependency classification
    dep_direct = dep_info.get("direct", False)
    dep_transitive = dep_info.get("transitive", False)
    locked_version = dep_info.get("locked_version")
    lock_files = dep_info.get("lock_files", [])
    dep_type = _dependency_presence_label(dep_info)

    advisory_summary = advisories.get("summary", "")

    # Determine whether code usage is direct (imports + calls in source)
    has_direct_code_usage = len(usage_hits) > 0 and any(
        h != "No direct usage found" for h in usage_hits
    )

    # Format invocation paths for the prompt
    paths_text = (
        "\n".join(f"    {p}" for p in invocation_paths[:10])
        if invocation_paths
        else "    NONE"
    )

    # Format deep analysis results (if available)
    deep = deep_analysis or {}
    deep_text = ""
    if deep and not deep.get("skipped"):
        deep_text = f"""\n- DEEP ANALYSIS (second pass on full source files):
    Confirmed: {deep.get("confirmed", "N/A")}
    Exploitable: {deep.get("exploitable", "N/A")}
    Risk level: {deep.get("risk_level", "N/A")}
    Mitigations: {deep.get("mitigations", "N/A")}
    Deep reasoning: {deep.get("reasoning", "N/A")}"""

    # Format transitive analysis results (if available)
    trans_text = _format_transitive_evidence(transitive_analysis)

    # Format version analysis with explicit detected version info
    version_ctx = _extract_version_context(version_inventory, dep_info)
    worst = version_inventory.get("worst_case", {})
    current_ws_affected = version_ctx.get(
        "current_workspace_affected", version_ctx["affected"]
    )
    any_version_affected = version_ctx["affected"]
    historical_affected = worst.get("historical_affected", [])
    version_text = ""
    affected_product_versions = version_ctx.get("affected_product_versions") or []
    product_version_refs = version_ctx.get("affected_product_version_refs") or {}
    if affected_product_versions:
        version_text += (
            "\n- DTVP AFFECTED PRODUCT VERSIONS TO COVER: "
            + ", ".join(str(version) for version in affected_product_versions)
        )
        if product_version_refs:
            version_text += "\n- PRODUCT VERSION REF MATCHES:"
            for product_version in affected_product_versions:
                refs = product_version_refs.get(product_version) or []
                version_text += (
                    f"\n    {product_version}: "
                    + (", ".join(refs) if refs else "no matching tag/branch")
                )
    if version_ctx["detected_version"]:
        version_text = (
            version_text
            + f"\n- DETECTED COMPONENT VERSION (workspace): {version_ctx['detected_version']} "
            f"(source: {version_ctx['version_source']})"
            f"\n- WORKSPACE VERSION IN AFFECTED RANGE: {'YES' if current_ws_affected else 'NO'}"
            f"\n- ANY TRACKED RELEASE IN AFFECTED RANGE: {'YES' if any_version_affected else 'NO'}"
        )
        if version_ctx["note"]:
            version_text += f"\n- VERSION CHECK NOTE: {version_ctx['note']}"
    elif locked_version:
        version_text = (
            version_text
            + f"\n- DETECTED COMPONENT VERSION (workspace): {locked_version} (source: lock file)"
            f"\n- WORKSPACE VERSION IN AFFECTED RANGE: {'YES' if current_ws_affected else 'NO'}"
            f"\n- ANY TRACKED RELEASE IN AFFECTED RANGE: {'YES' if any_version_affected else 'NO'}"
        )
    else:
        version_text += "\n- DETECTED COMPONENT VERSION: could not determine"
    if historical_affected:
        version_text += "\n- HISTORICAL RELEASES WITH AFFECTED VERSION:"
        for h in historical_affected:
            version_text += (
                f"\n    {h['ref']} ({h['ref_type']}): {h['component_version']}"
            )
    if version_ctx["affected_ranges_summary"]:
        version_text += "\n- CHECKED AGAINST RANGES:"
        for rng in version_ctx["affected_ranges_summary"]:
            version_text += f"\n    {rng}"
    version_text += (
        "\n- NOTE: Reachability and code analysis are performed on the current "
        "workspace only. A tracked release shipping an affected version is "
        "sufficient to flag the project as Affected unless the vulnerable "
        "code path is demonstrably unreachable in the current workspace."
    )

    # Format the version/branch table for the prompt
    versions_checked_text = ""
    if version_table:
        ver_lines = []
        for row in version_table:
            ref = row.get("ref", "?")
            ref_type = row.get("ref_type", "?")
            ver = row.get("component_version", "-")
            source = row.get("source", "")
            notes = row.get("notes", "")
            product_version = row.get("product_version", "")
            aff = row.get("affected", "?")
            lowered_notes = str(notes).lower()
            not_found = ver in ("", "-") and (
                "not found" in lowered_notes
                or "no matching tag or branch" in lowered_notes
            )
            if aff == "YES":
                status = "AFFECTED"
            elif not_found:
                status = "unknown"
            else:
                status = "not affected"
            source_tag = f" [{source}]" if source else ""
            product_tag = f" product={product_version}" if product_version else ""
            notes_tag = f" ({notes})" if notes else ""
            ver_lines.append(
                f"    {ref} ({ref_type}{product_tag}): {ver}{source_tag} — {status}{notes_tag}"
            )
        versions_checked_text = "\n- Versions/branches checked:\n" + "\n".join(
            ver_lines
        )
    else:
        versions_checked_text = "\n- Versions/branches checked: none available"

    mandatory_research_log: list[Dict[str, Any]] = []
    mandatory_research_text = ""
    mandatory_query = _mandatory_upstream_research_query(
        vuln_id=vuln_id,
        advisory_packages=advisory_pkgs,
        dep_info=dep_info,
        version_ctx=version_ctx,
        llm_analysis=llm_analysis,
        transitive_analysis=transitive_analysis,
        user_guidance=user_guidance,
        vulnerable_component=vulnerable_component,
    )
    if mandatory_query:
        directives = [{"type": "search", "target": mandatory_query}]
        fetched_text = await fulfill_directives(
            directives,
            vulnerable_component=vulnerable_component,
        )
        mandatory_research_log.append(
            {
                "round": 0,
                "required": True,
                "directives": directives,
                "results_summary": fetched_text[:500],
            }
        )
        mandatory_research_text = f"""
MANDATORY EXTERNAL CHECK:
- Analyst guidance names an upstream platform/framework, local dependency evidence is SBOM-only, and no checked version was found.
- The following lookup was performed before final verdict. If it is only search metadata and exact source text is still needed, request FETCH_URL for the best authoritative result.
- Analyzer-required tool request:
  FETCH_SEARCH: {mandatory_query}

--- RESEARCH RESULTS (mandatory upstream-platform check) ---
{fetched_text}"""

    prompt = f"""{_VERDICT_ANALYSIS_PROTOCOL}
Now produce a verdict for the following:
VULNERABILITY: {vuln_id}
SUMMARY: {advisory_summary or "No advisory summary available."}
AFFECTED PACKAGES (from advisory): {advisory_pkgs}
AFFECTED VERSION RANGES: {json.dumps(advisory_ranges, default=str)}
EVIDENCE:
- Dependency type: {dep_type}
- Dependency found: {dep_info.get("found", False)}
- Dependency rediscovered in local repo: {dep_info.get("repo_found", dep_info.get("found", False))}
- Dependency attributed from SBOM/input tuple: {dep_info.get("sbom_attributed", False)}
- Declared in manifests: {", ".join(dep_info.get("declared_in", [])) or "N/A"}
- Found in lock files: {", ".join(lock_files) or "N/A"}
- Locked version: {locked_version or "unknown"}{version_text}{versions_checked_text}
- Code usage hits: {len(usage_hits)} ({"direct imports/calls found in source" if has_direct_code_usage else "no direct imports or calls in source"})
- Code reachability: {"REACHABLE" if code_reachable else "NOT REACHABLE"}
- Invocation paths (entry-point → vulnerable call):
{paths_text}
- Code reasoning: {code_reasoning}
- Risk areas: {", ".join(risk_areas) if risk_areas else "NONE"}{deep_text}{trans_text}
{"" if not user_guidance else f"{chr(10)}ANALYST GUIDANCE:{chr(10)}{user_guidance}"}
{mandatory_research_text}
{_VERDICT_RESPONSE_CONTRACT}
{_VERDICT_REASONING_CONTRACT}"""

    raw, research_log = await generate_with_research(
        ollama,
        prompt,
        system=_VERDICT_SYSTEM_WITH_RESEARCH,
        vulnerable_component=vulnerable_component,
    )
    result = _parse_verdict_response(raw)
    combined_research_log = mandatory_research_log + research_log
    if result and combined_research_log:
        result["research_log"] = combined_research_log
    if result:
        result["reasoning"] = _strip_version_details_from_reasoning(
            result.get("reasoning", "")
        )
    return result


def _parse_verdict_response(raw: str) -> Dict[str, Any] | None:
    """Parse the structured LLM verdict response.

    Handles models that produce extra text or multi-line REASONING.
    """
    result: Dict[str, Any] = {}
    in_reasoning = False

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()

        if upper.startswith("VERDICT:"):
            val = stripped.split(":", 1)[1].strip()
            # Normalise to one of the four canonical values.
            # Check longer / more specific phrases first so that
            # "Not Affected" is not swallowed by the substring
            # match on "Affected".
            for canon in (
                "Not Affected",
                "Probably Affected",
                "Inconclusive",
                "Affected",
            ):
                if canon.upper() in val.upper():
                    val = canon
                    break
            result["verdict"] = val
            in_reasoning = False
        elif upper.startswith("CONFIDENCE:"):
            val = stripped.split(":", 1)[1].strip()
            for canon in ("High", "Medium", "Low"):
                if canon.upper() in val.upper():
                    val = canon
                    break
            result["confidence"] = val
            in_reasoning = False
        elif upper.startswith("AFFECTED:"):
            val = stripped.split(":", 1)[1].strip().lower()
            result["affected"] = val == "true"
            in_reasoning = False
        elif upper.startswith("EXPOSURE:"):
            val = stripped.split(":", 1)[1].strip().lower()
            for canon in ("direct", "transitive", "none"):
                if canon in val:
                    val = canon
                    break
            result["exposure"] = val
            in_reasoning = False
        elif upper.startswith("REASONING:"):
            result["reasoning"] = stripped.split(":", 1)[1].strip()
            in_reasoning = True
        elif in_reasoning:
            result["reasoning"] = result.get("reasoning", "") + " " + stripped

    if "verdict" in result and "affected" in result:
        result.setdefault("confidence", "Medium")
        result.setdefault("exposure", "none")
        result.setdefault("reasoning", "")
        return result
    return None


def _strip_version_details_from_reasoning(reasoning: str) -> str:
    """Remove detailed version audit blocks from freeform reasoning text."""
    text = (reasoning or "").strip()
    if not text:
        return ""

    markers = (
        "Checked versions:",
        "Versions/branches checked:",
        "Checked branches:",
    )
    cut_positions = [text.find(marker) for marker in markers if text.find(marker) != -1]
    if cut_positions:
        text = text[: min(cut_positions)].rstrip(" ,.;")

    sentences = []
    for sentence in text.split(". "):
        lowered = sentence.lower()
        if (
            lowered.startswith("the locked version ")
            or lowered.startswith("locked version ")
            or lowered.startswith("all checked versions ")
            or lowered.startswith("checked versions ")
        ):
            continue
        sentences.append(sentence)
    text = ". ".join(sentences).strip()
    return text


# ----------------------------------------------------------------------- #
# Contradiction safeguard
# ----------------------------------------------------------------------- #


def _fix_contradictions(
    verdict: Dict[str, Any],
    *,
    llm_reachable: bool,
    deep_confirmed: bool,
    deep_exploitable: str,
    dep_found: bool,
    dep_direct: bool,
    dep_info: Dict[str, Any] | None = None,
    transitive_reachable: str,
    worst_affected: bool,
    current_workspace_affected: bool,
    version_unknown: bool = False,
) -> Dict[str, Any]:
    """Override an LLM verdict that contradicts hard evidence.

    The LLM sometimes produces "Not Affected" even when the deep analysis
    has confirmed exploitable code.  This function detects such cases and
    corrects the verdict to match the evidence.
    """
    v = verdict.get("verdict", "")
    is_weak = v in ("Not Affected", "Inconclusive")
    is_not_affected = v == "Not Affected"
    overrides: list[str] = []
    dep_info = dep_info or {}

    # Rule 1: deep analysis confirmed exploitable → must be Affected
    if deep_confirmed and deep_exploitable in ("YES", "LIKELY") and is_not_affected:
        verdict["verdict"] = "Affected"
        verdict["affected"] = True
        verdict["confidence"] = "High"
        overrides.append(
            "deep analysis confirmed exploitable code — "
            "overrode LLM 'Not Affected' verdict"
        )

    # Rule 2: LLM reachability + deep confirmed → at least Probably Affected
    elif deep_confirmed and llm_reachable and is_not_affected:
        verdict["verdict"] = "Probably Affected"
        verdict["affected"] = True
        verdict["confidence"] = "Medium"
        overrides.append(
            "code is reachable and deep analysis confirmed — "
            "overrode LLM 'Not Affected' verdict"
        )

    # Rule 3: LLM says reachable but verdict is Not Affected → Probably Affected
    elif llm_reachable and is_not_affected:
        verdict["verdict"] = "Probably Affected"
        verdict["affected"] = True
        verdict["confidence"] = "Medium"
        overrides.append(
            "LLM reachability analysis found code reachable — "
            "overrode LLM 'Not Affected' verdict"
        )

    # Rule 4: transitive path reachable but verdict is Not Affected
    elif transitive_reachable in ("YES", "LIKELY") and is_not_affected:
        verdict["verdict"] = "Probably Affected"
        verdict["affected"] = True
        verdict["confidence"] = "Low"
        overrides.append(
            "transitive call-path analysis found reachable path — "
            "overrode LLM 'Not Affected' verdict"
        )

    # Rule 5: SBOM/input attribution is dependency evidence. A local repo miss
    # or unknown version is not enough for a Not Affected downgrade.
    elif (
        is_not_affected
        and dep_found
        and dep_info.get("sbom_attributed")
        and not dep_info.get("repo_found", False)
        and version_unknown
        and not worst_affected
    ):
        verdict["verdict"] = "Inconclusive"
        verdict["affected"] = False
        verdict["confidence"] = "Low"
        verdict["exposure"] = "transitive"
        overrides.append(
            "dependency is SBOM-attributed but not rediscovered locally and "
            "no concrete version was checked — replaced unsupported "
            "'Not Affected' verdict with Inconclusive"
        )

    # Rule 6: a tracked release shipped an affected version — LLM may not
    # discount this based solely on the current workspace version being
    # patched.  Reachability evidence (unreachable in workspace) is the
    # only acceptable basis for a "Not Affected" verdict here.
    if worst_affected and not current_workspace_affected and is_weak and not overrides:
        # The workspace version is patched, which is good. But since at least
        # one released version was affected, require explicit unreachability
        # evidence before accepting a weak verdict.
        unreachable_evidence = (
            not llm_reachable
            and not deep_confirmed
            and transitive_reachable not in ("YES", "LIKELY", "UNCERTAIN")
        )
        if not unreachable_evidence:
            verdict["verdict"] = "Probably Affected"
            verdict["affected"] = True
            verdict["confidence"] = "Medium"
            overrides.append(
                "a tracked release shipped an affected version and reachability "
                "is not confirmed absent — overrode weak LLM verdict"
            )
        else:
            existing = verdict.get("reasoning", "")
            note = (
                "[NOTE: current workspace version is patched and vulnerable code "
                "path is unreachable — weak verdict accepted despite historical "
                "releases having shipped an affected version]"
            )
            verdict["reasoning"] = f"{note} {existing}" if existing else note

    # Rule 7: verdict is Affected but no evidence supports it
    if verdict.get("verdict") == "Affected" and not overrides:
        has_evidence = (
            llm_reachable
            or deep_confirmed
            or transitive_reachable in ("YES", "LIKELY")
            or dep_found
        )
        if not has_evidence:
            verdict["verdict"] = "Inconclusive"
            verdict["affected"] = False
            verdict["confidence"] = "Low"
            overrides.append(
                "LLM said 'Affected' but no supporting evidence found — "
                "downgraded to Inconclusive"
            )

    if overrides:
        original_reasoning = _sanitize_overridden_reasoning(
            verdict.get("reasoning", ""),
            verdict.get("verdict", ""),
        )
        override_note = " | ".join(overrides)
        verdict["reasoning"] = f"[SAFEGUARD: {override_note}] {original_reasoning}"
        logger.warning("Verdict contradiction detected and fixed: %s", override_note)

    return verdict


# Patterns that contradict an Affected / Probably Affected verdict.
# Each tuple is (compiled regex, replacement).
_CONTRADICTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # "the project is not affected" / "is not exploitable" / "not vulnerable"
    (
        re.compile(
            r"\b(?:the project |it |the (?:assessed |current )?(?:project|codebase|application) )"
            r"is not (?:affected|exploitable|vulnerable)\b",
            re.IGNORECASE,
        ),
        "the project may still be affected",
    ),
    # "Consequently, … not affected" style conclusions
    (
        re.compile(
            r"Consequently,?\s+the project is not (?:affected|exploitable|vulnerable)\b",
            re.IGNORECASE,
        ),
        "Consequently, the project may still be affected",
    ),
    # Bare "is not affected by this vulnerability"
    (
        re.compile(
            r"\bis not affected by this vulnerability\b",
            re.IGNORECASE,
        ),
        "may still be affected by this vulnerability",
    ),
    (
        re.compile(
            r"\bno [A-Za-z0-9_.:/@+\- ]{1,80}?dependency is present\b",
            re.IGNORECASE,
        ),
        "the dependency was not rediscovered locally",
    ),
    # "not exploitable" as a standalone assertion (not preceded by negation of negation)
    (
        re.compile(
            r"\bis not exploitable\b",
            re.IGNORECASE,
        ),
        "may still be exploitable",
    ),
]


def _sanitize_overridden_reasoning(reasoning: str, new_verdict: str) -> str:
    """Remove or rephrase assertions that contradict the overridden verdict.

    When the safeguard promotes a verdict from "Not Affected" to something
    more severe, the original LLM reasoning may still contain statements
    like "the project is not affected."  This function rewrites those
    phrases so the reasoning no longer contradicts the final verdict.
    """
    if not reasoning or new_verdict == "Not Affected":
        return reasoning

    text = reasoning
    for pattern, replacement in _CONTRADICTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _heuristic_verdict(
    dep_found: bool,
    dep_direct: bool,
    dep_transitive: bool,
    reach: str,
    worst_affected: bool,
    has_advisory_data: bool,
    llm_reachable: bool,
    transitive_reachable: str,
    adjusted_cvss: Any,
    version_inventory: Dict[str, Any],
    dep_info: Dict[str, Any] | None = None,
    debug: bool = False,
) -> Dict[str, Any]:
    """Pure-heuristic fallback when the LLM is unavailable."""
    if dep_info is None:
        dep_info = {}
    version_ctx = _extract_version_context(
        version_inventory,
        dep_info,
        include_debug=debug,
    )
    exposure = "direct" if dep_direct else "transitive" if dep_transitive else "none"
    if not dep_found:
        logger.info(
            "Component not rediscovered in local repo scan; treating absence as unproven and continuing heuristic verdict"
        )
        exposure = "transitive"

    # Prefer LLM reachability signal when available
    is_reachable = llm_reachable or reach in ("Reachable", "Potentially Reachable")
    # For transitive deps, consider transitive path analysis
    is_transitive_reachable = transitive_reachable in ("YES", "UNCERTAIN")

    if worst_affected and is_reachable:
        v = "Affected"
        c = "High"
    elif worst_affected and is_transitive_reachable:
        v = "Probably Affected"
        c = "Medium"
    elif worst_affected:
        v = "Probably Affected"
        c = "Medium"
    elif not has_advisory_data:
        v = "Inconclusive"
        c = "Low"
    else:
        v = "Not Affected"
        c = "Low"

    logger.info("Heuristic verdict: %s (%s, exposure=%s)", v, c, exposure)
    return {
        "affected": v in ("Affected", "Probably Affected"),
        "verdict": v,
        "confidence": c,
        "exposure": exposure,
        "adjusted_cvss": adjusted_cvss,
        "version_inventory": version_inventory,
        "version_context": version_ctx,
    }
