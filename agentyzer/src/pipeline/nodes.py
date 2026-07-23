"""Pipeline node functions.

Each function is a thin adapter between the graph state and one or more
agent modules.  Nodes read what they need from ``PipelineState``, delegate
to the appropriate agent, and return a dict of state updates (including
``evidence`` entries for the audit trail).

Keeping nodes separate from the graph wiring (``graph.py``) makes it easy
to add, remove, or reorder steps without touching business logic — and
vice-versa.
"""

from __future__ import annotations

import json
import logging
import os

from src.agents import (
    ast_analyzer,
    code_scanner,
    dependency_scanner,
    verdict,
    version_analyzer,
    web_fetcher,
)
from src.agents.dependency_scanner import RepoError
from src.llm.prompt_registry import get_prompt_value
from src.pipeline.advisory_context import (
    build_advisory_analysis_input as _build_advisory_analysis_input,
    get_scan_target as _get_scan_target,
    list_project_manifests as _list_project_manifests,
)
from src.pipeline.state import PipelineState

logger = logging.getLogger(__name__)

_ADVISORY_RELEVANCE_SYSTEM = get_prompt_value("advisory_relevance", "system")
_ADVISORY_RELEVANCE_INSTRUCTIONS = get_prompt_value(
    "advisory_relevance", "instructions"
)
_ADVISORY_RELEVANCE_INPUT_PREAMBLE = get_prompt_value(
    "advisory_relevance", "input_preamble"
)

# ----------------------------------------------------------------------- #
# discover_vuln
# ----------------------------------------------------------------------- #
async def discover_vuln(state: PipelineState) -> dict:
    """If no vuln_id was provided, query OSV for known vulns and pick the worst."""
    vuln_id = state.get("vuln_id", "")
    component = state["component_name"]

    if vuln_id:
        logger.info(
            "[discover_vuln] vuln_id provided: %s — skipping discovery", vuln_id
        )
        return {
            "step_reports": {
                "discover_vuln": {
                    "title": "Vulnerability Discovery",
                    "status": "provided",
                    "findings": {"vuln_id": vuln_id, "source": "user-provided"},
                    "evidence": [f"Using user-provided vulnerability: {vuln_id}"],
                },
            },
            "evidence": [f"Using user-provided vulnerability: {vuln_id}"],
        }
    # Guess ecosystem from component name
    ecosystem = web_fetcher.guess_ecosystem(component)
    logger.info(
        "[discover_vuln] component=%s, guessed ecosystem=%s",
        component,
        ecosystem,
    )

    if not ecosystem:
        logger.warning("[discover_vuln] Cannot guess ecosystem for '%s'", component)
        return {
            "step_reports": {
                "discover_vuln": {
                    "title": "Vulnerability Discovery",
                    "status": "skipped",
                    "findings": {"reason": "unknown ecosystem"},
                    "evidence": [
                        f"Cannot determine ecosystem for '{component}' — "
                        "provide a vuln_id explicitly"
                    ],
                },
            },
            "evidence": [
                f"Cannot determine ecosystem for '{component}' — "
                "provide a vuln_id explicitly"
            ],
        }

    vulns = await web_fetcher.discover_vulnerabilities(component, ecosystem)

    if not vulns:
        logger.info(
            "[discover_vuln] No known vulnerabilities for %s/%s", ecosystem, component
        )
        return {
            "step_reports": {
                "discover_vuln": {
                    "title": "Vulnerability Discovery",
                    "status": "clean",
                    "findings": {
                        "ecosystem": ecosystem,
                        "total_vulns": 0,
                    },
                    "evidence": [
                        f"No known vulnerabilities found for {ecosystem}/{component}"
                    ],
                },
            },
            "evidence": [f"No known vulnerabilities found for {ecosystem}/{component}"],
        }

    worst = vulns[0]
    selected_id = worst["id"]
    # Prefer a CVE alias if available (more universally useful).
    for alias in worst.get("aliases", []):
        if alias.startswith("CVE-"):
            selected_id = alias
            break

    logger.info(
        "[discover_vuln] Discovered %d vulns for %s/%s — worst: %s (score=%.1f)",
        len(vulns),
        ecosystem,
        component,
        selected_id,
        worst.get("severity_score", 0),
    )

    evidence_lines = [
        f"Discovered {len(vulns)} known vulnerabilities for {ecosystem}/{component}",
        f"Selected worst: {selected_id} (severity={worst.get('severity_score', 0):.1f})",
        f"  Summary: {worst.get('summary', 'N/A')}",
    ]
    if len(vulns) > 1:
        for v in vulns[1:5]:
            evidence_lines.append(
                f"  Other: {v['id']} (severity={v.get('severity_score', 0):.1f}) — "
                f"{v.get('summary', '')[:80]}"
            )
        if len(vulns) > 5:
            evidence_lines.append(f"  … and {len(vulns) - 5} more")

    return {
        "vuln_id": selected_id,
        "discovered_vulns": vulns,
        "step_reports": {
            "discover_vuln": {
                "title": "Vulnerability Discovery",
                "status": "discovered",
                "findings": {
                    "ecosystem": ecosystem,
                    "total_vulns": len(vulns),
                    "selected": selected_id,
                    "severity_score": worst.get("severity_score", 0),
                    "all_vulns": [
                        {"id": v["id"], "severity": v.get("severity_score", 0)}
                        for v in vulns[:10]
                    ],
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# fetch_advisory
# ----------------------------------------------------------------------- #
async def fetch_advisory(state: PipelineState) -> dict:
    vuln_id = state.get("vuln_id", "")
    if not vuln_id:
        logger.info("[fetch_advisory] No vuln_id — returning empty advisory data")
        return {
            "advisories": {},
            "summary": "No vulnerability ID available — discovery found no known CVEs",
            "step_reports": {
                "fetch_advisory": {
                    "title": "Advisory Fetch",
                    "status": "skipped",
                    "findings": {"reason": "no vuln_id"},
                    "evidence": ["No vulnerability ID to look up"],
                },
            },
            "evidence": ["No vulnerability ID to look up"],
        }
    logger.info("[fetch_advisory] Fetching advisories for %s", vuln_id)
    advisories = await web_fetcher.fetch_advisory(state["vuln_id"])
    src_count = len(advisories.get("sources", []))
    range_count = len(advisories.get("affected_ranges", []))
    sym_count = len(advisories.get("vulnerable_symbols", []))
    ver_count = len(advisories.get("affected_versions", []))
    data_warnings = advisories.get("data_warnings", [])
    summary = advisories.get("summary", "")
    logger.info(
        "[fetch_advisory] sources=%d, affected_ranges=%d, affected_versions=%d, "
        "symbols=%d, summary=%d chars, warnings=%d",
        src_count,
        range_count,
        ver_count,
        sym_count,
        len(summary),
        len(data_warnings),
    )
    for w in data_warnings:
        logger.warning("[fetch_advisory] Data warning: %s", w)

    # Build detailed range descriptions for evidence
    range_details = []
    for r in advisories.get("affected_ranges", []):
        ev = r.get("event", {})
        range_details.append(
            f"  {r.get('type', '?')} range: introduced={ev.get('introduced', '?')} "
            f"fixed={ev.get('fixed', 'none')} (source={r.get('source', '?')})"
        )

    evidence_lines = [
        f"Advisory: {summary}"
        if summary
        else f"Advisory: no summary available for {state['vuln_id']}",
        f"Affected packages: {', '.join(advisories.get('affected_packages', [])) or 'unknown'}",
        f"Affected version ranges: {range_count} from {src_count} sources",
    ]
    evidence_lines.extend(range_details)
    if ver_count:
        vers = advisories.get("affected_versions", [])
        evidence_lines.append(
            f"Explicit affected versions: {ver_count} "
            f"(e.g. {', '.join(vers[:5])}{'...' if ver_count > 5 else ''})"
        )
    evidence_lines.extend(
        [
            f"Vulnerable symbols: {', '.join(advisories.get('vulnerable_symbols', [])) or 'none identified'}",
            f"CWEs: {', '.join(advisories.get('cwe', [])) or 'none'}",
        ]
    )
    for w in data_warnings:
        evidence_lines.append(f"WARNING: {w}")

    # Derive scan targets from the advisory's affected package list.
    # Entries look like "ecosystem:name" (e.g. "PyPI:werkzeug").  Strip the
    # ecosystem prefix to get bare package names that dependency scanning
    # and version analysis can use.
    raw_pkgs = advisories.get("affected_packages", [])
    scan_targets: list[str] = []
    for pkg in raw_pkgs:
        # Strip ecosystem prefix ("PyPI:werkzeug" → "werkzeug")
        name = pkg.split(":", 1)[-1] if ":" in pkg else pkg
        name = name.strip()
        if name and name.lower() != "unknown":
            scan_targets.append(name)
    # De-duplicate while preserving order
    scan_targets = list(dict.fromkeys(scan_targets))

    if scan_targets:
        logger.info(
            "[fetch_advisory] Scan targets derived from advisory: %s", scan_targets
        )
    else:
        logger.warning(
            "[fetch_advisory] Advisory has no identifiable affected packages — "
            "dependency scan will fall back to component_name"
        )

    return {
        "advisories": advisories,
        "summary": summary,
        "scan_targets": scan_targets,
        "step_reports": {
            "fetch_advisory": {
                "title": "Advisory Lookup",
                "status": "ok" if summary else "partial",
                "findings": {
                    "summary": summary
                    or f"No summary available for {state['vuln_id']}",
                    "affected_packages": advisories.get("affected_packages", []),
                    "affected_ranges": advisories.get("affected_ranges", []),
                    "affected_versions_count": ver_count,
                    "vulnerable_symbols": advisories.get("vulnerable_symbols", []),
                    "cwes": advisories.get("cwe", []),
                    "data_warnings": data_warnings,
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# filter_advisory  (ecosystem relevance check)
# ----------------------------------------------------------------------- #


def _detect_project_ecosystems(repo_path: str | None) -> set[str]:
    """Detect the project's ecosystems from manifest files on disk.

    Only works when *repo_path* is available (pre-seeded or already cloned).
    Returns an empty set when we cannot determine the ecosystems.
    """
    if not repo_path or not os.path.isdir(repo_path):
        return set()
    ecosystems: set[str] = set()
    max_depth = 4
    for root, dirs, files in os.walk(repo_path):
        rel_root = os.path.relpath(root, repo_path)
        depth = 0 if rel_root == "." else rel_root.count(os.sep) + 1
        if depth > max_depth:
            dirs[:] = []
            continue

        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".") and d not in {"node_modules", "dist", "build"}
        ]
        for fname in files:
            eco = web_fetcher._ECOSYSTEM_HINTS.get(fname)
            if eco:
                ecosystems.add(eco)
    return ecosystems


async def filter_advisory(state: PipelineState) -> dict:
    """Decide whether the advisory is relevant to this project's technology.

    Runs after ``fetch_advisory`` (advisory data available) and before
    ``prepare_repo``.  When the advisory clearly targets a different
    technology ecosystem the pipeline short-circuits to the verdict node
    with "Not Affected — advisory not relevant".

    Relevance rules (conservative — only rejects clear mismatches):

    1. If the advisory contains OSV-sourced packages (``PyPI:foo``,
       ``npm:bar``, …) **and** the project ecosystem is known, require
       at least one ecosystem overlap.
    2. If the advisory contains **only** ``NVD:`` prefixed packages
       (no OSV data), the CVE is likely about standalone / commercial
       software rather than a library dependency.  Mark irrelevant
       unless the bare product name matches the component name or
       known scan targets.
    3. Default: assume relevant (avoid false negatives).
    """
    advisory = state.get("advisories") or {}
    affected_packages = advisory.get("affected_packages", [])
    cpe_entries = advisory.get("cpe_entries", [])
    component = state.get("component_name", "")

    # Fast path: no advisory data → nothing to filter.
    if not affected_packages:
        logger.info("[filter_advisory] No affected packages — assuming relevant")
        return {
            "advisory_relevant": True,
            "step_reports": {
                "filter_advisory": {
                    "title": "Advisory Relevance Filter",
                    "status": "skipped",
                    "findings": {"reason": "no affected packages in advisory"},
                    "evidence": ["No affected packages — skipping filter"],
                },
            },
            "evidence": [
                "Advisory relevance filter: no packages to check — pass-through"
            ],
        }

    # Separate OSV-sourced from NVD-only packages.
    osv_packages = [p for p in affected_packages if not p.startswith("NVD:")]
    nvd_packages = [p for p in affected_packages if p.startswith("NVD:")]

    # Try to determine the project's ecosystem.
    project_eco: set[str] = set()
    cfg_eco = (state.get("component_cfg") or {}).get("ecosystem")
    if cfg_eco:
        project_eco.add(cfg_eco)
    # Use repo_path when already set in state (pre-seeded or already cloned).
    effective_repo_path = state.get("repo_path")
    # filter_advisory runs before prepare_repo, so repo_path is usually not
    # set yet.  If the repo was previously cloned we can still detect the
    # ecosystem from the on-disk copy by computing the deterministic path.
    if not effective_repo_path:
        cfg_url = (state.get("component_cfg") or {}).get("url")
        if cfg_url:
            candidate = dependency_scanner._repo_dir(cfg_url)
            if os.path.isdir(candidate):
                effective_repo_path = candidate
    if not project_eco:
        project_eco = _detect_project_ecosystems(effective_repo_path)

    manifest_files = _list_project_manifests(effective_repo_path)

    reasons: list[str] = []

    # --- Rule 1: OSV ecosystem mismatch ---
    if osv_packages:
        advisory_ecosystems = {p.split(":", 1)[0] for p in osv_packages if ":" in p}
        if project_eco and advisory_ecosystems:
            overlap = advisory_ecosystems & project_eco
            if overlap:
                reasons.append(
                    f"OSV ecosystem match: {overlap} (project={project_eco})"
                )
                logger.info(
                    "[filter_advisory] OSV ecosystems match: %s ∩ %s = %s",
                    advisory_ecosystems,
                    project_eco,
                    overlap,
                )
            else:
                msg = (
                    f"Advisory targets {advisory_ecosystems} but project uses "
                    f"{project_eco} — ecosystem mismatch"
                )
                reasons.append(msg)
                logger.info("[filter_advisory] %s", msg)
                return _irrelevant_result(state, reasons)
        else:
            reasons.append(
                f"OSV packages present ({len(osv_packages)}) but project ecosystem "
                f"unknown — deferring to additional relevance checks"
            )

    # --- Rule 2: NVD-only advisory (no OSV data) ---
    if not osv_packages and nvd_packages:
        # All affected packages are NVD CPE-derived.  This almost always
        # means the CVE is about standalone / commercial software.
        # Only pass through if a CPE product name matches the component
        # itself. We intentionally do not trust scan_targets here because
        # they are derived from the advisory we are evaluating.
        nvd_products = {p.split(":", 1)[-1].lower() for p in nvd_packages}
        comp_lower = component.lower()

        name_match = nvd_products & {comp_lower}
        if name_match:
            reasons.append(
                f"NVD-only advisory but product name {name_match} matches "
                f"the component name — assuming relevant"
            )
        else:
            llm_result = await _llm_relevance_decision(
                state=state,
                project_ecosystems=project_eco,
                manifest_files=manifest_files,
                advisory_ecosystems=set(),
            )
            if llm_result:
                reasons.extend(llm_result["reasons"])
                if not llm_result["relevant"]:
                    logger.info(
                        "[filter_advisory] LLM marked advisory irrelevant: %s",
                        "; ".join(llm_result["reasons"]),
                    )
                    return _irrelevant_result(state, reasons)

            if not llm_result:
                msg = (
                    f"Advisory has only NVD CPE data (products: "
                    f"{', '.join(sorted(nvd_products))}) with no OSV ecosystem "
                    f"coverage — likely standalone/commercial software, not a "
                    f"library dependency of '{component}'"
                )
                reasons.append(msg)
                logger.info("[filter_advisory] %s", msg)
                return _irrelevant_result(state, reasons)

    # --- Rule 3: ambiguous ecosystem / package context ---
    if osv_packages and not project_eco:
        llm_result = await _llm_relevance_decision(
            state=state,
            project_ecosystems=project_eco,
            manifest_files=manifest_files,
            advisory_ecosystems={p.split(":", 1)[0] for p in osv_packages if ":" in p},
        )
        if llm_result:
            reasons.extend(llm_result["reasons"])
            if not llm_result["relevant"]:
                logger.info(
                    "[filter_advisory] LLM marked advisory irrelevant: %s",
                    "; ".join(llm_result["reasons"]),
                )
                return _irrelevant_result(state, reasons)

    # Default: relevant
    logger.info(
        "[filter_advisory] Advisory deemed relevant for '%s': %s",
        component,
        "; ".join(reasons) or "no mismatch detected",
    )
    return {
        "advisory_relevant": True,
        "step_reports": {
            "filter_advisory": {
                "title": "Advisory Relevance Filter",
                "status": "ok",
                "findings": {"relevant": True, "reasons": reasons},
                "evidence": reasons or ["No ecosystem mismatch detected — proceeding"],
            },
        },
        "evidence": reasons
        or ["Advisory relevance filter: pass — no mismatch detected"],
    }


async def _llm_relevance_decision(
    *,
    state: PipelineState,
    project_ecosystems: set[str],
    manifest_files: list[str],
    advisory_ecosystems: set[str],
) -> dict | None:
    """Ask the configured LLM to classify advisory relevance in ambiguous cases.

    Returns ``None`` when no LLM is configured or when the response cannot be parsed.
    The returned payload is ``{"relevant": bool, "reasons": list[str]}``.
    """
    ollama = state.get("ollama")
    if not ollama:
        return None

    advisory = state.get("advisories") or {}
    payload = {
        "component_name": state.get("component_name", ""),
        "project_ecosystems": sorted(project_ecosystems),
        "project_manifests": manifest_files,
        "component_cfg": {
            key: value
            for key, value in (state.get("component_cfg") or {}).items()
            if key in {"name", "ecosystem", "language", "type"}
        },
        "vuln_id": state.get("vuln_id", ""),
        "summary": state.get("summary", ""),
        "affected_packages": advisory.get("affected_packages", []),
        "advisory_ecosystems": sorted(advisory_ecosystems),
        "cpe_entries": advisory.get("cpe_entries", []),
        "sources": advisory.get("sources", []),
        "data_warnings": advisory.get("data_warnings", []),
    }

    prompt = (
        f"{_ADVISORY_RELEVANCE_INSTRUCTIONS}\n\n"
        f"{_ADVISORY_RELEVANCE_INPUT_PREAMBLE}\n"
        f"{json.dumps(payload, indent=2, sort_keys=True)}"
    )

    try:
        raw = await ollama.generate(
            prompt,
            system=_ADVISORY_RELEVANCE_SYSTEM,
            temperature=0.0,
            timeout=45,
            num_predict=400,
        )
    except Exception as exc:
        logger.warning("[filter_advisory] LLM relevance check failed: %s", exc)
        return {
            "relevant": None,
            "reasons": [f"LLM relevance check failed: {exc}"],
            "error": str(exc),
        }

    parsed = _extract_json_object(raw)
    if not isinstance(parsed, dict):
        logger.warning("[filter_advisory] Could not parse LLM relevance JSON: %r", raw)
        return None

    relevant = parsed.get("relevant")
    reasons = parsed.get("reasons")
    confidence = str(parsed.get("confidence", "")).lower()
    if not isinstance(relevant, bool) or not isinstance(reasons, list):
        logger.warning("[filter_advisory] Invalid LLM relevance payload: %r", parsed)
        return None

    cleaned_reasons = [str(reason).strip() for reason in reasons if str(reason).strip()]
    if confidence:
        cleaned_reasons.insert(0, f"LLM relevance decision ({confidence} confidence)")
    else:
        cleaned_reasons.insert(0, "LLM relevance decision")
    return {"relevant": relevant, "reasons": cleaned_reasons}


def _extract_json_object(raw: str) -> dict | None:
    """Extract a top-level JSON object from model output."""
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def _capture_llm_usage(ollama: object | None) -> dict[str, int] | None:
    usage = getattr(ollama, "last_usage", None)
    if not isinstance(usage, dict):
        return None

    normalized: dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int):
            normalized[key] = value

    return normalized or None


def _irrelevant_result(state: PipelineState, reasons: list[str]) -> dict:
    """Build a state update that marks the advisory as irrelevant.

    Populates enough of the downstream state keys that ``aggregate_verdict``
    can produce a clean "Not Affected" report without running any analysis.
    """
    vuln_id = state.get("vuln_id", "unknown")
    summary = state.get("summary", "")
    evidence_lines = [f"FILTERED: {r}" for r in reasons]

    return {
        "advisory_relevant": False,
        # Pre-populate fields that aggregate_verdict reads so it doesn't
        # trip on missing keys.
        "dep_info": {"found": False, "declared_in": [], "reason": "advisory filtered"},
        "usage": [],
        "snippets": [],
        "llm_analysis": {},
        "deep_analysis": {},
        "transitive_analysis": {},
        "version_inventory": {},
        "what_if": {},
        "repo_path": state.get("repo_path", ""),
        "result": {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "high",
            "exposure": "none",
            "reasoning": (
                f"Advisory {vuln_id} was filtered as not relevant to this "
                f"project: {'; '.join(reasons)}"
            ),
        },
        "step_reports": {
            "filter_advisory": {
                "title": "Advisory Relevance Filter",
                "status": "filtered",
                "findings": {"relevant": False, "reasons": reasons},
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# prepare_repo
# ----------------------------------------------------------------------- #
async def prepare_repo(state: PipelineState) -> dict:
    # If a focus_path was already seeded into state (e.g. from the request),
    # skip cloning and use that path directly.
    if state.get("repo_path"):
        repo_path = state["repo_path"]
        logger.info("[prepare_repo] Using pre-set repo_path=%s (skip clone)", repo_path)
        return {
            "repo_path": repo_path,
            "step_reports": {
                "prepare_repo": {
                    "title": "Repository Clone",
                    "status": "skipped",
                    "findings": {"repo_path": repo_path},
                    "evidence": [f"Using local path {repo_path} (no clone needed)"],
                },
            },
            "evidence": [f"Using local path {repo_path} (no clone needed)"],
        }
    logger.info(
        "[prepare_repo] Cloning repo for component '%s'", state["component_name"]
    )
    try:
        repo_path = await dependency_scanner.prepare_repo(state["component_cfg"])
    except RepoError as exc:
        logger.error("[prepare_repo] %s", exc)
        raise
    logger.info("[prepare_repo] Repo ready at %s", repo_path)
    return {
        "repo_path": repo_path,
        "step_reports": {
            "prepare_repo": {
                "title": "Repository Clone",
                "status": "ok",
                "findings": {"repo_path": repo_path},
                "evidence": [f"Cloned repo to {repo_path}"],
            },
        },
        "evidence": [f"Cloned repo to {repo_path}"],
    }


# ----------------------------------------------------------------------- #
# scan_dependencies
# ----------------------------------------------------------------------- #
async def scan_dependencies(state: PipelineState) -> dict:
    scan_target = _get_scan_target(state)
    sbom_attributed = bool(state.get("sbom_attributed", True))
    logger.info(
        "[scan_dependencies] Scanning for '%s' in %s (component=%s, sbom_attributed=%s)",
        scan_target,
        state["repo_path"],
        state["component_name"],
        sbom_attributed,
    )
    dep_info = dependency_scanner.find_component(
        state["repo_path"],
        scan_target,
        sbom_attributed=sbom_attributed,
    )
    dep_info["repo_path"] = state["repo_path"]
    dep_info["component_name"] = scan_target
    dep_type = dep_info.get("presence_basis", "not_found")
    logger.info(
        "[scan_dependencies] found=%s, repo_found=%s, sbom_attributed=%s, type=%s, declared_in=%s, lock_files=%s, locked_version=%s",
        dep_info["found"],
        dep_info.get("repo_found", False),
        dep_info.get("sbom_attributed", False),
        dep_type,
        dep_info["declared_in"],
        dep_info.get("lock_files", []),
        dep_info.get("locked_version"),
    )
    dep_evidence = [
        f"Dependency scan: found={dep_info['found']} ({dep_type}), "
        f"repo_found={dep_info.get('repo_found', False)}, "
        f"sbom_attributed={dep_info.get('sbom_attributed', False)}, "
        f"manifests={dep_info['declared_in']}, "
        f"lock_files={dep_info.get('lock_files', [])}, "
        f"locked_version={dep_info.get('locked_version')}"
    ]
    return {
        "dep_info": dep_info,
        "step_reports": {
            "scan_dependencies": {
                "title": "Dependency Scan",
                "status": "found" if dep_info["found"] else "not_found",
                "findings": {
                    "found": dep_info["found"],
                    "repo_found": dep_info.get("repo_found", False),
                    "sbom_attributed": dep_info.get("sbom_attributed", False),
                    "dependency_type": dep_type,
                    "declared_in": dep_info["declared_in"],
                    "lock_files": dep_info.get("lock_files", []),
                    "locked_version": dep_info.get("locked_version"),
                },
                "evidence": dep_evidence,
            },
        },
        "evidence": dep_evidence,
    }


# ----------------------------------------------------------------------- #
# scan_code
# ----------------------------------------------------------------------- #
async def scan_code(state: PipelineState) -> dict:
    symbols = state["advisories"].get("vulnerable_symbols", [])
    component = _get_scan_target(state)
    cwe_ids = state["advisories"].get("cwe", [])
    repo_path = state["repo_path"]
    logger.info(
        "[scan_code] Scanning for %d symbols + '%s' (component=%s)",
        len(symbols),
        component,
        state["component_name"],
    )

    # --- AST analysis: discover imported symbols + call sites --- #
    ast_graph = ast_analyzer.analyze_repository(repo_path, component, symbols)

    # When the advisory listed no vulnerable symbols, try CWE heuristics.
    cwe_hints: list[str] = []
    if not symbols:
        cwe_hints = ast_analyzer.infer_symbols_from_cwe(cwe_ids)
        logger.info(
            "[scan_code] No advisory symbols; CWE hints: %s",
            cwe_hints,
        )

    # Merge: advisory symbols + AST-discovered symbols + CWE hints.
    all_symbols = list(
        dict.fromkeys(
            symbols + ast_graph.resolved_symbols + cwe_hints,
        )
    )

    # --- Traditional text search with expanded symbols --- #
    usage = code_scanner.search_usage(repo_path, component, all_symbols)
    snippets = code_scanner.collect_snippets(repo_path, component, all_symbols)
    structure = code_scanner.collect_structure(repo_path, component, all_symbols)

    # --- Format AST context for LLM --- #
    ast_context = ast_analyzer.format_for_llm(ast_graph)

    hit_count = len(usage) if isinstance(usage, list) else 0
    logger.info(
        "[scan_code] %d hits, %d snippets, %d chars of structure, "
        "%d AST imports, %d AST calls",
        hit_count,
        len(snippets),
        len(structure),
        len(ast_graph.imports),
        len(ast_graph.calls),
    )

    search_terms = [t for t in ([component] + all_symbols) if t]
    files_with_hits = sorted({s["file"] for s in snippets}) if snippets else []

    evidence_lines = [
        f"Code scan searched for: {', '.join(search_terms)}",
    ]
    if ast_graph.resolved_symbols:
        evidence_lines.append(
            f"AST-discovered symbols (from imports): "
            f"{', '.join(ast_graph.resolved_symbols)}"
        )
    if cwe_hints:
        evidence_lines.append(
            f"CWE-inferred patterns ({', '.join(cwe_ids)}): {', '.join(cwe_hints)}"
        )
    evidence_lines.extend(
        [
            f"Files with references ({len(files_with_hits)}): "
            f"{', '.join(files_with_hits) if files_with_hits else 'none'}",
            f"Total references: {hit_count}, snippets extracted: {len(snippets)}, "
            f"structural context: {len(structure)} chars",
            f"AST analysis: {len(ast_graph.imports)} imports, "
            f"{len(ast_graph.calls)} call sites across "
            f"{ast_graph.files_analyzed} files",
        ]
    )
    if usage and usage != ["No direct usage found"]:
        for h in usage[:10]:
            evidence_lines.append(f"  hit: {h}")
        if len(usage) > 10:
            evidence_lines.append(f"  … and {len(usage) - 10} more")

    return {
        "usage": usage,
        "snippets": snippets,
        "structure": structure,
        "ast_context": ast_context,
        "step_reports": {
            "scan_code": {
                "title": "Code Scan",
                "status": "hits"
                if (usage and usage != ["No direct usage found"])
                else "clean",
                "findings": {
                    "search_terms": search_terms,
                    "hit_count": hit_count,
                    "files_with_hits": files_with_hits,
                    "snippet_count": len(snippets),
                    "ast_imports": len(ast_graph.imports),
                    "ast_calls": len(ast_graph.calls),
                    "discovered_symbols": ast_graph.resolved_symbols,
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# llm_analyze_code
# ----------------------------------------------------------------------- #
async def llm_analyze_code(state: PipelineState) -> dict:
    """Send collected source snippets to the LLM for reachability analysis."""
    ollama = state.get("ollama")
    snippets = state.get("snippets", [])
    advisories = state.get("advisories", {})

    advisory_summary = _build_advisory_analysis_input(
        state["vuln_id"],
        advisories,
        state.get("user_guidance", ""),
    )

    structure = state.get("structure", "")
    ast_context = state.get("ast_context", "")
    if ast_context:
        structure = structure + "\n\n" + ast_context if structure else ast_context
    logger.info(
        "[llm_analyze_code] Analyzing %d snippets + structure (%d chars) with LLM",
        len(snippets),
        len(structure),
    )
    analysis = await code_scanner.analyze_with_llm(
        ollama,
        state["vuln_id"],
        advisory_summary,
        snippets,
        structure=structure,
    )
    llm_usage = _capture_llm_usage(ollama)
    if llm_usage:
        analysis = {**analysis, "llm_usage": llm_usage}
    logger.info(
        "[llm_analyze_code] reachable=%s, risk_areas=%s, invocation_paths=%d",
        analysis.get("reachable"),
        analysis.get("risk_areas"),
        len(analysis.get("invocation_paths", [])),
    )

    paths = analysis.get("invocation_paths", [])
    risk_areas = analysis.get("risk_areas", [])
    reasoning = analysis.get("reasoning", "")
    analysis_error = analysis.get("error", "")
    analyzed_files = sorted({s["file"] for s in snippets}) if snippets else []

    evidence_lines = [
        f"LLM analyzed {len(snippets)} code snippets from: {', '.join(analyzed_files) if analyzed_files else 'none'}",
        f"Structural context provided: {'yes' if structure else 'no'} ({len(structure)} chars)",
        f"LLM reachability verdict: {'REACHABLE' if analysis.get('reachable') else 'NOT REACHABLE'}",
    ]
    if risk_areas:
        evidence_lines.append(f"Risk areas identified: {', '.join(risk_areas)}")
    if paths:
        evidence_lines.append(f"Invocation paths found ({len(paths)}):")
        for p in paths:
            evidence_lines.append(f"  {p}")
    else:
        evidence_lines.append("Invocation paths: none found")
    if reasoning:
        evidence_lines.append(f"LLM reasoning: {reasoning}")
    if analysis_error:
        evidence_lines.append(f"LLM error: {analysis_error}")
    if llm_usage:
        evidence_lines.append(
            "LLM usage: "
            f"prompt={llm_usage.get('prompt_tokens', 0)}, "
            f"completion={llm_usage.get('completion_tokens', 0)}, "
            f"total={llm_usage.get('total_tokens', 0)}"
        )
    if analysis.get("research_log"):
        evidence_lines.append("Web research performed:")
        for entry in analysis["research_log"]:
            evidence_lines.append(f"  {entry}")

    return {
        "llm_analysis": analysis,
        "step_reports": {
            "llm_analyze_code": {
                "title": "LLM Reachability Analysis",
                "status": "reachable" if analysis.get("reachable") else "not_reachable",
                "findings": {
                    "reachable": analysis.get("reachable", False),
                    "risk_areas": risk_areas,
                    "invocation_paths": paths,
                    "reasoning": reasoning,
                    "error": analysis_error,
                    "analyzed_files": analyzed_files,
                    "llm_usage": llm_usage,
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# llm_deep_analyze
# ----------------------------------------------------------------------- #
async def llm_deep_analyze(state: PipelineState) -> dict:
    """Optional second-pass deep analysis when the first pass found paths."""
    llm_analysis = state.get("llm_analysis", {})
    reachable = llm_analysis.get("reachable", False)
    inv_paths = llm_analysis.get("invocation_paths", [])

    if not reachable and not inv_paths:
        logger.info("[llm_deep_analyze] Skipped — first pass found no reachable paths")
        return {
            "deep_analysis": {},
            "step_reports": {
                "llm_deep_analyze": {
                    "title": "Deep Exploitability Analysis",
                    "status": "skipped",
                    "findings": {"reason": "No reachable paths from first pass"},
                    "evidence": [
                        "Deep analysis: skipped (no reachable paths from first pass)"
                    ],
                },
            },
            "evidence": ["Deep analysis: skipped (no reachable paths from first pass)"],
        }

    repo_path = state.get("repo_path", "")
    risk_areas = llm_analysis.get("risk_areas", [])

    snippets = state.get("snippets", [])
    snippet_files = sorted({s["file"] for s in snippets}) if snippets else []

    path_context = code_scanner.extract_path_context(
        repo_path,
        inv_paths,
        risk_areas,
        snippet_files=snippet_files,
    )

    if not path_context:
        logger.info("[llm_deep_analyze] Skipped — no source files resolved from paths")
        return {
            "deep_analysis": {},
            "step_reports": {
                "llm_deep_analyze": {
                    "title": "Deep Exploitability Analysis",
                    "status": "skipped",
                    "findings": {
                        "reason": "Could not resolve source files from invocation paths"
                    },
                    "evidence": [
                        "Deep analysis: skipped (could not resolve source files from invocation paths)"
                    ],
                },
            },
            "evidence": [
                "Deep analysis: skipped (could not resolve source files from invocation paths)"
            ],
        }

    advisories = state.get("advisories", {})
    summary = _build_advisory_analysis_input(
        state["vuln_id"],
        advisories,
        state.get("user_guidance", ""),
    )
    ollama = state.get("ollama")
    deep = await code_scanner.deep_analyze_with_llm(
        ollama,
        state["vuln_id"],
        summary,
        llm_analysis,
        path_context,
    )
    llm_usage = _capture_llm_usage(ollama)
    if llm_usage:
        deep = {**deep, "llm_usage": llm_usage}

    logger.info(
        "[llm_deep_analyze] confirmed=%s, exploitable=%s, risk_level=%s",
        deep.get("confirmed"),
        deep.get("exploitable"),
        deep.get("risk_level"),
    )

    deep_files = [f["file"] for f in path_context]
    deep_error = deep.get("error", "")
    evidence_lines = [
        f"Deep analysis examined {len(path_context)} files: {', '.join(deep_files)}",
        f"Confirmed: {deep.get('confirmed')}, Exploitable: {deep.get('exploitable')}, "
        f"Risk level: {deep.get('risk_level')}",
        f"Mitigations: {deep.get('mitigations', 'N/A')}",
        f"Deep reasoning: {deep.get('reasoning', '')}",
    ]
    if deep_error:
        evidence_lines.append(f"LLM error: {deep_error}")
    if llm_usage:
        evidence_lines.append(
            "LLM usage: "
            f"prompt={llm_usage.get('prompt_tokens', 0)}, "
            f"completion={llm_usage.get('completion_tokens', 0)}, "
            f"total={llm_usage.get('total_tokens', 0)}"
        )
    if deep.get("research_log"):
        evidence_lines.append("Web research performed:")
        for entry in deep["research_log"]:
            evidence_lines.append(f"  {entry}")

    return {
        "deep_analysis": deep,
        "step_reports": {
            "llm_deep_analyze": {
                "title": "Deep Exploitability Analysis",
                "status": "confirmed" if deep.get("confirmed") else "not_confirmed",
                "findings": {
                    "confirmed": deep.get("confirmed", False),
                    "exploitable": deep.get("exploitable", "UNCERTAIN"),
                    "risk_level": deep.get("risk_level", "MEDIUM"),
                    "mitigations": deep.get("mitigations", "N/A"),
                    "reasoning": deep.get("reasoning", ""),
                    "error": deep_error,
                    "files_examined": deep_files,
                    "llm_usage": llm_usage,
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# analyze_versions
# ----------------------------------------------------------------------- #
async def analyze_versions(state: PipelineState) -> dict:
    scan_target = _get_scan_target(state)
    affected_ranges = state["advisories"].get("affected_ranges", [])
    affected_versions = state["advisories"].get("affected_versions", []) or None
    affected_product_versions = state.get("affected_product_versions") or []
    locked_version = state.get("dep_info", {}).get("locked_version")
    logger.info(
        "[analyze_versions] %d affected ranges, %d explicit versions, "
        "%d affected product versions for '%s' (component=%s), locked_version=%s",
        len(affected_ranges),
        len(affected_versions or []),
        len(affected_product_versions),
        scan_target,
        state["component_name"],
        locked_version,
    )
    inventory = version_analyzer.inventory_versions(
        state["repo_path"],
        scan_target,
        affected_ranges,
        locked_version=locked_version,
        affected_versions=affected_versions,
        affected_product_versions=affected_product_versions,
    )
    worst = inventory.get("worst_case", {})
    logger.info(
        "[analyze_versions] worst_case.affected=%s, rows=%d, locked_version=%s",
        worst.get("affected", False),
        len(inventory.get("version_table", [])),
        worst.get("locked_version"),
    )
    worst_affected = worst.get("affected", False)
    table = inventory.get("version_table", [])
    version_trace = inventory.get("trace", [])
    lock_rows = sum(1 for r in table if r.get("source") == "lock")
    manifest_rows = sum(1 for r in table if r.get("source") == "manifest")
    tag_rows = sum(1 for r in table if r.get("ref_type") == "tag")
    branch_rows = sum(1 for r in table if r.get("ref_type") == "branch")
    historical = worst.get("historical_affected", [])
    comparison_inputs = inventory.get("comparison_inputs", {})
    found_lockfiles = comparison_inputs.get("lock_files_found_by_ref", {})
    processed_lockfiles = comparison_inputs.get("lock_files_processed_by_ref", {})

    evidence_lines = [
        f"Locked version: {locked_version or 'unknown'}",
        "DTVP affected product versions: "
        + (", ".join(affected_product_versions) if affected_product_versions else "none provided"),
        f"Worst-case affected: {worst_affected}",
        f"Release refs analysed: {len(table)} "
        f"({tag_rows} tags, {branch_rows} release branches, "
        f"{lock_rows} from lock files, {manifest_rows} from manifests)",
    ]
    if found_lockfiles or processed_lockfiles:
        evidence_lines.append("Lock files found and processed:")
        evidence_lines.extend(
            version_analyzer._format_lockfile_summary_lines(
                found_lockfiles,
                processed_lockfiles,
            )
        )
    if historical:
        evidence_lines.append(
            "Historical releases affected: "
            + ", ".join(f"{h['ref']} ({h['component_version']})" for h in historical)
        )
    # Include the version comparison trace for full traceability
    if version_trace:
        evidence_lines.append("Version comparison trace:")
        evidence_lines.extend(f"  {line}" for line in version_trace)

    return {
        "version_inventory": inventory,
        "step_reports": {
            "analyze_versions": {
                "title": "Version Inventory",
                "status": "affected" if worst_affected else "not_affected",
                "findings": {
                    "locked_version": locked_version,
                    "affected_ranges": version_analyzer.summarize_ranges_for_debug(
                        affected_ranges,
                        affected_versions,
                    ),
                    "affected_product_versions": affected_product_versions,
                    "lock_files_found_by_ref": found_lockfiles,
                    "lock_files_processed_by_ref": processed_lockfiles,
                    "worst_case_affected": worst_affected,
                    "version_table": table,
                    "historical_affected": historical,
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# what_if_remediation
# ----------------------------------------------------------------------- #
async def what_if_remediation(state: PipelineState) -> dict:
    """Determine remediation options: which fixed version resolves the CVE."""
    inventory = state.get("version_inventory", {})
    affected_ranges = state["advisories"].get("affected_ranges", [])
    fixed_versions = state["advisories"].get("fixed_versions", [])
    affected_versions = state["advisories"].get("affected_versions", []) or None

    what_if = version_analyzer.analyze_what_if(
        inventory,
        affected_ranges,
        fixed_versions=fixed_versions,
        affected_versions=affected_versions,
    )
    logger.info(
        "[what_if_remediation] current=%s affected=%s, %d fixed versions, summary=%s",
        what_if.get("current_version"),
        what_if.get("current_affected"),
        len(what_if.get("fixed_versions", [])),
        what_if.get("summary"),
    )

    evidence_lines = [what_if["summary"]]
    if what_if.get("remediation"):
        for opt in what_if["remediation"]:
            line = f"  Upgrade to {opt['target_version']}"
            if opt.get("change"):
                line += f" ({opt['change']})"
            evidence_lines.append(line)

    return {
        "what_if": what_if,
        "step_reports": {
            "what_if_remediation": {
                "title": "What-If Remediation",
                "status": "action_needed" if what_if.get("current_affected") else "ok",
                "findings": {
                    "current_version": what_if.get("current_version"),
                    "current_affected": what_if.get("current_affected"),
                    "component_not_found": what_if.get("component_not_found"),
                    "fixed_versions": what_if.get("fixed_versions", []),
                    "remediation": what_if.get("remediation", []),
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# check_transitive_paths
# ----------------------------------------------------------------------- #
async def check_transitive_paths(state: PipelineState) -> dict:
    """Check whether a transitive dependency is reachable via intermediary packages.

    Runs only when the dependency is transitive (lock-file-only) and there
    is no direct code usage of the vulnerable component.

    Builds full dependency chains from lock files (project → A → B → vuln)
    and merges any caller-supplied ``dependency_paths``.  Finds the first-hop
    intermediary from each chain, scans the project code for those, and asks
    the LLM to trace the path using the full chain context.
    """
    dep_info = state.get("dep_info", {})
    usage = state.get("usage", [])
    is_transitive = dep_info.get("transitive", False)
    has_direct_usage = usage and usage != ["No direct usage found"]

    # Skip if not transitive or if there's already direct usage
    if not is_transitive or has_direct_usage:
        reason = (
            "not a transitive dependency"
            if not is_transitive
            else "direct code usage already found"
        )
        logger.info("[check_transitive_paths] Skipped — %s", reason)
        return {
            "transitive_analysis": {"skipped": True, "reason": reason},
            "step_reports": {
                "check_transitive_paths": {
                    "title": "Transitive Call-Path Analysis",
                    "status": "skipped",
                    "findings": {"reason": reason},
                    "evidence": [f"Transitive path check: skipped ({reason})"],
                },
            },
            "evidence": [f"Transitive path check: skipped ({reason})"],
        }

    repo_path = state.get("repo_path", "")
    component_name = _get_scan_target(state)
    advisories = state.get("advisories", {})
    ollama = state.get("ollama")

    # 1. Build full chains from lock files
    lock_chains = dependency_scanner.build_dependency_chains(repo_path, component_name)

    # 2. Merge caller-supplied dependency_paths (for Conan, pip, etc.)
    caller_paths = state.get("dependency_paths", [])
    caller_chains: list[dict] = []
    for path_list in caller_paths:
        if path_list:
            chain = [{"name": name, "version": ""} for name in path_list]
            caller_chains.append({"chain": chain, "lock_file": "caller-provided"})

    all_chains = lock_chains + caller_chains

    # 3. Also get flat intermediary list (for backward compat + code scan)
    intermediaries = dependency_scanner.find_reverse_dependencies(
        repo_path, component_name
    )
    # Add any first-hop intermediaries from chains that aren't already known
    known_names = {i["name"].lower() for i in intermediaries}
    for c in all_chains:
        if c["chain"]:
            first_hop = c["chain"][0]
            if first_hop["name"].lower() not in known_names:
                known_names.add(first_hop["name"].lower())
                intermediaries.append(
                    {
                        "name": first_hop["name"],
                        "version": first_hop["version"],
                        "lock_file": c["lock_file"],
                    }
                )

    if not intermediaries and not all_chains:
        logger.info(
            "[check_transitive_paths] No intermediary packages found for '%s'",
            component_name,
        )
        return {
            "transitive_analysis": {
                "reachable": "UNCERTAIN",
                "confidence": "Low",
                "intermediary": "",
                "reasoning": (
                    "The component is a transitive dependency but no intermediary "
                    "packages could be identified from lock files."
                ),
                "usage_hits": 0,
                "intermediaries_checked": [],
                "dependency_chains": [],
            },
            "step_reports": {
                "check_transitive_paths": {
                    "title": "Transitive Call-Path Analysis",
                    "status": "no_intermediaries",
                    "findings": {"intermediaries": [], "dependency_chains": []},
                    "evidence": [
                        "Transitive path check: no intermediary packages identified"
                    ],
                },
            },
            "evidence": ["Transitive path check: no intermediary packages identified"],
        }

    # Format chains for logging and evidence
    chain_strs = []
    for c in all_chains:
        names = [n["name"] for n in c["chain"]]
        chain_strs.append(
            " → ".join(names) + f" → {component_name} (via {c['lock_file']})"
        )

    logger.info(
        "[check_transitive_paths] Found %d intermediaries, %d chains for '%s'",
        len(intermediaries),
        len(all_chains),
        component_name,
    )
    for cs in chain_strs:
        logger.info("[check_transitive_paths]   chain: %s", cs)

    advisory_summary = _build_advisory_analysis_input(
        state["vuln_id"],
        advisories,
        state.get("user_guidance", ""),
    )

    result = await code_scanner.analyze_transitive_paths(
        ollama=ollama,
        vuln_id=state["vuln_id"],
        advisory_summary=advisory_summary,
        intermediaries=intermediaries,
        repo_path=repo_path,
        vulnerable_symbols=advisories.get("vulnerable_symbols", []),
        dependency_chains=all_chains,
        vulnerable_component=component_name,
    )
    inter_names = [i["name"] for i in intermediaries]
    result.setdefault("dependency_chains", chain_strs)
    result.setdefault("intermediaries", inter_names)

    logger.info(
        "[check_transitive_paths] reachable=%s, confidence=%s, intermediary=%s, hits=%d",
        result.get("reachable"),
        result.get("confidence"),
        result.get("intermediary"),
        result.get("usage_hits", 0),
    )

    evidence_lines = [
        f"Dependency chains found: {len(all_chains)}",
    ]
    for cs in chain_strs[:10]:
        evidence_lines.append(f"  {cs}")
    if len(chain_strs) > 10:
        evidence_lines.append(f"  … and {len(chain_strs) - 10} more")
    evidence_lines.extend(
        [
            f"First-hop intermediary packages: {', '.join(inter_names)}",
            f"Code references to intermediaries: {result.get('usage_hits', 0)}",
            f"Transitive reachability: {result.get('reachable')} (confidence: {result.get('confidence')})",
            f"Transitive reasoning: {result.get('reasoning', '')}",
        ]
    )
    if result.get("research_log"):
        evidence_lines.append("Web research performed:")
        for entry in result["research_log"]:
            evidence_lines.append(f"  {entry}")

    return {
        "transitive_analysis": result,
        "step_reports": {
            "check_transitive_paths": {
                "title": "Transitive Call-Path Analysis",
                "status": result.get("reachable", "UNCERTAIN").lower(),
                "findings": {
                    "reachable": result.get("reachable"),
                    "confidence": result.get("confidence"),
                    "intermediary": result.get("intermediary"),
                    "intermediaries": inter_names,
                    "dependency_chains": [
                        " → ".join(n["name"] for n in c["chain"])
                        + f" → {component_name}"
                        for c in all_chains
                    ],
                    "usage_hits": result.get("usage_hits", 0),
                    "reasoning": result.get("reasoning", ""),
                },
                "evidence": evidence_lines,
            },
        },
        "evidence": evidence_lines,
    }


# ----------------------------------------------------------------------- #
# aggregate_verdict
# ----------------------------------------------------------------------- #
async def aggregate_verdict(state: PipelineState) -> dict:
    logger.info("[aggregate_verdict] Producing final verdict with LLM …")
    ollama = state.get("ollama")
    final = await verdict.aggregate(
        ollama=ollama,
        vuln_id=state["vuln_id"],
        advisories=state["advisories"],
        dep_info=state["dep_info"],
        usage=state["usage"],
        version_inventory=state.get("version_inventory"),
        llm_analysis=state.get("llm_analysis"),
        deep_analysis=state.get("deep_analysis"),
        transitive_analysis=state.get("transitive_analysis"),
        user_guidance=state.get("user_guidance", ""),
        cvss_vector=state.get("cvss_vector", ""),
        debug=state.get("debug", False),
        vulnerable_component=_get_scan_target(state),
    )
    final["version_inventory"] = state.get("version_inventory", {})
    final["what_if"] = state.get("what_if", {})
    final["summary"] = state.get("summary", "")
    deep = state.get("deep_analysis", {})
    if deep and not deep.get("skipped"):
        final["deep_analysis"] = deep
    logger.info(
        "[aggregate_verdict] verdict=%s, confidence=%s, affected=%s",
        final.get("verdict"),
        final.get("confidence"),
        final.get("affected"),
    )
    verdict_evidence = [
        f"Final verdict: {final.get('verdict')} (confidence={final.get('confidence')})",
    ]
    # CVSS rescoring traceability
    adj_cvss = final.get("adjusted_cvss") or {}
    version_ctx = final.get("version_context") or adj_cvss.get("version_context") or {}
    if adj_cvss:
        verdict_evidence.append(
            f"CVSS rescoring: {adj_cvss.get('original_score')} → {adj_cvss.get('adjusted_score')}"
        )
        if version_ctx.get("detected_version"):
            verdict_evidence.append(
                f"  Workspace component version checked: {version_ctx['detected_version']} "
                f"(source: {version_ctx.get('version_source', 'unknown')})"
            )
            verdict_evidence.append(
                "  Workspace version in affected range: "
                + (
                    "YES"
                    if version_ctx.get("current_workspace_affected", False)
                    else "NO"
                )
            )
            verdict_evidence.append(
                "  Any tracked release in affected range: "
                + ("YES" if version_ctx.get("affected") else "NO")
            )
            if version_ctx.get("note"):
                verdict_evidence.append(f"  Version check note: {version_ctx['note']}")
            for rng in version_ctx.get("affected_ranges_summary", []):
                verdict_evidence.append(f"  Range: {rng}")
        for reason in adj_cvss.get("reasons", []):
            verdict_evidence.append(f"  Reason: {reason}")
    elif version_ctx.get("detected_version"):
        verdict_evidence.append(
            f"Workspace component version: {version_ctx['detected_version']} "
            f"(source: {version_ctx.get('version_source', 'unknown')})"
        )
        verdict_evidence.append(
            "Workspace version in affected range: "
            + (
                "YES"
                if version_ctx.get("current_workspace_affected", False)
                else "NO"
            )
        )
        verdict_evidence.append(
            "Any tracked release in affected range: "
            + ("YES" if version_ctx.get("affected") else "NO")
        )
        if version_ctx.get("note"):
            verdict_evidence.append(f"Version check note: {version_ctx['note']}")
        for rng in version_ctx.get("affected_ranges_summary", []):
            verdict_evidence.append(f"  {rng}")
    if final.get("research_log"):
        verdict_evidence.append("Web research performed:")
        for entry in final["research_log"]:
            verdict_evidence.append(f"  {entry}")

    return {
        "result": final,
        "step_reports": {
            "aggregate_verdict": {
                "title": "Final Verdict",
                "status": final.get("verdict", "Inconclusive"),
                "findings": {
                    "verdict": final.get("verdict", "Inconclusive"),
                    "confidence": final.get("confidence", "Low"),
                    "affected": final.get("affected", False),
                    "exposure": final.get("exposure", "none"),
                    "reasoning": final.get("reasoning", ""),
                    "version_context": version_ctx,
                },
                "evidence": verdict_evidence,
            },
        },
        "evidence": verdict_evidence,
    }
