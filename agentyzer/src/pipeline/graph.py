"""Vulnerability analysis pipeline — graph topology and runner.

The graph is defined declaratively below so the processing flow is
visible at a glance and easy to modify.

Topology
--------

::

    discover_vuln
         │
    fetch_advisory
         │
    filter_advisory ──[irrelevant]──► aggregate_verdict ──► END
         │ [relevant]
    prepare_repo
         │
     ┌───┴───┐
     │       │               (parallel branches)
     ▼       ▼
  scan_deps  scan_code
     │       │
     ▼       ▼
  versions   llm_analyze
     │       │
     ▼       ▼
  what_if    deep_analyze
     │       │
     └───┬───┘
         ▼
  check_transitive_paths
         │
    aggregate_verdict
         │
        END
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, Awaitable, Callable, Dict, Mapping

from langgraph.graph import END, StateGraph

from src.llm.base import LLMClient
from src.pipeline import nodes
from src.pipeline.state import PipelineState
from src.pipeline.verdict_assembly import (
    apply_audit_guardrail,
    build_advisory_relevance_summary,
    build_audit_summary_emphasis,
    build_audit_view,
    build_developer_ticket_text,
    build_remediation_view,
    build_researcher_view,
    build_structured_details,
    build_version_analysis_summary,
    dependency_presence_payload,
    map_to_dependency_track,
)

logger = logging.getLogger(__name__)

PIPELINE_STEP_ORDER = [
    "discover_vuln",
    "fetch_advisory",
    "filter_advisory",
    "prepare_repo",
    "scan_dependencies",
    "scan_code",
    "llm_analyze_code",
    "llm_deep_analyze",
    "analyze_versions",
    "what_if_remediation",
    "check_transitive_paths",
    "aggregate_verdict",
]

STEP_METADATA: Dict[str, Dict[str, str]] = {
    "discover_vuln": {
        "title": "Vulnerability Discovery",
        "agent": "web_fetcher",
        "activity": "Discovering the most relevant vulnerability to assess",
    },
    "fetch_advisory": {
        "title": "Advisory Fetch",
        "agent": "web_fetcher",
        "activity": "Fetching advisory details, affected ranges, and symbols",
    },
    "filter_advisory": {
        "title": "Advisory Relevance Filter",
        "agent": "verdict",
        "activity": "Checking whether the advisory applies to this component",
    },
    "prepare_repo": {
        "title": "Repository Preparation",
        "agent": "dependency_scanner",
        "activity": "Preparing the repository checkout for scanning",
    },
    "scan_dependencies": {
        "title": "Dependency Scan",
        "agent": "dependency_scanner",
        "activity": "Scanning manifests and lock files for the vulnerable package",
    },
    "scan_code": {
        "title": "Code Scan",
        "agent": "code_scanner",
        "activity": "Searching source files for vulnerable symbols and usage",
    },
    "llm_analyze_code": {
        "title": "LLM Reachability Analysis",
        "agent": "code_scanner",
        "activity": "Assessing whether vulnerable code paths appear reachable",
    },
    "llm_deep_analyze": {
        "title": "Deep Code Analysis",
        "agent": "code_scanner",
        "activity": "Reviewing surrounding code context for exploitability",
    },
    "analyze_versions": {
        "title": "Version Analysis",
        "agent": "version_analyzer",
        "activity": "Comparing detected versions against the advisory ranges",
    },
    "what_if_remediation": {
        "title": "Remediation Analysis",
        "agent": "version_analyzer",
        "activity": "Evaluating upgrade targets and remediation options",
    },
    "check_transitive_paths": {
        "title": "Transitive Path Analysis",
        "agent": "code_scanner",
        "activity": "Tracing dependency chains and intermediary reachability",
    },
    "aggregate_verdict": {
        "title": "Final Verdict",
        "agent": "verdict",
        "activity": "Combining evidence into the final assessment",
    },
}

MODEL_BOUND_STEPS = {
    "filter_advisory",
    "llm_analyze_code",
    "llm_deep_analyze",
    "check_transitive_paths",
    "aggregate_verdict",
}
MODEL_HEARTBEAT_SECONDS = 15

NODE_INPUT_KEYS: Dict[str, tuple[str, ...]] = {
    "discover_vuln": ("vuln_id", "component_name"),
    "fetch_advisory": ("vuln_id",),
    "filter_advisory": (
        "advisories",
        "component_name",
        "component_cfg",
        "scan_targets",
        "repo_path",
        "summary",
        "ollama",
        "vuln_id",
    ),
    "prepare_repo": ("repo_path", "component_name", "component_cfg"),
    "scan_dependencies": ("repo_path", "component_name", "scan_targets"),
    "scan_code": ("advisories", "component_name", "scan_targets", "repo_path"),
    "llm_analyze_code": (
        "ollama",
        "snippets",
        "advisories",
        "vuln_id",
        "user_guidance",
        "structure",
        "ast_context",
    ),
    "llm_deep_analyze": (
        "llm_analysis",
        "snippets",
        "repo_path",
        "summary",
        "user_guidance",
        "ollama",
        "vuln_id",
    ),
    "analyze_versions": (
        "advisories",
        "component_name",
        "scan_targets",
        "repo_path",
        "dep_info",
        "affected_product_versions",
    ),
    "check_transitive_paths": (
        "dep_info",
        "usage",
        "repo_path",
        "component_name",
        "scan_targets",
        "advisories",
        "ollama",
        "dependency_paths",
        "user_guidance",
        "vuln_id",
    ),
    "aggregate_verdict": (
        "ollama",
        "vuln_id",
        "advisories",
        "dep_info",
        "usage",
        "version_inventory",
        "what_if",
        "llm_analysis",
        "deep_analysis",
        "transitive_analysis",
        "user_guidance",
        "cvss_vector",
    ),
    "what_if_remediation": ("version_inventory", "advisories"),
}


def _snapshot_input_value(value: Any) -> Any:
    """Convert pipeline state values into JSON-friendly debug snapshots."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _snapshot_input_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_snapshot_input_value(v) for v in value]
    if isinstance(value, tuple):
        return [_snapshot_input_value(v) for v in value]
    if isinstance(value, set):
        return [_snapshot_input_value(v) for v in sorted(value, key=repr)]
    return repr(value)


def _snapshot_mapping_inputs(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize noisy advisory fields while preserving explicit ranges."""
    snapshot: Dict[str, Any] = {}
    for key, value in mapping.items():
        if key == "affected_versions" and isinstance(value, list):
            snapshot["affected_versions_count"] = len(value)
            continue
        snapshot[str(key)] = _snapshot_input_value(value)
    return snapshot


def _snapshot_state_inputs(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Capture the full inbound node state except recursive audit fields."""
    snapshot: Dict[str, Any] = {}
    for key, value in state.items():
        if key in {"step_reports", "evidence"}:
            continue
        if key == "advisories" and isinstance(value, dict):
            snapshot[key] = _snapshot_mapping_inputs(value)
            continue
        snapshot[key] = _snapshot_input_value(value)
    return snapshot


def _snapshot_node_inputs(node_name: str, state: PipelineState) -> Dict[str, Any]:
    """Capture only the state fields that a specific node reads."""
    relevant_keys = NODE_INPUT_KEYS.get(node_name)
    if not relevant_keys:
        return _snapshot_state_inputs(state)
    filtered_state = {
        key: state[key]
        for key in relevant_keys
        if key in state and key not in {"step_reports", "evidence"}
    }
    return _snapshot_state_inputs(filtered_state)


def _with_input_snapshot(
    node_name: str,
    fn: Callable[[PipelineState], Awaitable[dict]],
) -> Any:
    async def _emit_progress_event(state: PipelineState, event: Dict[str, Any]) -> None:
        callback = state.get("progress_callback")
        if not callback:
            return
        try:
            maybe_awaitable = callback(event)
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable
        except Exception:
            logger.exception(
                "Progress callback failed for step %s", event.get("step", node_name)
            )

    async def _model_wait_heartbeat(
        state: PipelineState,
        meta: Dict[str, str],
    ) -> None:
        elapsed = 0
        while True:
            activity = (
                f"Waiting for model response during "
                f"{meta.get('title', node_name)}"
            )
            if elapsed:
                activity += f" ({elapsed}s elapsed)"
            await _emit_progress_event(
                state,
                {
                    "phase": "heartbeat",
                    "step": node_name,
                    "title": meta.get("title", node_name),
                    "agent": meta.get("agent", node_name),
                    "activity": activity,
                },
            )
            await asyncio.sleep(MODEL_HEARTBEAT_SECONDS)
            elapsed += MODEL_HEARTBEAT_SECONDS

    async def _stop_heartbeat(task: asyncio.Task[Any] | None) -> None:
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def wrapped(state: PipelineState) -> dict:
        meta = STEP_METADATA.get(node_name, {})
        await _emit_progress_event(
            state,
            {
                "phase": "start",
                "step": node_name,
                "title": meta.get("title", node_name),
                "agent": meta.get("agent", node_name),
                "activity": meta.get("activity", meta.get("title", node_name)),
            },
        )
        heartbeat_task: asyncio.Task[Any] | None = None
        if state.get("progress_callback") and node_name in MODEL_BOUND_STEPS:
            heartbeat_task = asyncio.create_task(_model_wait_heartbeat(state, meta))
        try:
            result = await fn(state)
        except Exception as exc:
            await _stop_heartbeat(heartbeat_task)
            await _emit_progress_event(
                state,
                {
                    "phase": "failed",
                    "step": node_name,
                    "title": meta.get("title", node_name),
                    "agent": meta.get("agent", node_name),
                    "activity": meta.get("activity", meta.get("title", node_name)),
                    "error": str(exc),
                },
            )
            raise

        await _stop_heartbeat(heartbeat_task)
        report = (result.get("step_reports") or {}).get(node_name) or {}
        await _emit_progress_event(
            state,
            {
                "phase": "completed",
                "step": node_name,
                "title": report.get("title") or meta.get("title", node_name),
                "agent": meta.get("agent", node_name),
                "activity": meta.get("activity", meta.get("title", node_name)),
                "status": report.get("status", "completed"),
                "report": report,
            },
        )

        if not state.get("debug", False):
            return result
        report = result.setdefault("step_reports", {}).setdefault(node_name, {})
        findings = report.setdefault("findings", {})
        findings["inputs"] = _snapshot_node_inputs(node_name, state)
        return result

    return wrapped


# ----------------------------------------------------------------------- #
# Graph construction
# ----------------------------------------------------------------------- #


def build_graph() -> Any:
    g = StateGraph(PipelineState)

    # -- register nodes --------------------------------------------------
    node_functions = {
        "discover_vuln": nodes.discover_vuln,
        "fetch_advisory": nodes.fetch_advisory,
        "filter_advisory": nodes.filter_advisory,
        "prepare_repo": nodes.prepare_repo,
        "scan_dependencies": nodes.scan_dependencies,
        "scan_code": nodes.scan_code,
        "llm_analyze_code": nodes.llm_analyze_code,
        "llm_deep_analyze": nodes.llm_deep_analyze,
        "analyze_versions": nodes.analyze_versions,
        "what_if_remediation": nodes.what_if_remediation,
        "check_transitive_paths": nodes.check_transitive_paths,
        "aggregate_verdict": nodes.aggregate_verdict,
    }
    for node_name, fn in node_functions.items():
        g.add_node(node_name, _with_input_snapshot(node_name, fn))

    # -- wire edges ------------------------------------------------------
    g.set_entry_point("discover_vuln")

    g.add_edge("discover_vuln", "fetch_advisory")
    g.add_edge("fetch_advisory", "filter_advisory")

    # Conditional: skip analysis when the advisory is irrelevant
    def _advisory_route(state: PipelineState) -> str:
        if state.get("advisory_relevant", True):
            return "prepare_repo"
        return "aggregate_verdict"

    g.add_conditional_edges(
        "filter_advisory",
        _advisory_route,
        {"prepare_repo": "prepare_repo", "aggregate_verdict": "aggregate_verdict"},
    )

    # Fan-out: two parallel branches after repo is cloned
    g.add_edge("prepare_repo", "scan_dependencies")
    g.add_edge("prepare_repo", "scan_code")

    # Branch A: dependency → version inventory → what-if remediation
    g.add_edge("scan_dependencies", "analyze_versions")
    g.add_edge("analyze_versions", "what_if_remediation")

    # Branch B: code scan → LLM reachability → optional deep analysis
    g.add_edge("scan_code", "llm_analyze_code")
    g.add_edge("llm_analyze_code", "llm_deep_analyze")

    # Fan-in: both branches converge into transitive check
    g.add_edge("what_if_remediation", "check_transitive_paths")
    g.add_edge("llm_deep_analyze", "check_transitive_paths")

    # Transitive check → final verdict
    g.add_edge("check_transitive_paths", "aggregate_verdict")

    g.add_edge("aggregate_verdict", END)

    return g.compile()


# Pre-compiled graph instance (reused across requests).
graph = build_graph()


def _sync_aggregate_verdict_step(
    step_reports: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """Keep the visible final-verdict step aligned with guardrail changes."""
    report = step_reports.get("aggregate_verdict")
    if not isinstance(report, dict):
        return step_reports

    synced_reports = dict(step_reports)
    synced_report = dict(report)
    verdict = result.get("verdict", "Inconclusive")
    confidence = result.get("confidence", "Low")
    synced_report["status"] = verdict

    findings = dict(synced_report.get("findings") or {})
    findings.update(
        {
            "verdict": verdict,
            "confidence": confidence,
            "affected": result.get("affected", False),
            "exposure": result.get("exposure", "none"),
            "reasoning": result.get("reasoning", ""),
        }
    )
    synced_report["findings"] = findings

    evidence = list(synced_report.get("evidence") or [])
    verdict_line = f"Final verdict: {verdict} (confidence={confidence})"
    if evidence and str(evidence[0]).startswith("Final verdict:"):
        evidence[0] = verdict_line
    else:
        evidence.insert(0, verdict_line)
    if "FINAL SANITY CHECK" in str(result.get("reasoning", "")):
        evidence.append("Final sanity check adjusted the emitted verdict.")
    synced_report["evidence"] = evidence
    synced_reports["aggregate_verdict"] = synced_report
    return synced_reports


# ----------------------------------------------------------------------- #
# Public entry point
# ----------------------------------------------------------------------- #


async def run_pipeline(
    vuln_id: str | None,
    component_cfg: Dict[str, Any],
    ollama: LLMClient | None = None,
    dependency_paths: list[list[str]] | None = None,
    affected_product_versions: list[str] | None = None,
    focus_path: str | None = None,
    user_guidance: str | None = None,
    cvss_vector: str | None = None,
    progress_callback: Callable[[Dict[str, Any]], Any] | None = None,
    debug: bool = False,
) -> Dict[str, Any]:
    """Run the full vulnerability analysis pipeline and return the result.

    If *vuln_id* is ``None``, the pipeline discovers the worst known
    vulnerability for the component via OSV and analyses that.

    Returns a dict with:
        assessment  — the overall verdict, confidence, exposure, reasoning
        steps       — ordered list of per-step reports (each with title,
                      status, findings, evidence)
    """
    initial_state: PipelineState = {
        "vuln_id": vuln_id or "",
        "component_cfg": component_cfg,
        "component_name": component_cfg.get("name") or "",
        "scan_targets": [],
        "debug": debug,
        "ollama": ollama,
        "dependency_paths": dependency_paths or [],
        "affected_product_versions": [
            str(version).strip()
            for version in (affected_product_versions or [])
            if str(version).strip()
        ],
        "sbom_attributed": bool(component_cfg.get("sbom_attributed", True)),
        "user_guidance": user_guidance or "",
        "cvss_vector": cvss_vector or "",
        "progress_callback": progress_callback,
        "discovered_vulns": [],
        "advisories": {},
        "advisory_relevant": True,
        "summary": "",
        "repo_path": focus_path or "",
        "dep_info": {},
        "usage": [],
        "snippets": [],
        "structure": "",
        "ast_context": "",
        "llm_analysis": {},
        "deep_analysis": {},
        "transitive_analysis": {},
        "version_inventory": {},
        "what_if": {},
        "result": {},
        "step_reports": {},
        "evidence": [],
    }
    final_state = await graph.ainvoke(initial_state)

    result = final_state["result"]
    step_reports = final_state.get("step_reports", {})
    advisory_relevance = build_advisory_relevance_summary(step_reports)
    version_analysis = build_version_analysis_summary(result)

    verdict_label = result.get("verdict", "Inconclusive")
    affected = result.get("affected", False)
    reasoning = result.get("reasoning", "")
    adj_cvss = result.get("adjusted_cvss") or {}
    audit_view = build_audit_view(
        final_state=final_state,
        verdict_label=verdict_label,
        affected=affected,
        reasoning=reasoning,
        version_analysis=version_analysis,
        adjusted_cvss=adj_cvss,
    )

    result = apply_audit_guardrail(
        result,
        audit_view,
        version_analysis,
        final_state,
    )
    step_reports = _sync_aggregate_verdict_step(step_reports, result)

    # Ordered step keys matching the graph topology
    steps = [
        {"step": key, **step_reports[key]}
        for key in PIPELINE_STEP_ORDER
        if key in step_reports
    ]

    # ---- Map verdict to Dependency-Track fields ----
    verdict_label = result.get("verdict", "Inconclusive")
    affected = result.get("affected", False)
    exposure = result.get("exposure", "none")
    reasoning = result.get("reasoning", "")
    adj_cvss = result.get("adjusted_cvss") or {}

    analysis, justification, response = map_to_dependency_track(
        verdict_label,
        affected,
        exposure,
        adj_cvss,
    )

    cvss_vec = adj_cvss.get("adjusted_vector") or adj_cvss.get("original_vector")
    cvss_score = adj_cvss.get("adjusted_score") if adj_cvss else None
    researcher_view = build_researcher_view(
        final_state=final_state,
        advisory_relevance=advisory_relevance,
        version_analysis=version_analysis,
        verdict_label=verdict_label,
        reasoning=reasoning,
    )
    audit_view = build_audit_view(
        final_state=final_state,
        verdict_label=verdict_label,
        affected=affected,
        reasoning=reasoning,
        version_analysis=version_analysis,
        adjusted_cvss=adj_cvss,
    )
    remediation_view = build_remediation_view(
        final_state=final_state,
        verdict_label=verdict_label,
        adjusted_cvss=adj_cvss,
        version_analysis=version_analysis,
        exposure=exposure,
        audit_view=audit_view,
    )
    assessment_summary = build_audit_summary_emphasis(
        audit_view,
        result.get("summary", ""),
    )

    # Build the structured, audit-grade details text for DT comment field.
    details = build_structured_details(
        vuln_id=final_state.get("vuln_id", vuln_id or ""),
        component_name=component_cfg.get("name", ""),
        repo_url=component_cfg.get("url", ""),
        repo_path=final_state.get("repo_path", ""),
        verdict_label=verdict_label,
        confidence=result.get("confidence", "Low"),
        affected=affected,
        exposure=exposure,
        reasoning=reasoning,
        adj_cvss=adj_cvss,
        cvss_vec=cvss_vec,
        cvss_score=cvss_score,
        advisory_relevance=advisory_relevance,
        advisories=final_state.get("advisories", {}),
        dep_info=final_state.get("dep_info", {}),
        result=result,
        researcher_view=researcher_view,
        remediation_view=remediation_view,
        audit_view=audit_view,
    )
    dep_info = final_state.get("dep_info", {})
    ticket_text = build_developer_ticket_text(
        vuln_id=final_state.get("vuln_id", vuln_id or ""),
        component_name=component_cfg.get("name", ""),
        final_state=final_state,
        verdict_label=verdict_label,
        confidence=result.get("confidence", "Low"),
        affected=affected,
        exposure=exposure,
        reasoning=reasoning,
        advisories=final_state.get("advisories", {}),
        dep_info=dep_info,
        version_analysis=version_analysis,
        researcher_view=researcher_view,
        remediation_view=remediation_view,
        audit_view=audit_view,
        adjusted_cvss=adj_cvss,
    )

    return {
        "assessment": {
            "affected": affected,
            "verdict": verdict_label,
            "confidence": result.get("confidence", "Low"),
            "exposure": exposure,
            "dependency_presence": dependency_presence_payload(dep_info),
            "adjusted_cvss": adj_cvss or None,
            "summary": assessment_summary,
            "reasoning": reasoning,
            "advisory_relevance": advisory_relevance,
            "version_analysis": version_analysis,
            "researcher_view": researcher_view,
            "remediation_view": remediation_view,
            "audit_view": audit_view,
            "ticket_text": ticket_text,
            "analysis": analysis,
            "justification": justification,
            "response": response,
            "details": details,
            "cvss_vector": cvss_vec,
            "cvss_score": cvss_score,
        },
        "steps": steps,
    }
