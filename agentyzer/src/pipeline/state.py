"""Shared pipeline state schema.

All nodes in the vulnerability analysis graph read from and write to this
TypedDict.  Keeping it in a single module makes the data contract explicit
and avoids circular imports between nodes and graph wiring.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List

from typing_extensions import TypedDict

from src.llm.base import LLMClient


def _merge_dicts(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dicts without mutating either side (used by ``step_reports``)."""
    merged = {**left}
    merged.update(right)
    return merged


class PipelineState(TypedDict, total=False):
    # ---- inputs ----
    vuln_id: str
    component_cfg: Dict[str, Any]
    component_name: str
    scan_targets: List[str]  # vulnerable package names from advisory
    debug: bool
    ollama: LLMClient | None
    dependency_paths: List[List[str]]
    affected_product_versions: List[str]
    sbom_attributed: bool  # treat incoming vuln/component tuple as SBOM-attributed
    user_guidance: str  # optional analyst context; empty string when not provided
    cvss_vector: (
        str  # optional caller-provided CVSS vector; empty string when not provided
    )
    progress_callback: Any  # optional in-process hook for async job progress updates

    # ---- intermediate results ----
    discovered_vulns: List[Dict[str, Any]]
    advisories: Dict[str, Any]
    advisory_relevant: bool  # set by filter_advisory; False → skip analysis
    summary: str
    repo_path: str
    dep_info: Dict[str, Any]
    usage: List[str]
    snippets: List[Dict[str, Any]]
    structure: str
    ast_context: str
    llm_analysis: Dict[str, Any]
    deep_analysis: Dict[str, Any]
    transitive_analysis: Dict[str, Any]
    version_inventory: Dict[str, Any]
    what_if: Dict[str, Any]

    # ---- output ----
    result: Dict[str, Any]

    # ---- per-step structured reports (merge-on-write) ----
    step_reports: Annotated[Dict[str, Any], _merge_dicts]

    # ---- flat audit trail (append-only, kept for logging) ----
    evidence: Annotated[list[str], operator.add]
