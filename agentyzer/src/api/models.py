"""Pydantic models, enums, and response examples for the assessment API."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

# ===================================================================== #
# Dependency-Track compatible enums                                      #
# ===================================================================== #


class AnalysisState(str, Enum):
    """Dependency-Track analysis states (VEX)."""

    EXPLOITABLE = "EXPLOITABLE"
    IN_TRIAGE = "IN_TRIAGE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_AFFECTED = "NOT_AFFECTED"
    RESOLVED = "RESOLVED"
    NOT_SET = "NOT_SET"


class AnalysisJustification(str, Enum):
    """Dependency-Track justification values for NOT_AFFECTED findings."""

    CODE_NOT_PRESENT = "CODE_NOT_PRESENT"
    CODE_NOT_REACHABLE = "CODE_NOT_REACHABLE"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"
    REQUIRES_DEPENDENCY = "REQUIRES_DEPENDENCY"
    REQUIRES_ENVIRONMENT = "REQUIRES_ENVIRONMENT"
    PROTECTED_BY_COMPILER = "PROTECTED_BY_COMPILER"
    PROTECTED_AT_RUNTIME = "PROTECTED_AT_RUNTIME"
    PROTECTED_AT_PERIMETER = "PROTECTED_AT_PERIMETER"
    PROTECTED_BY_MITIGATING_CONTROL = "PROTECTED_BY_MITIGATING_CONTROL"
    NOT_SET = "NOT_SET"


class AnalysisResponse(str, Enum):
    """Dependency-Track analysis response values."""

    CAN_NOT_FIX = "CAN_NOT_FIX"
    WILL_NOT_FIX = "WILL_NOT_FIX"
    UPDATE = "UPDATE"
    ROLLBACK = "ROLLBACK"
    WORKAROUND_AVAILABLE = "WORKAROUND_AVAILABLE"
    NOT_SET = "NOT_SET"


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


DEFAULT_CVSS_VECTOR = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

JOB_NOT_FOUND_DETAIL = "Job not found"


# ===================================================================== #
# Response examples (used by OpenAPI schema)                             #
# ===================================================================== #


ASSESS_SYNC_REQUEST_EXAMPLE = {
    "summary": "Synchronous assessment against a configured component",
    "description": "Block until the pipeline finishes and return the full assessment in one response.",
    "value": {
        "vuln_id": "CVE-2024-49766",
        "component_name": "benchmark",
        "debug": True,
        # This is an OpenAPI example, not a temporary-file operation.
        "focus_path": "/tmp/agentyzer-repos/vuln-benchmark-08dfa46a5b30",  # nosec B108
        "user_guidance": "Prioritize code paths reachable from HTTP request handlers.",
    },
}

ASSESS_ASYNC_REQUEST_EXAMPLE = {
    "summary": "Asynchronous assessment with dependency path hints",
    "description": "Submit a background job and later poll for status or retrieve the completed result.",
    "value": {
        "vuln_id": "CVE-2024-49766",
        "component_name": "benchmark",
        "debug": False,
        "dependency_paths": [["flask", "werkzeug"]],
    },
}

ASSESS_RESPONSE_EXAMPLE = {
    "assessment": {
        "affected": True,
        "verdict": "Affected",
        "confidence": "High",
        "exposure": "direct",
        "dependency_presence": {
            "found": True,
            "repo_found": True,
            "sbom_attributed": True,
            "presence_basis": "direct",
            "direct": True,
            "transitive": False,
            "declared_in": ["pyproject.toml"],
            "lock_files": ["uv.lock"],
            "locked_version": "2.0.0",
        },
        "advisory_relevance": {
            "relevant": True,
            "status": "ok",
            "source": "rules",
            "reasons": ["OSV ecosystem match: {'PyPI'} (project={'PyPI'})"],
        },
        "version_analysis": {
            "detected_version": "2.0.0",
            "version_source": "lock file",
            "affected": True,
            "note": "lock file — version 2.0.0 is in the explicit affected versions list",
            "affected_ranges_summary": [
                "SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
            ],
            "comparison_inputs": {
                "component_name": "werkzeug",
                "locked_version": "2.0.0",
                "affected_ranges_summary": [
                    "ECOSYSTEM range: introduced=0 fixed=3.0.6 (source=osv_ghsa)",
                    "Explicit affected versions: 2 listed",
                ],
                "affected_versions_count": 2,
            },
            "comparison_trace": [
                "Affected ranges: 1 SEMVER/ECOSYSTEM, 0 GIT, 2 explicit versions",
                "  Explicit affected versions: ['2.0.0', '3.0.2']",
                "  SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)",
                "version=2.0.0: MATCH in explicit affected versions list",
            ],
            "checked_versions": [
                {
                    "ref": "LOCKED",
                    "ref_type": "lock",
                    "version": "2.0.0",
                    "source": None,
                    "affected": True,
                    "notes": "lock file — version 2.0.0 is in the explicit affected versions list",
                },
                {
                    "ref": "WORKTREE",
                    "ref_type": "worktree",
                    "version": "2.0.0",
                    "source": "manifest",
                    "affected": True,
                    "notes": "version is in the explicit affected versions list",
                },
            ],
            "historical_affected": [],
        },
        "researcher_view": {
            "objective": "Find the weakness, determine exposure, and check whether the assessed application is actually affected.",
            "target_outcome": "Prefer an evidence-backed Not Affected / low-info outcome when the current codebase can be excluded.",
            "findings": [
                "Advisory relevance: relevant via rules",
                "Dependency presence: found as a direct dependency",
                "Version check: 2.0.0 (lock file) is inside the advisory range",
                "Direct reachability: reachable from production code",
                "Deep analysis: confirmed=True, exploitable=YES",
            ],
            "conclusion": "The dependency is present, the locked version is inside the advisory range, and the vulnerable API is reachable from application code.",
        },
        "remediation_view": {
            "objective": "Reduce the finding to low/info when supportable, ideally by proving the current codebase is Not Affected.",
            "status": "action_needed",
            "summary": "The current assessment does not yet justify a low/info outcome. Use the recommended changes to eliminate reachability or move the assessed version outside the affected range.",
            "recommendations": [
                "Upgrade to 3.0.6",
                "Upgrade, remove, or isolate the direct dependency and verify the vulnerable path is no longer reachable.",
                "Rerun Agentyzer after remediation to confirm a Not Affected or low/info rescoring outcome.",
            ],
        },
        "audit_view": {
            "objective": "Challenge the assessment and verify that the conclusion really matches the available evidence.",
            "status": "pass",
            "consistency": "strong",
            "downgrade_target": False,
            "downgrade_supported": True,
            "checks": [
                "Supports verdict: the current detected version remains within the affected range.",
                "Supports verdict: direct production reachability was identified.",
            ],
            "conclusion": "The available evidence is internally consistent with the current verdict. The dependency is present, the locked version is inside the advisory range, and the vulnerable API is reachable from application code.",
        },
        "adjusted_cvss": {
            "original_score": 6.3,
            "adjusted_score": 6.3,
            "original_vector": DEFAULT_CVSS_VECTOR,
            "adjusted_vector": f"{DEFAULT_CVSS_VECTOR}/E:A",
            "version": "4.0",
            "reasons": [
                "version 2.0.0 (lock file) confirmed in affected range — lock file — version 2.0.0 is in the explicit affected versions list",
                "LLM confirmed exploitable code path → E:A",
            ],
            "summary": "6.3 → 6.3 (version 2.0.0 confirmed in affected range; LLM confirmed exploitable code path)",
            "version_context": {
                "detected_version": "2.0.0",
                "version_source": "lock file",
                "affected": True,
                "note": "lock file — version 2.0.0 is in the explicit affected versions list",
                "affected_ranges_summary": [
                    "SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
                ],
                "comparison_inputs": {
                    "component_name": "werkzeug",
                    "locked_version": "2.0.0",
                    "affected_ranges_summary": [
                        "ECOSYSTEM range: introduced=0 fixed=3.0.6 (source=osv_ghsa)",
                        "Explicit affected versions: 2 listed",
                    ],
                    "affected_versions_count": 2,
                },
                "comparison_trace": [
                    "Affected ranges: 1 SEMVER/ECOSYSTEM, 0 GIT, 2 explicit versions",
                    "  Explicit affected versions: ['2.0.0', '3.0.2']",
                    "  SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)",
                    "version=2.0.0: MATCH in explicit affected versions list",
                ],
            },
        },
        "summary": "Direct dependency with reachable vulnerable code path.",
        "reasoning": "The dependency is present, the locked version is inside the advisory range, and the vulnerable API is reachable from application code.",
        "analysis": "EXPLOITABLE",
        "justification": "NOT_SET",
        "response": "UPDATE",
        "details": "The dependency is present, the locked version is inside the advisory range, and the vulnerable API is reachable from application code.\nCVSS: CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A (score: 6.3)\nRescoring: LLM confirmed exploitable code path → E:A",
        "cvss_vector": f"{DEFAULT_CVSS_VECTOR}/E:A",
        "cvss_score": 6.3,
    },
    "steps": [
        {
            "step": "scan_dependencies",
            "title": "Scan dependency manifests and lock files",
            "status": "pass",
            "findings": {
                "found": True,
                "direct": True,
                "locked_version": "2.0.0",
            },
            "evidence": [
                "Found werkzeug in fixtures/python-direct-werkzeug/uv.lock",
                "Locked version resolved to 2.0.0",
            ],
        }
    ],
}

JOB_SUBMITTED_EXAMPLE = {
    "job_id": "9f7e2c4b5a6d",
    "status": "pending",
    "poll_url": "/jobs/9f7e2c4b5a6d",
    "configuration": {
        "service_name": "Agentic Vulnerability Analyzer",
        "service_version": "0.1.0",
        "config_dir": "config",
        "repos_config_path": "config/repos.yaml",
        "repositories": {
            "workspace_dir": "repos",
            "component_count": 1,
            "components": ["benchmark"],
            "aliases": [],
            "default_template_configured": False,
            "hot_reload": True,
        },
        "features": {
            "async_assessments": True,
            "sync_assessments": True,
            "bounded_async_execution": True,
            "durable_job_store": True,
            "request_model_override": True,
            "debug_responses": True,
            "job_cancellation": True,
            "job_logs": True,
            "focus_path": True,
            "repos_config_hot_reload": True,
        },
    },
    "backend": {
        "llm": {
            "provider": "ollama",
            "backend": "OllamaClient",
            "host": "http://localhost:11434",
            "model": "mistral",
            "healthy": True,
            "supports_model_override": True,
        },
        "repositories": {
            "workspace_dir": "repos",
            "reuse_strategy": "stable directory per sanitized repository URL",
            "update_strategy": "fetch and reset an existing clone before scanning",
            "parallel_safety": "execution is bounded by AGENTYZER_MAX_CONCURRENT_JOBS; raise it only when the LLM backend and repository workspaces can handle parallel scans",
        },
        "jobs": {
            "job_store": "sqlite",
            "execution_model": "bounded asyncio background tasks in this API process",
            "known_jobs": 1,
            "max_concurrent_jobs": 1,
            "running_jobs": 0,
            "queued_jobs": 1,
            "available_slots": 1,
            "status_counts": {"pending": 1, "running": 0, "completed": 0, "failed": 0, "cancelled": 0},
        },
    },
}

JOB_STATUS_EXAMPLE = {
    "job_id": "9f7e2c4b5a6d",
    "status": "running",
    "created_at": "2026-04-24T15:42:10.123456+00:00",
    "finished_at": None,
    "error": None,
    "progress": {
        "completed_steps": 3,
        "total_steps": 12,
        "percent": 25,
        "current_step": "scan_code",
        "current_title": "Code Scan",
        "current_agent": "code_scanner",
        "current_activity": "Searching source files for vulnerable symbols and usage",
        "last_completed_step": "prepare_repo",
        "last_updated_at": "2026-04-24T15:42:11.102938+00:00",
        "active_agents": [
            {
                "step": "scan_code",
                "title": "Code Scan",
                "agent": "code_scanner",
                "activity": "Searching source files for vulnerable symbols and usage",
                "status": "running",
            },
            {
                "step": "scan_dependencies",
                "title": "Dependency Scan",
                "agent": "dependency_scanner",
                "activity": "Scanning manifests and lock files for the vulnerable package",
                "status": "running",
            },
        ],
        "step_statuses": {
            "discover_vuln": "completed",
            "fetch_advisory": "completed",
            "filter_advisory": "completed",
            "prepare_repo": "completed",
            "scan_code": "running",
            "scan_dependencies": "running",
        },
    },
}

ERROR_RESPONSE_EXAMPLE = {"detail": JOB_NOT_FOUND_DETAIL}


# ===================================================================== #
# Request / response models                                              #
# ===================================================================== #


class AssessRequest(BaseModel):
    """Input for starting a vulnerability assessment."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                ASSESS_SYNC_REQUEST_EXAMPLE["value"],
                ASSESS_ASYNC_REQUEST_EXAMPLE["value"],
            ]
        }
    )

    vuln_id: Optional[str] = Field(
        default=None,
        description="Vulnerability identifier to assess, typically a CVE or GHSA.",
        examples=["CVE-2024-49766"],
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="Optional CVSS vector string to rescore when advisory metadata does not already provide one.",
        examples=[DEFAULT_CVSS_VECTOR],
    )
    component_name: str = Field(
        description="Logical component name from config/repos.yaml, or an ad-hoc name when focus_path is provided.",
        examples=["benchmark"],
    )
    focus_path: Optional[str] = Field(
        default=None,
        description="Optional absolute path to a local checkout to assess instead of cloning or resolving from config/repos.yaml.",
        # This is an OpenAPI example, not a temporary-file operation.
        examples=["/tmp/agentyzer-repos/vuln-benchmark-08dfa46a5b30"],  # nosec B108
    )
    dependency_paths: Optional[List[List[str]]] = Field(
        default=None,
        description="Optional dependency chains to bias transitive reachability analysis. Each nested list represents one path from a top-level dependency to the vulnerable package.",
        examples=[[["flask", "werkzeug"]]],
    )
    affected_product_versions: Optional[List[str]] = Field(
        default=None,
        description="Product/application versions that DTVP already knows are affected. The analyzer tries to map these to repository tags or branches and lists every version in the final version analysis.",
        examples=[["1.0.0", "1.1.0", "2.0.0"]],
    )
    user_guidance: Optional[str] = Field(
        default=None,
        description="Optional analyst context passed verbatim to every LLM call.",
        examples=["Treat code reachable from background workers as in scope."],
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional LLM model override for this assessment.",
        examples=["mistral"],
    )
    llm_backend: Optional[str] = Field(
        default=None,
        description="Optional LLM backend label supplied by the caller for tracking.",
        examples=["ollama"],
    )
    llm_provider: Optional[str] = Field(
        default=None,
        description="Optional LLM provider label supplied by the caller for tracking.",
        examples=["ollama"],
    )
    debug: bool = Field(
        default=False,
        description="Enable verbose debug output, including per-step input snapshots and full version comparison traces.",
        examples=[True],
    )


class FollowUpRequest(BaseModel):
    """Input for rerunning an assessment using compacted parent-job context."""

    question: str = Field(
        description="Reviewer follow-up question to answer in the new assessment.",
        examples=["Is Keycloak itself vulnerable, not only the extension?"],
    )
    vuln_id: Optional[str] = Field(
        default=None,
        description="Optional vulnerability override. Defaults to the parent request.",
    )
    component_name: Optional[str] = Field(
        default=None,
        description="Optional component override. Defaults to the parent request.",
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="Optional CVSS vector override. Defaults to the parent request.",
    )
    focus_path: Optional[str] = Field(
        default=None,
        description="Optional local checkout override. Defaults to the parent request.",
    )
    dependency_paths: Optional[List[List[str]]] = Field(
        default=None,
        description="Optional dependency path override. Defaults to the parent request.",
    )
    user_guidance: Optional[str] = Field(
        default=None,
        description="Additional reviewer guidance appended after the compact parent context.",
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional LLM model override for the follow-up assessment.",
    )
    llm_backend: Optional[str] = Field(
        default=None,
        description="Optional LLM backend label supplied by the caller for tracking.",
    )
    llm_provider: Optional[str] = Field(
        default=None,
        description="Optional LLM provider label supplied by the caller for tracking.",
    )
    debug: bool = Field(
        default=False,
        description="Enable verbose debug output for the follow-up assessment.",
    )


class BenchmarkCompareRequest(BaseModel):
    """Input for comparing human and automated assessment artifacts."""

    benchmark: Dict[str, Any] = Field(
        description=(
            "Structured benchmark artifact prepared by DTVP. It includes the "
            "human assessment snapshot, automated Agentyzer assessment summary, "
            "deterministic state/CVSS deltas, and fallback rating."
        )
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional LLM model override for the probabilistic comparison.",
    )


class BenchmarkCompareResponse(BaseModel):
    """Probabilistic benchmark comparison result."""

    schema_version: str = Field(description="Benchmark comparison schema version.")
    comparison_method: str = Field(
        description="Comparison method, such as agentyzer_probabilistic or deterministic_fallback."
    )
    evaluator: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evaluator metadata including model and whether probabilistic scoring was available.",
    )
    rating: Dict[str, Any] = Field(
        description=(
            "Canonical 1-5 agreement rating for human and automated assessment "
            "artifacts. The optional letter grade is a derived display alias."
        )
    )
    human: Dict[str, Any] = Field(description="Normalized human assessment snapshot.")
    automated: Dict[str, Any] = Field(description="Normalized automated assessment snapshot.")
    deltas: Dict[str, Any] = Field(description="Deterministic state, CVSS, and reasoning anchors.")
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Important agreement or disagreement findings.",
    )
    recommendation: str = Field(description="Recommended reviewer action.")
    reasoning_summary: Optional[str] = Field(
        default=None,
        description="Probabilistic evaluator explanation for the rating.",
    )


class VersionContext(BaseModel):
    """Concrete version evidence used during CVSS rescoring."""

    detected_version: Optional[str] = Field(
        default=None,
        description="Version of the affected component that the analyzer actually evaluated.",
        examples=["2.0.0"],
    )
    version_source: Optional[str] = Field(
        default=None,
        description="Where the detected version came from, such as a lock file or worktree manifest.",
        examples=["lock file"],
    )
    affected: Optional[bool] = Field(
        default=None,
        description="Whether the detected version falls inside the advisory's affected range.",
    )
    note: Optional[str] = Field(
        default=None,
        description="Human-readable explanation of the version match decision.",
        examples=[
            "lock file — version 2.0.0 is in the explicit affected versions list"
        ],
    )
    affected_ranges_summary: List[str] = Field(
        default_factory=list,
        description="Normalized summaries of the advisory ranges used for the comparison.",
        examples=[["SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"]],
    )
    comparison_inputs: Dict[str, Any] = Field(
        default_factory=dict,
        description="Exact inputs supplied to the version comparison, including advisory ranges and explicit version lists.",
    )
    comparison_trace: List[str] = Field(
        default_factory=list,
        description="Full ordered trace of the version comparison logic, including each match or non-match decision.",
    )


class CvssAdjustment(BaseModel):
    """Original and rescored CVSS details for the assessment."""

    original_score: float = Field(
        description="Highest CVSS score reported by the advisory.", examples=[6.3]
    )
    adjusted_score: float = Field(
        description="Environment-adjusted CVSS score after dependency, reachability, and version evidence are applied.",
        examples=[6.3],
    )
    original_vector: Optional[str] = Field(
        default=None,
        description="Original CVSS vector used as the rescoring baseline.",
        examples=[DEFAULT_CVSS_VECTOR],
    )
    adjusted_vector: Optional[str] = Field(
        default=None,
        description="Modified CVSS vector after environmental metrics are applied.",
        examples=[f"{DEFAULT_CVSS_VECTOR}/E:A"],
    )
    version: Optional[str] = Field(
        default=None,
        description="CVSS specification version for the vector and scores.",
        examples=["4.0"],
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Ordered explanation of why the score changed or stayed the same.",
    )
    summary: str = Field(
        description="One-line explanation summarizing the original and adjusted score relationship.",
        examples=[
            "6.3 → 6.3 (version 2.0.0 confirmed in affected range; LLM confirmed exploitable code path)"
        ],
    )
    version_context: VersionContext = Field(
        default_factory=VersionContext,
        description="Detailed context for the component version checked during rescoring.",
    )


class StepFindings(BaseModel):
    """Structured findings from a single pipeline step."""

    step: str = Field(
        description="Stable machine-readable step identifier.",
        examples=["scan_dependencies"],
    )
    title: str = Field(
        description="Human-readable title for the pipeline step.",
        examples=["Scan dependency manifests and lock files"],
    )
    status: str = Field(
        description="Outcome of the step, such as pass, fail, or skip.",
        examples=["pass"],
    )
    findings: dict = Field(
        description="Structured findings emitted by the step. Keys vary by step type.",
        examples=[{"found": True, "direct": True, "locked_version": "2.0.0"}],
    )
    evidence: List[str] = Field(
        description="Short evidence statements supporting the step findings.",
        examples=[["Found werkzeug in fixtures/python-direct-werkzeug/uv.lock"]],
    )


class DependencyPresence(BaseModel):
    """Dependency presence and provenance evidence for the assessed component."""

    found: bool = Field(
        description="True when the vulnerable dependency is considered present in the assessed project.",
    )
    repo_found: bool = Field(
        description="True when manifests or lock files in the local repo scan rediscovered the dependency.",
    )
    sbom_attributed: bool = Field(
        description="True when the dependency presence comes from upstream SBOM/input attribution.",
    )
    presence_basis: str = Field(
        description="Primary presence source used for reporting (for example: direct, transitive, sbom_attributed, not_found).",
        examples=["sbom_attributed"],
    )
    direct: bool = Field(
        description="True when the dependency is declared directly in a top-level manifest.",
    )
    transitive: bool = Field(
        description="True when dependency evidence is transitive rather than directly declared.",
    )
    declared_in: List[str] = Field(
        default_factory=list,
        description="Manifest files where the dependency was declared directly.",
    )
    lock_files: List[str] = Field(
        default_factory=list,
        description="Lock files where the dependency was observed.",
    )
    locked_version: Optional[str] = Field(
        default=None,
        description="Best-effort pinned version discovered in lock files.",
    )


class Assessment(BaseModel):
    """Overall verdict produced by the pipeline."""

    affected: bool = Field(
        description="Whether the analyzer concluded that the target is affected by the vulnerability."
    )
    verdict: str = Field(
        description="Top-level verdict label returned by the analyzer.",
        examples=["Affected"],
    )
    confidence: str = Field(
        description="Confidence level for the verdict.", examples=["High"]
    )
    exposure: str = Field(
        description="Exposure classification such as direct, transitive, or none.",
        examples=["direct"],
    )
    dependency_presence: Optional[DependencyPresence] = Field(
        default=None,
        description="Normalized dependency presence provenance combining local repo rediscovery and SBOM attribution signals.",
    )
    advisory_relevance: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Outcome of the advisory relevance filter step, including whether the advisory was considered relevant, whether the decision came from deterministic rules or the LLM, and the supporting reasons.",
    )
    version_analysis: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured version evidence for the assessed component, including the detected version, advisory range summaries, and the per-ref version table used during verdicting.",
    )
    researcher_view: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Security researcher / analyst view: what weakness was examined, what evidence was found, and why the project does or does not appear affected.",
    )
    remediation_view: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Remediation-focused view aimed at reaching low/info if possible, including upgrade targets or other concrete actions.",
    )
    audit_view: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Critical review of whether the final assessment is well supported by the available evidence.",
    )
    ticket_text: Optional[str] = Field(
        default=None,
        description=(
            "Developer-focused Markdown ticket text generated from the assessment, "
            "excluding analyzer runtime details."
        ),
    )
    adjusted_cvss: Optional[CvssAdjustment] = Field(
        default=None,
        description="Rescored CVSS details when advisory scoring data is available.",
    )
    summary: str = Field(
        description="Short summary intended for human-readable reporting."
    )
    reasoning: str = Field(description="Detailed rationale that supports the verdict.")

    # ---- Dependency-Track compatible fields ----
    analysis: AnalysisState = Field(
        description="Dependency-Track analysis state (VEX). Maps the verdict to one of: "
        "EXPLOITABLE, IN_TRIAGE, FALSE_POSITIVE, NOT_AFFECTED, NOT_SET.",
        examples=[AnalysisState.EXPLOITABLE],
    )
    justification: AnalysisJustification = Field(
        description="Dependency-Track justification for NOT_AFFECTED findings. "
        "One of CODE_NOT_PRESENT, CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION, "
        "REQUIRES_DEPENDENCY, REQUIRES_ENVIRONMENT, PROTECTED_BY_COMPILER, "
        "PROTECTED_AT_RUNTIME, PROTECTED_AT_PERIMETER, PROTECTED_BY_MITIGATING_CONTROL, NOT_SET.",
        examples=[AnalysisJustification.NOT_SET],
    )
    response: AnalysisResponse = Field(
        default=AnalysisResponse.NOT_SET,
        description="Dependency-Track analysis response recommendation.",
        examples=[AnalysisResponse.UPDATE],
    )
    details: str = Field(
        description="Assessment text that rationalizes the analysis decision. "
        "Suitable for the Dependency-Track analysis comment field.",
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="Full CVSS vector string (original or adjusted) for this finding.",
        examples=[DEFAULT_CVSS_VECTOR],
    )
    cvss_score: Optional[float] = Field(
        default=None,
        description="Numeric CVSS score derived from the vector (adjusted if rescoring was applied).",
        examples=[6.3],
    )


class AssessResponse(BaseModel):
    """Top-level response — assessment + per-step detail."""

    model_config = ConfigDict(json_schema_extra={"example": ASSESS_RESPONSE_EXAMPLE})

    assessment: Assessment = Field(description="Overall assessment result.")
    steps: List[StepFindings] = Field(
        description="Ordered pipeline findings produced while computing the assessment."
    )
    llm_conversation: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Actual LLM conversation turns captured during this assessment. Each "
            "turn includes the messages sent to the model and the assistant response "
            "when available."
        ),
    )


class ActiveAgentStatus(BaseModel):
    step: str = Field(description="Stable machine-readable pipeline step identifier.")
    title: str = Field(description="Human-readable step title.")
    agent: str = Field(description="Agent module currently handling the step.")
    activity: str = Field(description="Short description of the work in progress.")
    status: str = Field(description="Current state of the active agent entry.")


class JobProgress(BaseModel):
    completed_steps: int = Field(
        description="Number of pipeline steps that have finished so far."
    )
    total_steps: int = Field(
        description="Estimated number of steps for the current pipeline path."
    )
    percent: int = Field(
        description="Integer progress percentage for the assessment job.",
        ge=0,
        le=100,
    )
    current_step: Optional[str] = Field(
        default=None,
        description="Most recently started or currently active pipeline step.",
    )
    current_title: Optional[str] = Field(
        default=None,
        description="Human-readable title for the current pipeline step.",
    )
    current_agent: Optional[str] = Field(
        default=None,
        description="Agent module currently responsible for the active work.",
    )
    current_activity: Optional[str] = Field(
        default=None,
        description="Short description of what the current agent is doing.",
    )
    last_completed_step: Optional[str] = Field(
        default=None,
        description="Most recent pipeline step to finish.",
    )
    last_updated_at: Optional[str] = Field(
        default=None,
        description="RFC 3339 timestamp for the latest progress update.",
    )
    active_agents: List[ActiveAgentStatus] = Field(
        default_factory=list,
        description="All steps that are currently running, including parallel branches.",
    )
    step_statuses: Dict[str, str] = Field(
        default_factory=dict,
        description="Latest known status for each pipeline step reached so far.",
    )
    logs: List[Dict[str, Any] | str] = Field(
        default_factory=list,
        description="Recent live log entries emitted while the job runs.",
    )


class LlmBackendInfo(BaseModel):
    """Runtime LLM backend details useful to API consumers."""

    provider: Optional[str] = Field(
        default=None,
        description="Configured LLM provider label, such as ollama or openwebui.",
    )
    backend: Optional[str] = Field(
        default=None,
        description="Concrete backend client class used by the API process.",
    )
    host: Optional[str] = Field(
        default=None,
        description="Configured backend base URL when available.",
    )
    model: Optional[str] = Field(
        default=None,
        description="Default model configured for LLM-backed assessment steps.",
    )
    healthy: Optional[bool] = Field(
        default=None,
        description="Last known startup health-check result for the default backend.",
    )
    last_error: Optional[str] = Field(
        default=None,
        description="Last backend health or request error observed by the configured client, if any.",
    )
    supports_model_override: bool = Field(
        default=True,
        description="Whether callers can request a per-assessment model override with `model`.",
    )


class RepositoryConfigurationSummary(BaseModel):
    """Sanitized repository configuration summary."""

    workspace_dir: str = Field(
        description="Base directory where repository workspaces are cached or reused.",
    )
    component_count: int = Field(
        description="Number of explicitly configured components in repos.yaml.",
    )
    components: List[str] = Field(
        default_factory=list,
        description="Configured component names. Secrets and raw repository credentials are never included.",
    )
    aliases: List[str] = Field(
        default_factory=list,
        description="Configured alias names when the defaults template is used.",
    )
    default_template_configured: bool = Field(
        description="True when repos.yaml contains a defaults template for dynamic component resolution.",
    )
    hot_reload: bool = Field(
        description="True when the service watches repos.yaml mtime and reloads component configuration.",
    )


class ServiceConfiguration(BaseModel):
    """Sanitized service configuration returned by operational endpoints."""

    service_name: str = Field(description="Human-readable API service name.")
    service_version: str = Field(description="API service version.")
    config_dir: str = Field(description="Resolved configuration directory.")
    repos_config_path: str = Field(description="Resolved repos.yaml path.")
    repositories: RepositoryConfigurationSummary = Field(
        description="Sanitized repository configuration and workspace-cache summary."
    )
    features: Dict[str, bool] = Field(
        default_factory=dict,
        description="Feature switches and interface capabilities currently exposed by this process.",
    )


class RepositoryBackendInfo(BaseModel):
    """Repository workspace backend behavior."""

    workspace_dir: str = Field(
        description="Directory used for cloned or reused repository workspaces.",
    )
    reuse_strategy: str = Field(
        description="How repository workspace paths are selected and reused.",
    )
    update_strategy: str = Field(
        description="How existing workspaces are refreshed before scanning.",
    )
    parallel_safety: str = Field(
        description="Current concurrency guarantees and caveats for workspace reuse.",
    )


class JobBackendInfo(BaseModel):
    """Async job backend details."""

    job_store: str = Field(description="Persistence backend used for job records.")
    execution_model: str = Field(description="How background assessments are run.")
    known_jobs: int = Field(description="Number of durable jobs loaded by this API process.")
    max_concurrent_jobs: int = Field(
        description="Maximum number of assessment pipelines this process runs at the same time.",
        ge=1,
    )
    running_jobs: int = Field(
        description="Number of assessment pipelines currently occupying execution slots."
    )
    queued_jobs: int = Field(
        description="Number of accepted jobs waiting for an execution slot."
    )
    available_slots: int = Field(
        description="Number of execution slots currently available for pending work.",
        ge=0,
    )
    status_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Current loaded job count by lifecycle status.",
    )


class BackendInformation(BaseModel):
    """Operational backend information for API consumers."""

    llm: LlmBackendInfo = Field(description="Configured LLM backend details.")
    repositories: RepositoryBackendInfo = Field(
        description="Repository workspace backend details."
    )
    jobs: JobBackendInfo = Field(description="Async job backend details.")


class JobStatusResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": JOB_STATUS_EXAMPLE})

    job_id: str = Field(
        description="Opaque job identifier returned by POST /assess in async mode."
    )
    status: JobStatus = Field(
        description="Current lifecycle state of the assessment job."
    )
    created_at: str = Field(
        description="RFC 3339 timestamp for when the job was created."
    )
    finished_at: Optional[str] = Field(
        default=None,
        description="RFC 3339 timestamp for when the job finished, if available.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message for failed jobs.",
    )
    progress: JobProgress = Field(
        description="UI-friendly live progress snapshot for the assessment pipeline."
    )
    request: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Original assessment request metadata with unset fields omitted.",
    )
    model: Optional[str] = Field(
        default=None,
        description="LLM model used for this assessment when known.",
    )
    llm_backend: Optional[str] = Field(
        default=None,
        description="LLM backend identifier or URL when known.",
    )
    llm_provider: Optional[str] = Field(
        default=None,
        description="LLM provider label when known.",
    )
    llm: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured LLM backend metadata when known.",
    )
    logs: List[Dict[str, Any] | str] = Field(
        default_factory=list,
        description="Recent live log entries emitted while the job runs.",
    )
    configuration: Optional[ServiceConfiguration] = Field(
        default=None,
        description="Sanitized service configuration visible to API consumers.",
    )
    backend: Optional[BackendInformation] = Field(
        default=None,
        description="Operational backend details visible to API consumers.",
    )


class JobSubmittedResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": JOB_SUBMITTED_EXAMPLE})

    job_id: str = Field(
        description="Opaque identifier for the background assessment job."
    )
    status: JobStatus = Field(description="Initial status for the newly created job.")
    poll_url: str = Field(
        description="Relative URL that can be polled for job status updates."
    )
    model: Optional[str] = Field(
        default=None,
        description="LLM model accepted for this job when known.",
    )
    llm_backend: Optional[str] = Field(
        default=None,
        description="LLM backend accepted for this job when known.",
    )
    llm_provider: Optional[str] = Field(
        default=None,
        description="LLM provider accepted for this job when known.",
    )
    llm: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured LLM backend metadata accepted for this job.",
    )
    configuration: Optional[ServiceConfiguration] = Field(
        default=None,
        description="Sanitized service configuration accepted for this job.",
    )
    backend: Optional[BackendInformation] = Field(
        default=None,
        description="Operational backend details accepted for this job.",
    )


class JobListResponse(BaseModel):
    jobs: List[JobStatusResponse] = Field(description="Currently known durable jobs.")
    configuration: Optional[ServiceConfiguration] = Field(
        default=None,
        description="Sanitized service configuration shared by all listed jobs.",
    )
    backend: Optional[BackendInformation] = Field(
        default=None,
        description="Operational backend details shared by all listed jobs.",
    )


class CompactContextResponse(BaseModel):
    job_id: str = Field(description="Parent job identifier that was compacted.")
    compacted_at: str = Field(description="RFC 3339 timestamp for compaction.")
    context: Dict[str, Any] = Field(
        description="Structured compact context suitable for follow-up runs."
    )
    prompt_context: str = Field(
        description="Plain-text rendering of the compact context for LLM guidance."
    )


class HealthResponse(BaseModel):
    """Health check response."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "ok",
                "model": "mistral",
                "llm_backend": "http://localhost:11434",
                "llm_provider": "ollama",
                "configuration": JOB_SUBMITTED_EXAMPLE["configuration"],
                "backend": JOB_SUBMITTED_EXAMPLE["backend"],
            }
        }
    )

    status: str = Field(description="Service health indicator.", examples=["ok"])
    model: Optional[str] = Field(
        default=None,
        description="Configured LLM model when known.",
    )
    llm_backend: Optional[str] = Field(
        default=None,
        description="Configured LLM backend identifier or URL when known.",
    )
    llm_provider: Optional[str] = Field(
        default=None,
        description="Configured LLM provider label when known.",
    )
    llm: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured LLM backend metadata when known.",
    )
    configuration: Optional[ServiceConfiguration] = Field(
        default=None,
        description="Sanitized service configuration visible to API consumers.",
    )
    backend: Optional[BackendInformation] = Field(
        default=None,
        description="Operational backend details visible to API consumers.",
    )


class ErrorResponse(BaseModel):
    """Standard error payload returned by FastAPI."""

    model_config = ConfigDict(json_schema_extra={"example": ERROR_RESPONSE_EXAMPLE})

    detail: str = Field(description="Human-readable error description.")
