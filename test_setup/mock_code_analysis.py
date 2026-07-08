"""Mock Code Analysis service for local DTVP testing.

Implements the same API surface as the real Code Analysis service:
  POST /assess           – submit an async or sync assessment
  GET  /jobs             – list all jobs
  GET  /jobs/{id}        – poll job status
  GET  /jobs/{id}/result – fetch completed result
  DELETE /jobs/{id}      – cancel a running job or remove a finished job
  GET  /health           – liveness probe
"""

import hashlib
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

app = FastAPI(
    title="Mock Code Analysis",
    summary="Mock agentic vulnerability analyzer for local testing.",
    version="0.1.0",
)

# ── In-memory job store ──────────────────────────────────────────────────────

jobs: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()
_DEFAULT_MODEL = "gpt-4o"
_DEFAULT_LLM_BACKEND = "mock-openai-compatible"
_DEFAULT_LLM_PROVIDER = "mock"
try:
    _MAX_CONCURRENT_JOBS = max(
        1,
        int(os.getenv("MOCK_CODE_ANALYSIS_MAX_CONCURRENT_JOBS", "1")),
    )
except (TypeError, ValueError):
    _MAX_CONCURRENT_JOBS = 1
_analysis_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_JOBS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Request / response models ────────────────────────────────────────────────


class AssessRequest(BaseModel):
    vuln_id: Optional[str] = None
    cvss_vector: Optional[str] = None
    component_name: str
    model: Optional[str] = None
    llm_backend: Optional[str] = None
    llm_provider: Optional[str] = None
    focus_path: Optional[str] = None
    dependency_paths: Optional[List[List[str]]] = None
    user_guidance: Optional[str] = None
    debug: bool = False


# ── Mock data helpers ────────────────────────────────────────────────────────

# Deterministic seed so the same vuln_id always produces the same result.

_VERDICTS = [
    {
        "affected": True,
        "verdict": "Affected",
        "confidence": "High",
        "exposure": "direct",
    },
    {
        "affected": True,
        "verdict": "Affected",
        "confidence": "Medium",
        "exposure": "transitive",
    },
    {
        "affected": False,
        "verdict": "Not Affected",
        "confidence": "High",
        "exposure": "none",
    },
    {
        "affected": False,
        "verdict": "Not Affected",
        "confidence": "Medium",
        "exposure": "none",
    },
    {
        "affected": True,
        "verdict": "Affected",
        "confidence": "Low",
        "exposure": "direct",
    },
]

_MOCK_STEPS = [
    {
        "step": "scan_dependencies",
        "title": "Scan dependency manifests and lock files",
        "pass_findings": {"found": True, "direct": True, "locked_version": "2.0.0"},
        "pass_evidence": [
            "Found {component} in lock file",
            "Locked version resolved to 2.0.0",
        ],
        "fail_findings": {"found": False, "direct": False},
        "fail_evidence": ["No dependency manifest references {component}"],
    },
    {
        "step": "check_version_range",
        "title": "Check version against advisory affected ranges",
        "pass_findings": {
            "version_affected": True,
            "detected_version": "2.0.0",
            "source": "lock file",
        },
        "pass_evidence": [
            "Version 2.0.0 is within the affected range (introduced=0, fixed=3.0.6)",
            "Source: lock file",
        ],
        "fail_findings": {
            "version_affected": False,
            "detected_version": "4.1.0",
            "source": "lock file",
        },
        "fail_evidence": [
            "Version 4.1.0 is outside the affected range",
        ],
    },
    {
        "step": "code_reachability",
        "title": "Analyze code reachability of vulnerable API",
        "pass_findings": {
            "reachable": True,
            "call_chain": ["app.main", "werkzeug.serving.run_simple"],
        },
        "pass_evidence": [
            "Vulnerable API werkzeug.utils.safe_join is imported in app/routes.py:12",
            "Call chain: app.main → werkzeug.serving.run_simple",
        ],
        "fail_findings": {"reachable": False},
        "fail_evidence": [
            "No imports of the vulnerable API found in application code",
        ],
    },
    {
        "step": "llm_analysis",
        "title": "LLM-assisted exploitability analysis",
        "pass_findings": {"exploitable": True, "model": "gpt-4o"},
        "pass_evidence": [
            "LLM confirmed exploitable code path → E:A",
            "HTTP request handlers invoke vulnerable function directly",
        ],
        "fail_findings": {"exploitable": False, "model": "gpt-4o"},
        "fail_evidence": [
            "LLM found no exploitable code path in application context",
        ],
    },
]


def _deterministic_index(seed: str, n: int) -> int:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return int(h, 16) % n


def _llm_metadata(req: AssessRequest) -> Dict[str, str]:
    return {
        "model": req.model or _DEFAULT_MODEL,
        "backend": req.llm_backend or _DEFAULT_LLM_BACKEND,
        "provider": req.llm_provider or _DEFAULT_LLM_PROVIDER,
    }


def _service_configuration() -> Dict[str, Any]:
    return {
        "service_name": "Mock Code Analysis",
        "service_version": app.version,
        "config_dir": "test_setup",
        "repos_config_path": "test_setup/mock-repositories.yaml",
        "repositories": {
            "workspace_dir": "/tmp/dtvp-mock-code-analysis",
            "component_count": 3,
            "components": ["owned-service", "owned-worker", "owned-ui"],
            "aliases": ["libA", "libB"],
            "default_template_configured": True,
            "hot_reload": False,
        },
        "features": {
            "job_logs": True,
            "model_override": True,
            "running_abort": True,
        },
    }


def _status_counts(job_snapshot: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for job in job_snapshot:
        status = str(job.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _backend_information(
    *,
    model: str = _DEFAULT_MODEL,
    llm_backend: str = _DEFAULT_LLM_BACKEND,
    llm_provider: str = _DEFAULT_LLM_PROVIDER,
    job_snapshot: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    snapshot = job_snapshot or []
    status_counts = _status_counts(snapshot)
    running_jobs = status_counts.get("running", 0)
    queued_jobs = status_counts.get("pending", 0)
    return {
        "llm": {
            "provider": llm_provider,
            "backend": llm_backend,
            "host": "mock://code-analysis/llm",
            "model": model,
            "healthy": True,
            "last_error": None,
            "supports_model_override": True,
        },
        "repositories": {
            "workspace_dir": "/tmp/dtvp-mock-code-analysis",
            "reuse_strategy": "mock-fixtures",
            "update_strategy": "none",
            "parallel_safety": "thread-lock",
        },
        "jobs": {
            "job_store": "in-memory",
            "execution_model": "bounded thread-per-job",
            "known_jobs": len(snapshot),
            "max_concurrent_jobs": _MAX_CONCURRENT_JOBS,
            "running_jobs": running_jobs,
            "queued_jobs": queued_jobs,
            "available_slots": max(0, _MAX_CONCURRENT_JOBS - running_jobs),
            "status_counts": status_counts,
        },
    }


def _append_job_log(job: Dict[str, Any], message: str, level: str = "info") -> None:
    logs = job.setdefault("logs", [])
    logs.append({"timestamp": _now_iso(), "level": level, "message": message})
    del logs[:-200]


def _build_assessment(req: AssessRequest) -> Dict[str, Any]:
    seed = f"{req.vuln_id or ''}|{req.component_name}"
    verdict_template = _VERDICTS[_deterministic_index(seed, len(_VERDICTS))]
    affected = verdict_template["affected"]
    vuln_id = (req.vuln_id or "").upper()
    is_ghsa = vuln_id.startswith("GHSA-")
    advisory_sources = ["GHSA", "NVD"] if is_ghsa else ["NVD", "OSV"]
    cwe_ids = ["CWE-79", "CWE-94"] if affected else ["CWE-79"]
    cwe_descriptions = {
        "CWE-79": "Improper Neutralization of Input During Web Page Generation",
        "CWE-94": "Improper Control of Generation of Code",
    }

    # Build pipeline steps
    steps = []
    for step_tmpl in _MOCK_STEPS:
        # First two steps always pass for affected, last two depend on verdict
        is_pass = (
            affected
            if step_tmpl["step"] in ("code_reachability", "llm_analysis")
            else True
        )
        findings = dict(
            step_tmpl["pass_findings"] if is_pass else step_tmpl["fail_findings"]
        )
        if step_tmpl["step"] == "llm_analysis":
            findings.update(_llm_metadata(req))
        evidence = step_tmpl["pass_evidence"] if is_pass else step_tmpl["fail_evidence"]
        evidence = [e.format(component=req.component_name) for e in evidence]
        steps.append(
            {
                "step": step_tmpl["step"],
                "title": step_tmpl["title"],
                "status": "pass" if is_pass else "fail",
                "findings": findings,
                "evidence": evidence,
            }
        )

    # CVSS adjustment
    adjusted_cvss = None
    if req.cvss_vector:
        original_score = _score_from_vector(req.cvss_vector)
        if affected:
            adjusted_score = original_score
            adjusted_vector = req.cvss_vector
            # Append E:A for exploitable
            if "CVSS:4.0" in req.cvss_vector:
                if "/E:" not in req.cvss_vector:
                    adjusted_vector = req.cvss_vector + "/E:A"
            elif "CVSS:3." in req.cvss_vector:
                if "/E:" not in req.cvss_vector:
                    adjusted_vector = req.cvss_vector + "/E:H"
            reasons = [
                "version 2.0.0 (lock file) confirmed in affected range",
                "LLM confirmed exploitable code path → E:A",
            ]
        else:
            adjusted_score = max(0, original_score - 2.5)
            adjusted_vector = req.cvss_vector
            reasons = [
                "Vulnerable code path is not reachable from application entry points",
            ]

        adjusted_cvss = {
            "original_score": original_score,
            "adjusted_score": round(adjusted_score, 1),
            "original_vector": req.cvss_vector,
            "adjusted_vector": adjusted_vector,
            "version": _cvss_version(req.cvss_vector),
            "reasons": reasons,
            "summary": f"{original_score} → {round(adjusted_score, 1)} ({'confirmed reachable' if affected else 'not reachable'})",
            "version_context": {
                "detected_version": "2.0.0" if affected else "4.1.0",
                "version_source": "lock file",
                "affected": affected,
                "note": "lock file — version 2.0.0 is in the explicit affected versions list"
                if affected
                else "version is outside affected range",
                "affected_ranges_summary": [
                    "SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
                ],
                "comparison_inputs": {
                    "component_name": req.component_name,
                    "locked_version": "2.0.0" if affected else "4.1.0",
                    "affected_ranges_summary": [
                        "ECOSYSTEM range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
                    ],
                    "affected_versions_count": 2,
                },
                "comparison_trace": [
                    "Affected ranges: 1 SEMVER/ECOSYSTEM, 0 GIT, 2 explicit versions",
                    f"version={'2.0.0' if affected else '4.1.0'}: {'MATCH in explicit affected versions list' if affected else 'NO MATCH'}",
                ],
            },
            "version_affected": affected,
        }

    summary = (
        "Direct dependency with reachable vulnerable code path."
        if affected
        else "Dependency is present but vulnerable code path is not reachable."
    )
    if is_ghsa:
        summary += " GHSA advisory details were supplemented with NVD metadata for version-range coverage."

    reasoning = (
        f"The dependency {req.component_name} is present, the locked version is inside the advisory range, "
        f"and the vulnerable API is reachable from application code."
        if affected
        else f"The dependency {req.component_name} is present but the vulnerable API surface is not imported "
        f"or invoked anywhere in the application code."
    )
    reasoning += f" CWE mapping considered: {', '.join(cwe_ids)}."

    if req.user_guidance:
        reasoning += f" (User guidance considered: {req.user_guidance})"

    return {
        "llm": _llm_metadata(req),
        "model": req.model or _DEFAULT_MODEL,
        "llm_backend": req.llm_backend or _DEFAULT_LLM_BACKEND,
        "llm_provider": req.llm_provider or _DEFAULT_LLM_PROVIDER,
        "assessment": {
            "affected": affected,
            "verdict": verdict_template["verdict"],
            "confidence": verdict_template["confidence"],
            "exposure": verdict_template["exposure"],
            "advisory_sources": advisory_sources,
            "cwe_ids": cwe_ids,
            "cwe_descriptions": {
                cwe_id: cwe_descriptions[cwe_id]
                for cwe_id in cwe_ids
                if cwe_id in cwe_descriptions
            },
            "adjusted_cvss": adjusted_cvss,
            "summary": summary,
            "reasoning": reasoning,
        },
        "steps": steps,
    }


def _score_from_vector(vector: str) -> float:
    """Extract a plausible mock score from a CVSS vector string."""
    severity_metrics = vector.upper()
    # Count high-severity indicators
    highs = severity_metrics.count(":H") + severity_metrics.count(":C")
    lows = severity_metrics.count(":L") + severity_metrics.count(":N")
    base = 5.0 + (highs * 0.8) - (lows * 0.3)
    return round(max(0.0, min(10.0, base)), 1)


def _cvss_version(vector: str) -> str:
    if vector.startswith("CVSS:4.0"):
        return "4.0"
    if vector.startswith("CVSS:3.1"):
        return "3.1"
    if vector.startswith("CVSS:3.0"):
        return "3.0"
    return "2.0"


# ── Pipeline steps for progress simulation ───────────────────────────────────

_PIPELINE_STEPS = [
    {
        "step": "discover_vuln",
        "title": "Discover Vulnerability",
        "agent": "vuln_discoverer",
    },
    {
        "step": "fetch_advisory",
        "title": "Fetch Advisory Data",
        "agent": "advisory_fetcher",
    },
    {
        "step": "filter_advisory",
        "title": "Filter Advisory Relevance",
        "agent": "advisory_filter",
    },
    {"step": "prepare_repo", "title": "Prepare Repository", "agent": "repo_manager"},
    {
        "step": "scan_dependencies",
        "title": "Dependency Scan",
        "agent": "dependency_scanner",
    },
    {"step": "scan_code", "title": "Code Scan", "agent": "code_scanner"},
    {
        "step": "check_version_range",
        "title": "Version Range Check",
        "agent": "version_checker",
    },
    {
        "step": "code_reachability",
        "title": "Code Reachability Analysis",
        "agent": "reachability_analyzer",
    },
    {
        "step": "llm_analysis",
        "title": "LLM Exploitability Analysis",
        "agent": "llm_analyzer",
    },
    {"step": "cvss_rescoring", "title": "CVSS Rescoring", "agent": "cvss_rescorer"},
    {
        "step": "compile_verdict",
        "title": "Compile Verdict",
        "agent": "verdict_compiler",
    },
    {"step": "finalize", "title": "Finalize Assessment", "agent": "finalizer"},
]

_STEP_ACTIVITIES = {
    "discover_vuln": "Looking up vulnerability details in OSV and NVD databases",
    "fetch_advisory": "Fetching advisory data from GitHub Security Advisories",
    "filter_advisory": "Checking advisory applicability to target ecosystem",
    "prepare_repo": "Cloning and preparing repository for analysis",
    "scan_dependencies": "Scanning manifests and lock files for the vulnerable package",
    "scan_code": "Searching source files for vulnerable symbols and usage",
    "check_version_range": "Comparing detected version against advisory ranges",
    "code_reachability": "Tracing call paths from entry points to vulnerable API",
    "llm_analysis": "Running LLM exploitability assessment on code context",
    "cvss_rescoring": "Adjusting CVSS score based on environmental evidence",
    "compile_verdict": "Assembling findings into final verdict",
    "finalize": "Writing assessment report",
}


def _build_progress(
    completed: int, total: int, current_idx: int, step_statuses: Dict[str, str]
) -> Dict[str, Any]:
    """Build a JobProgress dict matching the OpenAPI schema."""
    current = _PIPELINE_STEPS[current_idx] if current_idx < total else None
    last_completed = (
        _PIPELINE_STEPS[current_idx - 1]["step"] if current_idx > 0 else None
    )

    # Build active agents — simulate parallel steps for scan_dependencies + scan_code
    active_agents = []
    if current:
        active_agents.append(
            {
                "step": current["step"],
                "title": current["title"],
                "agent": current["agent"],
                "activity": _STEP_ACTIVITIES.get(current["step"], "Processing..."),
                "status": "running",
            }
        )
        # Simulate parallel scan_code when scan_dependencies is running
        if current["step"] == "scan_dependencies" and current_idx + 1 < total:
            next_step = _PIPELINE_STEPS[current_idx + 1]
            if next_step["step"] == "scan_code":
                active_agents.append(
                    {
                        "step": next_step["step"],
                        "title": next_step["title"],
                        "agent": next_step["agent"],
                        "activity": _STEP_ACTIVITIES.get(
                            next_step["step"], "Processing..."
                        ),
                        "status": "running",
                    }
                )

    return {
        "completed_steps": completed,
        "total_steps": total,
        "percent": min(100, int((completed / total) * 100)) if total > 0 else 0,
        "current_step": current["step"] if current else None,
        "current_title": current["title"] if current else None,
        "current_agent": current["agent"] if current else None,
        "current_activity": _STEP_ACTIVITIES.get(current["step"], None)
        if current
        else None,
        "last_completed_step": last_completed,
        "last_updated_at": _now_iso(),
        "active_agents": active_agents,
        "step_statuses": step_statuses,
    }


# ── Background job runner ────────────────────────────────────────────────────


def _run_job_async(job_id: str, req: AssessRequest) -> None:
    """Simulate async processing with step-by-step progress updates."""
    total_steps = len(_PIPELINE_STEPS)

    def worker():
        with _analysis_slots:
            # Initial pending delay
            time.sleep(1)

            with _lock:
                job = jobs.get(job_id)
                if not job:
                    return
                if job["status"] == "cancelled":
                    return
                job["status"] = "running"
                job["progress"] = _build_progress(0, total_steps, 0, {})
                _append_job_log(job, "Analyzer started scan")

            step_statuses: Dict[str, str] = {}

            # Walk through each pipeline step with a short delay
            for i, step_def in enumerate(_PIPELINE_STEPS):
                step_statuses[step_def["step"]] = "running"
                with _lock:
                    job = jobs.get(job_id)
                    if not job:
                        return
                    if job["status"] == "cancelled":
                        return
                    job["progress"] = _build_progress(
                        i, total_steps, i, dict(step_statuses)
                    )
                    activity = _STEP_ACTIVITIES.get(step_def["step"], "Processing")
                    _append_job_log(job, f"{step_def['agent']}: {activity}")

                # Simulate variable processing time per step
                if step_def["step"] in ("llm_analysis", "code_reachability"):
                    time.sleep(1.5)
                elif step_def["step"] in (
                    "scan_dependencies",
                    "scan_code",
                    "prepare_repo",
                ):
                    time.sleep(1.0)
                else:
                    time.sleep(0.5)

                step_statuses[step_def["step"]] = "completed"
                with _lock:
                    job = jobs.get(job_id)
                    if not job:
                        return
                    if job["status"] == "cancelled":
                        return
                    _append_job_log(job, f"Completed {step_def['title']}")

            # Finalize
            result = _build_assessment(req)
            with _lock:
                job = jobs.get(job_id)
                if not job:
                    return
                if job["status"] == "cancelled":
                    return
                job["status"] = "completed"
                job["finished_at"] = _now_iso()
                job["result"] = result
                job["progress"] = _build_progress(
                    total_steps, total_steps, total_steps, step_statuses
                )
                _append_job_log(job, "Assessment complete")

    t = threading.Thread(target=worker, daemon=True)
    t.start()


# ── API endpoints ────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    with _lock:
        job_snapshot = list(jobs.values())
    return {
        "status": "ok",
        "model": _DEFAULT_MODEL,
        "llm_backend": _DEFAULT_LLM_BACKEND,
        "llm_provider": _DEFAULT_LLM_PROVIDER,
        "llm": {
            "model": _DEFAULT_MODEL,
            "backend": _DEFAULT_LLM_BACKEND,
            "provider": _DEFAULT_LLM_PROVIDER,
        },
        "configuration": _service_configuration(),
        "backend": _backend_information(job_snapshot=job_snapshot),
    }


@app.post("/assess")
async def assess(req: AssessRequest, sync: bool = Query(default=False)):
    if sync:
        # Synchronous mode — return result immediately
        result = _build_assessment(req)
        return result

    # Async mode — create background job
    job_id = uuid.uuid4().hex[:12]
    job = {
        "job_id": job_id,
        "status": "pending",
        "created_at": _now_iso(),
        "finished_at": None,
        "error": None,
        "result": None,
        "request": req.model_dump(),
        "model": req.model or _DEFAULT_MODEL,
        "llm_backend": req.llm_backend or _DEFAULT_LLM_BACKEND,
        "llm_provider": req.llm_provider or _DEFAULT_LLM_PROVIDER,
        "llm": _llm_metadata(req),
        "configuration": _service_configuration(),
        "logs": [
            {
                "timestamp": _now_iso(),
                "level": "info",
                "message": "Queued scan",
            }
        ],
        "progress": {
            "completed_steps": 0,
            "total_steps": len(_PIPELINE_STEPS),
            "percent": 0,
        },
    }
    with _lock:
        jobs[job_id] = job
        job_snapshot = list(jobs.values())

    _run_job_async(job_id, req)

    return {
        "job_id": job_id,
        "status": "pending",
        "poll_url": f"/jobs/{job_id}",
        "model": req.model or _DEFAULT_MODEL,
        "llm_backend": req.llm_backend or _DEFAULT_LLM_BACKEND,
        "llm_provider": req.llm_provider or _DEFAULT_LLM_PROVIDER,
        "llm": _llm_metadata(req),
        "configuration": _service_configuration(),
        "backend": _backend_information(
            model=req.model or _DEFAULT_MODEL,
            llm_backend=req.llm_backend or _DEFAULT_LLM_BACKEND,
            llm_provider=req.llm_provider or _DEFAULT_LLM_PROVIDER,
            job_snapshot=job_snapshot,
        ),
    }


@app.get("/jobs")
async def list_jobs():
    with _lock:
        job_snapshot = list(jobs.values())
        return {
            "jobs": [
                {
                    "job_id": j["job_id"],
                    "status": j["status"],
                    "created_at": j["created_at"],
                    "finished_at": j["finished_at"],
                    "error": j["error"],
                    "request": j.get("request"),
                    "model": j.get("model"),
                    "llm_backend": j.get("llm_backend"),
                    "llm_provider": j.get("llm_provider"),
                    "llm": j.get("llm"),
                    "logs": j.get("logs", [])[-50:],
                    "progress": j.get(
                        "progress",
                        {
                            "completed_steps": 0,
                            "total_steps": len(_PIPELINE_STEPS),
                            "percent": 0,
                        },
                    ),
                }
                for j in jobs.values()
            ],
            "configuration": _service_configuration(),
            "backend": _backend_information(job_snapshot=job_snapshot),
        }


@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    with _lock:
        job = jobs.get(job_id)
        job_snapshot = list(jobs.values())
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
        "error": job["error"],
        "request": job.get("request"),
        "model": job.get("model"),
        "llm_backend": job.get("llm_backend"),
        "llm_provider": job.get("llm_provider"),
        "llm": job.get("llm"),
        "configuration": job.get("configuration") or _service_configuration(),
        "backend": _backend_information(
            model=job.get("model") or _DEFAULT_MODEL,
            llm_backend=job.get("llm_backend") or _DEFAULT_LLM_BACKEND,
            llm_provider=job.get("llm_provider") or _DEFAULT_LLM_PROVIDER,
            job_snapshot=job_snapshot,
        ),
        "logs": job.get("logs", [])[-100:],
        "progress": job.get(
            "progress",
            {
                "completed_steps": 0,
                "total_steps": len(_PIPELINE_STEPS),
                "percent": 0,
            },
        ),
    }


@app.get("/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    with _lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] == "pending" or job["status"] == "running":
        raise HTTPException(status_code=409, detail="The job has not completed yet.")
    if job["status"] == "cancelled":
        raise HTTPException(status_code=409, detail="The job was cancelled.")
    if job["status"] == "failed":
        raise HTTPException(status_code=500, detail=job["error"] or "Job failed")
    return job["result"]


@app.delete("/jobs/{job_id}", status_code=204)
async def delete_job(job_id: str):
    with _lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] in ("pending", "running"):
        with _lock:
            job["status"] = "cancelled"
            job["finished_at"] = _now_iso()
            job["error"] = "Cancelled by request."
            _append_job_log(job, "Cancelled by request.", level="warning")
        return Response(status_code=204)
    with _lock:
        jobs.pop(job_id, None)
    return Response(status_code=204)


@app.get("/ui")
async def ui():
    with _lock:
        job_count = len(jobs)
        job_rows = ""
        for j in jobs.values():
            job_rows += (
                f"<tr>"
                f"<td style='padding:4px 8px;font-family:monospace'>{j['job_id']}</td>"
                f"<td style='padding:4px 8px'>{j['status']}</td>"
                f"<td style='padding:4px 8px'>{j['request'].get('vuln_id', '—')}</td>"
                f"<td style='padding:4px 8px'>{j['request'].get('component_name', '—')}</td>"
                f"<td style='padding:4px 8px'>{j['created_at']}</td>"
                f"</tr>"
            )
    return HTMLResponse(
        f"""
        <html>
                    <head><title>Mock Code Analysis</title></head>
          <body style="font-family: sans-serif; padding: 2rem; background: #111827; color: #f3f4f6;">
                        <h1>Mock Code Analysis</h1>
            <p>In-memory mock agentic vulnerability analyzer for local DTVP testing.</p>
            <ul>
              <li>Jobs: {job_count}</li>
              <li>Health: <a href="/health" style="color: #60a5fa;">/health</a></li>
              <li>OpenAPI: <a href="/openapi.json" style="color: #60a5fa;">/openapi.json</a></li>
            </ul>
            <h2>Jobs</h2>
            <table style="border-collapse:collapse; width:100%;">
              <thead>
                <tr style="border-bottom:1px solid #374151;">
                  <th style="padding:4px 8px;text-align:left">ID</th>
                  <th style="padding:4px 8px;text-align:left">Status</th>
                  <th style="padding:4px 8px;text-align:left">Vuln ID</th>
                  <th style="padding:4px 8px;text-align:left">Component</th>
                  <th style="padding:4px 8px;text-align:left">Created</th>
                </tr>
              </thead>
              <tbody>{job_rows or '<tr><td colspan="5" style="padding:4px 8px;color:#6b7280">No jobs yet</td></tr>'}</tbody>
            </table>
          </body>
        </html>
        """
    )


if __name__ == "__main__":
    uvicorn.run("mock_code_analysis:app", host="0.0.0.0", port=8095, reload=True)
