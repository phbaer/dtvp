"""Mock Agenyzer (Agentic Vulnerability Analyzer) for local DTVP testing.

Implements the same API surface as the real Agenyzer service:
  POST /assess           – submit an async or sync assessment
  GET  /jobs             – list all jobs
  GET  /jobs/{id}        – poll job status
  GET  /jobs/{id}/result – fetch completed result
  DELETE /jobs/{id}      – remove a finished job
  GET  /health           – liveness probe
"""

import hashlib
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
    title="Mock Agenyzer",
    summary="Mock agentic vulnerability analyzer for local testing.",
    version="0.1.0",
)

# ── In-memory job store ──────────────────────────────────────────────────────

jobs: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Request / response models ────────────────────────────────────────────────


class AssessRequest(BaseModel):
    vuln_id: Optional[str] = None
    cvss_vector: Optional[str] = None
    component_name: str
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


def _build_assessment(req: AssessRequest) -> Dict[str, Any]:
    seed = f"{req.vuln_id or ''}|{req.component_name}"
    verdict_template = _VERDICTS[_deterministic_index(seed, len(_VERDICTS))]
    affected = verdict_template["affected"]

    # Build pipeline steps
    steps = []
    for step_tmpl in _MOCK_STEPS:
        # First two steps always pass for affected, last two depend on verdict
        is_pass = (
            affected
            if step_tmpl["step"] in ("code_reachability", "llm_analysis")
            else True
        )
        findings = step_tmpl["pass_findings"] if is_pass else step_tmpl["fail_findings"]
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
    reasoning = (
        f"The dependency {req.component_name} is present, the locked version is inside the advisory range, "
        f"and the vulnerable API is reachable from application code."
        if affected
        else f"The dependency {req.component_name} is present but the vulnerable API surface is not imported "
        f"or invoked anywhere in the application code."
    )

    if req.user_guidance:
        reasoning += f" (User guidance considered: {req.user_guidance})"

    return {
        "assessment": {
            "affected": affected,
            "verdict": verdict_template["verdict"],
            "confidence": verdict_template["confidence"],
            "exposure": verdict_template["exposure"],
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


# ── Background job runner ────────────────────────────────────────────────────


def _run_job_async(job_id: str, req: AssessRequest) -> None:
    """Simulate async processing with a short delay."""

    def worker():
        time.sleep(3)  # simulate processing time
        with _lock:
            job = jobs.get(job_id)
            if not job:
                return
            job["status"] = "running"

        time.sleep(2)  # more processing

        result = _build_assessment(req)
        with _lock:
            job = jobs.get(job_id)
            if not job:
                return
            job["status"] = "completed"
            job["finished_at"] = _now_iso()
            job["result"] = result

    t = threading.Thread(target=worker, daemon=True)
    t.start()


# ── API endpoints ────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok"}


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
    }
    with _lock:
        jobs[job_id] = job

    _run_job_async(job_id, req)

    return {
        "job_id": job_id,
        "status": "pending",
        "poll_url": f"/jobs/{job_id}",
    }


@app.get("/jobs")
async def list_jobs():
    with _lock:
        return {
            "jobs": [
                {
                    "job_id": j["job_id"],
                    "status": j["status"],
                    "created_at": j["created_at"],
                    "finished_at": j["finished_at"],
                    "error": j["error"],
                }
                for j in jobs.values()
            ]
        }


@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    with _lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
        "error": job["error"],
    }


@app.get("/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    with _lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] == "pending" or job["status"] == "running":
        raise HTTPException(status_code=409, detail="The job has not completed yet.")
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
        raise HTTPException(
            status_code=409,
            detail="The job is still running and cannot be deleted yet.",
        )
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
          <head><title>Mock Agenyzer</title></head>
          <body style="font-family: sans-serif; padding: 2rem; background: #111827; color: #f3f4f6;">
            <h1>Mock Agenyzer</h1>
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
    uvicorn.run("mock_agenyzer:app", host="0.0.0.0", port=8095, reload=True)
