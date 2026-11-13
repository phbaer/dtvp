"""Content-free analyzer failure metadata, retained independently of remote jobs."""
import json
import logging
import math
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .code_analysis_result_services import (
    get_code_analysis_results_path, get_code_analysis_results_max_records,
    get_code_analysis_results_retention_days,
)

CODES = frozenset({"llm_timeout", "llm_unavailable", "llm_internal_error", "llm_invalid_response",
    "llm_authentication_failed", "llm_authorization_failed", "llm_model_unavailable",
    "llm_rate_limited", "llm_context_exceeded", "llm_request_rejected",
    "llm_incomplete_response", "pipeline_internal_error", "job_storage_unavailable"})
STAGES = frozenset({"discover_vuln", "fetch_advisory", "filter_advisory", "prepare_repo",
    "inspect_archives", "scan_dependencies", "analyze_versions", "scan_code",
    "llm_analyze_code", "what_if_remediation", "llm_deep_analyze", "check_transitive_paths",
    "aggregate_verdict", "final_verdict", "reachability_analysis", "deep_analysis",
    "transitive_analysis", "advisory_relevance", "model_output"})
EXCEPTIONS = frozenset({"Exception", "TypeError", "ValueError", "AttributeError", "KeyError",
    "IndexError", "RuntimeError", "TimeoutError", "ConnectError", "ReadError", "WriteError",
    "RemoteProtocolError", "LocalProtocolError", "PoolTimeout", "ConnectTimeout",
    "ReadTimeout", "WriteTimeout", "HTTPStatusError", "NetworkError", "RequestError"})


def safe_error_details(value):
    if not isinstance(value, dict):
        return None
    code = value.get("code")
    out = {"code": code if isinstance(code, str) and code in CODES else "unknown_error"}
    if isinstance(value.get("retryable"), bool):
        out["retryable"] = value["retryable"]
    diagnostics = value.get("diagnostics")
    clean = {}
    if isinstance(diagnostics, dict):
        for key, choices in (("stage", STAGES), ("exception_type", EXCEPTIONS),
                             ("failure_category", {"http", "transport", "timeout", "internal"})):
            if isinstance(diagnostics.get(key), str) and diagnostics[key] in choices:
                clean[key] = diagnostics[key]
        for key in ("http_status", "timeout_seconds", "response_chars", "opening_blocks", "closing_blocks"):
            number = diagnostics.get(key)
            if isinstance(number, (int, float)) and not isinstance(number, bool) and math.isfinite(number) and 0 <= number <= 100_000_000:
                clean[key] = number
    if clean:
        out["diagnostics"] = clean
    return out


def _timestamp(value):
    try:
        return datetime.fromisoformat(value).isoformat()
    except (TypeError, ValueError):
        return None


def safe_snapshot(job_id, value, *, source="agentyzer"):
    """Project both remote diagnostics and saved status onto a small safe contract."""
    value = value if isinstance(value, dict) else {}
    job = value.get("job") if isinstance(value.get("job"), dict) else value
    status = job.get("status")
    progress = job.get("progress") if isinstance(job.get("progress"), dict) else {}
    stage = progress.get("current_step") or job.get("current_step")
    runtime = value.get("current_runtime")
    configured = runtime.get("llm") if isinstance(runtime, dict) else None
    backend = {}
    if isinstance(configured, dict):
        provider = configured.get("provider")
        if isinstance(provider, str) and provider in {"ollama", "openwebui", "litellm", "lite-llm", "lite_llm"}:
            backend["provider"] = provider
        for key in ("model", "backend"):
            label = configured.get(key)
            if isinstance(label, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", label):
                backend[key] = label
        if isinstance(configured.get("startup_healthy"), bool):
            backend["startup_healthy"] = configured["startup_healthy"]
    return {
        "current_backend": backend,
        "schema_version": "dtvp.code-analysis-diagnostics/v1",
        "source": source,
        "job_id": job_id,
        "status": status if isinstance(status, str) and status in {"pending", "running", "completed", "failed", "cancelled"} else "unknown",
        "created_at": _timestamp(job.get("created_at")),
        "finished_at": _timestamp(job.get("finished_at")),
        "current_step": stage if isinstance(stage, str) and stage in STAGES else None,
        "error_details": safe_error_details(value.get("error_details") or job.get("error_details") or value.get("error")),
        "privacy": "Requests, prompts, model output, credentials, free-text errors and logs are excluded.",
    }


def _path():
    return Path(get_code_analysis_results_path() + ".diagnostics.sqlite")


def save_failure_snapshot(job_id, status):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", str(job_id or "")):
        return
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).isoformat()
    payload = safe_snapshot(job_id, status, source="dtvp_saved")
    payload["captured_at"] = now
    with closing(sqlite3.connect(path, timeout=5)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS diagnostics (job_id TEXT PRIMARY KEY, captured TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO diagnostics VALUES (?,?,?)", (job_id, now, json.dumps(payload)))
        days = get_code_analysis_results_retention_days()
        if days:
            db.execute("DELETE FROM diagnostics WHERE captured < ?", ((datetime.now(UTC)-timedelta(days=days)).isoformat(),))
        db.execute("DELETE FROM diagnostics WHERE job_id IN (SELECT job_id FROM diagnostics ORDER BY captured DESC, job_id LIMIT -1 OFFSET ?)", (get_code_analysis_results_max_records(),))


def _load_failure_snapshot(job_id):
    path = _path()
    if not path.exists():
        return None
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        row = db.execute("SELECT payload, captured FROM diagnostics WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        return None
    days = get_code_analysis_results_retention_days()
    if days and datetime.fromisoformat(row[1]) < datetime.now(UTC)-timedelta(days=days):
        return None
    return json.loads(row[0])


def load_failure_snapshot(job_id):
    try:
        return _load_failure_snapshot(job_id)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        logging.getLogger(__name__).warning("Saved analyzer diagnostics unavailable")
        return None
