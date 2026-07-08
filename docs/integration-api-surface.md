# External Integration API Surface

This document defines the external HTTP APIs expected by DTVP for the optional integrations.

## TMRescore Service

DTVP expects the TMRescore backend to expose the following endpoints under its configured base URL (`DTVP_TMRESCORE_URL`):

- `GET /health`
  - Returns service health and optional configuration status.

- `POST /api/v1/sessions`
  - Create a new analysis session.
  - Request body: JSON with `application_name`, `application_version`, and optional `session_id`.

- `POST /api/v1/sessions/{session_id}/inventory`
  - One-shot upload + analysis endpoint.
  - Multipart form data with `threatmodel`, `sbom`, optional `items_csv`, optional `config`, and query flags.

- `GET /api/v1/sessions/{session_id}/results`
  - Retrieve the final analysis result summary.

- `GET /api/v1/sessions/{session_id}/results/json`
  - Retrieve the raw JSON result document.

- `GET /api/v1/sessions/{session_id}/results/vex`
  - Download the CycloneDX VEX output.

- `GET /api/v1/sessions/{session_id}/outputs/{filename}`
  - Download any generated output artifact.

- `GET /api/v1/sessions/{session_id}/progress`
  - Poll the analysis progress state while an analysis is running.

### TMRescore Result JSON expectations

- `GET /api/v1/sessions/{session_id}/results`
  - Returns an `AnalysisResult` object with at least:
    - `session_id` — string
    - `status` — `completed` or `failed`
    - `total_cves` — integer
    - `rescored_count` — integer
    - `avg_score_reduction` — number
    - `elapsed_seconds` — number
    - `outputs` — object mapping output names to download URLs
    - `error` — string or null when status is `failed`

- `GET /api/v1/sessions/{session_id}/results/json`
  - Returns the complete raw analysis payload produced by TMRescore.
  - Expected to include the session context, proposal details, per-CVE rescoring information, and any internal scoring metadata needed by the DTVP backend.

- `GET /api/v1/sessions/{session_id}/progress`
  - Returns a progress snapshot containing:
    - `percent` — integer progress percentage
    - `completed_steps` — integer
    - `total_steps` — integer
    - `current_step` — string or null
    - `current_title` — string or null
    - `current_agent` — string or null
    - `current_activity` — string or null
    - `last_updated_at` — timestamp or null
    - `active_agents` — array of active step objects
    - `step_statuses` — object mapping step names to status strings

### Notes

- Static OpenAPI specifications for the integrations are available in `openapi/`.
- TMRescore has a static spec at `openapi/tmrescore-openapi.json`.
- Code Analysis has a static spec at `openapi/code-analysis-openapi.json`.
- In the mock environment, both service mocks expose a dynamic OpenAPI definition at `/openapi.json`.

## Code Analysis Service

DTVP expects the Code Analysis backend to expose the following endpoints under its configured base URL (`DTVP_CODE_ANALYSIS_URL`):

The repository includes Agentyzer under `agentyzer/` as the first-party implementation of this API. Docker Compose starts it as service `agentyzer` and points DTVP at `http://agentyzer:8000` by default.

- `GET /health`
  - Returns service readiness and health.
  - Expected response: `{ "status": "ok" }`.
  - May also include model/LLM metadata such as `model`, `llm_backend`, `llm_provider`, or a nested `llm` object.
  - May include `configuration` and `backend` objects. DTVP promotes these into `/api/code-analysis/status` so the dashboard can show analyzer config paths, repository workspace/counts, enabled features, LLM host/provider/model health, repository backend strategy, job-store details, and execution slot availability.

- `POST /assess`
  - Start an assessment.
  - Request body: JSON with at least `component_name`; optional `vuln_id`, `cvss_vector`, `user_guidance`, `model`, `llm_backend`, `llm_provider`, `focus_path`, `dependency_paths`, and `debug`.
  - Default behavior is asynchronous: the response is a job handle.
  - Expected async response:
    - `job_id` — string
    - `status` — `pending`
    - `poll_url` — relative URL to poll for job status
    - Optional model/LLM metadata (`model`, `llm_backend`, `llm_provider`, or `llm`) is preserved by DTVP when present.
    - Optional `configuration` and `backend` objects are preserved for dashboard display.

- `POST /assess?sync=true`
  - Start a synchronous assessment and return the finished result in the response.
  - Expected sync response: an `AssessResponse` object containing:
    - `assessment` — an `Assessment` object with top-level verdict metadata.
    - `steps` — an ordered array of `StepFindings`.

- `GET /jobs`
  - List jobs known to the analyzer process.
  - Expected response: `{ "jobs": [...], "configuration": {...}, "backend": {...} }`, where each item follows the `JobStatusResponse` shape.
  - Shared `configuration` and `backend` metadata should be returned once on the response envelope, not repeated on every job. Individual jobs should carry job-specific request, progress, log, and LLM metadata.
  - `backend.jobs` should include `job_store`, `execution_model`, `known_jobs`, `status_counts`, `max_concurrent_jobs`, `running_jobs`, `queued_jobs`, and `available_slots` when known.

- `GET /jobs/{job_id}`
  - Fetch the status of a previously created job.
  - Expected response: a `JobStatusResponse` object containing:
    - `job_id`, `status`, `created_at`, `finished_at`, `error`.
    - `progress` — a `JobProgress` object.
    - Optional model/LLM metadata (`model`, `llm_backend`, `llm_provider`, `llm`), optional `configuration`/`backend` objects, and optional log output (`logs`, `events`, or `messages`).
  - `status` is usually `pending`, `running`, `completed`, `failed`, or `cancelled`.

- `GET /jobs/{job_id}/result`
  - Fetch the final result of a completed asynchronous job.
  - Expected response: an `AssessResponse` object identical in structure to the sync response.

- `DELETE /jobs/{job_id}`
  - Cancel a pending/running job or remove a finished job.
  - Expected response: `204 No Content` on success.
  - Cancellation is best effort for a running job. If the analyzer cannot stop a running job, return a non-2xx response with `{ "detail": "..." }`; DTVP will keep its queue item running and surface the refusal.

### Result JSON expectations for Code Analysis

- `AssessResponse`
  - Must contain:
    - `assessment`
    - `steps`
  - `assessment` should include at least:
    - `affected` — boolean
    - `verdict` — string
    - `confidence` — string
    - `exposure` — string
    - `summary` — string
    - `reasoning` — string
    - `analysis` — VEX-style analysis state (e.g. `EXPLOITABLE`, `NOT_AFFECTED`)
    - `justification` — analysis justification
    - `details` — human-readable rationale
    - `cvss_vector` — string or null
    - `cvss_score` — number or null
  - Optionally includes:
    - `advisory_relevance`
    - `version_analysis`
    - `remediation_view`
    - `audit_view`
    - `adjusted_cvss`

- `StepFindings`
  - Each step object should include:
    - `step` — stable step identifier
    - `title` — human-readable name
    - `status` — step status such as `pass`, `fail`, or `skip`
    - `findings` — structured step-specific metadata
    - `evidence` — array of strings

- `JobStatusResponse.progress`
  - Must contain:
    - `percent` — integer 0–100
    - `completed_steps` — integer
    - `total_steps` — integer
  - May also include:
    - `current_step`, `current_title`, `current_agent`, `current_activity`
    - `last_completed_step`
    - `last_updated_at`
    - `active_agents` — array of active step objects
    - `step_statuses` — map of step name to status string
    - `logs`, `events`, or `messages` — optional live log entries; entries may be strings or objects containing fields such as `timestamp`, `level`, and `message`

- `JobSubmittedResponse`
  - Must contain:
    - `job_id`
    - `status`
    - `poll_url`

- Error responses
  - Standard error response shape is `{ "detail": "..." }`.

### Notes

- A static OpenAPI specification for Code Analysis is available at `openapi/code-analysis-openapi.json`.
- The expected Code Analysis API surface is also implemented by the mock service in `test_setup/mock_code_analysis.py`.
- In the mock environment, Code Analysis exposes a dynamic OpenAPI definition at `/openapi.json`.
