# External Integration API Surface

This document defines the external HTTP APIs expected by DTVP for the optional integrations.

## VScorer Service

DTVP expects the VScorer backend, historically called TMRescore in DTVP route and environment names, to expose the following endpoints under its configured base URL (`DTVP_TMRESCORE_URL`):

- `GET /health`
  - Returns service health and optional configuration status.

- `GET /wizard`
  - Serves the VScorer browser wizard. DTVP exposes this URL in the VScorer page context so reviewers can open the full wizard from the DTVP UI.

- `POST /api/v1/sessions`
  - Create a new analysis session.
  - Request body: JSON with `application_name`, `application_version`, and optional `session_id`.

- `PUT /api/v1/sessions/{session_id}/files/threatmodel`
  - Upload a `.tm7` threat model into a session for wizard review or later analysis.

- `PUT /api/v1/sessions/{session_id}/files/sbom`
  - Upload a CycloneDX SBOM into a session for wizard review or later analysis.

- `PUT /api/v1/sessions/{session_id}/files/items`
  - Upload an optional `items.csv` component-to-threat-model mapping into a session.

- `PUT /api/v1/sessions/{session_id}/config/upload`
  - Upload an optional analysis configuration YAML into a session.

- `POST /api/v1/sessions/{session_id}/inventory`
  - One-shot upload + analysis endpoint, or a prepared-session analysis endpoint when files were uploaded earlier.
  - Multipart form data with optional `threatmodel`, optional `sbom`, optional `items_csv`, optional `config`, and analysis flags. The threat model and SBOM are required only when they are not already stored in the session.

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

- `GET /api/v1/sessions/{session_id}/wizard/context`
  - Return a path-free wizard import view for files already uploaded to the session.
  - Includes session/file summaries, readiness, optional validation reports, parsed threat-model elements and boundaries, and threat-model repair editor state.

- `GET /api/v1/sessions/{session_id}/wizard/catalogs`
  - Return path-free wizard metadata for browser/API clients, including rule types, ATT&CK mitigations, archetypes, and app info.

- `GET/PATCH /api/v1/sessions/{session_id}/threatmodel/editor`
  - Return and apply session-scoped threat-model repair decisions.

- `POST /api/v1/sessions/{session_id}/validators/{threatmodel|sbom|cves}` and `GET /api/v1/sessions/{session_id}/validators/report`
  - Run preflight input-quality validation for uploaded session inputs.

### DTVP VScorer proxy endpoints

DTVP keeps its existing `/tmrescore` API paths for compatibility, but the page labels this integration as VScorer:

- Frontend routes:
  - `/project/{project_name}/vscorer` is the preferred DTVP VScorer page.
  - `/project/{project_name}/tmrescore` remains available as a legacy alias.

- `POST /api/projects/{project_name}/tmrescore/import`
  - Builds the selected synthetic SBOM, creates a VScorer session, uploads the threat model/SBOM/optional files through the session upload API, fetches `wizard/context` and `wizard/catalogs`, and returns a prepared DTVP session state.

- `POST /api/tmrescore/sessions/{session_id}/wizard/refresh`
  - Re-fetches session-scoped VScorer `wizard/context` and `wizard/catalogs` for a DTVP-tracked prepared session, so reviewers can refresh DTVP after using the VScorer wizard/editor.

- `POST /api/tmrescore/sessions/{session_id}/analyze`
  - Starts analysis for a previously prepared VScorer session by reusing files already uploaded to that session.

### VScorer Result JSON expectations

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
  - Returns the complete raw analysis payload produced by VScorer.
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
- VScorer/TMRescore has a static spec at `openapi/tmrescore-openapi.json`.
- Code Analysis has a static spec at `openapi/code-analysis-openapi.json`.
- In the mock environment, both service mocks expose a dynamic OpenAPI definition at `/openapi.json`.

## Code Analysis Service

DTVP expects the Code Analysis backend to expose the following endpoints under its configured base URL (`DTVP_CODE_ANALYSIS_URL`):

- `GET /health`
  - Returns service readiness and health.
  - Expected response: `{ "status": "ok" }`.

- `POST /assess`
  - Start an assessment.
  - Request body: JSON with at least `component_name`; optional `vuln_id`, `cvss_vector`, `user_guidance`, `focus_path`, `dependency_paths`, and `debug`.
  - Default behavior is asynchronous: the response is a job handle.
  - Expected async response:
    - `job_id` — string
    - `status` — `pending`
    - `poll_url` — relative URL to poll for job status

- `POST /assess?sync=true`
  - Start a synchronous assessment and return the finished result in the response.
  - Expected sync response: an `AssessResponse` object containing:
    - `assessment` — an `Assessment` object with top-level verdict metadata.
    - `steps` — an ordered array of `StepFindings`.

- `GET /jobs/{job_id}`
  - Fetch the status of a previously created job.
  - Expected response: a `JobStatusResponse` object containing:
    - `job_id`, `status`, `created_at`, `finished_at`, `error`.
    - `progress` — a `JobProgress` object.

- `GET /jobs/{job_id}/result`
  - Fetch the final result of a completed asynchronous job.
  - Expected response: an `AssessResponse` object identical in structure to the sync response.

- `DELETE /jobs/{job_id}`
  - Cancel or remove a job.
  - Expected response: `204 No Content` on success.

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
