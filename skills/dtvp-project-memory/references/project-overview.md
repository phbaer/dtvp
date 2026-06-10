# DTVP Project Overview

Last reviewed: 2026-06-10

## Purpose

DTVP, the Dependency-Track Vulnerability Processor, is a FastAPI and Vue application for reviewing Dependency-Track findings across many versions of a project. It groups matching vulnerabilities across versions and components, shows lifecycle and assessment state in one place, and lets analysts and reviewers apply synchronized assessments instead of repeating the same work for every release.

The app can run against a real Dependency-Track instance or the bundled mock services in `test_setup/`. Optional integrations add threat-model based rescoring through VScorer, historically named tmrescore in internal route/module names, and code-analysis backed vulnerability assessment.

## Core Functionality

- Authentication: OIDC login is implemented in `dtvp/auth.py`. The mock stack simulates SSO. `DTVP_DEV_DISABLE_AUTH=true` returns `devuser`, which is a reviewer in `data/user_roles.json`.
- Dashboard: `frontend/src/pages/Dashboard.vue` loads projects via `/api/projects`, groups them by classifier and project name, shows versions together, and carries optional project/CVE filters into the project view.
- Project review: `frontend/src/pages/ProjectView.vue` starts `/api/tasks/group-vulns`, polls task progress, and renders grouped vulnerabilities with filters for lifecycle, analysis state, team tags, IDs, components, assignees, dependency relationship, versions, CVSS mismatch, and VScorer proposal availability. It builds indexed list metadata through `frontend/src/lib/vulnListIndex.ts` so filters, smart search, counts, and sorts reuse precomputed fields instead of repeatedly walking affected versions/components. The analysis view uses a fixed-height workspace below the app header: a command bar stays above independently scrolling filter, list, and detail columns, so rows and details do not pass underneath the filter controls. The command bar provides smart search, result count, token insertion, removable search/filter chips, and reset state; search matches IDs, aliases, titles, descriptions, components, teams, assignees, and versions, supports typed tokens such as `team:`, `component:`, `assignee:`, `version:`, `state:`, `dep:`, `has:vscorer`, the legacy `has:tmrescore`, and `cvss:mismatch`, and offers prefix-aware completions from the loaded findings. Compact vulnerability rows are progressively mounted through `useVisibleGroupWindow` and select one responsive `VulnDetailInspector.vue` detail surface, so only one heavy full-detail `VulnGroupCard.vue` is mounted at a time; the desktop inspector only activates once there is enough width for a fixed compact selector column plus a minimum 48rem detail column, and the left filter/results rail stays hidden while details are open until very wide desktop widths. Narrower layouts expose details as an overlay and filters through a drawer from the command bar.
- Vulnerability grouping: `dtvp/logic.py::group_vulnerabilities` canonicalizes vulnerability IDs through aliases, preferring CVE IDs, then GHSA, then other IDs. It merges findings across project versions, keeps aliases, chooses the highest original or rescored CVSS values, attaches team tags, dependency paths, direct/transitive classification, assignees, and per-version component instances.
- Assessments: `/api/assessment` writes Dependency-Track analysis state, details, justification, suppression, and comments. `dtvp/assessment_services.py` handles conflict detection, payload construction, local cache updates, remote writes, and result finalization. Assessment details are stored as structured text blocks by team in `dtvp/logic.py::process_assessment_details`.
- Roles: `ANALYST` submissions get `[Status: Pending Review]`; `REVIEWER` can review, approve, use Settings, and access VScorer. Role mapping lives in `data/user_roles.json`.
- Statistics: `frontend/src/pages/Statistics.vue` calls `/api/statistics`, which reuses grouped vulnerability logic and returns severity, state, version, and major-version aggregates.
- Settings: `frontend/src/pages/Settings.vue` and `dtvp/settings_routes.py` manage team mapping, user roles, and CVSS rescore rules. Backing files are `data/team_mapping.json`, `data/user_roles.json`, and `data/rescore_rules.json`.
- App metadata: `dtvp/app_info_routes.py` exposes version, package metadata, cache status, changelog, OpenAPI JSON, and SBOM downloads. Container builds place CycloneDX SBOMs under `/sbom`.
- SPA hosting: `dtvp/frontend_routes.py` serves `frontend/dist` and injects runtime config values for the Vue app when the backend serves the built frontend.

## Optional Integrations

- Dependency-Track is the primary upstream. `dtvp/dt_client.py` calls projects, findings, project vulnerabilities, BOMs, user profile, and analysis update endpoints.
- VScorer is enabled by `DTVP_VSCORER_URL` with `DTVP_TMRESCORE_URL` retained as a legacy fallback. `frontend/src/pages/VScorer.vue`, `frontend/src/lib/api.ts`, `dtvp/tmrescore_routes.py`, `dtvp/tmrescore_inventory_services.py`, `dtvp/tmrescore_execution_services.py`, and `dtvp/tmrescore_integration.py` build either a latest-only or merged multi-version synthetic CycloneDX SBOM, upload `.tm7` plus optional `items.csv` and config files, poll progress, cache results, and expose per-project proposals to the Project View. Reviewers reach the page at `/project/{name}/vscorer`; `/project/{name}/tmrescore` remains a legacy alias. DTVP exposes preferred `/api/vscorer/...` proxy endpoints with `/api/tmrescore/...` compatibility aliases. Reviewers can either run a one-shot analysis or prepare a VScorer wizard session from DTVP; the prepared path uploads session files, fetches session-scoped `wizard/context` and `wizard/catalogs`, displays the wizard summary in DTVP, can refresh wizard context, run input validation, load and patch threat-model editor issues, download the prepared TM7, link to the backing `/wizard` UI, and then run analysis by reusing the uploaded VScorer session files. The VScorer session-scoped wizard endpoints expose uploaded-input context, wizard catalogs, validators, and threat-model editor state without requiring clients to use server filesystem paths.
- Code Analysis is enabled by `DTVP_CODE_ANALYSIS_URL`. `dtvp/code_analysis_routes.py`, `dtvp/code_analysis_integration.py`, `dtvp/analysis_queue_runtime.py`, and `dtvp/analysis_queue_services.py` support direct assessments and a global one-at-a-time analysis queue. The frontend API helpers and queue indicator are in `frontend/src/lib/api.ts`, `frontend/src/lib/analysisQueueStore.ts`, and `frontend/src/components/AnalysisQueueIndicator.vue`.
- External API expectations are documented in `docs/integration-api-surface.md`. Static OpenAPI specs live in `openapi/`.

## Backend Map

- `dtvp/main.py` builds the FastAPI app, CORS, context path, in-memory task stores, dependency wiring, routers, startup/shutdown, and SPA fallback.
- `dtvp/app_wiring.py` centralizes dependency construction so routes and services can be tested without importing the full app.
- `dtvp/general_api_routes.py` owns core API routes: `/projects`, `/tasks/group-vulns`, `/tasks/{task_id}`, `/statistics`, `/assessments/details`, `/assessment`, and dependency-chain lookup.
- `dtvp/grouped_vuln_services.py` fetches per-version findings, detailed vulnerabilities, and BOMs concurrently before grouping.
- `dtvp/logic.py` contains domain logic: team mapping and roles loading, BOM dependency analysis, grouping, statistics, CVSS vector sanitization, assessment-detail parsing, and aggregated-state calculation.
- `dtvp/dt_cache.py` persists Dependency-Track projects, findings, project vulnerabilities, BOMs, analyses, active project IDs, and pending updates under `data/dt_cache` by default. It also performs background refresh and pending-update sync.
- `dtvp/vulnerability_support_services.py` merges detailed vulnerability data into findings and caches VScorer proposal results.
- `dtvp/runtime_value_services.py`, `dtvp/app_bootstrap.py`, `dtvp/file_io_services.py`, and `dtvp/app_info_services.py` hold small environment, path, file, and metadata helpers.
- `test_setup/` contains mock Dependency-Track, VScorer, and code-analysis services for local and test workflows. `test_setup/mock_tmrescore.py` keeps its historical filename/process compatibility but presents the in-memory service as Mock VScorer and includes the VScorer session, inventory, result, validator, threat-model editor, and session-scoped wizard context/catalog endpoints used by DTVP integration tests.

## Frontend Map

- Vue entry points are `frontend/src/main.ts`, `frontend/src/App.vue`, and `frontend/src/router.ts`; `App.vue` owns the fixed-height app shell so document-level scrolling stays disabled, project review pages use their own internal scroll regions, and regular non-project pages scroll inside the main content region.
- `frontend/src/lib/api.ts` is the central backend client and defines most frontend-facing integration types.
- `frontend/src/types.ts` defines project, grouped vulnerability, assessment, statistics, cache, VScorer, wizard context/catalog/editor, and proposal shapes, with legacy TMRescore type aliases retained for compatibility.
- `frontend/src/lib/assessmentFormState.ts`, `assessmentSubmission.ts`, `assessment-helpers.ts`, `cvssRescore.ts`, `cvss.ts`, `mergedAssessmentData.ts`, `group-classifier.ts`, `vulnListIndex.ts`, `useVisibleGroupWindow.ts`, and modal/selection composables support the Project View workflow.
- Shared project header state lives in `frontend/src/lib/projectHeaderStore.ts`.
- Major UI surfaces are `Dashboard.vue`, `ProjectView.vue`, `VScorer.vue`, `Statistics.vue`, `Settings.vue`, and `Login.vue`.
- Reusable vulnerability and modal components live under `frontend/src/components/`, especially `VulnRowCompact.vue`, `VulnGroupCard.vue`, `VulnDetailInspector.vue`, `VulnDetailModal.vue`, `VulnModalTaskbar.vue`, `AssessmentReviewModal.vue`, `CalculatorModal.vue`, CVSS calculators, dependency chain components, filter/sidebar components, and bulk action modals. `CustomSelect.vue` teleports dropdown menus above modal overlays so selects inside dialogs remain clickable.

## Data And Domain Rules

- Team mapping accepts either `"component": "Team"` or `"component": ["Primary", "Alias"]`; aliases normalize to the primary team label in much of the UI.
- The wildcard team mapping key `"*"` provides a fallback team.
- Assessment details are text with metadata headers like `[Team: ...]`, `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`, `[Rescored: ...]`, `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Aggregated assessment state gives a non-`NOT_SET` General block precedence, otherwise it picks the worst team state using `STATE_PRIORITY` in `dtvp/logic.py`.
- Rescored CVSS vectors are sanitized against original base metrics so threat or environmental changes do not silently mutate base metrics.
- Dependency relationship and paths are derived from CycloneDX BOM dependency graphs by `BOMAnalysisCache`.
- Analysis states commonly include `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `FALSE_POSITIVE`, and `NOT_AFFECTED`.

## Local Development

- Python package metadata currently requires Python `>=3.14` in `pyproject.toml`.
- Install backend dependencies: `uv sync --dev`.
- Install frontend dependencies: run `npm ci` in `frontend/`.
- Full mock stack: `pm2 start ecosystem.config.js --update-env`.
- Mock services only: `pm2 start ecosystem.config.js --only mock-dt,mock-tmrescore`.
- Backend manually: set the `DTVP_DT_*`, `DTVP_OIDC_*`, `DTVP_FRONTEND_URL`, and optional integration env vars, then run `uv run uvicorn dtvp.main:app --reload --host 127.0.0.1 --port 8000`.
- Frontend dev server: run `npm run dev` in `frontend/`.
- Main local URLs in the pm2 mock stack: frontend `http://localhost:5173`, backend `http://localhost:8000`, mock Dependency-Track `http://localhost:8081`, mock VScorer `http://localhost:8090/ui`.

## Validation

- Backend tests: `uv run pytest`.
- Targeted backend tests: `uv run pytest tests/test_logic.py` or another test file.
- Frontend unit tests: run `npm run test:unit -- --run` in `frontend/`.
- Frontend build/type check: run `npm run build` in `frontend/`.
- Playwright UI tests: run `npm run test:ui` in `frontend/`, normally with the needed backend/mock services already running.
- README screenshot capture: `npm run test:ui:docs` in `frontend/`.

## Important Environment Variables

- Dependency-Track: `DTVP_DT_API_URL`, `DTVP_DT_API_KEY`, `DTVP_DT_API_KEY_FILE`, plus deployment aliases `DEPENDENCY_TRACK_URL` and `DEPENDENCY_TRACK_API_KEY`.
- Auth/runtime/frontend: `DTVP_OIDC_CLIENT_ID`, `DTVP_OIDC_CLIENT_SECRET`, `DTVP_OIDC_AUTHORITY`, `DTVP_OIDC_REDIRECT_URI`, `DTVP_SESSION_SECRET_KEY`, `DTVP_FRONTEND_URL`, `DTVP_CONTEXT_PATH`, `DTVP_DEV_DISABLE_AUTH`, `DTVP_CORS_ORIGINS`, `DTVP_API_URL`, `DTVP_DEFAULT_PROJECT_FILTER`, `DTVP_BUILD_COMMIT`.
- Cache and concurrency: `DTVP_DT_CACHE_PATH`, `DTVP_DT_CACHE_REFRESH_SECONDS`, `DTVP_VERSION_FETCH_CONCURRENCY`, `DTVP_VSCORER_CACHE_PATH`, `DTVP_VSCORER_TASK_TTL_SECONDS`, legacy `DTVP_TMRESCORE_CACHE_PATH`, legacy `DTVP_TMRESCORE_TASK_TTL_SECONDS`, `DTVP_ANALYSIS_QUEUE_TTL_SECONDS`.
- VScorer: `DTVP_VSCORER_URL`, `DTVP_VSCORER_TIMEOUT_SECONDS`, `DTVP_VSCORER_OLLAMA_MODEL`; legacy aliases `DTVP_TMRESCORE_URL`, `DTVP_TMRESCORE_TIMEOUT_SECONDS`, and `DTVP_TMRESCORE_OLLAMA_MODEL` still work.
- Code Analysis: `DTVP_CODE_ANALYSIS_URL`, `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS`.

## Update Policy For Agents

When you make meaningful changes, update this overview before finishing. Keep changes in the section where future agents will look first:

- Add or revise user workflows in `Core Functionality`.
- Add or revise route/service/module ownership in `Backend Map`.
- Add or revise pages, stores, API helpers, or component ownership in `Frontend Map`.
- Add or revise domain invariants in `Data And Domain Rules`.
- Add or revise setup, env vars, or tests in `Local Development`, `Validation`, or `Important Environment Variables`.

Do not turn this file into a changelog. Record the current truth of the project and remove stale guidance when it becomes wrong.
