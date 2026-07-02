# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings across all versions of a project. It groups vulnerabilities by CVE, surfaces version-by-version differences in one place, and lets teams apply assessments in bulk instead of repeating the same work on every release.

The repository also includes a mock Dependency-Track service, which makes it possible to run the full application locally without a live upstream instance.

Repository links:

- Main repo: https://git.baer.one/phbaer/dtvp/
- GitHub mirror: https://github.com/phbaer/dtvp/

## AI Agent Entry Point

This README is the canonical project overview for humans and AI agents. Any AI agent, assistant, automation, or project-specific skill should read this file before doing broad scans, planning changes, or modifying code.

Keep this file in sync with the project:

- When a change affects behavior, architecture, APIs, integrations, configuration, commands, workflows, or repository structure, update this README in the same change.
- If the README conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the source and update the README.
- Agent-specific files such as `AGENTS.md` and `skills/*/SKILL.md` are routing hints only; they should point agents back here instead of carrying a separate architecture overview.
- The generic project skill entry point is `skills/project-entrypoint/SKILL.md`; `skills/dtvp-project-memory/SKILL.md` remains as a DTVP-named compatibility entry point.
- Python and backend work uses `uv` from the repository root.
- Node and frontend work uses `npm` from `frontend/`.

GitHub Copilot support needs a little extra care because Copilot does not treat every agent file the same way across all surfaces:

- Copilot agents can read `AGENTS.md`, but GitHub.com Chat, IDE chat, code review, and cloud-agent workflows each support different subsets of `AGENTS.md`, `.github/copilot-instructions.md`, and `.github/instructions/*.instructions.md`.
- If Copilot appears to ignore the repository rules, first check that repository/custom instructions are enabled in the Copilot surface being used. In VS Code this is the `Code Generation: Use Instruction Files` setting.
- For broad Copilot repository instructions, use `.github/copilot-instructions.md` and keep it as a short pointer back to this README instead of duplicating the architecture overview.
- Copilot project skills are discovered from `.github/skills`, `.claude/skills`, or `.agents/skills`. The project-local `skills/` directory in this repo is for Codex/project-entrypoint compatibility and should not be assumed to activate as Copilot skills unless mirrored or installed into a Copilot-supported skills location.
- When adding any Copilot-specific instruction or skill file, keep this README canonical and update it whenever the workflow, command, architecture, or repository structure guidance changes.

## Repository Layout

- `dtvp/`: FastAPI backend package.
- `frontend/`: Vue 3, Vite, and Tailwind frontend package managed with npm.
- `test_setup/`: mock Dependency-Track, tmrescore, and code-analysis services for local and test workflows.
- `tests/`: backend pytest test suite.
- `data/`: local JSON configuration and cache defaults, including roles, team mapping, rescore rules, and Dependency-Track cache data.
- `openapi/`: static OpenAPI specs for optional external integrations.
- `docs/`: integration notes and generated README screenshot assets.
- `skills/`: project-local AI skill entry points. These are lightweight pointers to this README.

## SBOM

- The container includes a CycloneDX SBOM at `/sbom/dtvp-cyclonedx.json`.
- Generated via `syft` (standard SBOM tooling) during Docker image build.
- The app exposes it at `/api/sbom` and `/api/sbom/html`; footer includes "Download CycloneDX SBOM".
- Includes production frontend (`frontend/package.json`/`frontend/package-lock.json`) and backend (`pyproject.toml`/`uv.lock`) dependency components; test/dev dependencies excluded by design.

## What It Does

- Group the same vulnerability across multiple project versions.
- Show lifecycle states such as open, assessed, incomplete, inconsistent, and needs approval.
- Support global and team-specific assessments.
- Rescore findings with CVSS data and review the aggregated result in the UI.
- Optionally re-score against a Microsoft Threat Modeling Tool export via an external tmrescore service.
- Optionally run reachability/exploitability code analysis, including automatic background scanning of newly discovered open vulnerabilities.
- Export and import versioned project archives so Dependency-Track project versions, SBOMs, findings, vulnerability details, and DTVP assessments can be restored into a replacement Dependency-Track instance.
- Edit team mappings, user roles, and rescore rules from the settings screen.
- Run against either a live Dependency-Track server or the bundled mock service.

## Architecture And Structure

DTVP is split into a FastAPI backend, a Vue single-page application, and mock external services for local development. The backend can serve the built SPA from `frontend/dist`, while day-to-day development usually runs the backend and Vite dev server separately.

### Backend

- `dtvp/boot.py` is the default ASGI entry point for packaged and local runs. It is intentionally tiny, lets Uvicorn bind and accept HTTP before importing the full backend, serves `/startup` and `/api/startup` while the real app loads, then hands traffic to `dtvp.main:app`.
- `dtvp/main.py` builds the FastAPI app, CORS, context path handling, task stores, dependency wiring, routers, startup/shutdown hooks, and SPA fallback.
- `dtvp/app_wiring.py` centralizes dependency construction so routes and services can be tested without importing the full app.
- Backend startup prints a flushed console context block and logs the DTVP version, build commit, Python/platform/container hints, and a safe environment summary. Integration endpoints and auth providers are shown as configured/unset rather than printing secrets.
- `dtvp/general_api_routes.py` owns core routes for projects, grouped vulnerability tasks, task polling, statistics, assessment details, assessment writes, and dependency-chain lookup.
- `dtvp/grouped_vuln_services.py` fetches per-version findings, detailed vulnerabilities, and BOMs concurrently before grouping.
- Grouped vulnerability tasks support `response_mode=summary` for list-first views. Summary responses omit heavy per-instance assessment text, comments, and dependency-chain paths while retaining backend-precomputed list metadata such as lifecycle state, assessed teams, component/version rollups, attribution ages, dependency relationship, instance count, and CVSS mismatch flags. Task polling supports `include_result=false` so clients can wait for completion without downloading every group, `/api/tasks/{task_id}/events` streams progress and partial-result availability as NDJSON without the heavy result payload, running summary tasks can seed list windows from a persistent SQLite summary index keyed by project/version scope, cache revision, CVE, and team mapping while the live task refresh continues, version snapshots publish partial query indexes as they finish so `/api/tasks/{task_id}/groups` can serve early list windows before the full task completes, completed tasks keep a private query index and bounded query-result cache so repeated task-window queries can reuse precomputed filter/sort results for server-side filtering, sorting, opaque cursor pagination, offsets, limits, and all/filtered count metadata, including task-wide vulnerability ID, team, proposal, attribution-age, dependency, version, tag, assignee, and component facets, assessment writes refresh matching in-memory task snapshots and rebuild task query indexes so active filtered windows do not require a full reload, task statistics are available at `/api/tasks/{task_id}/statistics` without refetching Dependency-Track, and full groups remain available through `/api/tasks/{task_id}/groups/{group_id}` for detail panels or through backend-filtered `/api/tasks/{task_id}/group-details` windows for bulk workflows.
- `dtvp/logic.py` contains core domain logic for team mapping, roles, BOM dependency analysis, vulnerability grouping, statistics, CVSS vector handling, assessment-detail parsing, and aggregated assessment state.
- `dtvp/assessment_services.py` handles Dependency-Track assessment payloads, conflict detection, local cache updates, remote writes, and result finalization.
- `dtvp/dt_client.py` calls the Dependency-Track API. `dtvp/dt_cache.py` persists Dependency-Track projects, findings, vulnerabilities, BOMs, analyses, active project IDs, and pending updates under `data/dt_cache` by default.
- `dtvp/project_archive_routes.py` and `dtvp/project_archive_services.py` provide reviewer-only project archive export/import, archive task progress, local snapshot downloads, and scheduled local snapshots under `data/project_archives` by default.
- `dtvp/settings_routes.py` manages team mapping, user roles, and CVSS rescore rules backed by files under `data/`.
- `dtvp/app_info_routes.py`, `dtvp/app_info_services.py`, and `dtvp/frontend_routes.py` expose metadata, changelog/OpenAPI/SBOM downloads, and built frontend assets.
- Optional integration routes and services live in `dtvp/tmrescore_*`, `dtvp/code_analysis_*`, `dtvp/analysis_queue_*`, and the matching mock services under `test_setup/`.

### Frontend

- Vue entry points are `frontend/src/main.ts`, `frontend/src/App.vue`, and `frontend/src/router.ts`.
- DTVP serves a native startup page from `/startup` while runtime initialization is still running, the static `index.html` includes a first-paint startup page before Vue mounts, and the app shell shows an initialization page while it loads backend version metadata, project metadata, and the current session. If the backend is still starting or temporarily unavailable after the SPA loads, the UI shows a retryable startup page instead of exposing a raw HTTP/proxy error.
- `frontend/src/lib/api.ts` is the central backend client and defines most frontend-facing integration types.
- `frontend/src/types.ts` defines project, grouped vulnerability, assessment, statistics, cache, tmrescore, and proposal shapes.
- Major pages live under `frontend/src/pages/`: `Dashboard.vue`, `ProjectView.vue`, `TMRescore.vue`, `Statistics.vue`, `Settings.vue`, and `Login.vue`.
- Reusable vulnerability, modal, queue, filter, dependency-chain, and CVSS components live under `frontend/src/components/`.
- Reviewer users can export project archives from the dashboard or project view, and can preview/import archives from the Settings Archives tab.
- Project review state is supported by helpers and composables in `frontend/src/lib/`, including assessment form/submission helpers, project assessment/list-summary update handling, bulk incomplete resolve state, CVSS utilities, vulnerability list indexing, filter/query synchronization, selection/detail route state, smart-search controls, responsive project-view layout state, backend task-window query and filter-chip view models, detail hydration, modal selection, project header state, and code-analysis queue state.
- The project vulnerability list renders item-only compact rows from cached `VulnListItem` metadata hydrated from backend summary metadata when available, with precomputed search and sort fields, list-wide facets, static stats, and ID-indexed group lookups derived in one base index pass. It compiles active list/state filters and membership checks once per filtered pass for non-task fallback data, keeps filtered rows separate from final sorting, uses bounded search-completion matching, debounces expensive smart-search filtering while keeping input controls immediate, requests summary task results by default, streams grouped-vulnerability task events when available while falling back to result-free polling, loads an early backend-filtered partial task window when available, marks partial counts as provisional with version progress, refreshes the backend-filtered window as streamed version progress advances and again when task completion arrives, appends more cursor windows as the reviewer scrolls, renders backend-filtered task windows directly without a second local filter/sort pass, refreshes active task windows after assessment and team-mapping writes, reuses active task statistics when switching to the project statistics view, keeps backend all/filtered counts and task-wide facets for list badges and search completions where available, sends meaningful threat-model proposal IDs into backend task-window filters so TM proposal filtering stays windowed, keeps list state lightweight after detail hydration and local updates, lazy-loads full vulnerability groups for detail panels, prepares bulk incomplete sync from backend-filtered full-detail `INCOMPLETE` task windows instead of the current local list or per-group detail requests, and uses viewport windowing via `useVisibleGroupWindow` so row DOM stays proportional to the visible scroll area rather than the total number of vulnerabilities.

### Open Improvement Opportunities

- Backend-native bulk preview/apply flows are a good next scale improvement if reviewers often bulk-resolve hundreds or thousands of matching vulnerabilities. Today the bulk incomplete modal is already backend-filtered, but it still drains full-detail windows into the browser before the modal can act, so preparation cost remains proportional to the matched bulk set.
- A future bulk preview endpoint could accept a task ID, current task-window filters, and the intended bulk action, then return counts, affected teams/states, conflicts, representative sample rows, and grouped totals without returning every full vulnerability group.
- A future bulk apply endpoint should likely run as an async backend task that owns matching, detail hydration, conflict checks, batching, Dependency-Track writes, local cache updates, progress reporting, and final result summaries. A dry-run or preview ID should make the apply step correspond exactly to the reviewed preview.
- The UI could then open bulk modals immediately with preview summaries, stream apply progress, and fetch detailed samples/errors only on demand. Keep the current client-drained full-detail-window path as a fallback while the backend-native write flow matures.
- This is not urgent for small bulk sets, but it is the remaining place where a common workflow can still scale with matched vulnerability count rather than the user's immediate action surface. The main risk is write-path correctness, because bulk assessment touches permissions, conflict detection, assessment text generation, pending-review state, remote Dependency-Track updates, and local cache overlays.

### Data And Domain Rules

- Team mapping accepts either `"component": "Team"` or `"component": ["Primary", "Alias"]`; aliases normalize to the primary team label in much of the UI.
- The wildcard team mapping key `"*"` provides a fallback team.
- Assessment details are structured text blocks with metadata headers such as `[Team: ...]`, `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`, `[Rescored: ...]`, `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Aggregated assessment state gives a non-`NOT_SET` General block precedence; otherwise it picks the worst team state using the state priority in `dtvp/logic.py`.
- Rescored CVSS vectors are sanitized against original base metrics so threat or environmental changes do not silently mutate base metrics.
- Dependency relationship and paths are derived from CycloneDX BOM dependency graphs.
- Dependency-Track finding attribution timestamps are preserved on grouped component instances as `attributed_on`; the project view can filter vulnerability groups by attribution date range, invert that range to find older/outside findings such as "not in the last 4 weeks," and shows each vulnerability's age since its oldest attribution in the card header.
- Analysis states commonly include `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `FALSE_POSITIVE`, and `NOT_AFFECTED`.

## Project Archives

DTVP can create versioned project archives for replacing Dependency-Track with an empty instance or preserving projects that will no longer be touched by pipeline runs.

- Reviewer-only export starts with `POST /api/project-archives/exports` and writes a ZIP archive containing `manifest.json`, one directory per project version, raw CycloneDX SBOMs, raw findings, full vulnerability details, and normalized assessment records.
- The archive schema is `dtvp.project-archive/v1`. Newer DTVP versions must keep importing v1 archives. Unknown v1 fields are ignored; future major archive schemas may be rejected with a clear unsupported-version error.
- Import starts with `POST /api/project-archives/imports`, which uploads an archive and returns a preview task. Applying the preview uses `POST /api/project-archives/imports/{task_id}/apply` with `mode=create_missing` or `mode=update`.
- Restore matching uses project name and version first. When Dependency-Track creates new UUIDs, DTVP remaps assessments by component purl/name/version/bom-ref and vulnerability ID/name/aliases before writing the current mutable analysis state back through the Dependency-Track analysis API.
- `create_missing` creates missing project versions from archived SBOMs and leaves existing versions untouched. `update` is required to upload SBOMs and restore assessments into existing versions.
- Dependency-Track audit history and analysis comments are not exported or replayed. Restored assessments create fresh Dependency-Track audit entries under the restoring API identity.
- Stored archives are listed and downloadable from `GET /api/project-archives/snapshots`. Manual exports and scheduled snapshots use `DTVP_PROJECT_ARCHIVE_PATH`.
- Scheduled snapshots are disabled by default. When enabled, the backend periodically exports configured project names, or the locally active/cached project names when no include list is configured, and retains recent archives per project.
- Reviewer export actions on the dashboard and project view show queued/running/completed task progress and expose the generated archive download link when the ZIP is ready.
- When `DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED=true`, every successful export also rewrites a stable expanded project tree under `DTVP_PROJECT_ARCHIVE_EXPANDED_PATH`. This tree contains the same checksummed JSON payloads as the ZIP archive, but omits volatile export timestamp/build metadata from the Git-facing manifest so unchanged project state does not produce noisy commits. Git should archive this expanded tree, not the ZIP files.
- The expanded tree is still shaped like a v1 project archive. To restore from Git-only storage, zip the selected project directory contents so `manifest.json` and `versions/` are at the ZIP root, then upload it through the normal project archive import flow.

## Threat-Model Rescoring

DTVP can optionally call an external tmrescore service to re-score vulnerabilities against a Microsoft Threat Modeling Tool export.

- Configure the backend with `DTVP_TMRESCORE_URL` to enable the UI entry points.
- Optionally set `DTVP_TMRESCORE_CACHE_PATH` to control where the latest per-project proposal snapshots are stored. By default DTVP writes them to `data/tmrescore_proposals.json`.
- Open a project and use the `Threat Model` action from the dashboard or project view.
- Upload the current `.tm7` file and optional `items.csv` / analysis config inputs.
- If an LLM backend is configured for tmrescore, you can enable `LLM enrichment` in the Threat Model UI and optionally choose the model used for threat-justification enrichment.
- After a successful run, the latest cached proposal set for that project is available directly inside each reviewer rescoring dialog where the vulnerability ID matches.
- Returning to the project view after a run triggers an immediate proposal refresh so the rescoring dialog can use the new suggestions without waiting for a backend restart or a manual reload.

SBOM strategy matters here:

- `Latest only` is a clean single-version snapshot and uses only the newest project version.
- `Merged multi-version SBOM` is the recommended mode for DTVP because it creates an analysis-only synthetic CycloneDX document with separate roots per version, preserving historical findings without pretending they all belong to the latest inventory.
- DTVP intentionally does not combine the latest SBOM with vulnerabilities found only in older versions, because that would attach findings to components that may not exist in the latest release.

## Code Analysis

DTVP can call an external code-analysis service to assess whether a vulnerable component is actually reachable/exploitable in the consuming code, and surface the result inside the reviewer workflow.

- Configure the backend with `DTVP_CODE_ANALYSIS_URL` to enable the integration. When unset, all code-analysis UI and background scanning stay disabled.
- Scans run through an in-process queue. Each queue item carries the vulnerability ID, the target component, the CVSS vector, and reviewer guidance, and is processed by a background worker.
- The expected upstream API surface is defined by `dtvp/code_analysis_integration.py`, the static spec in `openapi/code-analysis-openapi.json`, and the mock server in `test_setup/mock_code_analysis.py`.

### Automatic Scanning Of Open Vulnerabilities

When `DTVP_AUTO_CODE_ANALYSIS_ENABLED=true` **and** a code-analysis URL is configured, DTVP automatically queues scans for genuinely new open vulnerabilities without a reviewer clicking anything.

- **New work:** opening/refreshing a project view queues scans for newly discovered open grouped vulnerabilities it surfaces.
- **Existing discovery:** a periodic sweep (`DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS`, default 900s) walks both the cached project snapshots and the live project list to catch new open vulnerabilities that no one has opened recently.

Only newly discovered, truly **open** grouped vulnerabilities are queued — never everything. A group is considered automatically open only when every grouped instance is still `NOT_SET` and no instance has assessment detail text at all. Groups that already carry any global, team, or legacy plaintext assessment details are treated as handled, even if one detail block still says `State: NOT_SET` or a newly appeared version is still unassessed. During cached and live sweeps, handled vulnerability IDs suppress other open-looking copies of the same vulnerability so an already assessed CVE is not automatically re-assessed just because team-specific blocks, versions, or project snapshots are missing. Stale automatic queue items for groups that have since become handled are cancelled on the next pass; manually requested scans are left untouched.

Because the sweep reads from the local cache, cached findings are overlaid with locally stored DTVP assessments before the open/closed decision is made. This keeps the background sweep consistent with the live project view, so a vulnerability assessed in DTVP is not re-scanned just because its cached findings file predates the assessment.

The `enabled` / `code_analysis_configured` / `active` state and last-sweep status are exposed through the code-analysis API and reflected in the `AnalysisQueueIndicator` UI.

## Stack

- Backend: Python 3.14+, FastAPI, Uvicorn, httpx
- Frontend: Vue 3, Vite, Tailwind CSS
- Python package manager: uv. Use `uv sync --dev`, `uv run pytest`, and `uv run uvicorn ...` from the repository root.
- Frontend and Node package manager: npm. Run frontend dependency and script commands from `frontend/`.
- Local process manager: pm2
- Container runtime: Docker / Docker Compose

## Prerequisites

Install the following first:

- Python 3.14+
- Node.js 22+
- uv
- npm
- pm2
- Docker and Docker Compose if you want the container-based deployment path

## Install Dependencies

From the repository root:

```bash
uv sync --dev
cd frontend
npm ci
cd ..
```

## Local Mock Workflow With pm2

This is the simplest way to test the full application locally. It starts:

- `mock-dt` on `http://localhost:8081`
- `mock-tmrescore` on `http://localhost:8090`
- `dtvp-backend` on `http://localhost:8000`
- `dtvp-frontend` on `http://localhost:5173`

The process definitions live in `ecosystem.config.js`.

### Start The Full Local Stack

```bash
pm2 start ecosystem.config.js --update-env
```

Then open:

- Frontend: `http://localhost:5173`
- Backend API version endpoint: `http://localhost:8000/api/version`
- Mock Dependency-Track service: `http://localhost:8081`
- Mock TMRescore service: `http://localhost:8090/ui`

### Sign In To The Mock Stack

1. Open `http://localhost:5173/login`.
2. Click `Sign in with SSO`.
3. The mock Dependency-Track login page opens on port `8081`.
4. Choose `Login as Reviewer` to access the full UI, including Settings.
5. After the redirect back to DTVP, start browsing projects.

### Useful pm2 Commands

Check status:

```bash
pm2 list
```

Tail logs for all services:

```bash
pm2 logs
```

Tail one service only:

```bash
pm2 logs mock-dt
pm2 logs mock-tmrescore
pm2 logs dtvp-backend
pm2 logs dtvp-frontend
```

Stop and remove the local stack:

```bash
pm2 delete mock-dt mock-tmrescore dtvp-backend dtvp-frontend
```

## Manual Development Workflow

If you want to iterate on the backend or frontend manually while keeping the mock services managed by pm2, use this split workflow.

### 1. Start Only The Mock Services

```bash
pm2 start ecosystem.config.js --only mock-dt,mock-tmrescore
```

### 2. Start The Backend

Use the mock service values directly in your shell:

```bash
export DTVP_DT_API_URL=http://127.0.0.1:8081
export DTVP_DT_API_KEY=mock_key
export DTVP_OIDC_AUTHORITY=http://127.0.0.1:8081
export DTVP_OIDC_CLIENT_ID=mock_id
export DTVP_OIDC_CLIENT_SECRET=mock_secret
export DTVP_OIDC_REDIRECT_URI=http://localhost:5173/auth/callback
export DTVP_FRONTEND_URL=http://localhost:5173
export DTVP_TMRESCORE_URL=http://127.0.0.1:8090
export DTVP_VERSION_FETCH_CONCURRENCY=4
uv run uvicorn dtvp.boot:app --reload --host 127.0.0.1 --port 8000
```

If you want to skip the mock OIDC login entirely during local backend work, set this before starting Uvicorn:

```bash
export DTVP_DEV_DISABLE_AUTH=true
```

In that mode, `/auth/me` resolves to `devuser`, which is mapped to the `REVIEWER` role in `data/user_roles.json`.

### 3. Start The Frontend

In a separate terminal:

```bash
cd frontend
npm run dev
```

### 4. Stop The Mock Service

```bash
pm2 delete mock-dt mock-tmrescore
```

## Application Walkthrough

The screenshots below were captured from the bundled mock stack started with `pm2 start ecosystem.config.js --update-env`.

Some selected visual coverage for the core DTVP workflows are covered by this README:

- Login and SSO handoff
- Dashboard project selection and filtering
- Project vulnerability detail and review workflow
- Expanded dependency chain inspection
- Statistics and severity analysis
- Settings for team mapping, roles, and rescore rules

The screenshot assets are generated by the Playwright flow in `frontend/e2e/capture-readme-screenshots.manual.ts`.

### 1. Login

Start at the DTVP login page and hand off to the mock SSO provider.

![DTVP login page](docs/screenshots/login.png)

### 2. Dashboard

The dashboard groups projects by classifier and shows all known versions of a project on a single card. Use the project filter to narrow the list and the global CVE filter to carry a CVE directly into the project view.

![Dashboard with grouped projects](docs/screenshots/dashboard.png)

### 3. Project Vulnerability View

Selecting a project opens the grouped vulnerability view. This is the core workflow: filter by lifecycle and analysis state, inspect team markers, expand a CVE, review the aggregated history, and apply a synchronized assessment.

Recent UI updates reflected in this screenshot:
- lifecycle and analysis badges now recalculate against the currently filtered dependency/version/search result set instead of showing only overall totals
- direct/transitive dependency chain rendering now hides the vulnerable endpoint component in each chain for reduced redundancy
- long chain lists are capped at three items with a “show more” link to expand full chain list for the group
- team mapping now resolves aliases to the primary configured team name for consistency across lifecycle badges and assessment blocks

![Expanded project vulnerability view](docs/screenshots/project-view.png)

### 3.1. Dependency Chain Detail

The dependency section groups paths by direct dependency, shows only the primary configured team name for mapped components, and lets you expand longer path lists without repeating the vulnerable endpoint component itself.

![Dependency chain detail view](docs/screenshots/project-view-dependencies.png)

### 4. Statistics

The statistics screen summarizes the same project data into totals, severity distribution, analysis progress, and per-major-version charts.

![Project statistics view](docs/screenshots/statistics.png)

### 5. Settings

Reviewer users can edit team mappings, user roles, and rescore rules directly from the settings page.

![Settings editor](docs/screenshots/settings.png)

## Running Tests

### Backend

```bash
uv run pytest
```

### Frontend Unit Tests

```bash
cd frontend
npm run test:unit -- --run
```

### Frontend Unit Tests in Container (Podman)

```bash
sh scripts/run-frontend-tests-podman.sh unit
```

### Frontend End-To-End Tests

The UI tests expect the local stack to be available.

To capture the README screenshots and exercise the real conflict modal, run:

```bash
cd frontend
npm run test:ui:docs
```

This will execute `frontend/e2e/capture-readme-screenshots.manual.ts` and update the screenshot assets under `docs/screenshots`.

### Testing the Apply Conflict Dialog

To verify the apply conflict flow manually:

1. Start the backend and frontend against the mock Dependency-Track stack.
2. Open the app in the browser and navigate to a project with a vulnerable component.
3. In one browser session, change the assessment for a team or apply an update.
4. In a second browser session or by forcing a server-side state change via the mock DT API, edit the same finding again and submit.
5. The conflict dialog should appear with the server state on the left and your changes on the right.
6. Use "Discard My Changes (Use Server)" or "Force Overwrite" to resolve the conflict.

The saved conflict modal screenshot is available at `docs/screenshots/conflict-resolution.png`. If you want to regenerate it, use the Playwright capture test above.


```bash
pm2 start ecosystem.config.js --update-env
cd frontend
npm run test:ui
```

### Frontend UI Tests in Container (Podman)

Use podman if your host OS does not support local Playwright execution:

```bash
sh scripts/run-frontend-tests-podman.sh ui
```

### Development Container

This repository now includes devcontainer support in `.devcontainer/`.

- Open the folder in VS Code using the Remote - Containers / Dev Containers extension.
- The container installs Python, Node.js, `uv`, and frontend dependencies.
- Forwarded ports: `8000` for the backend and `5173` for the frontend dev server.

If you use Podman as your container runtime, make sure VS Code is configured to use the Podman socket from `podman-docker`.

To run only the real-stack threat-model Playwright flow against the pm2 mocks, use:

```bash
pm2 start ecosystem.config.js --update-env
cd frontend
DTVP_E2E_REAL_STACK=true npm run test:ui -- --grep "Threat-Model UI Flow"
```

## Docker Deployment

Use this when you want to run the packaged application instead of the local dev stack.

### 1. Create The Environment File

```bash
cp .env.dist .env
```

Fill in the real Dependency-Track and OIDC values.

### 2. Start The Container

```bash
docker compose up -d
```

The Compose service loads `.env` when present and mounts `./data` into `/app/data` so local mapping files, role files, cache data, tmrescore proposal cache, and project archives persist across container restarts/recreates.

If you need to customize the deployment, edit `compose.yml` directly.

The bundled nginx gateway intentionally stays lean and only proxies `/dtvp` to DTVP, `/api` to Dependency-Track, and everything else to the Dependency-Track frontend. The default DTVP boot entry point lets Uvicorn bind and accept HTTP before the full backend imports or runtime preprocessing finishes. It serves the native startup page while that work is running and exposes `GET /dtvp/api/startup` with `ready: false` until initialization completes. No backend can serve a page before its process is listening, so a centralized reverse proxy may still show its generic upstream fallback for the very first process-start window.

### Project Archive Setup In Docker Compose

Manual project archive exports work with the default Compose setup after `DTVP_DT_API_KEY` is configured. The Dependency-Track API key used by DTVP must be allowed to read projects, findings, vulnerabilities, and BOMs; imports also need BOM upload and vulnerability-analysis update permissions.

By default, archives are written inside the container at `data/project_archives`, which resolves to `./data/project_archives` on the host through the Compose volume mount:

```env
DTVP_PROJECT_ARCHIVE_PATH=data/project_archives
```

To enable scheduled snapshots, set these values in `.env` before running `docker compose up -d`:

```env
DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED=true
DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS=86400
DTVP_PROJECT_ARCHIVE_RETENTION_COUNT=30
DTVP_PROJECT_ARCHIVE_INCLUDE=Project A,Project B
```

`DTVP_PROJECT_ARCHIVE_INCLUDE` is optional. When empty, scheduled snapshots export the active/cached projects DTVP knows about. For predictable production backups, set it to the exact project names you want archived.

For Git-backed archival, enable the expanded tree writer:

```env
DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED=true
DTVP_PROJECT_ARCHIVE_EXPANDED_PATH=data/project_archives_git
```

DTVP triggers the data update whenever a manual export or scheduled snapshot completes. Git commit/push is intentionally handled outside the DTVP backend so SSH keys, deploy tokens, and remote repository access stay out of the application process.

The bundled Compose file includes an optional one-shot Git client service using `alpine/git`. Configure a dedicated archive repository and deploy key in `.env`:

```env
DTVP_ARCHIVE_GIT_REMOTE=git@github.com:your-org/dtvp-project-archives.git
DTVP_ARCHIVE_GIT_BRANCH=main
DTVP_ARCHIVE_GIT_AUTHOR_NAME=DTVP Archive Bot
DTVP_ARCHIVE_GIT_AUTHOR_EMAIL=dtvp-archive@example.invalid
```

Put the SSH deploy key and known-hosts file at these default paths on the host:

```text
./secrets/dtvp_archive_deploy_key
./secrets/known_hosts
```

Then push the diffable archive tree on demand:

```bash
docker compose run --rm dtvp-archive-git-push
```

Because `dtvp-archive-git-push` is explicitly targeted, Docker Compose runs it even though it belongs to the optional `archive-git` profile. `docker compose --profile archive-git run --rm dtvp-archive-git-push` is equivalent and can be useful in tools that expose profile selection.

For automatic Git archival, schedule that command from host cron, systemd timer, CI, a Compose-manager terminal, or another Compose-aware scheduler after the DTVP snapshot interval. The helper commits `./data/project_archives_git` into `project_archives/` in the remote repository and skips the commit when there are no archive changes.

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Base URL of the Dependency-Track API | `http://localhost:8081` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | Optional file path to read the Dependency-Track API key from when `DTVP_DT_API_KEY` is not set | unset |
| `DEPENDENCY_TRACK_URL` | Deployment alias used when `DTVP_DT_API_URL` is unset | unset |
| `DEPENDENCY_TRACK_API_KEY` | Deployment alias used when `DTVP_DT_API_KEY` and `DTVP_DT_API_KEY_FILE` are unset | unset |
| `DTVP_DT_CACHE_PATH` | Local path for Dependency-Track cache files and pending update queue | `data/dt_cache` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | SQLite path for persisted grouped-vulnerability summary indexes used to seed repeat summary list loads | sibling of `DTVP_DT_CACHE_PATH` as `grouped_vuln_summary_index.sqlite` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted grouped-vulnerability summary indexes retained | `64` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background Dependency-Track cache refresh interval | `60` |
| `DTVP_PROJECT_ARCHIVE_PATH` | Local directory for manual project archive exports, uploaded import previews, and scheduled snapshots | `data/project_archives` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED` | Also write stable expanded archive trees for Git-friendly diff history | `false` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_PATH` | Local directory for expanded archive trees | `data/project_archives_git` |
| `DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED` | Enable scheduled project archive snapshots | `false` |
| `DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS` | Interval for scheduled project archive snapshots; minimum 60 seconds | `86400` |
| `DTVP_PROJECT_ARCHIVE_RETENTION_COUNT` | Number of recent scheduled/manual archive ZIPs retained per project name | `30` |
| `DTVP_PROJECT_ARCHIVE_INCLUDE` | Optional comma-separated project names for scheduled snapshots; when empty, snapshots use active/cached project names | empty |
| `DTVP_ARCHIVE_GIT_REMOTE` | Remote repository used by the optional `archive-git` Compose helper | empty |
| `DTVP_ARCHIVE_GIT_BRANCH` | Branch pushed by the optional `archive-git` Compose helper | `main` |
| `DTVP_ARCHIVE_GIT_AUTHOR_NAME` | Commit author name used by the optional `archive-git` Compose helper | `DTVP Archive Bot` |
| `DTVP_ARCHIVE_GIT_AUTHOR_EMAIL` | Commit author email used by the optional `archive-git` Compose helper | `dtvp-archive@example.invalid` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_FILE` | SSH private key path inside the optional `archive-git` Compose helper container | `/ssh/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_FILE` | SSH known-hosts path inside the optional `archive-git` Compose helper container | `/ssh/known_hosts` |
| `DTVP_TMRESCORE_URL` | Base URL of the external or mock tmrescore service | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | HTTP timeout for tmrescore API calls before DTVP falls back to polling `/progress` | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Path to the cached per-project tmrescore proposal snapshot file | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_OLLAMA_MODEL` | Default Ollama model preselected for LLM enrichment in the threat-model UI | `qwen2.5:7b` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | How long completed or failed tmrescore analysis tasks stay in DTVP memory for `/progress` polling | `3600` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | How long completed or failed grouped-vulnerability tasks keep summary/detail windows in memory | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | Base URL of the external or mock code analysis service | unset |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | HTTP timeout for code analysis API calls | `300` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | How long completed or failed code-analysis queue items stay in memory | `3600` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Automatically queue background code-analysis scans for newly discovered, fully unassessed grouped vulnerabilities when code analysis is configured | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Interval for sweeping existing cached findings and live projects for new open vulnerabilities to queue automatic scans | `900` |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback URL | derived from frontend URL and context path |
| `DTVP_FRONTEND_URL` | Frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | `/` |
| `DTVP_BOOT_APP` | Advanced override for the real ASGI app loaded by the early boot wrapper | `dtvp.main:app` |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_CORS_ORIGINS` | Optional comma-separated extra CORS origins | unset |
| `DTVP_API_URL` | Optional frontend API base URL override, also available as `VITE_DTVP_API_URL` during Vite development | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Default project filter shown on the dashboard | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Comma-separated attribution-age filter presets shown in the project filters; entries may use an optional `d` suffix | `7d,14d,28d` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Max number of project versions fetched in parallel when building grouped views and statistics | `4` |
| `DTVP_DEV_DISABLE_AUTH` | Disable OIDC and force the backend to return `devuser` locally | `false` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |

## External Integration API Specs

- TMRescore static OpenAPI spec: `openapi/tmrescore-openapi.json`
- Code Analysis static OpenAPI spec: `openapi/code-analysis-openapi.json`
- Expected Code Analysis API surface: defined by `dtvp/code_analysis_integration.py` and the mock server at `test_setup/mock_code_analysis.py`
- Integration API expectations are documented in `docs/integration-api-surface.md`

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
