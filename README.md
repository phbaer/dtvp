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
- Optionally run reachability/exploitability code analysis through an external code-analysis service.
- Edit team mappings, user roles, and rescore rules from the settings screen.
- Run against either a live Dependency-Track server or the bundled mock service.

## Architecture And Structure

DTVP is split into a FastAPI backend, a Vue single-page application, and mock external services for local development. The backend can serve the built SPA from `frontend/dist`, while day-to-day development usually runs the backend and Vite dev server separately.

### Backend

- `dtvp/main.py` builds the FastAPI app, CORS, context path handling, task stores, dependency wiring, routers, startup/shutdown hooks, and SPA fallback.
- `dtvp/app_wiring.py` centralizes dependency construction so routes and services can be tested without importing the full app.
- `dtvp/general_api_routes.py` owns core routes for projects, grouped vulnerability tasks, task polling, statistics, assessment details, assessment writes, and dependency-chain lookup.
- `dtvp/grouped_vuln_services.py` fetches per-version findings, detailed vulnerabilities, and BOMs concurrently before grouping.
- `dtvp/logic.py` contains core domain logic for team mapping, roles, BOM dependency analysis, vulnerability grouping, statistics, CVSS vector handling, assessment-detail parsing, and aggregated assessment state.
- `dtvp/assessment_services.py` handles Dependency-Track assessment payloads, conflict detection, local cache updates, remote writes, and result finalization.
- `dtvp/dt_client.py` calls the Dependency-Track API. `dtvp/dt_cache.py` persists Dependency-Track projects, findings, vulnerabilities, BOMs, analyses, active project IDs, and pending updates under `data/dt_cache` by default.
- `dtvp/settings_routes.py` manages team mapping, user roles, and CVSS rescore rules backed by files under `data/`.
- `dtvp/app_info_routes.py`, `dtvp/app_info_services.py`, and `dtvp/frontend_routes.py` expose metadata, changelog/OpenAPI/SBOM downloads, and built frontend assets.
- Optional integration routes and services live in `dtvp/tmrescore_*`, `dtvp/code_analysis_*`, `dtvp/analysis_queue_*`, and the matching mock services under `test_setup/`.

### Frontend

- Vue entry points are `frontend/src/main.ts`, `frontend/src/App.vue`, and `frontend/src/router.ts`.
- `frontend/src/lib/api.ts` is the central backend client and defines most frontend-facing integration types.
- `frontend/src/types.ts` defines project, grouped vulnerability, assessment, statistics, cache, tmrescore, and proposal shapes.
- Major pages live under `frontend/src/pages/`: `Dashboard.vue`, `ProjectView.vue`, `TMRescore.vue`, `Statistics.vue`, `Settings.vue`, and `Login.vue`.
- Reusable vulnerability, modal, queue, filter, dependency-chain, and CVSS components live under `frontend/src/components/`.
- Project review state is supported by helpers and composables in `frontend/src/lib/`, including assessment form/submission helpers, CVSS utilities, vulnerability list indexing, modal selection, project header state, and code-analysis queue state.

### Data And Domain Rules

- Team mapping accepts either `"component": "Team"` or `"component": ["Primary", "Alias"]`; aliases normalize to the primary team label in much of the UI.
- The wildcard team mapping key `"*"` provides a fallback team.
- Assessment details are structured text blocks with metadata headers such as `[Team: ...]`, `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`, `[Rescored: ...]`, `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Aggregated assessment state gives a non-`NOT_SET` General block precedence; otherwise it picks the worst team state using the state priority in `dtvp/logic.py`.
- Rescored CVSS vectors are sanitized against original base metrics so threat or environmental changes do not silently mutate base metrics.
- Dependency relationship and paths are derived from CycloneDX BOM dependency graphs.
- Dependency-Track finding attribution timestamps are preserved on grouped component instances as `attributed_on`; the project view can filter vulnerability groups by attribution date range, invert that range to find older/outside findings such as "not in the last 4 weeks," and shows each vulnerability's age since its oldest attribution in the card header.
- Analysis states commonly include `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `FALSE_POSITIVE`, and `NOT_AFFECTED`.

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

DTVP can optionally call an external code-analysis service to assess whether a vulnerable component is reachable or exploitable in consuming code.

- Configure the backend with `DTVP_CODE_ANALYSIS_URL` to enable the integration.
- Scans run through an in-process queue. Queue routes live in `dtvp/code_analysis_routes.py`, queue runtime/service code lives in `dtvp/analysis_queue_runtime.py` and `dtvp/analysis_queue_services.py`, and the frontend panel lives in `frontend/src/components/CodeAnalysisPanel.vue`.
- The expected upstream API surface is defined by `dtvp/code_analysis_integration.py`, `openapi/code-analysis-openapi.json`, and the mock server in `test_setup/mock_code_analysis.py`.

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
uv run uvicorn dtvp.main:app --reload --host 127.0.0.1 --port 8000
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

The image mounts `./data` into the container so local mapping and rule files persist.

If you need to customize the deployment, edit `compose.yml` directly.

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Base URL of the Dependency-Track API | `http://localhost:8081` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | Optional file path to read the Dependency-Track API key from when `DTVP_DT_API_KEY` is not set | unset |
| `DEPENDENCY_TRACK_URL` | Deployment alias used when `DTVP_DT_API_URL` is unset | unset |
| `DEPENDENCY_TRACK_API_KEY` | Deployment alias used when `DTVP_DT_API_KEY` and `DTVP_DT_API_KEY_FILE` are unset | unset |
| `DTVP_DT_CACHE_PATH` | Local path for Dependency-Track cache files and pending update queue | `data/dt_cache` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background Dependency-Track cache refresh interval | `60` |
| `DTVP_TMRESCORE_URL` | Base URL of the external or mock tmrescore service | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | HTTP timeout for tmrescore API calls before DTVP falls back to polling `/progress` | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Path to the cached per-project tmrescore proposal snapshot file | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_OLLAMA_MODEL` | Default Ollama model preselected for LLM enrichment in the threat-model UI | `qwen2.5:7b` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | How long completed or failed tmrescore analysis tasks stay in DTVP memory for `/progress` polling | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | Base URL of the external or mock code analysis service | unset |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | HTTP timeout for code analysis API calls | `300` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | How long completed or failed code-analysis queue items stay in memory | `3600` |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback URL | derived from frontend URL and context path |
| `DTVP_FRONTEND_URL` | Frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | `/` |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_CORS_ORIGINS` | Optional comma-separated extra CORS origins | unset |
| `DTVP_API_URL` | Optional frontend API base URL override, also available as `VITE_DTVP_API_URL` during Vite development | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Default project filter shown on the dashboard | empty |
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
