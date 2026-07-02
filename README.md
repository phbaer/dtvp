# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings across every version of a project. It groups findings by vulnerability, shows version-by-version assessment state, and lets reviewers apply consistent assessments in bulk instead of repeating the same work on each release.

It can run against a real Dependency-Track instance or against the bundled mock stack for local development and tests.

Repository links:

- Main repo: https://git.baer.one/phbaer/dtvp/
- GitHub mirror: https://github.com/phbaer/dtvp/

## Reader Guide

This README is the canonical project overview for humans and AI agents.

- Start here before broad scans, planning, or code changes.
- If this README conflicts with source code, tests, package metadata, lockfiles, or runtime configuration, trust the source and update this README.
- When a change affects behavior, architecture, APIs, integrations, configuration, commands, workflows, or repository structure, update this README in the same change.
- `AGENTS.md` and `skills/*/SKILL.md` are routing hints only. They should point back here rather than carrying a second architecture overview.
- Use `uv` for Python/backend work from the repository root.
- Use `npm` for frontend work from `frontend/`.

GitHub Copilot support varies by surface. `AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, and skills directories are not read consistently everywhere. Keep any Copilot-specific instruction files short and pointed back to this README.

## Quick Start

Install dependencies:

```bash
uv sync --dev
cd frontend
npm ci
cd ..
```

Run the full mock stack:

```bash
pm2 start ecosystem.config.js --update-env
```

Open:

- Frontend: `http://localhost:5173`
- Backend API version: `http://localhost:8000/api/version`
- Mock Dependency-Track: `http://localhost:8081`
- Mock tmrescore: `http://localhost:8090/ui`
- Mock code analysis: `http://localhost:8095`

Mock login:

1. Open `http://localhost:5173/login`.
2. Click `Sign in with SSO`.
3. On the mock Dependency-Track login page, choose `Login as Reviewer`.

Stop the mock stack:

```bash
pm2 delete mock-dt mock-tmrescore mock-code-analysis dtvp-backend dtvp-frontend
```

## Common Commands

| Task | Command |
| :--- | :--- |
| Install backend dependencies | `uv sync --dev` |
| Install frontend dependencies | `cd frontend && npm ci` |
| Run backend tests | `uv run pytest` |
| Run frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Run focused frontend tests | `cd frontend && npm run test:unit -- ProjectView` |
| Build frontend | `cd frontend && npm run build` |
| Start full local stack | `pm2 start ecosystem.config.js --update-env` |
| Tail local stack logs | `pm2 logs` |
| Start Docker deployment | `cp .env.dist .env && docker compose up -d` |

## Repository Map

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | FastAPI backend package, routes, services, runtime wiring, integrations |
| `frontend/` | Vue 3, Vite, Tailwind frontend managed with npm |
| `test_setup/` | Mock Dependency-Track, tmrescore, and code-analysis services |
| `tests/` | Backend pytest suite |
| `data/` | Local JSON defaults and cache data for roles, team mapping, rescore rules, Dependency-Track cache, archives |
| `openapi/` | Static OpenAPI specs for optional external integrations |
| `docs/` | Integration notes, workflow diagrams, generated README screenshots |
| `skills/` | Project-local AI skill entry points that route back to this README |
| `.devcontainer/` | VS Code devcontainer setup |

The generic project skill is `skills/project-entrypoint/SKILL.md`. `skills/dtvp-project-memory/SKILL.md` remains as a compatibility entry point.

## Product Scope

DTVP supports:

- Grouping the same vulnerability across project versions.
- Lifecycle states such as open, assessed, incomplete, inconsistent, and needs approval.
- Global and team-specific assessments.
- CVSS rescoring and reviewer workflows.
- Optional threat-model rescoring through tmrescore.
- Optional reachability/exploitability code analysis with automatic scans for newly discovered open vulnerabilities.
- Versioned project archive export/import for Dependency-Track replacement, restore, and retention workflows.
- UI editing for team mappings, user roles, and rescore rules.
- Local operation with a complete mock Dependency-Track stack.

## Architecture

DTVP is split into a FastAPI backend, a Vue single-page frontend, and mock external services for local development. In production, the backend can serve the built SPA from `frontend/dist`. During development, the backend and Vite frontend usually run separately.

Runtime flow:

```text
Browser
  -> Vue SPA / Vite dev server
  -> FastAPI backend
  -> Dependency-Track API and local DTVP cache
  -> optional tmrescore and code-analysis services
```

### Backend

Important backend entry points:

| File | Role |
| :--- | :--- |
| `dtvp/boot.py` | Default ASGI entry point. Binds early, serves `/startup` and `/api/startup`, then loads `dtvp.main:app`. |
| `dtvp/main.py` | Builds the FastAPI app, middleware, routers, task stores, startup/shutdown hooks, and SPA fallback. |
| `dtvp/app_wiring.py` | Central dependency construction for testable route/service wiring. |
| `dtvp/general_api_routes.py` | Projects, grouped vulnerability tasks, task polling, statistics, assessments, dependency chains. |
| `dtvp/grouped_vuln_services.py` | Concurrent per-version finding, vulnerability, and BOM fetching before grouping. |
| `dtvp/task_group_query_services.py` | Backend filtering, sorting, facets, pagination, and task-window query support. |
| `dtvp/logic.py` | Domain logic for grouping, team mapping, assessment parsing, statistics, CVSS, BOM dependency analysis. |
| `dtvp/assessment_services.py` | Dependency-Track assessment writes, conflict detection, local overlays, result finalization. |
| `dtvp/dt_client.py` | Dependency-Track API client. |
| `dtvp/dt_cache.py` | Local Dependency-Track cache and pending update storage. |
| `dtvp/project_archive_routes.py` and `dtvp/project_archive_services.py` | Project archive export/import, scheduled snapshots, local downloads. |
| `dtvp/settings_routes.py` | Team mapping, roles, and rescore rule APIs. |
| `dtvp/tmrescore_*` | Threat-model rescoring integration, task state, cache, inventory helpers. |
| `dtvp/code_analysis_*` and `dtvp/analysis_queue_*` | Code-analysis integration and queue runtime. |

Grouped vulnerability tasks are list-first by default. `response_mode=summary` avoids downloading heavy per-instance assessment text for list views, task events stream progress through `/api/tasks/{task_id}/events`, and `/api/tasks/{task_id}/groups` serves backend-filtered windows with counts and facets. Full group details stay available through `/api/tasks/{task_id}/groups/{group_id}` and backend-filtered detail windows.

### Frontend

Important frontend entry points:

| File or directory | Role |
| :--- | :--- |
| `frontend/src/main.ts`, `App.vue`, `router.ts` | Vue app shell, routing, startup handling. |
| `frontend/src/lib/api.ts` | Central backend client and frontend integration types. |
| `frontend/src/types.ts` | Shared frontend domain types. |
| `frontend/src/pages/` | Major pages: dashboard, project review, tmrescore, statistics, settings, login. |
| `frontend/src/components/` | Vulnerability rows/details, modals, filters, queue UI, dependency-chain and CVSS components. |
| `frontend/src/lib/` | Composables and helpers for filters, task windows, details, visible rows, assessment updates, project header state, queue state. |

The project vulnerability list renders compact rows from cached `VulnListItem` metadata. Summary task windows keep list payloads light, filtering/sorting can run in the backend, visible rows are viewport-windowed, details hydrate lazily, and grouping progress appears in the filter/status area while the final list shell is already visible.

DTVP has three startup surfaces:

- `/startup` and `/api/startup` from the backend boot wrapper while the real app loads.
- A static first-paint startup screen in `frontend/index.html`.
- A Vue initialization page while backend metadata, project metadata, and session state load.

### Data And Domain Rules

- Team mapping accepts `"component": "Team"` or `"component": ["Primary", "Alias"]`; aliases normalize to the primary team label in most UI paths.
- The wildcard team mapping key `"*"` is the fallback team.
- Assessment details are structured text blocks with headers such as `[Team: ...]`, `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`, `[Rescored: ...]`, `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- A non-`NOT_SET` General block takes precedence in aggregate assessment state; otherwise DTVP chooses the worst team state using the priority in `dtvp/logic.py`.
- Rescored CVSS vectors preserve original base metrics so threat/environment changes do not silently mutate base metrics.
- Dependency relationships and paths come from CycloneDX BOM dependency graphs.
- Dependency-Track attribution timestamps are preserved as `attributed_on` and can be filtered by age in the project view.
- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `FALSE_POSITIVE`, and `NOT_AFFECTED`.

## Key Workflows

### Project Review

The project view groups vulnerabilities by CVE or vulnerability ID across all selected project versions. Reviewers can search, filter by lifecycle and analysis state, inspect dependency paths and team ownership, open a full vulnerability detail panel, and apply synchronized assessments.

Backend task windows keep large projects responsive:

- Summary results seed compact list rows.
- Partial version results appear while grouping continues.
- Assessment and team-mapping writes refresh active task windows.
- Task statistics can be reused when switching to the statistics view.

### Project Archives

Reviewer-only archives preserve or restore project versions, SBOMs, findings, vulnerability details, and normalized assessments.

- Export starts with `POST /api/project-archives/exports`.
- Import preview starts with `POST /api/project-archives/imports`.
- Applying an import uses `POST /api/project-archives/imports/{task_id}/apply` with `mode=create_missing` or `mode=update`.
- Archive schema is `dtvp.project-archive/v1`; newer DTVP versions must keep importing v1.
- Stored archives are listed from `GET /api/project-archives/snapshots`.
- Archive ZIPs default to `data/project_archives`.
- Optional expanded archive trees for Git history default to `data/project_archives_git`.

Restore matching uses project name/version first, then remaps assessments by component purl/name/version/bom-ref and vulnerability ID/name/aliases when Dependency-Track UUIDs change. Dependency-Track audit history and comments are not replayed.

Backend-native bulk preview/apply endpoints remain the main future scale improvement. Today the bulk incomplete modal can use backend-filtered detail windows, but still drains full details into the browser before acting.

### Threat-Model Rescoring

Set `DTVP_TMRESCORE_URL` to enable tmrescore entry points. Users can open a project, choose `Threat Model`, upload a `.tm7` file plus optional `items.csv` or config inputs, and cache proposal snapshots for reviewer rescoring dialogs.

SBOM modes:

- `Latest only`: single-version latest snapshot.
- `Merged multi-version SBOM`: recommended for DTVP, with separate roots per version so historical findings stay visible without pretending they belong to the latest inventory.

DTVP intentionally does not mix latest SBOM components with vulnerabilities found only in older versions.

### Code Analysis

Set `DTVP_CODE_ANALYSIS_URL` to enable reachability/exploitability analysis. Scans run through an in-process queue and include vulnerability ID, target component, CVSS vector, reviewer guidance, and optional dependency context.

Automatic scanning is enabled only when both `DTVP_AUTO_CODE_ANALYSIS_ENABLED=true` and code analysis is configured. DTVP queues genuinely new open groups, not every finding:

- New work: opening or refreshing a project queues newly discovered open grouped vulnerabilities.
- Existing discovery: a sweep checks cached findings and live projects every `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` seconds.
- A group is auto-open only when every grouped instance is `NOT_SET` and has no assessment detail text.
- Groups with any global, team, or legacy plaintext assessment are treated as handled.
- Stale automatic queue items are cancelled when a group becomes handled; manually requested scans are left alone.

## Local Development

### Requirements

- Python 3.14+
- Node.js 22+
- `uv`
- `npm`
- `pm2`
- Docker and Docker Compose for container deployment

### Full Mock Stack

`ecosystem.config.js` starts:

| Service | URL |
| :--- | :--- |
| `mock-dt` | `http://localhost:8081` |
| `mock-tmrescore` | `http://localhost:8090` |
| `mock-code-analysis` | `http://localhost:8095` |
| `dtvp-backend` | `http://localhost:8000` |
| `dtvp-frontend` | `http://localhost:5173` |

Useful pm2 commands:

```bash
pm2 list
pm2 logs
pm2 logs dtvp-backend
pm2 logs dtvp-frontend
pm2 delete mock-dt mock-tmrescore mock-code-analysis dtvp-backend dtvp-frontend
```

### Split Backend And Frontend

Start only mocks:

```bash
pm2 start ecosystem.config.js --only mock-dt,mock-tmrescore,mock-code-analysis
```

Start backend:

```bash
export DTVP_DT_API_URL=http://127.0.0.1:8081
export DTVP_DT_API_KEY=mock_key
export DTVP_OIDC_AUTHORITY=http://127.0.0.1:8081
export DTVP_OIDC_CLIENT_ID=mock_id
export DTVP_OIDC_CLIENT_SECRET=mock_secret
export DTVP_OIDC_REDIRECT_URI=http://localhost:5173/auth/callback
export DTVP_FRONTEND_URL=http://localhost:5173
export DTVP_TMRESCORE_URL=http://127.0.0.1:8090
export DTVP_CODE_ANALYSIS_URL=http://127.0.0.1:8095
export DTVP_VERSION_FETCH_CONCURRENCY=4
uv run uvicorn dtvp.boot:app --reload --host 127.0.0.1 --port 8000
```

To bypass mock OIDC locally:

```bash
export DTVP_DEV_DISABLE_AUTH=true
```

With auth disabled, `/auth/me` resolves to `devuser`, which maps to `REVIEWER` in `data/user_roles.json`.

Start frontend:

```bash
cd frontend
npm run dev
```

Stop mocks:

```bash
pm2 delete mock-dt mock-tmrescore mock-code-analysis
```

## Testing

| Scope | Command |
| :--- | :--- |
| Backend tests | `uv run pytest` |
| Frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Frontend unit tests in Podman | `sh scripts/run-frontend-tests-podman.sh unit` |
| README screenshot capture and manual UI docs flow | `cd frontend && npm run test:ui:docs` |
| Frontend UI tests against local stack | `pm2 start ecosystem.config.js --update-env && cd frontend && npm run test:ui` |
| Frontend UI tests in Podman | `sh scripts/run-frontend-tests-podman.sh ui` |
| Real-stack threat-model manual flow | `pm2 start ecosystem.config.js --update-env && cd frontend && DTVP_E2E_REAL_STACK=true npm run test:ui -- --grep "Threat-Model UI Flow"` |

The README screenshots are generated by `frontend/e2e/capture-readme-screenshots.manual.ts` and written under `docs/screenshots`.

The apply-conflict dialog can be tested manually by editing the same finding from two sessions or by forcing a server-side mock Dependency-Track change before submitting. The saved screenshot is `docs/screenshots/conflict-resolution.png`.

## Docker Deployment

Create and edit the environment file:

```bash
cp .env.dist .env
```

Start the packaged deployment:

```bash
docker compose up -d
```

Compose mounts `./data` into `/app/data`, so mapping files, role files, cache data, tmrescore proposals, and project archives persist across container restarts.

The bundled nginx gateway proxies `/dtvp` to DTVP, `/api` to Dependency-Track, and other paths to the Dependency-Track frontend. `dtvp.boot:app` lets Uvicorn bind before the full app imports and serves startup endpoints until initialization completes. A reverse proxy can still show its own fallback during the tiny window before the process is listening.

### Docker Archive Setup

Manual archive exports work after `DTVP_DT_API_KEY` is configured with permissions to read projects, findings, vulnerabilities, and BOMs. Imports also need BOM upload and vulnerability-analysis update permissions.

Scheduled snapshots:

```env
DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED=true
DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS=86400
DTVP_PROJECT_ARCHIVE_RETENTION_COUNT=30
DTVP_PROJECT_ARCHIVE_INCLUDE=Project A,Project B
```

Git-friendly expanded archive trees:

```env
DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED=true
DTVP_PROJECT_ARCHIVE_EXPANDED_PATH=data/project_archives_git
```

Optional one-shot Git push helper:

```env
DTVP_ARCHIVE_GIT_REMOTE=git@github.com:your-org/dtvp-project-archives.git
DTVP_ARCHIVE_GIT_BRANCH=main
DTVP_ARCHIVE_GIT_AUTHOR_NAME=DTVP Archive Bot
DTVP_ARCHIVE_GIT_AUTHOR_EMAIL=dtvp-archive@example.invalid
```

Expected host files:

```text
./secrets/dtvp_archive_deploy_key
./secrets/known_hosts
```

Push the expanded archive tree:

```bash
docker compose run --rm dtvp-archive-git-push
```

Schedule that command from cron, systemd, CI, or another Compose-aware scheduler if you want automatic Git archival. DTVP writes archive data; Git authentication and pushes intentionally live outside the backend process.

## Configuration Reference

Most values can be set in `.env` for Docker Compose or in the shell for local `uv` runs.

### Dependency-Track And Cache

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | File containing the Dependency-Track API key when `DTVP_DT_API_KEY` is unset | unset |
| `DEPENDENCY_TRACK_URL` | Deployment alias for `DTVP_DT_API_URL` | unset |
| `DEPENDENCY_TRACK_API_KEY` | Deployment alias for `DTVP_DT_API_KEY` | unset |
| `DTVP_DT_CACHE_PATH` | Local Dependency-Track cache and pending update queue | `data/dt_cache` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background cache refresh interval | `60` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Parallel version fetch limit for grouped views and statistics | `4` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | Completed/failed grouped-vulnerability task retention | `3600` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | SQLite summary-index path for repeat summary list loads | sibling of `DTVP_DT_CACHE_PATH` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted summary indexes | `64` |

### Auth, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback URL | derived from frontend URL and context path |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_DEV_DISABLE_AUTH` | Disable OIDC and return `devuser` locally | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | `/` |
| `DTVP_BOOT_APP` | Advanced real ASGI app override for `dtvp.boot` | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Comma-separated extra CORS origins | unset |
| `DTVP_API_URL` | Frontend API base URL override; also available as `VITE_DTVP_API_URL` in Vite | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Project attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in UI | `unknown` |

### Project Archives

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_PROJECT_ARCHIVE_PATH` | Archive ZIPs, import previews, scheduled snapshots | `data/project_archives` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED` | Write stable expanded archive trees for Git history | `false` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_PATH` | Expanded archive tree directory | `data/project_archives_git` |
| `DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED` | Enable scheduled archive snapshots | `false` |
| `DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS` | Scheduled snapshot interval; minimum 60 seconds | `86400` |
| `DTVP_PROJECT_ARCHIVE_RETENTION_COUNT` | Recent archive ZIPs retained per project | `30` |
| `DTVP_PROJECT_ARCHIVE_INCLUDE` | Comma-separated project names for scheduled snapshots | empty |
| `DTVP_ARCHIVE_GIT_REMOTE` | Optional archive Git helper remote | empty |
| `DTVP_ARCHIVE_GIT_BRANCH` | Optional archive Git helper branch | `main` |
| `DTVP_ARCHIVE_GIT_AUTHOR_NAME` | Optional archive Git helper author name | `DTVP Archive Bot` |
| `DTVP_ARCHIVE_GIT_AUTHOR_EMAIL` | Optional archive Git helper author email | `dtvp-archive@example.invalid` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_FILE` | SSH private key path inside Git helper container | `/ssh/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_FILE` | SSH known-hosts path inside Git helper container | `/ssh/known_hosts` |

### Optional Integrations

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_TMRESCORE_URL` | External or mock tmrescore base URL | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | tmrescore HTTP timeout before polling fallback | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Cached per-project tmrescore proposals | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_OLLAMA_MODEL` | Default model for tmrescore LLM enrichment UI | `qwen2.5:7b` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | Completed/failed tmrescore task retention | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | External or mock code-analysis base URL | unset |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | Code-analysis HTTP timeout | `300` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | Completed/failed code-analysis queue item retention | `3600` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Queue scans for newly discovered fully unassessed grouped vulnerabilities | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Sweep interval for cached/live open vulnerability discovery | `900` |

## SBOM

The container image includes a CycloneDX SBOM at `/sbom/dtvp-cyclonedx.json`, generated with `syft` during Docker build. The app exposes it at `/api/sbom` and `/api/sbom/html`, and the footer links "Download CycloneDX SBOM".

The SBOM includes production frontend dependencies from `frontend/package.json` and `frontend/package-lock.json`, plus backend dependencies from `pyproject.toml` and `uv.lock`. Test and development dependencies are excluded by design.

## Screenshots And Docs

| Area | Screenshot |
| :--- | :--- |
| Login | `docs/screenshots/login.png` |
| Dashboard | `docs/screenshots/dashboard.png` |
| Project review | `docs/screenshots/project-view.png` |
| Dependency chains | `docs/screenshots/project-view-dependencies.png` |
| Statistics | `docs/screenshots/statistics.png` |
| Settings | `docs/screenshots/settings.png` |
| Conflict resolution | `docs/screenshots/conflict-resolution.png` |
| Code analysis | `docs/screenshots/code-analysis-result.png` |

Additional docs:

- Integration API surface: `docs/integration-api-surface.md`
- Workflow flowcharts: `docs/workflow-flowcharts.md`
- TMRescore static OpenAPI spec: `openapi/tmrescore-openapi.json`
- Code Analysis static OpenAPI spec: `openapi/code-analysis-openapi.json`

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
