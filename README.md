# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings across all versions of a project. It groups vulnerabilities by CVE, surfaces version-by-version differences in one place, and lets teams apply assessments in bulk instead of repeating the same work on every release.

The repository also includes a mock Dependency-Track service, which makes it possible to run the full application locally without a live upstream instance.

Repository links:

- Main repo: https://git.baer.one/phbaer/dtvp/
- GitHub mirror: https://github.com/phbaer/dtvp/

SBOM

- The container includes a CycloneDX SBOM at `/sbom/dtvp-cyclonedx.json`.
- Generated via `syft` (standard SBOM tooling) during Docker image build. 
- The app exposes it at `/api/sbom` and `/api/sbom/html`; footer includes "Download CycloneDX SBOM".
- Includes production frontend (`frontend/package.json`/`frontend/package-lock.json`) and backend (`pyproject.toml`/`uv.lock`) dependency components; test/dev dependencies excluded by design.

## What It Does

- Group the same vulnerability across multiple project versions.
- Show lifecycle states such as open, assessed, incomplete, inconsistent, and needs approval.
- Support global and team-specific assessments.
- Rescore findings with CVSS data and review the aggregated result in the UI.
- Edit team mappings, user roles, and rescore rules from the settings screen.
- Run against either a live Dependency-Track server or the bundled mock service.

## Stack

- Backend: Python 3.13+, FastAPI, Uvicorn, httpx
- Frontend: Vue 3, Vite, Tailwind CSS
- Python package manager: uv
- Frontend package manager: npm
- Local process manager: pm2
- Container runtime: Docker / Docker Compose

## Prerequisites

Install the following first:

- Python 3.13+
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
pm2 logs dtvp-backend
pm2 logs dtvp-frontend
```

Stop and remove the local stack:

```bash
pm2 delete mock-dt dtvp-backend dtvp-frontend
```

## Manual Development Workflow

If you want to iterate on the backend or frontend manually while keeping the mock Dependency-Track service managed by pm2, use this split workflow.

### 1. Start Only The Mock Dependency-Track Service

```bash
pm2 start ecosystem.config.js --only mock-dt
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
uv run uvicorn main:app --reload --host 127.0.0.1 --port 8000
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
pm2 delete mock-dt
```

## Application Walkthrough

The screenshots below were captured from the bundled mock stack started with `pm2 start ecosystem.config.js --update-env`.

### 1. Login

Start at the DTVP login page and hand off to the mock SSO provider.

![DTVP login page](docs/screenshots/login.png)

### 2. Dashboard

The dashboard groups projects by classifier and shows all known versions of a project on a single card. Use the project filter to narrow the list and the global CVE filter to carry a CVE directly into the project view.

![Dashboard with grouped projects](docs/screenshots/dashboard.png)

### 3. Project Vulnerability View

Selecting a project opens the grouped vulnerability view. This is the core workflow: filter by lifecycle and analysis state, inspect team markers, expand a CVE, review the aggregated history, and apply a synchronized assessment.

![Expanded project vulnerability view](docs/screenshots/project-view.png)

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

### Frontend End-To-End Tests

The UI tests expect the local stack to be available.

```bash
pm2 start ecosystem.config.js --update-env
cd frontend
npm run test:ui
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
cp compose.yml.dist compose.yml
docker compose up -d
```

The image mounts `./data` into the container so local mapping and rule files persist.

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Base URL of the Dependency-Track API | `http://localhost:8081` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback URL | derived from frontend URL and context path |
| `DTVP_FRONTEND_URL` | Frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | `/` |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_DEFAULT_PROJECT_FILTER` | Default project filter shown on the dashboard | empty |
| `DTVP_DEV_DISABLE_AUTH` | Disable OIDC and force the backend to return `devuser` locally | `false` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
