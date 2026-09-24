# Development and Testing

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Toolchain and CI](#toolchain-and-ci)
- [Split Backend And Frontend](#split-backend-and-frontend)
- [Testing Notes](#testing-notes)

## Toolchain and CI

The root pytest configuration uses importlib import mode so `uv run pytest`
can collect the DTVP and nested Agentyzer suites together even when both suites
contain test modules with the same filename.

The CI end-to-end job uses the Playwright container image in
`.github/workflows/build-publish.yml`. Its image tag must exactly match the
resolved `@playwright/test` version in `frontend/package-lock.json`; update both
in the same change. The regular, manual, and real-stack Playwright
configurations cover Chromium, Firefox, and WebKit desktop browsers.
Mocked E2E project fixtures provide lifecycle metadata for non-open groups;
list tests explicitly select the statuses they exercise. Separate browser
coverage verifies reviewer approval-ready defaults, incomplete pending work,
and legacy assessments under Assessed.
The Vitest configuration keeps local TypeScript config imports explicit so it
also loads with Vite's native config loader. It caps the process pool at four
workers so jsdom-heavy component tests do not contend past their per-test
timeouts; validate config changes with
`cd frontend && npx vitest --run --configLoader native`.
Frontend dependencies track stable releases compatible with the build and test
toolchain. The September 2026 refresh uses Vue 3.5.43, Vite 8.3.0, and Vitest
5.0.1. Icons use the maintained `@lucide/vue` package instead of the deprecated
`lucide-vue-next`; component imports and test mocks must use the new package name.
TypeScript stays on 6.0.3: the current `vue-tsc` 3.3.11 loads
`typescript/lib/tsc`, which TypeScript 7's native compiler no longer exports.
Revisit that constraint when Vue's type checker supports the native compiler;
do not bypass Vue component type checking to upgrade TypeScript.
CI uses `setup-uv`'s direct latest-release path, which avoids the remote version
manifest that range resolution requires. `Dockerfile.free-threaded` likewise
uses Astral's moving `alpine` image alias by default; set its `UV_IMAGE` build
argument to a versioned tag or digest when a reproducible external build needs
an explicit override. Pull-request runs cancel superseded workflow executions,
and image publication waits for Python (including Agentyzer), frontend, and
browser tests. Frontend jobs select Node.js 24 and reuse npm's download cache.
The single-platform image builds reuse inline cache metadata from the `dev`
images and exclude CI virtual environments from their build contexts. SBOM
generation is reproducible and consumes frozen dependency state without
rewriting project manifests or lockfiles in CI.
The committed frontend lockfile resolves packages only from the default
`registry.npmjs.org` registry; do not persist private registry or mirror URLs.

## Split Backend And Frontend

The [quick start](../README.md#quick-start) is preferred for normal work. To run processes separately,
start only the mocks:

```bash
pm2 start ecosystem.config.js --only mock-dt,mock-tmrescore,mock-code-analysis
```

Then start the backend:

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
uv run uvicorn dtvp.boot:app --reload --host 127.0.0.1 --port 8000
```

Use `DTVP_DEV_DISABLE_AUTH=true` to make `/auth/me` resolve to local `devuser`,
which maps to `REVIEWER` in `data/user_roles.json`. Start the frontend with
`cd frontend && npm run dev`.

## Testing Notes

Commands are in the [command reference](../README.md#command-reference). README screenshots
come from `frontend/e2e/capture-readme-screenshots.manual.ts`. Real-stack manual
flows use `npm run test:ui:real-stack` with the relevant Playwright grep.

To exercise apply conflicts, edit the same finding in two sessions or change it
through mock Dependency-Track before submitting. The expected dialog is shown
in `docs/screenshots/conflict-resolution.png`.
