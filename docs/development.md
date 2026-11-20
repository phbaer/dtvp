# Development and Testing

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Toolchain and CI](#toolchain-and-ci)
- [Split Backend And Frontend](#split-backend-and-frontend)
- [Testing Notes](#testing-notes)

## Toolchain and CI

DTVP requires Python 3.14 or newer. Its development dependencies do not install
Agentyzer or its LangGraph stack; code analysis is an external HTTP integration.
Use `uv sync --python 3.15 --dev --frozen` to select Python 3.15 explicitly.
Use a released Python version; early 3.15 alphas may lack APIs expected by
current dependencies. If a Pydantic wheel is unavailable for the interpreter,
the locked `pydantic-core` source build requires Rust 1.88 or newer.
Local `.python-version` preferences are ignored by Git. Docker images currently
use Python 3.14.

The root pytest configuration uses importlib import mode and collects only
`tests/`. Agentyzer lives in its own repository and is not part of this
checkout.

The CI end-to-end job uses the Playwright container image in
`.github/workflows/build-publish.yml`. Its image tag must exactly match the
resolved `@playwright/test` version in `frontend/package-lock.json`; update both
in the same change. The regular, manual, and real-stack Playwright
configurations cover Chromium, Firefox, and WebKit desktop browsers.
With `CI` set, the regular configuration builds the frontend and serves it
with `vite preview` instead of the dev server, which exhausted runner memory;
local runs keep using (and reusing) the dev server on port 5173. If another
project already uses that port, set `DTVP_E2E_PORT` to a free one; otherwise
the tests run against the wrong application.

Each test job appends a Markdown job summary through `scripts/ci-summary.mjs`:
pass/fail totals, failing or flaky tests with their first error, coverage
totals, and runner resources (memory, swap, container limit, and OOM-kill
count). Summaries are displayed by Forgejo 17 with Forgejo Runner 13.2 or
newer; on older versions the same Markdown is printed to the step log. JUnit
XML, the Playwright JSON report, traces, and HTML reports are uploaded as
artifacts. The script only reads reports, and a missing report is noted in the
summary rather than failing the job. Jobs that need `git`, `curl`, `jq`,
Buildah, or the `libatomic1` library that Node.js 26 links install them, so the runner image only has to provide Node.js and `apt`; see
[Deployment](deployment.md#python-runtime-images) for the image build's runner
requirements.
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
toolchain. The November 2026 refresh uses Vue 3.5.45, Vite 8.3.8, Vitest 5.1.0,
and jsdom 31. Icons use the maintained `@lucide/vue` package instead of the deprecated
`lucide-vue-next`; component imports and test mocks must use the new package name.
TypeScript stays on 6.0.3: the current `vue-tsc` 3.3.14 loads
`typescript/lib/tsc`, which TypeScript 7's native compiler no longer exports.
Do not bypass Vue component type checking to upgrade TypeScript, and do not
take the TypeScript 7 bump in routine dependency updates.
Support is planned for TypeScript 7.1 through Vue Language Tools v4, which
replaces `vue-tsc` with `tsc --runExternalCode` and a `contentMappers` entry for
`@vue/content-mapper` in `tsconfig.app.json`
([tracking issue](https://github.com/vuejs/language-tools/issues/5381),
[v4 pull request](https://github.com/vuejs/language-tools/pull/6170)).
A trial on 2026-11-17 with `typescript@7.1.0-beta` and
`@vue/content-mapper@4.0.0-alpha.3` built and passed the unit tests, but the
type check reported 240 errors where `vue-tsc` reports none: about 225 from an
alpha bug with bound `data-*` attributes on native elements
([#6355](https://github.com/vuejs/language-tools/issues/6355), fixed after
alpha.3), about 14 from attributes such as `data-testid`, `id`, and `title`
passed to components that do not declare them, which v4 rejects by design, and
one suspected false positive in a `v-if`/`v-else` chain. Installing the
prereleases also required `--legacy-peer-deps`. Revisit once TypeScript 7.1 is
stable and `@vue/content-mapper` has left alpha.
CI uses `setup-uv`'s direct latest-release path, which avoids the remote version
manifest that range resolution requires. `Dockerfile.free-threaded` likewise
uses Astral's moving `alpine` image alias by default; set its `UV_IMAGE` build
argument to a versioned tag or digest when a reproducible external build needs
an explicit override. Pull-request runs cancel superseded workflow executions,
and image publication waits for DTVP Python, frontend, and
browser tests. Frontend jobs select Node.js 26 and reuse npm's download cache.
The single-platform image builds reuse inline cache metadata from the `dev`
images and exclude CI virtual environments from their build contexts. SBOM
generation is reproducible and consumes frozen dependency state without
rewriting project manifests or lockfiles in CI.
The committed frontend lockfile resolves packages only from the default
`registry.npmjs.org` registry; do not persist private registry or mirror URLs.

Forgejo passes no secrets to pull requests from forks or to pull requests
created by pushing to `refs/for/<branch>`. For those, the image job still
builds the image as a check but does not publish it, and says so in a
warning. Open the pull request from a branch of this repository to get a
`pr-<number>` test image.

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
`frontend/e2e/event-stream.spec.ts` opens three tabs against a mocked backend
and checks that one tab holds the live-update stream and another takes over
when it closes; run it alone with
`DTVP_E2E_PORT=<free port> npm run test:ui -- event-stream.spec.ts`.

To exercise apply conflicts, edit the same finding in two sessions or change it
through mock Dependency-Track before submitting. The expected dialog is shown
in `docs/screenshots/conflict-resolution.png`.
