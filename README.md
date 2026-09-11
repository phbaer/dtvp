# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings
across project versions. It groups vulnerabilities, tracks team assessments,
and applies consistent decisions across releases.

[Main repository](https://git.baer.one/phbaer/dtvp/) ·
[GitHub mirror](https://github.com/phbaer/dtvp/)

- Team and global assessments, CVSS rescoring, SSVC prioritization, and exploitation evidence.
- Bulk assessment repair, audit-backed recovery, and project archive import/export.
- Optional threat-model rescoring through tmrescore/vscorer and code analysis through Agentyzer.
- Mock services for local development and testing.

[Quick start](#quick-start) · [Deployment](#docker-deployment) ·
[Commands](#command-reference) · [Review workflow](#review-workflow) ·
[Architecture](#repository-and-architecture) · [Documentation](#documentation)

## Quick Start

Requirements: Python 3.14+, `uv`, `npm`, `pm2`, and Node.js 24 LTS (24.15+)
or a newer supported Node.js release.

```bash
uv sync --dev
cd frontend
npm ci --include=optional
cd ..
pm2 start ecosystem.config.js --update-env
```

| Service | URL |
| :--- | :--- |
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000/api/version |
| Mock Dependency-Track | http://localhost:8081 |
| Mock tmrescore | http://localhost:8090/ui |
| Mock code analysis | http://localhost:8095 |

Open `/login`, choose **Sign in with SSO**, then **Login as Reviewer** on the
mock Dependency-Track page. Inspect services with `pm2 list` or `pm2 logs`.
Stop the stack with:

```bash
pm2 delete mock-dt mock-tmrescore mock-code-analysis dtvp-backend dtvp-frontend
```

For separate backend/frontend processes and authentication overrides, see
[Development and testing](docs/development.md).

## Docker Deployment

```bash
cp .env.dist .env
# Configure .env before starting services.
docker compose up -d
```

Set the Dependency-Track API URL/key, public frontend URL, OIDC settings, and a
strong `DTVP_SESSION_SECRET_KEY`. Compose serves DTVP under `/dtvp` by default;
`DTVP_HTTP_PORT` controls the host port. Persistent data lives in `./data`.

The published DTVP image uses Python 3.14 free threading. Compose also starts
Agentyzer; its source, image, and release are maintained in the sibling
`../agentyzer` repository. Configure its repository mappings before enabling
automatic scans. See [Deployment](docs/deployment.md) for networking, authentication, runtime
checks, and release details, and [Configuration](docs/configuration.md) for
all environment variables.

## Command Reference

Use `uv` from the repository root for Python/backend work and `npm` from
`frontend/` for frontend work.

| Task | Command |
| :--- | :--- |
| Run DTVP Python tests | `uv run pytest` |
| Run Agentyzer tests | `cd ../agentyzer && uv run pytest` |
| Run frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Run focused frontend tests | `cd frontend && npm run test:unit -- --run ProjectView` |
| Build the frontend | `cd frontend && npm run build` |
| Run browser tests | `cd frontend && npm run test:ui` |
| Run manual real-stack tests | `cd frontend && npm run test:ui:real-stack` |
| Capture documentation screenshots | `cd frontend && npm run test:ui:docs -- --project=chromium` |
| Benchmark grouped queries | `uv run python scripts/benchmark_group_queries.py` |

Browser tests cover Chromium, Firefox, and WebKit. CI's Playwright image must
match the version in `frontend/package-lock.json`. See
[Development and testing](docs/development.md) for test fixtures, toolchain
constraints, and CI conventions.

## Review Workflow

1. Open a project to review vulnerabilities across its versions.
2. Filter by lifecycle, team, component, version, or evidence; open a finding
   for context and assessment details.
3. Record team assessments, optionally using earlier team assessments,
   threat-model or code-analysis proposals. Reviewers approve global decisions
   and adjust CVSS scores.
4. Use **Bulk Changes** for repeated updates, repairs, or team takeovers
   scoped to mapped owner components; use archives to export and restore project data.

| Lifecycle | Meaning |
| :--- | :--- |
| **Open** | No assessment started |
| **Incomplete** | Required team or finding coverage is missing |
| **Conflicting** | Assessment data disagrees or needs repair |
| **Ready for approval** | Complete, consistent assessments await reviewer sign-off |
| **Assessed** | Complete with no pending approval; includes legacy assessments |

Analysts start with the **Analyst work** view (Open and Incomplete, including
Conflicting); reviewers start with **All statuses** and can use **Approval queue**
for ready findings. Untouched defaults follow role changes; custom status choices
stay selected. Conflicting findings retain their badge and require repair before
approval.

Select one or more **Teams** to enable **Assessment for selected teams**:
**Not recorded** finds a missing assessment among responsible selected teams;
**Recorded** requires all responsible selected teams to have an assessment
(including pending approval); **Any** adds no restriction. Analysts start with
Not recorded when selecting their first team; reviewers start with Any.
Clearing teams removes this restriction. Status choices remain unchanged.

Plain search still matches team names, without selecting teams. `team:` tokens
resolve to visible team selections; ambiguous matches require a choice.
Filters combine with AND across categories and OR within a category. Option
counts exclude their own category; result totals and bulk actions include all
filters. Specialist controls live under **More filters**. Selections persist in
shared URLs; Reset clears filters. Legacy assessments retain a **Legacy** badge.

Team mapping accepts `group:name` and scoped `group/name` keys. A mapped
component takes precedence over its mapped ancestors, even across alternate
dependency paths; independent owners can both appear. The backend's
resolved finding tags drive the list and detail views. Mapping edits rerun the
project query so both views use the same ownership.

See [Assessment model](docs/assessment-model.md) for exact state, ownership,
SSVC, and evidence rules; [Review workflows](docs/review-workflows.md) for
filtering, editing, bulk operations, and archives; or the
[screen guide](docs/screens.md) for UI examples.

## Repository And Architecture

```text
Browser → Vue SPA → FastAPI → Dependency-Track + local cache/outbox
                           → optional tmrescore and code-analysis services
```

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | Backend routes, domain logic, integrations, and migrations |
| `frontend/` | Vue pages, components, API client, and browser tests |
| `../agentyzer/` | Standalone code-analysis service and assessment pipeline |
| `test_setup/` | Mock Dependency-Track, tmrescore, and code-analysis services |
| `tests/` | Backend tests |
| `data/` | Local mappings, rules, caches, and archives |
| `openapi/` | Integration API specifications |
| `docs/` | Detailed guides, references, diagrams, and screenshots |
| `skills/` | Agent entry points that route back to this README |

Grouped tasks serve filtered summary windows and hydrate full details on demand.
Assessment saves commit to a local SQLite outbox before background synchronization
with Dependency-Track. Task registries are process-local: the supplied deployment
uses one backend worker; horizontal scaling requires shared task storage.

[Runtime and capacity](docs/runtime.md) documents the key modules, caching,
concurrency, access boundaries, benchmarks, and sizing guidance.

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Assessment model](docs/assessment-model.md) | Lifecycle rules, team ownership, SSVC, original severity, and official evidence |
| [Review workflows](docs/review-workflows.md) | Search, filters, assessments, bulk changes, and project archives |
| [Analysis integrations](docs/analysis-integrations.md) | Threat-model rescoring, code analysis, follow-ups, and automatic scanning |
| [Runtime and capacity](docs/runtime.md) | Module map, background tasks, caching, concurrency, and benchmarks |
| [Development and testing](docs/development.md) | Separate processes, test guidance, toolchain constraints, and CI |
| [Deployment](docs/deployment.md) | Docker, networking, OIDC, persistent data, and Python runtime images |
| [Configuration](docs/configuration.md) | Environment variables and defaults |
| [Screen guide](docs/screens.md) | UI walkthrough and screenshots |
| [Workflow diagrams](docs/workflow-flowcharts.md) | Visual workflow reference |
| [Integration API](docs/integration-api-surface.md) | Integration endpoints and contracts |

OpenAPI specifications: [tmrescore](openapi/tmrescore-openapi.json) and
[code analysis](openapi/code-analysis-openapi.json).

This README is the canonical project overview and documentation entry point for
humans and AI agents. Keep it brief; put detailed behavior and configuration in
the linked guides. Meaningful behavior, architecture, API, integration,
configuration, workflow, command, or structure changes must update this overview
or its guide links in the same change, together with the relevant reference.
If documentation conflicts with source, tests, configuration, or lockfiles,
trust the source and update the documentation. Keep `AGENTS.md` and agent skills
as routing hints; the generic entry point is `skills/project-entrypoint/SKILL.md`
(`skills/dtvp-project-memory/SKILL.md` is the compatibility entry point).

## License And SBOM

[MIT License](LICENSE). The DTVP image includes CycloneDX frontend/backend SBOMs,
served at `/api/sbom` and `/api/sbom/html`. Agentyzer publishes its own SBOM
from its standalone repository.
