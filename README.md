# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings
across every version of a project. It groups findings by vulnerability, exposes
version-by-version assessment state, and lets reviewers apply consistent
changes without repeating the same work for every release.

- [Main repository](https://git.baer.one/phbaer/dtvp/)
- [GitHub mirror](https://github.com/phbaer/dtvp/)

This README is the canonical project overview for humans and AI agents. If it
conflicts with source, tests, package metadata, lockfiles, or runtime
configuration, trust those sources and update this file. Keep `AGENTS.md`,
Copilot instructions, and `skills/*/SKILL.md` as short entry points back here.

## What DTVP Does

- Groups the same vulnerability across project versions and components.
- Distinguishes open, assessed, incomplete, inconsistent, and approval-needed
  lifecycle states.
- Supports global and team-specific assessments, CVSS rescoring, bulk repair,
  and audit-backed recovery of lost rescoring metadata.
- Optionally integrates threat-model rescoring through tmrescore/vscorer.
- Optionally runs reachability and exploitability analysis through Agentyzer or
  another compatible code-analysis service.
- Exports and imports versioned project archives for restore, replacement, and
  retention workflows.
- Includes mock Dependency-Track, tmrescore, and code-analysis services for
  local development and tests.

## Quick Start

Requirements: Python 3.14+, Node.js 22+, `uv`, `npm`, and `pm2`. Docker and
Docker Compose are needed only for the packaged deployment.

```bash
uv sync --dev
cd frontend
npm ci --include=optional
cd ..
pm2 start ecosystem.config.js --update-env
```

| Service | URL |
| :--- | :--- |
| Frontend | `http://localhost:5173` |
| Backend API | `http://localhost:8000/api/version` |
| Mock Dependency-Track | `http://localhost:8081` |
| Mock tmrescore | `http://localhost:8090/ui` |
| Mock code analysis | `http://localhost:8095` |

For mock login, open `/login`, choose `Sign in with SSO`, then select
`Login as Reviewer` on the mock Dependency-Track page. The mock provider uses
the same state, nonce, PKCE, JWKS, and signed-ID-token validation path as a real
OIDC provider.

Stop the stack with:

```bash
pm2 delete mock-dt mock-tmrescore mock-code-analysis dtvp-backend dtvp-frontend
```

## Command Reference

Use `uv` from the repository root for Python/backend work and `npm` from
`frontend/` for frontend work.

| Task | Command |
| :--- | :--- |
| Install backend dependencies | `uv sync --dev` |
| Install frontend dependencies | `cd frontend && npm ci --include=optional` |
| Start the full mock stack | `pm2 start ecosystem.config.js --update-env` |
| Inspect or tail the stack | `pm2 list` / `pm2 logs` |
| Run all Python tests, including Agentyzer | `uv run pytest` |
| Run Agentyzer tests only | `cd agentyzer && uv run pytest` |
| Run frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Run focused frontend tests | `cd frontend && npm run test:unit -- ProjectView` |
| Build the frontend | `cd frontend && npm run build` |
| Run local-stack UI tests | `cd frontend && npm run test:ui` |
| Capture README screenshots | `cd frontend && npm run test:ui:docs` |
| Start the packaged deployment | `cp .env.dist .env && docker compose up -d` |

The CI end-to-end job uses the Playwright container image in
`.github/workflows/build-publish.yml`. When upgrading `@playwright/test`, update
that image tag in the same change.

## Repository And Architecture

### Repository Map

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | FastAPI routes, services, domain logic, runtime wiring, and integrations |
| `agentyzer/` | Bundled code-analysis service and assessment pipeline |
| `frontend/` | Vue 3, Vite, and Tailwind single-page application |
| `test_setup/` | Mock Dependency-Track, tmrescore, and code-analysis services |
| `tests/` | Backend pytest suite |
| `data/` | Local configuration, cache data, mappings, rules, and archives |
| `dtvp/migrations/` | Numbered SQLite migrations for local stores |
| `openapi/` | Static OpenAPI specs for optional integrations |
| `docs/` | Integration notes, diagrams, screen guide, and generated screenshots |
| `skills/` | Project-local AI entry points that route back to this README |

The generic project skill is `skills/project-entrypoint/SKILL.md`;
`skills/dtvp-project-memory/SKILL.md` is the compatibility entry point.

### Runtime Shape

```text
Browser
  -> Vue SPA (Vite in development, FastAPI/nginx in production)
  -> FastAPI backend
  -> Dependency-Track API + local cache
  -> optional tmrescore and code-analysis services
```

Important backend components:

| Component | Role |
| :--- | :--- |
| `dtvp/boot.py` | Binds early, serves startup status, then loads the real ASGI app |
| `dtvp/main.py` and `app_wiring.py` | App lifecycle, middleware, dependency construction, routers, and task stores |
| `dtvp/auth.py` and `authorization.py` | OIDC/session principals, role normalization, and reusable reviewer/owner policies |
| `dtvp/general_api_routes.py` | Projects, grouped tasks, task windows, statistics, assessments, and dependency chains |
| `dtvp/grouped_vuln_services.py` | Concurrent finding, vulnerability, and BOM collection before grouping |
| `dtvp/task_group_query_services.py` | Backend filtering, sorting, facets, pagination, and task-window queries |
| `dtvp/logic.py` | Grouping, ownership, assessment parsing, CVSS, statistics, and dependency analysis |
| `dtvp/assessment_*` and `rescore_rule_services.py` | Assessment writes, conflict handling, metadata recovery, and CVSS rules |
| `dtvp/bulk_workflows/` | Registry-backed bulk-change plug-ins |
| `dtvp/dt_client.py` and `dt_cache.py` | Dependency-Track access, cached data, overlays, and pending writes |
| `dtvp/project_archive_*` | Project archive export/import and scheduled snapshots |
| `dtvp/tmrescore_*` | Threat-model integration, inventory, cache, execution, and task state |
| `dtvp/code_analysis_*` and `analysis_queue_*` | Analyzer integration, result store, queue, and automatic scans |

Important frontend components:

| Component | Role |
| :--- | :--- |
| `frontend/src/main.ts`, `App.vue`, `router.ts` | App shell, routing, authentication, and startup handling |
| `frontend/src/lib/api.ts` and `types.ts` | Backend client and shared integration/domain types |
| `frontend/src/pages/` | Dashboard, project review, statistics, settings, tmrescore, and code analysis |
| `frontend/src/components/` | Vulnerability rows/details, filters, dialogs, queue UI, CVSS, and dependency paths |
| `frontend/src/lib/` | Filter/task-window models, composables, caching, updates, and project state |

### Runtime Behavior

- Grouped-vulnerability tasks use `response_mode=summary` for compact list
  rows. `/api/tasks/{task_id}/events` streams progress,
  `/api/tasks/{task_id}/groups` serves filtered windows and facets, and
  `/api/tasks/{task_id}/groups/{group_id}` hydrates full details.
- Partial version results appear while grouping continues. CPU-heavy grouping,
  indexing, and filtering run outside the async event loop. When the final
  partial publish already contains every version, it becomes the completed
  snapshot without repeating grouping and index construction.
- Grouped-task searches use thread-safe per-task query caches, share identical
  in-flight queries, and reuse sort orders across filter changes. Lightweight
  code-assessment metadata is cached and invalidated when analyzer results
  change.
- The frontend viewport-windows list rows, coalesces partial refreshes, and
  hydrates dependency paths and full assessment details only when needed.
- The local cache under `DTVP_DT_CACHE_PATH` stores projects, findings,
  vulnerability details, BOMs, local overlays, and pending writes. Stale cached
  data remains readable while Dependency-Track is unavailable. Concurrent
  misses for the same resource share one Dependency-Track request, while each
  caller receives an isolated mutable snapshot.
- Grouped-vulnerability tasks, their bulk-workflow operations, uploaded or
  generated archive tasks, live tmrescore sessions, analyzer queue entries,
  and saved analysis results are private to the authenticated user who created
  them. Reviewers can inspect and manage analyzer work across users. Shared
  Dependency-Track assessments and cached project proposal snapshots remain
  collaborative application data.
- Authorization fails closed: a missing, unreadable, invalid, or incomplete
  `USER_ROLES_PATH` mapping assigns `ANALYST`. Only an explicit `REVIEWER`
  value grants reviewer permissions. Role-file uploads reject unknown roles.
  TMRescore, archive management, global code-analysis controls, bulk queue
  controls, and settings changes enforce reviewer permissions in the backend;
  frontend visibility is not treated as an authorization boundary.
- Live task registries are process-local; the supplied Uvicorn/PM2 launch uses
  one backend worker. A horizontally scaled deployment needs a shared task and
  result store before enabling multiple backend workers.
- Startup status exists at `/startup` and `/api/startup`, in the static first
  paint, and in the Vue initialization view.

### Capacity Planning

The current single-process deployment should be planned for roughly 8-12
simultaneously active users on very large projects, or 30-50 active users on
medium projects. Mostly idle or dashboard users are substantially cheaper;
100-300 concurrent sessions is a reasonable starting estimate when they are
not all retaining large grouped-vulnerability tasks.

These are sizing estimates, not production guarantees. A synthetic benchmark
on a 20-CPU, 15 GiB host with the Python GIL enabled measured eight concurrent
cold searches as follows:

| Grouped vulnerabilities | Throughput | p95 search latency |
| :--- | ---: | ---: |
| 1,000 | about 730 queries/second | 1.3 ms |
| 5,000 | about 176 queries/second | 50 ms |
| 10,000 | about 99 queries/second | 96 ms |
| 20,000 | about 25-40 queries/second | 260-470 ms |

At 16 simultaneous cold searches over 20,000 groups, p95 latency approached
one second. An identical cached search took about 0.07 ms, so new search terms
and filter combinations are the limiting case rather than pagination or repeat
requests.

A synthetic 20,000-group summary and query index retained about 78 MB of live
Python allocations and increased initial process RSS by about 175 MB. Real
tasks also retain full vulnerability, component, dependency, and BOM details;
budget roughly 150-300 MB or more for each large retained task. The default
one-hour `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` therefore makes memory, rather
than request throughput, the likely limit when many users open large projects.

For conservative per-instance planning:

- large projects with active searching: 8-12 users comfortably; around 20 is
  likely to show latency or memory pressure;
- medium projects: 30-50 active users;
- mostly browsing or dashboard use: 100-300 sessions, assuming few retained
  large tasks;
- code-analysis jobs: one runs concurrently by default through
  `DTVP_ANALYSIS_QUEUE_CAPACITY`; additional jobs wait in the shared queue.

Before increasing those ranges, use production-shaped load tests. The first
scaling steps are reducing grouped-task retention (for example, to 900
seconds), increasing the frontend search debounce, and introducing a shared
task/result store so multiple backend processes can use additional CPU cores.

## Domain Model

### Vulnerabilities And Assessments

A grouped vulnerability joins equivalent IDs and aliases across versions. Its
aggregate state follows these rules:

- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`,
  `FALSE_POSITIVE`, and `NOT_AFFECTED`.
- A non-`NOT_SET` General assessment takes precedence; otherwise DTVP chooses
  the worst team state using the priority in `dtvp/logic.py`.
- Inconsistency reasons are indexed separately: missing rescoring metadata,
  differing analysis states, differing structured team blocks, and differing
  substantive details. Selected reasons use OR semantics; filter categories
  combine with AND semantics.
- Assessment details use structured blocks such as `[Team: ...]`,
  `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`,
  `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Structured details retain at most one block per team (case-insensitive).
  Team assessments are not copied into the General block, and generated
  General summaries from older sync operations are removed on the next sync.
- Dependency paths come from CycloneDX BOM dependency graphs. Dependency-Track
  attribution timestamps are retained as `attributed_on`.

CVSS rescoring is data-driven through `RESCORE_RULES_PATH` (default
`data/rescore_rules.json`). The shipped `NOT_AFFECTED` and `FALSE_POSITIVE`
transitions support CVSS 2.0, 3.0, 3.1, and 4.0 and produce exactly `0.0`.
Vectors preserve their original CVSS version and base metrics. Cross-version,
malformed, or incomplete vectors stay visible for manual review rather than
being rewritten speculatively.

### Team Mapping And Analyzer Guidance

`TEAM_MAPPING_PATH` defaults to `data/team_mapping.json` and is editable in
Settings. Keys are deterministic CycloneDX component selectors:

| Selector | Match |
| :--- | :--- |
| `name` | Ungrouped or name-only component, case-insensitive |
| `group:name` | Group and name, case-insensitive |
| `purl::pkg:type/namespace/name` | PURL; version/qualifiers/subpath are ignored unless explicitly supplied |
| `cs::name`, `cs::group:name` | Case-sensitive name or group/name |
| `cs,purl::...` | Case-sensitive PURL |
| `nogroup::name` | Only components known to have no group |
| `cs,nogroup::name` | Case-sensitive no-group match |
| `*` | Fallback team; never creates an automatic scan target |

Single-colon keys such as `cs:name` are ordinary `group:name` selectors;
modifiers require `::`. Precedence is PURL, grouped, no-group, plain name,
case-sensitive specificity, exact case, then lexical key order. Mapping does
not otherwise match BOM refs, Dependency-Track UUIDs, or component versions.

Values are either a primary team string or an array whose first entry is the
primary label and remaining entries are historical aliases.

Analyzer guidance comes from `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` (default
`data/auto_analysis_guidance.json`) and uses the same selectors:

```json
{
  "components": {
    "component-name": "extra reviewer context"
  }
}
```

Values may be strings, arrays, or objects with `guidance`/`prompt`. Optional
`default` or `*` content is prepended. Guidance matches the selected owned scan
target, applies without restart, and is context only: it cannot establish
dependency presence, version, reachability, or affectedness without evidence.
A changed guidance fingerprint makes an automatic result eligible for rescanning.

## Workflows

### Project Review

The project view searches and filters grouped vulnerabilities by lifecycle,
inconsistency reason, analysis state, dependency relationship, component,
version, team, assignee, attribution age, tmrescore proposal, CVSS mismatch,
and code-assessment availability. The Open selection matches the displayed
`OPEN` lifecycle category, and vulnerability-ID searches are combined with all
active filters.

The Filters sidebar provides a searchable, alphabetically sorted Team dropdown
from the complete task facet list. Selecting a team uses a case-insensitive
exact name match; `team:` smart-search tokens remain available for free-form
team searches. The top search result count is the final number of grouped
vulnerabilities after every active filter, independent of how many paginated
rows are currently loaded. When filters reduce the task, it is shown relative
to the unfiltered task total. Every filter-chip count and the Team open/assessed
breakdown is calculated from that same final filtered result. Complete
task-wide facets remain available as filter choices even when their current
filtered count is zero. Overlapping properties such as teams and inconsistency
reasons can therefore have counts whose sum exceeds the final result count.

The detail workspace provides:

| Tab | Purpose |
| :--- | :--- |
| Overview | Advisory, references, affected components, ownership, and dependency context |
| CVSS & Rescoring | Original/rescored vectors, calculator, tmrescore, and analyzer CVSS notes |
| Assessments | Current Dependency-Track assessment blocks |
| Code Analysis | Target selection, queue/history, verdict, evidence, draft, ticket, and artifacts |
| Review | Global/team assessment editor and reviewer context |
| Team Mapping | Reviewer-only ownership editor |

Local drafts survive tab changes. Closing or switching a vulnerability prompts
the reviewer to apply, discard, or keep editing. Assessment writes refresh the
active task window, and route state preserves filters when navigating to
statistics or code analysis. Each vulnerability card can reload its current
assessment directly from Dependency-Track; the refreshed task snapshot updates
the card, lifecycle filters, and counts together.
Vulnerability headers always show whether a tmrescore/vscorer analysis is
available for that vulnerability.

### Bulk Changes

The reviewer-only `Bulk Changes` dialog runs one plug-in workflow at a time:

| Workflow | Candidates and action |
| :--- | :--- |
| Apply Automatic Assessments | Usable, unapplied analyzer assessments; applies the vulnerability-level overall verdict |
| Sync Incomplete Assessments | Groups whose otherwise consistent assessment is missing from some findings |
| Restore Rescored CVSS | Assessed findings with one unambiguous current vector recoverable from audit comments |
| Sync CVSS Rules | Findings whose rescored vector does not comply with configured transition rules |

`Sync CVSS Rules` preview rows show the original stored vector and score beside
the fixed vector and score that will be written.

Every candidate set is the intersection of all active project-list filters and
the selected workflow's applicability rules. The dialog loads plug-in metadata
first and prepares only the chosen preview. Preview tokens prevent applying a
stale candidate set; prepared previews are reused while the dialog is open.
Filtering uses compact task summaries, then carries their canonical lifecycle
metadata onto the hydrated full groups used by workflows. This keeps lifecycle-
specific workflows such as `Sync Incomplete Assessments` aligned with the
visible filtered list.

The UI starts preview, apply, and document work as background operations and
polls their short status endpoint. The operation survives the initiating HTTP
request, so reverse-proxy request timeouts do not cancel long bulk changes.
Apply operations use a bounded worker pool for Dependency-Track writes, retry
transient timeouts, rate limits, and gateway/server errors, and expose
item-level progress through the task status. Failed writes are persisted to the
local pending-update queue in one batch and retried by the cache synchronizer;
local cache overlays are also written in small yielding batches so large
updates do not stall status polling or unrelated API requests.
Endpoints are:

- `POST /api/bulk-workflows/summary`
- `POST /api/bulk-workflows/{workflow_id}/{preview|apply|document}-task`
- `GET /api/bulk-workflows/tasks/{operation_id}` returns progress and the final result

The synchronous `preview`, `apply`, and optional `document` endpoints remain
available for API compatibility.

Automatic-assessment discovery accepts current, reviewer-started, and
source-less legacy records when an assessment can be extracted. Benchmark and
explicitly non-final records are excluded. Matching uses vulnerability ID or
alias plus project context; it does not rely on stale client IDs.

Rows label assessment coverage as:

- `auto`: complete automatic coverage.
- `manual`: complete reviewer-started coverage.
- `mixed`: both automatic and reviewer-started coverage.
- `partial`: one or more grouped components have no code assessment.

The result store maintains dedicated assessment metadata for every saved run.
Task windows expose `code_assessment_status` and calculate filter counts from
that server-side property; the browser does not download result payloads or
assemble a parallel ID filter. Existing stores backfill metadata once through
the numbered SQLite migration path.

For apply, all relevant analyzer runs are combined using the most severe
overall verdict: Affected becomes `EXPLOITABLE`; Probably Affected and Uncertain
become `IN_TRIAGE`; Not Affected becomes `NOT_AFFECTED`. Applied details retain
every relevant run, the analyzer-generated summary and rationale verbatim, and
all decision-relevant advisory conclusions, version notes, research findings,
remediation recommendations, audit checks, and CVSS reasons without arbitrary
character or item limits. Assessment details use sectioned prose and bullets;
raw scan inventories, process prompts, and the analyzer's generated report are
not copied into the rationale when their conclusions are already represented
semantically. Ticket drafts remain separate from assessment details.
Application provenance prevents
successfully applied or queued run/finding pairs from being offered again.
Previews use only compact metadata; apply and document export hydrate full
payloads for the selected groups. Findings are identified by their finding UUID
when present, otherwise by project, component, and vulnerability UUIDs.

### Project Archives

Reviewer-only archives preserve project versions, SBOMs, findings,
vulnerability details, and normalized assessments.

- Export: `POST /api/project-archives/exports`
- Import preview: `POST /api/project-archives/imports`
- Apply: `POST /api/project-archives/imports/{task_id}/apply` with
  `create_missing` or `update`
- Stored snapshots: `GET /api/project-archives/snapshots`
- Schema: `dtvp.project-archive/v1`

Restore matches project name/version first, then remaps changed UUIDs by
component PURL/name/version/BOM ref and vulnerability ID/name/aliases. Audit
history and comments are not replayed. ZIPs default to `data/project_archives`;
optional Git-friendly expanded trees default to `data/project_archives_git`.

### Threat-Model Rescoring

Set `DTVP_TMRESCORE_URL` to enable the project `Threat Model` workspace. Users
can upload a `.tm7` model and optional `items.csv`, analysis configuration, or
MITRE countermeasures, then cache proposal snapshots for reviewer dialogs.

The integration supports vscorer's session/inventory contract, normalized
step-based progress, chain/prioritization/what-if analysis, MITRE enrichment,
offline mode, provider-neutral LLM enrichment, and output download maps. A
`skeptic_gate_failed` response is terminal and requires manual review.
DTVP submits inventory runs with vscorer's background-analysis contract and
polls the session progress/result endpoints, so long NVD-enriched analyses are
not tied to one HTTP response or cancelled by a caller/proxy disconnect. It
retains the blocking-call timeout and gateway fallback for older vscorer
deployments and reads the persisted result error when a background run fails.

SBOM modes are latest-only or merged multi-version. The merged mode keeps a
separate root per version so historical findings remain visible without being
misrepresented as current inventory.

### Code Analysis

Set `DTVP_CODE_ANALYSIS_URL` to enable reachability/exploitability analysis.
DTVP queues requests containing the vulnerability, selected owned target, CVSS
vector, affected product versions, dependency context, reviewer/static
guidance, optional tmrescore context, and optional LLM metadata.

Final results pass through a deterministic claim audit that aligns verdict and
reasoning, flags unsupported claims or downgrades, and restores original CVSS
when a downgrade is rejected. Version presence alone is capped at Probably
Affected unless reachability, exploitability, or a positive transitive path is
confirmed. Static guidance is never evidence by itself.

#### Results, Dedupe, And Follow-Ups

Completed results are stored in SQLite at `DTVP_CODE_ANALYSIS_RESULTS_PATH`.
The store retains full payloads separately from lightweight assessment metadata,
plus run/job IDs, parent links, model metadata, target context, and application
provenance. Numbered migrations live in `dtvp/migrations/code_analysis_results`;
a legacy sibling JSON cache imports on first use.

Automatic scans deduplicate against saved results and the live queue using a
fingerprint of the vulnerability, target, versions, components, dependency
context, aliases, CVSS, and static guidance. A changed fingerprint is eligible
again; `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` can additionally age out a
matching result.

Follow-ups use `source=follow-up`, retain `parent_run_id`, and prefer the
analyzer's `/jobs/{job_id}/follow-up` endpoint. Otherwise DTVP sends a normal
request with bounded persisted parent context.

Result APIs:

- `GET /api/code-analysis/results`
- `GET /api/code-analysis/results/{run_id}`
- `DELETE /api/code-analysis/results/{run_id}`
- `POST /api/code-analysis/results/{run_id}/compact`
- `POST /api/code-analysis/results/{run_id}/benchmark`
- `GET /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-results`

#### Project Workspace And Dashboard

The vulnerability card contains target selection, queue/history, verdict and
evidence, an editable assessment draft, benchmark comparison, component
results, ticket draft, version coverage, LLM conversation, and pipeline
artifacts. The metadata badge and lightweight history for the current
vulnerability load automatically; a full result (including its LLM
conversation) loads only when its row is opened. Runs can then be removed,
applied, benchmarked, or used as parents for follow-ups.

An affected result produces a copyable Markdown remediation ticket. Setting
`DTVP_JIRA_CREATE_URL` adds an action that copies the draft and opens Jira's
create screen using the browser's existing session; ticket text is never placed
in the URL or sent with Jira credentials.

The header `Code Analysis` page is an operations dashboard for DTVP queue
slots, saved results, analyzer health/jobs/agents/progress, configured model and
backend, automatic sweep state, logs, cancellation, and abort controls. It is
not a second assessment editor.

#### Benchmarks And Agentyzer

Selecting a saved normal analysis run automatically compares it with an
existing assessment. DTVP computes deterministic state, justification, and
CVSS anchors, then uses Agentyzer `POST /benchmark/compare` for semantic
reasoning. If the analyzer is unavailable, DTVP returns a labeled deterministic
fallback. No benchmark is shown for `NOT_SET` assessments. Ratings are 1/F
(contradiction) through 5/A (strong agreement).

Bundled Agentyzer lives in `agentyzer/`, runs at `http://agentyzer:8000` in
Compose, and exposes host port `8095` by default. PM2 uses the mock analyzer on
that port. DTVP optionally uses Agentyzer's compact, follow-up, and prompt
inspection endpoints; persisted DTVP context remains the fallback.

Agentyzer prompt bundles live under `agentyzer/config/prompts/`. They enforce
structured, conservative assessment contracts and support native tool calls or
text `FETCH_*` fallbacks for allowlisted web/package/source research. Java
dependency discovery covers Maven and Gradle build, lock, and version-catalog
formats.

#### Automatic Scanning

Automatic scanning requires both `DTVP_AUTO_CODE_ANALYSIS_ENABLED=true` and a
configured analyzer.

- Project refresh queues genuinely new groups only when every instance is
  `NOT_SET` with no assessment text.
- A scheduled single-worker sweep starts after one interval and checks cached
  findings and live projects every `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS`.
- Reviewers can trigger an immediate background sweep from the dashboard.
- Targets require an explicit team mapping or the first explicitly mapped
  parent on a dependency path; wildcard ownership is insufficient.
- Any global, team, or legacy assessment marks a group handled.
- Stale automatic queue items are cancelled when the group becomes handled or
  loses its eligible target. Manual requests are not cancelled.

DTVP and Agentyzer default to one running scan. Raise
`DTVP_ANALYSIS_QUEUE_CAPACITY` and `AGENTYZER_MAX_CONCURRENT_JOBS` together only
when the analyzer, model backend, and workspaces support parallel scans.

## Development

### Split Backend And Frontend

The quick start is preferred for normal work. To run processes separately,
start only the mocks:

```bash
pm2 start ecosystem.config.js --only mock-dt,mock-tmrescore,mock-code-analysis
```

Then start the backend:

```bash
export DTVP_DT_API_URL=http://127.0.0.1:8081
export DTVP_DT_API_KEY=mock_key
export DTVP_ENVIRONMENT=development
export DTVP_OIDC_AUTHORITY=http://127.0.0.1:8081
export DTVP_OIDC_CLIENT_ID=mock_id
export DTVP_OIDC_CLIENT_SECRET=mock_secret
export DTVP_SESSION_SECRET_KEY=local-development-session-secret-1234567890abcdef
export DTVP_OIDC_REDIRECT_URI=http://localhost:5173/auth/callback
export DTVP_FRONTEND_URL=http://localhost:5173
export DTVP_TMRESCORE_URL=http://127.0.0.1:8090
export DTVP_CODE_ANALYSIS_URL=http://127.0.0.1:8095
uv run uvicorn dtvp.boot:app --reload --host 127.0.0.1 --port 8000
```

Use `DTVP_DEV_DISABLE_AUTH=true` to make `/auth/me` resolve to local `devuser`,
which maps to `REVIEWER` in `data/user_roles.json`. This bypass is rejected when
`DTVP_ENVIRONMENT=production`. Start the frontend with `cd frontend && npm run
dev`.

### Testing Notes

Commands are in the [command reference](#command-reference). README screenshots
come from `frontend/e2e/capture-readme-screenshots.manual.ts`. Real-stack manual
flows use `npm run test:ui:real-stack` with the relevant Playwright grep.

To exercise apply conflicts, edit the same finding in two sessions or change it
through mock Dependency-Track before submitting. The expected dialog is shown
in `docs/screenshots/conflict-resolution.png`.

## Docker Deployment

```bash
cp .env.dist .env
docker compose up -d
```

Set the Dependency-Track API key, complete OIDC settings, an HTTPS public URL,
and a random session secret before starting the production profile. Generate a
session secret with `openssl rand -hex 32`. Production startup rejects missing,
short, or known placeholder secrets, insecure OIDC callbacks, and the
development authentication bypass. For a non-default gateway:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=https://host.example:8083/dtvp
DTVP_SESSION_SECRET_KEY=<random value from openssl rand -hex 32>
```

Deployment rules:

- `./data` mounts at `/app/data`; mappings, roles, rules, caches, proposals, and
  archives survive container restarts.
- Compose starts Agentyzer and persists cloned repositories in the
  `agentyzer-repos` volume. Populate or override the sanitized
  `agentyzer/config/repos.yaml` before enabling automatic scans; never commit
  repository credentials.
- Internal services use Compose names and container ports. DTVP reaches
  Dependency-Track at `http://dtrack-apiserver:8080` and Agentyzer at
  `http://agentyzer:8000` unless overridden.
- If proxies are configured, list exact internal hostnames/IPs in `NO_PROXY`;
  do not rely only on CIDR entries.
- DTVP OIDC is independent of Dependency-Track browser sessions. Backend calls
  use `DTVP_DT_API_KEY` and never forward browser credentials.
- OIDC login uses authorization code with PKCE, state, nonce, discovery issuer
  validation, JWKS signature verification, and expiring DTVP session cookies.
  Changing the session key invalidates existing sessions and requires users to
  sign in again. Logout is a credentialed `POST` from the frontend.
- nginx proxies `DTVP_CONTEXT_PATH` to DTVP and defaults it to `/dtvp`.
  `DTVP_HTTP_PORT` changes the host gateway port. Direct-container deployments
  must publish port `8000` and include the context path in the URL.
- `dtvp.boot:app` serves startup status while the real app initializes. Startup
  logs time cache and integration initialization.
- The frontend image renders `index.html` from its immutable template on every
  start, so frontend URL and context-path changes are restart-safe.

Archive imports require read, BOM upload, and vulnerability-analysis update
permissions in Dependency-Track. Scheduled snapshots and expanded Git trees
are controlled by the archive variables below. The optional
`dtvp-archive-git-push` Compose job pushes an expanded tree; schedule it with
cron, systemd, or CI when required.

## Configuration Reference

Set values in `.env` for Compose or in the shell for local `uv` runs. `unset`
means the integration or override is disabled.

### Dependency-Track, Cache, And Rules

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081`; Compose: `http://dtrack-apiserver:8080` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | API-key file used when the direct value is unset | unset |
| `DEPENDENCY_TRACK_URL` / `DEPENDENCY_TRACK_API_KEY` | Deployment aliases | unset |
| `DTVP_DT_CACHE_PATH` | Dependency-Track cache and pending update queue | `data/dt_cache` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background refresh interval | `60` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Parallel version fetch limit | `4` |
| `DTVP_ASSESSMENT_IO_CONCURRENCY` | Concurrent Dependency-Track assessment reads or writes per operation | `4` |
| `DTVP_ASSESSMENT_WRITE_MAX_ATTEMPTS` | Attempts for transient assessment-write timeouts, rate limits, and HTTP 5xx responses | `3` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | Completed/failed grouped-task retention | `3600` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | Persisted summary-index SQLite path | sibling of cache path |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted summary indexes | `64` |
| `TEAM_MAPPING_PATH` | Component ownership mapping | `data/team_mapping.json` |
| `USER_ROLES_PATH` | User-to-role mapping | `data/user_roles.json` |
| `RESCORE_RULES_PATH` | CVSS transition rules | `data/rescore_rules.json` |

### Authentication, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_ENVIRONMENT` | Security profile: `production`, `development`, or `test` | `production` |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_CLIENT_SECRET_FILE` | File containing the OIDC client secret when the direct value is unset | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback | derived from frontend URL/context path |
| `DTVP_OIDC_ALLOWED_ALGORITHMS` | Comma-separated asymmetric ID-token algorithms | `RS256` |
| `DTVP_OIDC_TRANSACTION_TTL_SECONDS` | Maximum OIDC state/nonce/PKCE transaction age | `300` |
| `DTVP_SESSION_SECRET_KEY` | Session signing key; at least 32 characters when authentication is enabled | unset; required outside the development bypass |
| `DTVP_SESSION_SECRET_KEY_FILE` | File containing the session key when the direct value is unset | unset |
| `DTVP_SESSION_TTL_SECONDS` | Signed DTVP session lifetime | `28800` (8 hours) |
| `DTVP_SESSION_COOKIE_SECURE` | Explicit Secure-cookie override | automatic; required `true` in production |
| `DTVP_DEV_DISABLE_AUTH` | Resolve local requests as `devuser` | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | app `/`; Compose `/dtvp` |
| `DTVP_HTTP_PORT` | Compose nginx host port | `80` |
| `DTVP_BOOT_APP` | Real ASGI app loaded by the boot wrapper | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Additional comma-separated CORS origins | unset |
| `DTVP_API_URL` | Frontend API base override; Vite alias `VITE_DTVP_API_URL` | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |

### Project Archives

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_PROJECT_ARCHIVE_PATH` | ZIPs, import previews, and snapshots | `data/project_archives` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED` | Write stable Git-friendly trees | `false` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_PATH` | Expanded tree directory | `data/project_archives_git` |
| `DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED` | Enable scheduled snapshots | `false` |
| `DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS` | Snapshot interval; minimum 60 | `86400` |
| `DTVP_PROJECT_ARCHIVE_RETENTION_COUNT` | Recent ZIPs retained per project | `30` |
| `DTVP_PROJECT_ARCHIVE_INCLUDE` | Comma-separated scheduled project names | empty |
| `DTVP_ARCHIVE_GIT_REMOTE` | Optional archive Git remote | empty |
| `DTVP_ARCHIVE_GIT_BRANCH` | Archive Git branch | `main` |
| `DTVP_ARCHIVE_GIT_AUTHOR_NAME` | Commit author name | `DTVP Archive Bot` |
| `DTVP_ARCHIVE_GIT_AUTHOR_EMAIL` | Commit author email | `dtvp-archive@example.invalid` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_FILE` | SSH key inside Git helper | `/ssh/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_FILE` | Known-hosts file inside Git helper | `/ssh/known_hosts` |

### Threat Model And Code Analysis

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_TMRESCORE_URL` | tmrescore/vscorer base URL | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | HTTP timeout before polling fallback | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Cached proposal snapshots | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | Completed/failed task retention | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | Analyzer base URL | unset; Compose: `http://agentyzer:8000` |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | Analyzer HTTP timeout | `300` |
| `DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS` | Dashboard health/jobs timeout | `5` |
| `DTVP_CODE_ANALYSIS_MODEL` | Analyzer model hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_BACKEND` | LLM backend hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_PROVIDER` | LLM provider hint | unset |
| `DTVP_JIRA_CREATE_URL` | Jira create-screen URL | unset |
| `DTVP_ANALYSIS_QUEUE_CAPACITY` | Concurrent DTVP queue items | `1` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | Completed/failed queue retention | `3600` |
| `DTVP_CODE_ANALYSIS_RESULTS_PATH` | Result/application SQLite store | `data/code_analysis_results.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` | Maximum stored results | `2000` |
| `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS` | Maximum result age; `0` disables | `0` |
| `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE` | Persist reviewer/follow-up guidance | `true` |
| `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` | Maximum dedupe age; `0` uses fingerprints only | `0` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Enable automatic scans | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Automatic sweep interval | `900` |
| `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` | Static component guidance | `data/auto_analysis_guidance.json` |

### Agentyzer

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `AGENTYZER_PORT` | Compose host port | `8095` |
| `AGENTYZER_LOG_LEVEL` | Service log level | `INFO` |
| `AGENTYZER_MAX_CONCURRENT_JOBS` | Concurrent assessment pipelines | `1` |
| `AGENTYZER_LLM_BACKEND` | `ollama` or `openwebui` | `ollama` |
| `AGENTYZER_OLLAMA_HOST` / `AGENTYZER_OLLAMA_MODEL` | Ollama endpoint and model | `http://host.docker.internal:11434` / `mistral` |
| `AGENTYZER_OPENWEBUI_HOST` / `AGENTYZER_OPENWEBUI_MODEL` | OpenWebUI endpoint and model | `http://host.docker.internal:3000` / `mistral` |
| `AGENTYZER_OPENWEBUI_API_KEY` | Optional OpenWebUI bearer token | unset |
| `AGENTYZER_OPENWEBUI_TOOL_CALLS` | Native tool calls: `auto` or `off` | `auto` |
| `AGENTYZER_OPENWEBUI_CONTEXT_WINDOW` | Optional context limit | `0` |
| `AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN` | Reserved token margin | `256` |
| `AGENTYZER_OPENWEBUI_CONTEXT_RETRIES` | Oversized-context retries | `2` |
| `AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS` | Completion budget preserved during compaction | `256` |

## SBOM, Documentation, And License

The DTVP image contains CycloneDX frontend/backend SBOMs. The app exposes the
combined document at `/api/sbom` and `/api/sbom/html`; CI publishes a separate
Agentyzer SBOM. Production dependencies come from `frontend/package*.json`,
`pyproject.toml`, and `uv.lock`; test/development dependencies are excluded.

Documentation entry points:

- [Screen guide](docs/screens.md) and generated images under `docs/screenshots/`
- [Integration API surface](docs/integration-api-surface.md)
- [Workflow diagrams](docs/workflow-flowcharts.md)
- [tmrescore OpenAPI](openapi/tmrescore-openapi.json)
- [Code-analysis OpenAPI](openapi/code-analysis-openapi.json)

This project is licensed under the MIT License. See [LICENSE](LICENSE).
