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
  lifecycle states, including a Ready for Approval filter for complete pending
  assessments.
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

Requirements: Python 3.14+, `uv`, `npm`, `pm2`, and Node.js 24 LTS (24.15+)
or a newer supported Node.js release. Docker and Docker Compose are needed
only for the packaged deployment.

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
`Login as Reviewer` on the mock Dependency-Track page.

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
| Benchmark grouped-query concurrency | `uv run python scripts/benchmark_group_queries.py` |
| Capture README screenshots | `cd frontend && npm run test:ui:docs` |
| Start the packaged deployment | `cp .env.dist .env && docker compose up -d` |

The root pytest configuration uses importlib import mode so `uv run pytest`
can collect the DTVP and nested Agentyzer suites together even when both suites
contain test modules with the same filename.

The CI end-to-end job uses the Playwright container image in
`.github/workflows/build-publish.yml`. Its image tag must exactly match the
resolved `@playwright/test` version in `frontend/package-lock.json`; update both
in the same change. The regular, manual, and real-stack Playwright
configurations cover Chromium, Firefox, and WebKit desktop browsers.
The Vitest configuration keeps local TypeScript config imports explicit so it
also loads with Vite's native config loader. It caps the process pool at four
workers so jsdom-heavy component tests do not contend past their per-test
timeouts; validate config changes with
`cd frontend && npx vitest --run --configLoader native`.
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
| `dtvp/general_api_routes.py` | Projects, grouped tasks, task windows, statistics, assessments, and dependency chains |
| `dtvp/grouped_vuln_services.py` | Concurrent finding, vulnerability, and BOM collection before grouping |
| `dtvp/task_group_query_services.py` | Backend filtering, sorting, facets, pagination, and task-window queries |
| `dtvp/logic.py` | Grouping, ownership, assessment parsing, CVSS, statistics, and dependency analysis |
| `dtvp/assessment_*` and `rescore_rule_services.py` | Assessment writes, conflict handling, metadata recovery, and CVSS rules |
| `dtvp/assessment_outbox_services.py` | Transactional assessment overlays, revisions, and pending Dependency-Track synchronization |
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
  `/api/tasks/{task_id}/groups/{group_id}` hydrates full details. Task
  mutations wake all event-stream clients through one shared event hub instead
  of one polling loop per client. Serialized status is reused across clients,
  progress streams carry only the latest 20 log entries, and a 15-second blank
  heartbeat keeps idle streams open. The backend also emits
  `X-Accel-Buffering: no`; if an outer proxy still buffers or leaves the stream
  idle for 35 seconds, the browser cancels it and resumes through status
  polling.
- Partial version results appear while grouping continues. Summary tasks
  publish at the first version, roughly one-third milestones, and completion
  instead of rebuilding cumulative snapshots after every tenth of the project.
  Version fetching continues while a partial window is being built; pending
  milestones coalesce to the newest snapshot instead of blocking progress or
  queuing stale builds. CPU-heavy grouping, indexing, and filtering run outside
  the async event loop. When the final partial publish already contains every
  version, it becomes the completed snapshot without repeating construction.
- Grouped-task searches use thread-safe per-task query caches, share identical
  in-flight queries, and reuse sort orders across filter changes. They run in a
  dedicated bounded executor so cold searches cannot exhaust the default
  application thread pool; queued browser searches are discarded when a newer
  generation supersedes them. Cached result indexes use packed integers and
  are evicted against both entry-count and approximate byte budgets. Exact
  Team filters start from a per-task inverted index instead of scanning every
  vulnerability, and a count-less cached result reuses its filtered order when
  the corresponding facet-count request arrives.
  Lightweight code-assessment metadata is cached and invalidated when analyzer
  results change. Derived automatic-assessment facets and team-group context
  are reused until their metadata or configuration revision changes.
- Grouped snapshot construction runs in a separate bounded worker pool from
  foreground filters and vulnerability-detail hydration. This prevents several
  simultaneous project builds from filling the application thread pool; two
  build workers allow independent users to make progress on the required
  free-threaded Python runtime. Automatic-analysis planning runs in a separate
  post-processing pool and starts only after clients are notified that the
  snapshot is complete. Detail hydration has its own reserved pool, so project
  builds and cold searches do not consume every slot needed to open a
  vulnerability.
- The global analysis indicator polls one compact queue-and-sweep status
  response: every five seconds while work is active and every 30 seconds while
  idle, with per-client jitter. Hidden browser tabs pause polling, and detailed
  queue payloads load only while the queue panel is opened.
- Project smart search waits 400 ms for continued typing and aborts superseded
  result-window requests. Deactivated keep-alive project views stop their cache
  freshness timers. Cache-status filesystem counts are reused for up to five
  seconds and invalidated when DTVP changes cached content.
- Queue submission and deduplication use in-memory FIFO and target indexes
  rather than rescanning and reindexing the complete queue. Detailed queue
  reads are newest-first and limited to 100 items by default (200 maximum);
  automatic and manual submissions share a configurable pending-item limit.
- The frontend viewport-windows list rows, coalesces partial refreshes, and
  hydrates dependency paths and full assessment details only when needed.
  Refreshed full-detail groups remain distinguishable from lightweight list
  summaries even when both carry current list metadata.
  Follow-up pages and full-result drains omit facet counts they do not consume;
  a Team-filter request renders its card window without facet counts, then
  refreshes complete task-wide and filtered counts in the background.
- The local cache under `DTVP_DT_CACHE_PATH` stores projects, findings,
  vulnerability details, BOMs, local overlays, and pending writes. Stale cached
  data remains readable while Dependency-Track is unavailable. Concurrent
  misses for the same resource share one Dependency-Track request, the complete
  project list has a short freshness TTL across clients, and API-key requests
  reuse one application-lifetime HTTP connection pool. The background cache
  sync also retains its client between refreshes. Each caller still receives an
  isolated mutable snapshot. Cold finding loads use
  Dependency-Track's Finding Packaging Format export so assessment state and
  details arrive in one request instead of issuing one analysis request per
  finding. Older Dependency-Track versions fall back to the legacy endpoint.
  Cache JSON is encoded and atomically replaced by one ordered writer thread;
  async operations await durability without holding the event loop or cache
  lock. Cache writes whose JSON content did not change are skipped. Grouped
  snapshots use project-scoped revisions plus the selected version metadata,
  so a background refresh or activity in another project does not invalidate
  an otherwise reusable result. Summaries created during a cold fill are saved
  against the scoped revision after that fill.
  Pending assessment writes and their local overlays live in a transactional
  SQLite outbox. Newer changes to the same finding replace older pending
  values, and one application-wide bounded dispatcher retries Dependency-Track
  synchronization without multiplying write concurrency per client. When a
  finding disappears before synchronization, a Dependency-Track 404 triggers
  a live findings-API check. Only a valid response confirming that the exact
  project/component/vulnerability tuple is absent drops the queued revision
  and its unsynced overlay; failed checks and findings that still exist keep
  retrying. Legacy
  `pending_updates.json` entries import once on first use. Interactive and bulk
  assessment requests return after the outbox transaction commits instead of
  waiting for Dependency-Track. Per-finding local revisions reject stale DTVP
  edits atomically; optional strict conflict mode additionally performs live
  Dependency-Track reads before accepting a save. Grouped-task artifacts carry
  reverse finding indexes, so accepted changes copy and re-summarize only
  affected groups; their list-query index is rebuilt lazily on the next read
  instead of delaying the save.
- Grouped-vulnerability tasks are access-controlled to users who independently
  requested the exact project/CVE/mode/cache/mapping snapshot; those matching
  requests share one task and result allocation. Their bulk-workflow
  operations, uploaded or generated archive tasks, and live tmrescore sessions
  remain private to the authenticated user who created them. Shared
  Dependency-Track assessments, the workspace-wide analyzer queue and saved
  analysis results, and cached project proposal snapshots remain collaborative
  application data.
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

These are sizing estimates, not production guarantees. The reproducible
benchmark below was run on a 20-CPU, 15 GiB host with 20,000 groups, filtered
facet counts enabled, and ten cold searches per simulated user:

| Runtime | Simultaneous searches | Throughput | p95 search latency |
| :--- | ---: | ---: | ---: |
| CPython 3.14.4, GIL enabled | 1 | 19.6 queries/s | 78 ms |
| CPython 3.14.4, GIL enabled | 4 | 21.1 queries/s | 355 ms |
| CPython 3.14.4, GIL enabled | 8 | 22.0 queries/s | 523 ms |
| CPython 3.14.4, free-threaded | 1 | 18.1 queries/s | 71 ms |
| CPython 3.14.4, free-threaded | 4 | 57.2 queries/s | 91 ms |
| CPython 3.14.4, free-threaded | 8 | 67.8 queries/s | 155 ms |

For this CPU-heavy path, free threading provides real multi-core scaling: at
four simultaneous cold searches it delivered about 2.7x the throughput and
cut p95 latency by about three quarters. Moving from four to eight
free-threaded workers gave only about 19% more throughput while increasing p95
by about 71%. Four query workers therefore remains the balanced default.
Identical cached searches remained below 1 ms in every case; new search/filter
combinations and their
facet counts are the limiting query path.

The same 20,000-group query index retained about 65 MiB of traced Python
allocations with the GIL build and 69 MiB with the free-threaded build. Real
tasks also retain full vulnerability, component, dependency, and BOM details;
budget roughly 150-300 MB or more for each large retained task. Matching
project/CVE/mode/cache/mapping requests share one access-controlled task, and
completed tasks are retained for 15 minutes by default. Memory remains the
likely limit when many users open distinct large projects.

For conservative per-instance planning:

- large projects with active searching: 8-12 users comfortably; around 20 is
  likely to show latency or memory pressure;
- medium projects: 30-50 active users;
- mostly browsing or dashboard use: 100-300 sessions, assuming few retained
  large tasks;
- code-analysis jobs: one runs concurrently by default through
  `DTVP_ANALYSIS_QUEUE_CAPACITY`; additional jobs wait in the shared queue.

Before increasing those ranges, use production-shaped load tests. The next
scaling steps are validating the free-threaded image with real project mixes,
tuning the grouped-task retention/count caps against available RAM, and
introducing a shared task/result store before multiple backend processes are
enabled. More Uvicorn workers are not safe while live task registries remain
process-local.

Reproduce the grouped-query measurements with:

```bash
uv run python scripts/benchmark_group_queries.py \
  --groups 1000 5000 10000 20000 \
  --concurrency 1 4 8 16
```

The benchmark generates deterministic groups, primes only the reusable sort
order, and then measures new search/filter contexts separately from identical
cached requests. It reports build time, retained Python allocations,
throughput, and p50/p95 latency in the `dtvp.group-query-benchmark/v1` schema;
add `--json` for machine-readable output and `--no-counts` to model follow-up
pages. Compare the normal project runtime with a clean `3.14t` interpreter on
the same host (the benchmark itself has no third-party dependencies):

```bash
uv run python scripts/benchmark_group_queries.py
uv run --no-project --python 3.14t python scripts/benchmark_group_queries.py
```

## Domain Model

### Vulnerabilities And Assessments

A grouped vulnerability joins equivalent IDs and aliases across versions. Its
aggregate state follows these rules:

- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`,
  `FALSE_POSITIVE`, and `NOT_AFFECTED`.
- A non-`NOT_SET` General assessment takes precedence; otherwise DTVP chooses
  the worst team state using the priority in `dtvp/logic.py`.
- A reviewer-approved, non-pending General assessment is terminal and makes
  the vulnerability `ASSESSED`, even if team-specific blocks were not all
  recorded before approval. Without an approved General result, the
  `ASSESSED` lifecycle requires a non-`NOT_SET` assessment block for every
  normalized team tag. Legacy unstructured assessments retain their separate
  `ASSESSED_LEGACY` classification.
- Pending review with missing team or finding coverage remains `INCOMPLETE`;
  pending review with all required assessments documented remains
  `NEEDS_APPROVAL` and matches the overlapping `READY_FOR_APPROVAL` filter.
- Inconsistency reasons are indexed separately: missing rescoring metadata,
  differing analysis states, differing structured team blocks, and differing
  substantive details. Selected reasons use OR semantics; filter categories
  combine with AND semantics.
- Assessment details use structured blocks such as `[Team: ...]`,
  `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`,
  `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Structured details retain at most one block per team (case-insensitive).
  Code-analysis assessment drafts keep evidence in the owning-team blocks and
  maintain one General block that references those teams and takes their worst
  effective state. An independently authored General assessment is preserved;
  team evidence is never copied into it. Generated General summaries from older
  sync operations are removed on the next sync.
- Dependency paths come from CycloneDX BOM dependency graphs. Dependency-Track
  attribution timestamps are retained as `attributed_on`.

CVSS rescoring is data-driven through `RESCORE_RULES_PATH` (default
`data/rescore_rules.json`). The shipped `NOT_AFFECTED` and `FALSE_POSITIVE`
transitions support CVSS 2.0, 3.0, 3.1, and 4.0 and produce exactly `0.0`.
Vectors preserve their original CVSS version and base metrics. Cross-version,
malformed, or incomplete vectors stay visible for manual review rather than
being rewritten speculatively.

A configured transition owns the vector of the state it covers. Whenever a
state with a rule is written — by the reviewer, by a code-analysis draft, or by
a bulk apply — the rule is layered on top of the proposed vector and the base
metrics of the Dependency-Track vector are restored, so an analyzer proposal
contributes only its extra metrics. States without a transition keep the
analyzer's proposed vector and score unchanged.

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
primary label and remaining entries are historical aliases. Every authenticated
user can read this ownership context so analyst views resolve the same teams as
backend filters and automatic analysis; creating or changing mappings remains
reviewer-only.

`TEAM_GROUPS_PATH` defaults to `data/team_groups.json` and is also editable in
Settings. Each group has explicit direct `teams` and nested `groups`, so an
abstract group can be composed from existing teams and groups while a group
such as `Core-MUC` can also include the existing `Core-MUC` team:

```json
{
  "Core-MUC": {
    "teams": ["Core-MUC", "3rd Party"],
    "groups": []
  },
  "Product Engineering": {
    "teams": ["Runtime"],
    "groups": ["Core-MUC"]
  }
}
```

Team references accept configured aliases and are normalized to their primary
team. Unknown teams or groups, empty groups, duplicate members, and cycles are
rejected when the configuration is saved. Group statistics expand nested
membership and count each vulnerability once per group, even when it carries
both parent-team and subteam tags.

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
code-assessment availability, automatic-analysis outcome, and proposed
automatic CVSS severity. Outcome choices (`Affected`, `Probably affected`,
`Not affected`, and `Uncertain`) and rescore choices (`Critical` through
`Info`, `No rescore`, and `Unscored`) use OR semantics within each facet and
AND semantics across facets. They are server-side task-window filters, so URL
state, counts, pagination, and Bulk Changes all operate on the same candidate
set. The Open selection matches the displayed `OPEN` lifecycle category, and
vulnerability-ID searches are combined with all active filters.

The Filters sidebar provides a searchable, alphabetically sorted Team dropdown
from the complete task facet list. Selecting a team uses a case-insensitive
exact name match; `team:` smart-search tokens remain available for free-form
team searches. That selection also scopes component-driven content inside an
opened vulnerability card: affected and triggering components, project
versions, header component/count/age metadata, current-assessment rows,
dependency context, code-analysis targets, and run history show only the
selected team's closest mapped components. Saved analyzer runs with explicit
`target_team` metadata must also match the canonical team or one of its
configured aliases; legacy component-scoped runs without that metadata remain
visible for compatibility. Team mappings are compiled and component ownership
is resolved once per card scope so switching filters does not repeatedly scan
the full mapping. Advisory metadata remains vulnerability-wide context. An
approved General assessment remains the authoritative aggregate state and makes
the vulnerability done once approved, even when team coverage is incomplete.
Before approval, a pending item with missing team or finding coverage is
classified as `INCOMPLETE`, while complete-but-pending work remains
`NEEDS_APPROVAL`. The overlapping `READY_FOR_APPROVAL` filter selects only the
complete pending subset; the broader Needs Approval filter still includes
incomplete pending work. The tab badges
and Next action state use assessment coverage from the selected team's visible findings.
The card reports how many findings are inside the
active team scope, and stale asynchronous history loads are discarded when the
selected scope changes. The top search result count is the final number of
grouped vulnerabilities after every active filter, independent of how many
paginated rows are currently loaded. When filters reduce the task, it is shown
relative to the unfiltered task total. Every filter-chip count and the Team
open/assessed breakdown is calculated from that same final filtered result.
Pending-review groups remain on the open side of that breakdown until they are
approved, even when their currently visible team blocks are populated.
Complete task-wide facets remain available as filter choices even when their
current filtered count is zero. Overlapping properties such as teams and
inconsistency reasons can therefore have counts whose sum exceeds the final
result count.
When groups are configured, the Results tab renders one Per Group table with
indented nested groups, direct team members, and non-grouped teams at the root,
so each parent total can be compared with its subgroup and team totals without
a duplicate Per Team box. Group totals expand the hierarchy and deduplicate
vulnerabilities across member teams. Without group configuration, the existing
Per Team table remains as the fallback; it groups configured aliases into their
canonical team and shows aliases beneath the primary team. A vulnerability
carrying both canonical and alias names is counted only once there.

The detail workspace provides:

| Tab | Purpose |
| :--- | :--- |
| Context | Four ordered sections: advisory and references; finding/team/component scope with affected components visible to analysts and reviewers; dependency context; existing assessment evidence |
| Code Evidence | A semantic run list with an expandable new-analysis control; selected rows own indented outcome and evidence disclosures; a worst-case combined decision with the shared advisory shown once and rationale grouped into per-target cards |
| Assessment | Consistent scope and decision/rationale sections with Save/Submit and reload controls in the second section header; CVSS vector or score edits enable saving; analyzer proposals for team decisions; reviewer-only synchronization for incomplete coverage; inconsistent team decisions remain explicit for manual resolution; global CVSS/rescoring controls |
| Team Mapping | Reviewer-only ownership editor |

Compact vulnerability rows expose the current workflow state, such as mapping
needed, analysis running, result ready, assessment needed, awaiting review, or
complete. Inside the card, tab status badges and one Next action guide lead to
the relevant tab. The guide's navigation control disappears after reaching its
destination and is replaced by concrete in-tab instructions, leaving the real
run, draft, save, or submit control as the next action instead of repeating the
same button. The sticky bar contains only navigation and persistence state.
After a successful assessment save or analyst submission, the guide advances
to the next vulnerability in the current filtered and sorted result set.

CVSS and rescoring controls appear in the reviewer-only Global subview of
Assessment so the score and assessment can be evaluated and saved together.
Team subviews omit global rescoring controls. Analysts see mapped ownership and
triggering components in Context and can launch analysis for owned targets.
Each team subview shows the latest scoped analyzer assessment as a proposal,
including its state, summary, and rationale. The subview identifies the mapped
repository component or components for the selected team and provides a direct
copy action when the analyzer supplied a remediation ticket. A user can copy
that proposal into the editable draft, but a saved or manually edited team
assessment remains authoritative. Reviewers use the latest analyzer result only
as a fallback for a team without a manual assessment; the effective summary and
Global draft use the worst state across those per-team sources. This source
precedence is intentional rather than timestamp-based, so a newer automated run
cannot silently replace a team's considered decision.
An active Team filter establishes the card's assessment context immediately.
Analysts see and edit only that team's Assessment subview. Reviewers start in
the same focused view, retain direct access to Global, and can explicitly show
all other teams when a cross-team review is needed; returning to the focused
view restores the exact filtered team. Analyst submission requires a mapped
team, a non-empty analysis
state and details, and a justification for `NOT_AFFECTED`; the action is
explicitly labeled as a submission for reviewer approval. Assessment contains
only Global (for reviewers) and real mapped teams; automatic analysis and
tmrescore remain supporting context rather than a synthetic `automation` team.
A tmrescore proposal stages a normal Global draft and waits for the explicit
save action. Local drafts survive tab and team-scope changes. Closing or
switching a vulnerability prompts the user to save, discard, or keep editing.
Assessment writes refresh the active task window, and route state preserves
filters when navigating to statistics or code analysis. Once the transactional
local save succeeds, the card reports that it is saved locally while
Dependency-Track synchronization continues in the background; retry failures
remain visible without blocking another edit. Per-finding local revisions are
retained across list updates so subsequent edits keep conflict protection.
Each vulnerability card can reload its current assessment directly from
Dependency-Track; the refreshed task snapshot updates the card, lifecycle
filters, and counts together.
Vulnerability headers use compact status icons to show both available and
unavailable states for tmrescore/vscorer and code-analysis assessments. In the
compact list, the Dependency-Track reload action stays at the bottom-right of
the header so it does not overlap the assessed corner marker.

### Bulk Changes

The reviewer-only `Bulk Changes` dialog runs one plug-in workflow at a time:

| Workflow | Candidates and action |
| :--- | :--- |
| Apply Automatic Assessments | Usable, unapplied analyzer assessments; writes one assessment per owning team plus a global assessment with the worst verdict and its CVSS rescore |
| Sync Incomplete Assessments | Groups whose otherwise consistent assessment is missing from some findings |
| Restore Rescored CVSS | Assessed findings with one unambiguous current vector recoverable from audit comments |
| Repair Rescoring Definitions | Findings where a configured state-based CVSS rescore is missing, incomplete, or incorrect; repairs every safely actionable finding |

`Repair Rescoring Definitions` includes cases where a transition such as
`NOT_AFFECTED` should produce a `0.0` score but no rescore was stored. Preview
rows show why each finding is a mismatch and place the stored vector and score
beside the fixed values that will be written. Findings with a matching
transition but a missing or unsupported original CVSS vector remain listed for
manual review instead of being silently omitted.
`Apply Automatic Assessments` rows likewise show the current vulnerability
CVSS and the automatic rescore that will be written to every eligible finding,
together with the teams that receive an assessment and any analyzed component
without a team.
Its composable selection filters cover every automatic-analysis outcome and
every proposed CVSS severity, plus candidates with no rescore or a vector-only
unscored proposal. Multiple choices within a facet use OR semantics, while the
outcome and rescore facets combine with AND semantics. They filter the visible
rows and reset the apply selection to those rows. Their labels, values, and
rescore-band classification are shared with the main Filters sidebar.
Lightweight saved-result metadata retains the proposed score and vector for
this preview; older metadata rows are rebuilt automatically from their stored
full results.

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
Apply operations commit all selected changes to the transactional local outbox
and expose item-level progress through the task status. Dependency-Track writes
then use the shared bounded background dispatcher with coalescing and retry
backoff, so large applies do not hold an HTTP request open or multiply upstream
write concurrency.
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
become `IN_TRIAGE`; Not Affected becomes `NOT_AFFECTED`.

Applied details carry one assessment block per owning team plus the global
block, matching the vulnerability card's `Apply all to <n> teams` action. A
team's block holds the analyzer evidence for the components it owns and its own
worst-wins state and justification; ownership uses the same team mapping and
dependency-path resolution as automatic scan targets, with the run's recorded
target team as fallback. The global block carries the worst state across all
runs, its justification, and the CVSS rescore of that worst run — a milder run
never contributes the global vector or score, even when its proposed score is
higher. When the global state has a configured rescore transition, that rule
produces the written vector and score, so `Repair Rescoring Definitions` reports
nothing right after an apply. Components that no team owns keep their evidence
in the global block and are listed in the preview row. Applied details retain
every relevant run as a compact decision record: target, verdict, the two
executive lines (including the decisive concern or action when applicable), up
to three dependency/version facts, and the CVSS score change. Repeated raw
summary, rationale, research, audit, remediation, CWE, version-list, and CVSS-
reason sections remain in the saved full result instead of being copied into
Dependency-Track. Legacy results without an executive summary keep the older
semantic fallback so existing evidence is not silently dropped. Ticket drafts
remain separate from assessment details.
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
vector, processed project releases, dependency context,
reviewer/static guidance, optional tmrescore context, and optional LLM metadata.
DTVP sends every project release represented in the processed vulnerability
group. Agentyzer intersects those candidates with versions the selected
repository actually contains: matching Git tags, `release/*` branches from all
available remotes, and `main`/`master` when configured project-version metadata
identifies the branch's release. The request field is `project_versions`
(`affected_product_versions` remains a deprecated input alias). These values
remain explicitly distinct from vulnerable dependency versions read from
manifests and lock files.

Advisory lookup canonicalizes source-sensitive identifiers (including lowercase
GHSA payloads for OSV and GitHub), follows CVE aliases for NVD, and can use an
optional `AGENTYZER_GITHUB_TOKEN` for authenticated GitHub advisory requests.
The repository target remains separate from the vulnerable package identity:
if advisory lookup cannot establish the package and affected constraints, the
analysis stays Inconclusive instead of scanning the target as its own
dependency. For npm repositories, dependency evidence is read from structured
manifest and lockfile entries, so a root `package.json` or `package-lock.json`
`name` field is not reported as a direct or locked dependency.

Final results pass through a deterministic claim audit that aligns verdict and
reasoning, flags unsupported claims or downgrades, and restores original CVSS
when a downgrade is rejected. Version presence alone is capped at Probably
Affected unless reachability, exploitability, or a positive transitive path is
confirmed. A generic dependency-usage reachability result does not override a
later full-source analysis that affirmatively excludes the
vulnerability-specific path. Static guidance is never evidence by itself.

Each completed assessment also carries a compact `executive_summary` with two
separate statements: `vulnerability` briefly describes the advisory and its
affected dependency, while `assessment` states the final repository-specific
verdict, confidence, exposure, audit state, key basis, and at most one next
action. The assessment uses formal disposition, confidence, exposure, basis,
required-action, and audit-assurance language. A structured `why` list is
rendered as the **Decision rationale** and retains the complete deciding facts
from advisory applicability, dependency presence, current and product-release
versions, direct reachability, deep exploitability, transitive paths, and audit
caveats. Path
claims are explicitly scoped to the current workspace; a missing path remains
"not confirmed" unless affirmative evidence supports "not reachable". This
gives Affected, Not Affected, and Inconclusive results an audit-ready evidence
record without restoring the old raw report in the primary view. Compactness
comes from separating these evidence categories; the assessment payload and
human-facing statements never cut them at a character or item-count limit. It is
assembled after the deterministic audit guardrails, retained in lightweight
result metadata and shown in assessment drafts and run outcomes. The separate
follow-up prompt context remains bounded to the model's input budget.
Human-facing assessment text also lists every covered product version from the
repository intersection on one comma-separated `Product versions covered:`
line; dependency/component versions remain separately labeled evidence. The
complete summary, reasoning, role views, version
inventory, audit checks, and pipeline evidence remain available in the saved
run payload.

When the latest results for several targets are combined, the Code Evidence
view renders the vulnerability and worst-case decision once, followed by one
card per target. Each card uses the component name as its heading and lists the
target's rationale without repeating that name on every evidence line. The
separate target-status list is shown only for results whose full details are
still loading.

Agentyzer retains package provenance for affected ranges, explicit affected
versions, and fixed versions. For advisories covering multiple packages, it
selects the package found in the analyzed repository and excludes constraints
belonging to the other packages. OSV `fixed`, `last_affected`, and `limit`
boundaries keep their exclusive or inclusive semantics. npm advisory ranges
use SemVer precedence, including prereleases that are not valid PEP 440; a
range that cannot be evaluated is treated conservatively instead of being
reported as safe. Repository history includes tags and `release/*` branches
from every available remote. When project releases are supplied, only their
intersection with those repository versions is analyzed. The default branch
uses `.project.json` and its `version` field unless the component's
global or component-level `project_version_files` repository configuration
supplies another list of JSON paths and dotted fields. Version evidence
separately reports the current dependency version, verified project release
refs, metadata sources, and unmatched caller-supplied project releases. Fixed
versions remain associated with their affected release line so remediation
does not suggest cross-line downgrades.
Manifest ranges such as `^1.2.3` and `>=2.0` remain unresolved constraints
unless a lock file or artifact supplies a concrete version, so range boundaries
are not presented as installed affected versions.

#### Results, Dedupe, And Follow-Ups

Completed results are stored in SQLite at `DTVP_CODE_ANALYSIS_RESULTS_PATH`.
The store retains full payloads separately from lightweight assessment metadata,
plus run/job IDs, parent links, model metadata, target context, and application
provenance. Analyzer requests also carry the DTVP project name so external jobs
can be correlated without conflating the same vulnerability and component in
different projects. Numbered migrations live in
`dtvp/migrations/code_analysis_results`; a legacy sibling JSON cache imports on
first use.

Automatic scans deduplicate against saved results and the live queue using a
fingerprint of the vulnerability, target, versions, components, dependency
context, aliases, CVSS, and static guidance. A changed fingerprint is eligible
again; `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` can additionally age out a
matching result.

Follow-ups use `source=follow-up`, retain `parent_run_id`, and prefer the
analyzer's `/jobs/{job_id}/follow-up` endpoint. Otherwise DTVP sends a normal
request with bounded persisted parent context.

The code-analysis dashboard polls every five seconds while work is active and
every 15 seconds while idle, pauses in hidden tabs, and applies per-client
jitter. DTVP shares a short-lived dashboard snapshot across clients so one
polling wave causes one analyzer health/jobs lookup and one recent-result
query.

Result APIs:

- `GET /api/code-analysis/results`
- `GET /api/code-analysis/results/{run_id}`
- `DELETE /api/code-analysis/results/{run_id}`
- `POST /api/code-analysis/results/{run_id}/compact`
- `POST /api/code-analysis/results/{run_id}/benchmark`
- `GET /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-results`
- `POST /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-cleanup`

Vulnerability cleanup can independently remove saved analyzer assessments or
run records. Run cleanup reconciles DTVP queue entries with Agentyzer jobs,
including orphaned records that exist in only one store. It skips queued and
running work unless active cancellation is explicitly selected. The project
workspace exposes complete vulnerability cleanup plus per-run cleanup, while
the existing result deletion API remains available for assessment-only clients.

#### Project Workspace And Dashboard

The vulnerability card presents Code Evidence as a target-oriented workflow.
For analysts, the target-oriented runs section leads; reviewers start with the
Combined assessment because it is their primary decision input. The expandable
`Run new analysis` control sits inside the runs section above its compact latest-
run list. Each target row keeps View, Use as draft, Earlier runs, and Delete
actions on the right. View reveals a dismissible inline outcome with the
vulnerability and assessment executive summaries plus follow-up question
context directly beneath that row. Legacy results without an executive summary
fall back to their rationale. The list
indents the complete selected-run detail region—including every disclosure—so
the owning row remains visually unambiguous. Assessment draft, benchmark,
component results, ticket, version coverage, LLM conversation, and pipeline
evidence are peer disclosures in the same run context and start collapsed.
Derivative benchmark records do not replace a target's latest analysis row.
Live analyzer logs treat the analyzer-provided progress log as authoritative;
the current-activity and active-agent snapshots are fallback state rather than
additional log records. Repeated model-wait heartbeats replace the prior entry
for the same analysis stage, so a slow model call appears as one elapsed-time
status instead of three new rows every 15 seconds.
The LLM conversation opens in a taller vertically resizable viewer and can move
into an accessible near-full-screen dialog without changing renderers or losing
context. Each captured turn is a numbered request/tool/response timeline with
explicit `Agentyzer → Model` and `Model → Agentyzer` provenance, raw request and
response copy actions, and token/model metadata. Timeline stages are separately
collapsible: verbose requests and tool evidence start closed, model responses
start open, and conversation-wide controls switch between overview and full
audit views. Expanded stages use bounded, keyboard-focusable scroll regions so
one long prompt, tool trace, or response cannot consume the whole conversation
viewer. Inline and nested regions chain unused wheel movement to their parent,
so a short section or a reached scroll boundary does not trap page scrolling;
only the full-screen dialog contains overscroll. A summary above the timeline
reports Local-to-LLM messages and prompt
tokens, LLM-to-Local responses and completion tokens, total/captured timing,
per-turn LLM and inferred local-tool timing, retries, context adaptations,
models/providers, tool requests/results/failures, repository inspections, and
trace coverage when older providers omit telemetry. The per-turn timing table is
itself bounded and keyboard-scrollable for long conversations. Current configured prompts are
shown only as a clearly warned fallback when a run did not persist its actual
conversation, so configuration cannot be mistaken for run evidence. An
**Additional guidance used** panel extracts component/reviewer guidance from
the persisted model-request messages and identifies the exact turns that
received it. Saved queue guidance without a matching trace is labeled as not
verifiable, while storage-policy redaction is called out explicitly. Static
component guidance is resolved for both initial and follow-up runs against the
component actually selected for that request.
The Combined assessment displays the worst latest target verdict and a compact
cross-component executive summary before a draft is staged. Full component
reasoning remains in each saved run. Preview and draft preparation share the
same verdict-to-assessment
ordering (`EXPLOITABLE`, `IN_TRIAGE`, then `NOT_AFFECTED`) and use analyzer CVSS
only to break ties within the same state.

The metadata badge and lightweight history for the current
vulnerability and aliases load automatically for every component in the active
scope. History is paged until complete, grouped per component, and nests a
follow-up's predecessor chain beneath its latest successor while retaining
earlier independent runs. A full result (including its LLM conversation) loads
only when its row is opened. Runs can then be removed, applied, benchmarked, or
used as parents for follow-ups. Using one as an assessment draft resolves its
persisted target team, switches directly to that Assessment subview, and
populates the visible form deterministically; an unmapped result is reported
instead of being assigned to an unrelated first team. When any completed scoped
result exists, the new-analysis form starts collapsed; rerunning remains an
intentional action for changed scope or evidence.

When several components of one vulnerability have their own saved analyzer
result, `Use latest results as draft` uses the current scope. With an active
Team filter, it stages only the filtered team's component results plus one
General reference; it never stages another team's draft. Without a Team filter,
saved or manually edited team assessments are preserved and the latest analyzer
proposal is staged only for teams that are still missing a decision. The
General draft references the effective team blocks and uses their worst state
without duplicating their evidence. An existing independently authored General
assessment remains authoritative in either scope.
Benchmark runs, unfinished runs, and superseded runs of the same component are
never candidates, and components without a team mapping are reported instead of
silently dropped. Staged drafts land in the `Assessment` tab for explicit review
before saving.

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
text directive fallbacks for allowlisted web/package/source research. The
`clone_repository` / `CLONE_REPOSITORY` tool can additionally shallow-clone a
dependent public HTTPS repository into Agentyzer's persistent local cache and
analyze a narrow dependency, symbol, API, or call-path focus. It enumerates and
searches the complete eligible committed tree, then runs matching Git blobs
through the same language-aware import/call-site parsers and structural
extraction used for the primary repository before returning bounded evidence.
It never checks out or executes repository code, rejects credentials and
non-public destinations, and is constrained by host, clone-count, timeout,
repository-size, file-size, analysis-file, and output limits. External source,
comments, documentation, strings, tests, and prompt-like content are explicitly
delimited as untrusted evidence and can never become analyst guidance or change
the task/tool contract. Java dependency discovery covers Maven and Gradle build,
lock, and version-catalog formats.

The primary-repository pipeline also has an `archive_inspector` tool. It
discovers archives contained in the prepared checkout, expands supported
members into an isolated per-analysis workspace, and exposes the resulting
manifests and source files to the normal dependency, version, AST, and code
scanners. Archive contents are never executed. Extraction rejects traversal,
links, special filesystem entries, encrypted members, duplicate files, and
configured size or count limits; malformed archives are recorded as partial
evidence without preventing other archives from being inspected.

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
when the analyzer host and model backend support parallel scans. Agentyzer
serializes shared-cache Git mutations with per-repository filesystem locks and
analyzes configured repositories in detached per-run worktrees, so concurrent
components mapped to the same repository do not share mutable scan files.

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

Set at least the Dependency-Track API key and public URL. For a non-default
gateway:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=http://host.example:8083/dtvp
```

Deployment rules:

- `./data` mounts at `/app/data`; mappings, roles, rules, caches, proposals, and
  archives survive container restarts.
- Compose starts Agentyzer and persists control repositories, worktree locks,
  and transient detached worktrees in the `agentyzer-repos` volume. Populate
  or override the sanitized `agentyzer/config/repos.yaml` before enabling
  automatic scans; never commit repository credentials. Agentyzer immediately
  clones or fetches every explicit URL-backed mapping on startup, refreshes
  those control repositories every `AGENTYZER_REPO_REFRESH_SECONDS`, and fetches
  again immediately before creating an assessment worktree. The periodic pass
  is independent of advisory filtering, so references remain current even when
  an assessment exits before repository preparation.
- Internal services use Compose names and container ports. DTVP reaches
  Dependency-Track at `http://dtrack-apiserver:8080` and Agentyzer at
  `http://agentyzer:8000` unless overridden.
- If proxies are configured, list exact internal hostnames/IPs in `NO_PROXY`;
  do not rely only on CIDR entries.
- DTVP delegates OIDC discovery, state and nonce handling, the authorization-
  code flow with S256 PKCE, token exchange, and JWKS-backed ID-token validation
  to Authlib. Its transient login state lives in a signed, HttpOnly cookie that
  expires after ten minutes. Set a strong `DTVP_SESSION_SECRET_KEY` in every
  deployment. This login is independent of Dependency-Track browser sessions:
  backend calls use `DTVP_DT_API_KEY` and never forward browser credentials.
- API `401` responses move the SPA to sign-in and preserve the current route for
  the OIDC return. Reviewer authorization failures remain `403` errors and do
  not incorrectly log the user out.
- Completed grouped-vulnerability tasks are retained by idle time. Visible
  project tabs renew their lightweight task lease and rebuild an expired task
  automatically after a suspended browser resumes, so details and bulk actions
  do not require a full-page reload.
- Background Dependency-Track refresh tracks a timestamped, bounded set of
  recently viewed projects. Older projects remain on disk and load on demand;
  they no longer receive three upstream refresh calls every minute forever.
- Process-local cache objects and named project searches use LRU limits, and
  completed grouped tasks have a separate retained-count cap. These bounds keep
  long-running and multi-user instances from growing without limit.
- nginx proxies `DTVP_CONTEXT_PATH` to DTVP and defaults it to `/dtvp`.
  `DTVP_HTTP_PORT` changes the host gateway port. Direct-container deployments
  must publish port `8000` and include the context path in the URL.
- The Compose nginx gateway keeps upstream HTTP/1.1 connections open,
  compresses JSON/static text responses, and disables buffering for grouped
  task event streams. Uvicorn keeps those upstream connections for 30 seconds
  and uses a 2048-connection accept backlog.
- `dtvp.boot:app` serves startup status while the real app initializes. Startup
  logs time cache and integration initialization.
- The DTVP and Agentyzer container startup scripts print their packaged project
  versions and image build numbers before importing either application, so this
  deployment identity remains visible in Docker logs even if initialization fails.
- `/api/performance-status` reports grouped-query/build/post-processing
  saturation, retained task counts, process-local cache pressure, and the
  active Python/GIL state.
  API responses include a `Server-Timing: app;dur=...` header for browser and
  proxy latency analysis.
- Reviewers see the Python/GIL state in the application footer and can inspect
  live worker capacity, retained grouped tasks, and cache pressure on the
  Settings **Runtime** tab.
- The frontend image renders `index.html` from its immutable template on every
  start, so frontend URL and context-path changes are restart-safe.

### Python Runtime Images

The default Compose and published DTVP image use the Python 3.14 free-threaded
build. Start it normally:

```bash
docker compose up -d --build
```

`Dockerfile.free-threaded` asks `uv` for the explicit `3.14t` interpreter. It
loads DTVP's native dependencies and verifies the runtime during the image
build. Compose also sets `DTVP_REQUIRE_FREE_THREADED=true`, so the
application refuses to start if it receives a normal interpreter or a native
extension re-enables the GIL. Confirm the live state under `python` in
`/api/performance-status`; `free_threading_active` must be `true` and
`gil_enabled` must be `false`.

See the official [CPython free-threading
guide](https://docs.python.org/3/howto/free-threading-python.html) and [`uv`
Python variant documentation](https://docs.astral.sh/uv/concepts/python-versions/)
for the interpreter guarantees and `3.14t` selector.

Free threading lets DTVP's dedicated CPU worker pools execute Python code on
multiple cores. It does not make Dependency-Track/network I/O faster, and the
free-threaded interpreter has some single-thread overhead. The pipeline builds
and publishes only this validated free-threaded DTVP image. Its canonical tags
are `latest`, release versions, `dev`, and PR tags; no GIL-enabled or duplicate
variant tags are published.

DTVP and Agentyzer release in lockstep from this monorepo. The root
`pyproject.toml` is the single release-version source: Agentyzer derives its
dynamic package metadata from that value, and its container build receives the
same derived value as a build argument. Regenerate both lockfiles after changing
the root version. A manually pushed `v*` tag must match the root packaged
version before either container is published. The single Git tag identifies the
shared source commit; the workflow publishes that version tag and `latest` to
both the `dtvp` and `agentyzer` container packages. Agentyzer's
health/configuration responses read the installed package metadata instead of
a hard-coded API version.

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
| `DTVP_DT_PROJECT_LIST_TTL_SECONDS` | Freshness window for serving the complete cached project list without an upstream request | `30` |
| `DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS` | Idle window for periodic per-project background refresh | `900` |
| `DTVP_DT_ACTIVE_PROJECT_LIMIT` | Most-recent projects eligible for periodic refresh | `8` |
| `DTVP_DT_MEMORY_CACHE_MAX_ENTRIES` | Process-local LRU file-object cache entries; disk files remain persistent | `256` |
| `DTVP_DT_PROJECT_QUERY_CACHE_MAX_ENTRIES` | Process-local named-project query LRU entries | `128` |
| `DTVP_ASSESSMENT_OUTBOX_PATH` | Transactional assessment overlay and synchronization outbox | `<DTVP_DT_CACHE_PATH>/assessment_outbox.sqlite` |
| `DTVP_ASSESSMENT_SYNC_CONCURRENCY` | Global concurrent background assessment writes to Dependency-Track | `4` |
| `DTVP_ASSESSMENT_STRICT_DT_CONFLICTS` | Perform live Dependency-Track conflict reads before accepting assessment saves | `false` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Parallel version fetch limit | `4` |
| `DTVP_ASSESSMENT_IO_CONCURRENCY` | Concurrent Dependency-Track assessment reads or writes per operation | `4` |
| `DTVP_ASSESSMENT_WRITE_MAX_ATTEMPTS` | Attempts for transient assessment-write timeouts, rate limits, and HTTP 5xx responses | `3` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | Completed/failed grouped-task idle retention | `900` |
| `DTVP_GROUPED_VULN_TASK_MAX_RETAINED` | Maximum completed/failed grouped tasks retained in process | `24` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | Persisted summary-index SQLite path | sibling of cache path |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted summary indexes | `64` |
| `DTVP_GROUP_QUERY_WORKERS` | Dedicated grouped-search worker threads | `4` |
| `DTVP_GROUP_QUERY_MAX_PENDING` | Maximum grouped searches queued behind active workers | `8` |
| `DTVP_GROUP_QUERY_CACHE_ENTRIES` | Maximum cached filter combinations per grouped task | `32` |
| `DTVP_GROUP_QUERY_CACHE_BYTES` | Approximate per-task filtered-index and facet-cache budget | `8388608` |
| `DTVP_GROUP_BUILD_WORKERS` | Dedicated CPU workers for grouped snapshot/index construction | `2` |
| `DTVP_GROUP_BUILD_MAX_PENDING` | Group-build jobs admitted behind active build workers before async backpressure | `4` |
| `DTVP_GROUP_POSTPROCESS_WORKERS` | Dedicated workers for automatic-analysis planning after a snapshot completes | `1` |
| `DTVP_GROUP_POSTPROCESS_MAX_PENDING` | Post-processing jobs admitted behind active workers before async backpressure | `2` |
| `DTVP_GROUP_DETAIL_WORKERS` | Reserved workers for full vulnerability detail hydration | `2` |
| `DTVP_GROUP_DETAIL_MAX_PENDING` | Detail hydration jobs admitted before async backpressure | `8` |
| `TEAM_MAPPING_PATH` | Component ownership mapping | `data/team_mapping.json` |
| `TEAM_GROUPS_PATH` | Nested team-group definitions | `data/team_groups.json` |
| `USER_ROLES_PATH` | User-to-role mapping | `data/user_roles.json` |
| `RESCORE_RULES_PATH` | CVSS transition rules | `data/rescore_rules.json` |

### Authentication, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | Optional OIDC client secret for confidential clients | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback | derived from frontend URL/context path |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_DEV_DISABLE_AUTH` | Resolve local requests as `devuser` | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | app `/`; Compose `/dtvp` |
| `DTVP_HTTP_PORT` | Compose nginx host port | `80` |
| `DTVP_UVICORN_KEEP_ALIVE_SECONDS` | Backend upstream keep-alive timeout | `30` |
| `DTVP_REQUIRE_FREE_THREADED` | Fail startup unless CPython supports free threading and its GIL is actually disabled | local Python: `false`; Compose: `true` |
| `DTVP_BOOT_APP` | Real ASGI app loaded by the boot wrapper | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Additional comma-separated CORS origins | unset |
| `DTVP_API_URL` | Frontend API base override; Vite alias `VITE_DTVP_API_URL` | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |
| `BUILD_NUMBER` | Compose image build number, baked into DTVP and Agentyzer startup logs | `unknown` |

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
| `DTVP_CODE_ANALYSIS_DASHBOARD_CACHE_SECONDS` | Shared dashboard status snapshot lifetime | `3` |
| `DTVP_CODE_ANALYSIS_MODEL` | Analyzer model hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_BACKEND` | LLM backend hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_PROVIDER` | LLM provider hint | unset |
| `DTVP_JIRA_CREATE_URL` | Jira create-screen URL | unset |
| `DTVP_ANALYSIS_QUEUE_CAPACITY` | Concurrent DTVP queue items | `1` |
| `DTVP_ANALYSIS_QUEUE_MAX_PENDING` | Maximum pending DTVP queue items before new submissions receive HTTP 429 | `1000` |
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
| `AGENTYZER_REPO_REFRESH_SECONDS` | Background refresh interval for explicit URL-backed repository mappings; `0` disables and positive values have a 60-second minimum | `900` |
| `AGENTYZER_GITHUB_TOKEN` | Optional GitHub token for authenticated advisory lookups and higher API limits | unset |
| `AGENTYZER_ARCHIVE_MAX_INPUT_BYTES` | Maximum input size for one repository archive | `1073741824` |
| `AGENTYZER_ARCHIVE_MAX_ARCHIVES` | Maximum archives inspected per analysis | `25` |
| `AGENTYZER_ARCHIVE_MAX_NESTING` | Maximum nested-archive depth | `2` |
| `AGENTYZER_ARCHIVE_MAX_MEMBERS` | Maximum combined archive member count | `50000` |
| `AGENTYZER_ARCHIVE_MAX_MEMBER_BYTES` | Maximum extracted size of one member | `268435456` |
| `AGENTYZER_ARCHIVE_MAX_EXTRACTED_BYTES` | Maximum combined extracted archive data | `2147483648` |
| `AGENTYZER_LLM_BACKEND` | `ollama` or `openwebui` | `ollama` |
| `AGENTYZER_OLLAMA_HOST` / `AGENTYZER_OLLAMA_MODEL` | Ollama endpoint and model | `http://host.docker.internal:11434` / `mistral` |
| `AGENTYZER_OPENWEBUI_HOST` / `AGENTYZER_OPENWEBUI_MODEL` | OpenWebUI endpoint and model | `http://host.docker.internal:3000` / `mistral` |
| `AGENTYZER_OPENWEBUI_API_KEY` | Optional OpenWebUI bearer token | unset |
| `AGENTYZER_OPENWEBUI_TOOL_CALLS` | Native tool calls: `auto` or `off` | `auto` |
| `AGENTYZER_OPENWEBUI_CONTEXT_WINDOW` | Optional context limit | `0` |
| `AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN` | Reserved token margin | `256` |
| `AGENTYZER_OPENWEBUI_CONTEXT_RETRIES` | Oversized-context retries | `2` |
| `AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS` | Completion budget preserved during compaction | `256` |
| `AGENTYZER_RESEARCH_CLONE_ENABLED` | Allow bounded local dependent-repository inspection | `true` |
| `AGENTYZER_RESEARCH_GIT_HOSTS` | Comma-separated public HTTPS Git host allowlist (`*` permits any public host) | `github.com,gitlab.com,bitbucket.org` |
| `AGENTYZER_RESEARCH_MAX_CLONES_PER_ANALYSIS` | Shared repository-clone budget across one LLM research loop | `3` |
| `AGENTYZER_RESEARCH_CLONE_TIMEOUT_SECONDS` | Clone/inspection Git command timeout | `90` |
| `AGENTYZER_RESEARCH_CLONE_MAX_REPOSITORY_MB` | Maximum cached research-clone disk use | `256` |
| `AGENTYZER_RESEARCH_CLONE_MAX_FILE_BYTES` | Maximum committed file size inspected | `256000` |
| `AGENTYZER_RESEARCH_CLONE_CACHE_TTL_SECONDS` | Freshness window before a research repository is cloned again | `3600` |

When the OpenWebUI context window is configured, Agentyzer uses a conservative
code-oriented token estimate, reserves the requested completion budget, and
pre-compacts oversized messages. If the provider's tokenizer still rejects a
request, both supported OpenWebUI context-error formats are parsed; the reported
limit and request size drive a bounded retry and the learned limit is reused by
later calls. Reachability prompts also cap generated AST evidence at 48,000
characters with an explicit omission marker while retaining complete scan
counts in pipeline evidence.

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
