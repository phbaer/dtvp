# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings
across every version of a project.

It groups findings by vulnerability, shows version-by-version assessment state,
and lets reviewers apply consistent assessments in bulk instead of repeating
the same work on each release.

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

GitHub Copilot support varies by surface. `AGENTS.md`,
`.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`,
and skills directories are not read consistently everywhere. Keep
Copilot-specific instruction files short and pointed back to this README.

## Quick Start

Install dependencies:

```bash
uv sync --dev
cd frontend
npm ci --include=optional
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
| Install frontend dependencies | `cd frontend && npm ci --include=optional` |
| Run Python tests | `uv run pytest` |
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
| `agentyzer/` | Bundled code-analysis service used by Docker Compose and CI image publishing |
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
- Audit-backed repair of assessed findings whose rescored CVSS vector tag was
  lost from Dependency-Track details.
- Optional threat-model rescoring through tmrescore.
- Optional reachability/exploitability code analysis with automatic scans for newly discovered open vulnerabilities.
- Per-vulnerability benchmark comparisons between existing assessments and
  saved Agentyzer assessments, with a 1-5 agreement rating.
- Versioned project archive export/import for Dependency-Track replacement, restore, and retention workflows.
- UI editing for team mappings, user roles, rescore rules, and automatic assessment guidance.
- Local operation with a complete mock Dependency-Track stack.

## Architecture

DTVP is split into:

- A FastAPI backend.
- A Vue single-page frontend.
- Mock external services for local development.

In production, the backend can serve the built SPA from `frontend/dist`.
During development, the backend and Vite frontend usually run separately.

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
| `dtvp/assessment_restore_services.py` | Detection and repair helpers for missing rescored CVSS assessment tags recovered from Dependency-Track audit comments. |
| `dtvp/rescore_rule_services.py` | Data-driven CVSS rule validation, cross-version vector/score synchronization, and bulk preview/apply payload construction. |
| `dtvp/dt_client.py` | Dependency-Track API client. |
| `dtvp/dt_cache.py` | Local Dependency-Track cache and pending update storage. |
| `dtvp/sqlite_migration_services.py` and `dtvp/migrations/` | Lightweight SQLite migration runner and numbered SQL schema files for local stores. |
| `dtvp/project_archive_routes.py` and `dtvp/project_archive_services.py` | Project archive export/import, scheduled snapshots, local downloads. |
| `dtvp/settings_routes.py` | Team mapping, roles, and rescore rule APIs. |
| `dtvp/tmrescore_*` | Threat-model rescoring integration, task state, cache, inventory helpers. |
| `dtvp/code_analysis_*` and `dtvp/analysis_queue_*` | Code-analysis integration and queue runtime. |

Grouped vulnerability tasks are list-first by default:

- `response_mode=summary` avoids downloading heavy per-instance assessment text
  for list views.
- `/api/tasks/{task_id}/events` streams task progress.
- `/api/tasks/{task_id}/groups` serves backend-filtered windows with counts and
  facets.
- `/api/tasks/{task_id}/groups/{group_id}` serves full group details.

Dependency-Track data is persisted in a local cache rooted at
`DTVP_DT_CACHE_PATH`.

The cache stores:

- Project list.
- Per-project findings.
- Project vulnerability details.
- BOMs.
- Local analysis overlays.
- Pending assessment writes.

Startup initializes the cache, then a background sync loop flushes pending
writes, refreshes the project list, and refreshes project versions that have
been accessed. If Dependency-Track is temporarily unavailable, project lookup
falls back to stale cached project data when available. Cached findings and BOMs
continue to serve grouped views until a refresh succeeds.

### Frontend

Important frontend entry points:

| File or directory | Role |
| :--- | :--- |
| `frontend/src/main.ts`, `App.vue`, `router.ts` | Vue app shell, routing, startup handling. |
| `frontend/src/lib/api.ts` | Central backend client and frontend integration types. |
| `frontend/src/types.ts` | Shared frontend domain types. |
| `frontend/src/pages/` | Major pages: dashboard, project review, code analysis, tmrescore, statistics, settings, login. |
| `frontend/src/components/` | Vulnerability rows/details, modals, filters, queue UI, dependency-chain and CVSS components. |
| `frontend/src/lib/` | Composables and helpers for filters, task windows, details, visible rows, assessment updates, project header state, queue state. |

The project vulnerability list renders compact rows from cached
`VulnListItem` metadata. Summary task windows keep list payloads light,
filtering/sorting can run in the backend, visible rows are viewport-windowed,
details hydrate lazily, and grouping progress appears in the filter/status area
while the final list shell is already visible.

DTVP has three startup surfaces:

- `/startup` and `/api/startup` from the backend boot wrapper while the real app loads.
- A static first-paint startup screen in `frontend/index.html`.
- A Vue initialization page while backend metadata, project metadata, and session state load.

### Data And Domain Rules

Team mapping is loaded from `TEAM_MAPPING_PATH`, defaulting to
`data/team_mapping.json`, and can be edited from Settings.

Mapping keys are deterministic component identity selectors:

| Selector | Meaning |
| :--- | :--- |
| `"name"` | Matches a CycloneDX `component.name` case-insensitively when the component is known to have no `component.group`, or when only a name string is available. |
| `"group:name"` | Matches CycloneDX group and name case-insensitively. Use this for names that can appear in multiple ecosystems, such as `"@angular:core"` or `"org.internal:shared"`. |
| `"purl::pkg:type/namespace/name"` | Matches a CycloneDX package URL. Without `@version`, DTVP ignores PURL version, qualifiers, and subpath. With `@version`, `?qualifiers`, or `#subpath`, the full PURL must match. |
| `"cs::name"` and `"cs::group:name"` | Force case-sensitive name or group/name matching. |
| `"cs,purl::pkg:type/namespace/name"` | Forces case-sensitive package URL matching. |
| `"nogroup::name"` | Matches only components whose BOM identity is known and whose `component.group` is empty or absent. It does not match path-only names where group context is unknown. |
| `"cs,nogroup::name"` | Combines exact-case matching with the explicit no-group requirement. |
| `"*"` | Fallback team for otherwise unmapped components. |

Single-colon keys such as `"cs:name"` and `"nogroup:name"` are ordinary
`group:name` selectors for groups literally named `cs` or `nogroup`.
Modifiers always use the `::` separator.

Selector precedence is deterministic:

1. PURL selectors.
2. Grouped selectors.
3. No-group selectors.
4. Plain name selectors.
5. Explicit case-sensitive selectors over case-insensitive selectors at the same specificity.
6. Exact-case matches for remaining ties.
7. Lexicographically first selector key.

Team mapping does not currently match by BOM ref, Dependency-Track component
UUID, or version except when a PURL selector explicitly includes a version. If
a component has a CycloneDX `group`, use `group:name`; a plain `name` mapping
intentionally does not match that grouped component.

Mapping values accept either shape:

- `"Team"` for one primary team.
- `["Primary", "OldName", "OlderName"]` when old assessment tags should
  normalize to the primary team label in reviewer workflows.

Static prompt additions for code-analysis assessments are loaded from
`DTVP_AUTO_ANALYSIS_GUIDANCE_PATH`, defaulting to
`data/auto_analysis_guidance.json`, and can be edited from the Settings Config
tab.

The preferred guidance shape is:

```json
{
  "components": {
    "component-name": "extra guidance"
  }
}
```

Guidance keys use the same selector syntax as team mapping. DTVP matches
guidance against the selected scan target, meaning the team-mapped affected
component or the first explicitly team-mapped parent in a dependency chain. It
does not blindly match guidance against the vulnerable dependency.

Guidance behavior:

- The selected team-mapping selector is preserved on automatic targets and
  echoed in the analyzer guidance block.
- Values may be strings, arrays, or objects with a `guidance` or `prompt`
  field.
- Optional `default` or `*` guidance is prepended to every scan target.
- Manual vulnerability-card submissions append matching guidance for the
  selected component.
- Guidance is reviewer context only. It must not be treated as evidence for
  dependency presence, version, reachability, affectedness, or exclusion unless
  confirmed by code, dependency, SBOM, or fetched source evidence.
- DTVP reads the file when planning scans, so changes apply without a backend
  restart.
- If changed guidance alters automatic scan context, queued or recently
  finished automatic entries for the same vulnerability/component are replaced
  on the next grouping or sweep. Running scans keep the prompt they started
  with.

Other domain rules:

- Assessment details are structured text blocks with headers such as
  `[Team: ...]`, `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`,
  `[Rescored: ...]`, `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- Assessed findings that still have rescoring evidence but are missing an
  explicit `[Rescored Vector: ...]` tag are marked inconsistent. Reviewers can
  bulk restore the sole historical vector, or the strictly newest historical
  vector when an assessment was rescored more than once, from Dependency-Track
  analysis comments while preserving the current state, justification,
  suppression, and details text. Ambiguous or undated histories remain visible
  in the restore preview for manual review but are not applied automatically.
  Restore apply shows an indeterminate in-progress state while Dependency-Track
  is updating, then keeps a completion report open with restored,
  queued-for-retry, failed, and per-finding error details. An outer HTTP 405 is
  identified as a frontend/backend route or proxy method mismatch; downstream
  Dependency-Track 405 responses remain visible in the queued result details.
- Inconsistent groups carry one or more indexed reasons: missing rescoring
  vector metadata, differing analysis states, differing structured team
  assessments, or differing substantive assessment details. The project view
  can filter on these reasons; multiple selected reasons use OR semantics and
  still combine with other filter categories using AND semantics.
- A non-`NOT_SET` General block takes precedence in aggregate assessment state.
  Otherwise DTVP chooses the worst team state using the priority in
  `dtvp/logic.py`.
- Rescored CVSS vectors preserve original base metrics so
  threat/environment changes do not silently mutate base metrics. Sanitizing
  those vectors uses the correct base-metric set for CVSS 2.0, 3.0/3.1, and
  4.0, and preserves the original exact version instead of rewriting 3.0 as
  3.1. Cross-version vectors stay visible for manual review.
- CVSS rescore rules are loaded from `RESCORE_RULES_PATH`, defaulting to
  `data/rescore_rules.json`. The shipped `NOT_AFFECTED` and `FALSE_POSITIVE`
  transitions define actions for CVSS 2.0, 3.0, 3.1, and 4.0. Each version's
  `metric_rules` entry defines its base metrics, serialization order, undefined
  values, and base/modified/requirement relationships. The settings API rejects
  rule files that omit or contradict this schema. Both shipped transitions
  produce an exact rescored score of `0.0` for every supported CVSS version;
  CVSS 4.0 therefore clears all vulnerable-system and subsequent-system impact
  metrics.
- Rule application processes configured modified relationships before their
  requirement relationships. A relationship with a modified metric retains
  its requirement only while that override is effective; a relationship
  without one (CVSS 2.0 in the shipped rules) applies directly to its base
  metric. Redundant modified values and orphaned requirements are removed by
  both calculator cleanup and bulk synchronization without inferring metric
  pairings from their names.
- Existing rescored vectors that do not match the configured actions show a
  `Sync rules` control in the CVSS calculator. It stages the corrected vector;
  the reviewer then uses the normal `Apply` action to persist it across the
  finding instances.
- Reviewers also get a project-header `Sync CVSS Rules` action when a completed
  project task contains non-compliant findings. Its server-side preview shows
  current and proposed vectors/scores per group, auto-selects safe repairs, and
  leaves malformed, cross-version, or incomplete-identity findings for manual
  review. Apply recomputes the preview, preserves assessment state,
  justification, suppression, and explanatory text, refreshes active task
  snapshots, and reports successful, queued, and failed Dependency-Track
  updates. The endpoints are
  `POST /api/assessments/rescore-rule-preview` and
  `POST /api/assessments/rescore-rule-apply`.
- Dependency relationships and paths come from CycloneDX BOM dependency graphs.
- Dependency-Track attribution timestamps are preserved as `attributed_on` and
  can be filtered by age in the project view.
- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`,
  `RESOLVED`, `FALSE_POSITIVE`, and `NOT_AFFECTED`.

## Key Workflows

### Project Review

The project view groups vulnerabilities by CVE or vulnerability ID across all
selected project versions. Reviewers can:

- Search and filter by lifecycle, specific inconsistency reason, analysis state,
  attribution age, assignee, and automatic-assessment status.
- Inspect dependency paths and team ownership.
- Open a vulnerability detail card.
- Apply synchronized global or team-specific assessments across matching
  Dependency-Track findings.
- Limit Bulk Sync candidates with the active vulnerability-list filters and
  review explicit missing-coverage or inconsistency reasons before applying.
- Preview and bulk-apply audit-trail repairs for missing rescored CVSS vectors.
- Preview and bulk-apply configured CVSS rule synchronization across all
  findings in the completed project task.

Backend task windows keep large projects responsive:

- Summary results seed compact list rows before full details are hydrated.
- Partial version results appear while grouping continues.
- Assessment and team-mapping writes refresh active task windows.
- Task statistics can be reused when switching to the statistics view.
- The header keeps the last vulnerability-list route, including filters, so
  users can return from statistics and code-analysis pages with `Vuln List`.
- Cached project views reuse the loaded vulnerability list when returning to
  the same project or vulnerability card.

The loading path is deliberately incremental:

- The preparation placeholder mirrors task progress, current loading steps, and
  recent task log entries.
- Running summary tasks publish partial list windows at bounded progress
  checkpoints.
- Backend filtering reuses the in-memory query index for visible windows,
  counts, and facets.
- CPU-heavy grouping, summary/index construction, and filtering run outside the
  async event loop so task status and event streams keep updating.
- Summary tasks skip full dependency-chain expansion. Detail requests hydrate
  paths lazily for the selected group, and BOM processors memoize repeated
  tag/path lookups.
- The frontend coalesces partial-window refreshes so the newest useful result
  wins while current progress stays visible.

Expanded vulnerability cards are organized into tabs:

| Tab | Purpose |
| :--- | :--- |
| Overview | Advisory description, external references, affected components, team ownership, and dependency context. |
| CVSS & Rescoring | Reviewer CVSS calculator, original/proposed/rescored vectors, tmrescore reasoning, and latest analyzer CVSS proposal notes. |
| Assessments | Current Dependency-Track assessment blocks. |
| Code Analysis | Component selection, Analyze action, queue/history, decision, draft diff, evidence badges, ticket draft, and analysis artifacts. |
| Review | Selected global/team assessment form and persisted review context. Ticket reference is required only when the current rescored severity is High or Critical. |
| Team Mapping | Reviewer-only scrollable component list for adding or editing component team tags. |

The card header keeps the decision state, team and target context, CVSS score
chip, and local unsaved-draft marker visible. The expanded sticky bar keeps
icon-labeled tab navigation and the Apply action visible; switching away from a
card with a local draft prompts the user to apply it first.

### Project Archives

Reviewer-only archives preserve or restore project versions, SBOMs, findings, vulnerability details, and normalized assessments.

- Export starts with `POST /api/project-archives/exports`.
- Import preview starts with `POST /api/project-archives/imports`.
- Applying an import uses `POST /api/project-archives/imports/{task_id}/apply` with `mode=create_missing` or `mode=update`.
- Archive schema is `dtvp.project-archive/v1`; newer DTVP versions must keep importing v1.
- Stored archives are listed from `GET /api/project-archives/snapshots`.
- Archive ZIPs default to `data/project_archives`.
- Optional expanded archive trees for Git history default to `data/project_archives_git`.

Restore matching uses project name/version first. When Dependency-Track UUIDs
change, DTVP remaps assessments by component purl/name/version/bom-ref and
vulnerability ID/name/aliases. Dependency-Track audit history and comments are
not replayed.

Backend-native bulk preview/apply endpoints remain the main future scale
improvement for incomplete-assessment synchronization. Today the bulk incomplete
modal can use backend-filtered detail windows, but still drains full details
into the browser before acting.

### Threat-Model Rescoring

Set `DTVP_TMRESCORE_URL` to enable tmrescore entry points.

Users can open a project, choose `Threat Model`, upload a `.tm7` file plus
optional `items.csv`, analysis config, or MITRE countermeasures inputs, and
cache proposal snapshots for reviewer rescoring dialogs. The threat-model
workspace scrolls within the project shell so upload and analysis controls
remain reachable on short viewports. DTVP uses vscorer's current
session/inventory REST contract:

- Pipeline progress from `step` / `total_steps` is normalized into the DTVP
  progress bar while legacy percentage responses remain accepted.
- Chain analysis, prioritization, what-if, MITRE ATT&CK enrichment, offline
  mode, and provider-neutral LLM enrichment are available as run options.
  MITRE enrichment can include an uploaded countermeasures YAML.
- LLM availability, provider, and configured model come from vscorer's `llm_*`
  health fields, with the legacy Ollama health flag retained as a compatibility
  fallback. DTVP shows the vscorer model as read-only context and does not send
  a model override with analysis requests.
- The frontend resolves generated downloads from vscorer's
  output-name-to-URL map. A `skeptic_gate_failed` response is terminal and
  shown as requiring manual review rather than being polled indefinitely.

SBOM modes:

- `Latest only`: single-version latest snapshot.
- `Merged multi-version SBOM`: recommended for DTVP, with separate roots per version so historical findings stay visible without pretending they belong to the latest inventory.

DTVP intentionally does not mix latest SBOM components with vulnerabilities found only in older versions.

### Code Analysis

Set `DTVP_CODE_ANALYSIS_URL` to enable reachability and exploitability
analysis. Scans run through DTVP's in-process queue and send the analyzer:

- Vulnerability ID and target component.
- CVSS vector.
- Reviewer guidance.
- Affected product versions from the vulnerability card.
- Optional dependency context.
- Optional TMRescore/vscorer guidance.
- Optional LLM metadata hints.

Final analyzer verdicts pass through a deterministic claim audit before DTVP
maps them to Dependency-Track assessment fields. The audit normalizes the final
verdict, final reasoning, and structured pipeline evidence into comparable
claims, records any claim issues on the audit view, challenges unsupported
downgrades, restores original CVSS scoring when unsupported downgrades are
removed, keeps the final verdict step aligned with guarded verdicts, and catches
internally inconsistent final reasoning such as affected-version claims paired
with an already-satisfied fixed-version floor.

#### Result Store

Completed queue results are persisted in SQLite at
`DTVP_CODE_ANALYSIS_RESULTS_PATH`, defaulting to
`data/code_analysis_results.sqlite`.

The result store keeps completed assessment payloads, compact summaries,
parent/follow-up links, queue IDs, analyzer job IDs, model metadata, and
project/vulnerability/component context after operational queue rows are
cleared or pruned.

Store details:

- Schema migrations live in `dtvp/migrations/code_analysis_results`.
- Applied migration versions and checksums are tracked in SQLite
  `schema_migrations`.
- If an older `code_analysis_results.json` cache exists beside the configured
  store path, DTVP imports it into SQLite on first use and leaves the JSON file
  as a legacy snapshot.
- Result retention and privacy are controlled by
  `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS`,
  `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS`, and
  `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE`.

Result APIs:

- `GET /api/code-analysis/results`
- `GET /api/code-analysis/results/{run_id}`
- `DELETE /api/code-analysis/results/{run_id}`
- `POST /api/code-analysis/results/{run_id}/compact`
- `POST /api/code-analysis/results/{run_id}/benchmark`
- `GET /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-results`

#### Assessment Benchmarks

Reviewers start one normal `Analyze` run from a vulnerability card. Analysis
runs are saved in the normal code-analysis result history; there is no separate
benchmark scan action because it would execute the same Agentyzer source-analysis
pipeline. Historical/API-created queue items with `source=benchmark` remain
supported for compatibility.

When a saved run is selected and an existing assessment is available, DTVP
automatically compares the two, regardless of whether that assessment was
created by a person or automation. DTVP computes deterministic anchors for
state, justification, CVSS score/vector, and basic evidence differences, then
asks Agentyzer `POST /benchmark/compare` to judge the free-text reasoning
probabilistically. If Agentyzer or its LLM backend is unavailable, DTVP returns
the deterministic fallback and labels the evaluator as `DTVP fallback`. If the
existing assessment is `NOT_SET`, analysis still runs but no benchmark is
requested or displayed.

Benchmark ratings use a canonical numeric score. The optional letter grade in
API responses is only a display alias derived from that score:

- `5 / A`: strong semantic agreement.
- `4 / B`: aligned outcome with minor reasoning, evidence, or CVSS differences.
- `3 / C`: partial agreement or inconclusive baseline/result.
- `2 / D`: weak match with important disagreement.
- `1 / F`: direct contradiction, especially affected versus not-affected.

#### Automatic Dedupe

Automatic scans deduplicate against both the persisted result cache and the
live queue.

DTVP stores a deterministic context fingerprint based on:

- Vulnerability group.
- Selected target component.
- Affected project versions.
- Component identities.
- Dependency snippets.
- Vulnerability aliases.
- CVSS vector.
- Configured component-specific auto-assessment guidance.

A saved result suppresses a new automatic scan only while the fingerprint still
matches. Changed project versions, vulnerability context, or static guidance
are treated as stale and can be scanned again.

`DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` can also age out otherwise matching
results. The default `0` relies on fingerprint freshness only.

#### Vulnerability Card Workspace

The project vulnerability card is the main assessment workspace for analyzer
output. The Code Analysis tab stays mounted while hidden, so saved runs,
selected results, and prompt drawers survive tab switches.

The Code Analysis tab is organized as:

1. Scan controls with component selection and one `Analyze` action.
2. Active queue items and compact saved run history.
3. The assessment decision and its evidence-quality badges.
4. A `Summary` drawer, opened by default, containing the rationale, final
   reasoning, and follow-up question controls.
5. A separate artifact-style `Assessment Draft` drawer, opened by default,
   with the state, justification, details, CVSS, and assignee diff.
6. A separate `Assessment Benchmark` drawer, opened by default when a saved run
   is selected and a prior assessment exists. It compares the existing
   assessment with the analysis result side by side, emphasizing their CVSS
   scores and vectors. State, justification, CVSS-score, and CVSS-vector
   agreement are rendered as explicit comparison states with green aligned,
   red different, or amber review icons; DTVP does not offer or request a
   benchmark when the existing assessment state is `NOT_SET`.
7. Per-component result cards for multi-target assessments.
8. A separate, initially collapsed `Ticket Draft` drawer.
9. `Analysis Artifacts` drawers for version coverage, raw `LLM Conversation`,
   and pipeline evidence.

Expandable assessment and artifact sections use one bordered card whose body
extends below the header, rather than separate header and content boxes.

Artifact details:

- Single-component coverage rows fall back to the selected analysis target.
- Product-version cells distinguish DTVP affected-version ref checks from
  current-workspace or lock-file rows.
- The `LLM Conversation` drawer shows captured `llm_conversation` data as a
  compact chat-style transcript.
- Transcript bubbles distinguish static prompt-bundle content, dynamic
  vulnerability/advisory content, source/dependency context, analyst guidance,
  generated LLM answers, and tool activity.
- Tool activity includes web searches, URL downloads, package lookups, source
  fetches, and returned research results.
- Before a traced run is available, the drawer can fetch configured analyzer
  prompt bundle values through `GET /api/code-analysis/prompts`.

Card actions:

- Load a previous run into the result panel.
- Remove saved runs from history.
- Use a result as an editable assessment draft.
- Automatically compare a selected saved run against the current existing
  assessment when one is available.
- Submit follow-up questions linked to a parent run.
- Start additional non-duplicate component scans while other scans for the same
  vulnerability are queued or running.
- Cancel queued scans and request aborts for running scans.

Manual card scans append matching static component guidance before the queue
item is stored. They also pass every affected project version as
`affected_product_versions` so the analyzer can try to match product versions
to repository tags or release branches. Tag matching accepts both `v1.2.3` and
`1.2.3` forms for the same product version.

When a result says the product is affected, the card shows a copyable Markdown
ticket draft focused on developer action: vulnerability, affected
product/component context, vulnerable dependency, attack surface or dependency
chain, remediation, and validation steps. The fallback ticket renderer for
older results avoids analyzer runtime details and targets the vulnerable
dependency or direct parent dependency.

Set `DTVP_JIRA_CREATE_URL` to show a `Create Jira issue` action beside the
ticket draft. The action copies the complete draft and opens the configured
Jira create screen in a new tab. Jira uses its existing browser/SSO session;
DTVP does not read or forward Jira cookies. The URL may be absolute, such as
`https://jira.example/secure/CreateIssue!default.jspa`, or root-relative when
Jira and DTVP share a gateway. The generated vulnerability text stays out of
the URL and must be pasted into the Jira description. When running the Vite
development frontend directly, use the equivalent
`VITE_DTVP_JIRA_CREATE_URL` variable.

Submitted scans and follow-ups are reconciled by queue ID after submission and
polling refreshes. A run that finishes before the first poll still updates and
selects the matching history row without a page reload.

Follow-up queue items use `source=follow-up`, preserve `parent_run_id`, and
include bounded parent context. When the analyzer supports
`/jobs/{job_id}/follow-up`, DTVP asks it to reuse the parent job context and
sends only the analyst's extra note. Otherwise DTVP falls back to a normal
assessment request with compacted persisted context.

#### Code Analysis Dashboard

The header `Code Analysis` page is an operations dashboard, not a duplicate
assessment editor.

It shows:

- DTVP queue state and execution slots.
- Latest saved results and result-cache retention/privacy policy.
- External analyzer health, jobs, execution slots, active agents, and progress.
- Configured or reported model.
- LLM backend/provider metadata.
- Analyzer configuration/backend details.
- Automatic sweep status.
- Queue controls.

Queue items and saved result rows keep optional project context, so dashboard
rows can jump back to the matching project vulnerability detail with
`?vuln=...`.

Each queue item has an on-demand scan log expansion directly under the row. The
log uses the full queue-table width and combines structured entries from DTVP
lifecycle events, analyzer `logs`/`events`/`messages` fields, and live progress
activities from agentyzer-style status payloads. Expanded logs auto-scroll to
the newest line and use text-only level colors.

Queued scans can be cancelled, finished scans can be cleared, and running scans
can be aborted when the configured analyzer accepts `DELETE /jobs/{job_id}`. If
the analyzer independently reports `cancelled`, DTVP treats the queue item as
terminal. If the analyzer refuses a running abort, DTVP keeps the item running
and surfaces the refusal.

#### Agentyzer

Agentyzer is included under `agentyzer/`. Docker Compose starts it as the
default code-analysis backend at `http://agentyzer:8000` and exposes it on host
port `8095` by default. The PM2 development stack still uses
`test_setup/mock_code_analysis.py` on port `8095` so local UI work does not
require a live LLM backend.

Agentyzer endpoints used by DTVP:

- `POST /jobs/{job_id}/compact` for completed-job compaction.
- `POST /jobs/{job_id}/follow-up` for parent-context follow-up runs.
- `GET /prompts` for prompt inspection. Prompt values are omitted unless
  `include_values=true` is requested.

Completed assessment responses include `llm_conversation`, a per-call trace of
messages sent to the configured LLM backend and assistant responses returned by
it.

OpenWebUI research calls can use native OpenAI-style tool calls when
`OPENWEBUI_TOOL_CALLS=auto`. The model can request `search_web`, `fetch_url`,
`fetch_package`, or `fetch_source` structurally; Agentyzer executes those
requests locally through allowlisted handlers, records assistant tool calls and
returned `tool` messages, and falls back to the text `FETCH_*` protocol when
native calls are unavailable.

Compacted contexts include bounded result summaries, CVSS reasoning, structured
assessment views, step findings, and evidence snippets. Agentyzer caps rendered
follow-up context and emits model-wait heartbeats during LLM-bound stages so
DTVP polling can show that the analyzer is still waiting for the model. The
OpenWebUI backend retries one transient remote stream disconnect before
reporting the model call as unavailable.

These Agentyzer endpoints are optional from DTVP's perspective because the
persisted DTVP result cache can supply fallback context.

DTVP and Agentyzer both default to one running scan because the packaged stack
usually has one LLM backend. Raise `DTVP_ANALYSIS_QUEUE_CAPACITY` and
`AGENTYZER_MAX_CONCURRENT_JOBS` together only when the analyzer, model backend,
and repository workspaces can handle parallel scans.

#### Prompt And Verdict Rules

Agentyzer prompt bundles are written for reproducible, conservative
assessments.

Prompt behavior:

- All Agentyzer LLM prompts live in dedicated YAML prompt bundles under
  `agentyzer/config/prompts/`; runtime overrides can provide matching files via
  `AGENTYZER_CONFIG_DIR/prompts`.
- Reachability, deep-analysis, transitive-analysis, and final-verdict prompts
  use compact `analysis_protocol` sections instead of bundled few-shot example
  transcripts.
- Benchmark comparison uses the `benchmark_comparison` prompt bundle and never
  asks the model to fetch source or rerun repository analysis.
- The model keeps its analysis private and emits only structured fields with
  evidence anchors.
- Response contracts list exact output fields, allowed values, evidence labels,
  and the ban on markdown, JSON, preambles, or extra fields.
- Legacy custom prompt overrides that still provide `few_shot` are mapped to
  `analysis_protocol` for compatibility.

Verdict behavior:

- Final verdict reasoning remains usable as developer ticket summary material
  with Desc, Surface, Evidence, Fix, and Validate guidance.
- An affected-range dependency version without confirmed direct reachability,
  deep exploitability, or a positive transitive path is capped at
  `Probably Affected` with medium confidence. Version presence alone cannot
  produce a confirmed `Affected` verdict.
- Transitive and verdict prompts require a source/search fetch before unresolved
  intermediary or advisory facts can drive `UNCERTAIN` or a `Not Affected`
  downgrade.
- If a dependency is only SBOM/input-attributed, not rediscovered locally, and
  no concrete version was checked, Agentyzer prevents an unsupported
  `Not Affected` result and reports unresolved triage instead.
- If static guidance identifies a framework/platform such as Keycloak, the
  vulnerable dependency is only SBOM-attributed, and every checked version
  remains unknown, final verdicting performs a mandatory upstream-platform
  search before accepting an inconclusive or downgrade-style result. Successful
  results from that mandatory lookup are treated as upstream-platform evidence,
  not as local reachability evidence: they can support `Probably Affected` with
  medium confidence even when local analysis excludes the checked codebase, but
  cannot by themselves support a confirmed `Affected` verdict. Static guidance
  without successful research remains non-evidentiary.

The LLM research loop supports native OpenAI-style tool calls plus text
`FETCH_SEARCH`, `FETCH_URL`, `FETCH_PACKAGE`, and `FETCH_SOURCE`, including
malformed inline requests such as `Validate: FETCH_SEARCH ...`. Public web
search tries DuckDuckGo Lite, DuckDuckGo HTML, and Bing result pages so provider
challenge pages can be bypassed or reported explicitly.

Java dependency/version discovery handles Maven `pom.xml`, Gradle Groovy/Kotlin
build files, Gradle dependency lockfiles, and Gradle version catalogs, including
Maven namespace/property resolution and common `group:artifact:version`
notations.

#### Automatic Scanning

Automatic scanning is enabled only when both
`DTVP_AUTO_CODE_ANALYSIS_ENABLED=true` and code analysis is configured. DTVP
queues genuinely new open groups, not every finding.

Automatic scan rules:

- Opening or refreshing a project queues newly discovered open grouped
  vulnerabilities.
- A scheduled sweep checks cached findings and live projects every
  `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` seconds.
- The scheduled sweep waits one interval after process startup before its first
  run.
- Whole-cache sweep discovery runs in a dedicated single-worker thread and
  returns an immutable queue plan to the FastAPI event loop.
- Reviewers can trigger an immediate sweep from the Code Analysis dashboard;
  the trigger returns while the worker continues in the background.
- A group is auto-open only when every grouped instance is `NOT_SET` and has no
  assessment detail text.
- Automatic and manual scan targets are limited to components with explicit
  team mappings, or the first explicitly team-mapped parent on a dependency
  path.
- Wildcard mappings do not create scan targets.
- Groups with any global, team, or legacy plaintext assessment are treated as
  handled.
- Stale automatic queue items are cancelled when a group becomes handled or no
  longer has an eligible owned target. Manually requested scans are left alone.

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
| Python tests, including Agentyzer | `uv run pytest` |
| Agentyzer-only tests | `cd agentyzer && uv run pytest` |
| Frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Frontend unit tests in Podman | `sh scripts/run-frontend-tests-podman.sh unit` |
| README screenshot capture and manual UI docs flow | `cd frontend && npm run test:ui:docs` |
| Frontend UI tests against local stack | `pm2 start ecosystem.config.js --update-env && cd frontend && npm run test:ui` |
| Frontend UI tests in Podman | `sh scripts/run-frontend-tests-podman.sh ui` |
| Real-stack threat-model manual flow | `pm2 start ecosystem.config.js --update-env && cd frontend && npm run test:ui:real-stack -- --grep "Threat-Model UI Flow"` |
| Real-stack code-analysis manual flow | `pm2 start ecosystem.config.js --update-env && cd frontend && npm run test:ui:real-stack -- --grep "Code Analysis UI Flow"` |

The README screenshots are generated by `frontend/e2e/capture-readme-screenshots.manual.ts` and written under `docs/screenshots`.

The apply-conflict dialog can be tested manually by editing the same finding
from two sessions or by forcing a server-side mock Dependency-Track change
before submitting. The saved screenshot is
`docs/screenshots/conflict-resolution.png`.

## Docker Deployment

Create and edit the environment file:

```bash
cp .env.dist .env
```

For a remote host or non-default gateway port, set the public URL and host port in
`.env`. For example:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=http://192.168.128.117:8083/dtvp
```

Start the packaged deployment:

```bash
docker compose up -d
```

Compose runtime notes:

- `./data` is mounted into `/app/data`, so mapping files, role files, cache
  data, tmrescore proposals, and project archives persist across container
  restarts.
- The frontend image build copies the canonical `data/rescore_rules.json` into
  its build stage because `vue-tsc` also type-checks the rule-engine tests.
- The bundled `agentyzer` service is started by default.
- Cloned analysis workspaces persist in the `agentyzer-repos` Docker volume.
- DTVP points at `http://agentyzer:8000` unless `DTVP_CODE_ANALYSIS_URL` is
  overridden.
- Inside the Compose network, DTVP and nginx reach Dependency-Track at
  `http://dtrack-apiserver:8080`. Host-facing ports are separate from
  container-to-container ports.

Proxy and authentication notes:

- If `HTTP_PROXY` or `HTTPS_PROXY` is set, make `NO_PROXY` include the exact
  internal hosts or IP addresses for Dependency-Track, tmrescore, Agentyzer,
  and any reverse-proxy host that should be reached directly.
- Do not rely on CIDR-only `NO_PROXY` entries for DTVP's Python HTTP clients.
  For example, use
  `NO_PROXY=192.168.128.117,127.0.0.1,::1,vscorer,agentyzer,vp.apps.ge-healthcare.net`
  rather than only `192.168.0.0/16`.
- DTVP authentication is independent from Dependency-Track browser sessions.
  Users authenticate through DTVP's configured OIDC flow.
- Backend Dependency-Track API calls use `DTVP_DT_API_KEY`; incoming browser
  cookies and bearer headers are not forwarded to Dependency-Track.

Agentyzer ships with an empty sanitized component registry at
`agentyzer/config/repos.yaml`. Populate that file, or mount an
environment-specific replacement with a Compose override, before enabling
automatic code analysis. Do not put repository credentials in public branches;
the dashboard only shows sanitized repository configuration.

Context-path and startup notes:

- The bundled nginx gateway proxies `DTVP_CONTEXT_PATH` to DTVP, `/api` to
  Dependency-Track, and other paths to the Dependency-Track frontend.
- Compose defaults `DTVP_CONTEXT_PATH` to `/dtvp`.
- Setting `DTVP_CONTEXT_PATH=/dtvp-stage` makes nginx forward `/dtvp-stage/` to
  the DTVP container.
- Compose publishes nginx on host port `80` by default. Set
  `DTVP_HTTP_PORT=8083` to open `http://host:8083`.
- `dtvp.boot:app` lets Uvicorn bind before the full app imports and serves
  startup endpoints, such as `/dtvp/api/startup` or
  `/dtvp-stage/api/startup`, until initialization completes.
- If `DTVP_CONTEXT_PATH` is changed outside Compose, route health checks and
  reverse-proxy paths to that context path.
- The DTVP container serves a 200 response at `/` that redirects browsers to
  the configured context path, so root probes do not receive a 404.
- Startup logs include timings for the tmrescore cache load, Dependency-Track
  cache initialization, and final runtime-ready point. Slow mounted data or
  pending updates will show up there.

The container image keeps `frontend/dist/index.html.template` and renders
`frontend/dist/index.html` from that template on every start. Context-path and
frontend-url changes are therefore restart-safe; the generated `index.html` is
not used as the next boot's source template.

If you run the DTVP image directly instead of through the bundled nginx service,
publish the container's Uvicorn port and include the context path in the browser
URL:

```yaml
ports:
  - "8083:8000"
environment:
  - DTVP_CONTEXT_PATH=/dtvp-stage
  - DTVP_FRONTEND_URL=https://dt.vp.apps.ge-healthcare.net
```

With that shape, the direct container URL is
`http://host:8083/dtvp-stage`; the public reverse-proxy URL should route
`https://dt.vp.apps.ge-healthcare.net/dtvp-stage` to the same container.

### Docker Archive Setup

Manual archive exports work after `DTVP_DT_API_KEY` is configured with
permissions to read projects, findings, vulnerabilities, and BOMs. Imports also
need BOM upload and vulnerability-analysis update permissions.

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
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081`; Compose default `http://dtrack-apiserver:8080` |
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
| `DTVP_CONTEXT_PATH` | Application mount path; Docker Compose also uses it for the nginx route | app default `/`, compose default `/dtvp` |
| `DTVP_HTTP_PORT` | Docker Compose nginx gateway host port | `80` |
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
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | Completed/failed tmrescore task retention | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | External or mock code-analysis base URL | unset; Compose defaults to `http://agentyzer:8000` |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | Code-analysis HTTP timeout | `300` |
| `DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS` | Short timeout for dashboard health/jobs polling so a stuck analyzer cannot hang the UI | `5` |
| `DTVP_CODE_ANALYSIS_MODEL` | Model hint sent to the analyzer and shown on the dashboard when available | unset |
| `DTVP_CODE_ANALYSIS_LLM_BACKEND` | LLM backend hint shown on the dashboard and sent with analysis requests | unset |
| `DTVP_CODE_ANALYSIS_LLM_PROVIDER` | LLM provider hint shown on the dashboard and sent with analysis requests | unset |
| `DTVP_JIRA_CREATE_URL` | Jira create-screen URL used by the ticket-draft action; the browser's existing Jira session handles authentication | unset |
| `DTVP_ANALYSIS_QUEUE_CAPACITY` | Maximum number of code-analysis queue items DTVP runs at the same time | `1` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | Completed/failed code-analysis queue item retention | `3600` |
| `DTVP_CODE_ANALYSIS_RESULTS_PATH` | SQLite store for completed code-analysis results and compact follow-up context. Legacy `.json` paths import into a sibling `.sqlite` file. | `data/code_analysis_results.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` | Maximum persisted code-analysis result records kept in the SQLite store | `2000` |
| `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS` | Maximum age for persisted result records; `0` disables age pruning | `0` |
| `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE` | Persist reviewer guidance/follow-up prompt text in the result cache; set false to redact it | `true` |
| `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` | Maximum age for persisted results to suppress automatic re-scans; `0` relies on context fingerprints only | `0` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Queue scans for newly discovered fully unassessed grouped vulnerabilities | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Sweep interval for cached/live open vulnerability discovery | `900` |
| `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` | Static per-component prompt additions for automatic and manual vulnerability-card code-analysis assessments | `data/auto_analysis_guidance.json` |
| `AGENTYZER_PORT` | Host port for the bundled Compose Agentyzer service | `8095` |
| `AGENTYZER_LOG_LEVEL` | Agentyzer service log level | `INFO` |
| `AGENTYZER_MAX_CONCURRENT_JOBS` | Maximum number of Agentyzer assessment pipelines executing at the same time | `1` |
| `AGENTYZER_LLM_BACKEND` | Agentyzer LLM backend, `ollama` or `openwebui` | `ollama` |
| `AGENTYZER_OLLAMA_HOST` | Ollama base URL used by the Compose Agentyzer service | `http://host.docker.internal:11434` |
| `AGENTYZER_OLLAMA_MODEL` | Ollama model used by Agentyzer | `mistral` |
| `AGENTYZER_OPENWEBUI_HOST` | OpenWebUI base URL used by Agentyzer | `http://host.docker.internal:3000` |
| `AGENTYZER_OPENWEBUI_MODEL` | OpenWebUI model used by Agentyzer | `mistral` |
| `AGENTYZER_OPENWEBUI_API_KEY` | Optional OpenWebUI bearer token | unset |
| `AGENTYZER_OPENWEBUI_TOOL_CALLS` | Native OpenAI-style tool calls for OpenWebUI research loops, `auto` or `off` | `auto` |
| `AGENTYZER_OPENWEBUI_CONTEXT_WINDOW` | Optional OpenWebUI model context window in tokens; enables preflight prompt compaction when set, for example `131072` | `0` |
| `AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN` | Token margin reserved below the configured or reported OpenWebUI context limit | `256` |
| `AGENTYZER_OPENWEBUI_CONTEXT_RETRIES` | Context-length retry attempts after OpenWebUI rejects an oversized request | `2` |
| `AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS` | Minimum completion budget preserved when Agentyzer truncates oversized OpenWebUI prompt context | `256` |

## SBOM

The DTVP container image includes CycloneDX SBOM files for the frontend and
backend build. The app exposes the combined SBOM at `/api/sbom` and
`/api/sbom/html`, and the footer links "Download CycloneDX SBOM". CI also
uploads an Agentyzer CycloneDX SBOM artifact when publishing images.

The SBOM includes production frontend dependencies from `frontend/package.json`
and `frontend/package-lock.json`, plus backend dependencies from `pyproject.toml`
and `uv.lock`. Test and development dependencies are excluded by design.

## Screenshots And Docs

The dedicated screen guide describes each captured UI state: `docs/screens.md`.

| Area | Screenshot |
| :--- | :--- |
| Login | `docs/screenshots/login.png` |
| Dashboard | `docs/screenshots/dashboard.png` |
| Project review | `docs/screenshots/project-view.png` |
| Lifecycle badges | `docs/screenshots/lifecycle-badges.png` |
| Vulnerability card overview | `docs/screenshots/vuln-card-overview.png` |
| Assignee chips and approval | `docs/screenshots/assignee-chips-approve.png` |
| Assignee filter | `docs/screenshots/assignee-filter.png` |
| Automatic assessment filter | `docs/screenshots/automatic-assessment-filter.png` |
| User assignment form | `docs/screenshots/user-assignment-form.png` |
| Review context | `docs/screenshots/vuln-card-review-context.png` |
| Inconsistent assessment | `docs/screenshots/inconsistent-assessment.png` |
| Team mapping | `docs/screenshots/vuln-card-team-mapping.png` |
| Rescored CVSS | `docs/screenshots/rescored-cvss.png` |
| CVSS & Rescoring tab | `docs/screenshots/vuln-card-cvss-rescoring.png` |
| CVSS calculator | `docs/screenshots/cvss-calculator.png` |
| Bulk sync modal | `docs/screenshots/bulk-sync-modal.png` |
| Conflict resolution | `docs/screenshots/conflict-resolution.png` |
| Statistics | `docs/screenshots/statistics.png` |
| Statistics sidebar | `docs/screenshots/statistics-sidebar.png` |
| Settings | `docs/screenshots/settings.png` |
| Settings archives | `docs/screenshots/settings-archives.png` |
| Threat-model rescoring | `docs/screenshots/tmrescore.png` |
| Code analysis running | `docs/screenshots/code-analysis-running.png` |
| Code analysis result | `docs/screenshots/code-analysis-result.png` |
| Code analysis dashboard | `docs/screenshots/code-analysis-dashboard.png` |
| Analysis queue dropdown | `docs/screenshots/analysis-queue-dropdown.png` |

Additional docs:

- Screen guide: `docs/screens.md`
- Integration API surface: `docs/integration-api-surface.md`
- Workflow flowcharts: `docs/workflow-flowcharts.md`
- TMRescore static OpenAPI spec: `openapi/tmrescore-openapi.json`
- Code Analysis static OpenAPI spec: `openapi/code-analysis-openapi.json`

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
