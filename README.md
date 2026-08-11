# Dependency Track Vulnerability Processor (DTVP)

DTVP is a FastAPI and Vue application for reviewing vulnerability findings
across every version of a project. It groups findings by vulnerability, exposes
version-by-version assessment state, and lets reviewers apply consistent
changes without repeating the same work for every release. Vulnerability data
comes from a selected backend adapter; Dependency-Track is the first supported
adapter, not a service owned or deployed by DTVP.

- [Main repository](https://git.baer.one/phbaer/dtvp/)
- [GitHub mirror](https://github.com/phbaer/dtvp/)

This README is the concise human entry point. The canonical curated project
model for humans and AI agents is the [OKF knowledge bundle](docs/index.md).
Source, tests, package metadata, lockfiles, and runtime configuration remain
operational truth; update the relevant OKF concept and this summary when they
change. `AGENTS.md` and `skills/*/SKILL.md` are short routing entry points.

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

## Security At A Glance

DTVP fails closed around identity, authorization, backend selection, storage,
and concurrency. It uses OIDC code flow with PKCE, backend-enforced roles and
fresh-state conflict checks, distinct least-privilege workload credentials,
bounded and sanitized untrusted inputs, and human review for LLM output.
Packaged Compose adds secret-file mounts, host/origin and request limits,
non-root read-only containers, narrow writable volumes, network segmentation,
exclusive per-volume process leases, audit/storage health, and verified backup
helpers. The release path uses lockfiles, immutable pins, security scans, SBOMs,
provenance, and digest signing.

Operators still own HTTPS, IdP MFA, exact host/proxy/egress policy, independent
secret rotation, immutable audit export, encrypted off-host backups and restore
tests, source-cache retention, and signature verification. See the complete
[security principles, guardrail catalogue, threat analysis, and residual risks](docs/threat-model.md).

## Quick Start

Requirements: Python 3.14+, `uv`, `npm`, `pm2`, and Node.js 24 LTS (24.15+)
or a newer supported Node.js release. Docker and Docker Compose are needed
only for the packaged deployment.
The ready-to-run local stack below is an explicitly isolated Dependency-Track
adapter demo; it does not make Dependency-Track a DTVP service.

```bash
uv sync --dev
cd frontend
npm ci --include=optional
cd ..
pm2 start demo/dependency-track/ecosystem.config.js --update-env
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
| Start the Dependency-Track mock demo | `pm2 start demo/dependency-track/ecosystem.config.js --update-env` |
| Inspect or tail the stack | `pm2 list` / `pm2 logs` |
| Run backend tests | `uv run pytest` |
| Run Agentyzer tests | `cd agentyzer && uv run pytest --cov=src` |
| Regenerate Agentyzer OpenAPI | `cd agentyzer && uv run python ../scripts/generate-agentyzer-openapi.py` |
| Regenerate the Forgejo workflow | `uv run python scripts/sync-forgejo-workflow.py` |
| Validate the OKF knowledge bundle | `uv run python scripts/validate-okf.py docs` |
| Scan Python source for security issues | `uv run bandit -ll -ii -c pyproject.toml -r dtvp agentyzer/src threatmodel` |
| Audit Python dependencies | `uv run pip-audit --local --vulnerability-service=osv` |
| Generate the OWASP pytm analysis | `./scripts/generate-threat-model.sh` |
| Run frontend unit tests | `cd frontend && npm run test:unit -- --run` |
| Run focused frontend tests | `cd frontend && npm run test:unit -- ProjectView` |
| Build the frontend | `cd frontend && npm run build` |
| Run local-stack UI tests | `cd frontend && npm run test:ui` |
| Benchmark grouped-query concurrency | `uv run python scripts/benchmark_group_queries.py` |
| Capture README screenshots | `cd frontend && npm run test:ui:docs` |
| Regenerate CycloneDX SBOMs | `./scripts/generate-sboms.sh` |
| Start the packaged deployment | `cp .env.dist .env && docker compose -f compose.yml -f compose.secrets.yml up -d` |
| Start the GIL-enabled fallback deployment | `docker compose -f compose.yml -f compose.secrets.yml -f compose.gil.yml up -d --build` |
| Deploy with Arcane | See [`deploy/arcane/`](deploy/arcane/README.md) |
| Start the optional Dependency-Track demo | `docker compose --env-file .env --env-file demo/dependency-track/.env -f compose.yml -f demo/dependency-track/compose.yml up -d` |
| Back up packaged durable state | `./scripts/backup-compose-state.sh /absolute/backup/root` |
| Enable scheduled Compose backups | `docker compose --profile backup up -d` |
| Run the Compose backup immediately | `docker compose --profile backup exec dtvp-backup-scheduler /usr/local/bin/dtvp-backup` |

The CI end-to-end job uses the Playwright container image in
`.github/workflows/build-publish.yml` and its Forgejo-native counterpart at
`.forgejo/workflows/build-publish.yml`. Forgejo prefers its native directory;
that copy omits GitHub's unsupported `permissions` field and translates
GitHub's artifact uploader to Forgejo's compatible action, while the GitHub
copy retains a read-only default and GitHub's native artifact protocol. The
GitHub file is canonical; regenerate the Forgejo file with
`scripts/sync-forgejo-workflow.py` after editing it. CI rejects drift between
the two files. Their image tags must exactly match the resolved
`@playwright/test` version in `frontend/package-lock.json`; update all three and
regenerate the Forgejo counterpart in the same change. The regular, manual,
and real-stack Playwright configurations cover Chromium, Firefox, and WebKit
desktop browsers.
The Vitest configuration keeps local TypeScript config imports explicit so it
also loads with Vite's native config loader. It caps the process pool at four
workers so jsdom-heavy component tests do not contend past their per-test
timeouts; validate config changes with
`cd frontend && npx vitest --run --configLoader native`.
CI installs the same exact uv release pinned in the application images, avoiding
mutable latest-version discovery. `Dockerfile.free-threaded` likewise uses
Astral's moving `alpine` image alias by default; set its `UV_IMAGE` build
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
CI executes pull-request code only for branches in this repository; fork pull
requests do not run on the project runner. After tests and image scans pass,
trusted pull requests publish DTVP, Agentyzer, and backup-scheduler images as
`pr-<number>` without changing the `dev`, `latest`, or version tags. Registry
credentials and image publishing otherwise remain limited to trusted `main`
and version-tag push events. Third-party actions are pinned to immutable commit
SHAs with their major versions recorded in comments. GitHub artifact uploads
use its native v7 action. The generated Forgejo workflow substitutes Forgejo's
Node 20 v3 upload action because this Forgejo instance does not support
GitHub's v4+ artifact protocol.
Image scanning downloads the pinned Trivy release archive once, verifies its
hard-coded SHA-256, and invokes the binary directly so the Forgejo `act` runner
does not depend on an action mirror, nested installer, or action-cache service.
All four candidate-image scans reuse that installation and its local database
cache.
The application containers use checksum-pinned minimal Alpine runtimes.
Agentyzer's restricted build context explicitly includes its startup wrapper,
copies a separately pinned `uv` binary, and adds Git as its only runtime
package.

Coverage reports measure production sources even when a module is never
imported by a test. Backend and Agentyzer coverage are branch-aware and run in
their respective locked environments. CI enforces independent floors of 70%
for the backend and 63% for Agentyzer. Frontend coverage is limited to runtime
TypeScript and Vue sources and excludes test helpers and application bootstrap
files; CI requires 79% statements, 68% branches, 76% functions, and 81% lines.
Raise these ratchets as targeted tests improve the baseline.

## Architecture And Project Knowledge

The [OKF knowledge bundle](docs/index.md) provides progressive, typed project
context without turning this README into a second detailed architecture model:

- [Project purpose, repository map, and runtime shape](docs/project.md)
- [Backend architecture](docs/architecture/backend.md)
- [Frontend architecture](docs/architecture/frontend.md)
- [Agentyzer architecture and persistent-workspace policy](docs/architecture/agentyzer.md)
- [Security boundaries and residual risks](docs/threat-model.md)
- [External integration contracts](docs/integration-api-surface.md)

At a glance, the browser uses the Vue SPA, which calls the FastAPI backend. The
backend authorizes user actions and accesses Dependency-Track through a
capability-based vulnerability-backend adapter and backend-scoped cache.
Cybeats and other vendors can implement that contract. TMRescore and code
analysis are optional services. The supported deployment uses one DTVP API
process per state volume and one Agentyzer process per repository volume;
horizontal scaling requires shared coordination and durable task/result stores.

Use [bundle conventions](docs/conventions.md) when changing project knowledge.
The validator requires indexed concepts, source ownership, maintenance
triggers, and working local links.

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
approved General assessment remains authoritative across teams; otherwise the
tab badges and Next action state use assessment coverage from the selected
team's visible findings. The card reports how many findings are inside the
active team scope, and stale asynchronous history loads are discarded when the
selected scope changes. The top search result count is the final number of
grouped vulnerabilities after every active filter, independent of how many
paginated rows are currently loaded. When filters reduce the task, it is shown
relative to the unfiltered task total. Every filter-chip count and the Team
open/assessed breakdown is calculated from that same final filtered result.
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
  `create_missing` or `update`; apply is available only after a successful
  preview, and a failed apply may be retried after the underlying issue is fixed
- Stored snapshots: `GET /api/project-archives/snapshots`
- Schema: `dtvp.project-archive/v1`

Restore matches project name/version first, then remaps changed UUIDs by
component PURL/name/version/BOM ref and vulnerability ID/name/aliases. Audit
history and comments are not replayed. ZIPs default to `data/project_archives`;
optional Git-friendly expanded trees default to `data/project_archives_git`.
Imports reject oversized uploads, encrypted or unsupported ZIP members,
duplicate or unsafe paths, excessive member counts or expanded sizes, and
high-ratio compressed members before writing the upload to disk. The nginx
gateway accepts enough multipart overhead for the 100 MiB archive limit;
route-specific limits still protect direct backend deployments.

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

Queue clients treat failed and cancelled runs as terminal outcomes. Both paths
release registered completion/error callbacks; cancellation reports the
backend error when present and otherwise uses a stable cancellation message.

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
Agentyzer also caps the accepted async backlog globally and per owner. Requests
over either admission limit receive `429` with `Retry-After`; completed jobs do
not consume admission capacity. LLM-facing guidance, follow-up questions, and
dependency-path collections have explicit request-size bounds.

## Development

### Split Backend And Frontend

The quick start is preferred for normal work. To run processes separately,
start only the mocks:

```bash
pm2 start demo/dependency-track/ecosystem.config.js --only mock-dt,mock-tmrescore,mock-code-analysis
```

Then start the backend:

```bash
export DTVP_VULNERABILITY_BACKEND_ID=dependency-track-mock
export DTVP_VULNERABILITY_BACKEND_TYPE=dependency-track
export DTVP_VULNERABILITY_BACKEND_LABEL="Dependency-Track Mock"
export DTVP_VULNERABILITY_BACKEND_API_URL=http://127.0.0.1:8081
export DTVP_VULNERABILITY_BACKEND_API_KEY=mock_key
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
# Select a backend adapter and fill every required backend/authentication value.
docker compose -f compose.yml -f compose.secrets.yml up -d
```

Existing instances need a state-aware migration: current root Compose no longer
owns Dependency-Track or PostgreSQL, production secrets move to file mounts,
and the backend instance ID controls every local state namespace. Preserve the
complete DTVP data and vendor database backups; map legacy `DTVP_DT_*` settings
to `DTVP_VULNERABILITY_BACKEND_*`; use backend ID `dependency-track` and retain
the old `data/dt_cache` path on the first upgrade; create distinct Agentyzer
service/admin tokens; and fix `./data` ownership for the non-root runtime. Follow
the full [change summary, migration, verification, and rollback guide](docs/upgrade.md)
before replacing a running stack.

The base file keeps direct environment-value support for local compatibility.
Production deployments should include `compose.secrets.yml`; it converts the
selected backend API key, session key, OIDC client secret, both analyzer
credentials, and the optional OpenWebUI API key into `/run/secrets` mounts and
clears their direct environment entries. Compose does not inject the entire
`.env` file into application containers: only the explicit, vendor-neutral
configuration allowlist in `compose.yml` crosses the container boundary.

The default deployment contains DTVP, its gateway, and the first-party
Agentyzer integration. It does not deploy a vulnerability-management product
or database. Configure an independently operated backend through
`DTVP_VULNERABILITY_BACKEND_*`. For local evaluation of the current
Dependency-Track adapter, use the isolated setup in
[`demo/dependency-track/`](demo/dependency-track/README.md); its services,
credentials, networks, volumes, and nginx routes are not part of the default
stack.

For image-only deployment through Arcane, use the self-contained
[`deploy/arcane/`](deploy/arcane/README.md) project. The same Compose file can
be pasted into a manually managed Arcane project or selected at
`deploy/arcane/compose.yml` for Git sync. Arcane retains an editable project
environment outside the read-only Git workspace for secrets, while
service-specific non-secret settings remain separately versioned.

To rotate the DTVP session-signing key without immediately logging out every
user, move the old value to `DTVP_SESSION_PREVIOUS_SECRET_KEY`, generate a new
`DTVP_SESSION_SECRET_KEY`, and recreate DTVP with the temporary overlay:

```bash
docker compose \
  -f compose.yml \
  -f compose.secrets.yml \
  -f compose.session-key-rotation.yml \
  up -d --force-recreate dtvp
```

New sessions and OIDC transactions are signed only by the new key; unexpired
ones signed by the previous key remain valid. After
`DTVP_SESSION_TTL_SECONDS`, clear the previous value and recreate DTVP without
the rotation overlay. Remove the previous key immediately instead of using a
grace window when the old key may have been compromised.

Rotate the Agentyzer service and admin credentials without an authorization
gap by using the temporary dual-token grace window:

1. Copy the old current values to `AGENTYZER_SERVICE_TOKEN_PREVIOUS` and
   `AGENTYZER_ADMIN_TOKEN_PREVIOUS`, generate two distinct new current values,
   and update the four variables atomically in the deployment secret store.
2. Recreate Agentyzer first with the temporary overlay:

   ```bash
   docker compose \
     -f compose.yml \
     -f compose.secrets.yml \
     -f compose.agentyzer-token-rotation.yml \
     up -d --force-recreate agentyzer
   ```

   Agentyzer accepts both generations, so the still-running DTVP can continue
   using its old credential. Only admin generations can use service-wide owner
   scope.
3. Recreate DTVP with the base and secrets files. It switches outbound calls to
   the new current credentials while Agentyzer still accepts both generations.
4. Verify `/api/code-analysis/status` from a reviewer session and inspect the
   authenticated Agentyzer `/health` response.
5. Clear both `*_PREVIOUS` values and recreate Agentyzer without the rotation
   overlay. Do not leave grace credentials mounted after the rollout.

Agentyzer rejects short, duplicated, or service/admin-colliding generations at
startup. Token files are read for every request, so standalone secret-file
deployments can replace them atomically; Compose secrets take effect when the
container is recreated.

Archive apply is disabled by the hardened overlay unless the dedicated import
key is mounted with the additional overlay:

```bash
docker compose \
  -f compose.yml \
  -f compose.secrets.yml \
  -f compose.archive-import-secret.yml \
  up -d
```

Networks with a private certificate authority should pass the CA bundle as a
BuildKit secret instead of disabling TLS verification:

```bash
DTVP_CA_CERTS_FILE=/path/to/ca-bundle.crt \
  docker compose -f compose.yml -f compose.ca-certs.yml build
docker compose -f compose.yml -f compose.secrets.yml up -d
```

The bundle is not sent in either Docker build context. It is installed in the
runtime trust stores, and uv explicitly uses that native trust store while
installing Python and dependencies, so HTTPS downloads, OIDC, and internal
integration endpoints can be verified normally. Do not set
`NODE_TLS_REJECT_UNAUTHORIZED=0` or disable certificate checks.

Select an available backend adapter, set its URL and least-privilege API key,
complete OIDC settings, and configure an HTTPS public URL plus random session,
Agentyzer service, and Agentyzer admin secrets before starting the production
profile. Generate each secret with `openssl rand -hex 32`. Production startup
rejects missing backend selection/credentials, missing or placeholder session
secrets, insecure OIDC callbacks, the development authentication bypass, and an
enabled code-analysis integration without distinct service and admin tokens.
For a non-default gateway:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=https://host.example:8083/dtvp
DTVP_SESSION_SECRET_KEY=<random value from openssl rand -hex 32>
AGENTYZER_SERVICE_TOKEN=<a second random value from openssl rand -hex 32>
AGENTYZER_ADMIN_TOKEN=<a third random value from openssl rand -hex 32>
```

Deployment rules:

- `./data` mounts at `/app/data`; mappings, roles, rules, caches, proposals, and
  archives survive container restarts. Application containers use immutable image
  digests, read-only root filesystems where supported, bounded process counts,
  rotated local logs, and reduced Linux capabilities. DTVP and Agentyzer run as
  non-root users with writable mounts only for data, repositories, and temporary
  files. Set `DTVP_RUNTIME_UID` and `DTVP_RUNTIME_GID` to the numeric owner of
  `./data` (for example, `id -u` and `id -g`) when it is not `1000:1000`.
- Compose starts Agentyzer and persists control repositories, worktree locks,
  transient detached worktrees, and its bounded async-job SQLite store in the
  `agentyzer-repos` volume. Populate or override the sanitized
  `agentyzer/config/repos.yaml` before enabling automatic scans; never commit
  repository credentials. Docker builds use an empty container-only repository
  map, so the mounted environment-specific file and local `.env` are not sent
  in either application build context. Agentyzer is not published on the host
  by default; add `-f compose.agentyzer-debug.yml` for an authenticated
  loopback debugging port. Every API route requires a bearer token. DTVP forwards the authenticated
  username as a trusted owner identity; Agentyzer lists, reads, follows up,
  cancels, and deletes only that owner's jobs. DTVP reviewer-wide status
  requests explicitly use a separate admin credential and the trusted
  service-wide owner scope.
  Repository authentication is injected only into the child `git` process;
  stored remote URLs are scrubbed in place. Each scan uses a detached worktree
  backed by the persistent control repository, so repeat scans reuse Git
  objects without sharing mutable files. Normal completion removes only the
  per-run worktree, and the next repository preparation reclaims unlocked crash
  leftovers. The source scanner reads only bounded, non-symlink regular files
  whose resolved paths remain inside that worktree, preventing a malicious
  checkout from exposing host files through source-like symlinks. The entire
  volume is a disposable runtime cache: it is excluded from DTVP backups and
  may be reconstructed from the configured Git sources.
  Agentyzer immediately clones or fetches every explicit URL-backed mapping on
  startup, refreshes those control repositories every
  `AGENTYZER_REPO_REFRESH_SECONDS`, and fetches again immediately before
  creating an assessment worktree. The periodic pass is independent of
  advisory filtering, so references remain current even when an assessment
  exits before repository preparation.
- Compose separates gateway, application, analyzer, and database traffic on
  distinct networks. Internal networks cannot reach the internet. DTVP,
  Agentyzer, and the archive helper each receive a separate outbound bridge so
  an egress-capable service does not create a lateral path between trust zones.
- The archive Git helper uses a digest-pinned image, read-only root filesystem,
  dropped capabilities, strict SSH host-key checking, and a dedicated outbound
  network. Remote lookup/fetch failures abort the job; they are never treated
  as an empty branch, and an initialized volume refuses a changed remote.
- Internal services use Compose names and container ports. DTVP reaches
  Agentyzer at `http://agentyzer:8000` unless overridden. Vulnerability
  backends are external and use the configured adapter URL.
- If proxies are configured, list exact internal hostnames/IPs in `NO_PROXY`;
  do not rely only on CIDR entries.
- DTVP OIDC is independent of backend browser sessions. Adapter calls use
  `DTVP_VULNERABILITY_BACKEND_API_KEY` and never forward browser credentials,
  authorization headers, or session cookies. Use a least-privilege workload
  identity for normal review and a separate
  `DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY` when archive apply requires
  broader project/BOM creation rights. Rotate credentials according to the
  selected backend's overlap procedure, recreate DTVP, and verify a read plus
  an authorized write before revoking the previous credential.
- `/api/vulnerability-backend` publishes the active non-secret adapter
  descriptor, capabilities, and adapter catalog. Dependency-Track is the active
  implementation. Cybeats is registered as a fail-closed scaffold until its
  private API contract and a test tenant are supplied; selecting it cannot
  silently route data through Dependency-Track-shaped behavior.
- OIDC login uses authorization code with PKCE, state, nonce, discovery issuer
  validation, JWKS signature verification, and expiring DTVP session cookies.
  A direct session-key replacement invalidates existing sessions; use the
  temporary previous-key overlay above for a planned grace period. Logout is a
  credentialed `POST` from the frontend.
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
  `DTVP_HTTP_PORT` changes the host gateway port and `DTVP_SERVER_NAME` is the
  exact public host accepted by nginx. Unknown hosts are rejected at nginx and
  by the application. Direct-container deployments must publish port `8000`,
  include the context path in the URL, and configure `DTVP_ALLOWED_HOSTS`.
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
- The backend serves a no-store, same-origin `runtime-config.js`; the immutable
  frontend shell contains no environment-derived inline script. Production
  responses set a restrictive content security policy, HSTS, clickjacking,
  MIME-sniffing, referrer, opener, and browser-permission headers. Interactive
  API documentation and the OpenAPI route are disabled in production.
- Markdown from changelogs and vulnerability advisories is parsed through a
  shared DOMPurify allowlist before Vue renders it as HTML.
- nginx rejects request bodies larger than 105 MiB. Backend routes apply
  narrower limits to settings uploads, each tmrescore input, and project
  archives, so the same controls remain active when port `8000` is exposed
  directly.
- nginx applies connection and per-IP request limits. DTVP additionally applies
  bounded session/IP quotas to login, mutation, and expensive task-creation
  requests. Cookie-authenticated unsafe requests require an Origin in the exact
  CORS allowlist; requests with a cross-site fetch indicator or a different
  Origin are rejected. CORS permits only the methods and headers used by the
  application.
- Every state-changing request, login outcome, reviewer denial, host/origin
  rejection, and rate-limit denial produces a structured event. Production
  appends those events to an owner-only JSONL file as well as the
  `dtvp.security_audit` logger; `/api/security/health` exposes persistence
  health and active quotas to reviewers. Ship that logger/file to immutable
  external retention for production investigations.
- The same reviewer health endpoint performs read-only JSON validation and
  SQLite `quick_check` operations across durable stores, reports available
  bytes, and can enforce an external-backup freshness SLO. Audit JSONL files
  rotate at a bounded size with owner-only backups. DTVP refuses startup when
  a configured state path is unreadable, unwritable, corrupt, or below the
  free-space threshold.

`./scripts/backup-compose-state.sh /absolute/backup/root` provides a consistent
Compose backup of DTVP-owned state. It briefly pauses DTVP and archives only
`./data`. It validates the gzip stream, writes SHA-256 checksums, resumes DTVP
even after an error, and only then atomically updates
`DTVP_BACKUP_STATUS_PATH`. The isolated maintenance container has no network;
its read-only source mounts and narrow DAC capabilities let it read files owned
by the two different non-root runtime users.

For a deployment managed entirely through Docker Compose, enable the optional
`backup` profile. The scheduler uses the same pause, archive, validation,
checksum, and marker sequence without host cron or systemd:

```dotenv
COMPOSE_PROFILES=backup
DTVP_BACKUP_PATH=/absolute/path/on-the-docker-host
DTVP_BACKUP_INTERVAL_SECONDS=86400
DTVP_BACKUP_INITIAL_DELAY_SECONDS=300
DTVP_BACKUP_RETRY_SECONDS=3600
DTVP_BACKUP_MAX_AGE_SECONDS=172800
```

Recreate the stack with `docker compose up -d`. If no verified marker exists,
the first backup starts after the initial delay. Later backups are scheduled
from the last successful marker, and failures retry at the configured
interval. `docker compose logs dtvp-backup-scheduler` reports each outcome. A
manual `docker compose --profile backup exec dtvp-backup-scheduler
/usr/local/bin/dtvp-backup` uses an in-container lock and safely refuses to
overlap an active scheduled run.

Consistent cross-container snapshots require pausing and resuming writers, so
this optional profile mounts the Docker Engine socket. Socket access is
effectively host-administrator access even though the scheduler has no
published port or network, uses a read-only root, and drops Linux capabilities.
Enable the profile only with the trusted scheduler image on a dedicated Docker
host. If that trust is not acceptable, keep the profile disabled and invoke the
host script from an external scheduler.

Set `DTVP_BACKUP_MAX_AGE_SECONDS` to the recovery policy;
`/api/security/health` becomes unhealthy when the verified marker is missing,
invalid, or stale. Freshness enforcement is disabled by default so a new
deployment can start before its first backup. Store backup directories
encrypted and outside the checkout. To test recovery, first verify
`sha256sum -c SHA256SUMS`, restore `persistent-files.tar.gz` into fresh matching
storage while DTVP is stopped, then start the stack and exercise both health
endpoints plus a representative project and scan. Never restore over a running
deployment. Agentyzer clones, worktrees, and local jobs are disposable and are
recreated rather than restored.

Neither backup path prunes snapshots or copies them off-host. Apply encrypted
storage lifecycle and replication separately. Vulnerability backends are
external systems and remain outside DTVP backups; their operators own their
database, object-storage, retention, and restore procedures.

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

Archive imports may require a dedicated
`DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY` with read, upload,
project-creation, and assessment-update permissions supported by the selected
adapter. Scheduled snapshots and expanded Git trees are controlled by the
archive variables below. The optional
`dtvp-archive-git-push` Compose job pushes an expanded tree; schedule it with
cron, systemd, or CI when required.

## Configuration Reference

The complete environment-variable catalog, defaults, secret-file alternatives,
storage paths, and optional-integration settings live in the
[runtime configuration reference](docs/configuration.md). Set values in `.env`
for Compose or in the shell for local `uv` runs.

Cross-cutting runtime defaults are owned by `dtvp/configuration.py` and
`agentyzer/src/configuration.py`; integration credentials retain their focused
typed settings classes.

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
The generators are lockfile-managed development dependencies, and CI builds
the Python documents from separate production-only environments without
rewriting manifests or locks. Generated DTVP SBOM snapshots and the changelog
are tracked so a checkout can build the Compose images without CI-only setup;
CI refreshes them before publishing images. Run `./scripts/generate-sboms.sh`
after dependency changes and `uv run git-cliff -o CHANGELOG.md` after release
history changes.

The publish workflow is fail-closed around the software supply chain. It audits
the locked Python graph with `pip-audit`, scans the DTVP and Agentyzer Python
source with Bandit, executes the combined DTVP/Agentyzer
[OWASP pytm model](threatmodel/dtvp.py), audits both npm lockfiles, and rejects
Node operations when TLS certificate verification has been disabled. The pytm
run includes DTVP's vscorer, vulnerability-backend, identity, and Agentyzer
connections and publishes its Markdown findings, JSON model, and Graphviz DFD
as a CI artifact. Before a tag is created or an image is published, separate
local DTVP, Agentyzer, and backup-scheduler image candidates are scanned for all
HIGH and CRITICAL operating-system and library vulnerabilities, including
vulnerabilities that do not yet have a fix. Every published image carries
BuildKit SBOM and maximum-mode provenance attestations in the registry.

Release images are signed by immutable digest with cosign. Configure an
encrypted cosign private key and its password as protected CI secrets named
`COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`, and distribute the corresponding
`cosign.pub` through a trusted channel. Tag builds fail when either signing
secret is absent; mutable `dev` and `pr-<number>` images are deliberately not
signed.
Verify a release against its displayed digest, for example:

```sh
cosign verify --key cosign.pub registry.example/owner/dtvp@sha256:<digest>
cosign verify --key cosign.pub registry.example/owner/agentyzer@sha256:<digest>
```

The [OKF knowledge bundle](docs/index.md) is the canonical curated project
model. Its main specialized references are:

- [Security threat model and residual-risk register](docs/threat-model.md)
- [Screen guide](docs/screens.md) and generated images under `docs/screenshots/`
- [Integration API surface](docs/integration-api-surface.md)
- [Runtime configuration reference](docs/configuration.md)
- [Workflow diagrams](docs/workflow-flowcharts.md)
- [tmrescore OpenAPI](openapi/tmrescore-openapi.json)
- [Code-analysis OpenAPI](openapi/code-analysis-openapi.json)

This project is licensed under the MIT License. See [LICENSE](LICENSE).
