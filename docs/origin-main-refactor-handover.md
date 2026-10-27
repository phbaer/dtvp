# Handover: refactoring `origin/main` toward the knowledge-journal branch

## Comparison point

- Baseline: `origin/main` at `f236a96f839076ad3c0987b8c5f9976bc094b594`
- Reference branch: `rewrite/knowledge-journal` at `c0353c4ea3b8cf4753fcf8d83b518c7914edc961`
- Common ancestor: `bdc7ba41a40697b0a3f5aa1b619518216e5087f8`

This is a large refactor. The comparison reports roughly 220k added and 169k
removed lines across 1,111 changed paths. Those counts include tests, fixtures,
docs, generated/reference data, and frontend files; they are not a measure of
new production code. The batches below are a proposed porting plan, not a claim
that the branch commits are already separated into these units.

## What changes, stated narrowly

- **Web framework:** FastAPI remains the backend framework. The refactor changes
  the backend structure, domain contracts, persistence responsibilities, and
  workflows; it is not a FastAPI migration.
- **Knowledge persistence:** immutable logical knowledge revisions and original
  artifacts are held in a local journal/artifact store. PostgreSQL holds
  operational data and rebuildable knowledge projections. Operational records
  still need their own backup and recovery plan.
- **Domain model:** products contain independently advancing version branches;
  inventory baselines, imports, evidence, assessments, reviews, and scores are
  pinned to explicit states/revisions. Ownership responsibility is modeled
  separately from product access. Assessments can retain distinct consuming
  contexts and explicit version coverage.
- **Workflow boundaries:** imports from Dependency-Track, CyBeats, SBOMs, and
  advisory/analysis providers are evidence inputs. Decisions are owned by DTVP;
  imports do not write decisions back. Integrations use the API and durable job
  workflows. Agentyzer is treated as an external application; its service code
  is removed from this repository in the reference branch.
- **Clients:** UI and CLI use authenticated backend workflows. The frontend
  reorganizes product work into sidebar destinations and scoped workspaces.
- **Runtime:** the reference deployment uses an API/UI process, worker,
  PostgreSQL, and local persistent storage. There is no required object-storage
  service or separate search service.

For exact current contracts, use [`native-reference.md`](native-reference.md),
[`api.md`](api.md), and the branch's `/openapi.json`. The rewrite plan contains
historical decisions as well as current design notes; verify implementation
against code/configuration where they differ.

## Suggested porting batches

Each batch should be made reviewable on `origin/main` before starting the next.
The branch has cross-cutting commits, so use file/domain boundaries and API
contracts rather than cherry-picking its recent commits as if they were
independent layers.

## Backend-first implementation plan

### Goal and boundary

DTVP becomes the system of record for product inventory, vulnerability context,
assessments, reviews, and operational decisions. Dependency-Track (DT) becomes
an external source that DTVP can import from and synchronize with. DTVP's API,
authentication, and FastAPI runtime remain; this work changes data ownership and
backend workflows first. UI migration follows after the DTVP-backed API is
stable.

Use a source-neutral domain boundary: provider connectors fetch and normalize
observations; domain services validate and publish them into DTVP state; query
services serve the existing backend API from DTVP state. External identifiers
and raw payloads are retained as provenance, but do not become DTVP primary
keys or dictate its domain schema.

Recommended storage direction, consistent with the reference branch: PostgreSQL
for transactional operational data and rebuildable/queryable projections, plus
the local immutable journal/artifact store for authoritative knowledge revisions
and original imports. Both are DTVP-owned persistence. If implementation chooses
a different internal split, preserve the same guarantees: transactional writes,
reconstructable history, source provenance, and a supported backup/restore path.

Initial DT synchronization should be **inbound**: it imports source observations
into DTVP. DTVP decisions are authored and retained in DTVP. Any later
publication of decisions back to DT is a separate, explicit integration
capability; it must not be required for normal DTVP reads or writes.

### Implementation progress

- **Implemented foundation:** separate DTVP PostgreSQL storage in Compose
  (file-backed SQLite for direct local development), automatically applied
  Alembic migrations, DTVP product/version records, generic source connections
  and external references, durable import runs, immutable snapshot metadata,
  and SHA-256 verified content-addressed artifacts.
- **Implemented first connector slice:** authenticated reviewer endpoints can
  import or fully refresh one Dependency-Track project. The adapter returns a
  source-neutral snapshot, preserves the exact provider capture, records the
  initiating user and durable run status, and avoids a new state revision when
  normalized content is unchanged. DTVP catalog/read endpoints expose products,
  versions, pinned snapshots, import runs, and source artifacts.
- **Implemented DTVP-backed inventory reads and refreshes:** inventory cache
  misses and refreshes import a complete Dependency-Track project scope and
  publish it before returning the existing UI response. Cached reads use the
  retained DTVP snapshot; a failed refresh serves the last published snapshot.
  Project discovery can fall back to the imported catalog during a
  Dependency-Track outage. The legacy cache facade no longer fetches BOMs,
  findings, advisories, or source analysis directly; those reads go through the
  connector/import service.
- **Implemented DTVP-owned project catalog:** complete project discovery runs
  through the connector, and active/inactive catalog observations plus original
  provider records are stored in DTVP before the compatibility API returns
  them. The local project cache is disposable.
- **Implemented DTVP-owned decisions:** assessment writes append revisions in
  the relational database with actor and snapshot metadata. The legacy SQLite
  queue remains only for explicitly enabled publication and migration of older
  local decisions; outbound synchronization is disabled by default. SQLite
  decisions and per-finding JSON overlays migrate after a successful project
  import. Archive restore publishes through DTVP's generic source importer;
  export can refresh through the configured source connector. The
  automatic-analysis sweep reads the DTVP catalog and retained snapshots.
  Project discovery and optional DT publication still use the
  Dependency-Track connector/client.
- **Legacy inventory migration command:** `uv run dtvp-legacy-cache-migrate`
  reports eligible versions; `--apply` imports them resumably while preserving
  legacy files. It does not delete or disable the old cache. The next backend
  slice is reconciliation and retirement of legacy project caches/outbox data,
  then removing client dependencies from compatibility routes where they are
  no longer needed. Add operational backup, restore, and verification
  procedures for the DTVP database and artifact store.

### Target backend boundaries

1. **Domain model:** product/workspace, product version, inventory baseline,
   component occurrence, dependency edge, vulnerability/advisory, contextual
   finding, source observation, and DTVP assessment/review/scoring records.
   Keep source identity separate from canonical DTVP identity. Multiple
   occurrences/consuming roots must remain representable.
2. **Source registry:** source type, connection configuration reference,
   capabilities, enabled state, and per-project/version external references.
   Secrets stay in configuration/secret storage, not in imported payloads.
3. **Connector contract:** discover/select scope, fetch complete or incremental
   data, normalize provider payloads, report source cursor/watermark, and retain
   raw artifacts and provider identifiers. A connector declares which data it
   supplies; missing capabilities are explicit, not represented as empty data.
4. **Import/sync service:** create a durable run with selected scope, start/end,
   status, counts, warnings, cursor, and error detail. Validate and stage input,
   compute changes, then atomically publish a pinned baseline/revision. Retries
   use stable request/run identities. Deletions/removals require complete-snapshot
   semantics or explicit tombstones; partial feeds never erase inventory.
5. **Query/API services:** resolve existing UI routes from DTVP-owned projections.
   Keep response behavior stable initially, including pagination, filters,
   assessment overlays, and project/version identifiers where feasible. Add
   explicit import-run and source-status endpoints before changing the UI.
6. **Decision writes:** save assessments and reviews to DTVP persistence with
   authorization, concurrency checks, and history. Do not depend on DT API
   availability to record or read decisions.

### Delivery phases

#### Phase 0: contract and data inventory

- Map every route/service that currently reads projects, BOMs, findings, or
  analysis from `DTClient` / `CacheManager`; identify which routes need canonical
  DTVP records versus a transitional source view.
- Map all writes to DT, including the assessment outbox and archive restore.
- Specify identity keys and preserve distinct component occurrences and
  consuming contexts. Decide what constitutes a complete snapshot per scope.
- Document legacy behavior to preserve and intentional changes. Define how
  imported DT assessments are classified as source observations versus DTVP
  decisions; do not auto-promote imported text to a locally approved decision.

**Exit:** reviewed data dictionary, route/write inventory, migration mapping,
initial sync scope, and explicit inbound-only behavior.

#### Phase 1: DTVP persistence foundation

- Introduce PostgreSQL models/migrations, transaction/session management, and
  startup/health checks. Add journal/artifact persistence and revision publication
  if using the reference architecture.
- Persist operational identity/access separately from knowledge revisions, and
  document backups for both.
- Add storage repository interfaces so route logic does not import SQL or journal
  internals. Use disposable database fixtures for persistence/concurrency work.
- Add audit-friendly revisions and optimistic concurrency pins for state changes.
- Provide one documented upgrade entry point for Docker Compose, local `uv`
  deployments, and supported operators; ordinary releases must not require
  hand-written SQL.

**Exit:** create/read/update flows work without contacting DT; a revision and
its raw artifact can be restored and verified from backup; migrations are
repeatable on a clean database and upgrade an existing DTVP installation. A
normal application update applies pending schema migrations automatically and
reports success or a clear blocking error before serving traffic.

#### Phase 2: source-neutral domain and read path

- Implement canonical DTVP products/versions, inventory occurrences/edges,
  vulnerability/finding context, and separate imported observations from local
  decisions.
- Build query services over DTVP storage and adapt existing API routes behind
  their current response schemas. Preserve current filtering and grouping
  semantics while replacing DT-backed reads incrementally.
- Keep local caches as disposable performance layers only. Cache misses and
  restarts must not require DT to reconstruct already imported state.

**Exit:** imported fixture data can power project/version/finding list and detail
reads after DT is unavailable; response contracts and authorization are stable.

#### Phase 3: Dependency-Track connector and sync

- Isolate DT API calls into a connector implementing the common source contract;
  keep pagination, rate limits, retry handling, provider version quirks, and
  credential use inside it.
- Support selecting a DT project/version, previewing the import, initial full
  import, and incremental refresh. Retain original BOM/source payloads and DT
  UUIDs as provenance/external references.
- Record import runs and per-scope cursors/watermarks. Detect unchanged,
  added, updated, removed, and unresolved records; surface identity ambiguity
  instead of merging distinct usages.
- Publish accepted snapshots atomically. A failed or partial run leaves the
  previous DTVP baseline intact. Start with explicit manual sync; schedule/poll
  only after idempotency and retry behavior are established.

**Exit:** repeat imports are idempotent; interrupted/partial imports do not
damage the current baseline; DT removal/change history remains inspectable; the
same sync service can accept another connector without changing domain tables.

#### Phase 4: DTVP-owned assessment and workflow writes

- Move assessment/review/scoring writes from DT update calls and the SQLite
  outbox into DTVP-owned records, preserving exact history, actor, state pins,
  and permission checks.
- Import DT analysis fields as attributed source observations. Map them to local
  state only through an explicit migration/import policy, keeping provenance and
  approval status clear.
- Retain DT publication, if desired, as a separate optional outbound job with
  explicit enablement, capability checks, conflict reporting, and no effect on
  local commit success. Default it off during cutover.

**Exit:** users can read and record decisions with DT stopped; a failed DT sync
cannot lose or roll back DTVP decisions; imported assessments cannot silently
become approved local decisions.

#### Phase 5: migrate integrations and retire DT-backed reads

- Change tmrescore/Agentyzer and archive flows to consume DTVP inventory through
  domain/query APIs. Keep provider-specific inputs and results attributed to
  their source and pinned to the inventory revision used.
- Migrate startup, project catalogs, statistics, scheduled work, and cache
  invalidation to DTVP state. Keep DT only in the connector/outbound adapter.
- Add an installation migration/import command, progress/resume, duplicate
  detection, reconciliation report, and rollback checkpoint. Do not remove
  legacy caches/outbox until the migration is validated and recoverable.

**Exit:** application routes and background workflows operate without DT
credentials except DT sync features; source outages affect only those features.

#### Phase 6: operational cutover

- Make DTVP database/journal backup, restore, verification, retention, and
  upgrade guidance part of deployment. Define PostgreSQL and local artifact
  storage capacity/permissions and recovery ordering.
- Update config and compose for DTVP storage and optional DT source connection;
  remove DT-required startup gates only after consumers are migrated.
- Update README and operator/consumer docs. Keep UI changes out of this backend
  slice except for minimal API compatibility needed to exercise it.
- Make routine schema migration part of the deployment path. Run it once under
  a database advisory lock or a single migration job before application workers
  become ready; workers must not race to alter schema independently.
- Use expand-and-contract migrations: additions first, deploy code compatible
  with old/new schema as needed, backfill resumably, then remove obsolete schema
  in a later release. Keep destructive data conversion out of an opaque startup
  step unless it is bounded, restart-safe, and recoverable.
- Expose current schema revision and the last migration outcome in startup logs
  and an authorized health/diagnostic surface. On migration failure, stop
  readiness; either leave transactional changes unapplied or report a resumable
  checkpoint and recovery action. Never serve against an ambiguous partial
  schema or expose credentials/raw sensitive records.
- Document automatic backup/restore expectations and provide a pre-upgrade
  backup hook for releases that change persistent data. Do not imply that
  reversing application code reverses a database migration; prefer forward
  fixes and a tested restore path.

**Exit:** clean install, upgrade, restore, and no-DT operation are documented;
the backend has one authoritative DTVP write path. A routine release requires
no manual schema commands, migration status is visible, and an interrupted or
failed migration can be retried or recovered without ambiguous partial state.

### Database upgrade requirements

- **Automatic by default:** on a normal release update, DTVP discovers and
  applies pending versioned schema migrations before API/worker readiness. The
  same migration runner is available as an explicit command for operators who
  need a staged deployment; manual SQL is not the standard path.
- **Single runner:** serialize migration execution with a PostgreSQL advisory
  lock or a one-shot Compose/deployment migration job. Concurrent app instances
  wait for or verify the completed schema revision; they never run DDL in
  parallel.
- **Transparent:** log migration name/version, start/end, duration and outcome;
  expose current/required schema revisions and failure status to operators.
  Never log secrets, assessment content, or full imported payloads.
- **Retryable and bounded:** migrations are versioned and checksum-checked.
  Small transactional schema changes complete atomically; large backfills use
  checkpoints, bounded batches, and idempotent resume. A failed migration must
  not be marked complete.
- **Compatible rollout:** prefer additive expand-and-contract releases so old
  and new app code can coexist during deployment when needed. Gate contract or
  destructive steps on a later release after old code is retired.
- **Recoverable:** define the pre-upgrade backup boundary for both PostgreSQL
  and journal/artifact data when a release changes persisted meaning. Verify
  restore procedures. Do not promise automatic rollback for irreversible data
  migrations; provide a forward repair or restore procedure.
- **Low-touch operations:** ordinary minor releases need no bespoke operator
  steps. When a release needs a special action, surface it before rollout with
  a precise command, expected duration, progress signal, and recovery procedure.

### Current code seams to migrate

- `dtvp/dt_client.py`: existing provider-specific HTTP client; retain/refactor as
  the DT connector rather than using it from domain/query logic.
- `dtvp/dt_cache.py`: `CacheManager` currently fetches/caches project and finding
  data and overlays local assessment state. Split into source ingestion, DTVP
  query repository, and optional disposable cache; do not replace it with one
  giant database-backed cache manager.
- `dtvp/assessment_outbox_services.py` and its migrations: currently queue
  assessment updates for DT. Replace local decision persistence first; preserve
  an optional outbound queue only if explicit DT publication remains in scope.
- `dtvp/grouped_vuln_services.py`, `dtvp/grouped_vuln_task_services.py`,
  `dtvp/tmrescore_inventory_services.py`, and `dtvp/project_archive_services.py`:
  callers to migrate from `CacheManager`/DT reads to DTVP query services.
- Existing SQLite stores for SSVC, grouped summaries, and analysis results have
  separate responsibilities; inventory this before moving or consolidating them.

### Main risks and controls

| Risk | Control |
| :--- | :--- |
| DTVP schema copies DT's shape and cannot accept future sources | Normalize to source-neutral domain records; keep connector payload mapping at the boundary |
| A sync treats partial data as a complete replacement | Require declared scope/completeness; stage then atomically publish |
| Duplicate/mismatched component identities collapse contexts | Preserve occurrences and provider refs; make uncertain matches explicit |
| Imported DT assessment text looks like a local approval | Store as attributed observation; require explicit conversion policy and actor |
| Cutover loses local outbox/cache/archive data | Inventory, migrate, reconcile counts/identities, retain backup checkpoint, support resume |
| Provider outage blocks local work | All normal reads/writes use DTVP state; connector failures are isolated and visible |
| New source requires schema/API rewrites | Capability-based connector contract and source-neutral import envelope |

### Acceptance scenarios for the backend slice

- Import a full DT project/version, restart DTVP, disconnect DT, and continue
  reading inventory and making local decisions.
- Re-import identical input; no duplicate components/findings/decisions are
  created. Import changed and removed components; history and provenance remain.
- Fail during fetch/validation/publication; prior baseline remains current and
  retry resumes safely with the same run identity.
- Import an incomplete/partial source response; no unrelated inventory is
  deleted.
- Import DT analysis/assessment content and verify its source/actor/status are
  visible without it becoming locally approved by default.
- Run a second mock connector through the same import/publish/query path using
  a different external schema, demonstrating that the domain does not depend on
  DT identifiers or field names.
- Back up and restore the DTVP database plus journal/artifacts and verify the
  restored project state, decisions, provenance, and source cursors.

### 1. Persistence and runtime foundation

**Port:** journal and artifact storage, immutable revision envelopes, PostgreSQL
projections/operational models, migrations, startup/configuration, worker wiring,
verification, backup/recovery, and deployment changes.

**Reference areas:** `dtvp/knowledge/journal.py`, `projection.py`,
`dtvp/storage.py`, `dtvp/db.py`, `dtvp/models.py`, `dtvp/migration_models.py`,
`dtvp/backup.py`, `dtvp/main.py`, `dtvp/migrations/`, `alembic.ini`,
`compose.yml`, `Dockerfile`.

**Before proceeding:** document the legacy-to-new data mapping and recovery path;
prove that a committed revision can be read back and projections can be
reconstructed; preserve access/identity configuration independently of journal
recovery. Decide how existing installations move data before removing old
writers.

### 2. Core product, inventory, and decision workflows

**Port:** product/version branches, coherent source baselines, import and
assembly, component inventory/identity, ownership, evidence, contextual
assessments, independent reviews, scoring, retained history, and exports.

**Reference areas:** `dtvp/knowledge/` modules including `assembly.py`,
`assessments.py`, `ownership.py`, `evidence.py`, `scoring.py`, `comparison.py`,
`exports.py`, plus `dtvp/domain.py`, `dtvp/parsers.py`, and the matching
`dtvp/api_*` modules.

**Before proceeding:** define stable identifiers and state pins; specify what
imports may replace and what they must retain; preserve authorization and
approval gates; make previews and apply requests check the same captured inputs.
Keep product access distinct from component responsibility.

### 3. API contracts and migration/compatibility boundary

**Port:** versioned API contract, endpoint registration, request/response
schemas, auth integration, legacy archive/migration readers, and the supported
consumer contract. This can start alongside batches 1–2, but UI/CLI work should
target stable contracts.

**Reference areas:** `dtvp/api.py`, `dtvp/api_contract.py`, `dtvp/api_*.py`,
`dtvp/auth.py`, `dtvp/api_migration.py`, `dtvp/knowledge/legacy*`,
`docs/api.md`, `docs/consumers.md`, `openapi/`.

**Before proceeding:** settle pagination/filter semantics, idempotency and
concurrency pins, permission checks, and error behavior. Keep compatibility
readers explicit; do not leave two authoritative write paths.

### 4. External evidence integrations and durable jobs

**Port:** advisory/source clients, analysis result intake, CPE and identity
workflows, pipeline metadata/evidence, synchronization proposals, job scheduling,
retry/cancel behavior, and provenance retention.

**Reference areas:** `dtvp/knowledge/*jobs*`, `*synchronization*`,
`*advisory*`, `*vscorer*`, `*agentyzer*`, `*pipeline*`, `dtvp/jobs.py`, and the
corresponding API modules.

**Before proceeding:** pin every calculation to its inputs and provider/source
identity; keep proposal generation separate from adoption; bound/coalesce durable
work; retain exact reports and original source artifacts. Treat each provider as
an integration contract, not a reason to bundle its service implementation.

### 5. CLI and frontend workflow clients

**Port:** CLI commands over the API and the frontend's product catalog, work
scope, sidebar destinations, assessment/review workspace, evidence views,
configuration pages, draft persistence, and captured-request handling.

**Reference areas:** `dtvp/cli.py`, `frontend/src/`, `frontend/e2e/`,
`frontend/package.json`, and client tests.

**Before proceeding:** make both clients follow backend permission and workflow
rules; keep exact request identities across uncertain responses; preserve drafts
only with their relevant state/revision; ensure navigation cannot discard
unresolved captured edits.

### 6. Deployment, operations, docs, and removal of superseded paths

**Port:** compose/container/CI changes, operator docs, playground and recovery
scenarios, migration/upgrade support, and removal of legacy writers/routes only
after their replacement and migration paths are accepted.

**Reference areas:** `.github/workflows/`, `Dockerfile`, `compose.yml`,
`docs/deployment.md`, `docs/development.md`, `scripts/`, `playground/`, and
deleted legacy modules/tests shown by the comparison.

**Before proceeding:** check upgrade and rollback expectations, backup/restore,
local persistent-storage permissions, and supported deployment modes. Remove
old code only when no supported migration or consumer still depends on it.

## Working method and guardrails

1. Start each batch from the then-current `origin/main`; record the exact base
   commit and intended scope in its PR/branch notes.
2. Use the reference branch as behavioral evidence, not as a requirement to copy
   every file or historical implementation detail. Port only the agreed slice.
3. Keep a written list of preserved `origin/main` behaviors and intentional
   behavior changes. The design explicitly changes several old assumptions,
   including automatic external writes and implicit approval/coverage transfer.
4. For each API/workflow slice, include migration behavior and authorization
   semantics with the implementation. Do not postpone data ownership questions
   until UI integration.
5. Update the project README and operator/consumer docs with each landed
   architecture or workflow change. Use `/openapi.json` and source as the
   implemented contract when planning notes disagree.

## Original comparison checkout note

When this comparison was first prepared, the checked-out branch was
`rewrite/knowledge-journal` and the tree had untracked frontend output/log files.
Those files were not part of the recorded `origin/main...HEAD` comparison.
