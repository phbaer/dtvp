# Runtime and Capacity

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Runtime Shape](#runtime-shape)
- [Runtime Behavior](#runtime-behavior)
- [Event Channel](#event-channel)
- [Capacity Planning](#capacity-planning)

## Runtime Shape

```text
Browser
  -> Vue SPA (Vite in development, FastAPI/nginx in production)
  -> FastAPI backend
  -> Dependency-Track API + local database
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
| `dtvp/assessment_use_cases.py` | Transport-independent assessment save rules shared by the REST route and the MCP tools |
| `dtvp/auth.py` and `session_services.py` | OIDC login, session tokens (expiry, sliding renewal, per-user revocation) and the signing-key check |
| `dtvp/access_token_*` and `mcp_server.py` | Personal access tokens, their audit log, per-user browser session versions, and the MCP endpoint for AI agents |
| `dtvp/assessment_outbox_services.py` | Local assessments with their base value and history, the export queue, the merge with source values, and conflict resolution |
| `dtvp/bulk_workflows/` | Registry-backed bulk-change plug-ins |
| `dtvp/dt_client.py` and `dt_cache.py` | Dependency-Track access, in-memory document cache, overlays, and pending writes |
| `dtvp/local_store.py` | SQLite database for imported source data and the one-time JSON cache import |
| `dtvp/finding_lifecycle_services.py` | What happened to findings: the analysis gate of a read, gone findings with reasons, carry-over from the record (`finding_lifecycle` migrations, same database file as the assessments) |
| `dtvp/backup/` | The instance dump `dtvp.dump/1`: online export from database snapshots, inspect and verify (`python -m dtvp.backup`); the published JSON Schemas are in `dtvp/resources/dump-schemas/1/` |
| `dtvp/backup/` | The instance dump `dtvp.dump/1`: online export from database snapshots, inspect, verify, and the offline restore with staged files and a journaled swap (`python -m dtvp.backup`); the published JSON Schemas are in `dtvp/resources/dump-schemas/1/` |
| `dtvp/instance_stores.py` | The registry of every file an instance persists (records, settings, caches, legacy inputs) and the instance lock |
| `dtvp/ports.py` | The source and sink interfaces the cache manager is written against; Dependency-Track implements both |
| `dtvp/project_archive_*` | Project archive export/import and scheduled snapshots |
| `dtvp/bundle_io.py` | ZIP container helpers shared by the project archive and the instance dump: stable JSON and JSONL encodings, a deterministic streaming writer, a reader that checks names, member count and declared sizes before reading, and atomic output files |
| `dtvp/settings_files.py` and `file_io_services.py` | The settings files with their validation rules; every write validates first and then replaces the file atomically (temporary file, fsync, rename) |
| `dtvp/tmrescore_*` | Threat-model integration, inventory, cache, execution, and task state |
| `dtvp/code_analysis_*` and `analysis_queue_*` | Analyzer integration, result store, queue, and automatic scans |
| `dtvp/event_hub.py`, `event_routes.py`, `event_producers.py` | The app-wide live-update stream: sequence, replay buffer, `/api/events`, and the producers fed by cache-manager listeners |
| `dtvp/shutdown_signals.py` | Runs a callback (closing the event hub) on SIGINT/SIGTERM before uvicorn waits for open connections |

Important frontend components:

| Component | Role |
| :--- | :--- |
| `frontend/src/main.ts`, `App.vue`, `router.ts` | App shell, routing, authentication, and startup handling |
| `frontend/src/lib/api.ts` and `types.ts` | Backend client and shared integration/domain types |
| `frontend/src/pages/` | Dashboard, project review, statistics, settings, tmrescore, and code analysis |
| `frontend/src/components/` | Vulnerability rows/details, filters, dialogs, queue UI, CVSS, and dependency paths |
| `frontend/src/lib/` | Filter/task-window models, composables, caching, updates, and project state |

## Runtime Behavior

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
- Scheduled instance dumps (`dtvp/backup/schedule.py`) are off by default.
  With `DTVP_BACKUP_INTERVAL_SECONDS` set, a background task exports in a
  worker thread after each interval, verifies and prunes, and reports the
  outcome in the `backup` block of `/api/performance-status`. It takes the
  export lock only, so the backend keeps serving requests.
- The cache manager takes the instance locks (`flock` on
  `<DTVP_DT_CACHE_PATH>/.dtvp-instance.lock` and on `.dtvp-instance.lock`
  in every other directory holding a record database, the proposals file or
  a cache; settings directories are not locked) before it opens or migrates
  a database, at import time, and holds them until it is closed. Opening
  stores on the same directories again in one process shares the locks;
  another process fails with `InstanceBusyError`, and an unfinished restore journal
  raises `RestoreInProgressError`. Both show on the startup failure page.
- The local database (`DTVP_DATABASE_PATH`, by default
  `<DTVP_DT_CACHE_PATH>/dtvp.sqlite3`) stores projects, findings,
  vulnerability details, BOMs, and the last known source assessment of each
  finding in typed SQLite tables; every source document is kept losslessly
  beside its lookup columns. Local assessments, the export queue, and access
  tokens are tables in the same file; a former stand-alone outbox file is
  copied in once. Projects are remembered after Dependency-Track stops
  listing them, so stored findings and queued exports keep their product and
  version. Stored data remains readable while Dependency-Track is
  unavailable. An existing JSON cache in `DTVP_DT_CACHE_PATH` is imported once
  on first start, in one transaction; its files are left in place, are no
  longer read, and can be deleted after the database has been verified. Concurrent
  misses for the same resource share one Dependency-Track request, the
  stored project list is served once it was read (the
  [sync scheduler](#sync-scheduler) keeps it current), and API-key requests
  reuse one application-lifetime HTTP connection pool. The sync scheduler
  also retains its client between passes. A version not yet imported in the
  background is imported when it is opened and served from the database
  afterwards. The automatic code-analysis sweep uses its own
  cache manager and imports versions nobody opened. Each caller still receives an
  isolated mutable snapshot. The last step of a project refresh reads the
  affected version ranges of the project's vulnerabilities that have no
  recommendation and are missing or stale in the table
  `source_vulnerability_ranges` (rebuildable source data, shared by all
  projects): at most `DTVP_FIXED_VERSIONS_READS_PER_CYCLE` per scheduler
  pass, four at a time, one read per vulnerability across projects, and
  again after `DTVP_FIXED_VERSIONS_REFRESH_DAYS` or when the record changed.
  A failed read backs off, from one minute doubling to a day per failure in
  a row, and failed reads come after never-read and stale ones, so they
  cannot use up a cycle's reads.
  Its failure does not fail the refresh, and a CycloneDX export only reads
  what is stored ([Recommendation](cyclonedx-export.md#recommendation)).
  Cold finding loads use
  Dependency-Track's Finding Packaging Format export so assessment state and
  details arrive in one request instead of issuing one analysis request per
  finding. Older Dependency-Track versions fall back to the legacy endpoint.
  Documents are encoded and written by one ordered writer thread, each
  collection in one transaction; async operations await durability without
  holding the event loop or cache lock. Writes whose content did not change
  are skipped. Per-finding assessment lookups of a project load are answered
  by one query. Grouped
  snapshots use project-scoped revisions plus the selected version metadata,
  so a background refresh or activity in another project does not invalidate
  an otherwise reusable result. Summaries created during a cold fill are saved
  against the scoped revision after that fill.
  A project version has two counters. The project revision counts every
  stored change and keys the grouped summaries. The source revision counts
  every change except a local assessment write (a save, a deletion, a bulk
  apply, an MCP save, a discarded export, and the export of a local value),
  and keys the grouped snapshot: those writes are patched into the live
  snapshots instead. A patch reads the recorded value under the snapshot
  lock and shows that, so patches landing in any order leave the newest
  value. Until a patch has shown the recorded value of a written finding in
  the snapshots, the write is unapplied, and a snapshot whose build started
  before it is built again instead of reused; so is one that was still
  building when the patch came, and one that finished knowing project
  versions it did not know when it started, if anything was written in
  between. A request does not join a build in progress, or a finished build
  not yet finalized, that is already known to lack a write. A request
  between the write and its patch therefore builds a new snapshot and is
  never served the old one as current. An export changes only the sync
  status of a value already shown: it is not an unapplied write and does
  not mark a running build; the snapshots get the new sync status when the
  export batch ends. Imports, carry-overs, lifecycle changes, merges with the
  source and restored archives count in the source revision and always lead
  to a new build. The unapplied writes are kept in memory, like the
  snapshots. Each request for a grouped snapshot logs one INFO line: the
  task it reused, or that it builds a new one and why (`no snapshot yet`,
  `the stored source data changed`, `an assessment was saved that the
  snapshot does not show yet`, `an assessment change could not be patched
  into the snapshot`); a finished build logs its duration.
  Pending assessment writes and their local overlays live in a transactional
  SQLite outbox. Newer changes to the same finding replace older pending
  values, and one application-wide bounded dispatcher retries Dependency-Track
  synchronization without multiplying write concurrency per client. When a
  finding disappears before synchronization, a Dependency-Track 404 triggers
  a live findings-API check. Only a valid response confirming that the exact
  project/component/vulnerability tuple is absent removes the queued export.
  A deleted project counts as such a response when the project lookup answers
  404 too while the API's version endpoint answers normally;
  the assessment itself is kept and marked inactive, and the finding gone
  (`missing_at_export`). Failed checks and
  findings that still exist keep retrying. Assessments read from
  Dependency-Track are merged with local ones rather than replacing or being
  shadowed by them, and each export first reads the value it would replace;
  see [Import and export](import-export.md). Legacy
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
- Background sync (planned, [ADR 0004](adr/0004-background-sync-and-event-stream.md)):
  one scheduler will own every Dependency-Track read, keep all active versions
  current within a request budget, and announce changes on an app-wide event
  stream; readers will serve only the database. The design lives in the ADR.
- Live task registries are process-local; the supplied Uvicorn/PM2 launch uses
  one backend worker. A horizontally scaled deployment needs a shared task and
  result store before enabling multiple backend workers.
- Startup status exists at `/startup` and `/api/startup`, in the static first
  paint, and in the Vue initialization view.


## Sync state

Every read of a project version from Dependency-Track is recorded in
`sync_versions` (local store, migration `0005_source_sync.sql`;
[ADR 0004](adr/0004-background-sync-and-event-stream.md#sync-state)), by
`dtvp/source_sync_state.py`. The project list adds versions as
`never_synced` and marks inactive ones, and, from a complete list, missing
ones, `gone`; it stores the source's change hints (`dtvpSourceMarks`, for
Dependency-Track its last BOM import and vulnerability analysis) in
`source_bom_hint` and `source_analysis_hint`. Hints are optional
(`ChangeHints` in `dtvp/ports.py`): a source without them gets regular,
staggered re-reads instead ([Sync scheduler](#sync-scheduler)). A
findings, vulnerability, or BOM read stores a sha256 digest over the raw
response (before DTVP's overlay), the attempt and success times, and resets
the failures; a failed read records its error class and counts failures.
A version changes (`last_change_at`, `generation` + 1) only when a known
digest differs; an unknown one (after the upgrade) is stored without
counting a change. Only analyses changed in Dependency-Track change the
version (see below); the counts of the last read are kept. `lastRiskScore` is not
part of the grouped snapshot's revision: every export changes it.

An analysis that differs from the previous read is an `export_echo` when
Dependency-Track now holds the value DTVP last exported for it (the record's
base, set by `mark_synced` and `note_exported`), even while a newer local
value waits for export; otherwise it is a change in Dependency-Track.

`GET /api/sync/versions?product=&changed_since=` lists the rows (with
`changed_since`, only versions changed after that time); `GET
/api/sync/status` counts them by status and adds the scheduler's state
(`scheduler_state`: breaker, queue, running versions, watched products). The
table is not in the dump: the next reads rebuild it.

### Sync scheduler

Status: implemented 2026-11-21 (ADR 0004 step 5; checked against
`tests/test_source_sync.py`, `tests/test_source_sync_state.py` and
`tests/test_dt_cache.py`).

`SourceSync` (`dtvp/source_sync.py`) is the background loop of the
backend. Each pass (at least once a second, and at once after a save) it:

1. runs the automatic export, then reads the project list when
   `DTVP_DT_CACHE_REFRESH_SECONDS` have passed;
2. plans every row of `sync_versions` when something changed (the list, a
   finished sync, the watched products, the breaker closing) or 15 seconds
   have passed:

   | Priority | Due |
   | :--- | :--- |
   | P0 | a pending user request (`requested_at`; the request route comes with step 8) |
   | P1 | the first import of a version of a watched product |
   | P2 | a changed change hint, for a source with hints (BOM: all kinds; analysis: findings and vulnerability records), or a watched product's findings after 120 s, vulnerability records after 6 h, BOM after 24 h |
   | P3 | the first import of any other active version (backfill); and, for a source without change hints (one that does not declare `ChangeHints`), every active version's findings after `DTVP_SYNC_UNHINTED_FINDINGS_SECONDS` (1 h), vulnerability records after 6 h, the BOM after 24 h or after changed findings, each interval staggered per version between 75 % and 100 % |
   | P4 | the safety re-read, 12 h after the last success |

   Gone and inactive versions are skipped; a failed one, requested or
   not, waits for its backoff (60 s doubling per failure in a row, at most
   1 h). An item rises one priority level per 10 minutes of waiting. A
   queued version that is no longer due returns to its settled status. The
   queued statuses are written in one transaction per plan.
3. starts syncs in the free slots of `DTVP_SYNC_CONCURRENCY` (2): the kinds
   of one version in order (findings, vulnerability records, BOM), then the
   version ranges of the recommendation within one budget per pass. A sync
   holds only its own slot: the next passes, the export and a save's wakeup
   do not wait for it.

A sync is staged: its reads keep their digests, counts and read times beside
the committed ones and note which kinds changed; the version is committed
once, in one transaction that applies them, moves the generation (on a
change or the first import) and settles the status. The list signals seen
when the sync started count as read only for the kinds it read (the BOM
import signal for the BOM, the analysis signal for the findings), and only a
request made before it started is answered. A failed sync, or a restart,
drops the stage: the committed digests are untouched, so the next sync sees
the change again, and versions interrupted by a restart are queued again
first. A failed read on the request path counts as a failure but leaves a
running sync's stage alone. A sync that fails outside a recorded read (a
cache write, a merge, a busy database) is recorded as a failure too, so it
backs off like any other. A call the open breaker refused is no failure of
the version. Until the store-only readers of step 6, views read the stored
documents as soon as each kind is written. Migration `0006_sync_schedule.sql`
counts versions read before the upgrade as read as of their last success,
so an upgrade does not re-read the whole portfolio at once.

Watched products are the union of the browsers' leases
([Product interest](#product-interest)) and short 15-minute leases from a
user's own reads: starting a project's grouped view, polling its task, and
the MCP project tools (`ProductInterest.touch`, renewed at most once a
minute, at most 50 per user, apart from the browsers' 20). Sync work never renews interest. The cache status's
`active_projects` counts the versions of watched products.

Every HTTP request of the scheduler and the export to Dependency-Track takes
a token from one bucket (`DTVP_DT_REQUESTS_PER_SECOND` 4, burst 8): the
client runs the budget as a request hook, so each page of a paginated list
and each per-finding read pays (`BudgetedTransport` in `dtvp/ports.py`; a
source without the hook pays per call). Each call reports to a circuit
breaker, once: five transport, 5xx, or 429 failures in a row open it as
`down`, a 401 or 403 at once as `misconfigured`; while it is open no call is
made (the export waits too) and a probe every 30 s, one `GET /api/version`
within the budget, closes it again; a failed probe waits another 30 s. A
`misconfigured` breaker is closed only by the scheduler's own calls: a
user's read with other credentials succeeding says nothing about the
scheduler's key.

Per project, export writes share a gate and a findings read holds it alone
(a waiting read goes before new writes), so DTVP's own export, including
the record of an export a newer save overtook, cannot land between a read
and its classification and count as a change in Dependency-Track. A batch
skips the keys of a project being read; they go with the next batch. Gates
of idle projects are dropped. The automatic export runs as a task of its
own, one at a time, so an export waiting on a read never holds up the list
reads, the planning or new syncs.

When the loop stops, it cancels its running syncs and the shared reads they
wait on, and waits up to 5 s for them, before its client closes. The
breaker sets `source.state`; a first successful read turns an `unknown`
state to `ok`.

At startup, `queued` and `syncing` rows return to their settled status,
staged syncs are dropped and their versions queued again first; the rest of
the queue is rebuilt from the rows on the first pass.

Events: `version.sync_state` `{uuid, product, status, position}` (queued,
syncing, and the settled result; at most one every 5 s per version unless
the status settles; when a plan queues more than 20 versions at once, as on
a first start, only the backlog in `source.state` tells), `version.synced` on a change or a first import (kinds
changed, findings added and removed, up to 20 new vulnerability ids),
`version.sync_failed` on the transition to failing, `source.state` with
`backlog` (versions queued or syncing; published when it turns empty or
not, or moves by ten), and `assessments.changed` with origin `dt` (the
source changed an assessment) or `export_echo` (the source now holds
DTVP's export; open views are not refreshed for it).

### Manual requests

Status: implemented 2026-11-22 (ADR 0004 step 8, the request part; checked
against `tests/test_sync_requests.py`).

Reviewers can trigger work on the source by hand, from the project view's
**Sync** menu (shown to reviewers only) or the API. Each request takes one
project version (`project_uuid`) or every active version of a product
(`product`); other roles get 403.

- `POST /api/sync/requests` reads the versions again before anything else
  (P0) and wakes the loop, so the read of findings, vulnerability records
  and BOM starts within one planning interval while the source is
  reachable. The request is persisted (`requested_at`, `requested_by`,
  `request_id`). A repeat while it waits is the same request: the answer
  lists it under `already_requested` with the waiting `request_id`. A
  request made while the version syncs is kept, so it is read once more
  afterwards. Its progress is under `request` in `GET /api/sync/versions`:
  `requested`, `running`, `done` with `read_at`, or `failed` with `error`
  (a failed request stays and is tried again after the version's backoff). The read is the scheduler's own: it
  respects a failing version's backoff, the budget and the breaker, and its
  progress is in the usual `version.sync_state`, `version.synced` and
  `version.sync_failed` events.
- `POST /api/sync/analysis-requests` asks the source to analyse the
  versions again, for a source that offers it (`ports.AnalysisTrigger`;
  Dependency-Track: `POST /api/v1/finding/project/{uuid}/analyze`, followed
  with `GET /api/v1/event/token/{token}`; checked against Dependency-Track
  4.14.x `FindingResource` and `EventResource`: the analysis needs only the
  `VIEW_VULNERABILITY` permission on DTVP's API key, the token check any
  authenticated key). Each version gets a
  `version.sync_state` event with status `analysing`; when the source
  reports the analysis finished (polled every 10 s within the budget, at
  most 30 min), the version is requested as above. One analysis per version
  at a time. 501 when the source cannot be asked, 503 while the breaker is
  open. `GET /api/sync/status` tells under `scheduler_state.source` the
  source's name and `can_request_analysis`; the menu hides the analysis then.
- **Export now** in the menu calls `POST /api/export` (all queued
  assessments), as **Settings → Export** does.
- `POST /api/sync/cancel` (reviewers only; body `{"scope": [...]}` with
  `pass`, `requests`, `running`, all three when left out) stops the running
  portfolio pass, withdraws the waiting requests (their last request shows
  `cancelled`) and cancels the running version syncs together with their
  in-flight reads; their staged reads are dropped and each version keeps
  what it had. Nothing of it counts as a failure: no backoff, no breaker.
  Without a scope it also drops the waiting versions and **pauses** the
  sync: no list read, no planning of due versions, no pass and no range
  reads until `POST /api/sync/resume` (reviewers), or the safety-re-read
  interval (`DTVP_SYNC_SAFETY_SECONDS`, 12 h) has passed; a reviewer's
  request still runs. Otherwise the next tick would plan the same due
  versions again and start them at once. The response counts what was
  stopped (`pass`, `running`, `waiting`, `requests`); `progress.paused`
  says until when. **Cancel** in the menu calls it while something runs;
  the menu then shows "Sync paused after cancel" with **Resume**.

**Progress and timings.** `source.sync_progress` (at most two a second,
the last state always sent) and `scheduler_state.progress` in
`GET /api/sync/status` carry what runs now: the portfolio pass with its
pages, each running version with its phase (`preparing`, `findings`,
`vulns`, `bom`, `commit`, `events`) and seconds, how many wait and how many
of them are requests, the version-range reads and the pause. It is sent on
every change of the queue as well, and once more when a cancel has
settled (`source.sync_cancelled` with `settled`), on which the menu reads
the status again. The Sync button shows
the pass's pages or the number of versions waiting; the menu shows the
detail and the last pass's outcome. Every version sync logs one INFO line
with its time per phase, its requests, the time spent waiting for the
budget and in the source; the last 20 are under `recent_syncs`. A
portfolio pass logs its pages and their slowest, the budget wait, the time
to compare and to mark, and why versions are read one by one (`changed`,
`no_digest`, `not_in_list`); the last one is under `last_portfolio_pass`.
These lines show where a slow sync spends its time.

**Version ranges.** The version ranges of the recommendation
(`refresh_fixed_versions`) are read between syncs, when no version waits or
runs and no pass runs, at most every minute, and at low priority in the
budget: a range read takes a token only while no other request waits. They
used to run inside every version sync, each with a fresh allowance of
`DTVP_FIXED_VERSIONS_READS_PER_CYCLE` reads.

**Analysis details.** A version's findings read is one request: the
source lists each assessment's state and suppression (Dependency-Track:
`GET /api/v1/finding/project/{uuid}`, which has no details). Where those
equal the value DTVP last read from the source or last exported for the
finding, the details come from that record. Only the other assessed
findings are read one by one (`get_analysis`): those DTVP has no record of
(adoption, so a first import still reads every assessed finding) and those
whose state or suppression changed in the source. The 12-hour safety re-read
reads every assessment, so an edit of the details alone in the source shows
then. Each sync's log line counts these reads (`analysis_reads` in
`recent_syncs`). Before, every read of a version read each assessed
finding's analysis, about 900 requests in two hours on a production
instance.

**Portfolio pass.** "Read all versions again", and any moment when the due
versions' own reads would cost more requests than the last portfolio list
had pages (one request per kind a version is due for: findings, vulnerability
records, BOM; at least five versions, at most one pass a minute, a request
not waiting for that minute unless the last pass failed), use one portfolio-wide
findings list instead of a read per version, for a source that offers it
(`ports.BulkFindings`; Dependency-Track: `GET /api/v1/finding`, paged).
A version whose unsuppressed findings and their analysis states are as its
last own read left them (`portfolio_digest`) is marked checked and its
request answered as done; only the others are read one by one, and they are
not put into another pass before that read is done. First imports and the
12-hour safety re-read stay per version: the list has no details,
justification or response, so an edit of the details alone in
Dependency-Track shows with that re-read. While a pass runs, the versions it covers wait;
`source.portfolio_pass` events (`started`, `reading` with pages read and
total, `done` with unchanged and changed counts, or `failed`) and
`portfolio_pass` in `GET /api/sync/status` show its progress. A failed pass
leaves the versions to their own reads. See ADR 0004, "Portfolio pass".

Versions read again without a request: a version whose sync state says
read but which has no stored findings (more than five minutes after that
read, as documents are written in the background) is read again, once. A
restore with `python -m dtvp.backup` brings back the stored documents but
not the sync state (it is not dumped), so after a restore every active
version counts as never read and is read once.

### Product interest

Status: implemented 2026-11-21 (ADR 0004 step 4a; checked against
`tests/test_product_interest.py`, `frontend/src/lib/__tests__/eventStream.spec.ts`
and `frontend/e2e/event-stream.spec.ts` in Chromium, Firefox and WebKit).

Each tab tells the browser's leader, over the live-update channel, which
product it shows (a project page shows its project), when its route changes
and every 60 seconds; the leader forgets a tab silent for 2 minutes or that
says goodbye on `pagehide`. The leader sends the union to
`PUT /api/events/interest` `{client_id, products}` when it changes and every
60 seconds while it is not empty. `client_id` is random per leader term; the
server (`dtvp/product_interest.py`) keeps one lease per user and `client_id`
for `DTVP_SYNC_WATCH_TTL_SECONDS` (default 900) after its last renewal, at
most 20 per user; an empty list, or a leader tab that closes, ends it. The
leases are held in the process. The [sync scheduler](#sync-scheduler) reads
them; the self-renewal of recently opened versions is retired.
## Event Channel

Status: implemented for the producers listed below (2026-11-20, checked
against `tests/test_event_hub.py`, `tests/test_event_routes.py`,
`tests/test_event_producers.py`, `tests/test_shutdown_signals.py`,
`tests/test_dt_cache.py`, `frontend/src/lib/__tests__/eventStream.spec.ts`,
`frontend/src/lib/__tests__/useCacheStatus.spec.ts`,
`frontend/src/components/__tests__/ExportIssuesIndicator.spec.ts`, and
`frontend/e2e/event-stream.spec.ts` in Chromium, Firefox, and WebKit). The design and
the later producers are in [ADR 0004](adr/0004-background-sync-and-event-stream.md).

`GET /api/events` is one app-wide stream in the Server-Sent Events format
(`text/event-stream`), read by the browser with `fetch`. It accepts the
session cookie or a read-scoped access token. Each frame has an `id` of the
form `<boot id>:<seq>`, an `event` type, and one `data` line holding the
envelope `{seq, at, type, product, data}`. Events carry identifiers, counts,
and times, never data; clients fetch the data from the usual endpoints.

| Event | Data | Sent |
| :--- | :--- | :--- |
| `hello` | `{boot_id, seq, build, source}` | First frame of every connection |
| `resync` | `{seq, reason}`: `restart`, `gap`, or `invalid_cursor` | When the cursor sent cannot be served; refetch everything |
| `auth` | `{status}` | The heartbeat check failed; the stream ends |
| `projects.changed` | `{added, removed, changed, truncated, count}` with `{uuid, name, version}` entries (`changed` adds `fields`), or `{initial: true, count}` for the first list | After a stored project-list change. Risk score and metrics alone are no change |
| `assessments.changed` | `{product, project_uuids, keys_count, origin: "local"}` | After an import merge or a discarded export changed DTVP's records, once the open views were updated. `dt` and `export_echo` are reserved for the scheduler |
| `export.state` | `{pending, failed, oldest_pending_at}` | Reviewers only, when the export queue numbers change (checked at most every 2 s, and every 60 s) |
| `cache.refreshed` | `{last_refreshed_at}` | When the cache's refresh time moved, for example after the background refresh of active versions saved new data (checked at most every 2 s, and every 60 s) |
| `source.state` | `{dt: unknown\|ok\|down\|misconfigured, since, last_success_at, error_class}` | When a project-list read from Dependency-Track changes the state; 401/403 is `misconfigured` |

- **Heartbeat and authentication.** Every 15 seconds the server sends the
  comment `: hb` with the current cursor as `id:`, re-runs the authentication
  of the request that opened the stream, and re-reads the role. A failed check
  sends `auth` and closes the stream: a revoked or expired access token ends
  it, and a role change switches the reviewer filter in place. A browser
  session cookie cannot fail this check: the session is a stateless token
  without expiry and the open request keeps its cookie, so a logout in another
  browser does not end the stream on the server. Server-side session
  revocation and expiry plug into the `session_valid` hook of the event routes
  when sessions get server-side state (branch `fix/session-key-and-expiry`).
  A logout in the browser itself stops the stream in every tab (see the
  browser client below). Streams end after 27 to 30 minutes (the lifetime is
  shortened by up to 10 % at random, so streams opened together do not
  rotate together) and the client reconnects.
- **Cursor of filtered clients.** Events a client may not see (reviewer-only
  `export.state` for analysts) send no frame, but the heartbeat `id:`, and a
  last one when the stream rotates, moves the client's cursor past them, so a
  reconnect replays from there instead of hitting a `gap`.
- **Resume.** A client reconnects with `?since=<boot id>:<seq>` or the
  `Last-Event-ID` header (the query wins) and receives every event after it.
  A cursor from another process start (`restart`), one older than the buffer
  (`gap`), or a malformed one (`invalid_cursor`) gets one `resync`.
- **Limits.** The last `DTVP_EVENT_BUFFER_SIZE` (2,000) events are kept for
  replay. Each connection is a cursor into that buffer, so a slow client only
  falls behind. Above `DTVP_EVENT_MAX_CONNECTIONS` (200) open streams the
  server answers `503` with `Retry-After: 30`. One user may hold at most
  `DTVP_EVENT_MAX_CONNECTIONS_PER_USER` (20) streams; more get `429` with
  `Retry-After: 30`, so one principal cannot take every slot.
- **Polling.** `GET /api/events/poll?since=` returns the same events as JSON
  `{boot_id, cursor, events, resync, more}`, at most 500 per call, for clients
  whose proxy cannot stream. Without `since` it returns the current cursor.
  The browser gives up a poll after 20 s and makes the next one, so a proxy
  that holds a poll does not end the fallback.
- **Scope.** The hub is process-local, like the task registries: one backend
  worker.
- **Shutdown.** Uvicorn runs the application's shutdown only after open
  connections have finished, and a stream never finishes on its own before it
  rotates. The application therefore chains its own handler in front of
  uvicorn's SIGINT and SIGTERM handlers (`dtvp/shutdown_signals.py`): the
  signal closes the hub, every open stream ends at once, and uvicorn's
  graceful shutdown proceeds. The lifespan teardown closes the hub again as a
  backstop.
- **Browser client** (`frontend/src/lib/eventStream.ts`). One stream per
  browser and DTVP instance: the tabs elect a leader with the Web Locks API
  (lock `dtvp:events:leader:<API base>`) and share its events, cursor, and
  status over the BroadcastChannel `dtvp:events:<API base>`. Both names carry
  the API base (for example `/dtvp/api`), so two instances under different
  context paths on one origin keep separate leaders, events, and sign-outs.
  When the leader's tab closes, another tab takes the lock and resumes from
  the last cursor it saw. Without these APIs each tab holds its own stream.
  The leader reconnects with full-jitter backoff from 1 to 30 seconds, within
  5 seconds after a server rotation, and after a `503` or `429` at
  `Retry-After` plus up to the same time again at random, so refused browsers
  do not come back together. A connection whose response headers do not
  arrive within 35 seconds (a proxy that holds the response) and a stream
  silent for 35 seconds count as failed. After three failures in a row
  it also polls `/api/events/poll` every 15 seconds until a stream says
  `hello` again. A 401 or an `auth` frame signs every tab out, and a logout in
  one tab stops the stream in all of them. The task streams and the event
  stream share one line reader (`streamLines.ts`).
- **Consumers.** The cache status (`useCacheStatus`) refetches one second
  after `hello`, `resync`, `projects.changed`, `source.state`,
  `export.state`, `assessments.changed`, or `cache.refreshed`; it polls every
  30 seconds only while the stream is not live, and every 5 minutes as a
  safety net while it is. The reviewers' export warning takes its numbers
  from `export.state`, refetches when its tab becomes visible, and polls
  every 60 seconds only while the stream is not live.
- **Known limits.** Saves by users publish no event yet. The project-list
  reads of the automatic code-analysis sweep, which uses its own cache
  manager, are not announced. A background refresh announces only that the
  cache's refresh time moved (`cache.refreshed`), not which products
  changed. Per-product events come with the scheduler of ADR 0004. A cookie
  session ends a stream server-side only once sessions have server-side state
  (see the heartbeat above).

## Capacity Planning

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

### Assessment Record

DTVP keeps a record of every assessed finding, held in memory and in the
database ([ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md)). The
numbers below are from 2026-11-18 on a 20-CPU development host with CPython
3.15 and synthetic assessments (three to four team blocks each):

```bash
uv run python scripts/benchmark_assessment_store.py --assessments 50000 200000
```

| | 50,000 assessments | 200,000 assessments |
| :--- | ---: | ---: |
| Adopting on import | 9.9 s (5,000 per second) | 40.8 s |
| Later import of a 1,000-finding project, nothing changed | 1.6 ms | 1.9 ms |
| Same, every assessment lost in Dependency-Track (all queued again) | 109 ms | 108 ms |
| Start with an existing database | 0.4 s | 2.4 s |
| One-off read of existing assessments into fields | 5.8 s | 27.7 s |
| Database, 2.3 KB texts | 368 MiB | 1,452 MiB |

Time does not grow with the number of records already stored; memory and disk
grow linearly with the number of assessments and the length of their texts.

- **Memory:** a record holds its text once plus about 1.2 KB. With 50,000
  assessments that is 174 MiB at 2.5 KB per text and 103 MiB at 1 KB
  (measured with `tracemalloc`). Process memory after a restart with 50,000
  assessments of 2.3 KB was 224 MiB above an empty process.
- **Disk:** the text is stored twice: in the record and split into the team
  fields. The value last agreed with Dependency-Track and the history entry
  of an adopted assessment refer to the record while they equal it; a
  database trigger writes the text out to them when the record changes. That
  brought the databases in the table down from 618 and 2,468 MiB.
  An existing database is converted at the first start; the file itself only
  shrinks after `VACUUM`. The imported finding adds one more copy.
- **Sizing example:** about 51,000 assessed findings with texts around 1 KB
  need roughly 110 MiB of memory for the records and 400 MiB of database
  (measured with 52,050 synthetic findings in 347 projects).
- **Through the application** (`CacheManager`, mock source): the first import
  of a 1,000-finding project took about 200 ms, a re-import without changes
  68 ms, a CycloneDX VDR of 1,000 findings 104 ms, and listing 1,000 queued
  exports 217 ms. That list carried both texts of every entry (5.4 MiB of
  JSON) when measured; it now leaves them out and the Export tab loads them
  per entry.

Not measured: the HTTP layer, grouping tasks, concurrent users, and a real
Dependency-Track. The sizing example above was measured before the text was
reduced to two copies; expect a smaller database.


### Instance Dump

The [instance dump](deployment.md) was measured on 2026-11-20 on the same
20-CPU host with CPython 3.15, using the synthetic assessments of the
benchmark above (about 2 KB of text each, adopted on import, so every record
has one history entry):

```bash
uv run python scripts/benchmark_backup.py --assessments 10000 50000
```

| | 10,000 assessments | 50,000 assessments |
| :--- | ---: | ---: |
| Database before the export | 72 MiB | 361 MiB |
| Export (snapshot, records, compression) | 5.1 s | 20.3 s |
| Dump file | 1.1 MiB | 5.7 MiB |
| Verify | 4.3 s | 19.7 s |
| Restore into an empty instance, in total | 10.4 s | 50.0 s |
| of which staging the records | 5.4 s | 27.3 s |
| of which reading them into fields | 1.0 s | 5.1 s |
| of which the round-trip proof | 0.3 s | 1.5 s |
| of which the swap | 0.01 s | 0.01 s |
| Database after the restore | 71 MiB | 358 MiB |

Export, verify and restore grow linearly with the number of records. The
synthetic texts repeat a great deal, so they compress far better than real
ones; plan the dump size of a real instance from a real export (`python -m
dtvp.backup inspect` shows it). The swap, the only step during which the
instance is not consistent on disk, takes milliseconds whatever the size.
The restore writes its staged databases without fsync per statement
(`synchronous=OFF`) and syncs each file once when it is complete; a crash
before that discards the staged files, never the live ones.
