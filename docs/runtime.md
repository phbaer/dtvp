# Runtime and Capacity

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Runtime Shape](#runtime-shape)
- [Runtime Behavior](#runtime-behavior)
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
| `dtvp/access_token_*` and `mcp_server.py` | Personal access tokens, their audit log, and the MCP endpoint for AI agents |
| `dtvp/assessment_outbox_services.py` | Local assessments with their base value and history, the export queue, the merge with source values, and conflict resolution |
| `dtvp/bulk_workflows/` | Registry-backed bulk-change plug-ins |
| `dtvp/dt_client.py` and `dt_cache.py` | Dependency-Track access, in-memory document cache, overlays, and pending writes |
| `dtvp/local_store.py` | SQLite database for imported source data and the one-time JSON cache import |
| `dtvp/ports.py` | The source and sink interfaces the cache manager is written against; Dependency-Track implements both |
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
  misses for the same resource share one Dependency-Track request, the complete
  project list has a short freshness TTL across clients, and API-key requests
  reuse one application-lifetime HTTP connection pool. The background cache
  sync also retains its client between refreshes. Each caller still receives an
  isolated mutable snapshot. Cold finding loads use
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
  Pending assessment writes and their local overlays live in a transactional
  SQLite outbox. Newer changes to the same finding replace older pending
  values, and one application-wide bounded dispatcher retries Dependency-Track
  synchronization without multiplying write concurrency per client. When a
  finding disappears before synchronization, a Dependency-Track 404 triggers
  a live findings-API check. Only a valid response confirming that the exact
  project/component/vulnerability tuple is absent removes the queued export.
  A deleted project counts as such a response when the project lookup answers
  404 too while the API's version endpoint answers normally;
  the assessment itself is kept and marked inactive. Failed checks and
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
- Live task registries are process-local; the supplied Uvicorn/PM2 launch uses
  one backend worker. A horizontally scaled deployment needs a shared task and
  result store before enabling multiple backend workers.
- Startup status exists at `/startup` and `/api/startup`, in the static first
  paint, and in the Vue initialization view.

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
| Database, 2.3 KB texts | 618 MiB | 2,468 MiB |

Time does not grow with the number of records already stored; memory and disk
grow linearly with the number of assessments and the length of their texts.

- **Memory:** a record holds its text once plus about 1.2 KB. With 50,000
  assessments that is 174 MiB at 2.5 KB per text and 103 MiB at 1 KB
  (measured with `tracemalloc`). Process memory after a restart with 50,000
  assessments of 2.3 KB was 224 MiB above an empty process.
- **Disk:** the text is stored four times (the record, the value last agreed
  with Dependency-Track, the first history entry, and the team fields), about
  12.9 KB per assessment at 2.5 KB per text and 5.6 KB at 1 KB. The imported
  finding adds one more copy.
- **Sizing example:** about 51,000 assessed findings with texts around 1 KB
  need roughly 110 MiB of memory for the records and 400 MiB of database
  (measured with 52,050 synthetic findings in 347 projects).
- **Through the application** (`CacheManager`, mock source): the first import
  of a 1,000-finding project took about 200 ms, a re-import without changes
  68 ms, a CycloneDX VDR of 1,000 findings 104 ms, and listing 1,000 queued
  exports 217 ms (5.4 MiB of JSON, because the list carries both texts of
  every entry).

Not measured: the HTTP layer, grouping tasks, concurrent users, and a real
Dependency-Track. Known ways to reduce the disk use (not implemented): do not
store the text again in the history entry of an adopted assessment, and do
not store the agreed value when it equals the record.

