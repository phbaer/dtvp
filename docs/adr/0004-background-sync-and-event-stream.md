# ADR 0004: Backend I/O runs in the background; clients follow an event stream

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-20, repository owner) |
| Implementation status | In progress (2026-11-20): event channel implemented; see [Implementation progress](#implementation-progress) |
| Supersedes | The read-through import of [ADR 0002](0002-local-first-database-with-import-and-export.md) (a version is read from Dependency-Track when a reader finds nothing stored). Its database, ports, and export queue remain. |
| Related | [ADR 0003](0003-dtvp-is-the-record-for-assessments.md) |

This record is the canonical home of the design. The guides link here and
describe only what is implemented.

## Context

DTVP reads from its database, but every reader in `dtvp/dt_cache.py`
(`get_projects`, `get_vulnerabilities`, `get_project_vulnerabilities`,
`get_bom`, `get_analysis`) reads from Dependency-Track when nothing is stored.
Opening a version for the first time, the dashboard project list, statistics,
dependency chains, the CycloneDX export, the tmrescore inventory, and the MCP
tools therefore wait on Dependency-Track whenever they reach something not
yet imported. The complete project list is read from Dependency-Track whenever
the stored copy is older than `DTVP_DT_PROJECT_LIST_TTL_SECONDS` (30 seconds).
That is half the 60-second background interval, so about half of all
dashboard loads wait on Dependency-Track. Some paths go there every time: the
tmrescore context, the Reload in the detail view, the manual export, and the
strict conflict check.

The background refresh keeps at most `DTVP_DT_ACTIVE_PROJECT_LIMIT` (8)
project **versions** current. Their access time is renewed by
`record_project_access`, which `get_vulnerabilities` and `get_bom` call
(`dt_cache.py:1396` and `:1523`). `refresh_project` goes through those two
readers, so every background re-read renews the version itself, and the
15-minute expiry (`DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS`) hardly applies: a
version leaves the set only when eight more recently opened versions push it
out. Versions that nobody opened are imported only by the automatic
code-analysis sweep, which runs a second `CacheManager` on another thread
(`main.py:854`).

Once a project has loaded, nothing reaches the client. The only push channel
is a per-task stream that closes when the task completes. A BOM upload that
replaced components went unnoticed until something forced a fresh read.

The other integrations behave the same way. Agentyzer health and its job list,
tmrescore health and session setup, and Vulnrichment lookups are called from
requests, while their status is polled from five independent timers.

## Drivers

- Loading a view never interacts with Dependency-Track or another backend.
- Clients learn about new versions, new and removed findings, changed
  advisories, assessment changes, and export state without reloading.
- Unknown, not yet imported, stale, and failed are different states, and
  each is shown as such.
- The load on Dependency-Track is bounded and configurable.
- No additional infrastructure for the supported single-process deployment.

## Decision

1. **One background owner for all Dependency-Track reads.** A sync scheduler
   (`SourceSync`) in the backend process reads the project list, findings,
   vulnerability records, BOMs, and analyses with the API key. Request
   handlers, grouped tasks, and MCP tools never hold a Dependency-Track client
   and never forward browser credentials. Writes keep going through the
   export queue ([ADR 0003](0003-dtvp-is-the-record-for-assessments.md)), and
   the archive restore uses that queue too.
2. **Readers are store-only.** A reader returns the stored data together with
   its sync state (`synced`, `never_synced`, `failed`, `gone`), the time of
   the last read, and the generation it belongs to. Reading something not yet
   stored queues an import; it never calls Dependency-Track.
3. **Sync state is persisted per version**, with its status, the time of the
   last attempt, success, and change, its errors, the Dependency-Track list
   signals, content digests, the current generation, and pending requests.
4. **Scheduling by product interest and change signals.** The project list is
   read every interval and compared with the stored one. Every version of a
   product that a client is watching has its findings re-read regularly.
   Vulnerability records and BOMs are re-read when the list signals a change,
   or after a safety interval. Every other active version is imported once and
   then re-read on a list signal or after a maximum age. Only user activity
   counts as interest. A user request ("Refresh from Dependency-Track") comes
   first. One request budget applies to all Dependency-Track calls, including
   the export, together with per-version backoff and a circuit breaker.
5. **Changes are detected by content digest** over what Dependency-Track
   returned, not by whether a stored document was rewritten. Revisions are
   bumped and events sent only when content changed, and an echo of DTVP's own
   export is not a change made in Dependency-Track.
6. **One app-wide event stream** at `GET /api/events`, in the Server-Sent
   Events format and read with `fetch`. Events carry identifiers, counts, and
   times, never data; clients fetch the data from local endpoints. The stream
   has a sequence number, sends a heartbeat every 15 seconds, re-checks the
   caller's authentication on each heartbeat, and replays missed events within
   one process. After a restart or a gap it sends a single `resync`, and the
   persisted sync state tells the client what changed while it was
   disconnected. One browser holds one stream, shared by its tabs.
7. **Clients do not lose their place.** A first import replaces a placeholder
   on its own. Any other change offers "Update view", which swaps in a newly
   built view and keeps filters, scroll position, and open cards. Nothing is
   swapped while an assessment is being edited.
8. **The other integrations follow the same rule.** Health checks, job lists,
   prompts, session setup, and evidence lookups run in the background and
   report through the event stream.

The repository owner decided the open questions on 2026-11-20:

- **User decision 1.** Import and keep current **every** active version in
  Dependency-Track. The backfill runs at a budget-limited rate, versions are
  re-read on list signals, and a safety re-read runs every 12 hours.
- **User decision 2.** For watched products, the findings export is read every
  120 seconds per version. Vulnerability records and the BOM are re-read on
  change signals, with safety re-reads after 6 hours and 24 hours. A global
  cap of 4 Dependency-Track requests per second (burst 8) is shared with the
  export.
- **User decision 3.** Explicit artifact downloads from Agentyzer and
  tmrescore, the archive import preview and the BOM upload during archive
  apply (both as tasks), and the OIDC login stay exceptions.

## Design

### Sync state

A table `sync_versions` (local store migration `0005_source_sync.sql`; `0003` and `0004` hold the fixed versions of the VDR recommendation,
reserved) holds one row per Dependency-Track project version:

- `project_uuid` (key), `product_name`, `version`, `active_in_dt`
- `status`: `never_synced`, `queued`, `syncing`, `synced`, `failed`, `gone`,
  and `settled_status`, the last of `synced`, `never_synced`, `failed`, `gone`
- `first_seen_at`, `last_attempt_at`, `last_success_at`, `last_change_at`
- `consecutive_failures`, `next_due_at`, `last_error_class`, `last_error`
- the list signals `dt_last_bom_import`, `dt_last_vuln_analysis`
- `findings_digest`, `analyses_digest`, `vulns_digest`, `bom_digest`
- `generation`, and a staged generation while an import is uncommitted
- `requested_at`, `requested_by`, `request_id` for a pending user request

It replaces the `active_projects` metadata key and is the only source of the
"Read from Dependency-Track … ago" text. `GET /api/sync/versions?product=&changed_since=`
reports what changed while a client was disconnected, from `last_change_at`;
`GET /api/sync/status` reports the scheduler.

### Schedule and priorities

All values are defaults and configurable.

- **Project list:** read every `DTVP_DT_CACHE_REFRESH_SECONDS` (60 s) and
  compared with `sync_versions`. A new uuid becomes `never_synced`
  (`projects.changed{added}`); a missing or inactive one becomes `gone`
  (`projects.changed{removed}`); a changed `lastBomImport` or
  `lastVulnerabilityAnalysis` makes the affected kinds due at once.
  `lastRiskScore` is **not** a signal: every export changes it. Name searches
  filter the stored list; `DTVP_DT_PROJECT_LIST_TTL_SECONDS` is retired.
- **Watched products** (see interest below): findings every 120 s per version;
  vulnerability records on a signal or every 6 h; the BOM when
  `lastBomImport` changes or every 24 h.
- **Every other active version** is imported once (backfill) and then re-read
  on a list signal and every 12 h.

Work is deduplicated per (uuid, kind):

| Priority | Work |
| :--- | :--- |
| P0 | An explicit user request: "Refresh from Dependency-Track", or Reload |
| P1 | The first import of a version of a watched product, or a miss on a read |
| P2 | Due re-reads of watched products, and versions whose list signal changed |
| P3 | The backfill of first imports |
| P4 | Safety re-reads |

Each item is raised one level for every 10 minutes it has waited.

### Limits

- At most 2 versions are synced at a time; the kinds of one version run in
  order (findings, vulnerability records, BOM).
- One token bucket for every Dependency-Track request: 4 per second, burst 8,
  shared with the export flush and the per-finding analysis reads.
- A failing version backs off exponentially, capped at 1 hour.
- A circuit breaker opens after 5 consecutive transport, 5xx, or 429
  failures, pauses all Dependency-Track work including the export, and probes
  `/api/version`. A 401 or 403 opens it as `misconfigured`. While it is open,
  everything is served from the store with its read time.

### Change detection

Digests are sha256 values over sorted canonical tuples:

| Digest | Covers |
| :--- | :--- |
| findings | (component uuid, vulnerability uuid) identities |
| analyses | key, state, justification, response, details hash, suppressed |
| vulns | id, severity, scores, and a hash of description and references |
| BOM | components (purl or name@version) and dependency edges, without serial number or timestamp |

- **Raw payload.** Each digest is computed inside the import path over the raw
  Dependency-Track response, before `_read_texts_without_state`,
  `_restore_recreated_finding_assessments`, `_overlay_local_analysis`, and the
  merge. The stored findings carry DTVP's overlay, so the upgrade seeds only
  the identity digests: the findings identity set from the stored findings
  (the overlay does not change identities), and the vulns and BOM digests
  from the stored raw vulnerability records and BOM. `analyses_digest` is
  seeded empty, meaning unknown; the first comparison stores it and emits
  nothing.
- **Echoes.** Each analysis that differs from the previous read is classified
  against the export queue. If Dependency-Track's value equals the value DTVP
  last exported for that key (`mark_synced`, `note_exported`), the change has
  origin `export_echo`: it is not counted in `analyses_changed_in_dt` and
  never marks an open card. Only keys that `reconcile_remote` adopts,
  requeues, or replaces count as origin `dt`.
- `lastRiskScore` is removed from the grouped-task fingerprint
  (`get_grouped_cache_revision`), because every export changes it.
- Revisions are bumped and `version.synced` sent only when a digest changes,
  so grouped tasks and the summary index survive re-reads that find nothing
  new. The identity diff gives `findings_added`, `findings_removed`, and up to
  20 `new_vuln_ids` with a truncated flag.

### Generations

`SourceSync` stages the kinds of one version and commits them in one store
transaction that also bumps `sync_versions.generation` and the status.
`read_version(uuid)` returns all kinds of one generation. While a staged
generation is uncommitted, readers serve the previous complete generation with
state `synced`, and the version's sync state separately reports `syncing`.
The grouped task, the CycloneDX export, and the tmrescore inventory read only
through `read_version`, so a view never joins new findings to old
vulnerability records or an old BOM.

### Interest and leases

A product is watched while an event stream subscribes to it and for
15 minutes after (`DTVP_SYNC_WATCH_TTL_SECONDS`). Interest is renewed by:

- the event stream subscription (the browser leader announces the union of
  its tabs' products; see "Product interest from the browser" below),
- `GET /api/tasks/{id}` (the task lease of an open project),
- the MCP project tools,
- store reads by authenticated users, by session or access token.

The last two take a short 15-minute lease, renewed at most once per product
per 60 seconds. Sync work never renews interest. The self-renewal through
`record_project_access` is removed in the same step that adds this interest,
never before. MCP and REST responses carry `synced_at` and `state`, so agents
see the age of the data.

### Recovery

At startup `SourceSync` resets `queued` and `syncing` rows to their
`settled_status` and drops staged generations, then rebuilds the queue from
`sync_versions`: due `next_due_at`, `never_synced`, and `requested_at`. User
requests are persisted on the row, so a restart re-queues them; a
`sync.request` event re-announces their state after a `resync`.

### Events

Envelope: `{seq, at, type, product, data}`; the SSE `id` is `<boot id>:<seq>`.

| Event | Payload |
| :--- | :--- |
| `hello` | `{boot_id, seq, build, source}`; first frame of every connection |
| `resync` | `{seq, reason}`: `restart`, `gap`, or `invalid_cursor` |
| `auth` | `{status}`; the stream ends |
| `projects.changed` | `{added, removed, changed, truncated, count}`, or `{initial, count}` for the first list |
| `version.sync_state` | `{uuid, product, status, position}`, at most one every 5 s per version |
| `version.synced` | `{uuid, product, version, synced_at, generation, first_import, kinds_changed, findings_added, findings_removed, new_vuln_ids, truncated, vulns_changed, analyses_changed_in_dt, bom_changed}`, only on a change or a first import |
| `version.sync_failed` | `{uuid, product, error_class, consecutive_failures, last_success_at, next_attempt_at}`, on a transition |
| `source.state` | `{dt: unknown\|ok\|down\|misconfigured, since, last_success_at, error_class, backlog}` |
| `assessments.changed` | `{product, project_uuids, keys_count, origin: local\|dt\|export_echo}` |
| `export.state` | `{pending, failed, oldest_pending_at}`, reviewers only |
| `cache.refreshed` | `{last_refreshed_at}`, when the cache's refresh time moved; until `version.synced` exists it is the only sign of a background refresh |
| `sync.request` | `{request_id, state, done, total}` |
| later | `analysis_queue.changed`, `tmrescore.session`, `integration.health`, `ssvc.updated` |

### Transport and the browser leader

- `GET /api/events?since=<boot>:<seq>` (or `Last-Event-ID`) returns
  `text/event-stream` from a plain `StreamingResponse`. Each connection holds
  a cursor into one shared ring buffer (2,000 events), not a queue of its
  own; a client that falls out of the buffer gets `resync`. Connections are
  capped (200; 503 with `Retry-After` above it). `GET /api/events/poll`
  returns the same events as JSON for clients whose proxy cannot stream.
- `frontend/src/lib/eventStream.ts` elects one leader per browser profile and
  DTVP instance with `navigator.locks` (exclusive lock
  `dtvp:events:leader:<API base>`) and shares events, the cursor, and the
  status over `BroadcastChannel('dtvp:events:<API base>')`. Web Locks and
  BroadcastChannel are scoped to the origin, not the path, so the API base
  keeps two instances under different context paths apart. A new leader
  resumes from the last cursor it saw. Without these APIs each tab holds its
  own stream.
- Browsers allow about six HTTP/1.1 connections per host. The Compose nginx
  listens with HTTP/1.1, so HTTP/2 is recommended at the TLS-terminating
  proxy, and one stream per browser keeps the connection count low either
  way.
- The client reconnects with full-jitter backoff from 1 to 30 seconds and
  polls `/api/events/poll` every 15 seconds after three failures in a row.
- nginx streams `/api/events` and both task-event paths without buffering.
- Each user may hold a limited number of streams (20; 429 with
  `Retry-After` above it), so one principal cannot take every slot. Refused
  clients retry after `Retry-After` plus up to the same time again at
  random, and stream lifetimes are shortened by up to 10 % at random, so
  clients do not return together.
- Heartbeats carry the cursor as `id:`, so a client that is filtered out of
  some events still advances past them.
- The stop signal (SIGINT, SIGTERM) closes the hub before uvicorn waits for
  open connections; otherwise an open stream would hold the graceful shutdown
  until it rotates.

### Product interest from the browser

SSE carries nothing from the client, so the subscription is its own request:

- Each tab tells the leader over the channel which products it shows
  (`{kind: 'interest', tab, products}`), when its route changes and every
  60 seconds; the leader drops a tab that has not reported for 2 minutes or
  that said goodbye on `pagehide`.
- The leader sends `PUT /api/events/interest` `{client_id, products}` with
  the union when it changes and every 60 seconds while it is not empty.
  `client_id` is random per leader term. The server keeps one lease per
  `(user, client_id)` with the watch TTL; a lease is never renewed by sync
  work, and an empty list ends it.
- The scheduler reads the union of live leases with the other interest
  sources above.

### Stream authentication

Each `/api/events` connection re-runs the existing current-user dependency
(`dtvp.auth.get_current_user`) on every heartbeat and re-derives the role with
`get_user_role`. A 401 or 403 sends `event: auth` and closes the stream; a
role change updates the reviewer filter in place; a changed identity closes
the stream. Streams rotate after 27 to 30 minutes. A revoked or expired
access token is caught by the same check. A browser session cookie is not: it
is a stateless token without expiry, and the open request keeps the cookie it
was opened with, so the check cannot see a logout in another browser or an
expired session. The routes therefore take an optional `session_valid`
check, run at each heartbeat, that accepts every session until sessions get
server-side state (session key and expiry, branch
`fix/session-key-and-expiry`). In the browser, a logout is broadcast to every
tab, and a 401 or an `auth` event signs every tab out.

## Alternatives

- **Keep reading through on a miss and only make the first open
  asynchronous**: every other reader still reaches Dependency-Track on a miss.
- **Raise the limit of 8 active versions, or count products instead**: keeps
  the self-renewal and the unconditional three reads per version, and leaves
  versions that nobody opened unimported.
- **WebSockets**: not available as deployed (no `websockets` or `wsproto`, no
  Upgrade handling in nginx, `boot.py` closes them early), and the traffic only
  goes from server to client.
- **Native `EventSource`**: cannot send an access token and hides a `401`.
- **NDJSON for the app-wide stream**: works, but has no standard resume
  identifier. NDJSON stays for task progress.
- **One stream per tab**: exhausts the HTTP/1.1 connection limit with a few
  tabs.
- **A durable event log written in the same transaction as the data**: the
  assessment outbox and the imported data do not share a transaction. The
  persisted sync state already answers "what changed while I was away".
- **Webhooks from Dependency-Track as the trigger**: they need administrator
  configuration and a route from Dependency-Track to DTVP, and they miss
  assessment changes. They remain a possible accelerator, never the source of
  truth.
- **A broker or a separate sync process**: needed only with several workers.
- **Swapping the view on every change**: cards would move under a reviewer.

## Consequences

- A version that has not been imported yet shows as "Not read from
  Dependency-Track yet" instead of blocking the view. A fresh installation
  imports its whole portfolio within the request budget.
- Assessment changes made directly in Dependency-Track on versions nobody
  watches are seen only at the next re-read. Under ADR 0003 they are
  overwritten by the next export anyway; the freshness text says when the data
  was read.
- `DTVP_DT_PROJECT_LIST_TTL_SECONDS`, `DTVP_DT_ACTIVE_PROJECT_LIMIT`,
  `DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS`, and
  `DTVP_ASSESSMENT_STRICT_DT_CONFLICTS` are retired, and new sync and event
  settings replace them. Removing the strict conflict check needs a release
  note.
- `POST /api/export` and the Reload of a vulnerability return at once. Their
  results arrive as events.
- Request-scoped Dependency-Track clients and the forwarding of browser
  credentials are removed, as `docs/deployment.md` already describes.
- The event hub, the buffer, and the watch interest are held in the process.
  More than one backend worker remains unsupported; with several, both the
  notifications and the Dependency-Track load would split.
- External proxies must not buffer `text/event-stream` and must keep idle
  connections open longer than 15 seconds. A polling fallback covers proxies
  that do not.
- The automatic code-analysis sweep and the project archive loop no longer
  read Dependency-Track; they read the store, and `version.synced` wakes them.

## Confirmation

- A test fails if any HTTP route, MCP tool, or grouped task calls a
  Dependency-Track client. The test replaces the client with one that raises
  outside the scheduler, and runs against a fixture database.
- Scheduler tests: priority order, aging, product interest without
  self-renewal, conditional re-reads, backoff, the circuit breaker, and the
  request budget shared with the export.
- No `version.synced` event and no revision bump for unchanged data,
  including the first pass after a restart and after a memory-cache eviction.
- Raw-payload digests: a version with a pending local assessment produces no
  `version.synced` and no revision bump on the first pass after the upgrade.
- Echoes: export, then re-read: no `assessments.changed{origin:dt}` and no
  grouped revision bump.
- Generations: a reader running during a staged import sees the previous
  complete generation of every kind.
- Recovery: a process stopped during an import restarts with no row stuck in
  `queued` or `syncing`, and a pending user request runs.
- Reconnecting with a sequence number yields every missed event, or exactly
  one `resync`.
- Stream authentication: a stream whose authentication or session check
  fails at a heartbeat sends `auth` and ends; a role change switches the
  reviewer filter.
- Shutdown: with a stream open, SIGTERM ends it and the process exits
  promptly.
- Product interest: a product shown in any tab of a browser is watched
  without self-renewal, and stops being watched one TTL after the last tab
  closes it.
- Several tabs of one browser hold one stream (Playwright), and another tab
  takes over when the holder closes.
- Playwright in Chromium, Firefox, and WebKit, against the mock
  Dependency-Track: opening a product not yet imported, then a BOM change that
  shows the banner, then reconnecting after a backend restart, then
  Dependency-Track going down.
- Request rate against a 29-version product and a 500-version fixture, kept
  within the configured budget.

## Implementation plan

| Step | Scope | Notes |
| :--- | :--- | :--- |
| 1 | docs(adr): this record; import wording corrected | |
| 2 | feat(events): event hub, `/api/events` and `/api/events/poll`, nginx; `eventStream.ts` with a leader; producers `hello`, `projects.changed`, `assessments.changed{origin:local}`, `export.state`, `source.state`; cache status and export indicator follow events | Lands before any store-only reader |
| 3 | fix(sync): the project list is served from the store | Name search filters the stored list; `list_synced_at`; no 30 s read. `record_project_access` and its self-renewal stay |
| 4 | feat(sync): `sync_versions` (local store migration `0005_source_sync.sql`; `0003` and `0004` hold the fixed versions of the VDR recommendation) | Raw-payload digests, echo classification, `lastRiskScore` out of the fingerprint, generation and request columns. Recorded during today's refresh. `GET /api/sync/versions`, `GET /api/sync/status` |
| 4a | feat(events): product interest from the browser | Tabs report their products to the leader over the channel; the leader's union goes to `PUT /api/events/interest` (see "Product interest from the browser"); server-side leases per `(user, client_id)` with the watch TTL. Tests: the channel union with tabs joining, leaving, and going silent; lease renewal and expiry in route tests; a Playwright check that two tabs on different products yield one request with both. Lands before step 5 retires the self-renewal |
| 5 | feat(sync): `SourceSync` scheduler | Priorities with aging, token bucket shared with the export, backoff, circuit breaker, backfill of all active versions, product interest (from the leases of step 4a and the other sources above), startup recovery, staged commit per version. Producers `version.sync_state`, `version.synced`, `version.sync_failed`, `assessments.changed{origin:dt\|export_echo}`, `source.state{backlog}`. The self-renewal and the `DTVP_DT_ACTIVE_PROJECT_*` and `DTVP_DT_PROJECT_LIST_TTL_SECONDS` settings are retired here |
| 6 | refactor(cache): store-only `read_*` methods beside the client-taking readers | `read_projects`, `read_version`, `read_findings`, `read_project_vulnerabilities`, `read_bom`, `read_analysis` return `StoredRead{data, state, synced_at, generation}`. The grouped task, statistics, and MCP use them. ProjectView shows placeholders, swaps on `version.synced{first_import}`, and offers "Update view". Dashboard: live list and "New" badges |
| 7 | refactor(cache): CycloneDX, dependency chains, tmrescore, and archive export use `read_*` | Remaining callers: `tmrescore_inventory_services.py`, `project_archive_services.py`, `dt_cache.export_cyclonedx`, `general_api_routes.py` (dependency chains), `auto_analysis_services.py`, `assessment_services.py`. Then the client-taking signatures are deleted and the guard test covers every route |
| 8 | feat(sync): Refresh from Dependency-Track | `POST /api/sync/requests` (P0, persisted), `POST /api/export` returns 202, Reload, archive restore through the export queue, strict conflict check removed (release note) |
| 9 | feat(integrations): Agentyzer, tmrescore, and SSVC in the background, with their events | |

## Implementation progress

| Decision | Status |
| :--- | :--- |
| 1 Background owner | Scheduler implemented 2026-11-21 (step 5): `SourceSync` owns the background reads and the export, with priorities and aging, one token bucket shared with the export, per-version backoff and a circuit breaker; see [Sync scheduler](../runtime.md#sync-scheduler). Request handlers still read through the client-taking readers on a miss until steps 6 and 7 |
| 2 Store-only readers | Not implemented |
| 3 Persisted sync state | Recording implemented 2026-11-21 (step 4): `sync_versions` with status, attempt/success/change times, failures, list signals, digests, generation and request columns, recorded during today's refresh; `GET /api/sync/versions`, `GET /api/sync/status`; see [Sync state](../runtime.md#sync-state). Step 5: staged syncs committed once per version, per-kind read times and the list signals of the last sync (migration `0006_sync_schedule.sql`), startup recovery. Readers serving the previous generation while a sync is staged come with `read_version` (step 6); the request columns are read, the request route comes with step 8 |
| 4 Scheduling by interest | Browser interest implemented 2026-11-21 (step 4a): tabs report their products to the leader, the leader renews one lease per `(user, client_id)` with `PUT /api/events/interest`, leases expire with `DTVP_SYNC_WATCH_TTL_SECONDS`; see [Product interest](../runtime.md#product-interest). Step 5: short leases from a user's reads (starting a grouped view, polling its task, MCP project tools), read by the scheduler; the self-renewal and `DTVP_DT_ACTIVE_PROJECT_*`, `DTVP_DT_PROJECT_LIST_TTL_SECONDS` are retired |
| 5 Content digests | Implemented 2026-11-21 (step 4): findings, analyses, vulnerability and BOM digests over the raw responses, `lastRiskScore` out of the grouped fingerprint. Step 5: echoes are classified against the value DTVP last exported (the record's base); `version.synced` is sent only on a digest change or a first import. Revisions still move when a stored document changes, which an unchanged read does not |
| 6 Event stream | Implemented 2026-11-20: hub, `/api/events`, `/api/events/poll`, nginx, producers `hello`, `projects.changed`, `assessments.changed{origin:local}`, `export.state`, `source.state`, `cache.refreshed`; step 5 adds `version.sync_state`, `version.synced`, `version.sync_failed`, `assessments.changed{origin:dt|export_echo}` and `source.state{backlog}`; per-user connection limit, cursor on heartbeats, streams end on the stop signal; the browser client with one stream per browser, the cache status and the export warning follow events; see [Event channel](../runtime.md#event-channel). The producers of later steps and the ProjectView and Dashboard updates are open |
| 7 Clients keep their place | Not implemented |
| 8 Other integrations | Not implemented |
