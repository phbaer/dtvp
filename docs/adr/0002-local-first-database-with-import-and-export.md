# ADR 0002: Local-first database with import and export

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-17, repository owner) |
| Implementation status | Implemented (2026-11-17), with the limits listed under [Implementation progress](#implementation-progress); see [Import and export](../import-export.md) |
| Related | [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md) |

## Context

The Dependency-Track cache under `DTVP_DT_CACHE_PATH` already behaves like a
database: it holds projects, findings, vulnerability details, BOMs, and local
assessment overlays, and stays readable while Dependency-Track is unavailable.
Technically it is JSON files per project plus an in-memory LRU, with
assessments in a separate SQLite outbox that keeps per-finding revisions.

Semantically, Dependency-Track is still the source of truth: a refresh
overwrites cached data, and a local overlay only wins until it has been
synchronized. Several special cases exist only because of that model, for
example restoring assessments on recreated findings and confirming that a
finding is really gone before a queued write is dropped.

## Drivers

- Local work must not be lost or silently overwritten by a refresh.
- Assessment history should be queryable and auditable.
- Other sources and sinks should be possible without touching domain logic.
- Direct queries for the API and MCP tools instead of file scans.
- No additional infrastructure for the supported single-process deployment.

## Decision

1. **The local database is the system of record.** DTVP imports from a source,
   works on local state, and exports to a sink.
2. **SQLite in WAL mode**, one database file, behind a repository interface,
   migrated with the existing SQLite migration service.
3. **Source and sink ports.** Dependency-Track is the first adapter for both.
   The project archive is the intended second adapter. No further adapters are
   built until one is needed.
4. **Import.** Source facts (projects, versions, components, findings,
   vulnerability data, BOMs) are upserted. Findings that disappear from the
   source are marked inactive, not deleted, and keep their assessments.
5. **Assessment merge on import** is three-way against the last synchronized
   value: a remote-only change becomes a new local revision; a change on both
   sides is recorded as a conflict and surfaced through the existing
   Conflicting lifecycle and conflict dialog. It is never resolved silently.
6. **Append-only assessment revisions** with author, origin (user, agent,
   import, bulk workflow), and timestamp.
7. **Export.** The outbox becomes the export queue with per-finding sync
   status: clean, local ahead, remote ahead, diverged. Automatic background
   export stays the default; a manual mode lets a user review the pending
   change set before exporting.

## Alternatives considered

- **Keep the JSON cache and extend the outbox.** Rejected: keeps
  Dependency-Track as the source of truth and the special cases that follow.
- **PostgreSQL.** Rejected for now: it adds an operated service and only pays
  off together with the shared task store required for multiple backend
  workers. The repository interface keeps this option open.
- **Manual export only.** Rejected as the default: it would change behaviour
  for every existing user.

## Consequences

- A one-time migration imports the JSON cache and the current outbox. The JSON
  files are kept until the migration is verified, then the cache code is removed.
- Cache-oriented configuration (`DTVP_DT_CACHE_*`, `DTVP_ASSESSMENT_OUTBOX_PATH`)
  needs a compatibility and deprecation path.
- Backups and project archives must cover the database file.
- Pending local changes can now exist for a long time in manual mode; the UI
  must show sync status clearly.
- Grouped tasks keep their current design and read from the database.

## Confirmation

- Migrating an existing cache directory yields the same grouped results and
  pending writes as before.
- An import never changes a locally modified assessment without recording a
  conflict; tests cover each merge case.
- Grouped-query benchmarks (`scripts/benchmark_group_queries.py`) do not
  regress, and cold project loads are not slower than with the JSON cache.

## Implementation progress

Implemented and verified 2026-11-17, by decision:

1. **System of record.** Assessments read from the source are merged into
   local state; neither side overwrites the other unnoticed.
2. **One SQLite database** in WAL mode (`dtvp/local_store.py`), migrated by
   the existing migration service. It holds source data, local assessments
   with the export queue, and access tokens. An existing JSON cache and an
   existing stand-alone outbox file are each imported once and left in place.
3. **Ports.** `dtvp/ports.py` defines `VulnerabilitySource` and
   `AssessmentSink`; `DTClient` satisfies both and the cache manager is typed
   against them. No second adapter exists.
4. **Import.** Source facts replace the stored copy. An assessment whose
   finding disappears is kept and marked inactive, and is active again when
   the finding returns under the same identifiers.
5. **Three-way merge** against the value last agreed on, with a conflict
   recorded when both sides changed. Conflicts are listed as Conflicting with
   their own reason and settled in the detail view.
6. **Revision history** with origin and author for every local value.
7. **Export queue** with per-finding status and a manual mode
   (`DTVP_EXPORT_MODE`), reviewed and triggered under Settings → Export.

Refinements made during implementation:

- **Read before write.** With automatic export a change is sent within a
  second, long before an import could notice a concurrent change in the
  source. Each export therefore first reads the value it would replace
  (`DTVP_EXPORT_VERIFY_SOURCE`, on by default). This costs one extra read per
  exported finding.
- **A lost assessment is exported again**, not adopted as empty. When the
  source reports nothing at all for a synchronized assessment (no state, no
  text, not suppressed), as when Dependency-Track recreates a finding, the
  local value is queued for export. Deliberately resetting an assessment to
  empty in Dependency-Track is therefore undone unless it is also cleared in
  DTVP. A source value that still carries a state or a suppression is a
  change and is adopted. An empty source value never conflicts with a
  waiting local change, because the export overwrites nothing.
- **Explicit deletion.** Because an empty source value is repaired, removing
  an assessment needs its own operation: one team's block or the whole
  assessment, recorded as a revision and exported. Reviewer role for the
  General assessment or everything.
- **The value an edit was made on** travels with every save from the UI and
  is the base of a finding's first edit, so an edit made on an outdated view
  becomes a conflict.
- **Independent review (2026-11-17)** of this work found, and these commits
  fix: an export batch could send a value that had been saved again in the
  meantime and then report a conflict with itself; the lost-assessment rule
  fired on any source value with empty details, overwriting a state-only
  change; a stale stored copy as the base of a first edit caused false
  conflicts; an unexported edit was replaced when its vanished finding
  returned; a failed per-finding read looked like emptied details; resolving
  several conflicts was not atomic; a failed write could turn a conflict back
  into a retry; assessments from before the history had no entry; the export
  response counted dropped findings as exported; and schema statements in a
  migration were not applied atomically.
- **Unknown base.** Assessments that were waiting for export when the
  database was upgraded have no recorded base and export as before, without
  conflict detection, until their next sync.
- **Sync status vocabulary** is `synced`, `pending`, `error`, `diverged`,
  `inactive`, `cancelled` rather than the four names in decision 7.

Checked: `tests/test_local_store.py`, `tests/test_assessment_outbox_services.py`,
`tests/test_dt_cache.py`, `tests/test_assessment_conflicts.py`,
`tests/test_export.py`, `tests/test_ports.py`; a copy of a real cache
directory (33 documents) compared equal after import; conflict detection,
restart persistence, resolution, and manual export exercised against the mock
Dependency-Track in Chromium. Load times on 20,000 generated findings match
the JSON cache (cold 402 ms vs 396 ms, after restart 291 ms vs 269 ms); a
source refresh was about 20% slower (929 ms vs 774 ms), measured once on a
developer machine before the merge step was added.

Not done:

- Findings are still replaced as a whole list per project. A finding that
  returns under new identifiers is matched against the previous import only.
- Source facts other than assessments are not versioned or merged.
- Bulk workflows record their revisions without an author.
- The JSON cache import and the path-shaped document addresses in
  `dt_cache.py` remain until existing installations have migrated.
- Access tokens created with a build of this branch before the stores were
  merged lived in `data/access_tokens.sqlite` and are not copied; that build
  was never released.
- Not run against a real Dependency-Track instance or real project data.
