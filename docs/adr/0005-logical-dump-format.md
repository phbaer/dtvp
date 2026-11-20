# ADR 0005: Logical dump format for backup, restore and migration

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-20, repository owner) |
| Implementation status | Partly implemented (2026-11-20): export, inspect, verify; see [Implementation progress](#implementation-progress) |
| Amends | [ADR 0002](0002-local-first-database-with-import-and-export.md), consequence "Backups and project archives must cover the database file": the instance dump is the backup; the project archive is not a backup |
| Related | [ADR 0002](0002-local-first-database-with-import-and-export.md), [ADR 0003](0003-dtvp-is-the-record-for-assessments.md), ADR 0004 (background sync), which reserves the event-log high-water mark in the manifest |

## Context

ADR 0003 makes DTVP's database the record for assessments. Backup, restore
and retention are therefore operational requirements. Until now the only
backup was the advice in [Deployment](../deployment.md) to copy
`dtvp.sqlite3` with its `-wal` and `-shm` files, or to copy it while the
backend is stopped. That advice falls short:

- It misses other records: `code_analysis_results.sqlite`, whose default
  path is relative to the working directory; `tmrescore_proposals.json`;
  and the five settings files. A missing `user_roles.json` makes every user
  a reviewer.
- A raw file is tied to SQLite and to the migration checksums. The
  migration runner does not refuse a database newer than the code, so a
  downgrade runs silently on an unknown schema.
- The assessment tables use two storage tricks, `base_same` and
  `text_in_record`, and the trigger `assessment_state_keep_replaced_text`.
  Any copy at row level must resolve them, and any restore that updates
  texts would rewrite history.

The per-project archive `dtvp.project-archive/v1` is not a backup: it is
built from live Dependency-Track reads, strips comments, omits history,
sync state, the outbox, inactive findings, known projects, tokens, audit,
code analysis and configuration, and its restore writes to
Dependency-Track, not to DTVP's record.

## Drivers

- No record is lost: assessments including inactive ones, the revision
  history in its order, the outbox and sync state, known projects, audit,
  code-analysis runs and their applications, proposals and configuration.
- One format serves backup, restore, and moves to another host, version and
  storage engine.
- An online backup without downtime beside the background sync.
- A restore is validated before anything is written and cannot leave a
  mixed state.
- Credentials and secrets are not spread by accident.
- No new service to operate; the single-process deployment stays the
  supported one.

## Decision

1. **A logical dump `dtvp.dump/1`.** A ZIP of JSONL records, one JSON Schema
   per entity, a manifest with the digest, size and record count of every
   part, and the settings files as they are. There is no separate manifest
   checksum: the ZIP CRCs, the part digests and a `sha256sum` sidecar cover
   integrity. Every storage trick is resolved on export. The format is
   specified in [Backup and restore](../backup-and-restore.md).
2. **Whole instance only in version 1.** The manifest reserves `scope.kind`
   for a later per-project scope.
3. **Online export from snapshots.** Each SQLite file is snapshotted
   (`VACUUM INTO` for WAL files, the backup API in steps otherwise) and the
   records are streamed from the copy. Consistency is per store; the
   default shared file keeps assessments, history, outbox, source data,
   known projects, tokens and audit in one snapshot.
4. **Offline restore into an empty instance only.** Validate everything
   first; stage new files with the target's own migrations; insert records
   with their original ids and revisions, with INSERT only, so the trigger
   never fires; compact again with the rules of migration 0007; rebuild the
   derived tables; prove the round trip by re-exporting the staged files;
   swap the files under a journal. There is no merge. The backend holds an
   instance lock and refuses to start while a restore journal exists.
5. **Three version axes.** The format's major and minor version with
   required features; a version per entity schema, with upcasters; the
   DTVP version and the migration state, recorded as provenance only.
6. **Secrets.** Environment secrets are never in a dump. Access-token
   digests are unkeyed and therefore valid on any host: they are excluded
   by default and included only with an opt-in flag, which marks the dump
   with the required feature `credentials` and its file name with
   `-with-credentials`. The dump has no encryption of its own; it is
   written with mode 0600 and the operator encrypts it at rest.
7. **Ports.** Export and restore go through `DumpSource` and `DumpTarget`.
   The SQLite adapter owns the storage tricks; a PostgreSQL adapter can
   implement the same ports without changing the format.
8. **Operation.** A module CLI, `python -m dtvp.backup {export, inspect,
   verify, restore, recover, prune}`. There is no HTTP route: DTVP has no
   role above reviewer, and a dump holds the role map and the audit.
9. **Decisions of the repository owner (2026-11-20).**
   - Token digests are excluded by default; an opt-in flag includes them
     and marks the dump as containing credentials.
   - The project archive moves onto this format later. The container
     helpers (`dtvp/bundle_io.py`) and the entity schemas are shared now,
     and `scope.kind` is reserved.
   - Scheduled dumps run in the application, off by default; a host cron
     job is documented as an equal alternative.
   - `jsonschema` is a direct runtime dependency; restore and verify
     validate against the same published schemas the tests use.

## Alternatives

- **Raw file copy, the SQLite backup API or `VACUUM INTO` output as the
  format.** Tied to SQLite and the migration checksums, copies caches,
  misses the other files, does not detect a downgrade and cannot move to
  PostgreSQL. Kept only as the internal snapshot step, and as a documented
  cold copy for the same version while the backend is stopped.
- **SQL text dump (`.dump`).** The SQLite dialect; keeps the storage tricks
  and the trigger, and carries the derived and migration tables.
- **A dump of each table as it is.** The storage tricks, the integer
  booleans and the empty timestamps would become the format, so every
  storage change would change the format.
- **Extending the project archive, or one format for both scopes now.** The
  archive targets Dependency-Track and is reviewer-facing; a unified
  rewrite needs selective online import with identity remapping. Left for a
  later decision.
- **Merge restore into a populated instance.** Revision tokens, update ids
  and history ids collide, and ADR 0003 has no second writer to merge with.
- **Built-in encryption or signing.** Adds key management; tying it to the
  session key would make dumps unreadable after a key rotation.

## Consequences

- Restore needs free space for a second copy of the databases. Export needs
  temporary space of about the database size: 368 MiB at 50,000 and
  1,452 MiB at 200,000 assessments.
- Settings writes are atomic and validated first; this was a prerequisite.
- A new value in a closed enum of a dumped field (for example a sync status)
  is refused by every existing reader until the entity schema version is
  raised and an upcaster is added. A test compares the enums with the code.
- Every migration that changes rows needs an entry in the migration-effects
  table, and every migration that touches a dumped table updates the entity
  mapping and its schema in the same change. Coverage tests enforce both.
- One DTVP process per data directory, enforced by the instance lock; the
  lock needs a local filesystem.
- A move to a *different* Dependency-Track instance is not supported: every
  key is one of its UUIDs.
- ADR 0004 (background sync) starts a new event-log epoch after a restore.
- The project archive may later adopt the container and the entity schemas
  with `scope.kind = "projects"`; that is its own decision.
- [Deployment](../deployment.md) names the dump as the backup method and
  keeps the cold copy as a fallback for the same version.

## Confirmation

- A round trip over every entity: dump, restore into an empty instance, dump
  again gives identical record and settings files, including history
  revisions in order, `text_in_record` and `base_same` resolution, sync,
  base and remote values, pending and failing exports, inactive and
  cancelled records, known projects, source data, code-analysis results and
  applications, audit, tokens with the flag, proposals and instance
  metadata.
- The trigger does not fire during a restore; the history is unchanged.
- Every manifest and record written in the tests validates against the
  published schemas.
- Every validation rule has a negative test.
- Resume and abort work after a simulated crash between any two renames.
- An export runs while another connection writes, for WAL and non-WAL
  stores.
- The frozen fixture `tests/fixtures/dump-v1` restores in every later
  release.
- The coverage test, the migration-effects test and the enum test pass.
- Measured at 50,000 and 200,000 assessments: dump size, export, verify and
  restore time, recorded in [Runtime](../runtime.md).

## Implementation Progress

| Decision | Status |
| :--- | :--- |
| 1, 2, 5, 6, 9: format, schemas, versioning, credentials | Implemented (2026-11-20): `dtvp/resources/dump-schemas/1/`, `dtvp/backup/schemas.py`, `tests/test_dump_schemas.py` |
| 3: online export | Implemented (2026-11-20): `dtvp/backup/export.py`, `sqlite_source.py`; `tests/test_backup_export.py` |
| 4: offline restore | Not implemented |
| 7: ports | `DumpSource` implemented by `SqliteDumpSource`; `DumpTarget` declared, not implemented |
| 8: CLI | `export`, `inspect`, `verify` implemented; `restore`, `recover`, `prune` not implemented |
