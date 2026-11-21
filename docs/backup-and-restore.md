# Backup And Restore: The Instance Dump

[Project overview](../README.md) · [Documentation index](../README.md#documentation) ·
[ADR 0005](adr/0005-logical-dump-format.md)

| | |
| :--- | :--- |
| Status | Format, export, inspect, verify, restore and recover: implemented; see [Implementation status](#implementation-status) |
| Owner | Repository owner |
| Verified | 2026-11-20 against `dtvp/backup/`, `dtvp/resources/dump-schemas/1/` and `tests/test_dump_schemas.py`, `tests/test_backup_*.py` |

An instance dump is a logical copy of everything DTVP keeps as its record:
assessments with their history and sync state, the export queue, source
data, known projects, the access-token audit log (and, on request, the token
digests), code-analysis runs, threat-model proposals and the settings files.
It is the backup of an instance and the way to move one to another host,
version or storage engine. The per-project archive is not a backup.

- [Implementation status](#implementation-status)
- [How to export and verify a dump](#how-to-export-and-verify-a-dump)
- [How to restore a dump](#how-to-restore-a-dump)
- [How to recover an interrupted restore](#how-to-recover-an-interrupted-restore)
- [Reference: format `dtvp.dump/1`](#reference-format-dtvpdump1)
  - [File and container](#file-and-container)
  - [Manifest](#manifest)
  - [Value conventions](#value-conventions)
  - [Entities](#entities)
  - [Settings files](#settings-files)
  - [What is not in a dump](#what-is-not-in-a-dump)
  - [Versioning](#versioning)
  - [Validation rules](#validation-rules)

## Implementation Status

| Part | Status |
| :--- | :--- |
| Format, manifest and entity JSON Schemas, frozen fixture `tests/fixtures/dump-v1` | Implemented |
| `export`, `inspect`, `verify` | Implemented |
| `restore`, `recover`, `verify --deep` | Implemented |
| Scheduled dumps and `prune` | Implemented |

A cold copy of the whole data directory, taken while the backend was
stopped, remains a fallback for the same DTVP version; see
[Deployment](deployment.md).

## How To Export And Verify A Dump

Run the commands where the backend runs, with the same environment and
working directory, so they resolve the same files. With Compose:

```bash
docker compose exec dtvp python -m dtvp.backup export
docker compose exec dtvp python -m dtvp.backup verify data/backups/<file>.dtvp-dump.zip
```

| Command | What it does |
| :--- | :--- |
| `python -m dtvp.backup export [--out FILE\|-] [--dir DIR] [--label L] [--include-access-tokens] [--without-source] [--tmp-dir DIR]` | Writes a dump while the backend keeps running. Without `--out`, a new file goes to `--dir`, by default `DTVP_BACKUP_PATH` (`data/backups`). Prints the file name |
| `python -m dtvp.backup inspect FILE [--json]` | Checks the container and the manifest and prints a summary; reads no record |
| `python -m dtvp.backup verify FILE` | Checks every record and the rules below (C, F, S, R, W) |

Exit codes: 0 done (warnings go to standard error), 1 refused or failed,
2 usage error.

What export does:

1. Refuses while a restore journal exists (E6) or another export or a restore
   holds `data/dt_cache/.dtvp-export.lock` (E5). It does not take the
   instance lock: the backend keeps working.
2. Snapshots each database into a private temporary directory
   (`.dtvp-dump-tmp-<instance>-*`, mode 0700, files 0600) in `--tmp-dir`,
   or beside the output file, or in `data/dt_cache` for standard output. It
   needs about 1.1 times the space the databases use (E7). `<instance>` is
   a digest of the instance's export lock path: directories left by an
   interrupted export are removed by the next export of the same instance,
   and those of other instances sharing the directory are left alone.
   - Databases in WAL mode are copied with `VACUUM INTO`, one read
     transaction that does not block writers.
   - The code-analysis results database is not in WAL mode; it is copied
     with the SQLite backup API in small steps that release the lock in
     between, within 300 s (E8).
   - Without `--include-access-tokens` the token rows are deleted from the
     copy at once.
3. Refuses a database whose migrations differ from this DTVP version's
   (E1): start the matching backend once, or use the matching version.
4. Streams the records from the copies, validating each against its schema
   and checking the referential rules as it goes; reads each settings file
   and `tmrescore_proposals.json` twice and refuses one that changed (E2) or
   is not JSON (E3).
5. Writes the manifest last, renames the file into place with mode 0600 and
   writes the `.sha256` sidecar.

Consistency is per database file. With the default layout one file holds
assessments, history, export queue, source data, known projects, tokens and
the audit log, so they come from one moment.

`--include-access-tokens` adds the token digests: anyone holding the dump
can use those tokens against a DTVP with the same data. The file name gets
`-with-credentials` and the manifest the required feature `credentials`.
Sessions are not in a dump.

### Encryption At Rest

A dump holds every assessment, the role map and the audit log. It is written
with mode 0600 and has no encryption of its own. Encrypt it when it leaves
the host, for example with [age](https://age-encryption.org):

```bash
docker compose exec -T dtvp python -m dtvp.backup export --out - \
  | age -r age1examplepublickey... > dtvp-$(date -u +%Y%m%dT%H%M%SZ).dtvp-dump.zip.age
```

Decrypt to a file before `verify` or `inspect`; both need a seekable file.

### Scheduled Dumps

Two equal ways; use one of them.

**In the backend.** Set `DTVP_BACKUP_INTERVAL_SECONDS` (off at `0`, the
default; at least 3600). After each interval the backend exports to
`DTVP_BACKUP_PATH` with the label `DTVP_BACKUP_LABEL`, verifies the new
file, and keeps the newest `DTVP_BACKUP_RETENTION_COUNT` dumps of that
label. `DTVP_BACKUP_INCLUDE_ACCESS_TOKENS` and `DTVP_BACKUP_INCLUDE_SOURCE`
choose what goes in; see [Configuration](configuration.md#backup). A run is
skipped while another export or a restore runs. The outcome (time, file
name, size, duration, last error; no paths) is the `backup` block of
`/api/performance-status`.

**Host cron.**

```cron
# m h dom mon dow  command
15 2 * * *  cd /srv/dtvp && docker compose exec -T dtvp python -m dtvp.backup export --dir /app/data/backups && docker compose exec -T dtvp python -m dtvp.backup prune /app/data/backups --keep 7
```

`python -m dtvp.backup prune DIR --keep N [--label L]` deletes the oldest
dumps beyond N, each with its sidecar. It considers only files named
exactly as an export names a dump of that label,
`<label>-<yyyymmddTHHMMSSZ>[-with-credentials][-N].dtvp-dump.zip`, whose
container and manifest check out, orders them by the manifest's
`created_at` (never by file time) and never deletes another file. A dump
labelled `dtvp-before-upgrade` therefore never counts toward the label
`dtvp`. Manual exports with the default label `dtvp` do share the
scheduler's retention (when `DTVP_BACKUP_LABEL` is `dtvp`); give a dump
you want to keep its own label. Instances sharing one backup directory
should still use different labels, because each one prunes every dump of its
label. Two exports of one label in the same second never overwrite each
other: an export reserves its file name before it writes, and the second one
gets a `-N` suffix.

Keep the backup directory on a different disk, or copy it off the host. The
backup directory is never part of a dump and does not make a restore target
count as holding records.

## How To Restore A Dump

A restore replaces the instance's records with those of a dump. It runs
offline: stop the backend first. Run it with the backend's environment and
working directory so it resolves the same files; with Compose:

```bash
docker compose stop dtvp
docker compose run --rm dtvp python -m dtvp.backup verify --deep /app/data/backups/<file>.dtvp-dump.zip
docker compose run --rm dtvp python -m dtvp.backup restore /app/data/backups/<file>.dtvp-dump.zip --dry-run
docker compose run --rm dtvp python -m dtvp.backup restore /app/data/backups/<file>.dtvp-dump.zip
docker compose start dtvp
```

`python -m dtvp.backup restore FILE [--dry-run] [--replace] [--new-instance]
[--accept-dt-url-change] [--accept-pruning] [--accept-path-change]
[--allow-unknown]`:

1. Takes the instance locks and the export lock and holds them to the end
   (T1: the backend or an export is running). The instance locks are
   `.dtvp-instance.lock` in `data/dt_cache` and in every other directory
   holding a record database, the proposals file or a cache (by default
   `data/`), the same files a running backend holds. A backend of another
   `DTVP_DT_CACHE_PATH` whose results or proposals resolve to the same
   directory therefore blocks the restore too. Refuses while a restore
   journal exists (T2). Checks that the backend recorded the same paths
   (T6, `--accept-path-change`) and that a backend has run here at all (T7,
   `--new-instance` for a fresh host), and that there is room for the staged
   copies (T8).
   Refuses when a file this run would move an original to exists already
   (T9).
2. Reads the whole dump once and checks every rule (C, F, S, R, W); then
   refuses a target that already holds records (T3, `--replace`), a
   different Dependency-Track (T4, `--accept-dt-url-change`) and restored
   code-analysis results that this instance's
   `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` or `RETENTION_DAYS` would delete
   (T5, `--accept-pruning`). Settings files on the target do not count as
   records (the image ships `data/rescore_rules.json`); they are moved aside
   and reported. Nothing is written before this point.
3. Stages new files beside their targets (`<file>.restore-<dump id>`):
   fresh databases built with this version's migrations, the records
   inserted with their ids, revisions and full texts, the storage of
   migration 0007 applied again, the derived fields rebuilt and the legacy
   imports marked as done. It checks the databases (P1), reads them back as
   an export would and compares every record, setting and sequence with the
   dump (P2), and makes sure no side file is left (P3). A failure here
   removes the staged files and leaves the instance untouched.
4. Writes the journal `data/dt_cache/.dtvp-restore-<dump id>.json` and moves
   each file into place: the original goes to
   `<file>.pre-restore-<dump id>-<UTC yyyymmddTHHMMSSZ of this restore>`,
   the staged file takes its name. Restoring the same dump again therefore
   keeps the data replaced by that run under a new name. A database's
   `-wal`, `-shm` and `-journal` files go to the database's new name plus
   their suffix (`dtvp.sqlite3.pre-restore-<run>-wal`), so SQLite opens the
   moved-aside database with its last committed transactions and rolls back
   an unfinished one. Caches (the grouped summary index,
   the SSVC cache, the code-analysis diagnostics) are moved aside and rebuilt
   by the backend. Then the registry is written and the journal deleted.

`--dry-run` takes no lock and changes nothing: it reports every rule, the
planned moves with absolute paths, and whether the instance lock is held.

After a restore:

- Assessments, their history and revision numbers, sync state, base and
  remote values, rejected exports and the export queue are as they were, so
  exports continue; a client saving against an older revision is refused
  cleanly.
- Access tokens exist only if the dump included them. With `--replace`, the
  target's own tokens are in the moved-aside database.
- Browser sessions stay valid only if `DTVP_SESSION_SECRET_KEY` is the same
  as on the source.
- The first background sync reloads the project list from
  Dependency-Track.
- DTVP never deletes `*.pre-restore-*` files. Remove them once the
  restored instance has been checked. To open a moved-aside database, keep
  its `-wal` and `-journal` files beside it under their names.

`python -m dtvp.backup verify FILE --deep` stages a dump in a temporary
directory, without a target or a lock, and proves the round trip (P1-P3).

## How To Recover An Interrupted Restore

If a restore stops during the swap (a crash, a full disk, a killed
process), the journal stays and the backend refuses to start. Run, with
the backend stopped:

```bash
docker compose run --rm dtvp python -m dtvp.backup recover --resume   # finish the restore
docker compose run --rm dtvp python -m dtvp.backup recover --abort    # put the original back
```

Both repeat safely. `--abort` returns every file to its original state;
staged files remain and are removed by the next restore. If a file was
changed by something other than DTVP in between, recovery stops and prints
the action to fix by hand.

## Reference: Format `dtvp.dump/1`

### File And Container

A dump is a ZIP file named
`<label>-<UTC yyyymmddTHHMMSSZ>[-with-credentials].dtvp-dump.zip`, with mode
0600, and a sidecar `<file>.sha256` in `sha256sum` format. The label
defaults to `dtvp`; a taken or reserved name gets a `-N` suffix. Written to standard
output, there is no sidecar.

Members:

```text
records/<entity>/<entity>-NNNN.jsonl   one record per line; NNNN has at least 4 digits, from 0001
config/<name>.json                      a settings file, byte for byte
manifest.json                           written last
```

- A record line is the record as compact JSON with sorted keys and UTF-8
  kept as is, followed by `\n` (`bundle_io.jsonl_line`). An entity without
  records has no file.
- A record file is cut after 100,000 records or 64 MiB, whichever comes
  first. A single record may be at most 256 MiB; export fails above that,
  so it never writes a dump that cannot be read.
- `manifest.json` is indented JSON with sorted keys and a trailing newline.
  Readers process entities in the fixed order below, not in key order.
- Every member has the date 1980-01-01 and mode 0600, so the same records
  give the same member bytes.
- Integrity: the ZIP CRC-32 of every member, the SHA-256, size and record
  count of every part in the manifest, and the sidecar for the whole file.
  There is no signature and no encryption; encrypt the file at rest.

Reader limits: at most 10,000 members; at most
`DTVP_DUMP_MAX_UNCOMPRESSED_BYTES` (default 16 GiB) declared uncompressed in
total; at most 256 MiB per line. Every member must be listed in the manifest
and every listed member must exist. A member that produces more bytes than it
declares is refused.

### Manifest

Schema: `dtvp/resources/dump-schemas/1/manifest.schema.json`
(`dtvp.dump.manifest/1`). Unknown fields are refused.

| Field | Content |
| :--- | :--- |
| `format` | `"dtvp.dump"` |
| `format_version` | `1`; a reader accepts only its major version |
| `format_minor` | `0` |
| `required_features` | Features a reader must know. Known: `"credentials"` (the dump holds access-token digests) |
| `dump_id` | A UUIDv4 |
| `created_at` | RFC 3339, UTC |
| `created_by` | The operating-system user, or `"scheduler"` |
| `reason` | `manual` or `scheduled` |
| `scope` | `{kind}`; only `"instance"` in version 1. `"projects"` is reserved for the project archive |
| `dtvp` | `{version, build_commit}` of the writer; provenance only |
| `source` | `{dependency_track_url}`: scheme, host, port and path of the Dependency-Track URL, without user information, query or fragment. The API key is never written |
| `stores[]` | Per SQLite file: `{name, namespaces[], migrations[{namespace, version, name, checksum}], snapshot_at, snapshot_method}`; the method is `vacuum-into`, `backup-api` or `absent` |
| `entities{}` | Per entity: `{schema: "dtvp.dump.<entity>/<n>", records, parts[{path, sha256, bytes, records}]}`; every entity is listed |
| `config{}` | Per settings file: `{absent: true}` or `{absent: false, path, sha256, bytes}` |
| `excluded[]` | `"source"` (written with `--without-source`) and `"access_tokens"` (the default) |
| `contains_credentials` | True exactly when `required_features` holds `"credentials"` |
| `cut_point` | `{sequences: {assessment_revisions, access_token_audit}, event_log_high_water_mark: null}`: the `sqlite_sequence` values, or the largest id when there is none. The high-water mark is reserved for ADR 0004 (background sync) |
| `warnings[]` | Export warnings, for example how many records keep a text that is not JSON |

### Value Conventions

- `key` is `{project_uuid, component_uuid, vulnerability_uuid}`, each a
  non-empty string exactly as stored.
- Booleans are JSON booleans and integers are integers; SQLite's integer
  booleans do not appear.
- Timestamps are the stored strings, unchanged (an empty string stays empty).
- An assessment `value` is `{state, details, suppressed}`. `state` is one of
  `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `FALSE_POSITIVE`, `NOT_AFFECTED`,
  `RESOLVED`; `details` is always the full text.
- A stored JSON document becomes `payload` (any JSON value; an object for
  code analysis). A stored text that is not JSON is kept verbatim as
  `payload_raw` instead, restored as it was and counted in the manifest
  warnings. Exactly one of the two is present. The token audit uses
  `target` and `target_raw` the same way.
- Lookup columns derived from a payload are not in the dump; a restore
  computes them with the same functions the application uses.

### Entities

One JSON Schema (Draft 2020-12) per entity in
`dtvp/resources/dump-schemas/1/<entity>.schema.json`, with `$id`
`urn:dtvp:dump:1:<entity>`; shared definitions are in
`common.schema.json`. Unknown fields are refused, also in nested objects.
Entities are written in this order, each sorted as listed:

| Entity | Source | Sorted by | Fields |
| :--- | :--- | :--- | :--- |
| `assessment` | `assessment_state`, every row including inactive and cancelled | key | `key, revision, value, updated_at, sync{status, update_id, last_error, export_rejections, base, remote}`. `status` is `synced`, `pending`, `error`, `cancelled` or `inactive`. `base` is null without a stored base state; otherwise its text is `base_details`, or the record's own text when `base_details` is null. `base_same` is a storage hint and is not consulted. `revision` is kept exactly: clients use it as their concurrency token |
| `revision` | `assessment_revisions` | `revision_id` | `revision_id, key, revision, value, origin, author, created_at`. The text of an entry stored as `text_in_record` is the record's text. `origin` is an open string (workflow ids are origins) |
| `outbox_entry` | `assessment_outbox` | key | `key, revision, update_id, payload or payload_raw, attempts, next_attempt_at, last_error, created_at, updated_at` |
| `known_project` | `known_projects` | `project_uuid` | `project_uuid, name, version, first_seen_at, last_seen_at` |
| `source_snapshot` | `source_snapshots` | kind, project | `kind` (`projects`, `findings`, `project_vulnerabilities`), `project_uuid` (empty for projects), `item_count`, `updated_at`, `form` (`list`, or `raw` for a stored document that is not a list) and `raw` for the raw form |
| `source_project` | `source_projects` | `position` | `position, payload or payload_raw` |
| `source_finding` | `source_findings` | project, position | `project_uuid, position, payload or payload_raw` |
| `source_project_vulnerability` | `source_project_vulnerabilities` | project, position | as `source_finding` |
| `source_bom` | `source_boms` | `project_uuid` | `project_uuid, payload or payload_raw, updated_at` |
| `source_analysis` | `source_analyses` | key | `key, payload or payload_raw, updated_at` |
| `token_audit` | `access_token_audit` | `audit_id` | `audit_id, occurred_at, username, token_id, agent, action, outcome, target or target_raw, detail` |
| `access_token` | `access_tokens`; only with the `credentials` feature | `token_id` | `token_id, username, name, token_hash, scopes[]` (`read`, `write`), `created_at, expires_at, last_used_at, revoked_at` |
| `code_analysis_result` | `code_analysis_results` | `analysis_run_id` | `analysis_run_id, payload (an object) or payload_raw` |
| `code_analysis_application` | `code_analysis_result_applications` | run, finding | `analysis_run_id, finding_uuid, group_id_lower, workflow_id, status` (`applied`, `queued`, `failed`), `applied_by, applied_at, payload_fingerprint` |
| `code_evidence` | `code_evidence` and `code_evidence_vuln_ids` | `evidence_id` | `evidence_id, schema_version, source, project_name, vuln_id, vuln_ids[]` (the lower-case ids and aliases it is found under), `scope` (`vulnerability`, `components`, `findings`), `targets, title, body_markdown, references, suggested_state, suggested_justification, confidence` (`low`, `medium`, `high` or null), `author_username, token_id, agent_label, authority, idempotency_key, created_at, withdrawn_at, withdrawn_by, withdrawn_reason`. Agent code evidence is record data: withdrawn entries are kept, and analyzer retention never prunes it |
| `code_evidence_application` | `code_evidence_applications` | evidence, finding | `evidence_id, finding_uuid, workflow_id, status` (`applied`, `queued`, `failed`), `applied_by, applied_at` |
| `finding_presence` | `finding_presence` (namespace `finding_lifecycle`, in the assessment records' file) | finding key | `key, vuln_id, component_name, component_version, component_purl, component_identity, first_seen_at, status` (`reported`, `gone`), `gone_at, last_seen_at, gone_reason` (`replaced`, `component_removed`, `no_longer_matched`, `undetermined`, `missing_at_export` or null), `successor_component_uuid, carry_over` (`carried`, `conflict`, `own_assessment`, `undetermined` or null), `returned_at`. DTVP's record of findings the source stopped reporting; it cannot be read from the source again |
| `finding_read` | `finding_reads` | `project_uuid` | `project_uuid, read_at, went` (counts by reason; `went_raw` when not a JSON object), `returned, carried_over, not_carried` |
| `session_version` | `session_versions` (in the access-token file) | `username` | `username, version, revoked_at`. Not a credential, so it is in every dump; it keeps logouts and revocations effective after a restore. A restore writes each version one higher: every restored user signs in again, and no session revoked before or after the dump comes back. Users without a version keep any session signed with the same key; to end every session after a restore, rotate `DTVP_SESSION_SECRET_KEY` |
| `tmrescore_proposal` | `tmrescore_proposals.json` | `project_name` | `project_name, snapshot` (an object), as stored |
| `instance_metadata` | `store_metadata` key `active_projects` | key | `key, value`; zero or one record |

### Settings Files

`config/` holds the five settings files of `dtvp/settings_files.py` byte for
byte: `team_mapping`, `team_groups`, `user_roles`, `rescore_rules`,
`auto_analysis_guidance`. A file that does not exist is recorded as absent,
and a restore leaves it absent: without `user_roles.json` every user is a
reviewer. Export refuses a file that is not JSON; the semantic rules of each
file only produce warnings on restore, because the source instance ran with
these files.

### What Is Not In A Dump

| Kind | What | Why |
| :--- | :--- | :--- |
| Derived | `assessment_fields`, `assessment_team_fields`, `code_analysis_assessment_metadata` | Rebuilt from the records during a restore |
| Storage columns | `assessment_state.base_same`, `base_details` (resolved into `sync.base`), `assessment_revisions.text_in_record` | Resolved on export |
| Lookup columns | `source_projects.{project_uuid, name, version}`, `source_findings.{component_uuid, vulnerability_uuid, vuln_id, severity, component_name, component_version}`, `source_project_vulnerabilities.{vulnerability_uuid, vuln_id}`, `source_analyses.{analysis_state, analysis_details, suppressed}`, `code_analysis_results.{project_name_lower, vuln_id_lower, component_name_lower, source_lower, context_fingerprint, finished_at, submitted_at, recorded_at, record_timestamp}`, `code_evidence.project_name_lower` | Rebuilt from the payload |
| Re-read source data | `source_vulnerability_ranges` (the version ranges for the VDR recommendation, ADR 0007); `sync_versions` (the per-version sync state, ADR 0004) | Read from Dependency-Track again in the background after a restore; the next reads rebuild the sync state |
| Caches | `store_metadata.projects_meta`, the grouped summary index, the SSVC enrichment cache, the code-analysis diagnostics | Rebuilt by the backend; a restore moves the files aside |
| Migration bookkeeping | `schema_migrations` (listed in the manifest), `store_metadata.legacy_json_import`, `assessment_outbox_metadata`, `finding_lifecycle_metadata` (the one-time presence backfill), `code_analysis_result_meta`, `sqlite_sequence` (in `cut_point`) | A restore builds the schema with the target's own migrations and writes "done" markers |
| Files | Project archives and uploads, the expanded archive tree, the legacy JSON and SQLite inputs, the backup directory | Not records of this instance |
| Process state | In-memory task registries; the live-update event stream of ADR 0004 (its events live only in memory) | Clients resynchronise after a restart; only the reserved high-water mark is kept |
| Secrets | The Dependency-Track API key, `DTVP_SESSION_SECRET_KEY`, the OIDC client secret, SSH keys | They belong to the deployment definition |

`tests/test_backup_coverage.py` fails when a table or column is neither in
the dump nor listed here.

### Versioning

Three axes are versioned separately.

1. **Format** (`format_version`, `format_minor`, `required_features`). A
   reader accepts only major version 1 and refuses a required feature it
   does not know. A dump of the reader's minor version or older is validated
   strictly. A dump of a newer minor version may carry entities and fields
   the reader does not know: `verify` reports them as warnings; `restore`
   refuses them unless `--allow-unknown` is given, which drops them with a
   warning. A future major version ships a pure upcaster from version 1 and
   keeps the version 1 reader for at least one release line.
2. **Entity schema** (`dtvp.dump.<entity>/<n>`). An added optional field
   changes nothing. A rename, a change of meaning (including the markup of
   `details`) and a new value in a closed enum raise `n` and need an
   upcaster (`dtvp/backup/upcasters.py`) with frozen fixtures. The reader
   upcasts first and validates after; it refuses a newer `n` or a gap in
   the chain.
3. **Database schema and application version** are provenance only. A
   restore builds the target's schema with the target's migrations and
   writes the records through the current code. Every migration that
   changes rows (`INSERT`, `UPDATE`, `DELETE`) needs an entry in
   `dtvp/backup/migration_effects.py`: applied before dump/1 (`Baseline`),
   no effect on dumped records, or an upcaster. A test enforces it. Raw
   database copies across versions are unsafe because the migration runner
   does not refuse a database newer than the code.

### Validation Rules

Each rule has a negative test. Refusals stop the command; warnings are
reported.

| Rule | Check | Outcome |
| :--- | :--- | :--- |
| C1 | Unsafe member name | Refused |
| C2 | A member not listed in the manifest | Refused |
| C3 | A listed member is missing | Refused |
| C4 | More members than allowed | Refused |
| C5 | Declared uncompressed total over the limit | Refused |
| C6 | Part SHA-256 differs | Refused |
| C7 | Part size differs | Refused |
| C8 | Part record count differs | Refused |
| C9 | A line over the maximum | Refused |
| C10 | Damaged ZIP, bad CRC or a member larger than declared | Refused |
| C11 | A line that is not a JSON object | Refused |
| F1 | `format` is not `dtvp.dump` | Refused |
| F2 | Unknown major version | Refused |
| F3 | Unknown required feature | Refused |
| F4 | `scope.kind` is not `instance` | Refused |
| F5 | The manifest fails its schema | Refused |
| F6 | Unknown entity or field under a newer minor version | Warning in `verify`; refused by `restore` without `--allow-unknown` |
| F7 | An entity schema newer than the reader | Refused |
| F8 | An older entity schema without an upcaster chain | Refused |
| F9 | `contains_credentials` disagrees with `required_features` | Refused |
| S1 | A record fails its entity schema | Refused |
| R1 | A duplicate natural key | Refused |
| R2 | A duplicate outbox `update_id` or token digest | Refused |
| R3 | A history entry without an assessment | Refused |
| R4 | An application without its code-analysis result | Refused |
| R5 | A list snapshot whose items do not number `item_count`, or items of a raw or missing snapshot | Refused |
| R6 | A `cut_point` sequence below the largest id | Refused |
| W1 | Outbox `update_id` differs from the assessment's `sync.update_id` | Warning |
| W2 | A `pending` or `error` assessment without an outbox entry | Warning |
| W3 | An outbox entry for an assessment that is not `pending` or `error` | Warning |
| W4 | `assessment.revision` below the largest revision in its history | Warning |
| W5 | An outbox entry without an assessment | Warning |
| W6 | An assessment without history | Warning |
| W7 | A settings file fails its semantic rules | Warning |
| W8 | `payload_raw` or `target_raw` present | Warning |
| E1 | Export: a snapshot's migrations differ from the code's | Refused |
| E2 | Export: a settings or proposals file changed between two reads | Refused |
| E3 | Export: a settings or proposals file is not JSON | Refused |
| E4 | Export: a record over the maximum size | Refused |
| E5 | Export: the export lock is held | Refused |
| E6 | Export: a restore journal exists | Refused |
| E7 | Export: not enough free space | Refused |
| E8 | Export: a database kept changing and its copy did not finish within 300 s | Refused |
| T1 | Restore: an instance lock (`data/dt_cache` or a record or cache directory) or the export lock is held (backend or export running) | Refused |
| T2 | Restore: a restore journal exists; use `recover` | Refused |
| T3 | Restore: the target holds records (any row in a dumped table, or a proposals file) | Refused without `--replace` |
| T4 | Restore: the Dependency-Track URL differs from the dump's | Refused without `--accept-dt-url-change` |
| T5 | Restore: this instance's code-analysis retention would delete restored results | Refused without `--accept-pruning` |
| T6 | Restore: the backend recorded other paths than the command resolves | Refused without `--accept-path-change` |
| T7 | Restore: no backend has run here (no `.dtvp-instance.json`) | Refused without `--new-instance` |
| T8 | Restore: not enough free space beside the targets | Refused |
| T9 | Restore: a file this run would move an original to exists already | Refused |
| P1 | Staging: `integrity_check` or `foreign_key_check` fails | Refused; target untouched |
| P2 | Staging: the staged files read back differ from the dump | Refused; target untouched |
| P3 | Staging: a `-wal`, `-shm` or `-journal` file is left beside a staged database | Refused; target untouched |

The W rules are kept by the current code but legacy and imported data may
break them; a restore reproduces the source as it was.
