# Deployment and recovery

Start with [README](../README.md). The production runtime has PostgreSQL 18,
the API/UI and one durable worker. No external source is mandatory. Artifacts
are stored locally. Knowledge lives in the immutable local journal; SQL holds rebuildable
projections. Accounts, permissions, connectors and operational jobs remain SQL-owned.

## Configuration

`DTVP_DATABASE_URL` is the application database. `DTVP_MIGRATION_DATABASE_URL`
optionally supplies separate migration privileges. Set `DTVP_SESSION_SECRET`
to at least 32 random characters and `DTVP_PUBLIC_URL` to the exact browser
origin. Configure `DTVP_OIDC_ISSUER`, `DTVP_OIDC_CLIENT_ID` and
`DTVP_OIDC_CLIENT_SECRET`. Issuer/subject memberships are explicit, with no
default reviewer grant.

`DTVP_PROVIDERS_ENABLED=["osv","nvd","circl"]` enables optional outbound reads.
`DTVP_DT_URL` is the DT server origin without `/api/v1`; `DTVP_DT_API_KEY` is its
read credential. `DTVP_VSCORER_URL` adds a contextual UI link. Keep
`DTVP_PLAYGROUND=false` in production. `DTVP_ARTIFACT_DIR` defaults to
`/data/artifacts` in the image; mount persistent storage there.

Managed PostgreSQL works through the same URL. Multiple application/worker
instances need the same artifact filesystem. The supplied Compose installation
uses one worker and database-backed leases; it does not require a broker.

## Automatic schema updates

API and worker startup run Alembic to `head`. PostgreSQL's migration advisory
lock serializes concurrent starts. `/readyz` requires the current schema and a
native projection checkpoint matching the journal publication hash and sequence.
Lag, missing checkpoints and unreadable current publications return 503. The
probe reads under the journal lock but does not repair or publish anything;
`/healthz` remains a separate process-liveness check. Checkpoint alignment does
not replace full offline journal verification or validate evidence claims.
Upgrading an existing schema first writes a checksummed, owner-readable JSONL
logical data backup under `/data/migration-backups`; failure aborts startup.
Migration revisions are frozen, transactional schema changes. Never edit an
already deployed revision to change its meaning.

The backup is recovery data, not a replacement for PostgreSQL operational backups.
Take a consistent database backup and the full artifact volume before deployment.
Keep source observations and older snapshots; local files are immutable and
not garbage-collected automatically. The backup includes credential hashes and
all teams' private data; protect its directory like the database.

## PostgreSQL engine upgrades

Engine major upgrades are separate from schema updates. Stop API/worker writes
and use the helper to restore into a new PostgreSQL 18 volume:

```bash
docker compose stop api worker
export DTVP_UPGRADE_TARGET_PASSWORD='your-new-strong-password'
uv run python scripts/database_upgrade.py \
  --source-container dtvp-db-1 --target-name dtvp-pg18-candidate \
  --database dtvp --user dtvp --port 55433 --writers-stopped
```

The helper uses the source cluster's `pg_dump`, an atomic target restore and a
SHA-256 manifest. It retains the source container/volume and refuses to overwrite
an existing backup. It supports the standard application-owned database; custom
roles, extensions and server configuration must be transferred separately.
PostgreSQL 18 mounts the parent `/var/lib/postgresql` volume.

The target image must already exist locally; the helper pins its image ID and
never pulls it. It rejects an existing target container, target-named volume, dump
or manifest and uses a fresh ownership-labelled candidate volume. Only source
majors 10–17 and target 18 are admitted; that is an input bound, not qualification
of all source versions or extensions. The candidate major and dump checksum are
checked again before restore. Backups/manifests are exclusive, owner-readable files.

`DTVP_UPGRADE_REHEARSAL=1 uv run pytest -q tests/test_database_upgrade_rehearsal.py`
exercises actual local-image PostgreSQL 17→18 conversion with synthetic operational
rows, journal/projection recovery, frozen exports and permission checks. The test
cleans only its uniquely named, ownership-labelled resources. It does not establish
production identity, extension/custom-role or concurrent-write recovery acceptance.

Before reopening writes, verify the candidate's schema, counts, artifact hashes,
consumer snapshots, credentials and denied cross-team access with DTVP. Change
the database URL only after validation. Until new writes start, reverting to the
old URL restores the old cluster. After new writes, rollback requires reconciling
those changes; never assume switching URLs preserves them.

## Native journal recovery

Back up the complete artifact volume together with a consistent operational SQL
backup. Stop API/worker writers or use a consistent filesystem snapshot; copying a
live directory piecemeal is not a qualified backup. Preserve `knowledge/FORMAT`,
`HEAD`, all objects and file permissions. An older journal backup paired with newer
SQL projections must be explicitly rebuilt before serving. Journal recovery alone
does not reconstruct accounts, permissions, connector credentials or jobs.

Verify a restored candidate before pointing an application at it:

```bash
uv run dtvp verify-knowledge --directory /restore/artifacts/knowledge
```

This requires an existing journal, opens no SQL connection and initializes no
missing directory. It pins HEAD, checks the full publication/reference chain and
every committed state, parent, section, record and retained artifact. Uncommitted
orphan files are excluded. Output reports the verified head, publication/state
counts and unique referenced object bytes; these are integrity diagnostics, not
publisher authenticity, complete filesystem size or validation of evidence claims.
A corrupt/missing committed object fails the command; no repair or deletion occurs.

After restoring SQL and configuring the candidate artifact path, run `uv run dtvp
rebuild-knowledge` to replace only native projections. Check project permissions,
consumer hashes, tags and active branch coverage before reopening writes. Keep the
original backup unchanged. Cross-version serializer compatibility and operational
restore qualification remain release acceptance work.

The repeatable local rehearsal is `uv run pytest -q tests/test_installation_recovery.py`.
It stops writers, backs up the SQLite playground database and copies the full
artifact directory into a separate candidate. It verifies the complete journal,
rebuilds only native projections and checks preserved credentials, memberships,
uncertain remote-job outcomes, tags, exact reviews and issued artifact bytes,
including denied cross-team reads. The source artifact copy remains unchanged.
SQLite runs by default. To exercise actual PostgreSQL custom-format dump and
single-transaction restore, explicitly provide two existing disposable databases
on the same server and its Docker container:

```bash
DTVP_RECOVERY_SOURCE_URL='postgresql+psycopg://USER:PASSWORD@127.0.0.1:PORT/source_recovery_test' \
DTVP_RECOVERY_TARGET_URL='postgresql+psycopg://USER:PASSWORD@127.0.0.1:PORT/candidate_recovery_test' \
DTVP_RECOVERY_CONTAINER='disposable-postgres-container' \
uv run pytest -q tests/test_installation_recovery.py
```

Both names must end in `_recovery_test` and differ. The test resets the source
schema and replaces the candidate database contents. The container must allow
its application user to run local socket `pg_dump`/`pg_restore`; credentials never
enter command arguments. The container's databases must correspond to the URLs.
This path has passed on disposable PostgreSQL 18 alongside SQLite. It exercises
application-owned data, not custom roles/extensions, major-version conversion,
production identity-provider access or remote service reconciliation. Those remain
deployment-specific qualification gates.

## Legacy migration

Retained local data and historical Git revisions remain intact. Original SBOMs
and DT findings enter through native imports. Historical DTVP-tagged and metadata-free DT analysis is decoded into owned
source records, including plain rationale, applicability, team blocks, dates,
assignments, claimed reviewers, historical/copied teams, suppression and SSVC.
Legacy rescoring remains separate from Base severity. Missing metadata stays
unknown; no imported author name grants membership or creates a new approval. Explicitly remap issuer/subject identities and review legacy decisions.
Automated full archive/assessment migration and production cutover reconciliation
remain separate work; no production data was migrated by this branch.
