# Deployment and recovery

Start with [README](../README.md). The production runtime has PostgreSQL 18,
the API/UI and one durable worker. No external source is mandatory. Artifacts
are stored locally; database rows own inventory, metadata and decisions.

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
lock serializes concurrent starts. `/readyz` opens only when the schema matches.
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

Before reopening writes, verify the candidate's schema, counts, artifact hashes,
consumer snapshots, credentials and denied cross-team access with DTVP. Change
the database URL only after validation. Until new writes start, reverting to the
old URL restores the old cluster. After new writes, rollback requires reconciling
those changes; never assume switching URLs preserves them.

## Legacy migration

Legacy local data and the old Git revision remain intact. Import original SBOMs
and DT finding data through the new ingestion endpoints. Historical DTVP-tagged and metadata-free DT analysis is decoded into owned
source records, including plain rationale, applicability, team blocks, dates,
assignments, claimed reviewers, historical/copied teams, suppression and SSVC.
Legacy rescoring remains separate from Base severity. Missing metadata stays
unknown; no imported author name grants membership or creates a new approval. Explicitly remap issuer/subject identities and review legacy decisions.
Automated full archive/assessment migration and production cutover reconciliation
remain separate work; no production data was migrated by this branch.
