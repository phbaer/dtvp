---
type: Workflow
title: Existing Instance Upgrade Guide
description: Security and architecture change summary plus a backup, configuration, state, verification, and rollback procedure for existing DTVP instances.
tags:
  - upgrade
  - migration
  - deployment
  - security
source_paths:
  - .env.dist
  - compose.yml
  - compose.secrets.yml
  - compose.session-key-rotation.yml
  - compose.agentyzer-token-rotation.yml
  - compose.archive-import-secret.yml
  - demo/dependency-track/compose.yml
  - deploy/arcane/
  - dtvp/vulnerability_backend.py
  - dtvp/dt_client.py
  - dtvp/dt_cache.py
  - dtvp/sqlite_migration_services.py
  - dtvp/code_analysis_result_services.py
  - dtvp/analysis_queue_state_services.py
  - scripts/backup-compose-state.sh
  - scripts/backup-compose-state-container.sh
review_when:
  - A required variable, compatibility alias, state path, automatic migration, Compose service, credential boundary, backup workflow, or rollback assumption changes.
---

# Existing Instance Upgrade Guide

This workflow upgrades an instance from the older bundled
Dependency-Track/PostgreSQL Compose topology to the current backend-neutral,
hardened deployment. Read the [security model](threat-model.md),
[configuration reference](configuration.md), and the selected deployment guide
before the maintenance window.

## What Changed

| Area | Current behavior | Upgrade impact |
| :--- | :--- | :--- |
| Vulnerability backend | DTVP selects a capability-based adapter with a stable type and instance ID. Dependency-Track is the first adapter; Cybeats remains unavailable until its contract is verified. | Existing Dependency-Track instances must set the new vendor-neutral variables. Use the exact ID `dependency-track` to retain legacy unscoped state paths. |
| Deployment boundary | Root Compose deploys DTVP, nginx, and Agentyzer only. Dependency-Track, PostgreSQL, and their data lifecycle are no longer owned by DTVP; the repository copy is an isolated demo. | Preserve the old PostgreSQL volume and migrate or continue operating Dependency-Track separately before replacing the stack. Never treat the demo overlay as a production database migration. |
| Authentication and authorization | DTVP uses its own OIDC code flow with PKCE/state/nonce, signed sessions, server-side reviewer/team authorization, fresh-state conflict checks, and structured audit events. | Register an exact DTVP OIDC callback, configure HTTPS, retain or rotate the session key deliberately, review role mappings, and test analyst/reviewer boundaries. |
| Service identity | Backend review, archive import, Agentyzer owner scope, and Agentyzer service-wide scope use separate credentials. Production Compose mounts current secrets as files; rotation overlays temporarily mount previous generations. | Create independent least-privilege credentials. Start with `compose.secrets.yml`; add archive-import or rotation overlays only while their capability is required. |
| HTTP and input boundaries | Host/origin/proxy checks, browser headers, application and nginx quotas, bounded uploads/archive expansion, sanitized rendering, SSRF restrictions, and analyzer request limits fail closed. | Supply exact public host/proxy settings and verify that upstream proxies preserve required upload/streaming behavior without weakening route limits. |
| Local state | Caches, outboxes, analysis queues, summary indexes, analyzer results, archives, proposals, audit events, and health markers are durable and backend-scoped. SQLite schemas use numbered checksum-verified migrations. | Preserve the complete DTVP data directory. Keep legacy paths explicitly on the first upgrade; do not copy selected JSON files into a new empty tree. |
| Runtime coordination | One DTVP process and one Agentyzer process hold exclusive leases for each local state volume. Queues, executors, retention, disk health, and retries are bounded. | Run one worker per volume. Remove old processes before starting the new stack and fix bind-mount ownership for the non-root UID/GID. |
| Agentyzer | Every route requires a scoped token; jobs are durable and bounded; repository credentials are child-only and persisted remotes are scrubbed. Repository reads and public research are constrained. | Generate distinct service/admin tokens. Treat the old repository volume as a disposable source cache and recreate it if it may contain credential-bearing remotes. |
| Containers and networking | Application images are digest-built, non-root by default, read-only in Compose, capability-reduced, PID/log bounded, health-gated, and split across internal and service-specific outbound networks. Agentyzer has no published port by default. | Publish only the gateway. Use the loopback debug overlay temporarily if direct Agentyzer access is needed, and remove it after verification. |
| Recovery and supply chain | Verified manual/scheduled backups, storage readiness, dependency/source/image scans, SBOMs, provenance, and digest signing are part of the release boundary. | Configure encrypted off-host backups and immutable audit export; verify release signatures by digest and test restore rather than relying on readiness alone. |

## Migration Procedure

### 1. Inventory And Back Up

1. Record the running DTVP, Agentyzer, Dependency-Track, and PostgreSQL image
   references; the Compose project name; public URLs; OIDC registration; current
   `.env`; enabled profiles; custom CA; bind mounts; named volumes; and the
   owner UID/GID of `./data`.
2. Schedule downtime and stop all DTVP and Agentyzer writers. Do not run old and
   new application versions against the same state or repository volume.
3. Back up the complete DTVP `./data` tree while stopped. Back up the old
   Dependency-Track PostgreSQL database with its supported database procedure;
   a DTVP project archive is not a database or local-state backup.
4. Verify checksums, restore both backups into an isolated environment, and
   retain the old checkout, Compose inputs, image digests, and secret versions
   until the upgrade is accepted. Do not use `docker compose down -v` during
   this migration.

After the new checkout is in place, future root-Compose backups can use:

```bash
./scripts/backup-compose-state.sh /absolute/encrypted-or-off-host/backup-root
```

The optional scheduled profile holds Docker Engine authority. Enable it only
after accepting that boundary and configuring its backup destination.

### 2. Build The New Configuration

Create a new file from `.env.dist` and copy reviewed values into it; do not
replace the template with the old `.env` wholesale. Root Compose now passes an
explicit allowlist, so an old variable that is absent from `compose.yml` will
not reach a container even when it remains in `.env`.

For an existing Dependency-Track deployment, map variables as follows:

| Previous name | Current name or action |
| :--- | :--- |
| `DTVP_DT_API_URL` | `DTVP_VULNERABILITY_BACKEND_API_URL` |
| `DTVP_DT_API_KEY` | `DTVP_VULNERABILITY_BACKEND_API_KEY`; preferably replace it with a dedicated least-privilege review-team key |
| `DTVP_DT_API_KEY_FILE` | `DTVP_VULNERABILITY_BACKEND_API_KEY_FILE` for non-Compose deployments; production root Compose derives the file mount from the direct `.env` value through `compose.secrets.yml` |
| `DTVP_DT_IMPORT_API_KEY` | `DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY`; use a separate import team/key and enable `compose.archive-import-secret.yml` only when apply is needed |
| `DTVP_DT_IMPORT_API_KEY_FILE` | `DTVP_VULNERABILITY_BACKEND_IMPORT_API_KEY_FILE` for non-Compose deployments |
| `DTVP_DT_CACHE_PATH` | `DTVP_VULNERABILITY_BACKEND_CACHE_PATH`; retain the exact old value, normally `data/dt_cache`, for the first upgrade |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | `DTVP_VULNERABILITY_BACKEND_CACHE_REFRESH_SECONDS` |
| `DTVP_DT_PROJECT_LIST_TTL_SECONDS` | `DTVP_VULNERABILITY_BACKEND_PROJECT_LIST_TTL_SECONDS` |
| `DTVP_AGENYZER_*` | `DTVP_CODE_ANALYSIS_*`; legacy spellings are deprecated and scheduled for removal in DTVP 2.0 |
| Unprefixed Agentyzer `LLM_BACKEND`, `OLLAMA_*`, `OPENWEBUI_*`, `LOG_LEVEL` | Canonical `AGENTYZER_*` names |

Set these non-secret backend identifiers:

```env
DTVP_VULNERABILITY_BACKEND_ID=dependency-track
DTVP_VULNERABILITY_BACKEND_TYPE=dependency-track
DTVP_VULNERABILITY_BACKEND_LABEL=Dependency-Track
DTVP_VULNERABILITY_BACKEND_CACHE_PATH=data/dt_cache
```

`dependency-track` is a deliberate compatibility ID: it keeps cache, queue,
archive, proposal, and analyzer-result locations unscoped. Any other ID uses a
new `backends/<id>` namespace and makes the old state appear absent unless it is
migrated explicitly while DTVP is stopped. Never change an instance ID merely
to rename its display label.

Also configure:

- `DTVP_ENVIRONMENT=production`, an HTTPS `DTVP_FRONTEND_URL`, exact OIDC
  authority/client/callback values, `DTVP_SESSION_COOKIE_SECURE=true`, and exact
  `DTVP_ALLOWED_HOSTS`; set only the immediate proxy ranges in
  `DTVP_TRUSTED_PROXY_CIDRS`;
- the existing session key if preserving current sessions is required and the
  key is random, non-placeholder, and at least 32 characters; otherwise perform
  a deliberate rotation and expect old sessions to end;
- distinct random `AGENTYZER_SERVICE_TOKEN` and `AGENTYZER_ADMIN_TOKEN` values,
  plus an optional OpenWebUI key; do not reuse the backend, session, OIDC, Git,
  or LLM credential;
- existing mapping, role, rescoring, archive, tmrescore, and analyzer paths when
  they were customized; and
- `DTVP_RUNTIME_UID`/`DTVP_RUNTIME_GID` matching the owner of `./data`, or change
  that directory's ownership during downtime before the non-root container
  starts.

The previous root stack's Dependency-Track API, frontend, PostgreSQL, routes,
and `postgres-data` volume are not declared by current root Compose. Keep the
volume, complete the vendor's external deployment/restore, and point DTVP at
that independently operated API before continuing.

### 3. Prepare Secrets And Disposable State

Generate independent current secrets with `openssl rand -hex 32`. The normal
production stack is:

```bash
docker compose -f compose.yml -f compose.secrets.yml config --quiet
docker compose -f compose.yml -f compose.secrets.yml up -d --build
```

The base file retains direct values for local compatibility; it is not the
production secret boundary. `compose.secrets.yml` clears direct credential
entries and mounts files. Use the documented session or Agentyzer rotation
overlays only for a bounded grace period, then clear previous values and
recreate the affected service.

The `agentyzer-repos` volume is explicitly disposable. If the pre-upgrade
service may have persisted authenticated clone URLs or source outside the new
retention policy, remove and recreate only that volume while stopped after
confirming it contains no required data. Do not include it in DTVP backups.

### 4. Allow Automatic State Migration

On first startup DTVP creates or migrates its SQLite stores transactionally and
records the checksum of every numbered migration. A legacy
`pending_updates.json` is imported idempotently into the assessment outbox. A
configured `code_analysis_results.json` is imported once into its sibling
SQLite store. New durable queue, index, audit, lock, and health files are
created in the existing DTVP data tree.

Do not rename, edit, or skip applied SQL migration files. Do not manually move
individual state files between backend namespaces. If startup reports a
namespace marker mismatch, migration checksum mismatch, unsafe file, lock
contention, insufficient free space, or invalid production setting, leave the
service stopped and correct the cause rather than deleting the guardrail.

### 5. Verify Before Reopening Access

Verify all of the following:

1. `docker compose ps` reports healthy DTVP and Agentyzer containers; `/livez`
   and `/readyz` return success through the intended public gateway.
2. Login completes through the registered OIDC callback, cookies are Secure,
   and analyst/reviewer/team restrictions behave as expected.
3. `/api/vulnerability-backend` shows ID `dependency-track`, the intended
   label, and only supported capabilities. Existing projects, cached findings,
   pending assessment overlays, archives, and analyzer history are present.
4. A reviewer can read sanitized code-analysis, storage, quota, and audit
   health. Agentyzer is not publicly exposed, owner scope is isolated, and the
   admin token is required for service-wide scope.
5. A controlled assessment detects stale-state conflicts and synchronizes once;
   archive import remains disabled unless its separate overlay is present.
6. Host/origin checks reject an unexpected Host or cross-origin unsafe request;
   browser security headers and no-store diagnostic responses are present.
7. A fresh verified DTVP backup and a separate vulnerability-backend backup can
   be restored in isolation. Configure alerting only after the baseline is
   known-good.
8. Deployed image digests match the intended release, and cosign verification,
   SBOM/provenance retrieval, and local security scan policy succeed.

### 6. Roll Back Safely

If verification fails, stop the new DTVP and Agentyzer processes completely.
Restore the full pre-upgrade DTVP data snapshot and the matching external
Dependency-Track database snapshot, then start the recorded old images with the
old configuration. Do not point the old application at state after a partial
new-version run and do not run both versions concurrently. Preserve failed new
state and audit logs separately for diagnosis; never “roll back” by deleting a
lock, namespace marker, migration row, or outbox entry.

After acceptance, retire old credentials and grace generations, remove unused
debug/import profiles, securely expire old backups under the retention policy,
and keep the last verified rollback set for the operator-defined recovery
window.
