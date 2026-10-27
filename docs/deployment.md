# Deployment

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Compose](#compose)
- [Python Runtime Images](#python-runtime-images)

## Compose

```bash
cp .env.dist .env
docker compose up -d
```

Set the public URL, a strong `DTVP_DB_PASSWORD`, and a strong session secret.
Configure the Dependency-Track URL/key for source imports, refresh, or optional
decision publication. DTVP starts without Dependency-Track and serves already
imported inventory and local decisions from its own store. Its PostgreSQL
service and volume are separate from Dependency-Track's database. For a
non-default gateway:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=http://host.example:8083/dtvp
```

Deployment rules:

- DTVP schema migrations run automatically at startup before the application
  serves traffic. Startup output reports the migration check, applied revision,
  and current schema revision; `/api/startup` exposes the current revision after
  the migration check. A failed upgrade leaves DTVP unavailable with a
  startup error instead of serving against an unknown schema. `uv run
  dtvp-db-upgrade` runs the same migration path explicitly for staged upgrades.
- PostgreSQL migration execution uses a database advisory lock so simultaneous
  app starts cannot apply DDL concurrently. Local SQLite development uses a
  file lock. Large data backfills should use resumable, bounded migrations;
  routine schema changes need no manual SQL.
- DTVP uses its own `dtvp-postgres-data` volume. Back up this database together
  with `DTVP_ARTIFACT_STORE_PATH` (`data/dtvp_artifacts` by default) before
  releases that change persisted data. The existing Dependency-Track PostgreSQL
  volume remains independent.
- `docker compose exec -T dtvp uv run python scripts/dtvp_storage.py backup
  --output-dir /app/data/backups` creates a permission-restricted archive with a
  consistent SQLite copy or PostgreSQL custom dump plus SHA-256-verified DTVP
  artifacts. Compose includes PostgreSQL 18 client utilities for its PostgreSQL
  18 service and compiles Psycopg's C adapter into the Python 3.15 image.
  `pg_dump` must be at least as new as the server major version;
  PostgreSQL refuses a dump when the client major version is older than the
  server. [PostgreSQL pg_dump compatibility](https://www.postgresql.org/docs/18/app-pgdump.html)
- Restore with DTVP stopped while leaving the database service running:

  ```bash
  docker compose stop dtvp
  BACKUP=/app/data/backups/dtvp-backup-20261027T120000Z.tar.gz
  docker compose run --rm --no-deps dtvp uv run python scripts/dtvp_storage.py restore "$BACKUP" --replace
  docker compose start dtvp
  ```

  Restore verifies the database checksum and every artifact hash, adds artifacts
  first, then replaces the DTVP objects in the configured database. The
  PostgreSQL restore runs in a single transaction. `--replace` is required
  because the operation replaces DTVP database state. After restoring, DTVP's normal
  startup migration check upgrades the restored schema if needed. Keep the
  backup outside the artifact directory and protect it as sensitive project
  data. This archive covers the DTVP database and artifact store; preserve other
  `./data` configuration and archive directories separately.
- `./data` mounts at `/app/data`; mappings, roles, rules, caches, proposals, and
  archives survive container restarts.
- Code analysis is an optional external service. Deploy Agentyzer separately,
  configure its repository mappings there, and set `DTVP_CODE_ANALYSIS_URL` to
  an endpoint reachable from the DTVP container. An empty URL disables the
  integration. DTVP's Compose stack does not build or start the analyzer.
- Internal services use Compose names and container ports. DTVP reaches
  Dependency-Track at `http://dtrack-apiserver:8080` unless overridden.
- If proxies are configured, list exact internal hostnames/IPs in `NO_PROXY`;
  do not rely only on CIDR entries.
- DTVP delegates OIDC discovery, state and nonce handling, the authorization-
  code flow with S256 PKCE, token exchange, and JWKS-backed ID-token validation
  to Authlib. Its transient login state lives in a signed, HttpOnly cookie that
  expires after ten minutes. Set a strong `DTVP_SESSION_SECRET_KEY` in every
  deployment. This login is independent of Dependency-Track browser sessions:
  backend calls use `DTVP_DT_API_KEY` and never forward browser credentials.
- API `401` responses move the SPA to sign-in and preserve the current route for
  the OIDC return. Reviewer authorization failures remain `403` errors and do
  not incorrectly log the user out.
- Completed grouped-vulnerability tasks are retained by idle time. Visible
  project tabs renew their lightweight task lease and rebuild an expired task
  automatically after a suspended browser resumes, so details and bulk actions
  do not require a full-page reload.
- Background Dependency-Track refresh tracks a timestamped, bounded set of
  recently viewed projects. Older projects remain on disk and load on demand;
  they no longer receive three upstream refresh calls every minute forever.
- Process-local cache objects and named project searches use LRU limits, and
  completed grouped tasks have a separate retained-count cap. These bounds keep
  long-running and multi-user instances from growing without limit.
- nginx proxies `DTVP_CONTEXT_PATH` to DTVP and defaults it to `/dtvp`.
  `DTVP_HTTP_PORT` changes the host gateway port. Direct-container deployments
  must publish port `8000` and include the context path in the URL.
- The Compose nginx gateway keeps upstream HTTP/1.1 connections open,
  compresses JSON/static text responses, and disables buffering for grouped
  task event streams. Uvicorn keeps those upstream connections for 30 seconds
  and uses a 2048-connection accept backlog.
- `dtvp.boot:app` serves startup status while the real app initializes. Startup
  logs time cache and integration initialization, as well as database migration
  status.
- The DTVP container startup script prints its packaged project version and
  image build number before importing the application, so deployment identity
  remains visible in Docker logs even if initialization fails.
- `/api/performance-status` reports grouped-query/build/post-processing
  saturation, retained task counts, process-local cache pressure, and the
  active Python/GIL state.
  API responses include a `Server-Timing: app;dur=...` header for browser and
  proxy latency analysis.
- Reviewers see the Python/GIL state in the application footer and can inspect
  live worker capacity, retained grouped tasks, and cache pressure on the
  Settings **Runtime** tab.
- The frontend image renders `index.html` from its immutable template on every
  start, so frontend URL and context-path changes are restart-safe.

## Python Runtime Images

The default Compose and published DTVP image use the Python 3.15 free-threaded
build. Start it normally:

```bash
docker compose up -d --build
```

`Dockerfile.free-threaded` asks `uv` for the explicit `3.15t` interpreter. It
loads DTVP's native dependencies and verifies the runtime during the image
build. Compose also sets `DTVP_REQUIRE_FREE_THREADED=true`, so the
application refuses to start if it receives a normal interpreter or a native
extension re-enables the GIL. Confirm the live state under `python` in
`/api/performance-status`; `free_threading_active` must be `true` and
`gil_enabled` must be `false`.

See the official [CPython free-threading
guide](https://docs.python.org/3/howto/free-threading-python.html) and [`uv`
Python variant documentation](https://docs.astral.sh/uv/concepts/python-versions/)
for the interpreter guarantees and `3.15t` selector.

Free threading lets DTVP's dedicated CPU worker pools execute Python code on
multiple cores. It does not make Dependency-Track/network I/O faster, and the
free-threaded interpreter has some single-thread overhead. The pipeline builds
and publishes only this validated free-threaded DTVP image. Its canonical tags
are `latest`, release versions, `dev`, and PR tags; no GIL-enabled or duplicate
variant tags are published.

DTVP's root `pyproject.toml` is its release-version source. Regenerate the root
lockfile after changing that version. A manually pushed `v*` tag must match
DTVP's packaged version before the container is published. The workflow
publishes version tags and `latest` for the `dtvp` container package only.
External code-analysis services have their own releases and dependency state.

Archive imports write into DTVP and do not require Dependency-Track write
permissions. Export and scheduled snapshots use the DTVP catalog and its
configured source connector. These behaviors and expanded Git trees are
controlled by the [archive variables](configuration.md#project-archives). The optional
`dtvp-archive-git-push` Compose job pushes an expanded tree; schedule it with
cron, systemd, or CI when required.
