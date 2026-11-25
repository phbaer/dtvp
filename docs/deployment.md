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

Set at least the Dependency-Track API key and public URL. For a non-default
gateway:

```env
DTVP_HTTP_PORT=8083
DTVP_FRONTEND_URL=http://host.example:8083/dtvp
```

Deployment rules:

- `./data` mounts at `/app/data`; mappings, roles, rules, the local database,
  proposals, and archives survive container restarts. `data/dt_cache` holds
  the database (`dtvp.sqlite3`), which includes local assessments not yet
  exported: back it up, and do not clear it as if it were a cache.
- Back up with the instance dump while the backend runs:
  `docker compose exec dtvp python -m dtvp.backup export` writes a checked
  file to `data/backups` that holds every record and the settings files;
  see [Backup and restore](backup-and-restore.md). Restore it with the
  backend stopped:
  `docker compose run --rm dtvp python -m dtvp.backup restore <file>`.
  A cold copy of the whole `./data` directory taken while the backend was
  stopped remains a fallback, into the same River version only.
- Practise the restore once a quarter: copy a recent dump to a scratch
  host or directory, run `python -m dtvp.backup verify --deep <file>`, then
  restore it into a scratch instance (`restore <file> --new-instance`), start
  a backend on it and check a few projects, their history and the export
  queue. Record the date and the duration. Run the scratch instance in its
  own working directory, or set every path to scratch values:
  `DTVP_DT_CACHE_PATH`, `DTVP_CODE_ANALYSIS_RESULTS_PATH`,
  `DTVP_TMRESCORE_CACHE_PATH`, `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH`,
  `DTVP_SSVC_CACHE_PATH` and the settings paths. The results and proposals
  otherwise resolve to `data/` in the working directory, the production
  files; the restore then stops with T1 because the running backend holds
  that directory's lock.
- Run one River process per data directory. Before it opens a database the
  backend takes an exclusive lock (`flock`) on
  `data/dt_cache/.dtvp-instance.lock` and on `.dtvp-instance.lock` in every
  other directory holding its record databases, proposals file or caches
  (by default `data/`); a second backend, or a restore, using any of those
  directories fails at startup with a message naming the lock. The lock needs a local filesystem
  or a Docker volume; do not put the data directory on NFS. The backend
  records the paths it resolved in `data/dt_cache/.dtvp-instance.json`.
  While a restore journal (`data/dt_cache/.dtvp-restore-*.json`) exists, the
  backend refuses to start until the restore is completed or undone.
- Code analysis is an optional external service. Deploy Agentyzer separately,
  configure its repository mappings there, and set `DTVP_CODE_ANALYSIS_URL` to
  an endpoint reachable from the River container. An empty URL disables the
  integration. River's Compose stack does not build or start the analyzer.
- Internal services use Compose names and container ports. River reaches
  Dependency-Track at `http://dtrack-apiserver:8080` unless overridden.
- If proxies are configured, list exact internal hostnames/IPs in `NO_PROXY`;
  do not rely only on CIDR entries.
- River delegates OIDC discovery, state and nonce handling, the authorization-
  code flow with S256 PKCE, token exchange, and JWKS-backed ID-token validation
  to Authlib. Its transient login state lives in a signed, HttpOnly cookie that
  expires after ten minutes. This login is independent of Dependency-Track
  browser sessions: backend calls use `DTVP_DT_API_KEY` and never forward
  browser credentials.
- Every deployment needs its own session signing key of at least 32 random
  bytes. It signs the session cookie, the login-state cookie, and SSVC evidence
  tokens. Generate one with
  `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` or
  `openssl rand -base64 48` and set it as `DTVP_SESSION_SECRET_KEY` in `.env`,
  or write it to a file, mount that file read-only, and name it with
  `DTVP_SESSION_SECRET_KEY_FILE`. River refuses to start when the key is unset,
  the old `change_me` placeholder, or shorter than 32 bytes: the backend logs
  the reason and uvicorn exits with "Application startup failed", so the
  container stops instead of serving. Keys committed to the repository for
  development and tests start with `dtvp-dev-only-` and are refused unless
  `DTVP_SESSION_ALLOW_DEV_KEY=true`; never set that flag in a deployment.
  Rotating the key signs everyone out and invalidates SSVC suggestions that
  are still open in a browser.
- A session cookie is valid for `DTVP_SESSION_TTL_HOURS` (default 12 hours)
  after it was issued. It is renewed on use once more than half of that has
  passed, so active users stay signed in and an unused session ends within
  that time. However active, a session ends `DTVP_SESSION_MAX_AGE_HOURS`
  (default 168, one week) after sign-in. Each user has a
  session version in the database (the access-token tables, see
  `DTVP_ACCESS_TOKENS_PATH`), and every request checks it: logout ends all
  sessions of that user on every device. Back up that database like the main
  one: losing it restores every revoked session. When the version cannot be
  written, logout answers `503` and keeps the cookie instead of pretending to
  sign out. A reviewer ends another user's sessions with
  `POST <context path>/auth/sessions/revoke` and the body
  `{"username": "<user>"}` from a signed-in browser session; any user may
  revoke their own. There is no button for it yet; signed in as a reviewer,
  run this in the browser's developer console on a River page:

  ```js
  await fetch('/dtvp/auth/sessions/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'the-user-id' }),
  }).then(r => r.json())
  ```

  Replace `/dtvp` with the context path. The answer is
  `{"status": "revoked", "username": ...}`. The username is the identity River records (the OIDC
  `sub`, as in `user_roles.json`). Access tokens are revoked separately (see
  [AI and API access](ai-access.md)). When the database cannot be read,
  requests fail with `503` instead of signing users out. After upgrading to a
  version with expiring sessions, every user signs in once more; older
  cookies are rejected.
- API `401` responses move the SPA to sign-in and preserve the current route for
  the OIDC return. Reviewer authorization failures remain `403` errors and do
  not incorrectly log the user out.
- Completed grouped-vulnerability tasks are retained by idle time. Visible
  project tabs renew their lightweight task lease and rebuild an expired task
  automatically after a suspended browser resumes, so details and bulk actions
  do not require a full-page reload.
- A sync scheduler reads Dependency-Track in the background: the project
  list every minute, the findings of watched products every two minutes, and
  every other active version once and then on Dependency-Track's change
  signals or every 12 hours, within 4 requests per second shared with the
  export. Plan the first start of a large instance accordingly: the backfill
  imports every active version at that rate. See
  [Sync scheduler](runtime.md#sync-scheduler) and
  [ADR 0004](adr/0004-background-sync-and-event-stream.md).
  plans to replace this with a background scheduler.
- Process-local cache objects and named project searches use LRU limits, and
  completed grouped tasks have a separate retained-count cap. These bounds keep
  long-running and multi-user instances from growing without limit.
- nginx proxies `DTVP_CONTEXT_PATH` to River and defaults it to `/dtvp`.
  `DTVP_HTTP_PORT` changes the host gateway port. Direct-container deployments
  must publish port `8000` and include the context path in the URL.
- The Compose nginx gateway keeps upstream HTTP/1.1 connections open,
  compresses JSON/static text responses, and disables buffering and
  compression for the live-update stream `/api/events`, the grouped task
  event streams, and the project archive task streams (the archive stream was
  buffered before). Uvicorn keeps those upstream connections for 30 seconds
  and uses a 2048-connection accept backlog.
- An external proxy in front of River must not buffer or compress
  `text/event-stream` responses on `/api/events`, `/api/tasks/*/events`, and
  `/api/project-archives/tasks/*/events`, and must allow idle reads longer
  than 15 seconds (1 hour recommended). Clients whose proxy cannot stream
  (it buffers the stream, or holds the response headers for more than
  35 seconds) fall back to polling `/api/events/poll` after three failed
  attempts. See [Event channel](runtime.md#event-channel).
- Stop the container with SIGTERM (`docker stop` does). The signal ends open
  `/api/events` streams at once, so the graceful shutdown does not wait for
  them.
- Serve River over HTTP/2 at the TLS-terminating proxy. With HTTP/1.1 browsers
  open about six connections per host, and every long-lived stream holds one;
  the Compose nginx itself listens with HTTP/1.1.
- `dtvp.boot:app` serves startup status while the real app initializes. Startup
  logs time cache and integration initialization.
- Database and data migrations run during startup and report what they are
  doing: each step is printed to the console with a `[startup]` prefix, and
  the start page shows the current step, for example
  `Data migration: 4000 of 51000 assessments read into fields`, until it is
  finished. Reading existing assessments into fields happens once, at the
  first start of a version that needs it; 51,000 assessments took under
  three seconds in a test on a development machine.
- The River container startup script prints its packaged project version and
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

The default Compose and published River image use the Python 3.14 free-threaded
build. Start it normally:

```bash
docker compose up -d --build
```

`Dockerfile.free-threaded` asks `uv` for the explicit `3.14t` interpreter. It
loads River's native dependencies and verifies the runtime during the image
build. Compose also sets `DTVP_REQUIRE_FREE_THREADED=true`, so the
application refuses to start if it receives a normal interpreter or a native
extension re-enables the GIL. Confirm the live state under `python` in
`/api/performance-status`; `free_threading_active` must be `true` and
`gil_enabled` must be `false`.

See the official [CPython free-threading
guide](https://docs.python.org/3/howto/free-threading-python.html) and [`uv`
Python variant documentation](https://docs.astral.sh/uv/concepts/python-versions/)
for the interpreter guarantees and `3.14t` selector.

Free threading lets River's dedicated CPU worker pools execute Python code on
multiple cores. It does not make Dependency-Track/network I/O faster, and the
free-threaded interpreter has some single-thread overhead. The pipeline builds
and publishes only this validated free-threaded River image. Its canonical tags
are `latest`, release versions, `dev`, and PR tags; no GIL-enabled or duplicate
variant tags are published.

River's root `pyproject.toml` is its release-version source. Regenerate the root
lockfile after changing that version. A manually pushed `v*` tag must match
River's packaged version before the container is published. The workflow
publishes version tags and `latest` for the `dtvp` container package only.
A pre-release version in PEP 440 form (`2.0.0rc1`, `2.0.0b2`, `2.0.0a1`;
tag `v2.0.0rc1`) gets its version tag but does not move `latest`, and its
Forgejo release is marked as a pre-release.
External code-analysis services have their own releases and dependency state.

The pipeline builds the image with Buildah inside the job container, so the
runner needs neither a mounted Docker socket nor privileged job containers.
Buildah runs build steps in a user namespace, which Docker's default seccomp
profile blocks: start job containers with `--security-opt seccomp=unconfined`
(for Forgejo Runner, `container.options` in its configuration), and also
`--security-opt apparmor=unconfined` on hosts where AppArmor restricts
unprivileged user namespaces. The job checks this up front and fails with a
pointer to this section. It uses the `vfs` storage driver, chroot isolation,
and host networking, and builds without a layer cache.

Archive imports require read, BOM upload, and vulnerability-analysis update
permissions in Dependency-Track. Scheduled snapshots and expanded Git trees
are controlled by the [archive variables](configuration.md#project-archives). The optional
`dtvp-archive-git-push` Compose job pushes an expanded tree; schedule it with
cron, systemd, or CI when required.
