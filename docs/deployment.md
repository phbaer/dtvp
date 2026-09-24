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

- `./data` mounts at `/app/data`; mappings, roles, rules, caches, proposals, and
  archives survive container restarts.
- Compose starts Agentyzer and persists control repositories, worktree locks,
  and transient detached worktrees in the `agentyzer-repos` volume. Populate
  or override the sanitized `agentyzer/config/repos.yaml` before enabling
  automatic scans; never commit repository credentials. Agentyzer immediately
  clones or fetches every explicit URL-backed mapping on startup, refreshes
  those control repositories every `AGENTYZER_REPO_REFRESH_SECONDS`, and fetches
  again immediately before creating an assessment worktree. The periodic pass
  is independent of advisory filtering, so references remain current even when
  an assessment exits before repository preparation.
- Internal services use Compose names and container ports. DTVP reaches
  Dependency-Track at `http://dtrack-apiserver:8080` and Agentyzer at
  `http://agentyzer:8000` unless overridden.
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
  logs time cache and integration initialization.
- The DTVP and Agentyzer container startup scripts print their packaged project
  versions and image build numbers before importing either application, so this
  deployment identity remains visible in Docker logs even if initialization fails.
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

The default Compose and published DTVP image use the Python 3.14 free-threaded
build. Start it normally:

```bash
docker compose up -d --build
```

`Dockerfile.free-threaded` asks `uv` for the explicit `3.14t` interpreter. It
loads DTVP's native dependencies and verifies the runtime during the image
build. Compose also sets `DTVP_REQUIRE_FREE_THREADED=true`, so the
application refuses to start if it receives a normal interpreter or a native
extension re-enables the GIL. Confirm the live state under `python` in
`/api/performance-status`; `free_threading_active` must be `true` and
`gil_enabled` must be `false`.

See the official [CPython free-threading
guide](https://docs.python.org/3/howto/free-threading-python.html) and [`uv`
Python variant documentation](https://docs.astral.sh/uv/concepts/python-versions/)
for the interpreter guarantees and `3.14t` selector.

Free threading lets DTVP's dedicated CPU worker pools execute Python code on
multiple cores. It does not make Dependency-Track/network I/O faster, and the
free-threaded interpreter has some single-thread overhead. The pipeline builds
and publishes only this validated free-threaded DTVP image. Its canonical tags
are `latest`, release versions, `dev`, and PR tags; no GIL-enabled or duplicate
variant tags are published.

DTVP and Agentyzer release in lockstep from this monorepo. The root
`pyproject.toml` is the single release-version source: Agentyzer derives its
dynamic package metadata from that value, and its container build receives the
same derived value as a build argument. Regenerate both lockfiles after changing
the root version. A manually pushed `v*` tag must match the root packaged
version before either container is published. The single Git tag identifies the
shared source commit; the workflow publishes that version tag and `latest` to
both the `dtvp` and `agentyzer` container packages. Agentyzer's
health/configuration responses read the installed package metadata instead of
a hard-coded API version.

Archive imports require read, BOM upload, and vulnerability-analysis update
permissions in Dependency-Track. Scheduled snapshots and expanded Git trees
are controlled by the [archive variables](configuration.md#project-archives). The optional
`dtvp-archive-git-push` Compose job pushes an expanded tree; schedule it with
cron, systemd, or CI when required.
