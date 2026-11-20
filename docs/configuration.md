# Configuration Reference

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Dependency-Track, Cache, And Rules](#dependency-track-cache-and-rules)
- [Authentication, Runtime, And Frontend](#authentication-runtime-and-frontend)
- [Project Archives](#project-archives)
- [Threat Model And Code Analysis](#threat-model-and-code-analysis)

Set values in `.env` for Compose or in the shell for local `uv` runs. `unset`
means the integration or override is disabled.

## Dependency-Track, Cache, And Rules

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081`; Compose: `http://dtrack-apiserver:8080` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | API-key file used when the direct value is unset | unset |
| `DEPENDENCY_TRACK_URL` / `DEPENDENCY_TRACK_API_KEY` | Deployment aliases | unset |
| `DTVP_DT_CACHE_PATH` | Directory of the local database and the pending update queue. Persistent data, not a disposable cache | `data/dt_cache` |
| `DTVP_DATABASE_PATH` | The local SQLite database: imported projects, findings, vulnerability details, BOMs, last known source assessments, local assessments with their export queue, and access tokens | `<DTVP_DT_CACHE_PATH>/dtvp.sqlite3` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background refresh interval in whole seconds, at least 1; an unusable value falls back to the default | `60` |
| `DTVP_SSVC_ENRICHMENT_ENABLED` | Fetch exploitation evidence for SSVC from the sources listed in `dtvp/resources/ssvc-sources.json` over the network. Off with anything but `true`, `1`, or `yes` | `true` |
| `DTVP_SSVC_CACHE_PATH` | Cache of that evidence | `<DTVP_DT_CACHE_PATH>/ssvc_enrichment.sqlite3` |
| `DTVP_DT_PROJECT_LIST_TTL_SECONDS` | Freshness window for serving the complete cached project list without an upstream request | `30` |
| `DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS` | Idle window for periodic per-project background refresh | `900` |
| `DTVP_DT_ACTIVE_PROJECT_LIMIT` | Most-recent projects eligible for periodic refresh | `8` |
| `DTVP_DT_MEMORY_CACHE_MAX_ENTRIES` | Process-local LRU of decoded documents; the database remains the persistent copy | `256` |
| `DTVP_DT_PROJECT_QUERY_CACHE_MAX_ENTRIES` | Process-local named-project query LRU entries | `128` |
| `DTVP_ASSESSMENT_OUTBOX_PATH` | Separate file for local assessments and the export queue. Leave unset to keep them in the database; a former `<DTVP_DT_CACHE_PATH>/assessment_outbox.sqlite` is copied in once | `DTVP_DATABASE_PATH` |
| `DTVP_EXPORT_MODE` | `auto` exports assessments in the background as they are saved; `manual` keeps them local until a reviewer exports them. See [Import and export](import-export.md) | `auto` |
| `DTVP_FIXED_VERSIONS_REFRESH_DAYS` | Days after which the background refresh reads a vulnerability's affected version ranges from Dependency-Track again, for the [derived VDR recommendation](cyclonedx-export.md#recommendation); a changed record is read at once. Whole number, at least 1; an unusable value falls back to the default | `7` |
| `DTVP_FIXED_VERSIONS_READS_PER_CYCLE` | Most vulnerabilities whose version ranges one background refresh cycle reads (four at a time); the rest follow in later cycles | `200` |
| `DTVP_CYCLONEDX_ASSESSMENT_SOURCE` | `source.name` of DTVP's own rating in [CycloneDX VDR exports](cyclonedx-export.md); a request parameter overrides it | `DTVP` |
| `DTVP_CYCLONEDX_PROPERTY_PREFIX` | Namespace of the properties in CycloneDX VDR exports; a request parameter overrides it | `dtvp` |
| `DTVP_CYCLONEDX_TICKET_PREFIXES` | Comma-separated project keys of ticket references (`EXP` for `EXP-123`) that CycloneDX VDR exports recognise in assessment texts; the request parameter `ticket_prefixes` overrides it | unset: only recorded ticket fields are exported |
| `DTVP_ASSESSMENT_SYNC_CONCURRENCY` | Global concurrent background assessment writes to Dependency-Track | `4` |
| `DTVP_ASSESSMENT_STRICT_DT_CONFLICTS` | Perform live Dependency-Track conflict reads before accepting assessment saves | `false` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Parallel version fetch limit | `4` |
| `DTVP_ASSESSMENT_IO_CONCURRENCY` | Concurrent Dependency-Track assessment reads or writes per operation | `4` |
| `DTVP_ASSESSMENT_WRITE_MAX_ATTEMPTS` | Attempts for transient assessment-write timeouts, rate limits, and HTTP 5xx responses | `3` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | Completed/failed grouped-task idle retention | `900` |
| `DTVP_GROUPED_VULN_TASK_MAX_RETAINED` | Maximum completed/failed grouped tasks retained in process | `24` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | Persisted summary-index SQLite path | sibling of cache path |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted summary indexes | `64` |
| `DTVP_GROUP_QUERY_WORKERS` | Dedicated grouped-search worker threads | `4` |
| `DTVP_GROUP_QUERY_MAX_PENDING` | Maximum grouped searches queued behind active workers | `8` |
| `DTVP_GROUP_QUERY_CACHE_ENTRIES` | Maximum cached filter combinations per grouped task | `32` |
| `DTVP_GROUP_QUERY_CACHE_BYTES` | Approximate per-task filtered-index and facet-cache budget | `8388608` |
| `DTVP_GROUP_BUILD_WORKERS` | Dedicated CPU workers for grouped snapshot/index construction | `2` |
| `DTVP_GROUP_BUILD_MAX_PENDING` | Group-build jobs admitted behind active build workers before async backpressure | `4` |
| `DTVP_GROUP_POSTPROCESS_WORKERS` | Dedicated workers for automatic-analysis planning after a snapshot completes | `1` |
| `DTVP_GROUP_POSTPROCESS_MAX_PENDING` | Post-processing jobs admitted behind active workers before async backpressure | `2` |
| `DTVP_GROUP_DETAIL_WORKERS` | Reserved workers for full vulnerability detail hydration | `2` |
| `DTVP_GROUP_DETAIL_MAX_PENDING` | Detail hydration jobs admitted before async backpressure | `8` |
| `TEAM_MAPPING_PATH` | Component ownership mapping | `data/team_mapping.json` |
| `TEAM_GROUPS_PATH` | Nested team-group definitions | `data/team_groups.json` |
| `USER_ROLES_PATH` | User-to-role mapping | `data/user_roles.json` |
| `RESCORE_RULES_PATH` | CVSS transition rules | `data/rescore_rules.json` |

## Access Tokens And MCP

See [AI and API access](ai-access.md) for behavior and limits.

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_ACCESS_TOKENS_ENABLED` | Accept personal access tokens on `/api` (read-only) and serve the MCP endpoint at `<context path>/mcp` | `false` |
| `DTVP_ACCESS_TOKENS_PATH` | Separate file for token digests, the token audit log, and the browser session versions that logout and revocation depend on. Back it up with the main database: losing it restores revoked sessions. Leave unset to keep them in the database | `DTVP_DATABASE_PATH` |

## Authentication, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL; the older name `ISSUER_URL` is read when this is unset | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID; the older name `CLIENT_ID` is read when this is unset | unset |
| `DTVP_OIDC_CLIENT_SECRET` | Optional OIDC client secret for confidential clients | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback | derived from frontend URL/context path |
| `DTVP_SESSION_SECRET_KEY` | Required. Signs the session cookie, the OIDC login-state cookie, and SSVC evidence tokens. At least 32 bytes; startup is refused when it is unset, `change_me`, or shorter. Generate one with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` or `openssl rand -base64 48` | none (required) |
| `DTVP_SESSION_SECRET_KEY_FILE` | Alternative to `DTVP_SESSION_SECRET_KEY`: path of a file holding the key, for example a mounted secret. Trailing whitespace and newlines are stripped; an unreadable file is refused, and setting both variables is refused | unset |
| `DTVP_SESSION_TTL_HOURS` | Lifetime of a sign-in in whole hours, 1–720. A session is renewed on use once more than half of it has passed; an unused one ends this long after it was issued or last renewed. Logout and [revocation](deployment.md) end it earlier | `12` |
| `DTVP_SESSION_MAX_AGE_HOURS` | Absolute lifetime of a sign-in in whole hours, from the lifetime above to 2160. Renewal never extends a session past it; the user signs in again | `168` |
| `DTVP_SESSION_ALLOW_DEV_KEY` | Accept a key starting with `dtvp-dev-only-`, the keys committed for the local development stack and the tests. Never set it in a deployment | `false` |
| `DTVP_DEV_DISABLE_AUTH` | Resolve local requests as `devuser` | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000`; Compose: `http://localhost/dtvp` |
| `DTVP_CONTEXT_PATH` | Application mount path | app `/`; Compose `/dtvp` |
| `DTVP_HTTP_PORT` | Compose nginx host port | `80` |
| `DTVP_UVICORN_KEEP_ALIVE_SECONDS` | Backend upstream keep-alive timeout | `30` |
| `DTVP_EVENT_BUFFER_SIZE` | Events kept for clients that reconnect to `/api/events`; at least 100. See [Event channel](runtime.md#event-channel) | `2000` |
| `DTVP_EVENT_MAX_CONNECTIONS` | Open `/api/events` streams; more get `503`; at least 1 | `200` |
| `DTVP_EVENT_MAX_CONNECTIONS_PER_USER` | Open `/api/events` streams of one user; more get `429`; at least 1 | `20` |
| `DTVP_REQUIRE_FREE_THREADED` | Fail startup unless CPython supports free threading and its GIL is actually disabled | local Python: `false`; Compose: `true` |
| `DTVP_BOOT_APP` | Real ASGI app loaded by the boot wrapper | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Comma-separated CORS origins. A set value replaces the built-in list (the localhost development origins, `DTVP_FRONTEND_URL`, and the host name) for the application; the startup page shown while DTVP loads adds it to that list instead | unset |
| `VITE_DTVP_API_URL` | Frontend API base override, read by the Vite dev server and at frontend build time only. Setting `DTVP_API_URL` on the container has no effect | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |
| `BUILD_NUMBER` | Compose image build number, baked into DTVP startup logs | `unknown` |

## Project Archives

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_PROJECT_ARCHIVE_PATH` | ZIPs, import previews, and snapshots | `data/project_archives` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_ENABLED` | Write stable Git-friendly trees | `false` |
| `DTVP_PROJECT_ARCHIVE_EXPANDED_PATH` | Expanded tree directory | `data/project_archives_git` |
| `DTVP_PROJECT_ARCHIVE_SNAPSHOT_ENABLED` | Enable scheduled snapshots | `false` |
| `DTVP_PROJECT_ARCHIVE_INTERVAL_SECONDS` | Snapshot interval; minimum 60 | `86400` |
| `DTVP_PROJECT_ARCHIVE_RETENTION_COUNT` | Recent ZIPs retained per project | `30` |
| `DTVP_PROJECT_ARCHIVE_INCLUDE` | Comma-separated scheduled project names | empty |
| `DTVP_ARCHIVE_GIT_REMOTE` | Optional archive Git remote | empty |
| `DTVP_ARCHIVE_GIT_BRANCH` | Archive Git branch | `main` |
| `DTVP_ARCHIVE_GIT_AUTHOR_NAME` | Commit author name | `DTVP Archive Bot` |
| `DTVP_ARCHIVE_GIT_AUTHOR_EMAIL` | Commit author email | `dtvp-archive@example.invalid` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_FILE` | SSH key inside Git helper | `/ssh/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_FILE` | Known-hosts file inside Git helper | `/ssh/known_hosts` |

## Threat Model And Code Analysis

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_TMRESCORE_URL` | tmrescore/vscorer base URL | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | HTTP timeout before polling fallback | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Cached proposal snapshots | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | Completed/failed task retention | `3600` |
| `DTVP_CODE_ANALYSIS_URL` | Analyzer base URL | unset; code analysis disabled |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | Analyzer HTTP timeout | `300` |
| `DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS` | Dashboard health/jobs timeout | `5` |
| `DTVP_CODE_ANALYSIS_DASHBOARD_CACHE_SECONDS` | Shared dashboard status snapshot lifetime | `3` |
| `DTVP_CODE_ANALYSIS_MODEL` | Analyzer model hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_BACKEND` | LLM backend hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_PROVIDER` | LLM provider hint | unset |
| `DTVP_JIRA_CREATE_URL` | Jira create-screen URL | unset |
| `DTVP_ANALYSIS_QUEUE_CAPACITY` | Concurrent DTVP queue items | `1` |
| `DTVP_ANALYSIS_QUEUE_MAX_PENDING` | Maximum pending DTVP queue items before new submissions receive HTTP 429 | `1000` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | Completed/failed queue retention | `3600` |
| `DTVP_CODE_ANALYSIS_RESULTS_PATH` | Result/application SQLite store; also holds the code evidence agents add through MCP ([agent code evidence](analysis-integrations.md#agent-code-evidence)) | `data/code_analysis_results.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` | Maximum stored analyzer results; agent code evidence is not counted or pruned | `2000` |
| `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS` | Maximum analyzer result age; `0` disables. Agent code evidence is kept | `0` |
| `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE` | Persist reviewer/follow-up guidance | `true` |
| `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` | Maximum dedupe age; `0` uses fingerprints only | `0` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Enable automatic scans | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Automatic sweep interval | `900` |
| `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` | Static component guidance | `data/auto_analysis_guidance.json` |

The analyzer runs independently of DTVP. Configure its repositories, model
backend, credentials, and concurrency in its own deployment; DTVP's Compose
file and `.env.dist` configure only the HTTP integration above.
