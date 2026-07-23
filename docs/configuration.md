---
type: Reference
title: Runtime Configuration Reference
description: Environment variables, defaults, secrets, storage paths, and optional integration settings for DTVP and Agentyzer.
tags:
  - configuration
  - deployment
  - environment
source_paths:
  - dtvp/configuration.py
  - agentyzer/src/configuration.py
  - dtvp/auth.py
  - dtvp/dt_client.py
  - dtvp/code_analysis_integration.py
  - dtvp/tmrescore_integration.py
  - compose.yml
  - .env.dist
review_when:
  - A runtime variable, default, secret, path, capacity, timeout, or integration setting changes.
---

# Configuration Reference

Set values in `.env` for Compose or in the shell for local `uv` runs. `unset`
means the integration or override is disabled.

## Dependency-Track, Cache, And Rules

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_VULNERABILITY_BACKEND_ID` | Stable backend-instance namespace used for local state and resource identity | `dependency-track` |
| `DTVP_VULNERABILITY_BACKEND_TYPE` | Adapter implementation; currently only `dependency-track` is runnable | `dependency-track` |
| `DTVP_VULNERABILITY_BACKEND_LABEL` | Non-secret display label returned by backend discovery | `Dependency-Track` |
| `DTRACK_DB_PASSWORD` | Required random password shared only by the bundled Dependency-Track API and PostgreSQL; mounted as a secret with `compose.secrets.yml` | unset |
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081`; Compose: `http://dtrack-apiserver:8080` |
| `DTVP_DT_API_KEY` | Least-privilege Dependency-Track review service-team API key; required in production | unset |
| `DTVP_DT_API_KEY_FILE` | API-key file used when the direct value is unset | unset |
| `DTVP_DT_IMPORT_API_KEY` | Separate Dependency-Track archive-import team key | unset; archive apply unavailable |
| `DTVP_DT_IMPORT_API_KEY_FILE` | Archive-import key file used when the direct value is unset | unset |
| `DEPENDENCY_TRACK_URL` / `DEPENDENCY_TRACK_API_KEY` | Deployment aliases | unset |
| `DTVP_DT_CACHE_PATH` | Dependency-Track cache and pending update queue | `data/dt_cache` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background refresh interval | `60` |
| `DTVP_VERSION_FETCH_CONCURRENCY` | Parallel version fetch limit | `4` |
| `DTVP_ASSESSMENT_IO_CONCURRENCY` | Concurrent Dependency-Track assessment reads or writes per operation | `4` |
| `DTVP_ASSESSMENT_WRITE_MAX_ATTEMPTS` | Attempts for transient assessment-write timeouts, rate limits, and HTTP 5xx responses | `3` |
| `DTVP_GROUPED_VULN_TASK_TTL_SECONDS` | Completed/failed grouped-task retention | `3600` |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH` | Persisted summary-index SQLite path | sibling of cache path |
| `DTVP_GROUPED_VULN_SUMMARY_INDEX_MAX_ENTRIES` | Maximum persisted summary indexes | `64` |
| `TEAM_MAPPING_PATH` | Component ownership mapping | `data/team_mapping.json` |
| `USER_ROLES_PATH` | User-to-role mapping | `data/user_roles.json` |
| `RESCORE_RULES_PATH` | CVSS transition rules | `data/rescore_rules.json` |
| `DTVP_SETTINGS_UPLOAD_MAX_BYTES` | Maximum reviewer settings-file upload size | `1048576` (1 MiB) |

## Authentication, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_ENVIRONMENT` | Security profile: `production`, `development`, or `test` | `production` |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC client secret | unset |
| `DTVP_OIDC_CLIENT_SECRET_FILE` | File containing the OIDC client secret when the direct value is unset | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback | derived from frontend URL/context path |
| `DTVP_OIDC_ALLOWED_ALGORITHMS` | Comma-separated asymmetric ID-token algorithms | `RS256` |
| `DTVP_OIDC_TRANSACTION_TTL_SECONDS` | Maximum OIDC state/nonce/PKCE transaction age | `300` |
| `DTVP_SESSION_SECRET_KEY` | Session signing key; at least 32 characters when authentication is enabled | unset; required outside the development bypass |
| `DTVP_SESSION_SECRET_KEY_FILE` | File containing the session key when the direct value is unset | unset |
| `DTVP_SESSION_PREVIOUS_SECRET_KEY` | Temporary previous session key accepted during a rotation grace window | unset |
| `DTVP_SESSION_PREVIOUS_SECRET_KEY_FILE` | File containing the temporary previous session key | unset |
| `DTVP_SESSION_TTL_SECONDS` | Signed DTVP session lifetime | `28800` (8 hours) |
| `DTVP_SESSION_COOKIE_SECURE` | Explicit Secure-cookie override | automatic; required `true` in production |
| `DTVP_DEV_DISABLE_AUTH` | Resolve local requests as `devuser` | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | app `/`; Compose `/dtvp` |
| `DTVP_HTTP_PORT` | Compose nginx host port | `80` |
| `DTVP_SERVER_NAME` | Exact nginx virtual host; space-separated nginx names are supported | `localhost` |
| `DTVP_ALLOWED_HOSTS` | Comma-separated application Host allowlist; defaults to the frontend host plus local development names | derived |
| `DTVP_TRUSTED_PROXY_CIDRS` | Immediate proxy networks allowed to supply `X-Forwarded-For` | unset |
| `DTVP_SECURITY_AUDIT_PATH` | Owner-only structured JSONL security audit target | production: `data/security_audit.jsonl` |
| `DTVP_SECURITY_AUDIT_FSYNC` | Flush every audit event to durable storage before returning | `false` |
| `DTVP_SECURITY_AUDIT_MAX_BYTES` | Rotate the active audit JSONL before this size; `0` disables built-in rotation | `104857600` (100 MiB) |
| `DTVP_SECURITY_AUDIT_BACKUP_COUNT` | Owner-only rotated audit files retained | `10` |
| `DTVP_INSTANCE_LOCK_PATH` | Exclusive lease that prevents unsafe multiple backend workers on one state volume | `data/dtvp-runtime.lock` |
| `DTVP_STORAGE_MIN_FREE_BYTES` | Minimum available bytes required for every durable state path | `134217728` (128 MiB) |
| `DTVP_BACKUP_STATUS_PATH` | Atomic status marker written only after a verified external backup | `data/backup_status.json` |
| `DTVP_BACKUP_MAX_AGE_SECONDS` | Maximum accepted backup-marker age; `0` disables age enforcement | `0` |
| `DTVP_RATE_LIMIT_WINDOW_SECONDS` | Application quota window | `60` |
| `DTVP_AUTH_RATE_LIMIT` | Login/callback requests per IP and window | `30` |
| `DTVP_EXPENSIVE_RATE_LIMIT` | Expensive task mutations per session/IP and window | `20` |
| `DTVP_MUTATION_RATE_LIMIT` | Other state-changing requests per session/IP and window | `120` |
| `DTVP_RUNTIME_UID` / `DTVP_RUNTIME_GID` | Non-root DTVP process and `./data` owner IDs | `1000` / `1000` |
| `DTVP_BOOT_APP` | Real ASGI app loaded by the boot wrapper | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Additional comma-separated CORS origins | unset |
| `DTVP_API_URL` | Frontend API base override; Vite alias `VITE_DTVP_API_URL` | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |

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
| `DTVP_PROJECT_ARCHIVE_UPLOAD_MAX_BYTES` | Maximum uploaded archive size | `104857600` (100 MiB) |
| `DTVP_PROJECT_ARCHIVE_MAX_FILES` | Maximum ZIP member count | `10000` |
| `DTVP_PROJECT_ARCHIVE_MAX_MEMBER_BYTES` | Maximum expanded size of one ZIP member | `104857600` (100 MiB) |
| `DTVP_PROJECT_ARCHIVE_MAX_UNCOMPRESSED_BYTES` | Maximum total expanded ZIP size | `524288000` (500 MiB) |
| `DTVP_PROJECT_ARCHIVE_MAX_COMPRESSION_RATIO` | Maximum permitted ratio for members larger than 1 MiB | `200` |
| `DTVP_ARCHIVE_GIT_REMOTE` | Optional archive Git remote | empty |
| `DTVP_ARCHIVE_GIT_BRANCH` | Archive Git branch | `main` |
| `DTVP_ARCHIVE_GIT_AUTHOR_NAME` | Commit author name | `DTVP Archive Bot` |
| `DTVP_ARCHIVE_GIT_AUTHOR_EMAIL` | Commit author email | `dtvp-archive@example.invalid` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_FILE` | SSH key inside Git helper | `/run/secrets/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_FILE` | Known-hosts file inside Git helper | `/run/secrets/known_hosts` |
| `DTVP_ARCHIVE_GIT_SSH_KEY_HOST_FILE` | Host SSH key mounted only into the archive helper | `./secrets/dtvp_archive_deploy_key` |
| `DTVP_ARCHIVE_GIT_KNOWN_HOSTS_HOST_FILE` | Host known-hosts file mounted only into the archive helper | `./secrets/known_hosts` |

## Threat Model And Code Analysis

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_TMRESCORE_URL` | tmrescore/vscorer base URL | unset |
| `DTVP_TMRESCORE_TIMEOUT_SECONDS` | HTTP timeout before polling fallback | `180` |
| `DTVP_TMRESCORE_CACHE_PATH` | Cached proposal snapshots | `data/tmrescore_proposals.json` |
| `DTVP_TMRESCORE_TASK_TTL_SECONDS` | Completed/failed task retention | `3600` |
| `DTVP_TMRESCORE_UPLOAD_MAX_BYTES` | Maximum size of each tmrescore multipart file | `20971520` (20 MiB) |
| `DTVP_CODE_ANALYSIS_URL` | Analyzer base URL | unset; Compose: `http://agentyzer:8000` |
| `DTVP_CODE_ANALYSIS_TIMEOUT_SECONDS` | Analyzer HTTP timeout | `300` |
| `DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS` | Dashboard health/jobs timeout | `5` |
| `DTVP_CODE_ANALYSIS_SERVICE_TOKEN` | Bearer token shared with Agentyzer; required in production when enabled | unset |
| `DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE` | File containing the analyzer bearer token when the direct value is unset | unset |
| `DTVP_CODE_ANALYSIS_ADMIN_TOKEN` | Separate Agentyzer admin token for reviewer-wide status; required in production when enabled | unset |
| `DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE` | File containing the analyzer admin token when the direct value is unset | unset |
| `DTVP_CODE_ANALYSIS_MODEL` | Analyzer model hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_BACKEND` | LLM backend hint | unset |
| `DTVP_CODE_ANALYSIS_LLM_PROVIDER` | LLM provider hint | unset |
| `DTVP_JIRA_CREATE_URL` | Jira create-screen URL | unset |
| `DTVP_ANALYSIS_QUEUE_CAPACITY` | Concurrent DTVP queue items | `1` |
| `DTVP_ANALYSIS_QUEUE_TTL_SECONDS` | Completed/failed queue retention | `3600` |
| `DTVP_ANALYSIS_QUEUE_STATE_PATH` | Durable analyzer queue SQLite store | `data/analysis_queue.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_PATH` | Result/application SQLite store | `data/code_analysis_results.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` | Maximum stored results | `2000` |
| `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS` | Maximum result age; `0` disables | `0` |
| `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE` | Persist reviewer/follow-up guidance | `true` |
| `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` | Maximum dedupe age; `0` uses fingerprints only | `0` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Enable automatic scans | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Automatic sweep interval | `900` |
| `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` | Static component guidance | `data/auto_analysis_guidance.json` |

The misspelled `DTVP_AGENYZER_*` names are accepted only through the deprecated
`dtvp.agentizer_integration` compatibility facade. New deployments must use
`DTVP_CODE_ANALYSIS_*`; the facade and legacy names are scheduled for removal
in DTVP 2.0.

## Agentyzer

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `AGENTYZER_PORT` | Compose host port | `8095` |
| `AGENTYZER_LOG_LEVEL` | Service log level | `INFO` |
| `AGENTYZER_ENVIRONMENT` | Security profile: `production`, `development`, or `test` | `production` |
| `AGENTYZER_INSTANCE_LOCK_PATH` | Exclusive lease preventing multiple job executors on one repository volume | Compose: `/app/repos/.agentyzer-runtime.lock` |
| `AGENTYZER_STORAGE_MIN_FREE_BYTES` | Minimum free bytes required for the job/repository volume | `134217728` (128 MiB) |
| `AGENTYZER_SERVICE_TOKEN` | Bearer token required by every Agentyzer API route | unset |
| `AGENTYZER_SERVICE_TOKEN_FILE` | File containing the bearer token when the direct value is unset | unset |
| `AGENTYZER_SERVICE_TOKEN_PREVIOUS` | Temporary previous service token accepted only during a rotation grace window | unset |
| `AGENTYZER_SERVICE_TOKEN_PREVIOUS_FILE` | File containing the temporary previous service token | unset |
| `AGENTYZER_ADMIN_TOKEN` | Separate bearer token required for service-wide owner scope | unset |
| `AGENTYZER_ADMIN_TOKEN_FILE` | File containing the admin token when the direct value is unset | unset |
| `AGENTYZER_ADMIN_TOKEN_PREVIOUS` | Temporary previous admin token retaining admin scope during rotation | unset |
| `AGENTYZER_ADMIN_TOKEN_PREVIOUS_FILE` | File containing the temporary previous admin token | unset |
| `AGENTYZER_ALLOW_UNAUTHENTICATED` | Explicit local-only bypass; rejected in production | `false` |
| `AGENTYZER_MAX_CONCURRENT_JOBS` | Concurrent assessment pipelines | `1` |
| `AGENTYZER_MAX_QUEUED_JOBS` | Maximum accepted async jobs waiting for execution | `100` |
| `AGENTYZER_MAX_ACTIVE_JOBS_PER_OWNER` | Maximum pending/running async jobs for one owner | `10` |
| `AGENTYZER_WORKTREE_RETENTION_SECONDS` | Maximum age of orphaned per-run Git worktrees after an interrupted process | `86400` (1 day; minimum 300) |
| `AGENTYZER_JOB_STORE_PATH` | Durable async-job SQLite store | Compose: `/app/repos/agentyzer_jobs.sqlite`; standalone: `repos/agentyzer_jobs.sqlite` |
| `AGENTYZER_JOB_RETENTION_SECONDS` | Terminal-job retention; `0` disables age pruning | `604800` (7 days) |
| `AGENTYZER_JOB_MAX_RECORDS` | Maximum records; active jobs are never pruned | `1000` |
| `AGENTYZER_LLM_BACKEND` | `ollama` or `openwebui` | `ollama` |
| `AGENTYZER_OLLAMA_HOST` / `AGENTYZER_OLLAMA_MODEL` | Ollama endpoint and model | `http://host.docker.internal:11434` / `mistral` |
| `AGENTYZER_OPENWEBUI_HOST` / `AGENTYZER_OPENWEBUI_MODEL` | OpenWebUI endpoint and model | `http://host.docker.internal:3000` / `mistral` |
| `AGENTYZER_OPENWEBUI_API_KEY` | Optional OpenWebUI bearer token | unset |
| `AGENTYZER_OPENWEBUI_API_KEY_FILE` | File containing the OpenWebUI token when the direct value is unset | unset |
| `AGENTYZER_OPENWEBUI_TOOL_CALLS` | Native tool calls: `auto` or `off` | `auto` |
| `AGENTYZER_OPENWEBUI_CONTEXT_WINDOW` | Optional context limit | `0` |
| `AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN` | Reserved token margin | `256` |
| `AGENTYZER_OPENWEBUI_CONTEXT_RETRIES` | Oversized-context retries | `2` |
| `AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS` | Completion budget preserved during compaction | `256` |
