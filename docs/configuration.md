# Configuration Reference

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Dependency-Track, Cache, And Rules](#dependency-track-cache-and-rules)
- [Authentication, Runtime, And Frontend](#authentication-runtime-and-frontend)
- [Project Archives](#project-archives)
- [Threat Model And Code Analysis](#threat-model-and-code-analysis)
- [Agentyzer](#agentyzer)

Set values in `.env` for Compose or in the shell for local `uv` runs. `unset`
means the integration or override is disabled.

## Dependency-Track, Cache, And Rules

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_DT_API_URL` | Dependency-Track API base URL | `http://localhost:8081`; Compose: `http://dtrack-apiserver:8080` |
| `DTVP_DT_API_KEY` | Dependency-Track API key | `change_me` |
| `DTVP_DT_API_KEY_FILE` | API-key file used when the direct value is unset | unset |
| `DEPENDENCY_TRACK_URL` / `DEPENDENCY_TRACK_API_KEY` | Deployment aliases | unset |
| `DTVP_DT_CACHE_PATH` | Dependency-Track cache and pending update queue | `data/dt_cache` |
| `DTVP_DT_CACHE_REFRESH_SECONDS` | Background refresh interval | `60` |
| `DTVP_DT_PROJECT_LIST_TTL_SECONDS` | Freshness window for serving the complete cached project list without an upstream request | `30` |
| `DTVP_DT_ACTIVE_PROJECT_TTL_SECONDS` | Idle window for periodic per-project background refresh | `900` |
| `DTVP_DT_ACTIVE_PROJECT_LIMIT` | Most-recent projects eligible for periodic refresh | `8` |
| `DTVP_DT_MEMORY_CACHE_MAX_ENTRIES` | Process-local LRU file-object cache entries; disk files remain persistent | `256` |
| `DTVP_DT_PROJECT_QUERY_CACHE_MAX_ENTRIES` | Process-local named-project query LRU entries | `128` |
| `DTVP_ASSESSMENT_OUTBOX_PATH` | Transactional assessment overlay and synchronization outbox | `<DTVP_DT_CACHE_PATH>/assessment_outbox.sqlite` |
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

## Authentication, Runtime, And Frontend

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `DTVP_OIDC_AUTHORITY` | OIDC authority URL | unset |
| `DTVP_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `DTVP_OIDC_CLIENT_SECRET` | Optional OIDC client secret for confidential clients | unset |
| `DTVP_OIDC_REDIRECT_URI` | OIDC callback | derived from frontend URL/context path |
| `DTVP_SESSION_SECRET_KEY` | Session signing key | `change_me` |
| `DTVP_DEV_DISABLE_AUTH` | Resolve local requests as `devuser` | `false` |
| `DTVP_FRONTEND_URL` | Public frontend base URL | `http://localhost:8000` |
| `DTVP_CONTEXT_PATH` | Application mount path | app `/`; Compose `/dtvp` |
| `DTVP_HTTP_PORT` | Compose nginx host port | `80` |
| `DTVP_UVICORN_KEEP_ALIVE_SECONDS` | Backend upstream keep-alive timeout | `30` |
| `DTVP_REQUIRE_FREE_THREADED` | Fail startup unless CPython supports free threading and its GIL is actually disabled | local Python: `false`; Compose: `true` |
| `DTVP_BOOT_APP` | Real ASGI app loaded by the boot wrapper | `dtvp.main:app` |
| `DTVP_CORS_ORIGINS` | Additional comma-separated CORS origins | unset |
| `DTVP_API_URL` | Frontend API base override; Vite alias `VITE_DTVP_API_URL` | empty |
| `DTVP_DEFAULT_PROJECT_FILTER` | Dashboard default project filter | empty |
| `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` | Attribution-age presets | `7d,14d,28d` |
| `DTVP_BUILD_COMMIT` | Build metadata shown in the UI | `unknown` |
| `BUILD_NUMBER` | Compose image build number, baked into DTVP and Agentyzer startup logs | `unknown` |

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
| `DTVP_CODE_ANALYSIS_URL` | Analyzer base URL | unset; Compose: `http://agentyzer:8000` |
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
| `DTVP_CODE_ANALYSIS_RESULTS_PATH` | Result/application SQLite store | `data/code_analysis_results.sqlite` |
| `DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS` | Maximum stored results | `2000` |
| `DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS` | Maximum result age; `0` disables | `0` |
| `DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE` | Persist reviewer/follow-up guidance | `true` |
| `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` | Maximum dedupe age; `0` uses fingerprints only | `0` |
| `DTVP_AUTO_CODE_ANALYSIS_ENABLED` | Enable automatic scans | `false` |
| `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS` | Automatic sweep interval | `900` |
| `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` | Static component guidance | `data/auto_analysis_guidance.json` |

## Agentyzer

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `AGENTYZER_PORT` | Compose host port | `8095` |
| `AGENTYZER_LOG_LEVEL` | Service log level | `INFO` |
| `AGENTYZER_MAX_CONCURRENT_JOBS` | Concurrent assessment pipelines | `1` |
| `AGENTYZER_REPO_REFRESH_SECONDS` | Background refresh interval for explicit URL-backed repository mappings; `0` disables and positive values have a 60-second minimum | `900` |
| `AGENTYZER_GITHUB_TOKEN` | Optional GitHub token for authenticated advisory lookups and higher API limits | unset |
| `AGENTYZER_ARCHIVE_MAX_INPUT_BYTES` | Maximum input size for one repository archive | `1073741824` |
| `AGENTYZER_ARCHIVE_MAX_ARCHIVES` | Maximum archives inspected per analysis | `25` |
| `AGENTYZER_ARCHIVE_MAX_NESTING` | Maximum nested-archive depth | `2` |
| `AGENTYZER_ARCHIVE_MAX_MEMBERS` | Maximum combined archive member count | `50000` |
| `AGENTYZER_ARCHIVE_MAX_MEMBER_BYTES` | Maximum extracted size of one member | `268435456` |
| `AGENTYZER_ARCHIVE_MAX_EXTRACTED_BYTES` | Maximum combined extracted archive data | `2147483648` |
| `AGENTYZER_LLM_BACKEND` | `ollama` or `openwebui` | `ollama` |
| `AGENTYZER_OLLAMA_HOST` / `AGENTYZER_OLLAMA_MODEL` | Ollama endpoint and model | `http://host.docker.internal:11434` / `mistral` |
| `AGENTYZER_OPENWEBUI_HOST` / `AGENTYZER_OPENWEBUI_MODEL` | OpenWebUI endpoint and model | `http://host.docker.internal:3000` / `mistral` |
| `AGENTYZER_OPENWEBUI_API_KEY` | Optional OpenWebUI bearer token | unset |
| `AGENTYZER_OPENWEBUI_TOOL_CALLS` | Native tool calls: `auto` or `off` | `auto` |
| `AGENTYZER_OPENWEBUI_CONTEXT_WINDOW` | Optional context limit | `0` |
| `AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN` | Reserved token margin | `256` |
| `AGENTYZER_OPENWEBUI_CONTEXT_RETRIES` | Oversized-context retries | `2` |
| `AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS` | Completion budget preserved during compaction | `256` |
| `AGENTYZER_RESEARCH_CLONE_ENABLED` | Allow bounded local dependent-repository inspection | `true` |
| `AGENTYZER_RESEARCH_GIT_HOSTS` | Comma-separated public HTTPS Git host allowlist (`*` permits any public host) | `github.com,gitlab.com,bitbucket.org` |
| `AGENTYZER_RESEARCH_MAX_CLONES_PER_ANALYSIS` | Shared repository-clone budget across one LLM research loop | `3` |
| `AGENTYZER_RESEARCH_CLONE_TIMEOUT_SECONDS` | Clone/inspection Git command timeout | `90` |
| `AGENTYZER_RESEARCH_CLONE_MAX_REPOSITORY_MB` | Maximum cached research-clone disk use | `256` |
| `AGENTYZER_RESEARCH_CLONE_MAX_FILE_BYTES` | Maximum committed file size inspected | `256000` |
| `AGENTYZER_RESEARCH_CLONE_CACHE_TTL_SECONDS` | Freshness window before a research repository is cloned again | `3600` |

When the OpenWebUI context window is configured, Agentyzer uses a conservative
code-oriented token estimate, reserves the requested completion budget, and
pre-compacts oversized messages. If the provider's tokenizer still rejects a
request, both supported OpenWebUI context-error formats are parsed; the reported
limit and request size drive a bounded retry and the learned limit is reused by
later calls. Reachability prompts also cap generated AST evidence at 48,000
characters with an explicit omission marker while retaining complete scan
counts in pipeline evidence.
