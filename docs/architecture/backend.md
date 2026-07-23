---
type: Component
title: DTVP Backend Architecture
description: FastAPI composition, domain services, task execution, durable state, and provider boundaries.
tags:
  - backend
  - fastapi
  - architecture
source_paths:
  - dtvp/
  - tests/
  - pyproject.toml
  - compose.yml
review_when:
  - Backend composition, authorization, task execution, durable state, provider capabilities, or scaling assumptions change.
---

# DTVP Backend Architecture

The backend is the authorization and consistency boundary for the application.
It composes FastAPI routes around domain services, a capability-based
vulnerability-backend adapter, backend-scoped local state, and optional
TMRescore and code-analysis clients.

## Components

| Component | Role |
| :--- | :--- |
| `dtvp/boot.py` | Binds early, serves startup status, then loads the real ASGI app |
| `dtvp/main.py`, `app_wiring.py`, and `runtime_state.py` | Composition root, lifecycle, dependency construction, routers, and explicit process-state ownership |
| `dtvp/auth.py` and `authorization.py` | OIDC/session principals, role normalization, and reusable reviewer/owner policies |
| `dtvp/general_api_routes.py` | Projects, grouped tasks, task windows, statistics, assessments, and dependency chains |
| `dtvp/grouped_vuln_services.py` | Concurrent finding, vulnerability, and BOM collection before grouping |
| `dtvp/task_group_query_services.py` | Backend filtering, sorting, facets, pagination, and task-window queries |
| `dtvp/logic.py` | Grouping, ownership, assessment parsing, CVSS, statistics, and dependency analysis |
| `dtvp/assessment_*` and `rescore_rule_services.py` | Assessment writes, conflict handling, metadata recovery, and CVSS rules |
| `dtvp/bulk_workflows/` | Registry-backed bulk-change plug-ins |
| `dtvp/vulnerability_backend.py`, `dt_client.py`, and `dt_cache.py` | Vendor-neutral capabilities/resource references, Dependency-Track adapter, cached data, overlays, and pending writes |
| `dtvp/project_archive_*` | Project archive export/import and scheduled snapshots |
| `dtvp/tmrescore_*` | Threat-model integration, inventory, cache, execution, and task state |
| `dtvp/code_analysis_*` and `analysis_queue_*` | Analyzer integration, result store, queue, and automatic scans |

`dtvp.code_analysis_integration` is the maintained analyzer HTTP client. The
former misspelled `dtvp.agentizer_integration` import is a compatibility facade
for downstream callers and legacy `DTVP_AGENYZER_*` settings; new code uses the
provider-neutral `DTVP_CODE_ANALYSIS_*` names.

## Runtime And Data Flow

- Grouped-vulnerability tasks use `response_mode=summary` for compact list
  rows. `/api/tasks/{task_id}/events` streams progress,
  `/api/tasks/{task_id}/groups` serves filtered windows and facets, and
  `/api/tasks/{task_id}/groups/{group_id}` hydrates full details.
- Partial version results appear while grouping continues. CPU-heavy grouping,
  indexing, and filtering run outside the async event loop. When the final
  partial publish already contains every version, it becomes the completed
  snapshot without repeating grouping and index construction.
- Grouped-task searches use thread-safe per-task query caches, share identical
  in-flight queries, and reuse sort orders across filter changes. Lightweight
  code-assessment metadata is cached and invalidated when analyzer results
  change.
- The local cache under `DTVP_DT_CACHE_PATH` stores projects, findings,
  vulnerability details, BOMs, local overlays, and pending writes. Stale cached
  data remains readable while the provider is unavailable. Concurrent misses
  for one resource share one provider request, while each caller receives an
  isolated mutable snapshot.
- Non-default backend instance IDs place caches, queues, archives, TMRescore
  proposals, and analyzer results in separate `backends/<id>` namespaces.
  Cache markers reject accidental reuse by a different instance.
- Grouped-vulnerability tasks, their bulk operations, archive tasks, live
  TMRescore sessions, analyzer queue entries, and saved analysis results are
  private to their authenticated creator. Reviewers can manage analyzer work
  across users. Shared vulnerability-provider assessments and cached proposal
  snapshots remain shared domain data.
- Analyzer queue snapshots are persisted in SQLite. Queued work resumes after
  restart, while work that was running is marked failed as interrupted so DTVP
  cannot submit a duplicate external scan.

## Authorization And Consistency

Authorization fails closed: a missing, unreadable, invalid, or incomplete
`USER_ROLES_PATH` mapping assigns `ANALYST`; only an explicit `REVIEWER` value
grants reviewer permissions. TMRescore, archive management, global code-analysis
controls, bulk queue controls, and settings changes enforce reviewer
permissions in the backend.

Assessment writes are authorized and reconciled by the backend. A normal write
includes the current snapshot for every unique finding UUID. DTVP refreshes the
findings from the vulnerability provider and returns `409` for stale state or
`503` when current state cannot be verified. Analysts can update only a named,
non-General team block. Only reviewers can force an overwrite, and force
requires `REPLACE` mode.

Provider credentials remain server-side and backend-instance scoped. A
Dependency-Track API key represents the configured service account and is not a
substitute for the signed-in DTVP user: DTVP owns end-user authentication,
authorization, attribution, and policy enforcement. Future adapters such as
Cybeats implement the same capability contract without exposing vendor
credentials or identifiers to frontend policy.

Project dependency-chain reads require an authenticated DTVP session like
other project and finding endpoints. Startup status is available at `/startup`
and `/api/startup`; minimal unauthenticated `/livez` and `/readyz` probes
distinguish process liveness from runtime and durable-storage readiness. Normal
host validation still applies.

## Process Model And Capacity

Grouping, archive, and live TMRescore task registries remain process-local. The
supplied Uvicorn/PM2 launch uses one backend worker. DTVP takes an owner-only
exclusive lease on its state volume and fails startup if a second process
targets it. A horizontally scaled deployment needs shared coordination and
must replace that lease before enabling multiple API workers.

The current single-process deployment should be planned for roughly 8–12
simultaneously active users on very large projects or 30–50 on medium projects.
Mostly idle or dashboard users are substantially cheaper; 100–300 concurrent
sessions is a reasonable starting estimate when they are not all retaining
large grouped-vulnerability tasks. These are sizing estimates, not production
guarantees.

A synthetic benchmark on a 20-CPU, 15 GiB host with the Python GIL enabled
measured eight concurrent cold searches:

| Grouped vulnerabilities | Throughput | p95 search latency |
| :--- | ---: | ---: |
| 1,000 | about 730 queries/second | 1.3 ms |
| 5,000 | about 176 queries/second | 50 ms |
| 10,000 | about 99 queries/second | 96 ms |
| 20,000 | about 25–40 queries/second | 260–470 ms |

At 16 simultaneous cold searches over 20,000 groups, p95 latency approached
one second. An identical cached search took about 0.07 ms. A synthetic
20,000-group summary and query index retained about 78 MB of live Python
allocations and increased initial process RSS by about 175 MB. Real tasks also
retain full vulnerability, component, dependency, and BOM details, so budget
roughly 150–300 MB or more for each large retained task. The default one-hour
`DTVP_GROUPED_VULN_TASK_TTL_SECONDS` makes memory the likely limit when many
users retain large tasks.

Before increasing these ranges, use production-shaped load tests. Initial
scaling steps are reducing grouped-task retention, increasing frontend search
debounce, and introducing a shared task/result store. Code analysis runs one
job concurrently by default through `DTVP_ANALYSIS_QUEUE_CAPACITY`; additional
jobs wait in the shared queue.

## Related Concepts

- [Frontend architecture](frontend.md)
- [Agentyzer architecture](agentyzer.md)
- [Integration API surface](../integration-api-surface.md)
- [Threat model](../threat-model.md)
- [Workflow diagrams](../workflow-flowcharts.md)
