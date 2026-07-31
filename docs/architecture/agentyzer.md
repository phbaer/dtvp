---
type: Component
title: Agentyzer Architecture
description: Isolated repository analysis service, persistent workspaces, asynchronous jobs, and credential hygiene.
tags:
  - agentyzer
  - code-analysis
  - architecture
source_paths:
  - agentyzer/src/
  - agentyzer/config/prompts/
  - agentyzer/pyproject.toml
  - agentyzer/Dockerfile
  - scripts/generate-agentyzer-openapi.py
  - compose.yml
review_when:
  - Repository acquisition, workspace retention, job ownership, queue recovery, prompt handling, provider credentials, or analysis contracts change.
---

# Agentyzer Architecture

Agentyzer is the bundled first-party code-analysis service. DTVP talks to it
through the provider-neutral code-analysis integration rather than importing
its internals. The service clones or updates source repositories, runs
assessment jobs, and returns structured reachability and exploitability
evidence.

## Workspaces And Jobs

Repository workspaces persist on the Agentyzer volume by design. Keeping them
across scans avoids cloning the same repository for every project version and
supports repeated analysis efficiently. Workspace cleanup is therefore not a
normal post-scan action. This persistence is a performance cache, not a
durability boundary: the entire repository/job volume is excluded from DTVP
backups and may be discarded and reconstructed from configured Git sources.
Saved DTVP assessment results remain in DTVP-owned storage.

Credentials are transient even though workspaces persist. Repository URLs and
Git configuration must be sanitized after authenticated operations so tokens
are not left in remotes, credential helpers, logs, prompts, or generated
artifacts. A retained checkout must be safe to reuse without retaining the
credential used to acquire it.

Owner-scoped asynchronous jobs live in bounded SQLite storage on the repository
volume. Pending jobs resume after restart; jobs that were running are marked
interrupted. Terminal jobs default to seven-day retention and a 1,000-record
cap. The database and service lease use owner-only permissions. One job runs at
a time by default; DTVP queues additional work. Synchronous assessments and
LLM-backed benchmark comparisons share the same execution semaphore, reserve a
bounded inline-admission slot before waiting, and return retryable HTTP 429
responses when global or per-owner capacity is exhausted.

`agentyzer/src/configuration.py` owns service, workspace, concurrency,
retention, and job-store defaults. Advisory prompt construction and manifest
discovery live in `pipeline/advisory_context.py`, leaving `pipeline/nodes.py`
focused on graph-state orchestration.

## Trust Boundary

Repositories, dependency metadata, advisories, web research, and model output
are untrusted inputs. Repository content can provide evidence to an analysis
but cannot override the service's task or security policy. Prompts and output
must not contain source-control credentials, provider API keys, DTVP sessions,
or unrelated tenant data.

All filesystem and historical Git-tree inputs used by dependency, version,
AST, and source analysis pass through the same bounded reader. It refuses
symlinks, non-regular files, paths outside the active worktree, individual
files over 1 MB, and repository-analysis reads beyond a 24 MB aggregate
budget. Reads remain byte-bounded if a file changes after it is opened.

All source, manifest, lockfile, and historical Git-blob reads go through the
same repository-input boundary. It rejects symlinks and non-regular files,
rechecks that opened files remain inside the checkout, and applies per-file and
per-operation byte limits before parsing or prompt construction. Files outside
those limits are ignored as unavailable evidence.

The service has its own API authentication and process/storage boundary. It
does not become the DTVP identity provider: DTVP authorizes end users and sends
only the scoped work that the service needs. LLM and source-control credentials
are service credentials with the narrowest practical scope and rotation
independent of DTVP user sessions.

The packaged container uses a checksum-pinned Python 3.14 Alpine runtime,
copies a separately pinned `uv` binary, installs Git as its only added system
package, and resolves the locked production environment during the build. It
runs as the dedicated non-root UID/GID `10001:10001`.

The checked-in code-analysis OpenAPI document is generated from the live
FastAPI application and verified in the Agentyzer CI job. Agentyzer tests and
their independent coverage ratchet are owned by that job; the root backend
suite covers only `dtvp/`.

## Related Concepts

- [Backend architecture](backend.md)
- [Integration API surface](../integration-api-surface.md)
- [Runtime configuration](../configuration.md)
- [Threat model](../threat-model.md)
