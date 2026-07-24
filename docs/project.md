---
type: Project
title: DTVP Project Overview
description: Purpose, repository structure, runtime shape, and knowledge map for DTVP.
tags:
  - project
  - repository
  - vulnerability-management
source_paths:
  - README.md
  - pyproject.toml
  - frontend/package.json
  - compose.yml
  - deploy/arcane/compose.yml
  - threatmodel/dtvp.py
  - demo/dependency-track/compose.yml
  - demo/dependency-track/ecosystem.config.js
review_when:
  - The project purpose, top-level repository structure, runtime services, or documentation hierarchy changes.
---

# DTVP Project Overview

DTVP is a FastAPI and Vue application for reviewing vulnerability findings
across every version of a project. It groups findings by vulnerability, exposes
version-by-version assessment state, and lets reviewers apply consistent
changes without repeating the same work for every release.

The vulnerability-backend boundary is capability-based: Dependency-Track is
the first adapter, while Cybeats and other vendors can be added without making
their resource identifiers or credentials part of the domain model. Backends
are independently operated source systems; they are not DTVP services or state.
TMRescore and code analysis are optional integrations.

## Repository Map

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | FastAPI routes, services, domain logic, runtime wiring, and integrations |
| `agentyzer/` | Bundled code-analysis service and assessment pipeline |
| `frontend/` | Vue 3, Vite, and Tailwind single-page application |
| `test_setup/` | Mock Dependency-Track, tmrescore, and code-analysis services |
| `demo/dependency-track/` | Optional, isolated Dependency-Track demonstration deployment and local mock runtime |
| `deploy/arcane/` | Image-only Arcane project for manual or Git-managed deployment |
| `threatmodel/` | Executable OWASP pytm model and findings-report template for DTVP and Agentyzer |
| `tests/` | Backend pytest suite |
| `data/` | Local configuration, cache data, mappings, rules, and archives |
| `dtvp/migrations/` | Numbered SQLite migrations for local stores |
| `openapi/` | Static OpenAPI specs for optional integrations |
| `docs/` | OKF project-knowledge bundle, security model, workflows, and screen guide |
| `skills/` | Project-local AI entry points that route to this bundle |
| `Dockerfile.backup`, `scripts/backup-compose-state*` | Verified manual and optional Compose-native scheduled backup tooling |

The generic project skill is `skills/project-entrypoint/SKILL.md`;
`skills/dtvp-project-memory/SKILL.md` is the compatibility entry point.

## Runtime Shape

```text
Browser
  -> Vue SPA (Vite in development, FastAPI/nginx in production)
  -> FastAPI backend
  -> vulnerability-backend adapter + backend-scoped local cache
     -> Dependency-Track today; capability contract for Cybeats/other vendors
  -> optional tmrescore and code-analysis services
```

The supported deployment uses one DTVP API process per state volume and one
Agentyzer process per repository volume. Horizontal scaling requires shared
coordination and task/result storage before multiple API workers use the same
durable state. Default Compose deploys no vulnerability backend or backend
database; operators select an adapter and connect DTVP to an external source.

The optional Compose `backup` profile runs a single interval scheduler. It
briefly pauses DTVP, archives `./data`, verifies the archive, records checksums,
and updates the DTVP backup-freshness marker. Backend state is outside this
boundary, and the Agentyzer repository/job volume is a disposable cache.
Because that coordination uses the Docker Engine socket, the scheduler is an
explicitly privileged operator component and is not enabled by default.

The Arcane deployment is a separate image-only topology. It publishes DTVP
directly, stores DTVP state in an Arcane-managed named volume, and keeps
Agentyzer clones/jobs in a second disposable volume. Its Compose project can be
pasted manually or synced from Git; Arcane owns the deployment `.env`, while
the repository owns the service-specific non-secret environment files.

## Knowledge Map

- [Backend architecture](architecture/backend.md)
- [Frontend architecture](architecture/frontend.md)
- [Agentyzer architecture](architecture/agentyzer.md)
- [External integration contracts](integration-api-surface.md)
- [Runtime configuration reference](configuration.md)
- [Threat model and residual risks](threat-model.md)
- [Runtime workflow diagrams](workflow-flowcharts.md)
- [Human quick start and command reference](../README.md)
