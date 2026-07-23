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
review_when:
  - The project purpose, top-level repository structure, runtime services, or documentation hierarchy changes.
---

# DTVP Project Overview

DTVP is a FastAPI and Vue application for reviewing Dependency-Track findings
across every version of a project. It groups findings by vulnerability, exposes
version-by-version assessment state, and lets reviewers apply consistent
changes without repeating the same work for every release.

The vulnerability-backend boundary is capability-based: Dependency-Track is
the current provider, while Cybeats and other vendors can be added without
making their resource identifiers or credentials part of the domain model.
TMRescore and code analysis are optional integrations.

## Repository Map

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | FastAPI routes, services, domain logic, runtime wiring, and integrations |
| `agentyzer/` | Bundled code-analysis service and assessment pipeline |
| `frontend/` | Vue 3, Vite, and Tailwind single-page application |
| `test_setup/` | Mock Dependency-Track, tmrescore, and code-analysis services |
| `tests/` | Backend pytest suite |
| `data/` | Local configuration, cache data, mappings, rules, and archives |
| `dtvp/migrations/` | Numbered SQLite migrations for local stores |
| `openapi/` | Static OpenAPI specs for optional integrations |
| `docs/` | OKF project-knowledge bundle, security model, workflows, and screen guide |
| `skills/` | Project-local AI entry points that route to this bundle |

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
durable state.

## Knowledge Map

- [Backend architecture](architecture/backend.md)
- [Frontend architecture](architecture/frontend.md)
- [Agentyzer architecture](architecture/agentyzer.md)
- [External integration contracts](integration-api-surface.md)
- [Runtime configuration reference](configuration.md)
- [Threat model and residual risks](threat-model.md)
- [Runtime workflow diagrams](workflow-flowcharts.md)
- [Human quick start and command reference](../README.md)
