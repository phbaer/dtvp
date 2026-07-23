---
type: Component
title: DTVP Frontend Architecture
description: Vue application structure, task-window data flow, state ownership, and security boundary.
tags:
  - frontend
  - vue
  - architecture
source_paths:
  - frontend/src/
  - frontend/package.json
  - frontend/vitest.config.ts
  - frontend/nginx.conf
review_when:
  - Frontend routing, shared state, API contracts, rendering strategy, authentication UX, or build/runtime topology changes.
---

# DTVP Frontend Architecture

The frontend is a Vue 3 single-page application built by Vite and styled with
Tailwind. Vite serves it in development; packaged deployments serve the built
assets behind the application gateway. The frontend presents authenticated
review workflows but is not an authorization boundary.

## Components

| Component | Role |
| :--- | :--- |
| `frontend/src/main.ts`, `App.vue`, `router.ts` | App shell, routing, authentication, and startup handling |
| `frontend/src/lib/api.ts` and `types.ts` | Backend client and shared integration/domain types |
| `frontend/src/pages/` | Dashboard, project review, statistics, settings, TMRescore, and code analysis |
| `frontend/src/components/` | Vulnerability rows/details, filters, dialogs, queue UI, CVSS, and dependency paths |
| `frontend/src/lib/` | Filter/task-window models, composables, caching, updates, and project state |

## Runtime Behavior

The project review consumes backend summary windows rather than loading every
full grouped vulnerability into the DOM. It viewport-windows list rows,
coalesces partial task refreshes, and hydrates dependency paths and complete
assessment details only when needed. Local models and composables coordinate
filters, task progress, project state, cache invalidation, and write results.

Authentication and startup handling live in the app shell. Page and control
visibility guide users, but every protected read or mutation is authorized by
the backend. In particular, reviewer-only controls must remain protected even
when a client calls the API directly.

Shared domain and integration types belong in `frontend/src/lib/types.ts`;
HTTP behavior belongs in `frontend/src/lib/api.ts`. Pages orchestrate workflows,
while reusable presentation and focused interaction logic belong in
components/composables.

## Related Concepts

- [Backend architecture](backend.md)
- [Screen guide](../screens.md)
- [Workflow diagrams](../workflow-flowcharts.md)
- [Threat model](../threat-model.md)

