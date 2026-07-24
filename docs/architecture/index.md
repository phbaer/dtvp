# DTVP Architecture

The runtime is split into three first-party components:

- [Backend](backend.md) — FastAPI composition, domain services, durable state,
  external vulnerability-backend adapters, and optional integrations.
- [Frontend](frontend.md) — Vue application, task-window clients, local state,
  and reviewer workflows.
- [Agentyzer](agentyzer.md) — isolated code-analysis service, persistent
  repository workspaces, and asynchronous assessment jobs.

Use the [project overview](../project.md) for repository and deployment context,
the [integration contracts](../integration-api-surface.md) for external HTTP
boundaries, and the [threat model](../threat-model.md) for security decisions.
