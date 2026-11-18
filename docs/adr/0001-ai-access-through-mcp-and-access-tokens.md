# ADR 0001: AI access through MCP and personal access tokens

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-17, repository owner) |
| Implementation status | Implemented (2026-11-17); see [AI and API access](../ai-access.md) |
| Related | [ADR 0002](0002-local-first-database-with-import-and-export.md) |

## Context

AI agents should be able to read vulnerabilities and improve assessments.
Today DTVP authenticates only browser sessions through an OIDC session cookie,
so no machine client can connect. The assessment save rules (SSVC permission,
analyzer-result eligibility, SSVC preservation, revision conflicts) live inline
in the `POST /api/assessment` route handler, and vulnerability reads go through
process-local grouped tasks built for the browser.

## Drivers

- One set of business rules for the browser, the REST API, and AI agents.
- AI output is untrusted input: a human must stay accountable for every
  approved decision.
- Every AI change must be attributable and auditable.
- Small operational footprint: no additional service or identity provider.

## Decision

1. **Shared application services.** Assessment read and write use cases move
   out of the route handlers into an application service layer. REST routes and
   MCP tools are thin callers of the same functions.
2. **MCP server inside the backend.** DTVP exposes an MCP endpoint over
   Streamable HTTP at `/mcp` (below `DTVP_CONTEXT_PATH`), built with the
   official `mcp` Python SDK.
3. **Personal access tokens.** Users create tokens in Settings. Tokens are
   stored hashed, belong to one user, carry `read` and `write` scopes, always
   expire, and can be revoked. They are accepted as `Authorization: Bearer` on
   `/mcp` and on the existing `/api`.
4. **Direct writes, always pending review.** An AI client writes team
   assessment blocks directly. Every such write is marked pending review and
   records provenance as the token's user acting through the named token.
5. **Write limits for token clients.** Writes use analyst authority whatever
   the owner's role: no General assessment, no approval, no CVSS or SSVC
   change, no `force`. The expected revision of every finding is mandatory, so
   stale edits are rejected instead of overwriting newer work.
6. **Audit log.** Every token-authenticated write attempt is recorded with
   user, token, target findings, outcome, and resulting revisions.

Refinements made during implementation (2026-11-17):

- **Tokens are read-only on `/api`.** The REST routes carry the full authority
  of the user's role, so a token there could have approved or changed
  settings. All machine writes therefore go through the MCP tools. This
  narrows point 3; widening it later needs per-route write rules.
- **The token name identifies the agent.** A stateless MCP request carries no
  trustworthy client identity, and a tool argument could be set freely by the
  agent. The user-chosen token name is the provenance label.
- **Opt-in.** `DTVP_ACCESS_TOKENS_ENABLED` defaults to `false`; it gates token
  creation, bearer authentication, and the MCP endpoint together.
- **Stateless transport.** The endpoint keeps no MCP session, so there is no
  session to hijack and nothing to lose on restart of the single backend
  process.
- **Independent review (2026-11-17)** found that a save could be based on a
  live task snapshot that `POST /api/assessments/details` lets a caller
  repaint, carrying another finding's General block, review marker, and
  suppression onto the target. Fixed three ways: that route is not available
  to tokens, the snapshot refresh ignores a finding UUID whose
  project/component/vulnerability identity disagrees, and saves build on the
  stored assessment only. The same review led to rejecting unclosed reserved
  tags, sanitising hyphen runs in token names, answering non-`POST` requests
  with 405, saving all findings in one transaction, never forwarding an
  access token to Dependency-Track however the header is spaced, and dropping
  team groups from the rules resource.
- **Read helpers stay in `general_api_routes.py`.** The grouped-task machinery
  lives there; MCP calls its public functions instead of duplicating it.
  Moving that machinery into a service module is left to the storage work in
  ADR 0002, which changes how reads are served anyway.

Planned tools: `list_projects`, `search_vulnerabilities`, `get_vulnerability`,
`get_dependency_chains`, `get_sync_status`, `preview_assessment`,
`save_assessment`. The assessment model, rescore rules, and team mapping are
exposed as MCP resources.

## Alternatives considered

- **Separate proposal store applied by a human** (as with code-analysis
  proposals). Safer by construction, but adds a second store and a UI step.
  Rejected: the existing pending-review state already keeps a human in the
  approval path.
- **OAuth 2.1 against the OIDC provider.** The route the MCP specification
  prefers for remote clients. Deferred: it depends on provider capabilities
  and is not needed for a first version. Tokens do not block adding it later.
- **REST only, no MCP.** Rejected: agents would need custom glue per client.
  Bearer tokens on `/api` still provide this for non-MCP clients.
- **Standalone MCP process.** Rejected: it would need its own access to the
  local state and duplicate wiring.

## Consequences

- A leaked token grants its user's access until revoked; tokens need expiry,
  revocation, last-used display, and must never be logged.
- AI-written text reaches reviewers and Dependency-Track; it is validated like
  any other assessment input and never interpreted as instructions or markup.
- The route refactoring precedes any MCP work and must not change behaviour.
- A new runtime dependency (`mcp`) must work on the free-threaded Python 3.14
  image. Checked 2026-11-17: `mcp` 2.3.0 imports and builds a Streamable HTTP
  app on CPython 3.14.3 (GIL build), and its native dependencies
  (`pydantic-core`, `rpds-py`, `cryptography`, `cffi`) publish `cp314t` wheels.
  The backend test suite (815 tests) also passed on free-threaded CPython
  3.14.10 (musl, `ghcr.io/astral-sh/uv:alpine`, the published image's base)
  with `sys._is_gil_enabled()` false after importing `mcp` and its native
  dependencies. A live client run was done on CPython 3.15.0 (GIL build)
  only. Use the 2.x API (`mcp.server.mcpserver.MCPServer`); the 1.x `FastMCP`
  name is gone.

## Confirmation

- REST and MCP saves of the same input produce identical stored assessments.
- Tests show that a token client cannot approve, change SSVC, force a save, or
  write with a stale revision, and that a `read` token cannot write.
- Every MCP write appears in the audit log and shows as pending review in the UI.

Checked 2026-11-17: the first two points are covered by
`tests/test_assessment_use_cases.py`, `tests/test_access_tokens.py`, and
`tests/test_mcp_server.py` (both entry points call the same `save_assessment`
function). The audit entry was confirmed in the UI after a live MCP save; the
pending-review marker was confirmed in the stored text, not visually on a
vulnerability card.
