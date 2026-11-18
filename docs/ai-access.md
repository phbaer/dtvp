# AI And API Access

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0001](adr/0001-ai-access-through-mcp-and-access-tokens.md) |
| Verified | 2026-11-17 against `tests/test_access_tokens.py`, `tests/test_mcp_server.py`, a live run with the `mcp` 2.3.0 client against the mock Dependency-Track, and the backend test suite on free-threaded CPython 3.14.10 (musl) |

AI agents and scripts connect with a personal access token. They can read
through the REST API and read or draft team assessments through an MCP
endpoint. The feature is off by default.

- [Enable It](#enable-it)
- [Create A Token](#create-a-token)
- [Connect An MCP Client](#connect-an-mcp-client)
- [MCP Tools](#mcp-tools)
- [What A Token Can And Cannot Do](#what-a-token-can-and-cannot-do)
- [REST API With A Token](#rest-api-with-a-token)
- [Audit](#audit)

## Enable It

Set `DTVP_ACCESS_TOKENS_ENABLED=true` and restart the backend. While it is
off, tokens are rejected, none can be created, and the MCP endpoint answers
404. The local development stack (`ecosystem.config.js`) enables it.

Lines to add to `.env` (and to `.env.dist` as the documented template):

```dotenv
# Personal access tokens and the MCP endpoint for AI agents and scripts.
# Off by default. See docs/ai-access.md.
DTVP_ACCESS_TOKENS_ENABLED=false
# Token digests and the token audit log are kept in the local database
# (DTVP_DATABASE_PATH). Set this only to keep them in a separate file.
# DTVP_ACCESS_TOKENS_PATH=
```

Compose passes `.env` to the backend, so no change to `compose.yml` is
needed. See [Configuration](configuration.md#access-tokens-and-mcp) for the
reference.

## Create A Token

Open **Settings → Access Tokens**. Every user can open this tab; the other
Settings tabs remain reviewer-only.

1. Name the token after the client that will use it. The name appears next to
   your user name on every assessment written with it.
2. Choose how long it stays valid (1 to 365 days, 90 by default).
3. Tick **Allow drafting team assessments** only if the client should write.
4. Copy the token. It is shown once; DTVP stores only a SHA-256 digest.

Revoke a token in the same list. Revocation takes effect on the next request.
Each user can hold 20 active tokens.

## Connect An MCP Client

The endpoint is `<DTVP base URL>/mcp` (the Settings tab shows the exact URL),
using MCP Streamable HTTP. Send the token on every request:

```text
Authorization: Bearer dtvp_pat_...
```

The endpoint is stateless and returns JSON responses: it keeps no server-side
session, so a backend restart does not disconnect a client. It accepts `POST`
only; `GET` and `DELETE` answer 405 because there is no stream to open and no
session to end. A reverse proxy needs no special handling beyond forwarding
the path and the header.

Example for Claude Code:

```bash
claude mcp add --transport http dtvp https://dtvp.example.com/dtvp/mcp \
  --header "Authorization: Bearer $DTVP_TOKEN"
```

## MCP Tools

| Tool | Scope | Purpose |
| :--- | :--- | :--- |
| `list_projects` | read | Projects and their versions |
| `search_vulnerabilities` | read | Filter one project's vulnerabilities by text, lifecycle, team, severity, or analysis state; at most 100 rows per call. `new_findings` counts the [findings added after the assessment](review-workflows.md#new-findings) |
| `get_vulnerability` | read | Description, scores, every finding with its revision and responsible teams (and `new_finding` when it was added after the assessment), dependency paths, exploitation evidence, and the current team assessments |
| `get_sync_status` | read | Local changes waiting for export, how many of them conflict with a change in Dependency-Track, and the time of the last import |
| `preview_assessment` | read | The assessment `save_assessment` would store, without saving, plus the revisions to pass on |
| `save_assessment` | write | Record one team's assessment for every finding of a vulnerability |

The resource `dtvp://assessment-rules` returns the valid states, the team
mapping, and the CVSS rescoring rules in force. Team groups are reviewer-only
in the REST API and are not included.

A vulnerability is addressed by project name and its ID or an alias. The first
read of a project builds the same grouped snapshot the web UI uses and may take
a while on a large project; the tool reports progress and asks the client to
retry if it exceeds two minutes.

## What A Token Can And Cannot Do

A token acts as its owner, with these limits on every write:

- It writes **one team's block** and that team must be responsible for the
  vulnerability. The General assessment is reserved for human reviewers.
- The change is stored with analyst authority even when the owner is a
  reviewer: it is marked **pending review**, clears a previous review of that
  block, and cannot set a rescored CVSS value.
- It cannot change SSVC, approve, force a save, delete an assessment, or
  change whether a finding is suppressed.
- `save_assessment` requires the revision of **every** finding, as returned by
  `get_vulnerability` or `preview_assessment`. All findings are written in one
  transaction: if any changed since, nothing is saved and the client must
  read again.
- The existing blocks a save builds on come from DTVP's stored state for each
  finding, never from the caller or from the live task snapshot.
- The assessment text must be plain prose. Text containing `---` or the start
  of a reserved tag such as `[Team:` or `[Reviewed By` (closed or not) is
  rejected, so an agent cannot forge or break a block.
- The author is recorded as `user (via token name)`; the name is reduced to
  letters, digits, spaces, dots, underscores, and single hyphens.

A token cannot create, list, or revoke tokens, and is never forwarded to
Dependency-Track.

Revisions count every local value, including one adopted from
Dependency-Track on import, so a save based on a value that has since been
replaced is rejected. If an agent's draft and a change in Dependency-Track
collide, the finding becomes a conflict that a person resolves; a token
cannot. `get_vulnerability` reports it as `sync_status: diverged`. See
[Import and export](import-export.md).

## REST API With A Token

The same `Authorization: Bearer` header works on `/api` for **reading**:
every `GET` endpoint, plus `POST /api/tasks/group-vulns`, which starts or
joins a project snapshot. All other requests are refused with 403, whatever
the token's scopes. That includes `POST /api/assessments/details`, which
refreshes the shared snapshots. Machine clients change
assessments through the MCP tools, where the rules above apply.

## Audit

Every attempted `save_assessment` that reaches the write checks is recorded
with time, user, token, target, outcome (`success`, `conflict`, `rejected`,
`error`), and resulting revisions. **Settings → Access Tokens** lists recent
entries: reviewers see all users, everyone else their own.
`GET /api/settings/tokens/audit` returns the same data to a browser session.
