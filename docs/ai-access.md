# AI And API Access

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0001](adr/0001-ai-access-through-mcp-and-access-tokens.md) |
| Verified | 2026-11-17 against `tests/test_access_tokens.py`, `tests/test_mcp_server.py`, a live run with the `mcp` 2.3.0 client against the mock Dependency-Track, and the backend test suite on free-threaded CPython 3.14.10 (musl). Code evidence (`add_code_evidence`, `list_code_evidence`): 2026-11-20 against `tests/test_mcp_server.py` and `tests/test_code_evidence_services.py` only, not yet with a live MCP client |
| Code evidence decision | [ADR 0006](adr/0006-agent-code-evidence-is-applied-by-a-person.md) (proposed) |

AI agents and scripts connect with a personal access token. They can read
through the REST API and, through an MCP endpoint, read, draft team
assessments, and add code evidence. The feature is off by default.

- [Enable It](#enable-it)
- [Create A Token](#create-a-token)
- [Connect An MCP Client](#connect-an-mcp-client)
- [MCP Tools](#mcp-tools)
- [Code Evidence](#code-evidence)
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
# Token digests, the token audit log and browser session versions are kept
# in the local database (DTVP_DATABASE_PATH). Set this only to keep them in a
# separate file, and back that file up with the database.
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
3. Tick **Allow writing: team assessment drafts and code evidence** only if
   the client should write (the `write` scope).
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
| `get_vulnerability` | read | Description, scores, every finding with its revision and responsible teams (and `new_finding` when it was added after the assessment), dependency paths, exploitation evidence, and the current team assessments with the finding's [response](assessment-model.md#response). Agents cannot set the response; their saves keep it |
| `get_sync_status` | read | Local changes waiting for export, how many exports keep failing, and the time of the last import |
| `preview_assessment` | read | The assessment `save_assessment` would store, without saving, plus the revisions to pass on |
| `save_assessment` | write | Record one team's assessment for every finding of a vulnerability |
| `add_code_evidence` | write | Record what the agent found in the code (Markdown) for a vulnerability, some of its components, or some of its findings. Changes no assessment; see [Code Evidence](#code-evidence) |
| `list_code_evidence` | read | The code evidence of a vulnerability, newest first: entries agents added (`kind: "agent"`) and code-analyzer runs (`kind: "analyzer"`, report cut to 8,000 characters with `report_truncated`); at most 50 items per call. Like the evidence list in the UI it leaves out benchmark-derived records |

`get_vulnerability` also returns `code_evidence: {"agent": n, "analyzer": m}`,
the number of active agent entries and analyzer runs (without benchmark-derived
records) for the vulnerability.

The resource `dtvp://assessment-rules` returns the valid states, the team
mapping, and the CVSS rescoring rules in force. Team groups are reviewer-only
in the REST API and are not included.

A vulnerability is addressed by project name and its ID or an alias. The first
read of a project builds the same grouped snapshot the web UI uses and may take
a while on a large project; the tool reports progress and asks the client to
retry if it exceeds two minutes.

## Code Evidence

`add_code_evidence` stores evidence beside the code-analyzer results (see
[Analysis integrations](analysis-integrations.md#agent-code-evidence)). It is
**never an assessment**: adding it changes no assessment, revision, export
queue entry, or SSVC record. A person opens it on the **Code Evidence** tab
and chooses **Use in assessment draft**, which adds a one-line reference to
the draft; the assessment is saved, and reviewed, as usual. The save records
which evidence it used.

Arguments: `project`, `vulnerability_id` (ID or alias), `title`,
`body_markdown`, and optionally `components`, `finding_uuids`, `references`,
`suggested_state`, `suggested_justification`, `confidence`, and
`idempotency_key`.

**Scope.** The findings are resolved against DTVP's own view of the
vulnerability, never taken from the caller:

- `finding_uuids`: exactly those findings (scope `findings`);
- otherwise `components`: every finding of those component names, matched
  case-insensitively (scope `components`);
- neither: every finding of the vulnerability (scope `vulnerability`).

An unknown finding or component is rejected with the list of valid ones.

**Recorded with each entry:** the user, the token ID, the agent label (the
token name, reduced as for assessments), the authority `ANALYST` whatever the
owner's role, the time (UTC), the project, the vulnerability ID and its
aliases, and each finding with component name, version, purl, and project
version.

**Limits:**

| Field | Limit |
| :--- | :--- |
| `title` | 1 to 160 characters on one line; control characters become spaces. It must not contain `---` or the start of a reserved tag such as `[Team:`, because it is the part a person copies into an assessment |
| `body_markdown` | 1 to 20,000 characters of Markdown; NUL and control characters other than newline and tab are removed. The UI renders it through an allow-list sanitiser: no images, scripts, frames, or raw HTML; only `http(s)` links without a user name or password |
| `references` | Up to 20, each one line of up to 300 characters. The UI links only `http(s)` URLs |
| `suggested_state` | One of the analysis states, or omitted |
| `suggested_justification` | A Dependency-Track justification such as `CODE_NOT_REACHABLE`, only with `NOT_AFFECTED` |
| `confidence` | `low`, `medium`, or `high` |
| `idempotency_key` | Up to 100 characters |
| Active entries | At most 100 per project and vulnerability; withdraw entries first |

**Idempotency.** A call with the same token and `idempotency_key` as an
earlier one, and the same project, vulnerability, targets and content, returns
the earlier entry with `created: false` instead of adding a second one. The
same key with a different project, vulnerability, targets, title, body,
references or suggestion is rejected ("idempotency_key already used for
different evidence") and audited as rejected; use a new key for new evidence.
Another token with the same key adds a new entry.

**Withdrawing.** A reviewer, or the user whose token wrote an entry, can
withdraw it in the UI with a reason. Withdrawn entries are hidden by default,
cannot be used in an assessment, and keep their provenance.
`list_code_evidence` returns them with `include_withdrawn: true`.

## What A Token Can And Cannot Do

A token acts as its owner. Code evidence follows the rules in
[Code Evidence](#code-evidence). Every assessment write has these limits:

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

Revisions count every value saved in DTVP, so a save based on a value that
has since been replaced is rejected. Dependency-Track never changes an
assessment in DTVP; `sync_status` only tells whether Dependency-Track holds
the value yet. See [Import and export](import-export.md).

## REST API With A Token

The same `Authorization: Bearer` header works on `/api` for **reading**.
Clients built for API keys can send the token as `X-Api-Key: <token>`
instead; it is the same token with the same limits. The MCP endpoint accepts
the `Authorization` header only. On `/api`:
every `GET` endpoint, plus `POST /api/tasks/group-vulns`, which starts or
joins a project snapshot, and the code evidence list
`GET /api/projects/{project}/vulnerabilities/{id}/code-evidence`. All other
requests are refused with 403, whatever the token's scopes, including
`POST /api/code-evidence/{id}/withdraw`. That includes `POST /api/assessments/details`, which
refreshes the shared snapshots. Machine clients change
assessments through the MCP tools, where the rules above apply.

## Audit

Every attempted `save_assessment` that reaches the write checks is recorded
with time, user, token, target, outcome (`success`, `conflict`, `rejected`,
`error`), and resulting revisions. Every `add_code_evidence` call that found
the vulnerability is recorded as action `add_code_evidence` with outcome
`success`, `rejected`, or `error`; the target holds the project, the
vulnerability, the evidence ID, and the finding UUIDs. The evidence text is
never written to the audit log. **Settings → Access Tokens** lists recent
entries: reviewers see all users, everyone else their own.
`GET /api/settings/tokens/audit` returns the same data to a browser session.
