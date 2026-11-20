# ADR 0006: Agent code evidence is applied by a person

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Proposed (2026-11-20) |
| Implementation status | Implemented on branch `feat/code-evidence-mcp` (2026-11-20), not merged; see [AI and API access](../ai-access.md#code-evidence) and [Analysis integrations](../analysis-integrations.md#agent-code-evidence) |
| Related | [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md), [ADR 0002](0002-local-first-database-with-import-and-export.md) |
| Numbering | 0005, because `feat/vdr-recommendation` holds 0004 (ADR 0004: the VDR recommendation comes from the ranges Dependency-Track holds). The sync and backup designs are drafting ADRs at the same time: whichever merges later takes the next free number |

## Context

Code evidence on the **Code Evidence** tab comes only from the code analyzer
(Agentyzer). Users want AI agents connected through MCP to add code evidence
too, and found the tab hard to read and operate.

The repository owner decided (2026-11-20):

- the evidence text may be Markdown;
- adding evidence through MCP requires the analyst role, and MCP agents can
  never approve assessments;
- external evidence never changes an assessment by itself: a person applies
  it.

[ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md) lets an agent
write a team assessment directly, marked pending review, and records every
write in the token audit log. It rejected a separate proposal store for
*assessments*, because pending review already keeps a person in the approval
path.

## Drivers

- Evidence is information, not a decision: it must not reach Dependency-Track
  or a review queue without a person choosing to use it.
- Every entry must say who wrote it, through which token, when, and for which
  findings, and keep that after it is withdrawn.
- Agentyzer runs and agent entries should be read in one place.
- Retention and cleanup of analyzer data must not remove agent evidence.

## Alternatives considered

- **Let the agent write a team draft with `save_assessment`.** It already
  exists. Rejected for evidence: the draft *is* an assessment (it changes the
  revision, queues an export, and shows as pending review), which contradicts
  the owner's decision.
- **A new store in the main database (`DTVP_DATABASE_PATH`).** Keeps all
  records in one file. Rejected for now: evidence is read with the analyzer
  results on the same tab and has the same lifecycle (it is evidence for an
  assessment, not the assessment), and the main database's record tables
  follow ADR 0003 rules that do not apply here.
- **Extend the analyzer result payload** (store agent evidence as a fake
  analyzer run). Rejected: the analyzer's retention and cleanup would delete
  it, the payload schema belongs to Agentyzer, and the provenance (token,
  agent label, authority) has no place in it.

## Decision

1. **A separate evidence store beside the analyzer results.** New tables
   `code_evidence`, `code_evidence_vuln_ids`, and
   `code_evidence_applications` in the analyzer result database
   (`DTVP_CODE_ANALYSIS_RESULTS_PATH`), added by migration
   `code_analysis_results/0004_code_evidence.sql`.
   `dtvp/code_evidence_services.py` owns the store and the validation shared
   by MCP and REST. Analyzer retention and cleanup do not touch these tables.
2. **MCP tools.** `add_code_evidence` (the `write` scope; analyst authority
   whatever the owner's role) and `list_code_evidence` (the `read` scope).
   Targets are resolved against DTVP's own view of the vulnerability. Every
   add is audited; the body is never written to the audit.
3. **Applied by a person.** The UI shows agent entries and analyzer runs in
   one list. **Use in assessment draft** adds a one-line plain-text reference
   (never the Markdown body) to the draft, and optionally the suggested state.
   Nothing is saved until the person saves the assessment, with the usual
   review rules. The save sends the `code_evidence_ids` whose reference line
   is still in the saved text; the server checks them before writing and
   records an application per finding afterwards.
4. **Withdrawal is a soft delete.** A reviewer or the author withdraws an
   entry with a reason; it is then hidden by default and cannot be applied.

## Consequences

- The [backup design](README.md) must include the three new tables of the
  analyzer result database; they are records written by people's tokens, not
  rebuildable data.
- No CycloneDX impact: evidence is not exported. The exported assessment
  contains only the reference text a person chose to keep.
- The analyzer result database now holds records that its retention settings
  do not govern; `docs/configuration.md` says so.
- Agents can add up to 100 active entries per project and vulnerability;
  more requires withdrawing entries.

## Confirmation

- `tests/test_mcp_server.py`: evidence is added with the user, token ID,
  agent label, and `ANALYST` (also through a reviewer's token); a read token
  is refused; unknown components or findings are rejected and audited;
  revisions, stored assessments, and the export queue are unchanged after an
  add; `list_code_evidence` returns both kinds and pages.
- `tests/test_code_evidence_services.py`: migration, idempotency, limits,
  withdrawal, and that analyzer retention and cleanup leave evidence alone.
- `tests/test_assessment_use_cases.py`: unknown, withdrawn, and foreign
  evidence IDs are rejected before the write; applications are recorded
  after it.
- `tests/test_code_analysis.py`: the list and withdraw routes, including
  403 for another analyst and for a bearer token.
- Front-end unit tests and `frontend/e2e/code-evidence.spec.ts`: one list, a
  reader with sanitised Markdown, a separate apply box, and the "Used in
  assessment" marker after a save.
