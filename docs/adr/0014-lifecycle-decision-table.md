# ADR 0014: One lifecycle decision table; a pending Global decision is ready for approval

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-25, repository owner): the pending-Global change; the decision table as the definition. Accepted (2026-11-26, repository owner): decisions 6 to 13, resolving the questions found while deriving the table, and decision 14, the Global decision |
| Implementation status | Implemented (2026-11-26): every decision, in the server and the web client, with shared cases for each |
| Related | [ADR 0010](0010-version-overrides.md) decision 3 (the lifecycle per scope; unchanged, the table states its combination). [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md): MCP reads the same lifecycle. The definition: [Lifecycle decision table](../assessment-model.md#lifecycle-decision-table) |

## Context

The lifecycle of a vulnerability (Open, Incomplete, Conflicting, Ready for
approval, Assessed) was defined by code comments and several overlapping
paragraphs in the README, the assessment model and the review workflows. The
names overlapped too: `NEEDS_APPROVAL` is a lifecycle value (Ready for
approval) and, as a status filter value, "any pending review" (Awaiting
review).

One rule was inconsistent with itself. An approved General decision covers
the teams that have no block of their own: the vulnerability is Assessed. The
same General decision pending review did not: the vulnerability was
Incomplete, although the reviewer's approval is the only thing left. The
Repair preview then said "<team> has not assessed this vulnerability yet;
nothing to copy … the global assessment is pending review, so no team can
refer to it", where the right advice is to approve it.

On production (2026-11-25, read-only, ViewPoint_Product), 35 of 538
Incomplete vulnerabilities were Incomplete only for this reason. They did show
under Awaiting review, through the pending flag.

## Drivers

- One definition that the server, the web client, the filters and counts,
  Bulk Changes, Repair and MCP all follow, with a case for every rule tested
  on both sides.
- A status says what is left to do and who does it.
- Approval is the reviewer's explicit act (ADR 0010 decision 6); nothing here
  changes who may approve or what approval writes.

## Alternatives

- **Keep Incomplete, change only the Repair message.** Rejected: the status
  would still send these vulnerabilities to analysts ("Needs my assessment")
  when only a reviewer can finish them.
- **A new lifecycle value (for example `AWAITING_GLOBAL_APPROVAL`).**
  Rejected: every consumer (filters, counts, MCP, saved links) would need it,
  and the reviewer's action is the same as for any Ready for approval
  vulnerability. The card and Repair name the difference instead.
- **Require every team block even with an approved General decision.**
  Rejected: it would reopen every vulnerability a reviewer closed globally.

## Decision

1. **The decision table in
   [assessment-model.md](../assessment-model.md#lifecycle-decision-table) is
   the definition** of the lifecycle, its inputs, the precedence of its rules,
   the flags beside it (`is_pending` = Awaiting review, `is_approval_ready` =
   Ready for approval) and the names of each state in the API, the filters
   and the UI. Other documents link to it instead of restating it.
2. **A pending General decision covers missing teams.** While a finding's text
   is pending review, a required team without a current block of its own no
   longer makes the vulnerability Incomplete when a current General block
   decides (a state other than `NOT_SET`). The vulnerability is
   `NEEDS_APPROVAL`, shown as Ready for approval, the same value and label as
   any other: the reviewer's action is the same. Approved, it is `ASSESSED`,
   as before.
3. A finding without a state still makes it Incomplete, pending or not, and
   so does a General block that is `NOT_SET` or absent.
4. The card's reviewer note **What completes it** and the Repair preview say
   "approve the Global assessment to complete it" for such vulnerabilities;
   the lifecycle tooltip says the same.
5. The grouped summary cache schema is bumped, so cached summaries are
   classified again.

Decided on 2026-11-26 (the former open questions; see
[Decided questions](#decided-questions)):

6. **Approve only when Ready for approval (Q2).** Approval is possible only
   when every required team has its own current assessment or is covered by
   a deciding General block, every finding has a state and the findings
   agree. The card offers Approve only then and otherwise says why; the
   server refuses any other approval with 422 (`approval_blocker`). A
   reviewer may still create the final Global assessment, which makes the
   vulnerability Ready for approval, and approve it without every team's own
   assessment.
7. **Coverage everywhere (Q5).** A recorded General decision (pending or
   approved) counts as the decision of every team without a block of its
   own, in the lifecycle (approved: Assessed; pending: Ready for approval),
   the team counters, the **Assessment for selected teams** filter and the
   Repair messages alike: one flag, `list_metadata.covers_all_teams`.
8. **The catch-all team is not special (Q6).** The `*` team is a required
   team, and a General decision covers it like any other. Repair names it
   when nothing covers it, never writes a reference block for it, and
   removes a reference under its name only while a General decision covers
   it.
9. **Legacy text is no block (Q1).** The web client's lifecycle reads only
   blocks under team headers, as the server does.
10. **Lifecycle values in MCP (Q4).** `search_vulnerabilities` documents
    `READY_FOR_APPROVAL` and `awaiting_review`; as a filter value
    `NEEDS_APPROVAL` is deprecated (it means awaiting review).
11. **Pending with nothing decided is Open (Q7).**
12. **One marker test (Q9).** The pending marker counts outside the SSVC
    details, on both sides (`has_pending_review_marker`,
    `hasPendingReviewMarker`).
13. **Cleanups (Q8, Q10).** The unused `_has_open_team_assessment` and
    `hasOpenTeamAssessment` are removed; the client's `matchesFilters` uses
    `getGroupLifecycle`. Repair's former-team and combine labels use the
    approval wording. The grouped summary schema is 16.

Q3 (pending review belongs to the whole text) is accepted as it is.

Decided on 2026-11-26 as well ("the global decision should by default
always be the worst of all existing assessments; we should point to it
explicitly; the reviewer can define it differently by hand"):

14. **The Global decision is the worst team decision unless a reviewer set
    it.** The effective Global decision is the reviewer's General block when
    it decides (manual); otherwise it is derived: the worst state among the
    current team blocks that decide, in the one order DTVP uses for every
    "worst" (Exploitable > In triage > False positive > Not affected >
    Resolved), with every team of that state named and the justification of
    the first of them. `list_metadata` and MCP carry its source, state and
    teams; the team overview, the state chip and the approval note point to
    it; an approval without a General block records it as the General
    block, in the card and on the server. The exported analysis state was
    already this decision (`calculate_aggregated_state` now calls the same
    function); the exported justification is not derived (DTVP exports
    none), which stays as it is.

PR #355, rebased under this ADR, added rule R10 (a team's block on some
assessed findings and not on others is Incomplete) and narrowed
`TEAM_ASSESSMENT_MISMATCH`; the table states both.

## Consequences

- These vulnerabilities move from Incomplete to Ready for approval: they leave
  the analysts' default (Open and Incomplete) and "Needs my assessment", and
  the reviewers' Ready for approval chip counts them. Awaiting review lists
  them as before.
- Repair lists them with the approval advice and nothing to write; its
  Synchronize stage, which handles Incomplete vulnerabilities only, no longer
  touches them (there was nothing to synchronize).
- Team counters and the **Assessment for selected teams** filter count the
  covered teams as assessed (decision 7). A team selected with Not recorded
  no longer finds a vulnerability a General decision covers.
- Approve disappears from pending vulnerabilities that are not Ready for
  approval, for example a new version's finding without a state; Synchronize
  or a Global decision comes first (decision 6).
- A pending placeholder without any decision moves from Incomplete to Open
  (decision 11).

## Confirmation

- `frontend/src/lib/__tests__/fixtures/lifecycle_cases.json` has a case for
  every rule; `tests/test_lifecycle_decision_table.py` and
  `frontend/src/lib/__tests__/lifecycleCases.spec.ts` pass on it, including
  the anonymised production shape (pending General, one team with an empty
  block → `NEEDS_APPROVAL`; the same approved → `ASSESSED`; a `NOT_SET`
  General → `INCOMPLETE`; a finding without a state → `INCOMPLETE`).
- Filters and counts select it as Ready for approval and Awaiting review, not
  Incomplete (`test_filters_facets_and_awaiting_review_follow_the_lifecycle`).
- Repair's preview gives the approval advice and treats the catch-all team
  like any team (`tests/test_repair_open_teams.py`).
- Every shared case also states `covers_all_teams` and whether Approve is
  possible; the server's `approval_blocker` and the card's
  `getApprovalUnavailableReason` agree with it, and the use case refuses an
  approval of an Incomplete vulnerability
  (`tests/test_assessment_use_cases.py`).

## Decided questions

Found while deriving the table from the code (origin/main 4ee2c95a), decided
on 2026-11-26 by the repository owner. The table keeps the finding and the
recommendation that was given; the last column says what was decided. Rule numbers are those of 2026-11-25; decision 11 inserted the new R2, so R2-R9 there are R3-R10 now.

| # | Where the code disagreed or was unclear | Recommendation | Decided |
| :--- | :--- | :--- | :--- |
| Q1 | **Legacy with several findings.** The server reads plain text without blocks as no block (R6, `ASSESSED_LEGACY`). The web client's parser makes one General `NOT_SET` block per finding, so its legacy test (`blocks.length === 1`) holds for one finding only; with two or more the card says Incomplete (with required teams) or Assessed while the list says Assessed (Legacy). | Make the client's lifecycle summary ignore the synthetic General block, as the server does, and add the two-finding case to the shared cases. | As recommended (decision 9); a two-finding case is shared |
| Q2 | **Approve on an Incomplete vulnerability.** The card offers Approve whenever the text is pending (`canApprove`), and approving saves a Global decision filled from the team assessments. An R3 (now R4) Incomplete vulnerability (team missing, no General decision) therefore becomes Assessed in one click, which the table calls Incomplete. | Decide whether Approve is meant for Incomplete vulnerabilities. Either offer it only for Ready for approval, or keep it and say in the card that approving records a Global decision for the missing teams. | Approve only when Ready for approval, enforced by the server too (decision 6) |
| Q3 | **Pending review belongs to the whole text, not a block.** The table cannot tell "the General decision is pending" from "a team's later submission is pending". Approving completes both, so the lifecycle is right, but the wording "approve the Global assessment" can be inexact. | Accept for now; record pending per block only if reviewers need to see which block waits. | Accepted as it is |
| Q4 | **`NEEDS_APPROVAL` has two meanings.** As a lifecycle value it is Ready for approval; as a status filter value (API, MCP `search_vulnerabilities`, counts `lifecycle.NEEDS_APPROVAL`) it is every pending vulnerability. The MCP docstring lists `NEEDS_APPROVAL` among the lifecycle filter values without saying so and omits `READY_FOR_APPROVAL`. | Document `READY_FOR_APPROVAL` and `awaiting_review` in the MCP docstring and mark the filter value `NEEDS_APPROVAL` deprecated; later accept `READY_FOR_APPROVAL` as the lifecycle value too. | As recommended (decision 10) |
| Q5 | **Per-team status vs lifecycle.** Team counters count a closed vulnerability as assessed for every team; the **Assessment for selected teams** filter (`team_assessment`) looks only at the teams' own blocks. A team covered by an approved (or now pending) Global decision is "Not recorded" in the filter while the vulnerability is Assessed or Ready for approval. | Decide whether a Global decision covers teams in that filter; if so, use the counters' closure there too (and the pending case for Recorded). | A recorded Global decision covers every team, one rule for filter and counters (decision 7) |
| Q6 | **The `*` fallback team.** The lifecycle requires the `*` team (for example Unknown) like any team and excludes only the tag `Unassigned`. Repair treats the `*` team's name as "not a team" (`_unowned_keys`) and never refers it to the Global decision, so such a vulnerability can stay Incomplete without a repair. | Decide whether components nobody owns need an assessment of "their" team. If not, exclude the `*` team from required teams in both lifecycles; if so, let Repair refer it. | The catch-all team is a team; the Global decision covers it, no references (decision 8) |
| Q7 | **Pending with nothing decided** (a pending placeholder block without a state) is Incomplete (R2), while the same text without the marker is Open (R8). | Treat it as Open: there is nothing to approve. | As recommended (decision 11) |
| Q8 | **Dead helpers that disagree.** `_has_open_team_assessment` (server) and `hasOpenTeamAssessment` (client) are used only by tests and differ (the client has a single-team-Global exception, the server none). `matchesFilters` in the client ignores version overrides, unlike `getGroupLifecycle`. | Remove the unused helpers; route `matchesFilters` through `getGroupLifecycle` or remove it. | As recommended (decision 13) |
| Q9 | **Marker detection.** The client looks for the pending marker after removing SSVC details; the server looks in the whole text. | Use the same text on both sides (strip SSVC details on the server too). | As recommended (decision 12) |
| Q10 | **Repair's former-team label.** With a pending Global decision, the former-team and combine labels end in "<team> still to assess", although the vulnerability becomes Ready for approval after the repair. | Use the approval wording there as well, together with the conflicts of PR #355 in the same stage. | As recommended (decision 13) |
