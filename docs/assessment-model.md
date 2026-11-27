# Assessment Model

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Vulnerabilities And Assessments](#vulnerabilities-and-assessments)
  ([lifecycle decision table](#lifecycle-decision-table))
- [SSVC And Original Severity](#ssvc-and-original-severity)
- [Team Mapping And Analyzer Guidance](#team-mapping-and-analyzer-guidance)

## Vulnerabilities And Assessments

A grouped vulnerability joins equivalent IDs and aliases across versions. Its
aggregate state follows these rules:

- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`,
  `FALSE_POSITIVE`, and `NOT_AFFECTED`.
- A non-`NOT_SET` General assessment takes precedence; otherwise DTVP chooses
  the worst team state using the priority in `dtvp/logic.py`.
- The lifecycle (Open, Incomplete, Conflicting, Ready for approval,
  Assessed), the Awaiting review flag, and exactly what decides them are
  defined in the [lifecycle decision table](#lifecycle-decision-table).
- Inconsistency reasons are indexed separately: missing rescoring metadata,
  differing analysis states, differing structured team blocks, and differing
  substantive details. Narrowed meanings:
  - **Team assessments differ** (`TEAM_ASSESSMENT_MISMATCH`): a team
    contradicts itself. Its current blocks differ (state, justification or
    text) across the findings of one scope (findings with a different
    version override are another scope) or within one finding. Teams may
    disagree with each other, since a vulnerability affects components
    differently; that is not a conflict, and a reviewer's Global decision
    settles it.
  - **Assessment details differ** (`ASSESSMENT_DETAILS_MISMATCH`): parts the
    findings both have say different things: the text ahead of the blocks,
    the same block (the Global one included), two different SSVC records,
    or two different responses.
  - A part that some findings have and others lack is a gap, not a
    difference: a team's block (the vulnerability is Incomplete until
    Synchronize copies it), the SSVC record or the response (optional; a
    save and Repair carry the agreed one as a tidy-up). Selected reasons use OR semantics; filter categories
  combine with AND semantics.
- Findings are compared on what they must agree on: the current team blocks
  and the text ahead of them. Left out are historical blocks, which are
  records of single findings, and the tags for assessor, date, rescoring,
  pending review and `[Version Coverage: ...]`, and the order of the team
  blocks. A vulnerability whose findings differ only in these is not
  Conflicting. The SSVC record and the response are compared on their own:
  missing is no difference, two different ones are. The server
  (`comparable_assessment_text` in `dtvp/grouped_vuln_services.py`) and the
  web client (`comparableAssessmentText`) compare the same way; both are
  tested against
  `frontend/src/lib/__tests__/fixtures/assessment_scope_cases.json`.
- The technical state of a vulnerability is the General decision of the first
  finding that has one, in the order of the findings' keys (project,
  component, vulnerability); without one, the worst team state, then the
  worst finding state. States of equal priority are ordered by name. The
  value does not depend on the order in which versions are loaded.
- Assessment details use structured blocks such as `[Team: ...]`,
  `[State: ...]`, `[Assessed By: ...]`, `[Reviewed By: ...]`,
  `[Rescored Vector: ...]`, and `[Assigned: ...]`.
- The [response](#response) is a tag of its own ahead of the blocks:
  `[Response: UPDATE]`.
- A transferred former-team block remains readable with `[Historical: yes]`;
  historical blocks do not count toward current team coverage or aggregate state.
  The current team's copied block records `[Copied From: TeamA]`, and its
  assessment remains pending review. Takeover copies decision, justification,
  and rationale, but resets assignees and review checks. The bulk
  [Repair Assessments](review-workflows.md#bulk-changes) operation marks a
  former team's block historical in the same way. Historical blocks can also
  come from the bulk
  [restore from a Dependency-Track export](review-workflows.md#restore-team-assessments-from-an-export).
  A historical block is a record, not the finding's decision: its rescoring
  tags and the CVSS vectors its text quotes do not rescore the finding
  (`without_historical_blocks` in `dtvp/logic.py`, `withoutHistoricalBlocks`
  in the frontend).
- A save never drops another team's assessment. When the text a save writes
  leaves out an assessed block (a state) of a team other than the saved one,
  for example because the client's view lacked it or an API client's text removed
  it, the server keeps that block as `[Historical: yes]` with every tag and
  its text; it no longer counts toward coverage or state. A block without a
  decision that still tracks work (a text, ticket, assignees, evidence or
  coverage) stays as it is, open. A save that sends only historical records
  of a team keeps that team's current block current, unless the save took
  the team's assessment over (`Copied From`): then it is retired. Only the
  saved team's own block, and the explicit clear action, remove a block. A
  team save never removes the General assessment: left out, it is kept
  unchanged and still counts.
- A historical block is a record, never a team's current assessment. A team
  that has one (for example because it owns the component again after the
  repair kept its former assessment) gets its new assessment as a block of
  its own beside it; a save never overwrites or drops a historical block, the
  saved team's own included, and one the saved text leaves out is put back.
  Clearing a team's assessment removes its current block and keeps its
  historical ones, unless they are all the team has.
- A save that is not an approval keeps a block's `[Assessed By]`, `[Date]`
  and `[Reviewed By]` when it changes only the block's ticket, evidence,
  version coverage or assignees; the server checks this for every client.
  Another team's block that a save sends back unchanged keeps them as well.
  A substantive edit invalidates a recorded approval of the changed block.
  Explicit approval stamps every current deciding block, including General, with `[Reviewed By: user]` and
  `[Reviewed At: epoch_ms]`. Historical and `NOT_SET` blocks are not stamped.
  The original `[Assessed By]` and `[Date]` stay on unchanged work, and one
  approval uses the same review time across all saved findings. The canonical
  fields expose `reviewed_by`, `reviewed_at_ms` and `assessed_at_ms`; the UI
  shows reviewer and time separately. A metadata-only save retains existing
  review provenance, and ordinary saves cannot supply a new approval time.
  Each explicit approval has revision origin `assessment-approval`, author
  and commit time. Older revisions already retain author/time, but their
  generic save origin alone does not establish an approval. Legacy missing
  reviewer/time remain unknown; no automatic backfill guesses them.

  Full automated application verification (2026-11-27): all 2,641 backend tests
  passed with no exclusions, including exhaustive backup crash recovery; all
  1,312 frontend unit tests passed with coverage; the production build and all
  189 regular browser tests passed (63 each on Chromium, Firefox and WebKit).
  No skips or flaky browser results; browser retries were disabled. The final
  backend run used `--no-cov` after the initial coverage run exposed two stale
  assertions that treated ordinary saves as approvals. The browser regression
  now distinguishes the team badge from the missing-team message; an HTTP
  regression checks explicit approval and metadata readback. Local runtimes:
  CPython 3.15.0 and Node.js 24.22.2 (CI uses Node.js 26). Manual real-stack
  scenarios and documentation captures are separate from these regular suites.
  This verifies local/mock behavior, not production rollout or backfill.

- Structured details retain at most one active block per team
  (case-insensitive), plus any number of historical blocks; historical blocks
  are merged only when they are the same record (team, decision, text,
  assessor, reviewer, date, ticket, rescoring).
  Code-analysis assessment drafts keep evidence in the owning-team blocks and
  maintain one General block that references those teams and takes their worst
  effective state. An independently authored General assessment is preserved;
  team evidence is never copied into it. Generated General summaries from older
  sync operations are removed on the next sync.
- Dependency paths come from CycloneDX BOM dependency graphs. Dependency-Track
  attribution timestamps are retained as `attributed_on`.

### Lifecycle decision table

| | |
| :--- | :--- |
| Status | Implemented; the canonical definition. Decided in [ADR 0014](adr/0014-lifecycle-decision-table.md) |
| Code | Server: `_derive_group_lifecycle` and `_build_group_list_metadata` in `dtvp/grouped_vuln_services.py`, `combine_lifecycles` and `has_pending_review_marker` in `dtvp/assessment_scopes.py`, `approval_blocker` in `dtvp/assessment_use_cases.py`. Web client (the card, and lists without server metadata): `getGroupLifecycleFromSummary` in `frontend/src/lib/assessment-helpers.ts`, `classifyGroup` and `coversAllTeamsOf` in `frontend/src/lib/group-classifier.ts`, `getApprovalUnavailableReason` in `frontend/src/lib/assessmentSyncIssues.ts` |
| Verified | 2026-11-26 (rebased onto PR #355) against the code above, `tests/test_lifecycle_decision_table.py` and `frontend/src/lib/__tests__/lifecycleCases.spec.ts`, which both read `frontend/src/lib/__tests__/fixtures/lifecycle_cases.json`: every rule, the team coverage and whether Approve is possible, for each case |

Every view takes the lifecycle from this one rule: the list, its status
filters, counts and quick views (`dtvp/task_group_query_services.py`), the
card, the Bulk Changes candidates, the Repair stages and MCP
(`search_vulnerabilities`) read `list_metadata.lifecycle`, `is_pending`,
`is_approval_ready` and `covers_all_teams` computed by the server; the card
computes the same with the web client's mirror.

#### Inputs

| Input | What counts |
| :--- | :--- |
| Findings | The vulnerability's findings Dependency-Track reports now, in every project version, including new findings of a new version and suppressed ones (suppression does not change the lifecycle). Gone findings are not part of the vulnerability ([Gone findings](review-workflows.md#gone-findings)) |
| Finding state | The finding's analysis state; `NOT_SET` or absent means the finding has no state |
| Required teams | The vulnerability's team tags from the [team mapping](#team-mapping-and-analyzer-guidance), an alias read as its team. The catch-all `*` team (for example Unknown) is a required team like any other; only the tag `Unassigned` is not. With version overrides, the teams owning the scope's findings |
| Team assessed | A **current** block (not `[Historical: yes]`) of that team, or of one of its aliases, compared without case and surrounding space, with a state other than `NOT_SET`, on any finding |
| General decides | A current `[Team: General]` block with a state other than `NOT_SET`, on any finding: the reviewer's (manual) [Global decision](#the-global-decision). A General block that is `NOT_SET` does not decide. A General decision stands for every required team without a block of its own, pending or approved |
| Pending review | Any finding's text holds `[Status: Pending Review]` outside its SSVC details. The marker belongs to the finding's whole text, not to one block (accepted, ADR 0014) |
| Legacy | Assessed findings without any block under a `--- [Team: …] ---` header (text ahead of the first header is no block), or whose only block is a General block that is `NOT_SET` |
| Inconsistency reasons | The reasons as defined [above](#vulnerabilities-and-assessments) (the bullets on inconsistency reasons and on what findings are compared on) and in [Version override](#version-override): `MISSING_RESCORING_VECTOR`, `ANALYSIS_STATE_MISMATCH`, `TEAM_ASSESSMENT_MISMATCH`, `ASSESSMENT_DETAILS_MISMATCH`, `VERSION_OVERRIDE_PARTIAL`, `VERSION_OVERRIDE_LABEL_MISMATCH`. What each compares is defined there, not here |
| Version overrides | With an override marker on any finding the rules run per scope and are combined ([Scopes and lifecycle](#scopes-and-lifecycle)) |

#### Rules

The first rule that matches decides. Inside each scope when the vulnerability
has version overrides.

| Rule | Condition | Lifecycle (API) |
| :--- | :--- | :--- |
| R1 | Any inconsistency reason | `INCONSISTENT` |
| R1a | An outstanding [request for changes](#changes-requested) | `INCOMPLETE` |
| R2 | Pending review, and no finding has a state | `OPEN` |
| R3 | Pending review, and a finding has no state | `INCOMPLETE` |
| R4 | Pending review, a required team has not assessed, and no General block decides | `INCOMPLETE` |
| R5 | Pending review otherwise: every required team assessed or covered by a General decision | `NEEDS_APPROVAL` |
| R6 | A finding has no state and another has one | `INCOMPLETE` |
| R7 | Legacy | `ASSESSED_LEGACY` |
| R8 | A General block decides (approved, since R2-R5 did not match) | `ASSESSED` |
| R9 | A required team has not assessed: `INCOMPLETE` if any finding has a state, else `OPEN` | `INCOMPLETE` / `OPEN` |
| R10 | A team's deciding block is on some assessed findings and missing on others (a gap for Synchronize, not a contradiction; PR #355) | `INCOMPLETE` |
| R11 | Otherwise: `ASSESSED` if any finding has a state, else `OPEN`. Teams that disagree do not prevent it: the [derived Global decision](#the-global-decision), the worst of them, is the decision | `ASSESSED` / `OPEN` |

A vulnerability without findings is `OPEN`. R5 and R8 are the same rule with
and without the pending marker: a General decision covers the teams without
a block of their own, so approving it is all that is left. R10 applies only
without a General decision and without pending review: a pending
vulnerability with such a gap is Ready for approval, and the approval
records a General decision (see [Approval](#approval)). Without a General
block, teams that disagree yield the derived worst as the decision: the
vulnerability is Assessed (R11), or Ready for approval while pending (R5). With version
overrides, the scope lifecycles combine worst first: any `INCONSISTENT` (or
two overrides in one version) gives `INCONSISTENT`; any `INCOMPLETE`, or
`OPEN` beside a scope that is not, gives `INCOMPLETE`; then `NEEDS_APPROVAL`;
all `OPEN` gives `OPEN`; then `ASSESSED_LEGACY`, then `ASSESSED`.

#### Flags beside the lifecycle

| Flag (`list_metadata`) | Definition |
| :--- | :--- |
| `is_pending` | Pending review (the input above), whatever the lifecycle. This is **Awaiting review** |
| `is_approval_ready` | `is_pending` and lifecycle `NEEDS_APPROVAL`. This is **Ready for approval**, and the only state in which Approve is possible |
| `covers_all_teams` | A General block decides (pending or approved), or the lifecycle is `ASSESSED` or `ASSESSED_LEGACY` without pending review: every required team counts as assessed ([Per-team status](#per-team-status)) |
| `is_assessed` | Lifecycle `ASSESSED` or `ASSESSED_LEGACY` |
| `is_open` | Lifecycle `OPEN`, or `is_pending` (pending review is not done) |

The list's **Review needed** workflow label covers both pending submissions
and incomplete assessments with an existing technical decision. It is broader
than the **Awaiting review** filter, which specifically selects the stored
pending-review marker. **Missing team assessments: ...** names missing coverage
separately, with aliases collapsed to canonical teams. Neither label implies
**Ready for approval**: that still requires complete finding/team coverage or
an applicable General decision. Conflicts and requested changes retain their
dedicated labels; active analyzer work retains its progress label.

Awaiting review is a filter flag, not a lifecycle: it cuts across R1-R5, so
an Awaiting review vulnerability can be Conflicting, Open, Incomplete or
Ready for approval. A Ready for approval vulnerability is always Awaiting
review.

#### The Global decision

| | |
| :--- | :--- |
| Code | `global_decision` and `STATE_ORDER` in `dtvp/logic.py`; `getGlobalDecision` and `STATE_PRIORITY` in `frontend/src/lib/assessment-helpers.ts`. Both are tested against `lifecycle_cases.json` (`global_decision` of every case) and `state_order.json` |

The **effective Global decision** of a vulnerability is:

- **manual**: the reviewer's current General block when it decides; it takes
  precedence over the team assessments, whatever they say;
- otherwise **derived**: the worst state among the current team blocks that
  decide. Every team with that state is a source, named in alphabetical
  order; the justification is that of the first of them that has one;
- otherwise **none**.

The worst-state order, worst first, is the one order DTVP uses for every
"worst": **Exploitable > In triage > Resolved > Not affected >
False positive** (then Not set). Repair, the analyzer verdicts of Apply Automatic
Assessments (Affected → Exploitable; Probably affected and Inconclusive →
In triage; Not affected) and the finding matrix use the same order.
False positive is the least concerning completed outcome. Not set is excluded
from deciding team blocks; it remains unassessed, not a safe outcome. This
same order sorts completed outcomes in work lists; unassessed findings appear
between In triage and Resolved when sorting by analysis state. This
order does not change the advisory severity or overwrite a reviewer’s General
block; see [ADR 0018](adr/0018-completed-assessment-priority.md).

The assessment pane lists the selected team's reported component names and
versions, paired with their product versions. It uses each finding's resolved
team ownership, including aliases and inherited dependency ownership, rather
than selecting every version of a matching component name. Selecting another
team through **Show all teams** changes this scope independently of the outer
list filter. The component chips and advisory summary use the same scope;
Global explicitly shows all teams' findings. Repeated product versions are
comma-separated. Component versions combine only when they have identical
release coverage and assessment state; grouping never invents a component/
release association or hides a different decision.

The team table shows that team's own current assessment blocks, resolving
aliases and keeping conflicting states separate. A General block or the
finding's combined state is not presented as an explicit team decision;
without its own block the table says **Not assessed by this team**. A scanner
report alone does not establish affectedness, and an absent finding does not
establish that a release is unaffected. Missing ownership is shown explicitly
instead of falling back to the global component list. Unknown product and
component versions are labelled explicitly.

- **Export.** The state DTVP writes to Dependency-Track for a finding is its
  effective decision (`calculate_aggregated_state`): the same derived worst
  when there is no General block. The justification is not derived: DTVP
  exports none of its own, and Dependency-Track keeps its value.
- **API.** `list_metadata.global_decision_source` (`manual`, `derived`,
  `none`), `global_decision_state`, `global_decision_justification`,
  `global_decision_teams` (the sources of a derived decision), and
  `derived_global_state` and `derived_global_teams` (the worst team decision
  in every case, to compare a manual one with). MCP `get_vulnerability`
  returns the same as `global_decision`.
- **UI.** The team overview on the Global assessment says "Global: derived,
  worst of team assessments: Exploitable (H-Core)", or "Global: set by
  reviewer: Not affected" with "differs from the worst team assessment
  (Exploitable, H-Core)" and **Use worst** when they differ. The card's state
  chip carries "· derived" and says so in its tooltip. The editable Global
  state stays **Not Set** when the decision comes from the teams.
- **Approval** records the effective decision. Without a General block,
  **Review & approve** prepares a draft of the derived worst. Approval stores it
  as the General block unless the reviewer changed it. The server does the
  same for API clients (`with_derived_global_block`), without applying a
  rescoring rule.

#### Approval

Approve is possible only for a vulnerability that is **Ready for approval**
(R5). The card offers it only then, and otherwise tells a reviewer why (for
example a finding without a state, or a team without an assessment and no
General decision). The server checks the same rule on the stored texts of
the findings the request names and refuses an approval of anything else with
422 (`approval_blocker`); a request whose findings hold nothing pending is a
reviewer's ordinary save when there are no outstanding change requests.
When teams are missing assessments and there are no outstanding requests, a
reviewer can record a final Global decision. It stays pending review and can
then be approved.

#### Changes requested

A reviewer can return a current submitted team assessment with a required
rationale. This records a review decision independently of the technical
state. The affected team counts as having work to do and the vulnerability
cannot be approved while the request is outstanding. A Global decision
cannot satisfy a change request for a team.

An explicit resubmission marks the selected team's revised assessment pending
review and resolves its outstanding request. A reviewer can also withdraw
an obsolete request, including after team ownership changes. Requests for
other teams are preserved. The assessment history keeps the rationale and
reviewer. An
outstanding request is stored in the assessment details and follows normal
Dependency-Track exports.

The browser uses `POST /api/assessments/request-changes` with the grouped
task and vulnerability IDs, team, rationale and displayed finding revisions.
Withdrawal uses the same endpoint with `action: "withdraw"`.
Resubmission uses `POST /api/assessment` with `resubmit_changes: true`, the
full grouped finding set and the revisions the analyst viewed. A stale
review action must be retried after reloading. A legacy approval request
can require a fresh grouped task when DTVP detects outstanding feedback
in the project family.
See [ADR 0016](adr/0016-team-assessment-changes-requested.md).

#### Names

| Lifecycle (API, MCP rows) | UI label | Status filter value | What resolves it | Who |
| :--- | :--- | :--- | :--- | :--- |
| `OPEN` | Open | `OPEN` | A team's or the Global assessment | Analyst (saved pending) or reviewer |
| `INCOMPLETE` | Incomplete | `INCOMPLETE` (the Incomplete chip also selects `INCONSISTENT`) | R3, R6, R10: Synchronize (the card's **Sync all**, Repair's Synchronize stage); R4, R9: the missing team assesses, or a reviewer records a Global decision (Repair also refers named teams to an approved one) | Analyst for team assessments; reviewer for Sync all, Repair and the Global decision |
| `INCONSISTENT` | Conflicting | `INCONSISTENT` (old links: `CONFLICTING`) | Align the findings: save one assessment for all, "Use for all findings", Repair (Combine conflicts, Restore CVSS) | Reviewer for Repair and "Use for all findings"; any user's save that rewrites every finding |
| `NEEDS_APPROVAL` | Ready for approval | `READY_FOR_APPROVAL` | **Approve** ([Approving](review-workflows.md#approving)); when teams have no block of their own the card says "Approve the Global assessment to complete it" | Reviewer |
| `ASSESSED` | Assessed | `ASSESSED` | Nothing to do | |
| `ASSESSED_LEGACY` | Assessed, with a **Legacy** badge | `ASSESSED` (old links: `ASSESSED_LEGACY`) | Nothing to do; a structured save replaces it | |
| (flag `is_pending`) | Awaiting review (row badge, quick view, toggle) | `awaiting_review=true`; the status value `NEEDS_APPROVAL` (deprecated) | [Approve](review-workflows.md#approving) when Ready for approval, or [clear the Global fields](import-export.md#clearing-an-assessment) while keeping team assessments | Reviewer |

"Pending review" is the marker `[Status: Pending Review]` in the text, not a
state. As a **lifecycle value** `NEEDS_APPROVAL` means Ready for approval.
As a **status filter value** it is deprecated: it still selects every
pending vulnerability (`awaiting_review=true` does the same), as it did
before Awaiting review existed; use `READY_FOR_APPROVAL` for Ready for
approval. The counts follow the filter meaning: `lifecycle.NEEDS_APPROVAL`
counts every pending vulnerability, `lifecycle.READY_FOR_APPROVAL` the Ready
for approval ones.

#### Per-team status

One rule decides whether a team has assessed a vulnerability, for the team
counters (Open/Assessed per team and team group) and the **Assessment for
selected teams** filter (`team_assessment`: Not recorded, Recorded) alike:
the team has assessed (the input above), pending review included, or
`covers_all_teams` holds. A recorded General decision therefore counts as
the decision of every team without a block of its own, the catch-all team
included.

#### Repair and the catch-all team

Repair names the teams a General decision covers only while that decision is
pending ("approve the Global assessment to complete it"), and teams without
any assessment and no General decision ("nothing to copy"). It refers named
teams to an approved General decision ("See global assessment."), but never
the catch-all `*` team: the General decision covers it. A reference under
the catch-all name is removed ("not needed, the global assessment covers
it") only while a General decision covers the team; without one it is what
the team has, and it stays. An assessment under the catch-all name that is
not a reference is a person's and stays; when the catch-all team is the
only owner, no block counts as a former team's.

CVSS rescoring is data-driven through `RESCORE_RULES_PATH` (default
`data/rescore_rules.json`). The shipped `NOT_AFFECTED` and `FALSE_POSITIVE`
transitions support CVSS 2.0, 3.0, 3.1, and 4.0 and produce exactly `0.0`.
On the Global form, **Reset to Original** explicitly removes saved rescoring
on the next save, even when its vector already equals the source or the
source has no numeric score. The form derives a missing source score from
its vector; without a source vector it does not invent one. The reset stays
pending across team tabs, can be discarded, and is replaced by a subsequent
CVSS edit or a new Global state with a rescoring rule. A reset alone keeps
team assessments and their derived Global decision; it creates no General
assessment. Team-tab navigation does not apply Global rescoring rules.
Vectors preserve their original CVSS version and base metrics. A rescored
vector stored in a different CVSS version than Dependency-Track supplies (for
example a CVSS 3.1 rescore of a vulnerability that only has a CVSS 2.0 vector)
cannot contribute its extra metrics: the rescoring repair proposes the rule
applied to the original vector, shows both, and leaves the vulnerability
unselected for review first. Malformed or incomplete original vectors stay
visible for manual review rather than being rewritten speculatively.

A configured transition owns the vector of the state it covers. Whenever a
state with a rule is written — by the reviewer, by a code-analysis draft, or by
a bulk apply — the rule is layered on top of the proposed vector and the base
metrics of the Dependency-Track vector are restored, so an analyzer proposal
contributes only its extra metrics. States without a transition keep the
analyzer's proposed vector and score unchanged.

### Response

| | |
| :--- | :--- |
| Status | Implemented |
| Verified | 2026-11-19 against `tests/test_assessment_model.py`, `tests/test_assessment_use_cases.py`, `tests/test_main_assessment.py`, `tests/test_bulk_workflows.py`, and `frontend/src/lib/__tests__/assessmentResponse.spec.ts`. Not checked against a running Dependency-Track |

The response says what is done about a finding. It is Dependency-Track's
`analysisResponse` and CycloneDX's `analysis.response`, with the same values:
`CAN_NOT_FIX`, `WILL_NOT_FIX`, `UPDATE`, `ROLLBACK`, `WORKAROUND_AVAILABLE`.

- **One value per finding, part of the Global assessment.** Teams have none.
  It is optional for every state, also for `EXPLOITABLE`.
- **In the text** it is the tag `[Response: UPDATE]` ahead of the team
  blocks, after the rescoring tags:
  `[Rescored: 2.5] [Rescored Vector: …] [Response: UPDATE]`. No tag means not
  set; `NOT_SET` is never written.
- **As a field** it is `response` of the finding (`null` when not set), in
  `GET /api/assessments/fields` and in `fields` of `POST /api/assessment`.
- Only a tag with one of the five values is the response. Other text in
  brackets, such as `[Response: ask the supplier]`, stays free text. A
  response tag inside a team's text is removed when the text is read; it
  never sets the field.

Who changes it:

| Save | Response |
| :--- | :--- |
| Reviewer, `fields` with `response` | Set to that value; `null` or `NOT_SET` removes it |
| Reviewer, `fields` without `response` | Each finding keeps its own; a finding without one takes the response the saved findings agree on (only where it has a General block) |
| Reviewer, text with `response` beside it (General assessment) | Set; `NOT_SET` removes it |
| Any other save: analysts, team saves as text, MCP agents | Each finding keeps its own, whatever the request's text or fields say; a finding without one takes the response the saved findings agree on (only where it has a General block) |
| Clearing the General assessment, or the whole assessment | Removed |
| Bulk workflows (apply automatic assessments, repair) | Each finding keeps its own; a finding without one takes the response the vulnerability's other findings agree on |

The stored record decides what "its own" is, not the text a client says it
loaded. An unknown value is answered with 422; a `response` beside a text
from someone who is not a reviewer, or with a team save, with 403.

Findings of one vulnerability with two different responses count as
differing assessments (`ASSESSMENT_DETAILS_MISMATCH`). A finding without a
response next to findings with one is no difference: the response is
optional, and a save or Repair gives it the agreed one as a tidy-up.

Dependency-Track receives the response with every export; see
[Export](import-export.md#export). The VDR carries it as `analysis.response`;
see [CycloneDX](cyclonedx-export.md#what-the-vdr-contains).

### Version override

A finding can carry a version override marker
([ADR 0010](adr/0010-version-overrides.md)): its version has its own
assessment, shared by every version with the same label. Implemented so far
(plan steps 4 and 5) are the marker as a field that every writer keeps and
the lifecycle per scope; scoped saves, the override operations and the
export come with the later steps of the
[design](version-overrides-design.md#19-plan).

- **In the text** it is two tags ahead of the team blocks, after the
  rescoring and response tags:
  `[Response: UPDATE] [Version Override: LTS 2.x] [Override Reason: Backported fix]`.
- **Label:** 1-40 characters from `A-Z a-z 0-9 space . _ + -`, compared
  case-insensitively with white space collapsed. `base` and `ambiguous` are
  reserved. **Reason:** 1-200 characters on one line, without `[`, `]` or
  `---`. A tag with another value is free text.
- **As a field** it is `version_override: {label, reason}` of the finding
  (`null` without one), in `GET /api/assessments/fields`.
- **Read only.** Every save, team or General, every bulk workflow
  (Synchronize, Combine and repair, automatic assessments, restores), a
  clear (clearing everything keeps the tags only) and an MCP save keep each
  finding's marker as stored. A save may repeat the finding's marker or send
  none; any other marker is refused with 422. Agent text and copied text
  cannot contain the tags.
- **Adopted from Dependency-Track** with a marker, the value is stored
  unchanged as revision 0 (origin `import`) and followed by revision 1
  (origin `import-review`) that adds `[Status: Pending Review]` and is
  exported; see [Import](import-export.md).

#### Scopes and lifecycle

The markers divide a vulnerability's findings into **scopes**
(`dtvp/assessment_scopes.py`, mirrored by `frontend/src/lib/assessmentScopes.ts`):

- A project version whose findings carry no marker belongs to **base**. One
  label makes it part of that label's scope, with every finding of the
  version, including untouched (new) findings without the marker. Two labels
  in one version make it **ambiguous**.
- The [lifecycle rules](#lifecycle-decision-table) run **inside each
  scope**, with the teams that own the scope's findings as required teams,
  and combine worst first as the table says. An
  override that differs from base is therefore not a conflict, and a pending
  override is never Assessed.
- Two new reasons make a scope Conflicting:
  **Override not on every finding** (`VERSION_OVERRIDE_PARTIAL`, an assessed
  finding without the marker in an overridden version) and
  **Two overrides in one version** (`VERSION_OVERRIDE_LABEL_MISMATCH`).
  Findings of one label with different reasons differ in their details
  (`ASSESSMENT_DETAILS_MISMATCH`).
- An untouched finding without the marker in an overridden version is a
  **gap**: its scope is Incomplete, and `list_metadata.override_gaps` names
  it.
- The technical state (sorting, filters) is the **primary scope's**: base
  when it has findings, else the scope with the most findings.
- `list_metadata.assessment_scopes` lists the scopes of a vulnerability with
  an override (name, label, reason, versions, finding keys, pending,
  lifecycle, required teams, reasons, gaps); it is absent without one. The
  statistics count such a vulnerability once by its combined state, and
  `groups_with_overrides` counts them.
- The card lists the overrides read-only ("Version overrides: legacy · 2.0 ·
  pending approval"), and the finding matrix marks each overridden version
  column. Saves are not scoped yet (step 7): until then, a save into an
  overridden version keeps each finding's stored marker, so a gap it fills
  shows as **Override not on every finding**.

## SSVC And Original Severity

SSVC is independent of CVSS and assessment state: it records deployment priority,
not a numerical severity or an automatic analysis-state transition. The initial
model is CERT/CC **Deployer Patch Application Priority 1.0.0**, with Defer,
Scheduled, Out-of-Cycle, and Immediate outcomes (not CISA's distinct tree).

Reviewers use the embedded SSVC calculator below the CVSS block in the global
assessment's Decision & rationale section. Questions, definitions, and the
live result come from the bundled model; links open the official documentation
and calculator. Save through the existing assessment action; clear explicitly
to remove SSVC. No values are inferred from CVSS. Official-source evidence can
prefill unanswered Exploitation as described below. Unsaved SSVC
edits survive team-tab switches but must be saved from the global assessment.
Vulnerability rows display saved SSVC priority; sidebar original-severity and
SSVC filters include counts, removable chips, and shareable URL state.

The question definitions and all 72 decision rules are bundled in
`dtvp/resources/ssvc/deployer-1.0.0.json`, pinned to the CERT/CC SSVC `2026.7.0`
release, with upstream URLs and the MIT(SEI) license alongside. Authenticated
`GET /api/ssvc/models` serves these resources; calculation needs no external
service. Both the model and its rules are versioned. Keep historical resources
when adding a revision, retain attribution, and test exhaustive input coverage
and expected outcomes before shipping rule changes. The backend rejects
incomplete or duplicate rule tables.
Frontend summaries validate saved decisions against the same canonical JSON,
bundled at build time, and tests exercise every rule. Both Docker frontend build
stages copy this resource directory for the build and type-checking.

`POST /api/assessment` accepts optional `ssvc: {model, version, answers, rationale,
exploitation_evidence?}`
for reviewer global assessments. The server validates answers and calculates
the outcome; omitted answers mean incomplete, never a default decision.
Omitting `ssvc` preserves each finding's stored record; a finding without one
takes the record the other saved findings hold, when they all hold the same
(only where the finding has a General block). Repair Assessments carries it
the same way ([Carry the SSVC record and the response](review-workflows.md#bulk-changes)).
`null` clears it.
The General header stores an atomic `[SSVC: IMMEDIATE]` tag (or `DEFER`,
`SCHEDULED`, `OUT_OF_CYCLE`, `INCOMPLETE`). A separate body block delimited by
`[SSVC Details]` and `[/SSVC Details]` contains pretty-printed JSON: model/version,
answers, outcome code (`D`/`S`/`O`/`I`, or `null` for incomplete), readable priority,
rationale, assessor, UTC timestamp, and any selected source-evidence snapshot.
Consumers can parse the JSON directly without URL decoding. Ordinary JSON string
escaping protects reserved assessment delimiters in free text; the decoded
values are unchanged. Header and JSON outcomes are validated against the rules.
Older percent-encoded `[SSVC: ...]` records remain readable and migrate on their
next save, without changing their assessor, timestamp, or evidence. Invalid and
unsupported records are retained for explicit correction, not silently dropped.
The grouped API continues to expose the decoded record as `ssvc_summary.record`.
The General body also
contains a managed `[SSVC Summary]` section with the **SSVC priority**, inputs,
rationale, source reference, source assessment/check dates, and assessor.
Incomplete assessments explicitly document `SSVC priority: Incomplete`.
The save-review preview includes changed SSVC priority and inputs. Ordinary
edits preserve/regenerate the summary; explicit clear removes it and metadata.
This travels with existing Dependency-Track assessment and archive workflows.
Team edits, CVSS changes, and bulk assessment workflows preserve SSVC per finding.
Grouped `ssvc_summary` reports coverage and explicitly distinguishes unassessed,
incomplete, mixed, and invalid/unsupported records; it never picks one result
from differing assessments.

Grouped `original_severity` is calculated before local rescoring, using the
original CVSS score (including zero), falling back to the source severity label
when no valid score exists. Alias/version groups retain the highest original
severity. Missing source data is `UNKNOWN`; effective rescored severity is
never used as the fallback. Task group/window and bulk filters accept
`original_severity` and `ssvc` arrays, with matching facet counts: selected
values use OR, filter categories use AND, and an empty selection means all.

### Official Exploitation Evidence

The backend proactively downloads the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
at startup and refreshes it hourly. Opening the global review's calculator
also checks [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) for the
vulnerability's CVE identifiers/aliases, caching each result (including 404s)
for 24 hours. The authenticated `GET /api/ssvc/exploitation?cve=CVE-...` endpoint
accepts up to 20 CVEs. `refresh=true` bypasses freshness, subject to a shared
60-second per-source/CVE cooldown. Fetching never saves an assessment.

`dtvp/resources/ssvc-sources.json` defines source URLs, supported source
versions, TTLs, and value mappings. KEV inclusion means **Active**; absence is
unknown, never **None**. Only the authoritative CISA ADP container's explicit
Vulnrichment Exploitation (`none`, `poc`, `active`, SSVC version 2.0.3) is mapped
to the Deployer input. Its other coordinator decisions are not imported.
Positive evidence takes precedence across aliases; a None suggestion requires
an explicit assessment for every supplied CVE. EPSS is not exploitation evidence.

Only fresh, conclusive evidence can automatically fill an unanswered, previously
unassessed field. Existing saved/manual answers and cleared drafts are not
overwritten: use **Use suggestion** explicitly. **Refresh evidence**, beside
Exploitation, checks again without persisting anything. The calculator displays
source links, assessment/check dates, missing data, and errors. Failed refreshes
retain the last good snapshot marked stale; stale evidence requires explicit
acceptance. Manual Exploitation edits detach source evidence; other edits keep it.
Save validates a server-signed evidence token and stores its historical snapshot;
later refreshes never rewrite documented assessments. Rotating the session secret
requires refreshing/reselecting evidence before editing and re-saving old SSVC.

The bounded SQLite cache defaults to `DTVP_DT_CACHE_PATH/ssvc_enrichment.sqlite3`
(`data/dt_cache/ssvc_enrichment.sqlite3` without configuration); override with
`DTVP_SSVC_CACHE_PATH`. It retains at most 4096 CVE entries plus the shared KEV
catalog, survives restarts, and bounds concurrent fetches and response sizes.

The sidebar's **KEV / CISA evidence** filters and list badges use this cache,
independently of saved SSVC assessments. **KEV listed** matches catalog inclusion;
**CISA SSVC available** matches an explicit CISA Exploitation assessment, including
`none`. Any CVE identifier or alias can match. Selecting multiple evidence values
uses OR; other filters (including the analyst lifecycle defaults) still use AND.
Task list/detail responses expose `evidence_sources`; task-window and bulk queries
accept an `evidence` array, with per-group counts under `counts.*.evidence`.
Shareable URLs support e.g. `evidence=KEV&evidence=CISA_SSVC`.

Available values are `KEV`, `CISA_SSVC`, `NOT_CHECKED`, `NO_DATA`, `STALE`,
`UNAVAILABLE`, and `NO_CVE`. Coverage flags can overlap source matches.
`NO_DATA` requires fresh negative checks for both sources across all CVE aliases;
unchecked, failed, expired, or evicted lookups never imply no data. Positive stale
evidence remains searchable. KEV covers the cached whole catalog; CISA coverage
is partial until individual CVEs are checked by opening/refreshing the global
SSVC calculator. Filtering never triggers external requests or a project-wide
crawl. Cache updates and freshness expiry invalidate query results/counts without
rebuilding the vulnerability task; calculator lookups refresh the visible window.

Set `DTVP_SSVC_ENRICHMENT_ENABLED=false` to disable background and on-demand
external requests. Default is enabled: whole-catalog requests go to `www.cisa.gov`,
and on-demand CVE-specific requests go to `raw.githubusercontent.com`; no local
assessment text or deployment context is sent. Manual calculation/saving works
without either source or network access.
TLS verification stays enabled. For deployments behind a TLS-inspecting proxy,
configure HTTPX's `SSL_CERT_FILE` with a trusted CA bundle (for example the system
CA store); do not disable certificate verification.

## Team Mapping And Analyzer Guidance

`TEAM_MAPPING_PATH` defaults to `data/team_mapping.json` and is edited in
Settings → Team Mapping ([screen guide](screens.md#settings-team-mapping)).
The file is organised by team ([ADR 0012](adr/0012-team-centric-mapping.md)):
each team lists what it owns.

```json
{
  "Core": {
    "aliases": ["DE-Core"],
    "projects": ["stats-srv", "estservice"],
    "components": ["vp-stats-app", "project:ViewPoint_Product::core"]
  },
  "3P": {
    "aliases": ["3rd Party"],
    "components": ["libtiff", "purl::pkg:generic/ffmpeg"]
  },
  "Unknown": "*"
}
```

| Field | Meaning |
| :--- | :--- |
| `aliases` | Former names of the team; legacy tags with these names count as the team |
| `projects` | Dependency-Track project names (case-insensitive); the team owns the project's findings no component entry owns |
| `components` | Component selectors (below); `*` makes the team the catch-all, at most one team owns it |

A string or a list of strings is shorthand for `components`
(`"Unknown": "*"`, `"Web": ["@scope/widget"]`). DTVP itself writes objects.

Component selectors are deterministic CycloneDX selectors:

| Selector | Match |
| :--- | :--- |
| `name` | Ungrouped or name-only component, case-insensitive |
| `group:name`, `group/name` | Group and name, case-insensitive; slash form supports scoped package names |
| `purl::pkg:type/namespace/name` | PURL; version/qualifiers/subpath are ignored unless explicitly supplied |
| `cs::name`, `cs::group:name` | Case-sensitive name or group/name |
| `cs,purl::...` | Case-sensitive PURL |
| `nogroup::name` | Only components known to have no group |
| `cs,nogroup::name` | Case-sensitive no-group match |
| `project:<project>::<selector>` | Any selector above, only inside that Dependency-Track project (case-insensitive), for example `project:ViewPoint_Product::core` or `project:P::purl::pkg:npm/x` |
| `project::<project>` | The same as listing the project under `projects` |
| `*` | Catch-all; never creates an automatic scan target |

Single-colon keys such as `cs:name` or `project:name` are ordinary
`group:name` selectors; modifiers and project scopes require `::`.

**Resolution.** A finding belongs to the nearest mapped component above it in
the BOM (the component itself first). Whether a component is mapped is
decided in this order:

1. a selector scoped to the component's project, then the selectors without
   a project; within each, PURL, grouped, no-group, plain name, then
   case-sensitive, exact case and lexical key order;
2. when nothing matches the component's own name, group or PURL, the same
   selectors against the package its PURL names: the package name, with the
   PURL namespace as the group. A BOM may name a component differently from
   its package, for example `stats-app` for `pkg:npm/vp-stats-app@0.1.2`;
   `vp-stats-app` then owns it. A match on the own name always wins.

Only when no component of any chain is mapped does the project decide: the
team listing the project (`projects`, or `project::<project>`), and last the
team owning `*`. Mapping does not otherwise match BOM refs,
Dependency-Track UUIDs, or component versions. The project name is the
Dependency-Track project of the version; where it is not known (the
dependency-chain endpoint), the BOM's root component names it.

**Validation.** A save is refused, with messages naming the teams, when a
selector or project is listed under two teams, `*` is owned twice, an alias
equals another team or another team's alias, two team names differ only by
case, a selector has an unknown or contradicting modifier (`foo::bar`,
`cs,ci::x`, `purl,nogroup::...`), or a value is malformed. Weak spots (stale,
broad, shadowed and near-duplicate entries) are warnings in the editor and do
not block a save.

**The older format** maps selectors to teams (`{"vp-stats-app": "Core",
"core-lib": ["Core", "DE-Core"], "*": "Unknown"}`, the first name the team,
the rest aliases). It still loads unchanged. A file is read as organised by
team when a value is an object or a team owns `*`; otherwise as selector
keys. The editor shows such a file by team (each key under its primary team,
aliases merged; an alias claimed by two teams stays with the first and is
reported) and saves it in the team format; so does every save or upload
through the API.

Every authenticated user can read the mapping (`GET /api/settings/mapping`
returns the selector mapping the matcher reads, `GET
/api/settings/mapping/teams` the document by team) and the
[mapping report](#team-mapping-report); creating or changing mappings remains
reviewer-only.

Ownership follows dependency direction: a mapped component takes precedence
over its mapped ancestors, including when another path bypasses that component.
Independent mapped branches may still contribute multiple teams. The
backend's per-finding tags are the authoritative ownership result; the browser
uses them for team labels and filtering context. Mapping edits start a fresh
project query rather than deriving new owners from dependency path text.

### Team Mapping Report

`GET /api/settings/mapping/report` is built in the background from the
stored BOMs and findings of the versions active in the source
(`sync_versions.active_in_dt`, not gone; the stored project list when the
sync state lists none), by `dtvp/team_mapping_report.py`. A request never
waits: `status` is `building` (with the previous report, `stale` when its
inputs changed), `ready` or `failed`. The report is rebuilt when the mapping
or a version's stored BOM or findings change; `?refresh=true` (reviewers)
rebuilds it now. It holds:

- totals and, per project, its versions, findings, findings on `*` and the
  project's entry;
- findings owned per entry (selector, `project::<project>`, `*`);
- the findings falling to `*` by project root and by the topmost component
  of their chains (a direct child of the root, or the top of a chain that
  does not reach it), with projects, versions and a suggested entry: the
  project for a root, the package a PURL names, `group:name`, or
  `project:<project>::<name>` for names without PURL or group;
- near-duplicate entries that give nearly the same name (case, separators
  and the PURL's type ignored) to different teams;
- an inventory of the stored components per project (name, group, PURL,
  findings below them), at most 40,000 entries, for autocomplete and the
  editor's live preview.

`GET /api/settings/mapping/tree?project_uuid=&ref=` returns one level of a
version's BOM tree (the root, or the children of `ref`) with every node's
owner (team and why: its own entry, inherited from the mapped components
above it, the project's entry, or `*`) and its findings; components no
dependency links to are listed under the root (flat BOMs).
`POST /api/settings/mapping/tree` (reviewers) takes `project_uuid`, an
optional `ref` and a draft `mapping` in either format and returns the same
level as the draft would own it; a node whose owner differs under the saved
mapping carries that one as `saved_owner`. The editor uses it to show unsaved
changes in the tree.
`POST /api/settings/mapping/preview` (reviewers) takes a draft mapping in
either format, optionally `projects`, and returns how many findings would
change owner, from which team to which, by project. Both use the slim
version models the report keeps in memory.

`TEAM_GROUPS_PATH` defaults to `data/team_groups.json` and is also editable in
Settings. Each group has explicit direct `teams` and nested `groups`, so an
abstract group can be composed from existing teams and groups while a group
such as `Core-MUC` can also include the existing `Core-MUC` team:

```json
{
  "Core-MUC": {
    "teams": ["Core-MUC", "3rd Party"],
    "groups": []
  },
  "Product Engineering": {
    "teams": ["Runtime"],
    "groups": ["Core-MUC"]
  }
}
```

Team references accept configured aliases and are normalized to their primary
team. Unknown teams or groups, empty groups, duplicate members, and cycles are
rejected when the configuration is saved. Group statistics expand nested
membership and count each vulnerability once per group, even when it carries
both parent-team and subteam tags.

Analyzer guidance comes from `DTVP_AUTO_ANALYSIS_GUIDANCE_PATH` (default
`data/auto_analysis_guidance.json`) and uses the same selectors:

```json
{
  "components": {
    "component-name": "extra reviewer context"
  }
}
```

Values may be strings, arrays, or objects with `guidance`/`prompt`. Optional
`default` or `*` content is prepended. Guidance matches the selected owned scan
target, applies without restart, and is context only: it cannot establish
dependency presence, version, reachability, or affectedness without evidence.
A changed guidance fingerprint makes an automatic result eligible for rescanning.


## Standalone assessment rationale and supporting evidence

Team and global assessment text must explain the conclusion, consumer and
release/configuration scope, relevant code or artifact observations, input
control and access requirements, demonstrated impact, uncertainty, and the
reason for exploitability or severity changes. Preserve source severity and
explain the environmental vector when rescoring. State the required action
or the conditions supporting an exclusion. A global rationale synthesizes
team conclusions without hiding material consumer differences.

Supporting evidence is associated separately inside DTVP; it does not replace
that rationale. New evidence use inserts no opaque ID into printable text.
A person edits the offered summary and explicitly saves the assessment;
selection alone changes no score, decision or approval. Editing prose keeps
selected evidence, and explicit removal does not alter prose. Evidence use
history is attributed to team/global scope, finding and assessment revision.
Existing assessments and legacy reference lines are preserved unchanged.
See [Agent code evidence](analysis-integrations.md#agent-code-evidence).
