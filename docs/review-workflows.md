# Review, Bulk Changes, and Archives

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Project Review](#project-review)
- [Bulk Changes](#bulk-changes)
- [Project Archives](#project-archives)

## Project Review

The project view searches and filters grouped vulnerabilities by lifecycle,
inconsistency reason, analysis state, dependency relationship, component,
version, team, assignee, attribution age, tmrescore proposal, CVSS mismatch,
missing rescoring, new findings,
code-assessment availability, automatic-analysis outcome, and proposed
automatic CVSS severity. Outcome choices (`Affected`, `Probably affected`,
`Not affected`, and `Uncertain`) and rescore choices (`Critical` through
`Info`, `No rescore`, and `Unscored`) use OR semantics within each facet and
AND semantics across facets. They are server-side task-window filters, so URL
state, counts, pagination, and Bulk Changes all operate on the same candidate
set. The Open selection matches the displayed `OPEN` lifecycle category, and
vulnerability-ID searches are combined with all active filters.

The **Not rescored** toggle under **More filters** lists vulnerabilities that
have neither a rescored CVSS score nor a rescored vector on any finding. It
ignores lifecycle, so combine it with an overall status such as Assessed to
find decisions that still lack a rescoring. The same filter is available as the
`has:no_rescore` or `cvss:not-rescored` search token and the `not_rescored=true`
URL and API parameter, and it also narrows Bulk Changes candidates.

### New findings

Dependency-Track creates a new finding, with no analysis, whenever a new
project version (or a re-imported BOM) contains a vulnerability again. Next to
the assessed findings of the other versions this looks like an assessment that
was lost; it is a finding nobody has assessed yet.

DTVP marks such a finding as **new**: it has neither a state nor text, and it
was first reported after the vulnerability's assessment was written (the
oldest team block date; for assessments without dated blocks, after every
assessed finding was reported). A finding that was merely left out when the
others were assessed is not new, only incomplete.

- The list row shows **N new**; its tooltip names the versions and the date
  the first of them was reported.
- In the vulnerability's dependency list each such finding carries a **New**
  badge.
- The **New findings** toggle under **More filters** lists only these
  vulnerabilities. The same filter is the `has:new_findings` search token and
  the `new_findings=true` URL and API parameter, and it narrows Bulk Changes
  candidates.

Nothing is copied automatically: the same component may be used differently in
the new version. Assess the finding by hand, or apply the existing assessment
with a bulk workflow. The mark disappears once the finding is assessed.

The Filters sidebar provides a searchable checkbox list of canonical **Teams**
from the complete task. Multiple selections match vulnerabilities owned by any
selected team. Exact names and aliases are case-insensitive. `team:` tokens
become visible selections; partial tokens with several matches require an
explicit choice. Plain text still searches team names alongside other fields,
but never establishes an assessment scope.

**Overall status** always describes the entire vulnerability. The **Workflow
view** controls offer Analyst work (Open plus Incomplete), All statuses, and
Approval queue (Ready for approval). The active view is highlighted; changing
individual status chips shows a Custom selection. Analysts start with Analyst
work; reviewers with All statuses. Untouched status defaults follow role changes,
while explicit selections remain. Incomplete includes Conflicting findings that
need repair before approval; cards and the API retain their distinct labels.
**Assessment for selected teams** is disabled without a team selection:

- **Any** adds no coverage restriction.
- **Not recorded** requires a missing assessment among responsible selected teams.
- **Recorded** requires assessments from all responsible selected teams, including
  pending approval or globally incomplete/conflicting work.

Only selected teams responsible for each vulnerability participate; unrelated
selected teams and unassigned findings cannot create missing assessments.
Analysts default to Not recorded when selecting their first team, reviewers to
Any. Untouched defaults follow role changes; explicit assessment choices remain.
Clearing the last team removes the assessment restriction. Neither assessment
nor inconsistency-reason changes alter overall status choices. Reset restores
the role default,
no teams, and Any. URLs persist explicit teams (`teams`), status choices
(`lifecycle`), and assessment choices (`team_assessment`); role defaults remain
implicit. Legacy single-team `tag` URLs remain supported. Pagination
and bulk actions use the same filters. Additional controls are under **More filters**.

A single selected team also scopes component-driven content inside an
opened vulnerability card; multiple teams leave its full context visible:
affected and triggering components, project
versions, header component/count/age metadata, current-assessment rows,
dependency context, code-analysis targets, and run history show only the
selected team's closest mapped components. Saved analyzer runs with explicit
`target_team` metadata must also match the canonical team or one of its
configured aliases; legacy component-scoped runs without that metadata remain
visible for compatibility. Team mappings are compiled and component ownership
is resolved once per card scope so switching filters does not repeatedly scan
the full mapping. Advisory metadata remains vulnerability-wide context. An
approved General assessment remains the authoritative aggregate state and makes
the vulnerability done once approved, even when team coverage is incomplete.
Finding coverage is still required: an approved or legacy assessment that is
missing from some finding instances, such as another project version, is
classified as `INCOMPLETE`. Before approval, a pending item with missing team or finding coverage is
classified as `INCOMPLETE`, while complete-but-pending work remains
`NEEDS_APPROVAL`, displayed as Ready for approval. The `READY_FOR_APPROVAL`
filter selects only that complete pending subset. The tab badges
use assessment coverage from the selected team's visible findings.
The card reports how many findings are inside the
active team scope, and stale asynchronous history loads are discarded when the
selected scope changes. The top search result count is the final number of
grouped vulnerabilities after every active filter, independent of how many
paginated rows are currently loaded. When filters reduce the task, it is shown
relative to the unfiltered task total. Filter option counts respect every other filter and exclude their own category,
so alternatives remain discoverable even when the current result is empty.
Combined team dropdown and version selections require
the selected team to own a finding in a selected release; matching the team
only in a different release does not include the vulnerability. The version
selection can come from a shared URL or a `version:` search token.
The Team open/assessed breakdown uses the final filtered result and each team's
recorded assessment. A team with an active assessment state other than `NOT_SET`
counts as assessed, including pending approval. Closed findings (including
approved General and legacy assessments) count as assessed for all assigned
teams, even where team documentation is missing. For findings that remain open,
missing team assessments count as open. The Not recorded/Recorded filter still
checks actual team documentation independently of closure.
With a version filter, the team and group breakdowns count only owners in those
releases. A wildcard (`*`) fallback such as Unknown uses its configured team
name and recorded team assessments, just like other owners.
Selected teams also restrict team/group statistics: other teams sharing a
matched vulnerability are omitted, and groups count only selected member teams.
The group hierarchy retains only selected teams and their containing groups.
Complete task-wide facets remain available as filter choices even when their
current filtered count is zero. Overlapping properties such as teams and
inconsistency reasons can therefore have counts whose sum exceeds the final
result count.
When groups are configured, the Results tab renders one Per Group table with
indented nested groups, direct team members, and non-grouped teams at the root,
so each parent total can be compared with its subgroup and team totals without
a duplicate Per Team box. Group totals expand the hierarchy and deduplicate
vulnerabilities across member teams. Closed findings count as assessed for a
group. An unclosed finding counts as open while any responsible member team
lacks an assessment, otherwise as assessed.
Without group configuration, the existing
Per Team table remains as the fallback; it groups configured aliases into their
canonical team and shows aliases beneath the primary team. A vulnerability
carrying both canonical and alias names is counted only once there.
Donut charts show severity and analysis distributions with counts and percentages
for the current filtered result. A team/group selector displays Open versus
Assessed coverage for one scope at a time, avoiding overlap across team slices.
Charts show an empty state for zero results and an updating indicator while
filters are being refreshed. The full Statistics view also includes severity
and analysis donuts; project review supplies its current filters, while the
standalone Statistics page uses the selected project and vulnerability ID.

The detail workspace provides:

| Tab | Purpose |
| :--- | :--- |
| Context | Three ordered sections: advisory and references; where it was found, a matrix of components by project versions with the assessment state of each finding and the dependency chains of a component behind its row; existing assessment evidence |
| Code Evidence | A semantic run list with an expandable new-analysis control; selected rows own indented outcome and evidence disclosures; a worst-case combined decision with the shared advisory shown once and rationale grouped into per-target cards |
| Assessment | Consistent scope and decision/rationale sections with Save/Submit and reload controls in the second section header; CVSS vector or score edits enable saving; analyzer proposals for team decisions; reviewer-only synchronization for incomplete coverage; inconsistent team decisions remain explicit for manual resolution; global CVSS/rescoring controls |

Compact vulnerability rows expose the current workflow state, such as mapping
needed, analysis running, result ready, assessment needed, awaiting review, or
complete. Inside the card, the tab status badges say what is still missing.

All actions of a card sit in one place, the sticky bar next to the tabs:
Approve (reviewers, while a review is pending), Save or Submit, Reload, and the
"More" menu. They share one button shape; the one that completes the current
work is filled, the others are outlined.

### Inconsistencies and differences

When a vulnerability is inconsistent, or its findings carry different
assessments, a banner above every tab says why: the reasons, how many findings
differ from the most common assessment, and the decision of each team when the
teams disagree. In the matrix every distinct assessment has a letter (A is the
most common one) and the findings that differ are outlined.

"Show differences" opens a comparison of the assessments field by field
(state, rescoring, response, and per team the state, justification, rationale, ticket,
assessor, reviewer and date). Only the fields that differ are listed unless
"Show equal fields too" is ticked. A reviewer can put one of them into the
Global assessment form with "Use for all findings"; it applies to every
finding once saved.

### Approving

A reviewer who opens a pending assessment lands on the Global assessment. If no
Global assessment exists yet, the form is filled from the team assessments: the
worst state, its justification and the combined rationale, with the rescoring
rule for that state applied. An existing Global assessment is never replaced.
Nothing is saved at this point. The reviewer adjusts the decision or the CVSS
vector where needed and presses Approve, which saves the Global assessment and
removes the pending status in one step. On a collapsed card the Approve button
in the header opens this view; it does not approve by itself.

### Response

The form of the Global assessment has a **Response** select below the
analysis state and justification: Not set, Update, Rollback, Workaround
available, Will not fix, Can not fix. It records what is done about the
finding and is optional for every state. Team assessments have no response,
and analysts do not see the field.

The response is saved with the Global assessment, for all findings of the
vulnerability. A choice that is not saved yet stays while team tabs are
switched; a team tab then says to return to the Global assessment to save
it. Discarding the draft or loading the assessment again shows the stored
value. Where the Global assessment is displayed, the response is shown with
it. See [Response](assessment-model.md#response) for the rules and the text
markup.

Component ownership is edited in Settings → Team Mapping, not in the card. A
vulnerability whose components belong to no team offers the team `Unassigned`,
so it can be assessed without a mapping.

The "More" menu next to Save holds the rarely used actions: deleting the
assessment and, for reviewers on the Global assessment, suppressing the
finding in Dependency-Track. A suppressed vulnerability carries a `Suppressed`
chip in its header.

CVSS and rescoring controls appear in the reviewer-only Global subview of
Assessment so the score and assessment can be evaluated and saved together.
Team subviews omit global rescoring controls. Analysts see mapped ownership and
triggering components in Context and can launch analysis for owned targets.
Each team subview shows the latest scoped analyzer assessment as a proposal,
including its state, summary, and rationale. The subview identifies the mapped
repository component or components for the selected team and provides a direct
copy action when the analyzer supplied a remediation ticket. A user can copy
that proposal into the editable draft, but a saved or manually edited team
assessment remains authoritative. Reviewers use the latest analyzer result only
as a fallback for a team without a manual assessment; the effective summary and
Global draft use the worst state across those per-team sources. This source
precedence is intentional rather than timestamp-based, so a newer automated run
cannot silently replace a team's considered decision.
Bulk team assessment transfer selects the mapped owner component (for example
`@gehc/nest-back-pack`), including findings on its transitive dependencies.
The selector lists mapped owners present in the current project task, and the
preview checks current ownership and assessment eligibility before writing.

When ownership changes, a team with no saved assessment can choose **Use as
draft** from **Previous team assessments** in its Assessment tab. The earlier
team need not appear as a current team tab. The copied state, justification,
and rationale are editable before submission; assignees, evidence checks,
version checks, and ticket references are not inherited. Saving marks the
source block historical and records the source team on the new block. The old
record remains readable without influencing active coverage or state.

An active Team filter establishes the card's assessment context immediately.
Analysts see and edit only that team's Assessment subview. Reviewers start in
the same focused view, retain direct access to Global, and can explicitly show
all other teams when a cross-team review is needed; returning to the focused
view restores the exact filtered team. Analyst submission requires a mapped
team, a non-empty analysis
state and details, and a justification for `NOT_AFFECTED`; the action is
explicitly labeled as a submission for reviewer approval. Assessment contains
only Global (for reviewers) and real mapped teams; automatic analysis and
tmrescore remain supporting context rather than a synthetic `automation` team.
A tmrescore proposal stages a normal Global draft and waits for the explicit
save action. Local drafts survive tab and team-scope changes. Closing or
switching a vulnerability prompts the user to save, discard, or keep editing.
Assessment writes refresh the active task window, and route state preserves
filters when navigating to statistics or code analysis. Once the transactional
local save succeeds, the card reports that it is saved locally while
Dependency-Track synchronization continues in the background; retry failures
remain visible without blocking another edit. Per-finding local revisions are
retained across list updates so subsequent edits keep conflict protection.
Each vulnerability card can reload its current assessment directly from
Dependency-Track; the refreshed task snapshot updates the card, lifecycle
filters, and counts together.
Vulnerability headers use compact status icons to show both available and
unavailable states for tmrescore/vscorer and code-analysis assessments. In the
compact list, the Dependency-Track reload action stays at the bottom-right of
the header so it does not overlap the assessed corner marker.

## Bulk Changes

The reviewer-only `Bulk Changes` dialog runs one plug-in workflow at a time:

| Workflow | Candidates and action |
| :--- | :--- |
| Apply Automatic Assessments | Usable, unapplied analyzer assessments; writes one assessment per owning team plus a global assessment with the worst verdict and its CVSS rescore |
| Repair Assessments | Every safe, rule-based repair in one operation; each vulnerability lists the repairs that apply |

**Repair Assessments** chains the following repairs. Each stage works on the
result of the previous one, so a finding is written once. Preview rows carry a
label per applicable repair and count only the findings that change.

| Repair | Applies to | Result |
| :--- | :--- | :--- |
| Restore CVSS vector | Findings whose rescored vector is recoverable unambiguously from audit comments | The vector and score are written back |
| Restore tickets | Findings whose history shows that a workflow removed a ticket | See below |
| Synchronize assessment | Incomplete groups whose otherwise consistent assessment is missing from some findings | Every finding carries the same assessment blocks; a rescored CVSS stored ahead of the blocks is kept, and copied to findings without one. The [response](assessment-model.md#response) is kept as well; a finding without one takes the response the other findings agree on |
| Move former team assessment | Assessment blocks of teams that no longer own the vulnerability | See below |
| Refer teams to the global assessment | An approved global assessment while a current team has no assessment of its own | Each such team receives a block with the global state and justification and the text `See global assessment.`; never while the global assessment is pending review or unset |
| Remove references no team stands behind | A block under the name for components no team owns (the team mapping's `*`, or `Unassigned`) whose text is only `See global assessment.` | The block is removed. An assessment someone wrote under that name stays: it is the assessment of a component without a team, not a former team's |
| Combine conflicting assessments | Conflicting groups in which no current team has an assessment | See below |
| Repair rescoring | Findings where a configured state-based CVSS rescore is missing, incomplete, or incorrect | The rule's vector and score are written |

A former team's assessment is never discarded. Its block is removed and its
decision, justification, assessor, date, ticket, and rationale are recorded as
a note in the global assessment (`…; assessed by alice; dated 2026-08-12;
ticket VP-101`). The date is the day the team wrote its assessment, not the
day of the repair; teams that decided the same on different days are listed as
separate decisions. Its tickets also become tickets of the global
assessment: a ticket tracks the vulnerability in the product, whoever owned
the component when it was opened. Notes are deduplicated, ignoring case and whitespace: a
rationale shared by several teams or decisions is written once with every
decision listed, a rationale the global assessment already contains is
referenced instead of repeated, and a decision that is already recorded adds
nothing. Who decided what is always kept:

- When every current team has its own assessment, the note is informational:
  the global state stays unset and the current teams keep deciding.
- When a current team has no assessment, the former decision becomes the
  global decision (the worst state when former teams differ), unless a global
  decision already exists. If that result is approved, each team without an
  assessment receives a block with the global state and the text
  `See global assessment.`; while it is pending review those teams stay open
  and the vulnerability remains Incomplete.

A Conflicting group is combined only when no current team has an assessment,
so nothing a responsible team decided is overruled. Its former-team and global
assessments across all findings become one global assessment written to every
finding: the worst state wins, distinct global texts are kept, and former-team
decisions are recorded as notes. If the sources agree on the state and none
was pending review, each current team receives a `See global assessment.`
block and the vulnerability becomes Assessed. If the sources disagree, the
combined decision is new: it is marked pending review and the current teams
stay open. Conflicts that involve a current team's assessment still need a
manual decision.

Tickets are restored from DTVP's own [history](import-export.md#history). A
ticket counts as dropped when one version of a finding's assessment had it in
a team's ticket field, the next version was written by a bulk workflow and
names it nowhere, and the current text does not name it either. It returns to
the block of its team when the team still has one, else to the global
assessment; without either, the preview lists it for a manual decision. A
ticket that a person removed stays removed. Versions from before the history
existed cannot be compared: for those, the text Dependency-Track still holds
or its audit trail is the only source.

Ownership comes from the current team mapping, including aliases. Groups with
no mapped team and blocks already marked `[Historical: yes]` are left
untouched. Because lifecycle metadata is read once per preview, a repair
that changes the lifecycle (for example restoring a vector on a Conflicting
group) can make further repairs available on the next preview.

Vulnerabilities that need a human decision first start unselected and show
`Review first`: a former team's decision would become the global decision,
conflicting assessments would be combined, or part of the vulnerability
cannot be repaired automatically. Selection buttons toggle all vulnerabilities
of one repair topic, or everything that needs review, alongside Select all.

The rescoring repair includes cases where a transition such as
`NOT_AFFECTED` should produce a `0.0` score but no rescore was stored. Rows
place the stored vector and score beside the fixed values that will be written.
Findings that cannot be repaired automatically stay listed with an amber note
and are not selectable: a matching transition with an unsupported original
CVSS vector, or a lost vector with ambiguous or no audit history.

Some advisories state a severity and no CVSS vector. A rescoring needs a base
all the same, so the repair invents one: the base metrics of the rescored
vector the finding already has, since whoever rescored it chose that base;
else a base without impact (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`),
the one the assessment form starts from in that case. The row says that the
base is invented. If
the rescore rule configuration is invalid, the other repairs still run and the
preview states why rescoring was skipped.

The single-assessment editor keeps its own takeover draft action for copying a
former team's decision into the selected team.

`Apply Automatic Assessments` rows likewise show the current vulnerability
CVSS and the automatic rescore that will be written to every eligible finding,
together with the teams that receive an assessment and any analyzed component
without a team.
Its composable selection filters cover every automatic-analysis outcome and
every proposed CVSS severity, plus candidates with no rescore or a vector-only
unscored proposal. Multiple choices within a facet use OR semantics, while the
outcome and rescore facets combine with AND semantics. They filter the visible
rows and reset the apply selection to those rows. Their labels, values, and
rescore-band classification are shared with the main Filters sidebar.
Lightweight saved-result metadata retains the proposed score and vector for
this preview; older metadata rows are rebuilt automatically from their stored
full results.

Every candidate set is the intersection of all active project-list filters and
the selected workflow's applicability rules. The dialog loads plug-in metadata
first and prepares only the chosen preview. Preview tokens prevent applying a
stale candidate set; prepared previews are reused while the dialog is open.
Filtering uses compact task summaries, then carries their canonical lifecycle
metadata onto the hydrated full groups used by workflows. This keeps lifecycle-
specific repairs such as assessment synchronization aligned with the
visible filtered list.

The UI starts preview, apply, and document work as background operations and
polls their short status endpoint. The operation survives the initiating HTTP
request, so reverse-proxy request timeouts do not cancel long bulk changes.
Apply operations commit all selected changes to the transactional local outbox
and expose item-level progress through the task status. Dependency-Track writes
then use the shared bounded background dispatcher with coalescing and retry
backoff, so large applies do not hold an HTTP request open or multiply upstream
write concurrency.
Endpoints are:

- `POST /api/bulk-workflows/summary`
- `POST /api/bulk-workflows/{workflow_id}/{preview|apply|document}-task`
- `GET /api/bulk-workflows/tasks/{operation_id}` returns progress and the final result

The synchronous `preview`, `apply`, and optional `document` endpoints remain
available for API compatibility.

Automatic-assessment discovery accepts current, reviewer-started, and
source-less legacy records when an assessment can be extracted. Benchmark and
explicitly non-final records are excluded. Matching uses vulnerability ID or
alias plus project context; it does not rely on stale client IDs.

Rows label assessment coverage as:

- `auto`: complete automatic coverage.
- `manual`: complete reviewer-started coverage.
- `mixed`: both automatic and reviewer-started coverage.
- `partial`: one or more grouped components have no code assessment.

The result store maintains dedicated assessment metadata for every saved run.
Task windows expose `code_assessment_status` and calculate filter counts from
that server-side property; the browser does not download result payloads or
assemble a parallel ID filter. Existing stores backfill metadata once through
the numbered SQLite migration path.

For apply, all relevant analyzer runs are combined using the most severe
overall verdict: Affected becomes `EXPLOITABLE`; Probably Affected and Uncertain
become `IN_TRIAGE`; Not Affected becomes `NOT_AFFECTED`.

Applied details carry one assessment block per owning team plus the global
block, matching the vulnerability card's `Apply all to <n> teams` action. A
team's block holds the analyzer evidence for the components it owns and its own
worst-wins state and justification; ownership uses the same team mapping and
dependency-path resolution as automatic scan targets, with the run's recorded
target team as fallback. The global block carries the worst state across all
runs, its justification, and the CVSS rescore of that worst run — a milder run
never contributes the global vector or score, even when its proposed score is
higher. When the global state has a configured rescore transition, that rule
produces the written vector and score, so the rescoring repair reports
nothing right after an apply. Components that no team owns keep their evidence
in the global block and are listed in the preview row. Applied details retain
every relevant run as a compact decision record: target, verdict, the two
executive lines (including the decisive concern or action when applicable), up
to three dependency/version facts, and the CVSS score change. Repeated raw
summary, rationale, research, audit, remediation, CWE, version-list, and CVSS-
reason sections remain in the saved full result instead of being copied into
Dependency-Track. Legacy results without an executive summary keep the older
semantic fallback so existing evidence is not silently dropped. Ticket drafts
remain separate from assessment details.
Application provenance prevents
successfully applied or queued run/finding pairs from being offered again.
Previews use only compact metadata; apply and document export hydrate full
payloads for the selected groups. Findings are identified by their finding UUID
when present, otherwise by project, component, and vulnerability UUIDs.

## Project Archives

Reviewer-only archives preserve project versions, SBOMs, findings,
vulnerability details, and normalized assessments.

- Export: `POST /api/project-archives/exports`
- Import preview: `POST /api/project-archives/imports`
- Apply: `POST /api/project-archives/imports/{task_id}/apply` with
  `create_missing` or `update`
- Stored snapshots: `GET /api/project-archives/snapshots`
- Schema: `dtvp.project-archive/v1`

Restore matches project name/version first, then remaps changed UUIDs by
component PURL/name/version/BOM ref and vulnerability ID/name/aliases. Audit
history and comments are not replayed. ZIPs default to `data/project_archives`;
optional Git-friendly expanded trees default to `data/project_archives_git`.
