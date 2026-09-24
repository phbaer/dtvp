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
code-assessment availability, automatic-analysis outcome, and proposed
automatic CVSS severity. Outcome choices (`Affected`, `Probably affected`,
`Not affected`, and `Uncertain`) and rescore choices (`Critical` through
`Info`, `No rescore`, and `Unscored`) use OR semantics within each facet and
AND semantics across facets. They are server-side task-window filters, so URL
state, counts, pagination, and Bulk Changes all operate on the same candidate
set. The Open selection matches the displayed `OPEN` lifecycle category, and
vulnerability-ID searches are combined with all active filters.

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
Before approval, a pending item with missing team or finding coverage is
classified as `INCOMPLETE`, while complete-but-pending work remains
`NEEDS_APPROVAL`, displayed as Ready for approval. The `READY_FOR_APPROVAL`
filter selects only that complete pending subset. The tab badges
and Next action state use assessment coverage from the selected team's visible findings.
The card reports how many findings are inside the
active team scope, and stale asynchronous history loads are discarded when the
selected scope changes. The top search result count is the final number of
grouped vulnerabilities after every active filter, independent of how many
paginated rows are currently loaded. When filters reduce the task, it is shown
relative to the unfiltered task total. Filter option counts respect every other filter and exclude their own category,
so alternatives remain discoverable even when the current result is empty. The
Team open/assessed breakdown uses the final filtered result.
Pending-review groups remain on the open side of that breakdown until they are
approved, even when their currently visible team blocks are populated.
Complete task-wide facets remain available as filter choices even when their
current filtered count is zero. Overlapping properties such as teams and
inconsistency reasons can therefore have counts whose sum exceeds the final
result count.
When groups are configured, the Results tab renders one Per Group table with
indented nested groups, direct team members, and non-grouped teams at the root,
so each parent total can be compared with its subgroup and team totals without
a duplicate Per Team box. Group totals expand the hierarchy and deduplicate
vulnerabilities across member teams. Without group configuration, the existing
Per Team table remains as the fallback; it groups configured aliases into their
canonical team and shows aliases beneath the primary team. A vulnerability
carrying both canonical and alias names is counted only once there.

The detail workspace provides:

| Tab | Purpose |
| :--- | :--- |
| Context | Four ordered sections: advisory and references; finding/team/component scope with affected components visible to analysts and reviewers; dependency context; existing assessment evidence |
| Code Evidence | A semantic run list with an expandable new-analysis control; selected rows own indented outcome and evidence disclosures; a worst-case combined decision with the shared advisory shown once and rationale grouped into per-target cards |
| Assessment | Consistent scope and decision/rationale sections with Save/Submit and reload controls in the second section header; CVSS vector or score edits enable saving; analyzer proposals for team decisions; reviewer-only synchronization for incomplete coverage; inconsistent team decisions remain explicit for manual resolution; global CVSS/rescoring controls |
| Team Mapping | Reviewer-only ownership editor |

Compact vulnerability rows expose the current workflow state, such as mapping
needed, analysis running, result ready, assessment needed, awaiting review, or
complete. Inside the card, tab status badges and one Next action guide lead to
the relevant tab. The guide's navigation control disappears after reaching its
destination and is replaced by concrete in-tab instructions, leaving the real
run, draft, save, or submit control as the next action instead of repeating the
same button. The sticky bar contains only navigation and persistence state.
After a successful assessment save or analyst submission, the guide advances
to the next vulnerability in the current filtered and sorted result set.

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
| Sync Incomplete Assessments | Groups whose otherwise consistent assessment is missing from some findings |
| Take over team assessments | Copy a former team's consistent assessment for selected components into missing current-team blocks using a source → target mapping |
| Restore Rescored CVSS | Assessed findings with one unambiguous current vector recoverable from audit comments |
| Repair Rescoring Definitions | Findings where a configured state-based CVSS rescore is missing, incomplete, or incorrect; repairs every safely actionable finding |

**Take over team assessments** requires previous and current team names plus one
or more components chosen by exact name. The component selection applies across
project versions. Preview uses the active project filters and shows ready
findings and skip reasons. It requires the target to own the finding now, the source to no
longer own the vulnerability, an unambiguous source decision, and no saved
target decision or approved global result. Conflicting source decisions across
versions are left for manual review. Apply creates pending target assessments,
preserves source blocks as history, and leaves existing target assessments
untouched. Preview tokens recheck the mapping and task assessment snapshot before apply.
The bulk action is reviewer-only; analysts can use the single-assessment draft
action for their selected team. Assessments no longer present in any current
finding require separate audit or archive retrieval.

`Repair Rescoring Definitions` includes cases where a transition such as
`NOT_AFFECTED` should produce a `0.0` score but no rescore was stored. Preview
rows show why each finding is a mismatch and place the stored vector and score
beside the fixed values that will be written. Findings with a matching
transition but a missing or unsupported original CVSS vector remain listed for
manual review instead of being silently omitted.
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
specific workflows such as `Sync Incomplete Assessments` aligned with the
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
produces the written vector and score, so `Repair Rescoring Definitions` reports
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
