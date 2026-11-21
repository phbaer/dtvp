# Assessment Model

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Vulnerabilities And Assessments](#vulnerabilities-and-assessments)
- [SSVC And Original Severity](#ssvc-and-original-severity)
- [Team Mapping And Analyzer Guidance](#team-mapping-and-analyzer-guidance)

## Vulnerabilities And Assessments

A grouped vulnerability joins equivalent IDs and aliases across versions. Its
aggregate state follows these rules:

- Common analysis states are `NOT_SET`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`,
  `FALSE_POSITIVE`, and `NOT_AFFECTED`.
- A non-`NOT_SET` General assessment takes precedence; otherwise DTVP chooses
  the worst team state using the priority in `dtvp/logic.py`.
- A reviewer-approved, non-pending General assessment is terminal and makes
  the vulnerability `ASSESSED`, even if team-specific blocks were not all
  recorded before approval. It must still cover every finding instance: while
  any instance (for example another project version) has no analysis state,
  the vulnerability stays `INCOMPLETE`, as do partially applied legacy
  assessments. Without an approved General result, the
  `ASSESSED` lifecycle requires a non-`NOT_SET` assessment block for every
  normalized team tag and consistent coverage across all finding instances;
  a General block is not required. Cached summaries from the previous
  classification are invalidated automatically. Legacy unstructured assessments
  retain their separate `ASSESSED_LEGACY` classification.
- Lifecycle filters show five mutually exclusive categories: Open (no work
  started), Incomplete (missing required team or finding coverage), Conflicting
  (assessment data disagrees or needs repair), Ready for approval (complete,
  consistent, pending sign-off), and Assessed (complete, no pending approval).
  Assessed includes legacy assessments, which retain a separate Legacy badge.
- Analysts default to Open plus Incomplete, including Conflicting findings;
  reviewers default to all statuses. The project filter groups Conflicting under
  Incomplete because conflicts require repair before approval. Cards and API
  lifecycle values still distinguish the two. Reset restores role defaults;
  explicit URL selections override them. Assessment coverage is independent
  and requires selected teams. Old Needs Approval URL selections migrate to
  Ready for approval; old Assessed Legacy selections migrate to Assessed.
  Smart-search aliases retain the API categories.
- Pending review remains internal metadata; it does not add an overlapping UI
  category. The server sets it on every save that is not a reviewer's, and
  removes it only for a reviewer's explicit approval
  ([Review workflows](review-workflows.md)). Incomplete tooltips identify missing teams and finding instances.
  A missing General block alone is not an incomplete-coverage issue.
- API lifecycle codes remain compatible: `INCONSISTENT` is displayed as
  Conflicting, and complete `NEEDS_APPROVAL` groups as Ready for approval.
  The legacy API Needs Approval filter still selects all pending work.
- Inconsistency reasons are indexed separately: missing rescoring metadata,
  differing analysis states, differing structured team blocks, and differing
  substantive details. Selected reasons use OR semantics; filter categories
  combine with AND semantics.
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
  for example because the client's view lacked it or a raw-text edit removed
  it, the server keeps that block as `[Historical: yes]` with every tag and
  its text; it no longer counts toward coverage or state. A block without a
  decision that still tracks work (a text, ticket, assignees, evidence or
  coverage) stays as it is, open. A save that sends only historical records
  of a team keeps that team's current block current, unless the save took
  the team's assessment over (`Copied From`): then it is retired. Only the
  saved team's own block, and the explicit delete action, remove a block. A
  team save never removes the General assessment: left out, it is kept
  unchanged and still counts.
- A historical block is a record, never a team's current assessment. A team
  that has one (for example because it owns the component again after the
  repair kept its former assessment) gets its new assessment as a block of
  its own beside it; a save never overwrites or drops a historical block, the
  saved team's own included, and one the saved text leaves out is put back.
  Deleting a team's assessment removes its current block and keeps its
  historical ones, unless they are all the team has.
- A save that is not an approval keeps a block's `[Assessed By]`, `[Date]`
  and `[Reviewed By]` when it changes only the block's ticket, evidence,
  version coverage or assignees; the server checks this for every client.
  Another team's block that a save sends back unchanged keeps them as well.
  A change of state, justification, text or rescoring, and every approval,
  records the saving user and the time as before.
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

CVSS rescoring is data-driven through `RESCORE_RULES_PATH` (default
`data/rescore_rules.json`). The shipped `NOT_AFFECTED` and `FALSE_POSITIVE`
transitions support CVSS 2.0, 3.0, 3.1, and 4.0 and produce exactly `0.0`.
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
| Reviewer, `fields` without `response` | Each finding keeps its own |
| Reviewer, text with `response` beside it (General assessment) | Set; `NOT_SET` removes it |
| Any other save: analysts, team saves as text, MCP agents | Each finding keeps its own, whatever the request's text or fields say |
| Deleting the General assessment, or the whole assessment | Removed |
| Bulk workflows (apply automatic assessments, repair) | Each finding keeps its own; a finding without one takes the response the vulnerability's other findings agree on |

The stored record decides what "its own" is, not the text a client says it
loaded. An unknown value is answered with 422; a `response` beside a text
from someone who is not a reviewer, or with a team save, with 403.

Findings of one vulnerability that differ only in the response count as
differing assessments (`ASSESSMENT_DETAILS_MISMATCH`), like any other
difference in the General assessment.

Dependency-Track receives the response with every export; see
[Export](import-export.md#export). The VDR carries it as `analysis.response`;
see [CycloneDX](cyclonedx-export.md#what-the-vdr-contains).

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
Omitting `ssvc` preserves each finding's stored record; `null` clears it.
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

`TEAM_MAPPING_PATH` defaults to `data/team_mapping.json` and is editable in
Settings. Keys are deterministic CycloneDX component selectors:

| Selector | Match |
| :--- | :--- |
| `name` | Ungrouped or name-only component, case-insensitive |
| `group:name`, `group/name` | Group and name, case-insensitive; slash form supports scoped package names |
| `purl::pkg:type/namespace/name` | PURL; version/qualifiers/subpath are ignored unless explicitly supplied |
| `cs::name`, `cs::group:name` | Case-sensitive name or group/name |
| `cs,purl::...` | Case-sensitive PURL |
| `nogroup::name` | Only components known to have no group |
| `cs,nogroup::name` | Case-sensitive no-group match |
| `*` | Fallback team; never creates an automatic scan target |

Single-colon keys such as `cs:name` are ordinary `group:name` selectors;
modifiers require `::`. Precedence is PURL, grouped, no-group, plain name,
case-sensitive specificity, exact case, then lexical key order. Mapping does
not otherwise match BOM refs, Dependency-Track UUIDs, or component versions.

Values are either a primary team string or an array whose first entry is the
primary label and remaining entries are historical aliases. Every authenticated
user can read this ownership context so analyst views resolve the same teams as
backend filters and automatic analysis; creating or changing mappings remains
reviewer-only.

Ownership follows dependency direction: a mapped component takes precedence
over its mapped ancestors, including when another path bypasses that component.
Independent mapped branches may still contribute multiple teams. The
backend's per-finding tags are the authoritative ownership result; the browser
uses them for team labels and filtering context. Mapping edits start a fresh
project query rather than deriving new owners from dependency path text.

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
