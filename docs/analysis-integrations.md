# Threat-Model and Code Analysis

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

Paths and commands refer to the repository root unless stated otherwise.

- [Threat-Model Rescoring](#threat-model-rescoring)
- [Code Analysis](#code-analysis)

## Threat-Model Rescoring

Set `DTVP_TMRESCORE_URL` to enable the project `Threat Model` workspace. Users
can upload a `.tm7` model and optional `items.csv`, analysis configuration, or
MITRE countermeasures, then cache proposal snapshots for reviewer dialogs.

The integration supports vscorer's session/inventory contract, normalized
step-based progress, chain/prioritization/what-if analysis, MITRE enrichment,
offline mode, provider-neutral LLM enrichment, and output download maps. A
`skeptic_gate_failed` response is terminal and requires manual review.
DTVP submits inventory runs with vscorer's background-analysis contract and
polls the session progress/result endpoints, so long NVD-enriched analyses are
not tied to one HTTP response or cancelled by a caller/proxy disconnect. It
retains the blocking-call timeout and gateway fallback for older vscorer
deployments and reads the persisted result error when a background run fails.

SBOM modes are latest-only or merged multi-version. The merged mode keeps a
separate root per version so historical findings remain visible without being
misrepresented as current inventory.

## Code Analysis

Set `DTVP_CODE_ANALYSIS_URL` to enable reachability/exploitability analysis.
DTVP queues requests containing the vulnerability, selected owned target, CVSS
vector, processed project releases, dependency context,
reviewer/static guidance, optional tmrescore context, and optional LLM metadata.
DTVP retries up to five consecutive transport failures while polling Agentyzer
job status; any successful poll resets the counter. Persistent disconnections
fail the queue item with a status-poll error.
DTVP sends every project release represented in the processed vulnerability
group. Agentyzer intersects those candidates with versions the selected
repository actually contains: matching Git tags, `release/*` branches from all
available remotes, and `main`/`master` when configured project-version metadata
identifies the branch's release. The request field is `project_versions`
(`affected_product_versions` remains a deprecated input alias). These values
remain explicitly distinct from vulnerable dependency versions read from
manifests and lock files.

Advisory lookup canonicalizes source-sensitive identifiers (including lowercase
GHSA payloads for OSV and GitHub), follows CVE aliases for NVD, and can use an
optional `AGENTYZER_GITHUB_TOKEN` for authenticated GitHub advisory requests.
The repository target remains separate from the vulnerable package identity:
if advisory lookup cannot establish the package and affected constraints, the
analysis stays Inconclusive instead of scanning the target as its own
dependency. For npm repositories, dependency evidence is read from structured
manifest and lockfile entries, so a root `package.json` or `package-lock.json`
`name` field is not reported as a direct or locked dependency.

Final results pass through a deterministic claim audit that aligns verdict and
reasoning, flags unsupported claims or downgrades, and restores original CVSS
when a downgrade is rejected. Version presence alone is capped at Probably
Affected unless reachability, exploitability, or a positive transitive path is
confirmed. A generic dependency-usage reachability result does not override a
later full-source analysis that affirmatively excludes the
vulnerability-specific path. Static guidance is never evidence by itself.

Each completed assessment also carries a compact `executive_summary` with two
separate statements: `vulnerability` briefly describes the advisory and its
affected dependency, while `assessment` states the final repository-specific
verdict, confidence, exposure, audit state, key basis, and at most one next
action. The assessment uses formal disposition, confidence, exposure, basis,
required-action, and audit-assurance language. A structured `why` list is
rendered as the **Decision rationale** and retains the complete deciding facts
from advisory applicability, dependency presence, current and product-release
versions, direct reachability, deep exploitability, transitive paths, and audit
caveats. Path
claims are explicitly scoped to the current workspace; a missing path remains
"not confirmed" unless affirmative evidence supports "not reachable". This
gives Affected, Not Affected, and Inconclusive results an audit-ready evidence
record without restoring the old raw report in the primary view. Compactness
comes from separating these evidence categories; the assessment payload and
human-facing statements never cut them at a character or item-count limit. It is
assembled after the deterministic audit guardrails, retained in lightweight
result metadata and shown in assessment drafts and run outcomes. The separate
follow-up prompt context remains bounded to the model's input budget.
Human-facing assessment text also lists every covered product version from the
repository intersection on one comma-separated `Product versions covered:`
line; dependency/component versions remain separately labeled evidence. The
complete summary, reasoning, role views, version
inventory, audit checks, and pipeline evidence remain available in the saved
run payload.

When the latest results for several targets are combined, the Code Evidence
view renders the vulnerability and worst-case decision once, followed by one
card per target. Each card uses the component name as its heading and lists the
target's rationale without repeating that name on every evidence line. The
separate target-status list is shown only for results whose full details are
still loading.

Agentyzer retains package provenance for affected ranges, explicit affected
versions, and fixed versions. For advisories covering multiple packages, it
selects the package found in the analyzed repository and excludes constraints
belonging to the other packages. OSV `fixed`, `last_affected`, and `limit`
boundaries keep their exclusive or inclusive semantics. npm advisory ranges
use SemVer precedence, including prereleases that are not valid PEP 440; a
range that cannot be evaluated is treated conservatively instead of being
reported as safe. Repository history includes tags and `release/*` branches
from every available remote. When project releases are supplied, only their
intersection with those repository versions is analyzed. The default branch
uses `.project.json` and its `version` field unless the component's
global or component-level `project_version_files` repository configuration
supplies another list of JSON paths and dotted fields. Version evidence
separately reports the current dependency version, verified project release
refs, metadata sources, and unmatched caller-supplied project releases. Fixed
versions remain associated with their affected release line so remediation
does not suggest cross-line downgrades.
Manifest ranges such as `^1.2.3` and `>=2.0` remain unresolved constraints
unless a lock file or artifact supplies a concrete version, so range boundaries
are not presented as installed affected versions.

### Results, Dedupe, And Follow-Ups

Completed results are stored in SQLite at `DTVP_CODE_ANALYSIS_RESULTS_PATH`.
The store retains full payloads separately from lightweight assessment metadata,
plus run/job IDs, parent links, model metadata, target context, and application
provenance. Analyzer requests also carry the DTVP project name so external jobs
can be correlated without conflating the same vulnerability and component in
different projects. Numbered migrations live in
`dtvp/migrations/code_analysis_results`; a legacy sibling JSON cache imports on
first use.

Automatic scans deduplicate against saved results and the live queue using a
fingerprint of the vulnerability, target, versions, components, dependency
context, aliases, CVSS, and static guidance. A changed fingerprint is eligible
again; `DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS` can additionally age out a
matching result.

Follow-ups use `source=follow-up`, retain `parent_run_id`, and prefer the
analyzer's `/jobs/{job_id}/follow-up` endpoint. Otherwise DTVP sends a normal
request with bounded persisted parent context.

The code-analysis dashboard polls every five seconds while work is active and
every 15 seconds while idle, pauses in hidden tabs, and applies per-client
jitter. DTVP shares a short-lived dashboard snapshot across clients so one
polling wave causes one analyzer health/jobs lookup and one recent-result
query.

Result APIs:

- `GET /api/code-analysis/results`
- `GET /api/code-analysis/results/{run_id}`
- `DELETE /api/code-analysis/results/{run_id}`
- `POST /api/code-analysis/results/{run_id}/compact`
- `POST /api/code-analysis/results/{run_id}/benchmark`
- `GET /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-results`
- `POST /api/projects/{project}/vulnerabilities/{vuln_id}/analysis-cleanup`

Vulnerability cleanup can independently remove saved analyzer assessments or
run records. Run cleanup reconciles DTVP queue entries with Agentyzer jobs,
including orphaned records that exist in only one store. It skips queued and
running work unless active cancellation is explicitly selected. The project
workspace exposes complete vulnerability cleanup plus per-run cleanup, while
the existing result deletion API remains available for assessment-only clients.

### Project Workspace And Dashboard

The vulnerability card presents Code Evidence as a target-oriented workflow.
For analysts, the target-oriented runs section leads; reviewers start with the
Combined assessment because it is their primary decision input. The expandable
`Run new analysis` control sits inside the runs section above its compact latest-
run list. Each target row keeps View, Use as draft, Earlier runs, and Delete
actions on the right. View reveals a dismissible inline outcome with the
vulnerability and assessment executive summaries plus follow-up question
context directly beneath that row. Legacy results without an executive summary
fall back to their rationale. The list
indents the complete selected-run detail region—including every disclosure—so
the owning row remains visually unambiguous. Assessment draft, benchmark,
component results, ticket, version coverage, LLM conversation, and pipeline
evidence are peer disclosures in the same run context and start collapsed.
Derivative benchmark records do not replace a target's latest analysis row.
Live analyzer logs treat the analyzer-provided progress log as authoritative;
the current-activity and active-agent snapshots are fallback state rather than
additional log records. Repeated model-wait heartbeats replace the prior entry
for the same analysis stage, so a slow model call appears as one elapsed-time
status instead of three new rows every 15 seconds.
The LLM conversation opens in a taller vertically resizable viewer and can move
into an accessible near-full-screen dialog without changing renderers or losing
context. Each captured turn is a numbered request/tool/response timeline with
explicit `Agentyzer → Model` and `Model → Agentyzer` provenance, raw request and
response copy actions, and token/model metadata. Timeline stages are separately
collapsible: verbose requests and tool evidence start closed, model responses
start open, and conversation-wide controls switch between overview and full
audit views. Expanded stages use bounded, keyboard-focusable scroll regions so
one long prompt, tool trace, or response cannot consume the whole conversation
viewer. Inline and nested regions chain unused wheel movement to their parent,
so a short section or a reached scroll boundary does not trap page scrolling;
only the full-screen dialog contains overscroll. A summary above the timeline
reports Local-to-LLM messages and prompt
tokens, LLM-to-Local responses and completion tokens, total/captured timing,
per-turn LLM and inferred local-tool timing, retries, context adaptations,
models/providers, tool requests/results/failures, repository inspections, and
trace coverage when older providers omit telemetry. The per-turn timing table is
itself bounded and keyboard-scrollable for long conversations. Current configured prompts are
shown only as a clearly warned fallback when a run did not persist its actual
conversation, so configuration cannot be mistaken for run evidence. An
**Additional guidance used** panel extracts component/reviewer guidance from
the persisted model-request messages and identifies the exact turns that
received it. Saved queue guidance without a matching trace is labeled as not
verifiable, while storage-policy redaction is called out explicitly. Static
component guidance is resolved for both initial and follow-up runs against the
component actually selected for that request.
The Combined assessment displays the worst latest target verdict and a compact
cross-component executive summary before a draft is staged. Full component
reasoning remains in each saved run. Preview and draft preparation share the
same verdict-to-assessment
ordering (`EXPLOITABLE`, `IN_TRIAGE`, then `NOT_AFFECTED`) and use analyzer CVSS
only to break ties within the same state.

The metadata badge and lightweight history for the current
vulnerability and aliases load automatically for every component in the active
scope. History is paged until complete, grouped per component, and nests a
follow-up's predecessor chain beneath its latest successor while retaining
earlier independent runs. A full result (including its LLM conversation) loads
only when its row is opened. Runs can then be removed, applied, benchmarked, or
used as parents for follow-ups. Using one as an assessment draft resolves its
persisted target team, switches directly to that Assessment subview, and
populates the visible form deterministically; an unmapped result is reported
instead of being assigned to an unrelated first team. When any completed scoped
result exists, the new-analysis form starts collapsed; rerunning remains an
intentional action for changed scope or evidence.

When several components of one vulnerability have their own saved analyzer
result, `Use latest results as draft` uses the current scope. With an active
Team filter, it stages only the filtered team's component results plus one
General reference; it never stages another team's draft. Without a Team filter,
saved or manually edited team assessments are preserved and the latest analyzer
proposal is staged only for teams that are still missing a decision. The
General draft references the effective team blocks and uses their worst state
without duplicating their evidence. An existing independently authored General
assessment remains authoritative in either scope.
Benchmark runs, unfinished runs, and superseded runs of the same component are
never candidates, and components without a team mapping are reported instead of
silently dropped. Staged drafts land in the `Assessment` tab for explicit review
before saving.

An affected result produces a copyable Markdown remediation ticket. Setting
`DTVP_JIRA_CREATE_URL` adds an action that copies the draft and opens Jira's
create screen using the browser's existing session; ticket text is never placed
in the URL or sent with Jira credentials.

The header `Code Analysis` page is an operations dashboard for DTVP queue
slots, saved results, analyzer health/jobs/agents/progress, configured model and
backend, automatic sweep state, logs, cancellation, and abort controls. It is
not a second assessment editor.

### Benchmarks And Agentyzer

Selecting a saved normal analysis run automatically compares it with an
existing assessment. DTVP computes deterministic state, justification, and
CVSS anchors, then uses Agentyzer `POST /benchmark/compare` for semantic
reasoning. If the analyzer is unavailable, DTVP returns a labeled deterministic
fallback. No benchmark is shown for `NOT_SET` assessments. Ratings are 1/F
(contradiction) through 5/A (strong agreement).

Bundled Agentyzer lives in `agentyzer/`, runs at `http://agentyzer:8000` in
Compose, and exposes host port `8095` by default. PM2 uses the mock analyzer on
that port. DTVP optionally uses Agentyzer's compact, follow-up, and prompt
inspection endpoints; persisted DTVP context remains the fallback.

Agentyzer prompt bundles live under `agentyzer/config/prompts/`. They enforce
structured, conservative assessment contracts and support native tool calls or
text directive fallbacks for allowlisted web/package/source research. The
`clone_repository` / `CLONE_REPOSITORY` tool can additionally shallow-clone a
dependent public HTTPS repository into Agentyzer's persistent local cache and
analyze a narrow dependency, symbol, API, or call-path focus. It enumerates and
searches the complete eligible committed tree, then runs matching Git blobs
through the same language-aware import/call-site parsers and structural
extraction used for the primary repository before returning bounded evidence.
It never checks out or executes repository code, rejects credentials and
non-public destinations, and is constrained by host, clone-count, timeout,
repository-size, file-size, analysis-file, and output limits. External source,
comments, documentation, strings, tests, and prompt-like content are explicitly
delimited as untrusted evidence and can never become analyst guidance or change
the task/tool contract. Java dependency discovery covers Maven and Gradle build,
lock, and version-catalog formats.

The primary-repository pipeline also has an `archive_inspector` tool. It
discovers archives contained in the prepared checkout, expands supported
members into an isolated per-analysis workspace, and exposes the resulting
manifests and source files to the normal dependency, version, AST, and code
scanners. Archive contents are never executed. Extraction rejects traversal,
links, special filesystem entries, encrypted members, duplicate files, and
configured size or count limits; malformed archives are recorded as partial
evidence without preventing other archives from being inspected.

### Automatic Scanning

Automatic scanning requires both `DTVP_AUTO_CODE_ANALYSIS_ENABLED=true` and a
configured analyzer.

- Project refresh queues genuinely new groups only when every instance is
  `NOT_SET` with no assessment text.
- A scheduled single-worker sweep starts after one interval and checks cached
  findings and live projects every `DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS`.
- Reviewers can trigger an immediate background sweep from the dashboard.
- Targets require an explicit team mapping or the first explicitly mapped
  parent on a dependency path; wildcard ownership is insufficient.
- Any global, team, or legacy assessment marks a group handled.
- Stale automatic queue items are cancelled when the group becomes handled or
  loses its eligible target. Manual requests are not cancelled.

DTVP and Agentyzer default to one running scan. Raise
`DTVP_ANALYSIS_QUEUE_CAPACITY` and `AGENTYZER_MAX_CONCURRENT_JOBS` together only
when the analyzer host and model backend support parallel scans. Agentyzer
serializes shared-cache Git mutations with per-repository filesystem locks and
analyzes configured repositories in detached per-run worktrees, so concurrent
components mapped to the same repository do not share mutable scan files.
