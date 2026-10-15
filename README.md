# DTVP

## Ground-up redesign

The agreed target is recorded in the [current rewrite design](docs/rewrite-plan.md#agreed-ground-up-design).
Product versions are independent branches with immutable release tags. Complete
logical state revisions in a local knowledge journal are authoritative;
PostgreSQL holds rebuildable projections. Shared assessments have explicit
version/context coverage and pinned references in each branch. UI and CLI use
the same backend workflows and contextual evidence synthesis.
VDR and VEX files are required evidence inputs, with scoped application to
components, product versions and usage contexts; imports preserve provenance
and remain distinct from DTVP's human approvals. See
[VDR/VEX ingestion](docs/rewrite-plan.md#vdr-and-vex-ingestion-and-application).
Parallel versions support [merge-aware synchronization proposals](docs/rewrite-plan.md#merge-aware-synchronization)
using pipeline provenance and target inventory, with explicit coverage review.

Implementation has started on `rewrite/knowledge-journal`. The first slice adds
immutable complete-state manifests, atomic multi-branch publication, immutable
tags, a rebuildable SQL projection and journal-backed inventory import/comparison
under `/api/v3`, with contextual assessment/review, coordinator scoring, curated
metadata, bound proposals, semantic comparisons and retained history.
The Review tab retains `/api/v2`; the Knowledge tab uses the journal-backed workspace.
VDR/VEX JSON semantic subsets are available; advanced scope reconciliation and
merge synchronization remain planned. Existing v2 data is not migrated or made
journal-authoritative implicitly.
Reuse decisions compare original v1 on local
`main` (`bdc7ba4`), committed refactoring and uncommitted work separately; see the
[baseline and reuse matrix](docs/rewrite-plan.md#baseline-and-reuse-matrix).
Latest fetched `origin/main` is `f236a96`; its corrected team/version statistics
are captured as rewrite acceptance requirements, including recorded versus
approved coverage and filtered chart scope.
Agentyzer remains external even though the historical `main` tree bundled it.

[DevSecOps concept and critical review](docs/devsecops-evidence-concept.md) covers
modern/legacy composition acquisition, multi-SBOM product assembly, CPE proposals,
vulnerability evidence, license clearance and architecture documentation. DTVP
coordinates evidence and controlled publication; it does not establish complete
discovery, legal clearance or regulatory compliance from imported data alone.
Scope is cybersecurity, license compliance and architecture documentation, not
safety analysis. SBOM correctness is the producer's responsibility; DTVP validates
its input contract and exposes coverage limits. Generator's established audit
documents are the output baseline to preserve while replacing DT reads with DTVP.
CPE discovery has an internal offline module preserving reviewed mappings and
provenance; complete service migration and refresh remain planned.
The concept's [integration status](docs/devsecops-evidence-concept.md#reviewed-integration-increments)
records isolated sibling fixes, validation and remaining cutover gates. Native
consumer commands and v2 compatibility boundaries are in [consumer contracts](docs/consumers.md).
Its [pipeline examples](docs/devsecops-evidence-concept.md#exemplary-pipeline-integration)
map PR/nightly builds, legacy C/C++, containers, supplier inputs and parallel
versions to intake, review, release gates, documentation and monitoring.

### Explore the new core

Team selectors retain v1 semantics: namespace/name matching, known-empty versus
unknown namespace, case modifiers, PURL selectors and deterministic specificity.
Name-only rules do not match known nonempty namespaces. Versionless PURL rules
span package versions; explicit version/qualifiers/subpath match the full PURL.
The primary team and descriptive aliases remain distinct; aliases do not add
required reviewers. Wildcard ownership is a fallback after recursive delegation.

Rebuild/start the isolated playground, then run the API-only scenario:

```bash
uv run python scripts/playground.py up
uv run python scripts/knowledge_demo.py
```

The scenario imports independent `7.1.1`/`7.1.2` inventories into the synthetic
Platform project, tags a state and prints their delta. It is repeatable and does
not reset existing playground work. Use `--url` for another playground address.
Open the Knowledge tab to browse these inventories.

`POST /api/v3/projects/{id}/versions/{version}/imports` requires an idempotency
request ID, expected head (null to create), source, monotonic source build number,
timezone-aware observation time, `completeness: complete` and an SBOM object.
Optional `predecessor` branches a new version from an existing product state.
The API rejects authority changes and stale builds rather than guessing ordering
across pipelines. JSON request data is retained as canonical JSON. For byte-exact
CycloneDX JSON/XML or SPDX 2.3 JSON intake, post multipart `file` plus JSON
`metadata` (the import fields without `sbom`) to `.../versions/{version}/files`.
`GET .../states/{state}/source` returns that pinned original with its SHA-256 and
representation headers; project permissions apply to downloads too.
`GET .../states/{state}/artifacts/{sha}` downloads any artifact explicitly pinned
in that state, including retained source responses and reports. Current project
permissions and state membership are checked; knowing an object hash grants no
access. Downloads preserve bytes and include their SHA-256.
The HTTP CLI preserves file bytes too:

```bash
uv run dtvp knowledge --url http://127.0.0.1:8900 import-file \
  --project PROJECT_ID --version 7.1.2 --file bom.json --metadata import.json
```

`import.json` contains the same explicit import metadata, request ID and expected
head. Reuse it unchanged after uncertain responses; the CLI never invents retry
identities or replaces concurrency pins. Add `--part PART_ID` for constituent
intake; product assembly remains a separate explicit publication.

Optional import `context` records subject kind/digest, target, platform,
configuration, source revision, pipeline run, collector/version/method, limitations
and separately declared package/dependency/license coverage. Missing coverage
stays unknown; `complete` is snapshot replacement within scope, not verified
product completeness. Ordinary imports cannot change declared scope and silently
overwrite another target/platform/configuration. Native assembly selects pinned
constituent inputs; legacy combined input cannot recover lost provenance.
V3 retains source relationship kinds; SPDX containment is not treated as dependency
topology. V2 retains its earlier conversion behavior until migration.

Exercise file intake and exact-byte retrieval with:

```bash
uv run python scripts/knowledge_demo.py --files
```

For multiple delivery parts, upload to
`POST .../versions/{version}/parts/{part_id}/imports` or `.../files` instead.
`GET .../versions/{version}/parts/{part_id}` returns the current source state.
Constituent references are separate from product branches: intake never changes
the assembled product. Source ordering/authority/scope checks apply per part.

Select inputs atomically with `POST .../versions/{version}/assembly`:

```json
{
  "request_id": "integration-42",
  "expected": null,
  "parts": [
    {"part_id": "backend", "required": true, "state": "<source-state-sha256>"},
    {"part_id": "frontend", "required": true, "state": null}
  ],
  "coherence": {"status": "unverified"}
}
```

The complete declaration retains missing required parts as incomplete candidates.
`GET .../states/{state}/assembly` returns pinned selections and collection evidence.
Omitting prior parts requires exact `removed_parts` and `removal_reason`; clearing
a prior selected input requires `withdrawn_parts` and `withdrawal_reason`.
Changing required/optional policy requires `policy_change_reason`. Assemblies
retain assessments, reviews, scoring and ownership; inventory/source observations
are replaced by the explicit selection. Source-local references are namespaced by
part, including roots, dependency edges and findings; equal PURLs are not merged.
Comparison includes part-level changes before the underlying record delta.

Release tags reject missing required inputs, empty selections and unverified
coherence. `coherence.status: producer_declared` requires `build_id` and `rationale`;
this declares the selected builds compatible, including deliberately reused parts,
but does not verify composition, approvals or release readiness beyond this input
gate. Optional missing parts stay visible. Original constituent bytes remain
retrievable by pinned source state after replacement or removal.

This slice supports delivery parts within one product/version, not overlapping
evidence views, nested assemblies or cross-part relationship mapping. Each new
product version needs its own constituent imports; cross-version source reuse
and semantic identity reconciliation remain planned. Unresolved relationship
endpoints fail assembly; external-document references need explicit reconciliation.
The Knowledge tab shows assembled findings and their consuming contexts.
Explore a repeatable two-part nightly update against the running playground:

```bash
uv run python scripts/assembly_demo.py
```

### Versioned ownership and consuming contexts

The journal-backed assessment engine supports immutable draft/submitted revisions
and independent reviews of exact vulnerability/context/version targets. Explicit
multi-version coverage is reviewed per target; a range or matching name does not
prove applicability. Branching from an approved state retains historical records
but never extends review or published-score scope to the new version. Pending revisions retain valid prior approved pins. Material
source, artifact, graph or advisory changes require reassessment; identical inputs
and ownership-only changes retain coverage. Not-affected submission requires a
specific justification. Historical absent assessments remain retained. API/UI
adapters use this engine rather than implementing separate approval logic.

### Assessment API and CLI

`GET /api/v3/projects/{id}/versions` lists current product branches.
`GET .../versions/{version}/workspace` returns contextual findings and full filtered
statistics; basic filters are `team_id`, `q` and `lifecycle`, with bounded `offset`/`limit`
and an optional pinned `expected` state. Detail is available at
`.../workspace/{context_id}/{vulnerability_id}`; its optional `expected` state pin
rejects a changed queue baseline before opening detail. Source assertions, original ratings,
current/pending coverage and published contextual scores remain separate.
Advanced filters cover `source_severity`, `contextual_severity`, `applicability`,
`scoring_status`, `team_review`, `provider`, `cvss_version`, `dependency`,
`source_conflict` and `component`. They apply before statistics and pagination.
Missing evidence stays unknown; outdated contextual scores do not match current
severity. Provider filters include received scoring proposals without assuming
eligibility. Provider attribution does not prove independent corroboration. Dependency
filters use reported topology, and contradictory source ratings compare like CVSS
versions. The Knowledge tab collapses these options by default, with explicit
Apply/Reset, shareable scoped URLs and user-local saved views.

`POST .../assessments/{assessment_id}/draft` or `.../submit` requires `request_id`,
exact `expected_versions`, `expected_revision` (null for a new assessment),
`targets` (`version`, `context_id`, `vulnerability_id`), applicability `state`,
`rationale`, optional `justification`, `conditions` and `evidence`. Targets must
share a vulnerability and compatible component lineage. Weak local references
need explicit supporting conditions; coverage is never extended automatically.
`POST .../reviews` pins `assessment_id`, `assessment_revision`, exact `targets` and
version heads, with `action: approve|request_changes` and a review rationale.
Assessor/reviewer authority requires both project access and the responsible
team's role; authors cannot approve their own revisions. Admin alone grants
neither assessment, review nor rescoring authority.

Coordinators use `POST .../scoring/preview`, then explicit `.../publish` with the
returned `preview` hash. Inputs include `request_id`, `expected_versions`,
`targets`, original `base_vector`, contextual `vector` and `rationale`. Publication
requires current approved coverage for every context of that vulnerability in
each selected version. Unrelated findings/versions do not block it. Original Base
metrics stay unchanged; pending drafts do not revoke valid approved score inputs.
Material changes make old coverage/scores visibly outdated rather than deleting them.

The CLI uses the same HTTP contracts without opening the application database:

```bash
uv run python -m dtvp.cli knowledge --persona analyst workspace --project PROJECT_ID --version 7.1.1
uv run python -m dtvp.cli knowledge --persona reviewer request POST /api/v3/projects/PROJECT_ID/reviews --body review.json
```

Production CLI calls read a bearer credential from `DTVP_API_TOKEN` (or the named
`--token-env` variable); `--persona` works only against an enabled playground.
Workspace flags mirror advanced server filters with hyphens, for example
`--source-severity critical --team-review approved --dependency transitive`.
Displayed totals always come from the server's complete filtered selection.
Team labels come from that authorized selection, including teams outside the
viewer’s memberships; showing a label grants no team role.
Use workspace `--json` for complete machine-readable rows and evidence. Mutations
forward the explicit JSON payload; no approval or scoring logic lives in the CLI.

### Native Dependency-Track intake

An administrator binds each product version independently using `PUT
/api/v3/projects/{id}/versions/{version}/connectors/dependency-track` with
`external_project_id` and `expected_external_project_id` (null initially).
The v2 global binding remains separate; no implicit fallback assigns it to every
native version. Deployment owns DT URL/read credentials. Source authority includes
the configured endpoint and DT UUID; changing a binding cannot silently replace
an existing branch from another authority.

`POST .../versions/{version}/imports/dependency-track/jobs` takes `request_id`,
expected head (null for a new branch), monotonic `build_number`, timezone-aware
`occurred_at`, optional collection `context`, `predecessor` or constituent `part_id`.
The worker makes GET requests only, rechecking permissions, binding, target and
lease between requests. It checkpoints complete composition, finding pages,
full legacy analysis, raw response bytes and an immutable capture before publishing.
Incomplete retrieval never advances the baseline. Exported SBOM vulnerability
claims and finding API claims stay separate, including contradictions; source Base
and tagged/plain legacy documentation remain attributed evidence, not approvals.

DT reads are nontransactional: captured originals and explicit consistency limits
do not establish a single remote snapshot or complete product discovery.
`GET .../versions/{version}/source-jobs` and `/source-jobs/{id}` expose bounded safe
status; explicit author-only `/retry` and `/cancel` use current permissions. After
capture, retries use exactly that capture and expected head, never a fresh upstream
fetch or implicit rebase. CAS conflicts require resolving the target explicitly;
unknown publication outcomes replay the original receipt. SQL job checkpoints
require operational backup. No DT writeback is implemented by this path.
The Knowledge workspace includes a collapsed source panel for the selected version:
explicit management binding, build/time intake, safe job refresh and backend-allowed
retry/cancel. Inputs survive conflicts and uncertain responses. New-version and
constituent intake remain available through the HTTP CLI/API.

### Withdraw an incorrect baseline

`POST /api/v3/projects/{id}/versions/{version}/withdrawal` takes `request_id`,
expected current head and a reason. It withdraws the active single-source
inventory selection, creating an empty current view while retaining assessments,
metadata, reports, original bytes and immutable release tags. Nothing is physically
deleted. The workspace explicitly marks withdrawal; it is not a clean vulnerability
result. Withdrawn states cannot be release-tagged. Corrected intake keeps the same
source/scope authority and requires a newer build number. Reappearing identical
contexts recheck retained coverage. Assemblies use explicit part withdrawal instead.

`GET .../states/{state}/retained-assessments` lists retained assessment revisions
for absent findings by default, with optional recorded `team_id`, `absent_only`,
`offset` and `limit`. The Knowledge workspace offers a collapsed history list.
Recorded team labels/targets are preserved across reassignment; these records are
historical evidence, not current approvals or proof of remediation.

### Offline journal verification

`uv run dtvp verify-knowledge --directory /path/to/artifacts/knowledge` verifies an
existing committed journal without SQL: publication/reference chain, all historical
states/parents and retained objects. It reports the pinned head and checked counts,
fails on corruption and performs no repair. Uncommitted orphan files are excluded.
Operational SQL data still requires its own backup; see [recovery](docs/deployment.md#native-journal-recovery).

### Retention maintenance preview

`GET /api/v3/projects/{id}/maintenance/retention-preview` requires project management.
It inspects exact targets across all current branches and tag-protected revisions,
including review-pinned older revisions. Shared assessments remain active while
any covered target is present. Unknown scope never becomes a candidate. Revision
age is explicit and does not establish disappearance date or obsolescence. Full
counts accompany bounded revision/logical-assessment pages; `expected=PLAN_HASH`
rejects changed references during pagination. The HTTP CLI can use `knowledge
request GET /api/v3/projects/ID/maintenance/retention-preview`. This dry run writes
nothing and makes no physical storage estimate. Archival/application, retention
policy and journal garbage collection remain planned; history is not deleted.

### Curated component metadata

`PUT /api/v3/projects/{id}/versions/{version}/metadata` explicitly replaces
annotations for one exact component occurrence. It requires project management,
`request_id`, expected branch head, expected metadata revision (null initially),
`component_ref`, typed `annotations`, `provenance` and `rationale`. Cybersecurity
criticality/exposure/mitigations/testing, deployment/usage and supplier/support
information remain separate from imported facts. No approval or license clearance
is implied. `GET .../states/{state}/metadata` lists current, stale, absent and
out-of-scope records; `component_ref` selects one. The Knowledge detail displays
these annotations and their attribution.

Annotations survive baseline replacement and retain immutable revisions. Identity
changes mark them stale; removed components retain absent records. Inherited
annotations from another product version require explicit adoption. Current
annotations and provenance throughout the consuming tree bind assessment/score
fingerprints: changes require revalidation. Editing only the recording rationale
without changing annotations/provenance does not invalidate coverage. Baseline
updates retain artifact pins for authored revisions and external reports; retention
and garbage collection remain explicit future maintenance work.

### License evidence worklist

`GET /api/v3/projects/{id}/states/{state}/license-worklist` returns pinned,
source-attributed license evidence with `offset`/`limit` and full-set statistics.
SPDX declared, concluded and file-derived expressions remain separate, including
`NONE`, `NOASSERTION` and custom identifiers. CycloneDX expressions, identifiers,
names and embedded evidence remain verbatim. Multipart rows retain constituent
format/provenance and declared collection coverage. No expression compatibility,
obligations, legal conclusion or license clearance is inferred; absent/malformed
information stays explicit. Document-level custom text remains in original sources.
Explicit organization dispositions are separate from these source facts.

`POST .../versions/{version}/licenses/draft` or `.../submit` records a human
concluded expression, allowed/restricted/prohibited/unresolved disposition,
obligations, conditions, evidence, distribution/modification/linking assumptions,
rationale and provenance for one component occurrence. It requires `request_id`,
expected head, expected disposition revision and the dedicated `license_assess`
capability. `POST .../licenses/reviews` requires `license_approve`, exact submitted
revision, action and rationale; authors cannot approve their own revision.
The `license_analyst` and `license_reviewer` roles are distinct from vulnerability
roles and administrators. Sharing and scoped tokens can grant these capabilities
only within the caller's authority.

The Knowledge workspace has a collapsed **License evidence and review** panel,
with original facts, explicit usage assumptions and independent disposition review.
Pending drafts preserve valid approved pins. Material inventory, license evidence
or applicable curated context changes require revalidation; ownership/upload
bookkeeping does not. Whole-product context is conservative: unrelated material
component changes can also require revalidation. Historical states retain their
pins. An approved organization disposition is an attributed judgment under stated
assumptions; DTVP does not infer legal permission, expression validity or compatibility.
The playground includes separate license analyst/reviewer personas without reset.

### Historical state comparison

`GET /api/v3/projects/{id}/refs` lists product branches and immutable tags.
`GET .../history?version=7.1.1` lists reachable product revisions. Both paginate
with `offset`/`limit`; configuration and constituent-source states are excluded.
`GET .../compare/details?before=SHA&after=SHA` returns bounded component,
dependency and contextual-finding changes with full-set counts. Classifications
separate material evidence, bookkeeping, ownership, assessment, review and scoring.
Retained absent assessments stay visible. Comparisons read immutable journal
states without loading historical data into live PostgreSQL tables. Current
intelligence reevaluation and comparison caches remain planned. Exact source-local
references determine identity: changed references appear as remove/add, never a
name-based match or proof of remediation.

The HTTP CLI exposes `knowledge refs`, `knowledge history` and
`knowledge compare --project ID --before SHA --after SHA`, with `--json`,
`--offset` and `--limit`. The Knowledge tab offers the same comparison within the
selected product, with compact before/after details.

### Assessment synchronization preview

`POST /api/v3/projects/{id}/synchronization/preview` takes pinned `source`, `target`,
optional common knowledge `basis` and explicit `context_mapping`. It returns a
bounded preview with full counts and a stable digest. No basis is invented;
without one, comparison is explicitly two-state. A supplied basis must be a
committed ancestor of both states. Categories distinguish reusable content,
already-covered targets, required review, conflicting edits, absent applicability
and unresolved scope. Exact source-local references/material evidence govern
matching; explicit maps cannot collapse different contexts or establish equivalence.
Target inventory, reviews and published scores remain unchanged. Knowledge ancestry
never proves a software merge. Verified pipeline merge provenance and automatic synchronization remain planned.
`POST .../synchronization/drafts` explicitly extends one source assessment's logical
ID into a target-only draft. It requires the source author, current source/target
heads, exact preview/revision, explicit target conditions and a reason. Any existing
target assessment or review blocks overwrite. Atomic publication guards the source
head and preserves its approval; source approvals and scores never transfer.
Successful retries replay the same receipt even after either branch advances.
The draft must still be submitted and independently reviewed for its new scope.

The comparison panel offers a collapsed reuse preview between selected states.
CLI: `knowledge synchronization --project ID --source SHA --target SHA`, optionally
`--basis SHA`, `--mapping contexts.json`, `--json`, `--offset` and `--limit`.

### Knowledge workspace and interactive demo

The Knowledge tab provides searchable product/version selectors, team/state/text
filters, bounded finding lists and full filtered workload statistics. Its compact
list/detail view keeps source and published severity visible, with readable long
descriptions and expandable evidence. Assessment, independent review and coordinator
scoring share the backend contracts; analyst controls do not expose rescoring.
Scoring compares Original/Published/Proposed values and requires a current preview
before explicit publication. Conflicts and uncertain writes retain the user's
input; unchanged retries reuse the original idempotency key. Light/dark themes
use the existing application tokens.

In the isolated playground, open Knowledge and choose **Load workflow demo**.
It creates a dedicated synthetic project with two versions/teams, unassessed,
draft, submitted, approved and stale coverage plus a historical tag. Repeated
loads preserve interactive work and other project policies. Seeding uses the real
domain services and publishes the complete fixture atomically. The seed endpoint
is absent in production; no third-party service is contacted.

**Load specialist demo** creates a separate synthetic project with qualified native
input examples, a computationally eligible VScorer proposal, explicitly ineligible
Agentyzer evidence and a submitted license disposition. These exercise comparison
and human review without claiming a real source scan or granting approval. Both
scenarios preserve interactive changes on repeated loads. API callers select it
with `POST /api/v3/playground/knowledge/seed {"scenario":"specialists"}`.

### Internal CPE proposals and VScorer inputs

CPE discovery now has an internal offline module. `GET/PUT
/api/v3/projects/{id}/cpe` reads or explicitly replaces versioned catalog/rule
inputs; writes require project-management permission and an expected policy head.
`GET .../states/{state}/cpe?component_ref=REF&policy=POLICY_SHA` returns pinned,
attributed candidates. Omitting `policy` selects current configuration. Reviewed
aliases and explicit CPE/PURL mappings are supported; package versions,
qualifiers and subpaths are retained. Candidates do not establish vulnerability
applicability or change component identity. Live feeds, fuzzy ranking and complete
standalone CPE-service migration remain planned.
The Knowledge detail offers an on-demand specialist panel: attributed CPE
candidates with explicit refresh, VScorer input preparation after original Base
selection, and qualified Agentyzer request downloads. Preparation contacts no
external analysis service and never adopts a candidate. VScorer downloads use
server-generated canonical file bytes, checked against receipt hashes before
being offered; browser JSON serialization cannot alter the bound artifacts.

`POST .../states/{state}/vscorer-input` takes `context_id`, `component_ref` and
explicit `base_selections` keyed by CVE. It derives a schema-validated CycloneDX
consuming tree, strict focused CVE input, coverage limitations and an exact
`dtvp.vscorer-source/1` receipt. Non-CVE identifiers and unsupported/missing Base
vectors remain excluded explicitly. The source Base is never replaced by a
contextual vector. This requires snapshot permission and makes no remote call.
VScorer's separate `feat/dtvp-context-binding` branch accepts this optional receipt
and retains it in proposals; commit `3994254` passed independent Python and
architecture reviews. It is not merged into the sibling checkout. Receipt hashes
establish artifact consistency, not remote publisher authenticity or DTVP approval.

Native VScorer results return through
`POST .../versions/{version}/proposals/vscorer` with `request_id`, expected branch
head, the assessment's `source_binding` wrapper and one native `finding` response.
DTVP reproduces the pinned input receipt, validates the focused component/CVE and
unchanged Base, recalculates supported contextual scores and retains the raw report.
Workspace rows, CLI and UI compare these proposals with source/published values.
Repeated report imports retain each importer’s attribution; retries reuse the original receipt.
Withheld, invalid and stale proposals remain attributed evidence with explicit
ineligibility; eligible proposals still require coordinator rationale, preview,
current independent team reviews and explicit publication. Importing a result
never creates an assessment, review or published score. Provider identity remains
caller-asserted; hashes verify artifact consistency only.

### Known-ID advisory enrichment

Product evidence imports also accept `dtvp.advisory-feed/1`: an explicit document
`id`, attributed `publisher` and `advisories` containing normalized `advisory`
facts plus original provider `raw` objects. Existing source ordinals, expected
heads, supersession, withdrawal and baseline reapplication apply unchanged.

These documents enrich exact vulnerability identifiers already reported by the
baseline SBOM/DT source, retaining independent descriptions, ratings, references
and aliases. They never match a new package, infer affected versions or turn
provider status into DTVP applicability. Unknown identifiers stay unresolved;
removed baseline findings are not resurrected. VEX-only claims are not enrichment
seeds in this initial subset. Contradictory ratings and original Base facts stay
separate. Material fact changes require review revalidation; withdrawal can restore
still-valid pinned coverage. Native live NVD/CIRCL/OSV refresh jobs and extended
non-US adapters remain planned; v2 connectors retain their separate runtime.

### Issued consumer exports

`POST /api/v3/projects/{id}/states/{state}/exports/bundle` explicitly archives exact
native bundle/manifest bytes under current read permission. The response includes
an issuance state, source receipt, serializer/material-fingerprint versions and
state-authorized file URLs. `GET .../issued-exports/{receipt_sha}` reads issuance
metadata; `/files/{filename}` serves its original bytes with SHA-256. Product heads
and human approvals are unchanged. Only committed product states can be issued.

Specialist input preparation likewise retains exact payloads, files and unchanged
native receipts. Repeating the same source/selector returns frozen inputs before
running current serializers. Returned results resolve issued receipts first;
corrupt issued data fails closed, never silently falls back to regenerated bytes.
Older unissued receipts retain their previous reproduction path and its compatibility
limits. Direct state `/bundle` remains a current-serializer convenience; controlled
outputs should archive issued files and receipts instead.

One project reference points to a complete sharded immutable export index; exports
do not add global references per finding. Exact bytes and source parents remain
journal-owned and recoverable. Uncertain issuance requires the identical retry.
Hashes establish consistency, not external provider identity or approval.

### Native analysis jobs

`PUT /api/v3/projects/{id}/connectors/agentyzer` binds an administrator-approved
repository name. With external Agentyzer configured, `POST
.../versions/{version}/analysis-jobs` accepts `request_id`, expected head,
`context_id`, `vulnerability_id` and optional `user_guidance`. It requires read,
snapshot and evidence permissions, qualified source inputs and the exact repository
binding. The SQL worker uses the native receipt; no v2 release/finding is created.

Jobs checkpoint submission intent before POST and the remote ID/report before
continuing. Agentyzer currently offers no submission idempotency guarantee: an
ambiguous submission becomes `submission_unknown`, with no automatic resubmission.
Known-job polling is safe to retry; completed reports survive baseline drift as
stale evidence. The worker rechecks credentials, permissions, endpoint and repository
binding at each step. Exact publication retries resolve existing journal receipts.
Projection failures report pending recovery without discarding committed evidence.

`GET .../versions/{version}/analysis-jobs` supports exact context/vulnerability
filters and bounded paging. `GET .../analysis-jobs/{id}` shows safe status; explicit
`POST .../{id}/retry` or `/cancel` requires the submitting actor and current
permissions. Cancel stops local work, not a claimed remote cancellation. Unknown
submissions need reconciliation or a deliberately new request. Operational SQL
backups remain necessary for jobs. Authenticated remote-ID reconciliation and
native follow-up conversations remain planned.
The specialist panel shows bounded jobs for the selected context/vulnerability.
Qualified input preparation precedes an explicit queue action. Status refresh,
retry and local cancellation are explicit; backend capabilities control actions.
Failed submissions preserve guidance and retry identity. Unknown submissions show
reconciliation guidance without a retry button.

### Qualified Agentyzer inputs

SBOM intake optionally accepts `context.analysis_source` with a repository name
and exact 40-hex Git commit. This is an explicit producer declaration; unqualified
`source_revision`, tags and branch names never establish an analysis source.
`POST /api/v3/projects/{id}/states/{state}/agentyzer-input` takes `context_id` and
`vulnerability_id` under snapshot permission. It derives a native request plus
`dtvp.agentyzer-source/1` receipt pinning consuming context, focal package/version,
source SBOM, constituent selection, declared subject digest and material fingerprint.
Missing, inconsistent or unavailable source information returns explicit not-ready
coverage. The endpoint contacts no service and creates no job or human approval.
An external orchestrator still authorizes the repository; a source commit does not
verify a built binary/container. The existing v2 connector stays separate.

`POST .../versions/{version}/proposals/agentyzer` imports `request_id`, expected
head, the exact `input_receipt`, `raw_report` and optional `source_label` under
project evidence permission. For eligible native scope binding, wrap the completed
job and report as `{"format":"dtvp.agentyzer-result-envelope/1","job":JOB,"report":REPORT}`.
DTVP reproduces the pinned request and checks structured advisory/package/source
commit consistency. Bare, incomplete or inconsistent reports remain attributed
ineligible evidence; free text never establishes vulnerability identity. Provider
identity and echoed job claims remain caller assertions, not authenticated proof.
Original reports are retained and project-authorized downloads are available at
`.../states/{state}/proposals/agentyzer/{id}/report`. Workspace, CLI and UI expose
current/stale analysis, reasons and optional locally recalculated scoring proposals.
Results never create human assessments, reviews or published scores. Separate
imports preserve each actor’s attribution; identical retries reuse their receipt.

### Imported DT documentation

Native v3 workspaces, bundles and CLI retain previous DTVP-tagged DT team
assessments and metadata-free legacy documentation from `dtvp:dt-analysis`.
Readable records include team-labelled history, rationale, comments, justification,
claimed assessor/reviewer, source state and legacy scoring claims. Missing identity
metadata and conflicting conclusions remain explicit. Imported names never grant
roles or establish authenticated human approval. Scores are source proposals;
matching a supported original Base/vector can make them usable for a coordinator
preview, never automatically published. Oversized/malformed legacy text remains
available in original source evidence with an explicit interpretation limit.

### VDR/VEX intake and application

`GET /api/v3/projects/{id}/evidence` returns bounded document summaries, current
`evidence_state` and version heads. `POST .../evidence/preview` previews matching
and contradictions without committing. `POST .../evidence/imports` requires
`request_id`, `expected_evidence`, the complete `expected_versions` map, `source`,
an explicit increasing producer `revision` and a JSON `document`. For exact file
retention, use multipart `.../evidence/files` with `file` plus JSON `metadata`
(the same fields without `document`). Originals remain available at
`GET .../evidence/{artifact_sha}/source` under current project permissions.

Supported semantic subsets: CycloneDX 1.5/1.6 JSON VDR/VEX, OpenVEX 0.2.x and
CSAF 2.0 VEX full-product-name statements. Exact versioned PURLs retain qualifiers
and subpaths. CycloneDX local refs need embedded identity or the same original
document; arbitrary matching BOM refs cannot establish cross-document identity.
Version ranges, OpenVEX subcomponents, CSAF relationship/group expansions and
unsupported scopes remain explicitly unresolved. This is not complete schema or
signature verification; publisher authenticity remains unverified.

Evidence selection is durable before inventory arrives and reapplied after
nightly import or assembly selection. It never replaces inventory. Explicit
publisher/source/document-bound ordinals govern supersession, not arrival time.
`POST .../evidence/withdrawals` pins expected evidence/version states, `artifact_sha`
and a reason; originals and prior human decisions remain retained. Matching claims
appear in the combined workspace as attributed evidence. Supplier not-affected
statements do not become internal assessments, approvals or contextual scores.

### Pinned consumer bundles

Authorized consumers can read `GET /api/v3/projects/{id}/states/{state}/bundle`,
`.../manifest` and `.../vscorer-worklist`. The manifest pins product/version/state,
section/source hashes, byte length and SHA-256 of canonical bundle bytes. Full
exports include every contextual finding rather than one UI page, original
component metadata/graphs, current and historical assessments, unresolved source
findings and separate original versus contextual scores. Digests establish
integrity, not publisher authenticity or approval.

These are explicit native contracts (`dtvp.knowledge-bundle/1` and
`dtvp.knowledge-vscorer-worklist/1`), not silent substitutes for v2 snapshots or
VScorer's legacy strict CVE upload. Consumer cutover needs its corresponding
adapter and controlled output verification. Current project permissions apply to
every pinned download, including after access revocation.

`GET /api/v3/projects/{id}/ownership` returns the current policy and exact active
version heads. A product manager can `PUT` the same resource with `request_id`,
`expected_policy`, `expected_versions`, `rules` and optional `context_roots`.
Rules contain `selector`, an existing workspace `team_id`, optional descriptive
`aliases`, and optional `versions` (exact product-version names). Rules span all
versions by default; PURL selectors separately support exact package versions.
Duplicate selectors require disjoint product-version scopes.

Policy changes atomically publish the policy and recomputed contexts for every
active product version. Supply the complete `expected_versions` map to prevent
concurrent nightly builds or newly created versions being missed. Imports and
assembly publication automatically capture the current policy; a concurrent policy
change makes stale publication fail. Team mappings never grant data access.

Contexts have one record per consuming root and component occurrence. Explicit
owners delegate recursively; a mapped child shadows its ancestor even through
bypass paths. Several paths within one tree share a context and retain graph
edges. Different consuming trees retain separate contexts. Sibling owner conflicts
and rootless cycles remain explicit; wildcard ownership applies only after
inheritance fails. Primary team and alias labels are not separate required reviews.

By default consuming roots use declared SBOM/part roots and uncovered graph roots.
`context_roots` can select exact source-local refs per product version when an
aggregate root would hide separate applications. Excluded aggregate nodes are
reported in `outside_selected_roots`; disconnected trees remain visible. Missing
dependency information stays `topology_unknown`, even when an explicit owner is
known. Removing a configured root requires explicit policy reconciliation.

`GET .../versions/{version}/contexts` provides bounded pages with optional
`team_id`, `offset`, `limit` and pinned `expected` state. Conflicts appear for each
candidate team. `include_delegated=true` additionally shows that team's consuming
trees with delegated work. Responses identify the policy revision, projection
freshness, matched selectors, owner boundaries and graph provenance. Historical
context details remain available at
`GET .../states/{state}/contexts/{context_id}` under current project permissions.
Context expansion is capped at 100,000 records per state; exceeding it fails publication
without changing the baseline.

Reassignment and inventory changes preserve existing assessment/review records
and immutable tagged states. Current contexts are recomputed, not silently
treated as renewed approvals. Context IDs remain based on source-local refs;
cross-import semantic identity remains planned. Exact contextual assessment coverage
is available through the Knowledge workspace, HTTP API and CLI. Run the isolated scenario:

```bash
uv run python scripts/ownership_demo.py
```

It uses a dedicated project, two versions, shared dependencies, bypass delegation
and a team reassignment; it leaves other project policies untouched.

Read paginated inventory at `GET .../versions/{version}/inventory`; pass its
`state` as `expected` on later pages to detect changes. Create protected tags
with `POST .../tags` and compare pinned revisions with
`GET .../compare?before=SHA&after=SHA`. Authentication and project permissions are
shared with v2. Imported claims are separate from future human decisions.

The journal lives in `DTVP_ARTIFACT_DIR/knowledge` on a local filesystem supporting
`flock`, hard links, atomic rename and directory fsync (including WSL's Linux
filesystem). Back up the complete artifact volume. One filesystem lock serializes
publication and projection, including across API processes. Immutable objects
are stored first; a single durable HEAD replacement publishes all references.
API responses distinguish committed/current (201), committed/projection pending
(202), and uncertain publication (503). Retry the same request ID and input.
Startup catches up committed publications; missing/corrupt committed data fails
closed. No background garbage collection is enabled in this slice.

Rebuild only the new projection, preserving v2/auth/job data:

```bash
uv run python -m dtvp.cli rebuild-knowledge
uv run pytest tests/test_knowledge_journal.py tests/test_knowledge_api.py
```

Migration `0005` runs implicitly. New `knowledge_*` tables hold active records,
reference heads and an applied-publication checkpoint; tags store only references.
They are an initial general projection, not the final indexed finding/context
schema. Diffs currently report changed record keys; cached interactive comparisons
and cross-import identity reconciliation are later slices. Normal application
commands must use the API; local reconstruction is an administrative operation.

## Existing refactoring runtime

DTVP owns SBOM inventory, component metadata, security evidence, assessments and
approvals. Dependency-Track, CyBeats exports and pipeline files are sources.
Generator and VScorer remain separate applications consuming immutable snapshots.
Agentyzer lives in the separate `../agentyzer` repository. DTVP owns imported
analysis evidence; Agentyzer owns its source, dependencies, tests and deployment.

FastAPI + Vue · PostgreSQL/JSONB · local immutable artifacts · no S3 or broker.
Database writes commit before successful HTTP responses and session cookies are sent.

## Try it locally

Requirements: Docker Compose and a current `uv` with Python 3.15 support. One command builds the real application,
starts PostgreSQL, applies migrations and loads synthetic data:

```bash
uv run python scripts/playground.py up
```

Open **http://127.0.0.1:8900** in WSL or Windows; WSL forwards localhost ports
automatically. The playground binds to loopback and contains synthetic data.
If Windows has reserved that port, choose a free `DTVP_PLAYGROUND_PORT` when
starting the playground and open that port instead. Windows reservations are
listed by `netsh interface ipv4 show excludedportrange protocol=tcp`.

Select Platform analyst, submit an assessment, then
switch to Platform reviewer to approve. Platform starts with two synthetic findings;
Operations has a separate private product with one offline-matched finding.
Playground persona switches and resets clear review filters. Empty queues offer
**Show all accessible findings** to recover from restrictive filters.
Products accepts CycloneDX/SPDX uploads and creates Generator/VScorer snapshots.
Replay changed evidence, conflicting sources and partial scans from the banner.
The offline demo matcher and simulated failure run through the durable worker.
System, light and dark themes and expandable technical evidence are available.
The UI retains v1's search-first workspace, collapsible filter rail and compact
findings navigation. On wide desktops (1440px+), a persistent detail pane opens
beside the findings; the queue and search remain usable during assessment.
Filters collapse when details open and can be restored. Smaller screens use the
review dialog, preserving the same draft and workflow when resizing.
Secondary filters and saved views remain collapsed by default.
The compact review sheet opens directly on the assessment. Evidence stays visible
alongside applicability and confirmation on desktop; mobile offers
an expandable evidence panel. One header, a small progress strip and a single fixed
action bar keep context and controls close. Reviewers inspect the submitted assessment
and confirm their checks before approving. Back navigation retains drafts.
Analysts do not rescore: their
submissions contain applicability, justification and supporting evidence only.
Rescoring unlocks per vulnerability occurrence after every required team independently
approves the current evidence. A dedicated security coordinator previews and
publishes scores in **Teams & scoring**. Analysts and reviewers cannot rescore.
Required teams default to the owning workspace; administrators assign additional
teams with explicit read/assessment/approval sharing. Sharing alone does not make
a team required. Each team retains its own decisions and reviewer approval;
users with multiple review teams select their team explicitly. Changing assignments
requires fresh assessments; evidence changes or revised team decisions invalidate
published scores. The playground includes Security coordinator and Operations reviewer.
Existing scoring history, analysis and technical evidence remain accessible. Dialogs retain keyboard
focus, close with Escape and return to the selected finding. Long descriptions open
a spacious view automatically; Expand review switches sizes manually. Evidence and
assessment scroll independently in spacious desktop mode; actions remain fixed.
When source descriptions differ, a source selector exposes each attributed text.
New not-affected assessments require a specific justification and supporting
explanation. Reviewers see both; snapshot findings retain the justification and
reviewed CycloneDX VEX exports include standard justification codes. Older and
imported decisions keep their original documentation; missing reasons are shown
explicitly, never inferred.
Searchable product/release selectors fetch bounded pages; releases show newest first. Browse products by name
and team, with release and active-finding counts. Review filters cover product,
team, component owner, status and text; sorting is stable across cursor pages.
Filter URLs are shareable; saved views are browser-local and scoped to the user.
Next/previous finding navigation and submit/approve-and-next actions retain queue
context and assessment drafts, including when completion removes an item from
the active status filter.
Reviewers can select up to 100 ready decisions, inspect their scope/rationale in
a bulk preview and explicitly approve the selection. Self-authored or changed
decisions are excluded; concurrent changes block the entire approval batch.
Administrators can replay **Load large inventory**: 100 projects × 20 findings.
It adds synthetic data without replacing existing projects; reset removes it.

```bash
uv run python scripts/playground.py down   # retains data
uv run python scripts/playground.py reset  # resets only playground volumes
uv run python scripts/playground.py logs
```

Set `DTVP_PLAYGROUND_PORT` to change the port. After the initial image build,
`up --skip-build` works offline. Production `.env` is not read by Compose here.
Uploads/edits remain interactive; test fixtures live in `playground/fixtures/`.
The legacy UI reset only resets SQL fixtures while the knowledge journal is empty.
Once any journal-backed knowledge exists, it returns 409 without changing data or
identities. Use the explicit volume-reset command above for a full playground reset;
it removes both the isolated journal and its database.

`uv run python scripts/playground.py test` uses disposable application/database
volumes and a separate local port. Browser fixture resets preserve the interactive
playground and its large inventory.

If your build network requires a private CA, keep TLS verification enabled:

```bash
docker build --secret id=build_ca,src=/path/to/trusted-ca.pem -t dtvp:rewrite .
uv run python scripts/playground.py up --skip-build
```

## Review and ownership

- Source revisions and original files are immutable. Reimports preserve curated metadata and decisions.
- Package coordinates, qualifiers, hashes and source refs establish identity; names alone do not.
- Each component occurrence has its own finding and decision history. Partial/failed scans cannot imply a clean result.
- Previous DTVP tags and plain DT documentation without metadata are imported, including team history, pending review, suppression, SSVC and contextual rescoring. Original text is retained; missing authors stay unknown.
- Decisions and independent approvals bind to the current evidence revision. Changed evidence requires revalidation.
- Team membership and explicit project sharing control access. Ownership metadata describes responsibility.
- Viewer, analyst, reviewer, security coordinator and administrator permissions are explicit; administration does not imply approval.
- No source receives automatic writes. SBOM, reviewed VEX and consumer exports are explicit downloads.

## API and consumers

The API is `/api/v2`; schema: `/openapi.json`; readiness: `/readyz`.
Browser access uses server-side sessions and request tokens. OIDC maps verified
issuer/subject identities to memberships. Administrators issue expiring, revocable,
workspace/project-scoped machine credentials; tokens are returned only once.

`POST /snapshots` freezes a release. Its manifest, bundle, paginated findings,
SBOM and VScorer worklist retain the same revision and hashes. Consumer reads
always recheck current authorization, including after sharing is revoked.

The separate Generator integration is on `feat/dtvp-snapshot-consumer`, initially
in `/tmp/dtvp-generator-consumer`; the existing `../generator` checkout is untouched.
It adds a native DTVP source to the existing CLI/API generation path, verifies
snapshot integrity and preserves occurrence-specific approved decisions without
DT fallback. See [consumer integration](docs/consumers.md).

VScorer accepts the exported SBOM/worklist through its existing intake. Returned
contextual evidence must identify the snapshot, finding, exact refs and original
Base vector. DTVP approval remains separate; lower severity never proves unaffectedness.

## Sources and matching

CycloneDX 1.5/1.6 JSON/XML and SPDX 2.3 JSON use one versioned ingestion path.
The envelope preserves source/event IDs, timestamps, pipeline context and raw
provider data. CyBeats uses standard SBOM exports; its proprietary API requires
a verified deployment contract before adding a native connector.

The DT connector is read-only. OSV supplies optional package/version matching;
NVD and Luxembourg's CIRCL supply optional advisory enrichment. Provider requests
are disabled unless configured. Mirrors retain upstream publisher data.
Qualified PURLs unsupported by a matcher remain unknown. Successful no-match
checks are coverage observations, not applicability decisions.

ENISA EUVD, Japan's JVN and other providers can use the advisory/evidence ports;
their native feed adapters are not yet shipped. See [API and adapters](docs/api.md).
Agentyzer submission, durable polling, follow-ups and immutable report retrieval
are available from each finding. Set `DTVP_AGENTYZER_ENABLED=true` and
`DTVP_AGENTYZER_URL` on the API and worker; optionally set a gateway bearer token.
A product administrator binds its Agentyzer repository name in Products.
External proposals also require qualified import `context.analysis_source` with
that `component_name` and a full 40-hex `source_commit`; returned checkout binding
must match. Generic product commits are insufficient. Unverified reports remain
visible but ineligible; changing qualified source invalidates previous evidence.
See [Agentyzer source binding](docs/agentyzer.md).
The playground uses the same workflow with clearly marked offline results,
incomplete coverage and simulated failures; no Agentyzer service is bundled.

Eligible, current results can be copied explicitly into an assessment draft.
DTVP requires matching package/version evidence and explicit application
eligibility; exclusion proposals also require exclusion coverage. Analysis never
submits or approves a human decision or changes the original CVSS score.
Full reports persist in local immutable artifacts; normalized evidence lives in
PostgreSQL. A changed finding, revoked credential or changed binding blocks
publication. Polling survives worker restarts. An ambiguous submission is failed
rather than replayed; start a new analysis explicitly. Cancel stops DTVP result
collection; the separate service may continue its run. See [analysis integration](docs/agentyzer.md).

## Statistics and contextual rescoring

Statistics counts the full authorized active inventory, not just the loaded
queue page. It distinguishes component/release findings from unique vulnerability
IDs, review lifecycle from applicability, and owning team workspaces from curated
component-owner labels. Shared projects are counted once. Team and state counts
open matching review queues; project rows are paginated. Statistics inherits the
review filters; Reset scope returns to all accessible data. PostgreSQL statistics
use a consistent read snapshot. Original and effective severity distributions,
legacy consistency, stale evidence and revalidation remain visible.

CVSS 2.0, 3.0, 3.1 and 4.0 contextual calculations and v1's version-aware rules
are available. Select a validated original Base vector, adjust optional metrics
or enter a vector, explain the context, and preview. Base metrics and the CVSS
version cannot change. Administrators edit project rules in Products; concurrent
policy edits are rejected and changed rules invalidate dependent scores while retaining team approvals.

Current VScorer vectors and eligible native Agentyzer results can supply explicit
rescoring proposals. Scores without a valid vector, mismatched Base assertions,
old snapshots and unverified results cannot be adopted. A contextual proposal
belongs to an occurrence and current evidence revision. It becomes effective
only when a security coordinator explicitly publishes it after all required team
approvals. Changing evidence or a team assessment removes the adoption until
reviews are current and the coordinator publishes a fresh score; original source scores and archived snapshots stay
unchanged. Original/effective severity sorting is available in Review. Frozen
consumer findings include required team reviews, scoring history and the proposed/adopted score, vector, rationale and rule
configuration; VScorer worklists keep original Base inputs. See
[statistics and rescoring API](docs/statistics-rescoring.md).

## Production deployment

```bash
cp .env.example .env
# Set unique secrets, database password/URL, public URL and OIDC configuration.
docker compose up -d --build
docker compose exec api uv run --no-sync python -m dtvp.cli bootstrap \
  --issuer https://your-identity-provider.example --subject YOUR_SUBJECT --name YOUR_NAME
```

Sign in with that identity, create workspaces, and assign explicit memberships.
The supplied deployment binds to loopback; terminate HTTPS through your reverse
proxy. PostgreSQL data and local artifacts use independent persistent volumes.
An optional managed PostgreSQL service uses the same database URL contract.

Schema updates run automatically under a database lock before readiness. Existing
schema upgrades first save a sealed logical data backup. A dedicated migration
database URL is supported. PostgreSQL major upgrades use a separate dump/restore
helper creating a new cluster and retaining the old volume. See
[deployment and recovery](docs/deployment.md).

## Development and verification

Use `uv` from the repository root, `npm` from `frontend/`. Python 3.15+, Node
24.15+ and Docker are supported.

```bash
uv sync --locked --dev
uv run pytest
uv run ruff check dtvp tests scripts
cd frontend
npm ci --include=optional
npm run build
npm run test:unit
npm run test:ui                 # requires DTVP_UI_URL pointing to a disposable playground
```

`DTVP_TEST_DATABASE_URL` enables destructive integration checks against an
explicitly disposable PostgreSQL database whose name ends in `_test`.
Fast tests use SQLite only as an isolated test adapter. Browser tests use the
actual PostgreSQL/auth/API stack, without mocked application requests.
`uv run python scripts/playground.py test` runs backend/build/unit/browser checks.
CI runs the same API, PostgreSQL and browser gates on pushes and pull requests.

For separate processes, set the configuration in [development](docs/development.md),
run `uv run python -m dtvp.cli serve` and `uv run python -m dtvp.cli worker`, then
`npm run dev` in `frontend/`. Theme and technical-detail preferences persist locally;
assessment drafts are retained per user/finding in the browser session.

## Repository

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | Domain, permissions, API, parsers, providers, snapshots and durable jobs |
| `dtvp/migrations/` | Frozen Alembic schema revisions |
| `frontend/` | Streamlined Vue review workspace and browser tests |
| `playground/` | Isolated Compose stack and shared public synthetic fixtures |
| `tests/` | Invariants, authorization, adapters, recovery and PostgreSQL checks |
| `scripts/` | Playground and PostgreSQL upgrade helpers |
| `docs/` | API, consumers, deployment, development and retained rewrite design |
| `skills/` | Agent routing back to this README |

The pre-rewrite runtime is preserved at Git commit
`bdc7ba41a40697b0a3f5aa1b619518216e5087f8`; planning checkpoint: `9697b53`.
Legacy DT cache/outbox code, obsolete pre-split analyzer copies, mocks, generated reports,
screenshots and obsolete configuration are removed from the new version.
Existing local legacy data is preserved and ignored; it is never interpreted
automatically as new memberships or approvals.

[Rewrite design and implementation status](docs/rewrite-plan.md) ·
[VScorer contract](docs/vscorer-consumer-contract.md) · [MIT License](LICENSE)

This README is the canonical project/agent overview. Update it alongside meaningful
behavior, API, integration, workflow or structure changes. Trust source and tests
if they disagree with prose. Agent instructions and skills remain routing hints.
