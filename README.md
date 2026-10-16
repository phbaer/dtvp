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
VDR/VEX JSON semantic subsets, explicit occurrence correspondence and pinned
assessment synchronization previews/drafts are available. Advanced scope handling
and automatic cascading synchronization remain planned. Local v2 snapshot migration
is explicit; existing v2 data never becomes journal-authoritative implicitly.
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
Generator’s isolated native adapter now retains authored support annotations and
provides a reproducible offline renderer comparison. Its full suite passes 743
tests (one optional skip). An actual synthetic DTVP HTTP run produced four support
formats and byte-exact archived inputs; three missing-input errors and twelve
warnings remain, so this does not establish controlled-document acceptance.
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

For a larger native playground dataset, run the API-only seeder against an already
running isolated playground:

```bash
uv run python scripts/knowledge_scale_demo.py
# Smaller/faster or another playground:
uv run python scripts/knowledge_scale_demo.py --url http://127.0.0.1:8900 --products 1 --packages 30 --vulnerabilities 12
```

Defaults: three explicitly `[SYNTHETIC]` products, two versions each, 250 dependency
packages and 50 synthetic CVE-2099 claims per version. The second version
removes one package/finding, adds a package/finding and changes another package version.
Each product has explicitly configured Platform/Operations consuming roots;
Platform owns the shared dependency subtree in both distinct consuming contexts,
while Operations covers its own other dependencies. Source severity includes zero
and unknown examples; identity and license facts are deliberately incomplete.
Discovery/source/build/provider/license coverage remains unknown and no human
assessments, approvals, scores or real matching results are manufactured.

The script verifies playground mode before resource writes, imports exact original
CycloneDX JSON bytes via multipart APIs, applies versioned ownership through the
backend, shares only its newly created products with Operations, and prints scoped
counts plus workspace URLs. Existing exact fixture project names are skipped
entirely, including partially seeded products; interactive edits are never reset.
Use a fresh playground for a complete reseed and run one seeder at a time. Bounds:
1–20 products, 6–2,000 packages and 1–250 synthetic claims per version.
It does not touch production or call external analysis/advisory services.


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

The Knowledge workspace's **Assemble product** editor also supports a new version
before its first baseline. Search source parts and explicitly choose immutable
states; existing pins stay selected even when newer source imports arrive.
Preview the exact selection, removals, withdrawals, required-part policy and
producer-declared coherence before publication. Edited selections default to
unverified coherence. The preview describes structure only; publication evaluates
current ownership and evidence, and never transfers approvals or infers links
between parts. Import and assembly buffers prevent competing edits and preserve
the exact request across uncertain responses. The guided API uses
`GET .../assembly-target`, `GET .../assembly-parts`, and
`POST .../versions/{version}/assembly-preview` / `assembly-apply`.

Assembly publication feedback survives the switch to the newly assembled version
after a successful workspace refresh, and clears when another product is selected.
Composition tools do not query version catalogs before a product is selected.

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

### Pinned composition input observations

The Knowledge workspace groups a lazy **Composition input observations** disclosure
with its existing source-import tools. It reads the selected product inventory only;
constituent/history states remain available through API/CLI. Source/part declarations,
full-model component/root/edge counts and exact machine-readable observation classes
remain separate from vulnerability workflow statistics. Search/class filters and
bounded pages use the backend report; full counts remain unchanged. Pages keep the
same inventory SHA, applied filters and full-report digest. A changed derived digest
retains the previous page until explicit reload; version/state changes clear the old
report, filters and page cursor, and stale responses cannot replace the new scope.
Source coverage remains producer-declared and unverified. No quality score, legal
conclusion, release block, data adoption or external provider request is triggered.


`GET /api/v3/projects/{id}/states/{state}/input-quality` provides a read-only,
source-attributed report for a committed product or constituent input state,
including retained source history before assembly. Current project read permission
is required. Unknown object hashes, arbitrary artifact blobs, and other projects'
objects do not grant access. The endpoint accepts bounded `offset`/`limit` plus
`q` and exact machine-readable `code` filters. `statistics` always describes the
complete pinned imported model; `total` describes matching observations before
pagination. `report_digest` binds the full report and all observation rows,
independently of presentation filters and page size.

The report preserves each selected source's collection scope, producer coverage,
format, source/artifact/state pins and normalization losses. Component occurrences,
metadata roots and constituent roots have explicit roles, with per-source counts.
It reports absent name/version/package identifiers, observed PURL/version conflicts,
reported dependency edges and unresolved references. Preserved source relationships
remain separate from dependency topology. Existing license evidence interpretation
keeps reported declarations, missing data, NOASSERTION, explicit NONE and malformed
or unknown-format evidence distinct. Withdrawn/empty inventories and incomplete or
unverified assemblies remain explicit; zero findings is not a clean-product claim.

CLI uses the same backend report:

```bash
uv run dtvp knowledge --url http://127.0.0.1:8900 input-quality \
  --project PROJECT_ID --state STATE_SHA --limit 50
```

Use `--json` for the machine-readable report, or `--code`/`--q` to inspect a subset.
There is no aggregate quality score, correctness verification, automatic release
block, vulnerability assessment, or license/legal conclusion. CI may apply its own
explicit policy to observation codes. A reported complete SBOM remains the
producer's declaration; the report cannot find components omitted by that producer.

### Historical comparison performance

Historical semantic comparisons reuse actor-independent canonical JSON bytes in a
process-local cache. Keys bind the product, ordered state hashes, historical mode
and derivation algorithm version. Current project permissions and committed
same-product membership are checked on every call. Journal instances have separate
namespaces; current intelligence and actor capabilities are never cached.

The cache retains at most 32 MiB of encoded payloads and 16 entries for five
minutes; individual results over 8 MiB bypass it. This bounds encoded bytes, not
process memory. Returned pages are detached. Errors are not cached; restarting
discards all entries. No files, SQL history or temporary tables are added. A cache
hit reuses prior derived data and does not verify every object's current bytes;
use offline journal verification for integrity checks.

On a local synthetic 2,000-library/250-CVE-per-version comparison, repeated pages
improved from 1.68–1.95 seconds and 19,785 object reads to roughly 0.01–0.07 seconds
and 21 reads. The first computation still took about 1.33 seconds. These exploratory
warm-filesystem timings exclude HTTP/concurrent deployment qualification. They
measure comparison reads; artifact reuse separately improves repeated import and
ownership writes, as described under offline journal verification.

### Assessment read performance

Native workspaces reuse a request-local dependency/evidence fingerprint builder.
Canonical root encodings use a bounded 32 MiB cache; the conservative
`dtvp.assessment-target/1` hashes remain unchanged. No permissions, approvals or
mutable state are cached between requests. Six pre-optimization fixtures guard
hash compatibility. A synthetic local 1,000-component/250-finding check improved
from roughly 7.7 seconds to 0.5 seconds for the first workspace read, with
subsequent reads around 0.13 seconds; these are workload-specific measurements,
not deployment guarantees.

### Interactive composition intake

**Import composition** in Knowledge works before the first baseline exists.
Inspect an existing or new product version, choose a complete product baseline or
isolated source part, and upload the original file with an explicit source sequence
and observation time. Source-part imports leave assembled products unchanged.
Connector-owned and assembled baselines cannot be silently replaced by manual files.
Existing boundary fields are prefilled, while build commits, digests, pipeline runs
and coverage claims must be declared for the new input; old provenance is not copied.

`GET /api/v3/projects/{id}/intake-target?version=VERSION[&part_id=PART]` returns the
exact target head, source authority, boundary template and current capabilities.
`.../intake-parts` supplies bounded searchable source-part choices. The form freezes
file bytes, metadata, expected head and request ID before publication; ambiguous
responses retry unchanged. Switching target requires an explicit new request.
Changing the signed-in identity discards buffered intake requests and capabilities.
Imports retain historical assessments; their current validity remains server-owned.

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

### Ownership editor

The collapsed **Component ownership** panel retains v1 selector semantics with
separate component name and namespace controls, case sensitivity, PURL selectors
and fallback ownership. Namespace absence and unknown namespace remain distinct;
bare-name matching honestly covers unknown or known-empty namespaces. The backend
encodes selectors through the existing matcher. Unfamiliar raw selectors remain
unchanged unless explicitly replaced. Rules default to all versions, with optional
explicit version scopes. Alias labels never add owners, reviewers or permissions.

`GET /api/v3/projects/{id}/ownership/editor` returns exact policy/head pins,
selector descriptions, team choices and management capabilities. Managers stage a
complete policy, call `/ownership/editor/preview`, then explicitly
`/ownership/editor/apply` with that preview digest. Preview writes no journal objects.
Apply uses the existing atomic policy workflow; retries of the same policy/request
return its receipt before checking changed heads. The preview digest is an initial
admission check, not part of the existing policy idempotency identity.
Consuming-root configuration and untouched selectors remain preserved. Historical
team assessments and approvals retain their original scope when ownership changes.

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

A replacement analyst explicitly starts a new logical assessment; the previous
author's record is read-only. Copied evidence stays visible for verification,
and prior decisions and approved pins remain retained.


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
Analysts and reviewers with exactly one responsible team start in that team’s
scope. Multiple teams require an explicit selection. An explicitly chosen all-team
view is retained in shared URLs and saved views, including after reload. Filtering
a workspace never grants team permissions.
Team labels come from that authorized selection, including teams outside the
viewer’s memberships; showing a label grants no team role.
Use workspace `--json` for complete machine-readable rows and evidence. Mutations
forward the explicit JSON payload; no approval or scoring logic lives in the CLI.

### Workspace tools

Knowledge workspace utilities use two compact responsive toolbars: product-level
intake, assembly, ownership, CPE policy, evidence and comparison; pinned-state
license, portfolio, documentation, source/advisory, correspondence and retained
assessment views. Existing disclosure summaries remain directly accessible.
Opening a panel expands it to full toolbar width. Other component instances,
captured requests and draft inputs remain mounted; no additional disclosure layer
or permission shortcut is introduced. Narrow screens use one readable column.
Empty products finish loading and retain product tools before a first baseline.

### Coordinator score publication

Coordinator score previews bind the exact selected context, source state/Base vector,
proposed vector and rationale. Editing inputs invalidates the preview. Publication
captures the complete preview token and request ID; failed, uncertain or
projection-pending outcomes retain that exact request in a visible retry buffer.
Source inputs and competing single-finding mutations stay disabled while that
publication is captured. Retry never regenerates a preview or repins a head.
Explicit local discard does not undo or prove absence of an uncertain commit.

Only `committed: true` with a current projection triggers authoritative refresh.
Changing queue scope or context keeps the current view and never reopens the old
context. Actor epochs and request signatures discard late preview/publication
responses, including actor roundtrips, at each asynchronous continuation. The
backend remains authoritative for coordinator permissions, source Base validation
and required independent reviews; proposals never grant approval or publish scores
implicitly.

### Guided queue progression

Native single-finding actions offer explicit **Submit and next**, **Approve and next**
and **Request changes and next**. These publish the current exact assessment/review
only. Navigation opens evidence for the next surviving finding on the current page;
it never assesses, approves or rescores that finding. Filters, page offset and scroll
position are retained. At the visible page boundary, the current position remains
and the UI reports that no next finding remains; paging stays explicit.

Advancement requires an authoritative `committed: true`, a current projection and
successful refreshed workspace/detail reads. Errors, uncertain publication and
pending projections retain the original endpoint, expected heads/revision, evidence,
request ID and exact body in a visible retry buffer. Retry never repins that input.
Changing the selected finding, filters, product, version or page prevents deferred
automatic navigation. Switching actors clears the local captured buffer; stale actor
responses cannot resume its workflow. Explicit local discard does not undo or prove
absence of an earlier uncertain commit.

### Explicit bulk review

The Knowledge queue lets independent team reviewers select up to 100 exact
submitted context assessments. The backend preview reports every ready/excluded
target before pagination; drafts, stale evidence, self-authored revisions,
missing authority and already reviewed current revisions are excluded. A newer
submitted revision remains reviewable while an older approved revision is retained.
Review rationale, evidence, consuming context and source/published severity are
available before explicit final selection and confirmation. Only selected ready
targets are committed atomically; shared assessment scope adds no implicit reviews.

`POST .../reviews/bulk/preview` and `/apply` use exact assessment revisions,
all candidate version heads, a complete preview digest and a stable request ID.
The UI preserves frozen requests across uncertain responses and scope navigation;
filter changes clear only the uncaptured queue selection. The generic HTTP CLI
uses the same API. Approval never publishes contextual scores or changes source
claims. A changed candidate head or selected exclusion blocks the entire batch.

### Explicit correspondence-linked assessment drafts

Explicit confirmed occurrence correspondence can now prepare a **new adopted target
draft**, separately from the existing same-lineage shared-assessment extension.
`POST /api/v3/projects/{id}/correspondence-drafts/preview` takes pinned source and
current target states, exact source/target contexts and vulnerability, an independently
approved source assessment revision, explicitly selected assertion IDs/revisions and
the current ownership-policy pin. Both component and consuming-context correspondence
are required. Active competing mappings, retractions and changed captured occurrence
material block adoption; no name/PURL matching, transitive mapping or identity merge
occurs. A historical source state remains usable, including an earlier nightly state
of the same version, without requiring its branch to remain at that head.

`POST .../correspondence-drafts` additionally requires a new assessment identifier,
request ID, preview digest, target conditions and adoption reason. The currently
authorized target analyst becomes the new draft's author; immutable evidence retains
the original source author/revision and both assertion and state pins. Existing target
content, source approval, ownership and published scores are preserved. Every adoption
needs independent target review and the normal coordinator scoring gate. Target/policy
CAS and exact uncertain-write replay retain frozen request inputs. Existing shared
assessment lineage checks and synchronization receipt formats remain unchanged.

CLI uses the same backend requests, with JSON files containing the exact fields:

```bash
uv run python -m dtvp.cli knowledge --persona analyst correspondence-draft \
  --project PROJECT --input preview.json
uv run python -m dtvp.cli knowledge --persona analyst correspondence-draft \
  --project PROJECT --input apply.json --apply
```

The second command explicitly publishes one unsubmitted draft.

The existing **Occurrence correspondence across imports** panel also offers a
collapsed **Reuse approved assessment through correspondence** workflow. Select a
source branch/tag or historical state first. Search its bounded, pinned approved
source findings, explicitly choose a target consuming context and recorded active
component/context assertion revisions, then request a server preview. The preview
shows the original attributed conclusion and complete evidence under a disclosure.
A new target assessment ID, target conditions, adoption reason and explicit
confirmation are required to create an unsubmitted linked draft. Source approval,
scores and identity are never transferred; independent target review is required.

Source, target, ownership policy, source assessment revision and correspondence
revisions remain pinned. A changed target blocks a first publication. An uncertain
publication retains the exact endpoint, body, request ID and preview through
503/409 and pending projection; retry never selects a newer baseline. Discard is
explicit. Source/candidate/context/assertion reads are bounded and paged; selected
assertion IDs remain visible across pages. Actor/project teardown invalidates late
responses, and a retained draft buffer prevents competing product/version and
correspondence edits. Presentation follows backend authorization and eligibility.

Adopted drafts retain original source evidence by the exact immutable assessment
revision, plus evidence count and digest. Source evidence is neither duplicated nor
truncated, so a source with the maximum 100 evidence entries remains usable. The
selected preview exposes the full original source assessment before adoption.
Captured correspondence targets must remain ancestors of the selected target; the
selected/captured source states must share comparable same-version ancestry and
unchanged occurrence/usage material. Equal-looking unrelated histories do not qualify.
The bounded historical source selector is
`GET /api/v3/projects/{id}/states/{state}/correspondence-draft-candidates` with
`q`, `offset` and `limit` (maximum 200). Candidate payloads contain summary text only;
exact rationale/evidence are retrieved by the explicitly selected preview.

### Cross-version assessment scope

Cross-version candidates optionally accept a closed numeric release selection:

```json
{
  "source": "SOURCE_STATE_SHA", "context_id": "CONTEXT_SHA", "vulnerability_id": "CVE-ID",
  "version_selection": {"lower": "7.1.1", "upper": "7.2.0", "include": ["main"], "exclude": ["7.1.2"]}
}
```

Bounds include their endpoints and order only strict numeric `major.minor.patch`
labels. No `v` prefixes, leading zeros, prereleases, build suffixes or other label
schemes are silently normalized. Unorderable branch names stay explicitly unknown
unless included by exact name; includes/excludes must name current branches and
cannot overlap. Exclusions remove exact named versions. Missing bounds are open;
an explicit empty selector selects numeric release labels only. Omitting the
selector preserves the existing unfiltered response and preview digest contract.

Selection inspects at most 1,000 current heads and 1,000 selected context rows,
otherwise fails without truncation. The report names selected, excluded, outside
range and unknown branches; counts precede paging. The digest binds the selector,
all captured heads (including excluded branches), classifications and explicit
candidate rows. Any new or advanced branch invalidates an existing preview page.
Selection performs no writes and never establishes applicability or approval.

The assessment panel's collapsed **Limit additional versions** controls require
explicit refresh; edits do not change the selector used by subsequent pages.
Additional target checkboxes remain unselected. The current assessment context
always remains in scope, even when outside the filter. Conditions and independent
reviews remain required. The CLI uses the same endpoint with `knowledge coverage
--version-from 7.1.1 --version-through 7.2.0 --exclude-version 7.1.2`; repeat
`--include-version`/`--exclude-version` for exact names, and retain
`--expected-preview` across pages.

A range materializes only the finite captured candidate set. Later branches and
nightlies do not inherit approved coverage. Assessment writes retain their
existing explicit-target/head checks and immutable payloads; there is no dynamic
range approval, persisted intent, assessment fingerprint change or new write
receipt. A branch appearing before a later ordinary explicit-target save is not
implicitly selected; this feature does not add a full-preview CAS to that write.


The Knowledge assessment panel can load a pinned coverage matrix across current
product versions. Candidates distinguish matching material, changed material,
different consuming contexts, identity conflicts and absence. Extra targets are
never preselected; compatible lineage alone does not establish applicability.
Independent existing decisions are preserved. Explicit shared targets require
supporting conditions and retain independent reviews per version/context.

`POST /api/v3/projects/{id}/coverage/candidates` accepts `source`, `context_id`,
`vulnerability_id` and optional `expected_preview`. The complete preview digest
pins heads across pages; a changed selection returns 409. Results include current
actor capabilities without granting access from team ownership. The HTTP CLI uses
`knowledge coverage --project ID --state SHA --context SHA --vulnerability CVE`
with `--json` for the complete server response. Review and score publication stay
separate from selecting assessment coverage.

### Interactive advisory-change playground

Against an already running isolated playground:

```bash
uv run python scripts/knowledge_intelligence_demo.py
# Optional private playground:
uv run python scripts/knowledge_intelligence_demo.py --url http://127.0.0.1:8900
```

The API-only script verifies playground mode, creates a separate clearly synthetic
project and retains an immutable pre-update tag. It imports an invented provider
update (including a zero rating) and a contradictory second provider. It verifies
one changed and one added claim group, the unchanged original SBOM rating, and
absence of assessments, reviews and scores. Output includes the historical inventory
SHA, selected evidence SHA, report digest and workspace URL. Paste those pins into
**Choose retained inventory state** in the advisory comparison panel. Ownership
and discovery/license coverage remain unknown; no external provider or human
review is simulated as real. Existing exact-name projects, including partial seeds
and interactive edits, are skipped without resetting or repairing them.

### Statistics across authorized projects

`GET /api/v3/portfolio` captures one complete current-reference selection across
explicit repeated `project=ID` values or all currently readable projects. Current
project and machine-token authorization applies before journal reads. The same
`q`, `lifecycle`, `team_id` and native finding filters scope the full workload.
No tenant filter grants access. Limits are 100 projects, 1,000 current product
versions, 250,000 section-record pointers, 64 MiB unique input objects and 100,000
potential context findings, checked before workspace synthesis. Larger selections
fail visibly; choose fewer projects instead of accepting truncated totals.

Global totals, team workloads and both severity distributions precede project
paging (`offset`, `limit` 1–100). Unique vulnerability identifiers deduplicate
across projects; logical assessment identifiers remain project-scoped. Every
version/context still contributes its own review target. Conflicting team groups
can overlap and are not additive. Source coverage and retained-history counts
remain explicitly unfiltered state-level facts, separate from filtered workload.

Retain the complete `heads_digest` as `expected_heads` alongside the same project
selection and filters on subsequent pages. Changed projects or heads return 409;
no automatic repinning occurs. Project rows sort by immutable project ID so a
renamed display label cannot reorder a pinned selection. CLI consumers can use
`knowledge request GET /api/v3/portfolio` with the same query parameters. This
read-only report creates no assessments, approvals or completeness claims.

The Knowledge workspace offers collapsed **Statistics across products** before a
product is selected. Opening it requests complete server-derived statistics for
all currently accessible products (up to 100), or use the bounded searchable
catalog to select products explicitly. Team and current workspace finding filters
apply on explicit load/refresh. Findings, unique vulnerability IDs, project-scoped
logical assessments and required context-review workload remain separate counts.
Source severity and current published contextual severity remain separate; missing
or outdated contextual scores stay unknown. Team workloads can overlap under
ownership disputes and must not be added as disjoint totals.

Product rows are paged, while totals and team workloads cover the entire selected
scope. Every page retains the original product/team/filter query and complete
project/version head digest, including after draft selector/filter edits. Changed
heads retain the previous result and require explicit refresh. Per-version facts,
unfiltered input coverage, exact pins and limitations are progressive details.
The view is read-only, loads only when opened, and actor changes invalidate late
responses. Oversized selections fail visibly instead of silently truncating.

### Current-version portfolio statistics

The Knowledge tab offers a collapsed portfolio panel. It inherits workspace
filters and can select current versions and a team. Changed heads retain the
previous displayed pins until an explicit refresh; counts come from the API.

`GET /api/v3/projects/{id}/portfolio` aggregates authorized current version heads
from one reference snapshot. Repeat `version` to select branches; optional
`expected_heads` rejects changed selection with 409. Workspace filters apply before
counts. Team groups may overlap when ownership conflicts; state-level collection
coverage and retained-history counts are explicitly unfiltered.

Counts distinguish contextual findings, unique vulnerability IDs, latest logical
assessments, independently approved logical assessments and the actual remaining
version/context review workload. Only current published scores contribute
contextual severity. Unknown coverage, unassigned targets and withdrawn inventory
remain explicit. CLI: `knowledge portfolio --project ID [--version VERSION]`
with the workspace filter flags and `--json` for the complete server response.

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

Native Agentyzer report JSON retains its 8 MiB, 100,000-node and depth-64
limits. Child traversal is admitted before queue expansion, so a wide report is
rejected before allocating an oversized traversal queue. These limits do not
change serialization, source binding or proposal eligibility.

Native Agentyzer jobs support explicit actor-only reconciliation of unknown POST
outcomes against the additive private authenticated Agentyzer completed-job
endpoint. Original private correlation (unique 256-bit nonce and issued/request
SHA-256) is required; legacy unknown jobs stay fail closed. Current permissions,
credential, repository/endpoint, material pins and SQL lease are rechecked before
and after GET. No analysis POST is retried. The authenticated exact public report
is durably checkpointed and imported through existing proposal-only semantics.
A sanitized transport summary/hashes are archived, never the nonce/private proof;
this is receipt consistency, not provider authenticity or cryptographic attestation.
Configure matching server-owned `DTVP_AGENTYZER_TOKEN` and upstream
`AGENTYZER_RECONCILIATION_TOKEN` (minimum 32 printable ASCII non-space characters).
The native jobs detail provides explicit frozen remote-ID verification/retry.
See [Agentyzer integration](docs/agentyzer.md) for contracts, operational-backup needs and limitations.

Set `DTVP_AGENTYZER_RECONCILIATION_ENABLED=true` explicitly (default false).
A strong existing token alone leaves the previous POST body unchanged; only new
opted-in jobs gain private proof. The isolated sibling completed-job reconciliation increment is commit
`a10b5d4` on `fix/immutable-source-binding` in `/tmp/agentyzer-source-binding`;
it has not been merged, pushed or deployed.

Native analyses now support explicit parent/report-bound follow-ups through
`POST /api/v3/projects/{id}/versions/{version}/analysis-jobs/{parent}/follow-up`.
This requires the optional authenticated Agentyzer extension: exact parent pins
are checked before enqueue and submission, source scope cannot change, and an
uncertain POST is never automatically repeated. Each child is independent
proposed evidence, with its own current authorization and private correlation;
no approval or score publication is inherited. See [Agentyzer](docs/agentyzer.md#native-bound-follow-ups).

The isolated upstream extension is `9bb5985` on `fix/immutable-source-binding`;
517 sibling tests passed. It remains unmerged and undeployed. Legacy unbound
follow-ups retain their existing upstream behavior; DTVP’s native bound mode
requires the explicit authenticated extension and never falls back to them.

Completed native Agentyzer jobs expose **Ask a bound follow-up** only when the
backend grants that capability. The UI captures the selected parent report and
workspace head when the analyst opens the question, requires an explicit question
and confirmation, and queues a separate source-bound job. Additional guidance is
optional; repository, commit, model and vulnerability overrides are unavailable.
The backend's authenticated parent/source proof remains authoritative.

The question lives outside the paged job list, so workspace refreshes and list
resets retain it. A changed workspace head blocks a first enqueue until explicit
discard/reselection. After an uncertain response, the exact endpoint, expected
head, parent report, question, guidance and request ID remain frozen through
503/409 and later state changes. A matching returned child job confirms local
recording; remote processing and evidence publication still have separate states.
Refresh status explicitly. Unknown remote submissions retain the existing
completed-job reconciliation workflow and are never automatically resubmitted.

An active question prevents competing context/product/version and job edits.
Actor/context teardown invalidates late responses. Discard does not cancel a job
that may already have been recorded. A follow-up report never creates a human
assessment, review or contextual score publication automatically.

### External v1 project archive dry run

Managers can inspect an exported `dtvp.project-archive/v1` ZIP without restoring it:

```bash
curl --fail-with-body --header "Authorization: Bearer $DTVP_TOKEN" \
  --header 'Content-Type: application/zip' --data-binary @project.dtvp-project-archive.zip \
  "$DTVP_URL/api/v3/projects/$PROJECT_ID/migration/v1-archive/preview"
```

The HTTP CLI can stream the same dry run without preparing JSON or multipart data:

```bash
uv run dtvp knowledge --url http://127.0.0.1:8900 legacy-archive-preview \
  --project PROJECT_ID --archive project.dtvp-project-archive.zip --json
```

Use `--offset`/`--limit` for source-version pages and resubmit the identical file
for the same report digest. The CLI admits a regular file no larger than 64 MiB
before opening it, rechecks the opened file and streams exact bytes in 64 KiB
chunks with an actual-growth bound. A smaller server upload limit still applies.
Only the backend parses the ZIP, checks permissions and interprets source claims;
HTTP rejection remains an error. This command does not apply or persist an archive.

The endpoint requires current target management permission before consuming the
body. This exact POST route bypasses the general eager upload buffer and enforces
its own streamed bound; all other routes and methods retain existing buffering,
authentication, CSRF and response headers. Parsing runs outside the event loop.
Use `offset`/`limit` (maximum 100) for bounded source-version pages. Resubmit exact
bytes to reproduce the same full-report `preview_digest`; pages never invent
source history or select target version mappings.

The pure reader validates actual ZIP end/central-directory metadata before
constructing the library member table, then checks original member hashes/sizes
and the v1 manifest's five per-version JSON files. It rejects unsafe/ambiguous
paths, duplicate aliases, encrypted/symlink/overlapping entries, ZIP64 and alternate
Unicode paths, undeclared/missing files, mismatched checksums/counts, duplicate JSON
keys, nonfinite JSON and unsupported archive schemas. Limits: configured upload
maximum or 64 MiB compressed (whichever is smaller), 128 MiB expanded, 16 MiB per
member, 4 MiB central directory, 2,000 entries, 100 source versions, JSON depth 64
and one million nodes per member. Actual decoded reads are bounded as well as
advertised sizes; archives are never extracted and no Git commands run.

Reports expose hashes, counts, native SBOM normalization support, exact source
UUID-to-exported-ref mapping coverage and explicit losses. They summarize tagged,
plain/missing documentation and unverified source-state claims without returning
raw source URLs, names, personal documentation or credentials. Missing/ambiguous
component mappings never fall back to package names or PURLs. Unsupported legacy
SBOMs are reported without silently adding a CycloneDX version or upgrading them.
Git-friendly expanded exports can be rezipped with their manifest at the root;
missing capture/author/build fields stay unknown, not reconstructed from Git.

The dry run persists no ZIP, member, metadata, assessment or permission.
It performs no DT writeback, membership creation or native approval. V1 captures are
partial snapshots: assessment comments may have been stripped, histories and
operational databases are incomplete, and exported BOM JSON need not be the
original pipeline bytes. Retain the caller's original archive. Complete migration
and controlled cutover still require representative sanitized archives and
reviewed publication acceptance.

Three committed synthetic fixtures were produced by the frozen v1 exporter and
its fake clients: its original incomplete BOM/plain documentation, an explicitly
valid CycloneDX/tagged variant, and the original diffable-tree writer. Fixture
provenance/hash pins are in `tests/fixtures/legacy-v1/provenance.json`; tests and
production inspection require no old runtime, Git, DT or customer data.

### Reviewed single-version v1 publication

A reviewed, sanitized **single-version** `dtvp.project-archive/v1` export can be previewed and explicitly published into a new, empty native product version. The existing archive dry run remains read-only. Publication requires current project read/manage/write permissions, an exact archive SHA/source-entry selection, explicit null branch expectation, ownership/evidence pins, a declared timezone-aware observation time, meaningful reason, and separate explicit acknowledgments of operator review, sanitization and disclosure to current and future target-project readers. Known credential configuration keys and credential-bearing URL user-info are rejected; this does not prove arbitrary free text is secret-free.

The exact submitted sanitized ZIP, manifest and five selected exported members become readable target-state artifacts. DTVP does not claim to retain the unsanitized original. Native composition uses the exact exported BOM member without adding a CycloneDX version or pretending it is original pipeline bytes. Tagged/plain/missing DTVP/DT documentation and all source assessment records remain attributed, unverified historical claims. Exact unique component UUID-field mappings and literal source-UUID-equals-exported-reference mappings admit source findings; conflicting/missing mappings remain historical without name/PURL guessing. Only validated original Base ratings enter source severity. Legacy team, author, reviewer, suppression, not-affected and contextual-score claims create no native permissions, assessments, reviews or scores.

`POST /api/v3/projects/{project}/versions/{version}/migration/v1-archive/{preview,apply}` accepts a raw `application/zip` body (maximum min(configured upload bound,64MiB)) and ASCII JSON `X-DTVP-Migration` metadata (maximum8192bytes; escape Unicode with JSON `ensure_ascii=True`). Required metadata: `request_id`, `archive_sha256`, `source_entry_id`, `expected:null`, `expected_policy`, `expected_evidence`, `source`, `build_number`, `occurred_at`, `reason`, `acknowledge_sanitized_export:true`, `acknowledge_operator_review:true`, `acknowledge_project_reader_disclosure:true`. Apply additionally requires the captured `preview_digest`. Authentication is checked before consuming uploads and refreshed afterward. Preview writes nothing; fresh apply requires the branch still absent and both pins unchanged. Exact receipt replay precedes archive parsing/head revalidation after current authorization and raw-byte hash validation. Changed input under one request ID conflicts; uncertain publication retries require the same bytes, metadata, UUID, endpoint and preview digest.

The HTTP-only CLI reads the explicit declaration from a bounded JSON file and streams the ZIP unchanged:

```bash
uv run dtvp knowledge --url "$DTVP_URL" legacy-archive-publication \
  --project PROJECT_ID --version NEW_VERSION --archive reviewed-single-version.zip \
  --input publication.json
# Add the returned preview_digest to the same declaration, then explicitly apply:
uv run dtvp knowledge --url "$DTVP_URL" legacy-archive-publication \
  --project PROJECT_ID --version NEW_VERSION --archive reviewed-single-version.zip \
  --input publication.json --apply
```

Populate every required metadata field listed above; obtain `archive_sha256` and `source_entry_id` from inspection and current policy/evidence pins from project references. The CLI supplies no acknowledgments automatically. Retain the exact apply declaration and ZIP for retries; backend failures remain command failures.

This deliberately does not restore a multi-version archive, Git history, source memberships, roles or a complete v1 database. Representative sanitized exports and producer/operator acceptance remain migration gates.

### Explicit local v2 snapshot migration rehearsal

`POST /api/v3/projects/{target}/versions/{version}/migration/v2/preview`
previews an existing local immutable `dtvp.snapshot/1` snapshot. The same body,
plus its returned `preview_digest`, is accepted by `/migration/v2/apply`.
Use the generic authenticated `knowledge request` CLI or HTTP API for this local
snapshot contract. External v1 ZIP inspection has its separate bounded dry run
and streamed CLI described above. Reviewed single-version publication uses the
separate explicit contract above.

Example request (replace IDs, digest and configuration pins):

```json
{
  "request_id": "cutover-rehearsal-1",
  "snapshot_id": "existing-local-snapshot-id",
  "snapshot_sha": "<snapshot sha256>",
  "expected": null,
  "expected_policy": null,
  "expected_evidence": null,
  "source": "pipeline/main",
  "build_number": 0,
  "occurred_at": "2026-10-16T03:00:00Z",
  "acknowledge_historical_claims": true
}
```

Read current ownership/evidence selections first and supply their actual hashes
(`null` only when absent). An optional explicit `context` uses the existing
`CollectionContext` schema; omitted coverage stays unknown. Choose the intended
future pipeline source identifier and a first native build number explicitly;
legacy source labels do not configure future authority or build ordering.

Both preview and apply reauthorize source-project read/snapshot access and
target-project manage/write access. SQL snapshot/release/revision membership,
manifest and bundle/SBOM hashes, and every captured source artifact are checked
before conversion. A target branch must be absent. Preview writes no journal
objects or SQL projections. Apply performs one atomic publication with empty-head,
ownership-policy and evidence-selection compare-and-swap checks. Exact request
replay precedes input-artifact rereads and stale-head checks after current
authorization, including uncertain publication and pending projection recovery.

The exact selected original SBOM supplies native inventory through the native
parser, preserving original format, license evidence and relationship semantics.
The v2 normalized SBOM remains historical evidence inside the exact retained
bundle; its containment-derived dependency edges are not promoted into native
dependencies. All listed original source bytes remain retained artifacts. Original
metadata, owner labels, decisions, approval claims,
rescoring history and unmatched/inactive findings remain typed historical evidence.
No legacy owner becomes a native permission and no decision/approval/score becomes
a native human record. Current native ownership and evidence policy apply explicitly.

Captured source observations and selected-original SBOM findings use exact declared
component IDs/refs and vulnerability IDs. Source ratings admit only validated
original CVSS 3/4 Base vectors and mathematically matching Base scores. Unsupported,
contextual or inconsistent ratings remain archived; mapped active findings retain
unknown-rating queue observations. All such observations are labelled historical
and unverified, including selected-original source claims; no past source assertion
is relabelled as a fresh future-pipeline observation. Explicit inactive targets stay
historical. Unsupported originals fail closed;
reference drift is exposed as unresolved without name/PURL identity guessing.
Preview identifies legacy-derived edges that were not adopted.
DT tagged and plain documentation remains readable even when Base ratings are unknown.
Preview exposes full counts, capture coverage/conversion losses and bounded first
200 mapping/unresolved details; the complete evidence remains in the original bundle.

Limits: local installation only, up to 200 source revisions, 64 MiB bundle and
256 MiB total original source bytes. Missing or corrupt originals fail closed.
External v1 archive inspection is implemented as the separate read-only dry run.
Reviewed single-version archive publication is available under the contract above.
Git history conversion, ownership/identity reconciliation and complete legacy
recovery still require explicit contracts. In particular,
`dtvp.snapshot/1` includes captured decisions but only the latest decision's
approval, so older approvals may be absent. No snapshot-completeness or regulatory
compliance claim is made.

### Offline journal verification

`uv run dtvp verify-knowledge --directory /path/to/artifacts/knowledge` verifies an
existing committed journal without SQL: publication/reference chain, all historical
states/parents and retained objects. It reports the pinned head and checked counts,
fails on corruption and performs no repair. Uncommitted orphan files are excluded.
Operational SQL data still requires its own backup; see [recovery](docs/deployment.md#native-journal-recovery).
`uv run pytest -q tests/test_installation_recovery.py` rehearses a stopped local
SQLite installation restore: operational accounts/credentials/permissions and
uncertain jobs, the complete artifact journal, tags, independent reviews and
issued consumer bytes. It rebuilds only native projections and checks denied
cross-team access. Explicit disposable PostgreSQL source/candidate URLs and a
Docker container also exercise real `pg_dump`/`pg_restore`; both database names
must end in `_recovery_test`. Both backends have passed this rehearsal. Custom
roles/extensions, major upgrades and deployment-specific identity/remote-job
qualification remain release gates; see the recovery instructions.

Repeated artifact writes hash-verify existing content-addressed bytes and reuse
them without creating and syncing a redundant temporary file. Both object-root
and destination-shard directory durability barriers remain mandatory. Missing
objects retain the temporary write, file fsync, atomic link and shard fsync
protocol. Corrupt or unreadable existing objects fail closed without overwrite.
Concurrent-writer and interrupted-publication tests cover this path; installation
restore remains tested on SQLite and PostgreSQL.

In an exploratory local 2,000-package/250-CVE fixture, a repeated import fell from
26.0 to 0.6 seconds; directory fsync counts were unchanged. This filesystem-specific
measurement is not a production performance or power-loss qualification.

### Retention maintenance preview

`GET /api/v3/projects/{id}/maintenance/retention-preview` requires project management.
It inspects exact targets across all current branches and tag-protected revisions,
including review-pinned older revisions. Shared assessments remain active while
any covered target is present. Unknown scope never becomes a candidate. Revision
age is explicit and does not establish disappearance date or obsolescence. Full
counts accompany bounded revision/logical-assessment pages; `expected=PLAN_HASH`
rejects changed references during pagination. The HTTP CLI can use `knowledge
request GET /api/v3/projects/ID/maintenance/retention-preview`. This dry run writes
nothing and makes no physical storage estimate. Explicit logical archival uses
the separate complete-history plan described below. Retention policy and physical
journal garbage collection remain planned; history is not deleted.

Reviewer queue and project/organization portfolios support `agentyzer_evidence`
and `vscorer_evidence` filters: `missing`, `current`, `historical_only` and
`eligible` (empty means unrestricted). They inspect received evidence in the
selected state, before counts and pagination. Current evidence can be ineligible;
historical-only requires every received record to be explicitly stale. Unknown
flags never establish eligibility or historical-only status. Agentyzer eligibility
means application proposal eligibility; VScorer eligibility means scoring proposal
eligibility. Neither is approval, publication or proof of provider authenticity.
CLI workspace/portfolio accept matching `--agentyzer-evidence` and
`--vscorer-evidence` options. No job state, receipt age or wall clock is inferred.

The Knowledge workspace's collapsed **More filters** section includes independent
Agentyzer and VScorer received-evidence selectors: no evidence, current evidence,
historical evidence only, or current eligible evidence. These filter the server's
workspace and project/cross-project statistics; saved views and shared URLs retain
the same scope. They describe received evidence, not queued jobs, human approval
or an automatically accepted assessment. Current evidence can remain ineligible.

Advanced queue and portfolio filters include authored cybersecurity `criticality`,
`exposure`, `support_status` and `metadata_status`. UI saved views and the HTTP CLI
(`--criticality`, `--exposure`, `--support-status`, `--metadata-status`) retain the
same backend scope. Only current, applicable curated annotations supply these
facts. Missing, stale or out-of-scope annotations yield unknown context values;
their original records remain visible. Source claims and support dates do not
infer authored criticality, exposure or support status. Filtering neither changes
applicability nor publishes a score, and full statistics precede pagination.

The Knowledge workspace's **Component inventory** browses all imported source-local
component occurrences, including those without vulnerability observations. Search
identity/PURL/reference, filter pinned ownership/team evidence, page backend totals,
and choose each distinct consuming context. Component names/PURLs never merge
occurrences; unknown ownership and delegated contexts remain explicit.

`GET /api/v3/projects/{id}/states/{sha}/components` and its `/contexts?component_ref=...`
read committed product states only, under current project-read authorization.
Current and historical states are exact pins; paste a historical SHA from version
history to inspect it. The existing component annotation editor is available to
managers at the current head, with the same expected state/revision and frozen
retry identity. Historical annotations remain read only. Direct imported dependency
neighbors and raw source facts use the existing context disclosure; this is not
an editable dependency graph, runtime topology, complete discovery or clearance.
No-finding components do not receive implicit security/license approval.

### Explicit logical assessment archival

Project managers can inspect `POST /api/v3/projects/{id}/maintenance/assessment-archive/preview`
and explicitly select up to 100 logical assessment IDs for `.../apply`. Apply also
requires current write permission, the exact full project-reference map and plan
hash, a stable request ID and a reason. The complete historical scan has finite
state, pointer and 64 MiB decoded-input budgets; exceeding a cap or encountering
unreadable/corrupt history fails closed. Unknown scope, any active covered target,
exact tag protection or a current scoring reference blocks retirement. Preview is
read-only and reports full counts alongside bounded pages.

Publication atomically records a retirement manifest and removes selected current
assessment/review pointers across affected branches. A concurrent new branch, tag,
source or policy reference invalidates the plan. Original assessment payloads,
review records, authorship, reasons, source artifacts and historical state exports
remain immutable. No files or historical approvals are deleted; this does not
reclaim disk space or implement retention policy or physical garbage collection.

Current project readers can list `GET .../maintenance/assessment-archive` and inspect
`GET .../maintenance/assessment-archive/{assessment_id}`; retained records explicitly
confer no current approval. Reappearing findings require a new logical assessment ID.
Retired IDs cannot be edited or reused, while exact earlier request receipts and
historical coverage remain unchanged. Explicit forks may retain historical pointers
without granting cross-version approval. Retries recheck current authorization
before returning a prior receipt and never repin inputs or publish a second change.

The collapsed **Assessment archive** product tool loads retained records only when
opened. Readers can inspect original rationale, authorship and review records;
management controls follow capabilities returned by the backend. Managers preview
bounded pages against one frozen plan hash and full reference map, manually select
up to 100 eligible IDs and provide a reason plus explicit confirmation. Changed
preview pages require discarding the old selection before starting again.
Captured publications retain their endpoint, request ID, selected IDs and all pins
through conflicts, uncertain responses and delayed projections; retries send the
identical request. Only confirmed commits with a current projection clear the
capture. Product/version navigation stays locked until success or explicit discard.
Actor/product changes remount the tool and ignore late responses. No archival is
performed automatically and this UI never deletes immutable records or files.

### Curated component metadata

Native component context and annotations are available from each Knowledge finding's
progressive **Component context, dependencies and annotations** detail. The read
adapter `GET /api/v3/projects/{id}/states/{state}/component-context` binds the exact
source-local component and optional consuming context to an authorized immutable
state. It returns imported facts separately from authored annotations/provenance,
current or historical metadata status, typed defaults and backend capabilities.

Only project managers viewing the exact current product head can open the guided
annotation editor. Existing versioned `PUT .../versions/{version}/metadata` remains
the write authority. The editor covers cybersecurity criticality/exposure,
runtime usage, deployment, support and provenance; advanced typed JSON retains
mitigations, testing evidence, references and extension properties. Explicit saving
freezes the expected product head, prior metadata revision, complete values and
request ID. Uncertain retries preserve the exact request; conflicts require an
explicit discard/refresh. Escape/backdrop cannot discard an uncertain capture.
Authored annotations apply to the selected component occurrence/version and can
change material evidence for all its consuming contexts. They do not establish
applicability, approvals, legal clearance, architecture approval or published scores.

Topology presentation initially shows 50 imported direct consumers and 50
dependencies, with full counts and explicit unresolved references/unknown graph
coverage. Each direction supports separate search and paging through all declared
neighbors; an unsubmitted search never changes the active paging scope. Failed
reads retain the displayed results and exact state/component pins.

`GET /api/v3/projects/{id}/states/{sha}/component-neighbors` requires current
project-read authorization and an existing component occurrence. It accepts
`component_ref`, `direction=incoming|outgoing`, `q`, `offset` and `limit` (1–200).
Full filtered and declared counts precede paging; duplicate direct edges are
deduplicated, unresolved references and cycles retained. Historical queries stay
pinned after nightly imports. CLI consumers can use `knowledge request GET`
with this same endpoint. Search covers source-local reference, name and version.
 It does not infer runtime reachability or completeness, add cross-part
assembly edges, edit dependency topology, provide a full interactive graph, or
prove generated architecture correspondence. Imported source facts remain intact;
prior metadata revisions and human decisions remain recoverable in journal history.


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

### Pinned composition and selected advisory comparison

`POST /api/v3/projects/{id}/compare/intelligence?offset=0&limit=50` takes
`inventory_state`, an explicit required `evidence_state` (SHA or null), and optional
`expected_digest`. Current project read permission applies on every request.
The composition must be committed product history in that product line; selected
evidence must belong to the retained ancestry of its evidence reference. An object
hash alone grants no access. Explicit null means no selected advisory catalog;
the endpoint never silently selects the latest state.

The report compares advisory-feed observations embedded in the pinned product
state with the selected retained advisory documents, restricted to exact baseline
SBOM/DT vulnerability identifiers. Source/publisher/document/identifier groups
stay separate. Rows disclose added, changed, unchanged, withdrawn-from-selection
and no-longer-selected claims, original/selected facts, artifact/source-revision
pins and inactive selection reasons. Missing selections and source withdrawal do
not establish publisher retraction, remediation or applicability. VDR/VEX status
documents are excluded with counts, not applied to historical composition; aliases
and affected ranges remain provider facts, not matching instructions.

Full statistics and the deterministic `report_digest` precede pagination. Keep
both state pins and `expected_digest` for subsequent pages; a different report
returns 409. The digest covers immutable selected inputs and all rows, while
`currentness` separately reports the evidence head captured for this request and
whether the selected evidence matched it. Later head changes can update that
currentness observation without changing the historical report or invalidating
its digest. Current-at-capture is not source authenticity or a live guarantee.

Scanning stops at explicit finite budgets: 10,000 states/frontier entries,
20,000 records per section, 10,000 documents/statements per side, 10,000 resulting
claim groups and 64 MiB decoded immutable object bytes. Bounds are checked before
loading the next object and failures never silently truncate. Raw provider
artifacts are named by retained hashes but not downloaded or all reverified by
this comparison. No provider call, object write, new finding, package rematching,
human assessment, approval, source Base or contextual score change occurs.

CLI uses the same backend contract:

```bash
uv run dtvp knowledge --url http://127.0.0.1:8900 compare-intelligence \
  --project PROJECT_ID --state INVENTORY_SHA --evidence-state EVIDENCE_SHA --json
```

Use `--no-evidence` for explicit null; neither flag may be omitted or combined.
For bounded pages retain `--expected-digest REPORT_SHA --offset OFFSET` and the
same inventory/evidence selection.

The existing **Advisory intelligence refresh** panel includes a collapsed,
read-only **Compare retained inventory with advisory evidence** view. Capture
inputs explicitly, optionally select an exact committed inventory SHA under
**Choose retained inventory state**, then choose the captured evidence reference,
an explicit no-evidence selection, or an exact retained evidence-state SHA.
**Use workspace inventory state** changes only the next comparison input; it
never repins displayed report pages. Comparing never
queries an external provider, updates source ratings or assessments, or infers
remediation. The inventory/evidence pins remain visible alongside complete
server-derived counts; provider differences on the displayed page and exact
before/after/inactive facts are available progressively.

Pagination retains the original inventory state, evidence state (including JSON
null) and report digest even after draft controls, the inventory workspace or
current evidence reference change. Capture and compare again explicitly to
replace that report. Currentness describes the evidence reference at comparison
capture; it does not establish continuous freshness or credibility. Digest
conflicts retain the previous page and pins. Current project authorization still
applies on every read, and actor/project changes invalidate late responses.

### Pinned pipeline evidence summary

`GET /api/v3/projects/{id}/states/{sha}/evidence-summary` returns
`dtvp.pipeline-evidence-summary/1`: exact product/version/state and section pins,
a deterministic `summary_digest`, and full unfiltered counts for imported
inventory, producer-declared acquisition coverage, input-quality observations,
contextual team reviews, ownership gaps, published-score currency, license
evidence/dispositions, controlled documents and retained absent assessments.
Counts reuse the existing backend classifications, including independently
retained approved pins alongside newer pending revisions. Historical document
approvals remain separate from approvals whose input material is current in the
selected state. Team counts may overlap; zero findings never establishes clearance.

```bash
uv run dtvp knowledge --url http://127.0.0.1:8900 evidence-summary \
  --project PROJECT_ID --state STATE_SHA --json
```

The CLI only presents the HTTP result. Project read permission and committed
product-state membership are checked on every request. Historical states remain
available without consulting newer branches, provider information or the clock.
The summary has no release/compliance verdict and changes no records. Consumers
must explicitly define downstream policies; machine-readable limitation codes
explain unknown producer coverage, historical-only scope and documentary limits.
Detailed pinned input-quality, license, document and consumer-bundle reports are
linked separately; original component/source/report payloads are not duplicated.

Native bundles with authored annotations also include an optional
`component_metadata` register (`dtvp.component-metadata-register/1`). It contains
every recorded occurrence, including components without findings, with exact
revision/authorship/provenance and server-derived current, stale, absent or
out-of-scope status. Consumers can present current support/context facts without
interpreting raw historical records as current annotations. No approval is implied.

New knowledge-bundle issuances containing this register identify serializer `/2`;
bundles without annotations keep their prior representation and serializer `/1`.
Previously issued selectors always replay their archived original bytes, including
older bundles without the register. They are never enriched through later lookups.

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

Native bundles with recorded license dispositions also expose an optional typed
`license_dispositions` register. It includes current, pending, independently
approved and stale status with exact revision pins and limitations. Source license
declarations remain separate; a pending prohibited decision never replaces the
retained approved disposition implicitly. No-record bundles retain their prior
bytes. Previously issued inputs always retain their exact archived representation.

Offline supplied-dictionary ranking is available through `POST
/api/v3/projects/{id}/states/{state}/cpe/rank`. Project readers submit an exact
component reference and up to 2,000 supplied records; no network call, journal
write, inventory change or identity adoption occurs. The state must be committed
product history, including assembled part roots. Optional `policy` pins a retained
CPE policy; omission explicitly uses current configuration, independently of the
historical inventory date. Existing exact discovery endpoints remain unchanged.

Example body:

```json
{
  "component_ref": "component-ref",
  "records": [{
    "cpeName": "cpe:2.3:a:vendor:product:*:*:*:*:*:node.js:*:*",
    "cpeNameId": "supplied-dictionary-id",
    "deprecated": false,
    "source": "organization-supplied-nvd-extract",
    "publisher": "claimed publisher",
    "refs": [{"ref": "https://www.npmjs.com/package/product"}]
  }],
  "offset": 0,
  "limit": 50
}
```

The complete request is limited to 2 MiB **before JSON decoding**, with bounded
strings and at most 50 references per record. Extract each selected NVD product's
`cpe` object and add explicit `source` attribution; the endpoint does not accept a
whole dictionary/feed envelope or download one. CLI users can call the route via
the generic native JSON request command. Candidate and rejection pages share an
offset/limit (1–200); `counts` and `content_digest` describe the full report before
paging. Ordering evidence is exposed by named tuple dimensions, never a confidence
percentage. An equal top rank across different CPE identities reports ambiguity;
`selection` always remains null.

Ranking reuses supplied policy mappings/aliases and tests exact package registry
references, supplied VCS repository plus product name, or namespace/vendor plus
product name. Deprecated, incompatible ecosystem/part, explicit version conflict
and contradictory supplied repository claims are excluded. Original CPE bindings,
versions and platform constraints are retained. Unknown package versions remain
explicitly unknown; a wildcard dictionary version is not an exact version match.
Publisher, dictionary and URL claims remain unverified. URL agreement is not proof
of binary/build identity or vulnerability applicability. There is no general
name-only matching, live registry/NVD refresh, Java vendor inference, deprecated
replacement traversal, automatic mapping approval or full standalone-service
parity. Compatibility fixtures cover sibling cpeservice homonyms, scoped npm
identity, incompatible Go/type-definition products, shared monorepos, ambiguity
and deprecated/malformed records.

The pinned license worklist supports `q` (at most 500 characters),
`evidence_status`, `review_status` and `approved_disposition`; all predicates
combine before statistics and pagination. Search spans component identity,
attributed source facts and recorded human review text. Evidence statuses are
`reported`, `explicit_none`, `unknown`, `not_reported` and `malformed`. Review
statuses follow the native license register; `pending` selects a new revision
while a valid earlier approval remains. Approved disposition is
`allowed`/`restricted`/`prohibited`/`unresolved`, or `missing` when no current
approval exists. A pending conclusion never substitutes for the pinned approved
one. Empty filters preserve the existing worklist and consumer representations.

```bash
uv run dtvp knowledge licenses --project PROJECT_ID --state STATE_SHA \
  --q MIT --evidence-status reported --review-status pending \
  --approved-disposition restricted --limit 20 --json
```

The license panel applies its compact search/filters explicitly. Dirty conclusions,
independent-review rationale and uncertain publication requests prevent silent
row/page/product/version changes; discard is explicit. A workspace refresh retains
the original selected source head and revision, including before the first submit.
Retries preserve the exact endpoint, body, request ID and concurrency pins. Buffers
clear only after a committed publication with a current projection, or explicit
discard; changing actor remounts the panel and drops the prior actor's buffers.

### Explicit occurrence correspondence

The collapsed Knowledge correspondence panel links explicitly selected component
occurrences or consuming contexts across committed product states. Source refs,
history and occurrence selectors are bounded/searchable. The server previews exact
PURL/version/hash facts and consuming-tree differences. Contradictory coordinates,
same-version checksum conflicts and malformed checksum evidence block confirmation.
Component links and usage-context links remain separate. Nothing is paired by name.

`POST /api/v3/projects/{id}/reconciliation/preview` accepts exact `source`, `target`
and 1–100 typed pairs. Confirm with `POST .../versions/{version}/reconciliations/{id}/confirm`
using expected target head/revision, preview digest, source, pairs, rationale,
evidence and request ID. Explicit `/retract` retains previous assertions; paged
`.../states/{state}/reconciliations` returns the registry. The generic HTTP CLI
uses these same JSON contracts. State-scoped `/reconciliation-candidates` supplies
bounded exact component/context IDs, including historical ownership.

Assertions retain source/target pins, author and immutable revision history. They
do not merge identities, transfer decisions or grant reviewed coverage. A preview
is a consistency check, not proof of equivalence. One-to-one pairs are enforced
within an assertion; separate assertions may conflict and are not a global identity
map. Semantic reconciliation, cross-assertion conflict resolution and controlled
assessment reuse remain separate work.

### Historical state comparison

`GET /api/v3/projects/{id}/refs` lists product branches and immutable tags.
`GET .../history?version=7.1.1` lists reachable product revisions. Both paginate
with `offset`/`limit`; configuration and constituent-source states are excluded.
`GET .../compare/details?before=SHA&after=SHA` returns bounded component,
dependency and contextual-finding changes with full-set counts. Classifications
separate material evidence, bookkeeping, ownership, assessment, review and scoring.
Retained absent assessments stay visible. Comparisons read immutable journal
states without loading historical data into live PostgreSQL tables. Historical
comparisons use the bounded actor-independent cache described above. The separate
pinned advisory comparison inspects selected retained claims without rematching
or reevaluating historical assessments. Exact source-local references determine
identity: changed references appear as remove/add, never a name-based match or
proof of remediation.

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

Native Knowledge includes a lazy CPE discovery policy panel, available before the
first inventory import. Readers can inspect the current policy, supplied catalog,
attributed mapping rules and scope limits. Project managers can prepare a complete
replacement as catalog/rules JSON, inspect server normalization and explicit
addition/removal/change counts, then confirm publication. Omitted catalog entries
and rules are removed from the current policy; immutable policy history remains.
Refresh does not repin a captured request. Failed or uncertain publication retains
the exact original inputs, expected policy state and idempotency key for retry.
The interactive editor is bounded to 8 MiB; the existing typed API supports up to
50,000 catalog entries and 50,000 rules. Configure policy through existing
`PUT /api/v3/projects/{id}/cpe`; the read-only editor adapter is
`GET .../cpe/editor` and the non-publishing normalization preview is
`POST .../cpe/preview` with the same DiscoveryInput body. Preview is optional for API
clients; it is not an additional approval or publication authorization.

This is an offline supplied-input module, not full standalone CPE-service parity.
Publisher/source and reviewed-status claims remain attributed, unverified inputs.
Preview checks supported input normalization, not dictionary existence or complete
alias validity for every future component/version. Component-specific alias cycles
and version conflicts are checked during discovery. Publishing a policy never
adopts CPE identities, changes SBOM inventory, assesses vulnerability applicability,
or creates human approval. Existing candidate panels refresh explicitly against
updated policy. Supplied-dictionary ranking is available offline through the
pinned component ranking endpoint. Network dictionary refresh, fuzzy ranking,
full service migration and deployment qualification remain separate work.


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
still-valid pinned coverage. Native NVD/CIRCL enrichment is available through
explicit durable jobs; native package matching/OSV jobs and extended non-US
adapters remain planned. V2 connectors retain their separate runtime.

`GET /api/v3/projects/{id}/advisory-refresh` returns a bounded searchable list of
baseline-known CVE IDs, enabled providers, next producer ordinals and complete
pinned version/evidence selections. The collapsed Knowledge refresh panel selects
up to 20 IDs explicitly. `POST .../advisory-jobs` requires those pins, provider,
IDs, explicit revision and request ID. GET job/status and POST retry/cancel use
current project permissions and requesting-actor authority. The generic HTTP CLI
can submit the same JSON through `knowledge request`.

Workers recheck permissions and provider enablement before each fixed-endpoint
GET, retain exact decoded response bodies, and checkpoint before atomic evidence
publication. Partial refresh preserves untouched catalog entries. Not-found may
withdraw that provider's prior fact but never removes a baseline finding or proves
remediation. A changed target requires a new explicit request; retries never
replace pins or refetch a completed capture. NVD and CIRCL must be enabled through
`DTVP_PROVIDERS_ENABLED` on API and worker. No provider requests occur implicitly.

`GET .../evidence/artifacts/{sha}?expected_evidence=SHA` retrieves a raw response or
capture pinned in the selected committed evidence ancestry. This keeps untouched
catalog evidence available after partial refresh and in new product branches.
Project authorization applies; the response identifies the actual retaining state.
Mirrors retain upstream publisher attribution and do not establish independent
corroboration. Provider rate-limit errors fail collection without partial publication;
broader scheduling and provider-specific rate management remain planned.

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

### Controlled generated documents

Native document registration stores exact output bytes, an issued input receipt,
renderer name/version, configuration and rationale. Documentation analyst and
reviewer are dedicated roles; vulnerability, license and administrator roles do
not confer these authorities. An independent reviewer approves an exact submitted
revision. Pending changes retain the previous approved output. Historical input
requires explicit acknowledgment, and approved output remains visibly historical
when material input changes. Approval records content review; it does not certify
architecture correctness, legal clearance or regulatory compliance.

Upload multipart `file` and JSON `metadata` to
`POST /api/v3/projects/{id}/versions/{version}/documents/draft` or `/submit`.
Metadata pins `expected`, `expected_revision`, `document_id`, `issued_receipt_sha`,
`renderer`, `configuration`, `title`, `purpose`, `rationale`, `filename`,
`media_type` and `request_id`. Submit exact revision reviews to `/documents/reviews`;
read paged records under `.../states/{state}/documents`. Original artifact downloads
use the authorized state artifact route. CLI uploads preserve the same exact bytes
and explicit metadata: `knowledge document-register --project ID --version VERSION
--file report.pdf --metadata document.json` saves a draft; add `--submit` for review.
The CLI never creates request IDs or replaces concurrency pins. Generator
qualification remains separate cutover work. Generator’s isolated integration
branch now consumes issued inputs and preserves exact input archives; see
[consumer delivery evidence](docs/consumers.md).

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
backups remain necessary for jobs. Opt-in actor-only authenticated remote-ID
reconciliation and exact parent/report-bound follow-up jobs are implemented as
described above. Follow-ups require the optional authenticated sibling extension;
legacy unbound follow-ups are never a silent fallback.
The specialist panel shows bounded jobs for the selected context/vulnerability.
Qualified input preparation precedes an explicit queue action. Status refresh,
retry and local cancellation are explicit; backend capabilities control actions.
Failed submissions preserve guidance and retry identity. Unknown submissions
never offer analysis resubmission; eligible opted-in jobs offer explicit completed
remote-job verification with frozen remote/request IDs. Legacy jobs without private
correlation remain unresolved.

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

The collapsed **Vulnerability evidence sources** panel works before the first SBOM.
It lists retained active/inactive documents, original downloads and parser losses.
Uploads preview semantic scope across exact version/evidence pins, then explicitly
import the frozen original bytes. Withdrawals require an explicit reason and keep
history. Unknown scope, source contradictions and unsupported fields remain visible;
received assertions never become human approvals automatically.

`POST /api/v3/projects/{id}/evidence/files/preview` accepts the same raw multipart
file/import metadata as `/evidence/files`. It writes nothing and returns the raw
SHA-256 plus matched/unresolved/conflict information. This is a semantic preview,
not an exact simulation of producer ordering or supersession; import performs those
checks separately. Read-authorized retained inspection uses
`POST .../evidence/{artifact}/preview` with expected evidence/version pins.

CLI: `knowledge evidence-import --project ID --file evidence.json --metadata import.json`
imports exact bytes; add `--preview` for read-only inspection. Metadata explicitly
supplies request ID, source, producer revision and evidence/version pins. Ambiguous
responses reuse the same bytes and metadata; the CLI never replaces pins or IDs.
JSON semantic subsets are supported; XML and signature verification remain outside
this intake contract.

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
schema. The basic comparison reports changed record keys; historical semantic
comparison adds bounded classified details and a process-local cache. Explicit
occurrence correspondence is available, while automatic semantic identity reuse
remains deferred. Normal application commands must use the API; local reconstruction
is an administrative operation.

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

APIs: `/api/v3` for native knowledge and `/api/v2` for compatibility;
schema: `/openapi.json`; readiness: `/readyz`; process liveness: `/healthz`.
Readiness requires the current SQL schema and a native projection checkpoint
aligned with the journal publication hash and sequence. Lag, missing checkpoints
or an unreadable current publication return 503 without changing data. Readiness
does not rebuild projections, inspect every retained object or verify source
claims; offline journal verification and explicit recovery remain separate.
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
npm run test:integration        # real native workflow; same explicit disposable URL
```

`DTVP_TEST_DATABASE_URL` enables destructive integration checks against an
explicitly disposable PostgreSQL database whose name ends in `_test`.
Fast tests use SQLite only as an isolated test adapter. The browser suite combines
mocked transport/UI contract checks with live legacy workflows. The separate
`test:integration` lane uses real native HTTP/storage: exact-byte intake, version
comparison, analyst submission, independent review, coordinator score publication,
source preservation and parallel-version isolation. It also covers the coordinator's
all-team queue. This lane has passed against SQLite and PostgreSQL.

`uv run python scripts/playground.py test` runs backend/build/unit/browser checks,
then the real native integration lane against its disposable PostgreSQL playground.
Native integration creates uniquely named synthetic projects without resetting
existing data; it verifies playground mode before project writes. It runs after
legacy reset-dependent cases because a populated journal intentionally blocks the
legacy SQL reset. Keep manual integration runs on an explicitly disposable target.
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
