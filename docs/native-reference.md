# Native workflow reference

[README](../README.md) is the canonical overview; this reference retains detailed
implemented native contracts and limitations. `/openapi.json` is the executable
request schema. All application endpoints use the single API prefix defined by
`API_VERSION` in `dtvp/api_contract.py` (currently `/api/v1`). Historical format
names such as `dtvp.snapshot/1` and migration paths identify captured data formats,
not a separately mounted legacy runtime. UI and CLI present these same workflows.
No retired SQL Review, finding, release-ingestion or snapshot-writer API remains.

## Inventory import and assembly

`POST /api/v1/projects/{id}/versions/{version}/imports` requires an idempotency
request ID, optional expected head (null for create-only; omitted or `"current"`
for server-selected current head), source, monotonic source build number,
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
  --project "Product name or ID" --version 7.1.2 --file bom.json --metadata import.json
```

`import.json` contains import metadata and a request ID; `expected` is optional.
The backend resolves or creates the product, then the import creates or updates
the version. Add `--workspace WORKSPACE_ID` for ambiguous product names or creation
among multiple writable workspaces. Omit `expected` to update the current baseline;
explicit SHA/null pins remain strict. Reuse metadata and bytes unchanged after
uncertain responses; the CLI never invents retry identities or replaces explicit
concurrency pins. Receipt replay precedes automatic head selection. New imports
still require increasing build numbers within their source binding. Add `--part PART_ID` for constituent
intake; product assembly remains a separate explicit publication.

Optional import `context` records subject kind/digest, target, platform,
configuration, source revision, pipeline run, collector/version/method, limitations
and separately declared package/dependency/license coverage. Missing coverage
stays unknown; `complete` is snapshot replacement within scope, not verified
product completeness. Ordinary imports cannot change declared scope and silently
overwrite another target/platform/configuration. Native assembly selects pinned
constituent inputs; legacy combined input cannot recover lost provenance.
Native intake retains source relationship kinds; SPDX containment is not treated as dependency
topology. Historical snapshots preserve their captured earlier conversion as evidence only.

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

The native workspace's **Assemble product** editor also supports a new version
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

Assembly selects delivery parts within one product/version. Separate observation
intake reconciles overlapping evidence; nested assemblies remain unsupported. Explicit pinned cross-part DEPENDS_ON/CONTAINS
relationships are supported; identities are never merged automatically. Each new
product version needs its own constituent imports; cross-version source reuse
remains outside the assembly contract. Unique strong identities now support same-version
lineage continuity without collapsing distinct delivery parts. Unresolved relationship
endpoints fail assembly; external-document references need explicit reconciliation.
Native Review shows assembled findings and their consuming contexts.
Explore a repeatable two-part nightly update against the running playground:

```bash
uv run python scripts/assembly_demo.py
```



### Automatic identity comparison (first implementation slice)

`GET /api/v1/projects/{id}/states/{target}/identity-matches?source=STATE` compares
pinned committed product states using unique exact versioned PURLs or conservative
component-artifact digest matches. Full qualifiers/subpath remain significant;
contradictory coordinates/hashes and duplicate occurrences block matching. Missing
fields stay unresolved rather than blocking import. Matching is separated by
part and root/component role; changed collection boundaries block candidates.
The report includes complete counts, a page-independent digest, up to 200 matches
per page and a bounded sample of 100 unresolved diagnostics.

The native correspondence panel offers **Component identity continuity** after
selecting a pinned source. It loads only on request and preserves exact report pins
while paging. CLI uses the same server report:

```bash
uv run dtvp knowledge identity-matches --project PROJECT --source SOURCE_SHA --target TARGET_SHA --json
```

This report discovers compatible identity candidates. Accepted imports additionally
retain the stable lineage metadata described below; neither mechanism rewrites
graph references, merges observations or carries approvals across changed references. Existing explicit correspondence/adoption
workflows remain separate. Source-local occurrence and assessment semantics are
unchanged.

### Stable import identity metadata

Accepted single-baseline and constituent imports now retain an additive
`inventory.identity` ledger (`dtvp.component-lineages/1`, matching policy
`dtvp.component-identity/1`). Component inventory read rows expose the corresponding
`identity` object; historical states and assembled inventories without a ledger
return `null`. Import-local component payloads, references, dependency edges and
assessment target fingerprints are unchanged.

Within the same product/version/source/part and collection boundary, unique
compatible exact-package or scoped strong-artifact matches continue stable lineage
IDs, including renamed source references. Existing pre-ledger states bootstrap IDs
deterministically from their original source artifact, reference and occurrence role.
Missing/ambiguous/conflicting markers retain distinct IDs with unresolved status;
names and references alone never establish cross-import correspondence. Removed IDs
remain tombstones linked to their last retained state/artifact. Reappearance does
not silently restore a removed lineage. New product versions continue exact matched lineage IDs only through an explicit
predecessor, with unchanged project/source/part/boundary. Independent branches never
inherit IDs implicitly; shared lineage does not extend approved version coverage.

The ledger is bounded to 100,000 current-plus-retired identities and 32 MiB; imports
fail closed rather than truncating retained links. It records identity continuity
only: it does not merge overlapping observations, rewrite references, establish
context equivalence or carry assessments/approvals across changed targets.

Assembly publication now propagates selected constituent lineage metadata into
`inventory.identity` (`dtvp.assembled-component-lineages/1`). Inventory rows expose
the selected source lineage ID with its exact part, source state and local reference;
source-root aliases share one metadata entry. Identical packages in distinct parts
remain distinct. Pre-ledger part states bootstrap the same original-artifact/ref IDs
used by subsequent imports. Removed/withdrawn identities remain tombstones, while
retained parent states preserve their original metadata. Selecting a historical
source state explicitly restores that state's recorded identity rather than guessing
continuity. Aggregate ledgers retain the 100,000 identity/32 MiB bounds.

This is metadata propagation, not overlapping-observation reconciliation. Assembled
component payloads/origins, namespaced references, dependency graphs and assessment
target fingerprints remain unchanged; lineage does not extend approval coverage.

### Same-subject observation reconciliation kernel

The pure `propose_observation` kernel compares individual delivery-part inventories.
Matching requires compatible collection/delivery-part scope and either an identical
known artifact digest or explicit user/CI same-build metadata. It returns unique occurrence mappings,
attributed supplemental metadata/conflicts and duplicate typed-edge support.
Additional components or topology remain explicit proposals; authoritative inventory,
consuming contexts and approvals are unchanged. Inputs remain immutable and report
records/bytes/diagnostics are bounded.

The kernel accepts `subject_declaration` using `dtvp.subject-declaration/1`:
product/version, optional part, subject/build IDs and exact SHA-256 of the original
authority and observation SBOM files. Reports distinguish `producer_declared`,
`digest_bound` and `unresolved`; conflicting known digests/scope or stale file
bindings block reconciliation. SBOM file hashes do not prove binary identity.

The CI owner/user supplies these relationships and threat-model mappings as
versioned metadata. DTVP validates them and returns diagnostics, rather than
routinely prompting reviewers. Generator's existing entity-name mappings remain
compatible; stable entity IDs require a pinned model revision. See the
[user/CI metadata contract](rewrite-plan.md#userci-supplied-metadata-and-subject-declarations).
Public observation intake/publication and durable mapping configuration now ship;
HTTP authorization checks the declared product/version scope before import.

### Read-only global orphan audit

Instance operators can inspect storage reachability across all projects and all
retained publications, ancestry, tags, source/issued artifacts and stored references:

```bash
uv run python -m dtvp.knowledge.garbage_collection --journal data/artifacts/knowledge --min-age-days 30
```

Select the actual existing journal directory. The command never initializes a new
journal or deletes objects. It validates stored hashes, bounds scans to 100,000
entries/256 MiB, and rejects detected storage changes. It holds the publication lock
while scanning; use a quiet maintenance window. `--operational-root SHA` can add
known pending-job roots, but these hints never establish complete operational
coverage. `--offset`/`--limit` page unreachable observations. Modification age is
not time since last use, and no default expiry is configured.

Every item reports `eligible_for_deletion: false`; `execution_supported` and
`operational_references_complete` remain false. Journal-unreachable bytes may be
staged inputs or SQL-backed job checkpoints. The observation digest is not a
permission to delete. Physical cleanup is a separate offline command with runtime exclusion and SQL
reference discovery; the read-only audit alone never authorizes deletion.

### Offline orphan cleanup

Physical cleanup uses an explicit maintenance window. Stop all API/worker replicas
and independent local writers first. API construction/lifetimes, workers and local
mutating CLI commands hold shared runtime leases; cleanup holds an exclusive lease
on the persistent `.knowledge-maintenance.lock` beside the journal. All processes
must use the same artifact directory on a local filesystem with POSIX flock support.
Do not remove the lock file. These guards do not fence arbitrary external scripts
or direct storage edits; those must also remain stopped.

Set `DTVP_DATABASE_URL` to this installation's operational database, then prepare
and inspect a bounded plan (at most 200 objects):

```bash
uv run python -m dtvp.knowledge.offline_cleanup --journal data/artifacts/knowledge plan --min-age-days 30 --output /tmp/dtvp-cleanup-plan.json
uv run python -m dtvp.knowledge.offline_cleanup --journal data/artifacts/knowledge apply --plan /tmp/dtvp-cleanup-plan.json --recovery-dir /path/to/new-cleanup-recovery
```

The plan/output and recovery paths must be fresh. Recovery must be outside the
installation artifact directory; its existing parent must be writable. Planning
and application require stopped managed runtimes and the exact current SQL schema
and projection. PostgreSQL table locks (or isolated SQLite exclusive transactions)
prevent operational DML during inspection/application. All SQL rows are hashed
without exposing their contents; existing object references from every table and
all job statuses are retained. Missing/corrupt known native checkpoints fail closed.
All retained journal history, tags, outputs and supporting artifacts remain protected.

Apply rechecks the complete SQL/storage observation and explicit age policy.
Stale or modified plans require a fresh preview. Before the first unlink it writes,
fsyncs and verifies exact recovery copies of every selected object, plus plan and
recovery manifests. Deletion receipts are stored in that operator-only recovery
directory. Interruption can leave partial deletion, but every selected original
has a verified recovery copy before deletion starts. Do not blindly replay a
partially applied plan; inspect its removal records and prepare a new plan, or
restore missing copies by verified digest with `Artifacts.put` while stopped.
Backups/recovery-directory retention is separate: copies consume space until an
operator's backup policy releases them. No journal ancestry or draft history is
compacted, and no cleanup runs automatically during imports or startup.

### Pinned composition input observations

The native workspace groups a lazy **Composition input observations** disclosure
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


`GET /api/v1/projects/{id}/states/{state}/input-quality` provides a read-only,
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

`GET /api/v1/projects/{id}/intake-target?version=VERSION[&part_id=PART]` returns the
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

`GET /api/v1/projects/{id}/ownership/editor` returns exact policy/head pins,
selector descriptions, team choices and management capabilities. Managers stage a
complete policy, call `/ownership/editor/preview`, then explicitly
`/ownership/editor/apply` with that preview digest. Preview writes no journal objects.
Apply uses the existing atomic policy workflow; retries of the same policy/request
return its receipt before checking changed heads. The preview digest is an initial
admission check, not part of the existing policy idempotency identity.
Consuming-root configuration and untouched selectors remain preserved. Historical
team assessments and approvals retain their original scope when ownership changes.

### Assessment API and CLI

`GET /api/v1/projects/{id}/versions` lists current product branches.
`GET .../versions/{version}/workspace` returns contextual findings and full filtered
statistics; basic filters are `team_id`, `work_scope`, `q` and `lifecycle`, with bounded `offset`/`limit`
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
versions. Native Review collapses these options by default, with explicit
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

From the repository root, use `uv run dtvp`; uv installs the project entry point
automatically. No shell alias/function or separate installation is required.
`uv run dtvp --help` lists commands; `uv run dtvp knowledge --help` lists remote
workflows. The CLI uses the same HTTP contracts without opening the application
database:

```bash
uv run dtvp knowledge --persona analyst workspace --project PROJECT_ID --version 7.1.1
uv run dtvp knowledge --persona reviewer request POST /api/v1/projects/PROJECT_ID/reviews --body review.json
```

Production CLI calls read a bearer credential from `DTVP_API_TOKEN` (or the named
`--token-env` variable); `--persona` works only against an enabled playground.
Workspace flags mirror advanced server filters with hyphens, for example
`--source-severity critical --team-review approved --dependency transitive`.
Displayed totals always come from the server's complete filtered selection.
My work defaults analysts and reviewers to all their current assessment/review
teams through server-derived `work_scope=my_teams`; managers/coordinators default
to `all`. Product browsing retains explicit team selection. An explicitly chosen all-team
view is retained in shared URLs and saved views, including after reload. Filtering
a workspace never grants team permissions.
Team labels come from that authorized selection, including teams outside the
viewer’s memberships; showing a label grants no team role.
Use workspace `--json` for complete machine-readable rows and evidence. Mutations
forward the explicit JSON payload; no approval or scoring logic lives in the CLI.

### Routine file intake

New UI products open Imports directly. Routine uploads need a product version,
file and complete-baseline confirmation. Advanced metadata is optional: target
inspection supplies the current file source or `file:upload`, next sequence (1 for
a new source) and current UTC time. UI preparation and CLI upload freeze resolved
metadata and state pins with exact bytes. Automatic sequence/time describe import
ordering/preparation, not verified producer build evidence. `import-file --metadata`
is optional; CLI diagnostics expose the resolved metadata for explicit exact retry.
Connector and assembled-source authority restrictions still apply. UTF-8 XML BOMs
are recognized without rewriting retained original bytes.

### Workspace tools

The left navigation separates My work, Products, Activity and authorized
Administration. Product navigation separates Overview, Vulnerabilities, Components,
Imports, Versions, Licenses, Documents and Settings. Ownership, source connections,
pipeline configuration, scoring policy, CPE identity policy, automation and product
sharing live in Settings; maintenance lives in Administration. Each destination opens
its primary native panel. Other component instances, captured requests and draft
inputs remain mounted. Pending captured changes lock navigation. Narrow screens use
a collapsible menu and product-view selector. Empty products retain Imports and
Settings before a first baseline. Hover changes background without widening control
borders; keyboard focus remains visible.

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

The native queue lets independent team reviewers select up to 100 exact
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
`POST /api/v1/projects/{id}/correspondence-drafts/preview` takes pinned source and
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
uv run dtvp knowledge --persona analyst correspondence-draft \
  --project PROJECT --input preview.json
uv run dtvp knowledge --persona analyst correspondence-draft \
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
`GET /api/v1/projects/{id}/states/{state}/correspondence-draft-candidates` with
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


The native assessment panel can load a pinned coverage matrix across current
product versions. Candidates distinguish matching material, changed material,
different consuming contexts, identity conflicts and absence. Extra targets are
never preselected; compatible lineage alone does not establish applicability.
Independent existing decisions are preserved. Explicit shared targets require
supporting conditions and retain independent reviews per version/context.

`POST /api/v1/projects/{id}/coverage/candidates` accepts `source`, `context_id`,
`vulnerability_id` and optional `expected_preview`. The complete preview digest
pins heads across pages; a changed selection returns 409. Results include current
actor capabilities without granting access from team ownership. The HTTP CLI uses
`knowledge coverage --project ID --state SHA --context SHA --vulnerability CVE`
with `--json` for the complete server response. Review and score publication stay
separate from selecting assessment coverage.

### Statistics across authorized projects

`GET /api/v1/portfolio` captures one complete current-reference selection across
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
`knowledge request GET /api/v1/portfolio` with the same query parameters. This
read-only report creates no assessments, approvals or completeness claims.

My work shows scoped product/version queues and workload, with the detailed
**Statistics across products** report. Product Overview contains only the selected
product’s statistics. Opening the cross-product report requests server-derived
statistics for all currently accessible products (up to 100), or use the bounded
searchable catalog to select products explicitly. Team and current workspace finding filters
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

Native Review offers a collapsed portfolio panel. It inherits workspace
filters and can select current versions and a team. Changed heads retain the
previous displayed pins until an explicit refresh; counts come from the API.

`GET /api/v1/projects/{id}/portfolio` aggregates authorized current version heads
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
/api/v1/projects/{id}/versions/{version}/connectors/dependency-track` with
`external_project_id` and `expected_external_project_id` (null initially).
Historical global bindings are not consulted by native version intake.
Deployment owns DT URL/read credentials. Source authority includes
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
The native workspace includes a collapsed source panel for the selected version:
explicit management binding, build/time intake, safe job refresh and backend-allowed
retry/cancel. Inputs survive conflicts and uncertain responses. New-version and
constituent intake remain available through the HTTP CLI/API.

### Withdraw an incorrect baseline

`POST /api/v1/projects/{id}/versions/{version}/withdrawal` takes `request_id`,
expected current head and a reason. It withdraws the active single-source
inventory selection, creating an empty current view while retaining assessments,
metadata, reports, original bytes and immutable release tags. Nothing is physically
deleted. The workspace explicitly marks withdrawal; it is not a clean vulnerability
result. Withdrawn states cannot be release-tagged. Corrected intake keeps the same
source/scope authority and requires a newer build number. Reappearing identical
contexts recheck retained coverage. Assemblies use explicit part withdrawal instead.

`GET .../states/{state}/retained-assessments` lists retained assessment revisions
for absent findings by default, with optional recorded `team_id`, `absent_only`,
`offset` and `limit`. The native workspace offers a collapsed history list.
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
See [Agentyzer integration](agentyzer.md) for contracts, operational-backup needs and limitations.

Set `DTVP_AGENTYZER_RECONCILIATION_ENABLED=true` explicitly (default false).
A strong existing token alone leaves the previous POST body unchanged; only new
opted-in jobs gain private proof. The isolated sibling completed-job reconciliation increment is commit
`a10b5d4` on `fix/immutable-source-binding` in `/tmp/agentyzer-source-binding`;
it has not been merged, pushed or deployed.

Native analyses now support explicit parent/report-bound follow-ups through
`POST /api/v1/projects/{id}/versions/{version}/analysis-jobs/{parent}/follow-up`.
This requires the optional authenticated Agentyzer extension: exact parent pins
are checked before enqueue and submission, source scope cannot change, and an
uncertain POST is never automatically repeated. Each child is independent
proposed evidence, with its own current authorization and private correlation;
no approval or score publication is inherited. See [Agentyzer](agentyzer.md#native-bound-follow-ups).

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

### Named VDR/VEX validation subsets

Evidence imports and JSON/file previews accept optional `validation_profile`:
`dtvp-cyclonedx-1.5-exact/1`, `dtvp-cyclonedx-1.6-exact/1`,
`dtvp-openvex-0.2.0-exact/1`, or `dtvp-csaf-2.0-vex-exact/1`.
These are DTVP consumed-field contracts, **not complete schema conformance**.
Omitting the field retains existing semantic-subset behavior and old request
fingerprints. Strict profile declarations are retained with the imported document
and returned by document listings/previews; they bind into retry identity.

Strict profiles validate consumed field shapes, version bounds, status/reason
semantics and exact versioned PURL scopes. Unsupported CycloneDX version/range
constraints and external references, OpenVEX inheritance/subcomponent scope, and
CSAF groups/relationships are rejected before publication. CSAF product identities
inside nested branches are now indexed without deriving relationships or ranges;
duplicate document-local identifiers remain unresolved. A strict profile also
rejects unknown/ambiguous product identifiers and conflicting CSAF status assignments.
An exact PURL identifies package occurrences; it does not verify every consuming
context or turn source claims into DTVP approvals.

`POST /api/v1/projects/{project}/evidence/conformance` takes
`{document, validation_profile}` and returns a non-publishing report with bounded
JSON paths/reason codes, validity, limitations and signature-verification status.
Current evidence permission is required. This check does not validate import
ordering, source supersession, branch pins or publisher trust; existing import
checks remain authoritative. File imports retain exact original bytes. No schemas,
contexts or source URLs are fetched; signatures/proofs are never trusted or verified,
including when present. Diagnostic traversal is bounded to 100,000 nodes and depth
64, with at most 64 reported issues. Existing non-strict parsing remains available
for evidence with explicitly unresolved scopes.

The existing evidence-file intake exposes profile selection under collapsed
**Supported-subset validation profile** details. Default requests omit the new
field entirely. A selected profile freezes with exact file bytes, source ordinal,
request ID and version/evidence pins through retries. Successful previews expose
the backend's conformance diagnostics, signature warnings and limitations; failed
strict previews retain their frozen request and display the backend rejection.

Contract references: [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md),
[CSAF 2.0 VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html),
[CycloneDX 1.6 reference](https://cyclonedx.org/docs/1.6/json/).
The supported version bounds describe this implementation; newer standard versions
are not implicitly accepted by these named profiles.

### Native OSV package/version matching

Native matching is now a distinct, explicit leased workflow; it does not reuse known-ID advisory refresh as a matcher or manufacture VEX applicability decisions. Enable `osv` in `DTVP_PROVIDERS_ENABLED` on API and worker to permit fixed-endpoint OSV queries. The default remains disabled. `GET /api/v1/projects/{project}/osv-matching` returns one captured product-head/evidence selection, paginated eligible PURLs, a selection digest, explicit unsupported-occurrence counts and the next source revision. Managers of pipeline evidence select at most20 distinct canonical versioned PURLs from those pinned inventories and `POST .../osv-jobs` with `request_id`, exact `expected_versions`, `expected_evidence`, `purls` and nonnegative `revision`. Current read/evidence authority is required; no package is selected automatically. Qualified/subpath, unversioned, contradictory and unselected occurrences retain unknown coverage.

Queries use OSV's official [`POST /v1/query`](https://google.github.io/osv.dev/post-v1-query/) contract: the version appears only in the PURL, and empty result pages with `next_page_token` are followed. This is an exact **input-coordinate** contract; OSV's version interpretation and reported affected ranges are provider claims. DTVP evaluates no local version ranges, merges no alias identities and infers no binary/build identity or human applicability.

Each completed package query checkpoints its exact identity-encoded response bytes and progress manifest before the next package request. Queries require HTTP200, no redirects, up to20 pages each /200 pages total, at most4MiB per page /32MiB captured response bytes and2,000 matches per package. The entire observation interval is bounded to900seconds. Chunk guards periodically recheck current authorization, exact heads/evidence, deadline and lease ownership, with forced checks after each body; expired workers cannot renew lost leases. A failed partial job publishes nothing and reports remaining coverage unknown. Explicit retry resumes completed frozen queries without refetching them. Once the complete capture is frozen, publication retries never contact OSV or repin heads.

One independently revisioned source document per PURL preserves unrelated query results. A completed no-match refresh retires only the previous claim from that same query source; it does not establish remediation. Provider-withdrawn records remain exact historical evidence and do not seed active occurrences or known-ID enrichment. Source claims are marked `external-match`, unverified and applicability-unassessed. Separate component/part-root occurrences and usage contexts remain separate. Source documents reapply only to current eligible exact PURLs; changed, qualified or contradictory package versions do not inherit them. No assessment, review, coordinator score or approval is created. Active exact matching claims may supply exact known IDs to NVD/CIRCL enrichment; VEX-only and advisory-only feedback cannot expand that identifier set, and aliases are not identity merges.

Before publication, immutable input bytes/pointers and potential expansion are admitted: at most64MiB input objects /250,000 pointers,100,000 source observations and100,000 potential contextual findings, with bounded per-version vulnerability records. Exceeding a limit fails before candidate snapshots or branch changes. Evidence and every captured product branch publish atomically under the original heads, including protection against newly added branches. Exact publication fingerprints bind the complete capture digest.

Readers use `GET .../osv-jobs`, `.../{job}`, and `.../{job}/artifacts/{sha}` for current-scope job status and exact checkpoint/capture/response objects. Only the submitting, currently authorized actor can cancel or retry. Artifact responses include `X-Content-SHA256`. Generic native CLI JSON requests use the same endpoints. Previously issued artifacts and tagged history remain unchanged. Real provider/deployment acceptance and broad ecosystem coverage remain separate gates; mocked qualification does not establish complete vulnerability discovery.

### Recorded software-integration observations

Native integration observations support the first bounded cascading-development
slice. `POST /api/v1/projects/{project}/integration-events` accepts JSON with
`request_id`, exact committed `source`/`target` states, `expected_target` (equal
to target), `repository`, `source_commit`, `target_commit`,
`target_subject_digest`, `pipeline_run`, `integration_kind`, timezone-qualified
`occurred_at`, and meaningful `rationale`. Both states must be single-baseline
product versions in one product line with producer-qualified repository/commit;
the target must retain an accepted SBOM, declared subject digest and matching
pipeline run. Assembly/part scope is explicitly unsupported for this first slice.

Optional `git_commit_objects` maps lowercase Git SHA-1 commit IDs to strict base64
of exact raw commit-object content (excluding Git's `commit <size>\0` header).
DTVP recomputes each object ID and follows an explicit source-to-target parent
path. Both endpoint objects and every intermediate object on the selected path
are required. Supplied malformed/partial/unreachable proof rejects; absent proof
remains a pipeline declaration. Limits: 1,000 objects, 256 KiB each, 8 MiB decoded
proof total and 12 MiB JSON request (also limited by configured upload size).
No repository is cloned, fetched or executed. Exact raw object bytes are retained
as project-readable artifacts. Git SHA-1 is compatibility, not authentication.
Hash/path consistency does not authenticate repository membership, authors,
signatures, tree/blob contents, producer identity or artifact/build correspondence;
cherry-pick, squash and backport labels remain producer declarations.

Recording appends target history under target-head CAS. It never changes inventory,
source branches, tags, assessments, reviews or scores, and never adds the source as
a knowledge parent. Exact receipt replay precedes stale-head/proof checks, after
current API authorization. GET `/states/{state}/integration-events[/event_id]`
reads retained observations. POST `/integration-events/{event_id}/synchronization-preview`
with `{target,basis?,context_mapping?}` reuses existing synchronization diagnostics
only when target is the current head and its exact software/artifact pins still
match the event. Source may be historical. No common basis is guessed, no approval
transfers, and existing draft/review gates remain unchanged.

The generic authenticated CLI uses the same JSON: `uv run dtvp knowledge request
POST /api/v1/projects/PRODUCT/integration-events --body integration.json`; inspect
or preview through `knowledge request GET/POST` on the endpoints above. Recording
remains an API/CLI operation; automatic cascade execution is not enabled.

The existing **Occurrence correspondence across imports** panel now contains a
collapsed **Pipeline integration observations** view. It lazily lists retained
observations for the displayed immutable workspace state, separates producer
integration claims from optional offline commit-object consistency, and keeps
source/target commits, artifact pins and assurance limits available in details.

An explicit event selection enables a read-only assessment comparison. A common
basis is never inferred; an optional exact basis SHA and context mapping JSON
freeze with the event and target across retries and pages. Page results must keep
the same report digest. Workspace advances mark the retained selection stale and
invalidate late responses; loading the new state requires explicit refresh. Actor
and project teardown discard old response authority. No draft, assessment, review,
score, SBOM merge or source integration is applied from this view. Pipeline/event
recording remains an API/CLI operation; existing human review remains independent.

The API-only synthetic cascade demo uses four independent development versions:

```bash
uv run python scripts/knowledge_integration_demo.py
```

Each run creates a new synthetic project with `6.15.6`, `7.1.1`, `7.1.2` and
`7.2.0`, records separate integration observations on `7.1.1 → 7.1.2 → 7.2.0`,
and retains locally checked synthetic commit-object parent paths. A later nightly
build advances only `7.2.0` and demonstrates rejection of stale integration inputs.
The older branch and other versions remain unchanged. No repository, tree, binary,
producer identity or human decision is verified or created by this scenario.

### Retained offline curated CPE sources

DTVP can explicitly preview and replace a bounded **curated** dictionary (up to 2,000 records /2MiB decoded input), or retain the standalone `cpeservice` eight-column `cpe-mapping.csv` as attributed historical claims. This is not full national-dictionary ingestion, upstream refresh or standalone-service parity. No network access, automatic rule publication, native approval, component identity change or vulnerability applicability inference occurs. CSV entries without explicit valid PURL/CPE identities remain unresolved; names are not used to guess identity. Imported status/author/source labels remain unverified. A CSV is a point-in-time capture, not reconstructed Git history.

Managers use `POST /api/v1/projects/{project}/cpe/sources/preview` and `/apply` with JSON `request_id`, `expected` CPE policy SHA or explicit null, `kind` (`dictionary` or `mapping_history`), `source`, declared `revision`, timezone-aware `occurred_at`, meaningful `reason`, exact `artifact_sha256` and `content_base64`. The complete JSON body is capped at3MiB before decoding. Apply adds the exact `preview_digest`. Preview writes nothing. Expected-head CAS controls replacement; declared source revisions/times do not prove freshness or enforce upstream chronology. Empty dictionaries explicitly remove the current curated set while historical captures remain readable. Exact retries use the same captured body and UUID; current management authorization is required before parsing or replay. Uncertain responses retain the captured request.

Dictionary input is an explicit JSON array of the existing supplied-ranking `DictionaryRecord` shape, or a bounded NVD-shaped `products[].cpe` extract. The latter projects supported fields for ranking and reports extra fields; exact original bytes are retained. This does not download NVD or claim completeness. Mapping CSV requires exactly `name,cpe,status,options,package_type,group,author,purl`; bounded fields and unique names are validated. No CSV rule is adopted automatically.

Exact source bytes and declared provenance are retained in immutable CPE policy states. Replacing one source preserves the other, catalog/rules and prior history. Ordinary catalog/rule edits preserve retained source metadata and artifact pins. Project readers use `GET .../cpe/sources/{policy}/{kind}` with offset/limit to inspect exact retained claims, and `/artifact` to download exact source bytes; every read rechecks current project scope and membership in retained CPE policy history. Ranking against retained inputs is explicit: `POST .../states/{inventory}/cpe/rank-retained` with `component_ref`, exact `policy`, and optional offset/limit. Inventory and policy pins remain separate. Generic native CLI JSON requests use the same backend workflow.

The existing CPE policy panel contains a collapsed Offline curated sources section: file/source/revision capture, normalization preview, explicit confirmation, exact failed/uncertain retries, retained-policy browsing and source downloads. UI draft locks protect context switches; committed-but-pending projection responses remain clearly committed and can refresh the identical receipt.

### Bounded workload measurements

```bash
uv run python scripts/knowledge_workload_probe.py --persona administrator \
  --project SYNTHETIC_PROJECT_ID --version 7.1.1 --requests 40 --concurrency 4
```

Against an isolated file-loaded playground, this measures read-only workspace latency,
status counts and consistent responses under a pinned version head. Limits: 200
requests, ten concurrent readers, ten-second per-request timeout and a 120-second
probe deadline. Publications during the probe yield explicit conflicts; the probe
never repins silently. JSON reports p50/p95/maximum including client/network time.
Use a scoped read token instead of `--persona` for an explicitly selected deployment.
Non-successful or inconsistent responses produce a nonzero exit. Measurements do
not establish import/job/mixed-write capacity or production acceptance; select
hardware, representative data and latency budgets for that deployment separately.

### Explicit cross-part occurrence relationships

Assembly selection optionally accepts `cross_part_relationships` (maximum 2,000):
`{relationship_id, kind, from:{part_id,state,ref}, to:{part_id,state,ref}, rationale}`.
Use exact original component/root references and the exact selected immutable part
revision for both endpoints. `DEPENDS_ON` creates an explicit dependency path;
`CONTAINS` remains typed containment and does not create dependency/ownership paths.
The assembler never matches names/PURLs or merges occurrences. Source roots,
imported edges and raw part provenance remain retained. Unselected/missing refs,
mismatched revisions, duplicate IDs/edges and same-part declarations fail closed.

Target inspection returns existing mappings for explicit preservation. Changing or
removing an existing declaration requires `relationship_change_reason`; older forms
cannot silently discard it. Existing requests without extension fields retain their
fingerprint and output shape. Structural previews report cross-part counts, changed
IDs and preserved source-root counts; these are operator declarations, not verified
runtime relationships, discovery completeness or approvals. Normal branch/policy/
evidence CAS and receipt-first replay continue to apply.

The existing assembly editor keeps these declarations in a closed advanced
section with an explicit JSON editor and endpoint example. Existing mappings are
loaded from the selected target; changing part pins never silently rewrites
relationship pins. Preview captures the complete declaration body and request ID
for unchanged retries. Syntax failures release the workspace lock for correction;
actor/project teardown invalidates late preview/publication completions.

### External v1 project archive dry run

Managers can inspect an exported `dtvp.project-archive/v1` ZIP without restoring it:

```bash
curl --fail-with-body --header "Authorization: Bearer $DTVP_TOKEN" \
  --header 'Content-Type: application/zip' --data-binary @project.dtvp-project-archive.zip \
  "$DTVP_URL/api/v1/projects/$PROJECT_ID/migration/v1-archive/preview"
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

`POST /api/v1/projects/{project}/versions/{version}/migration/v1-archive/{preview,apply}` accepts a raw `application/zip` body (maximum min(configured upload bound,64MiB)) and ASCII JSON `X-DTVP-Migration` metadata (maximum8192bytes; escape Unicode with JSON `ensure_ascii=True`). Required metadata: `request_id`, `archive_sha256`, `source_entry_id`, `expected:null`, `expected_policy`, `expected_evidence`, `source`, `build_number`, `occurred_at`, `reason`, `acknowledge_sanitized_export:true`, `acknowledge_operator_review:true`, `acknowledge_project_reader_disclosure:true`. Apply additionally requires the captured `preview_digest`. Full multiline operator reasons remain in retained declarations; revision labels use a fixed publication description. Authentication is checked before consuming uploads and refreshed afterward. Preview writes nothing; fresh apply requires the branch still absent and both pins unchanged. Exact receipt replay precedes archive parsing/head revalidation after current authorization and raw-byte hash validation. Changed input under one request ID conflicts; uncertain publication retries require the same bytes, metadata, UUID, endpoint and preview digest.

Within **Import composition**, the collapsed **Reviewed v1 archive** flow inspects
an operator-sanitized ZIP, selects its single exported version, and captures a new
native target/source plus current ownership/evidence pins. Source counts, mapping
coverage, known losses and retained-reader audience remain visible before explicit
publication. Three mandatory acknowledgments cover sanitization, operator review
and disclosure of the entire submitted ZIP to current and future project readers.
A server preview precedes publication; exact ZIP bytes, ASCII metadata, pins,
preview digest and request ID remain fixed through retries. Discarding a capture
does not reverse a potentially committed request. Legacy identities, labels and
scores remain historical source evidence; no native assessments or approvals are
adopted. Archive and regular composition intake mutually lock while captured.

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

`POST /api/v1/projects/{target}/versions/{version}/migration/v2/preview`
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
Operational SQL data still requires its own backup; see [recovery](deployment.md#native-journal-recovery).
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

`GET /api/v1/projects/{id}/maintenance/retention-preview` requires project management.
It inspects exact targets across all current branches and tag-protected revisions,
including review-pinned older revisions. Shared assessments remain active while
any covered target is present. Unknown scope never becomes a candidate. Revision
age is explicit and does not establish disappearance date or obsolescence. Full
counts accompany bounded revision/logical-assessment pages; `expected=PLAN_HASH`
rejects changed references during pagination. The HTTP CLI can use `knowledge
request GET /api/v1/projects/ID/maintenance/retention-preview`. This dry run writes
nothing and makes no physical storage estimate. Explicit logical archival uses
the separate complete-history plan described below. Stopped-writer orphan cleanup
now ships; committed history compaction remains unsupported.

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

The native workspace's collapsed **More filters** section includes independent
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

The native workspace's **Component inventory** browses all imported source-local
component occurrences, including those without vulnerability observations. Search
identity/PURL/reference, filter pinned ownership/team evidence, page backend totals,
and choose each distinct consuming context. Component names/PURLs never merge
occurrences; unknown ownership and delegated contexts remain explicit.

`GET /api/v1/projects/{id}/states/{sha}/components` and its `/contexts?component_ref=...`
read committed product states only, under current project-read authorization.
Current and historical states are exact pins; paste a historical SHA from version
history to inspect it. The existing component annotation editor is available to
managers at the current head, with the same expected state/revision and frozen
retry identity. Historical annotations remain read only. Direct imported dependency
neighbors and raw source facts use the existing context disclosure; this is not
an editable dependency graph, runtime topology, complete discovery or clearance.
No-finding components do not receive implicit security/license approval.

### Explicit logical assessment archival

Project managers can inspect `POST /api/v1/projects/{id}/maintenance/assessment-archive/preview`
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
adapter `GET /api/v1/projects/{id}/states/{state}/component-context` binds the exact
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

`GET /api/v1/projects/{id}/states/{sha}/component-neighbors` requires current
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


`PUT /api/v1/projects/{id}/versions/{version}/metadata` explicitly replaces
annotations for one exact component occurrence. It requires project management,
`request_id`, expected branch head, expected metadata revision (null initially),
`component_ref`, typed `annotations`, `provenance` and `rationale`. Cybersecurity
criticality/exposure/mitigations/testing, deployment/usage and supplier/support
information remain separate from imported facts. No approval or license clearance
is implied. `GET .../states/{state}/metadata` lists current, stale, absent and
out-of-scope records; `component_ref` selects one. The native detail displays
these annotations and their attribution.

Annotations survive baseline replacement and retain immutable revisions. Identity
changes mark them stale; removed components retain absent records. Inherited
annotations from another product version require explicit adoption. Current
annotations and provenance throughout the consuming tree bind assessment/score
fingerprints: changes require revalidation. Editing only the recording rationale
without changing annotations/provenance does not invalidate coverage. Baseline
updates retain artifact pins for authored revisions and external reports; retention
and garbage collection use explicit operator maintenance.

### Pinned composition and selected advisory comparison

`POST /api/v1/projects/{id}/compare/intelligence?offset=0&limit=50` takes
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

`GET /api/v1/projects/{id}/states/{sha}/evidence-summary` returns
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

`GET /api/v1/projects/{id}/states/{state}/license-worklist` returns pinned,
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

The native workspace has a collapsed **License evidence and review** panel,
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
/api/v1/projects/{id}/states/{state}/cpe/rank`. Project readers submit an exact
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

`POST /api/v1/projects/{id}/reconciliation/preview` accepts exact `source`, `target`
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

`GET /api/v1/projects/{id}/refs` lists product branches and immutable tags.
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
`--offset` and `--limit`. Native Review offers the same comparison within the
selected product, with compact before/after details.

### Assessment synchronization preview

`POST /api/v1/projects/{id}/synchronization/preview` takes pinned `source`, `target`,
optional common knowledge `basis` and explicit `context_mapping`. It returns a
bounded preview with full counts and a stable digest. No basis is invented;
without one, comparison is explicitly two-state. A supplied basis must be a
committed ancestor of both states. Categories distinguish reusable content,
already-covered targets, required review, conflicting edits, absent applicability
and unresolved scope. Exact source-local references/material evidence govern
matching; explicit maps cannot collapse different contexts or establish equivalence.
Target inventory, reviews and published scores remain unchanged. Knowledge ancestry
never proves a software merge. Explicit integration events retain software/artifact
pins and optionally verify supplied Git parent paths; this establishes object
consistency, not repository/build authenticity. Configured relationships now
automatically schedule proposals; draft adoption and target reviews stay explicit.
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
`PUT /api/v1/projects/{id}/cpe`; the read-only editor adapter is
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
pinned component ranking endpoint. Scoped official refresh and optional complete
catalog capture are described below. Full standalone-service migration and
deployment qualification remain separate acceptance work.


CPE discovery now has an internal offline module. `GET/PUT
/api/v1/projects/{id}/cpe` reads or explicitly replaces versioned catalog/rule
inputs; writes require project-management permission and an expected policy head.
`GET .../states/{state}/cpe?component_ref=REF&policy=POLICY_SHA` returns pinned,
attributed candidates. Omitting `policy` selects current configuration. Reviewed
aliases and explicit CPE/PURL mappings are supported; package versions,
qualifiers and subpaths are retained. Candidates do not establish vulnerability
applicability or change component identity. Optional scoped official refresh and
local full-catalog search extend this offline foundation; complete standalone
service/deployment parity is not established.
The native detail offers an on-demand specialist panel: attributed CPE
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
explicit durable jobs. Native OSV package/version matching is available separately
with explicit query selection and unknown-coverage diagnostics. EUVD and JVN
known-ID adapters are described below; they do not provide general package matching.

`GET /api/v1/projects/{id}/advisory-refresh` returns a bounded searchable list of
known source CVE IDs (baseline or active exact package matches), enabled providers,
next producer ordinals and complete
pinned version/evidence selections. The collapsed native refresh panel selects
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
`DTVP_PROVIDERS_ENABLED` on API and worker. Without an explicit request or opted-in advisory schedule, no provider requests occur.

`GET .../evidence/artifacts/{sha}?expected_evidence=SHA` retrieves a raw response or
capture pinned in the selected committed evidence ancestry. This keeps untouched
catalog evidence available after partial refresh and in new product branches.
Project authorization applies; the response identifies the actual retaining state.
Mirrors retain upstream publisher attribution and do not establish independent
corroboration. Provider rate-limit errors fail collection without partial publication. Optional
known-ID scheduling and durable shared provider pacing are described below.

Within **Advisory intelligence refresh**, the collapsed **External OSV package
matching** flow lists a bounded, pinned catalog of eligible package versions.
Users explicitly select at most 20 PURLs; selection persists across catalog pages,
whose selection digest must remain unchanged. Provider configuration and server
capabilities control available operations. Unsupported and unselected coordinates
retain unknown coverage; no-match responses never establish absence or remediation.

Enqueue captures exact PURLs, product heads, evidence selection, source revision
and request ID. Network failures and head conflicts retain that request unchanged;
workspace advances preserve the captured scope and block first enqueue of stale
drafts until an explicit plan refresh. Current server authorization governs every
retry/cancel; durable job lists and manual status refresh expose progress and raw
capture downloads without automatic polling. Actor/project teardown invalidates
late responses. OSV results remain provider claims requiring contextual human
analysis, never automatic assessments, approvals or scores.

Busy operations, unconfirmed enqueue receipts and uncertain job actions lock normal
product/version and global-page navigation until recording is confirmed or the
capture is explicitly discarded. The advisory parent combines its own request
state with the OSV child lock without disabling the child's retry/discard controls.
Changing persona remains possible and invalidates the old actor's responses.
Status/action responses must match the requested job ID, kind and immutable scope
before replacing displayed job data.

### Issued consumer exports

`POST /api/v1/projects/{id}/states/{state}/exports/bundle` explicitly archives exact
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

Frozen consumer compatibility fixtures now exercise current readers against actual
older code: `b5ff695687f2ff7a0e1fe90a3d2ff4afa6dbc1fc` (before the annotation
register) and `3480f645439010bc197ad87dfe43c7c28dd930fe` (register `/2` transition).
Each synthetic journal retains issued knowledge-bundle, VScorer and Agentyzer files,
source inputs and authored support annotations; it contains no human approvals or
credentials. Per-member/file SHA-256 and source-code provenance accompany the ZIPs.
The manual producer imports only an exact archived source tree and fixes journal,
issuance and annotation clocks; it never patches serializers. These are reconstructed
fixtures in the current Python environment, not historical production captures or
full old-runtime acceptance. Tests do not regenerate them or require Git/network.

Current reader, cached preparation and current-auth HTTP downloads preserve every
issued byte while today's serializers, derivation and annotation builders are
unavailable. `/1` output is not enriched with `/2` metadata; corrupt/missing captures
fail closed. This qualifies known issued formats, not arbitrary future formats or
older unissued receipts. Controlled consumer/document acceptance remains separate.
Fixture producer: `tests/fixtures/issued-serializer-compat/generate.py`, with
`--source-root` pointing at `git archive` output of the recorded commit and fresh
`--work`/`--output` paths. The checked-in ZIP/provenance/expected triplets are the
regression inputs; manual regeneration requires reviewing all changed hashes.

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
`POST /api/v1/projects/{id}/versions/{version}/documents/draft` or `/submit`.
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
[consumer delivery evidence](consumers.md).

### Native analysis jobs

`PUT /api/v1/projects/{id}/connectors/agentyzer` binds an administrator-approved
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
`POST /api/v1/projects/{id}/states/{state}/agentyzer-input` takes `context_id` and
`vulnerability_id` under snapshot permission. It derives a native request plus
`dtvp.agentyzer-source/1` receipt pinning consuming context, focal package/version,
source SBOM, constituent selection, declared subject digest and material fingerprint.
Missing, inconsistent or unavailable source information returns explicit not-ready
coverage. The endpoint contacts no service and creates no job or human approval.
An external orchestrator still authorizes the repository; a source commit does not
verify a built binary/container.

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

Native workspaces, bundles and CLI retain previous DTVP-tagged DT team
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

`POST /api/v1/projects/{id}/evidence/files/preview` accepts the same raw multipart
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

`GET /api/v1/projects/{id}/evidence` returns bounded document summaries, current
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

Authorized consumers can read `GET /api/v1/projects/{id}/states/{state}/bundle`,
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

`GET /api/v1/projects/{id}/ownership` returns the current policy and exact active
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
unique strong lineage matches support guarded same-version reference continuity. Exact contextual assessment coverage
is available through the native workspace, HTTP API and CLI. Run the isolated scenario:

```bash
uv run python scripts/ownership_demo.py
```

It uses a dedicated project, two versions, shared dependencies, bypass delegation
and a team reassignment; it leaves other project policies untouched.

Read paginated inventory at `GET .../versions/{version}/inventory`; pass its
`state` as `expected` on later pages to detect changes. Create protected tags
with `POST .../tags` and compare pinned revisions with
`GET .../compare?before=SHA&after=SHA`. Authentication and current project permissions apply to every read and write.
Imported claims are separate from future human decisions.

The journal lives in `DTVP_ARTIFACT_DIR/knowledge` on a local filesystem supporting
`flock`, hard links, atomic rename and directory fsync (including WSL's Linux
filesystem). Back up the complete artifact volume. One filesystem lock serializes
publication and projection, including across API processes. Immutable objects
are stored first; a single durable HEAD replacement publishes all references.
API responses distinguish committed/current (201), committed/projection pending
(202), and uncertain publication (503). Retry the same request ID and input.
Startup catches up committed publications; missing/corrupt committed data fails
closed. No background garbage collection is enabled in this slice.

Rebuild only native projections, preserving historical SQL, identity and job data:

```bash
uv run dtvp rebuild-knowledge
uv run pytest tests/test_knowledge_journal.py tests/test_knowledge_api.py
```

Migration `0005` runs implicitly. New `knowledge_*` tables hold active records,
reference heads and an applied-publication checkpoint; tags store only references.
They are an initial general projection, not the final indexed finding/context
schema. The basic comparison reports changed record keys; historical semantic
comparison adds bounded classified details and a process-local cache. Explicit
occurrence correspondence, stable lineage matching and proven same-version
reference continuity are available. Ambiguous identity or new-context approval
reuse is never inferred. Normal application commands must use the API; local reconstruction
is an administrative operation.

### Versioned pipeline metadata

`GET`/`PUT /api/v1/projects/{id}/pipeline-config` reads and explicitly publishes
bounded user/CI declarations. The PUT captures `expected_policy` and all
`expected_versions` (returned by GET); atomic CAS includes newly added branches.
Only the `pipeline` policy ref changes. Existing product inventories, assessments
and approvals never change implicitly. Requests are actor-scoped/idempotent, and
current manager authority is required on every replay.

Each delivery part (including `part_id: null` for a single root baseline) names
one exact `authority_source` and explicit `observation_sources`. These are source
IDs, independent of provider products. Models pin `model_id`, `revision`,
`digest_sha256` and an explicit entity catalog (`entity_id`, `name`, `external`).
Mappings use existing namespace/case-sensitive/PURL selector grammar separately
for components and optional consuming-root contexts; many-to-many entity links
are allowed. Legacy Generator names remain explicit strings, never inferred GUIDs.

`GET /api/v1/projects/{id}/states/{state}/pipeline-context?configuration=SHA`
resolves a retained configuration against committed product history without
changing either. Up to 200 rows/page share one report digest. Missing mappings are
visible as unmapped contexts/unused rules, not an intake-wide failure. Declared
models and entity mappings remain user/CI assertions, not verified model content
or evidence of vulnerability applicability. Configurations are bounded to 2 MiB;
resolution to 2 million selector evaluations and 32 MiB, failing without truncation.

Pinned product states with `inventory.pipeline_configuration.state` now expose a
`pipeline_context` register in native bundles and VScorer worklists. It resolves
only the retained configuration named by that product state; later configuration
edits do not change historical inputs. Legacy states without a pointer retain
existing emitted bytes. Generator receives this register through its issued
native bundle; its separate adapter must explicitly consume the added contract.

Focused VScorer derivations additionally emit `pipeline_context`, limited to the
selected context and its explicitly referenced model catalogs, plus a separately
issued `pipeline-context.json` whose SHA-256 is bound in the source receipt.
Missing mappings remain explicit diagnostics and do not silently create model
placements. Legacy names and entity IDs remain distinct; no implicit SBOM-property
rewriting, GUID conversion or model-content verification occurs. The separate
VScorer adapter must explicitly consume the new file for placement decisions.

Issuance validates this file against the pinned bundle and captures exact bytes;
subsequent retrieval never reruns serializers. New metadata-bearing captures use
serializer `/3`; existing `/1` and `/2` selectors/receipts remain authoritative.

Authoritative imports and assembly publication validate configured source roles and
pin the exact configuration in their immutable inventory. Optional
`expected_configuration` rejects stale CI declarations. Assembly previews include
the configuration pin; apply rejects changes even between preview verification
and publication. A configuration edit alone changes no existing product state.

### Overlapping observations

`POST .../versions/{version}/observation-files` accepts original SBOM bytes plus
JSON metadata; `/observation-imports` accepts JSON documents. Intake publishes
only an attributed source layer. It pins the current product/configuration and
checks the configured source role, delivery part, collection boundary and either
shared artifact digest or exact-file-bound `SubjectDeclaration`. Producer-declared
same-build relationships remain distinct from digest-bound subjects. Original
bytes and full reconciliation reports remain authorized historical artifacts.

`GET .../observation-sources` provides bounded source pages; `/observation-selection`
reads the current selection. POST `/observation-selection/preview` computes a
read-only reconciliation; POST `/observation-selection` requires its exact digest.
Publication rebuilds from the authoritative baseline plus the selected layers,
retaining current assessments/reviews/history. Omitted sources and removed adopted
components/relationships require an explicit reason. Retained historical layers
never accumulate into the latest inventory automatically.

Unique strong identities within the same delivery part/role/installation map to
existing occurrences. Supplementary component facts remain attributed assertions;
authoritative fields are never overwritten. New components and topology require
explicit adoption. Independently adopted equivalent observations can share one
node with both origins; conflicting identity/placement or ambiguous occurrences
remain separate. Metadata conflicts remain visible. Typed containment remains
separate from dependency topology and consuming contexts are not collapsed.

Workspace findings and component inventory expose supplemental component evidence;
assessment fingerprints include its effective facts within the consuming tree.
Capture-state/local-reference changes alone are immaterial; changed security facts
require renewed review. Full original files remain retrievable. Preview samples
are limited to 20 entries/list; full reports remain retained artifacts. Selection
is bounded to 200 sources, 2,000 adoptions/source, 100,000 candidate records and
64 MiB normalized candidate/report limits, failing without partial publication.

### Automatic synchronization proposal scheduling

Managers configure explicit source→target version relationships through
`GET/PUT /api/v1/projects/{id}/synchronization-policy`. Configuration is a
journal-backed CAS policy with ≤20 relationships, optional explicit common basis
and ≤1,000 one-to-one context mappings per relationship. Empty relationships
stop future scheduling; already captured jobs remain inspectable. Relationships
can reference not-yet-created versions and wait until both branch heads exist.

The existing SQL worker rescans committed policy/branch references every five
seconds, rotating across at most 100 configured products per pass. Deterministic
job IDs deduplicate exact policy/source/target pins. This repairs journal/SQL
enqueue gaps after process failure without blocking knowledge publication.
Imports, assessment/review/evidence changes and recorded integration events change
the relevant branch pins and therefore trigger fresh proposals. After downtime,
intermediate heads are coalesced into the latest observed state; this is not a
promise to produce an individual proposal for every historical publication.
Cyclic relationships cannot trigger feedback because proposals never mutate
knowledge, target inventory, assessments, approvals or scores.

`GET /projects/{id}/synchronization-jobs` lists durable jobs; detail and paginated
`/{job}/proposal` return exact frozen inputs, preview digest, retained artifact
hash and current stale classification. Computation reuses pinned synchronization
previews and is bounded to 2,000 rows/16 MiB with leased execution. Historical
proposals remain readable under current project authorization after heads/policy
change. Existing explicit draft adoption/review remains the only application path.

Execution rechecks the policy author's current credential and project manage
permission. Use a suitably scoped machine credential for unattended operation;
a revoked/expired credential fails closed. Reauthorize the policy explicitly or
retry a failed job as its original author with a current authorized credential.
`POST /synchronization-jobs/{job}/retry` preserves all knowledge pins; `/cancel`
stops queued/running collection. Failed/cancelled jobs never implicitly restart.
SQL jobs and proposal artifacts remain operational backup/retention roots; the
journal alone does not reconstruct operational job state.

Knowledge exposes lazy advanced **Pipeline source roles and threat-model mappings**
and **Automatic synchronization relationships** editors. Current server capabilities
govern editing; explicit review captures a complete JSON replacement and exact policy/
version pins. Uncertain PUT requests and job actions retain their original request
until resolved/discarded; actor changes invalidate prior responses. Proposal browsing
is read-only and paginated, with frozen source/target/digest and visible stale status.

The HTTP-only CLI offers:

```bash
uv run dtvp knowledge pipeline-config --project PROJECT
uv run dtvp knowledge pipeline-config --project PROJECT --input exact-request.json
uv run dtvp knowledge pipeline-context --project PROJECT --state STATE --configuration POLICY
uv run dtvp knowledge synchronization-policy --project PROJECT --input exact-policy-request.json
uv run dtvp knowledge synchronization-jobs --project PROJECT
uv run dtvp knowledge synchronization-jobs --project PROJECT --job JOB --action proposal
uv run dtvp knowledge synchronization-jobs --project PROJECT --job JOB --action retry
uv run dtvp knowledge observation-import --project PROJECT --version VERSION --input metadata.json --file original.cdx.json
uv run dtvp knowledge observation-sources --project PROJECT --version VERSION
uv run dtvp knowledge observation-selection --project PROJECT --version VERSION --input selection.json
uv run dtvp knowledge observation-selection --project PROJECT --version VERSION --input selection.json --apply
```

Configuration commands GET by default and PUT only with `--input`; observation
selection previews by default and publishes only with `--apply`. Files retain exact
SBOM bytes (CLI transport bound 32 MiB); all matching, validation, policy and workflow
decisions remain server-side. Commands print JSON; no local domain calculations.

An authority source can be replaced explicitly after a manager publishes its new
role in pipeline configuration. The import must supply that exact
`expected_configuration` and a nonblank `authority_change_reason`; the baseline
retains previous source, policy and reason. The new source starts its own build
counter. Existing history/assessments remain retained, and source-bound identities
are revalidated. An ordinary import cannot silently change inventory authority.

The advanced observations panel imports original SBOM files with user/CI metadata,
browses digest-consistent provenance pages, previews server-side conflicts/proposals
and explicitly publishes selected/adopted inventory. Captured uploads/apply requests
retain exact pins and preview through uncertain outcomes or projection lag. Actor
changes invalidate late responses; intake and selection drafts cannot replace one
another silently. Ordinary assessment screens remain focused on the selected team
and finding; supplemental component evidence expands on demand.

The API-only pipeline rehearsal now declares two delivery-part authorities and a
same-part binary-scanner observer in a pinned user/CI pipeline configuration before
imports. It includes a synthetic revision/digest-bound threat-model entity mapping.
Two original scanner SBOM revisions carry exact-file-bound producer declarations;
preview/publication demonstrate graph deduplication, attributed supplemental evidence
and a scanner-only component left as an explicit inventory proposal. Replacement and
explicit withdrawal preserve historical summaries and byte-exact source downloads.
Native issued bundles and VScorer input files are checked for pinned model metadata.
This remains synthetic contract validation, with no claim of real model authenticity,
producer completeness, license clearance or document acceptance.

Observation publication preserves the target revision as its first parent and
validates the complete live/retired identity ledger before accepting more nodes.
Adopted observation roots become ordinary live occurrences while retaining their
original source role; assembled provenance includes original artifact identity.
Pre-ledger inputs bootstrap complete lineage metadata. Withdrawn inventories
cannot receive observations, and even an empty observation selection must satisfy
the configured authority for every available delivery part.

Latest consumer integration batches are committed in their existing isolated
worktrees: Generator `feat/dtvp-snapshot-integrity` (`da3cba0`) and VScorer
`feat/dtvp-context-binding` (`9fd670b`). Both consume actual DTVP-issued metadata;
Generator emits contextual mapping supplements, while VScorer validates and
retains declarations without installing mappings or changing scores. They are
normal branches of the sibling repositories; default checkouts remain untouched.
See [consumer contracts](consumers.md#current-dtvp-contract) for validation
and remaining customer/document/deployment acceptance limits.

Pipeline and synchronization tools follow the existing compact closed-card and
full-width expanded layout, including narrow screens. Unfinished observation
intake/reconciliation blocks competing baseline imports and assembly edits.

VScorer preparation also exposes the exact optional `pipeline-context.json` file
in the UI. Both its receipt pin and exact byte hash must match before any native
input downloads become available; missing, changed or unpinned metadata fails
closed. Legacy three-file derivations retain their existing behavior.

### Explicit scoped official CPE refresh

Managers can capture current candidates from the [official NVD CPE 2.0 API](https://nvd.nist.gov/developers/products)
using `POST /api/v1/projects/{project}/cpe/sources/refresh` with `request_id`, exact
`expected` CPE policy SHA (or null), `keyword` (3–200 characters) and a meaningful
`reason`. Network access is disabled unless `nvd` appears in `DTVP_PROVIDERS_ENABLED`.
One fixed HTTPS GET requests the complete returned keyword subset. Redirects and
automatic retries are disabled; responses above 2 MiB, inconsistent pagination,
or more than 2,000 results fail rather than publishing a truncated dictionary.
Narrow broad queries explicitly. Upstream throttling/errors leave policy unchanged.
This scoped refresh is not a full national dictionary mirror or scheduled crawler.

Capture writes no journal state. It returns `source_input` and its exact `preview`;
explicit existing `/cpe/sources/apply` with that captured input plus
`preview.preview_digest` publishes the curated dictionary replacement. It retains
exact original NVD response bytes and typed query/endpoint/capture-time/hash
provenance, while preserving mapping rules, manually reviewed identities, other
retained sources, historical captures and approvals. Query matches are discovery
candidates, not vulnerability applicability. Capture provenance remains attributed
and replayable, not signed publisher authentication or a completeness guarantee
beyond the returned query subset. Current management authorization is rechecked
after network work; concurrent policy changes require a fresh explicit preview.
Once publication is attempted, retry the identical captured body, not a new fetch.

The existing advanced **Offline curated sources** panel offers a **Scoped official
NVD query** capture method alongside local files. It checks returned scope/policy
and exact byte digest, then requires independent replacement confirmation. Failed
capture retains the original query and pin; discard explicitly releases that draft.
Publication retries preserve exact captured bytes and request identity. Generic
`knowledge request POST` CLI calls use the same endpoints and JSON contracts.

Verification: 71 core CPE/source/ranking checks, 13 source/refresh HTTP checks,
seven CPE browser checks, frontend typecheck/build and Ruff passed. These mocked
provider fixtures qualify acquisition controls; no live NVD availability, customer
mapping correctness or full standalone-service parity is claimed.

Native Review offers a collapsed **Add product** form for users with a writable team.
Creation uses the shared authenticated project API and selects the new product,
so its first SBOM can be imported directly. Eligible teams come from current server capabilities; server
permissions remain authoritative. Drafts lock navigation and competing composition
changes. Actor changes invalidate late responses.

Project creation has no idempotent request contract. An unconfirmed response is
therefore never retried automatically: the captured name/team remain visible,
with read-only, scoped and paginated catalog inspection to open an existing
result. A user can explicitly discard the attempt, but catalog absence does not
prove a delayed request failed. Duplicate names remain constrained per owning
team by the database. Five focused browser checks and frontend typecheck/build
verify native creation, uncertain-result recovery, draft/mobile behavior,
read-only access and actor roundtrips.

### Optional official VDR/VEX JSON Schema checks

`POST /api/v1/projects/{id}/evidence/schema-validation` accepts a JSON object
with `document` and `validation_profile`. It requires project evidence permission
and returns a read-only `dtvp.official-schema-validation/1` report. Profiles:

- `cyclonedx-1.5-json-schema/1`
- `cyclonedx-1.6-json-schema/1`
- `openvex-0.2.0-json-schema/1`
- `csaf-2.0-json-schema/1`

This opt-in check validates the whole document against the selected official
JSON Schema, including locally resolved references and enabled format checks.
The existing `dtvp-*-exact/1` consumed-field profiles and import/application
semantics remain unchanged. A schema-valid document can still contain unsupported
ranges, relationships or statement semantics; schema validity never expands
product/context scope or creates an approval. CSAF's additional normative semantic
tests and VEX-profile rules are separate from its JSON Schema and are not claimed
by this report. Cryptographic signature verification is always `not_performed`,
even when a signature's JSON structure passes.

The exact vendored [OASIS CSAF 2.0 schema](https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json),
its three [FIRST CVSS schema dependencies](https://www.first.org/cvss/), and the
[official OpenVEX 0.2.0 schema at a pinned commit](https://github.com/openvex/spec/blob/61b5f885d0f481f48683c93345e49ef1a6e9fdff/openvex_json_schema.json)
ship under `dtvp/knowledge/schema_resources`, with exact source hashes and retained
license/notices. OpenVEX's `v0.2.0` release tag contains no JSON Schema; the bundle
explicitly identifies the maintained official 0.2.0 schema revision instead.
CycloneDX uses the versioned local schema snapshots in the locked official Python
library. Reports identify every resource, its exact SHA-256, library version and
the complete local resource-set digest. Runtime resolution is closed: no schema,
document URL, JSON-LD context or external reference is fetched.

Reports contain canonical document and report digests, schema dialect/ID, bounded
JSON-pointer diagnostics, explicit truncation and trust/semantic limitations.
Source values and raw error messages are not copied into diagnostics. Limits are
32 MiB canonical JSON, 100,000 tree nodes, depth 64, 64 KiB per text/key value and
64 displayed diagnostics. Exceeding input/evaluation bounds fails explicitly;
more errors retain `valid: false` with `diagnostics_truncated: true`. Validation
does not publish or retain an import, so source-byte intake and producer ordering
still use the normal evidence workflow.

OIDC login/callback use Authlib's authorization-code flow with S256 PKCE and
session-bound state. Authlib verifies signed ID tokens through discovered JWKS;
DTVP explicitly pins issuer, audience and the original nonce as required claims.
A provider's `nonce_supported=false` cannot disable DTVP's nonce requirement, and
an `azp` claim cannot compensate for a token missing DTVP from its audience.
Authlib's token-time validation retains its default 120-second clock leeway.
Only validated issuer/subject identify a local user; subject/name types, control
characters and persistence lengths are checked before database access. OIDC
profile/group/role/admin claims never grant memberships or administrator access.
New identities receive a local session with no team memberships; administrators
assign local permissions explicitly. Existing local authorization remains intact.
There is currently no separate user-disabled flag; credentials can be revoked.

Expected OAuth/JWT/HTTP/JSON failures return generic sign-in messages and clear
pending authorization state. Provider descriptions, tokens and client secrets
are not reflected in these responses. Successful callbacks clear temporary
state and issue Secure, SameSite=Strict cookies on HTTPS deployments; the session
cookie is HttpOnly, with the existing separate CSRF token retained. Deployment
issuer/client registration, proxy/public URL and actual IdP behavior still need
operator acceptance; offline tests cannot establish production federation.

The offline OIDC suite exercises real Authlib exchanges and generated RSA-signed
JWTs against mocked discovery/token/JWKS endpoints. It verifies PKCE linkage,
state/cookie tampering, callback replay, nonce/issuer/audience/expiry/signature,
malformed identities, sanitized provider/transport errors, unprivileged initial
provisioning and revoked-session denial. It does not bypass token verification
or replace Authlib with a fake authentication implementation.

Thin Authlib client extensions validate discovery, token-response and JWKS envelope
shapes before library parsing, including required endpoints and the configured
issuer. Malformed provider JSON/key metadata produces the same generic failures;
key decoding and cryptographic verification remain Authlib/joserfc operations.
Discovery endpoints must be HTTP(S) URLs without embedded credentials or fragments;
`none` is rejected as an ID-token signing algorithm. HTTPS termination and trusted
provider endpoint configuration remain deployment responsibilities.

### Exact-artifact signature verification

An optional read-only verifier supports standard compact [JWS](https://www.rfc-editor.org/rfc/rfc7515.html)
using [joserfc](https://jose.authlib.org/en/guide/jws/) and deployment-configured
public keys. `DTVP_EVIDENCE_JWS_TRUST` defaults to `[]`. Its JSON array entries
contain exactly `subject` (configured producer identity label), `project_ids`
(explicit permitted IDs), `algorithm` and `jwk` (public JWK with a unique `kid`).
Allowed algorithms are `ES256`/P-256, `ES384`/P-384, `RS256`, `PS256` and
fully specified `Ed25519`/Ed25519. Deprecated polymorphic `EdDSA` is excluded; see
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html). RSA keys must be 2048–8192
bits. Startup rejects private/symmetric keys, duplicate IDs, wildcard scopes,
remote/certificate/unknown key fields and conflicting algorithms, curves or usage.
At most 100 keys, 200 exact project scopes/key, 8 KiB/JWK and 1 MiB/policy are allowed.

`GET /api/v1/projects/{id}/evidence/signature-policy` returns the current complete
policy digest and only this project's permitted subjects, key IDs, algorithms and
RFC 7638 public-key thumbprints. `POST .../evidence/signature-verification`
accepts multipart uploads `file` (exact artifact bytes) and `signature` (ASCII
compact JWS file), plus `expected_artifact_sha256`, `trusted_subject` and optional
`expected_trust_policy_sha256`. Both routes require project evidence permission.
A stale policy pin returns 409; no trusted matching key, wrong bytes or an invalid
signature returns an explicit `verified: false` report. Request keys never become
trusted and no key/context/certificate URLs are fetched.

The signature must cover the complete raw artifact as its encoded payload. The
verifier compares its decoded payload byte-for-byte to the upload and checks the
caller's expected SHA-256; JSON whitespace changes therefore fail. Only a selected
key whose configured subject, exact project scope, protected `kid` and algorithm
all match can verify. Reports retain the policy hash, exact artifact/JWS hashes,
configured signer label, successful key thumbprint, algorithm, observation time
and report digest. The observation time is not an authenticated signing time.
Limits are 1 byte–8 MiB/artifact, 12 MiB/compact JWS and 8 KiB/protected header,
also respecting a smaller configured upload limit. Compact files must contain
only the serialization, without trailing whitespace; duplicate headers, padding,
unknown/critical headers, detached or unencoded payloads are rejected.

This establishes integrity under the configured key policy only. It does not
verify embedded JSF, DSSE, Sigstore, certificate chains, revocation or publisher
identity independently of configuration. It creates no import, retained trust
upgrade, human approval, product applicability or regulatory/legal conclusion.
The separate official-schema report continues to mark signature verification as
`not_performed`; callers must deliberately retain and assess the signature report
alongside their exact source bytes.

The evidence-source panel now provides a closed **Optional schema and signature
checks** tool for users with evidence-import permission. It reads local files and
calls only the read-only validation APIs. Official schema checks show a compact
result and bounded diagnostics; JWS checks load the project's deployment trust
policy and pin its hash, configured signer and both exact uploaded files.
No signer keys can be supplied through this UI.

Inputs freeze for repeatable checks until explicitly discarded. Cancel discards
late results and restores source controls; changing project/state or actor clears
captured validation and ignores prior responses. Concurrent evidence-source
mutations are disabled while validation runs. Schema reports distinguish the
server-canonical JSON digest from the displayed original local-file SHA-256.
Complete pins/reports remain collapsed; passing checks never import evidence,
change retained trust or grant an approval. The tool stays usable on narrow screens.

### Optional complete CPE catalog captures

Instance operators can retain an NVD-shaped complete CPE catalog outside product
journal states, under `ARTIFACT_DIR/cpe-catalog`. The [official NIST bulk-feed
contract](https://www.nist.gov/itl/nvd) uses a **tar.gz containing JSON 2.0 chunks**;
legacy XML dictionaries were retired in 2025. The current fixed acquisition URLs
are [META](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta) and
[tar.gz](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz).

```bash
uv run python scripts/cpe_catalog.py --root data/artifacts/cpe-catalog import --archive /path/nvdcpe-2.0.tar.gz --meta /path/nvdcpe-2.0.meta
uv run python scripts/cpe_catalog.py --root data/artifacts/cpe-catalog search 'openssl' --limit 25
uv run python scripts/cpe_catalog.py --root data/artifacts/cpe-catalog verify
uv run python scripts/cpe_catalog.py --root data/artifacts/cpe-catalog rebuild
uv run python scripts/cpe_catalog.py --root data/artifacts/cpe-catalog export 'openssl' --limit 25 --output /tmp/cpe-candidates.json
```

`mirror` explicitly checks official META before download, skips unchanged captures,
disables redirects and rechecks META afterward; failure or a changed active
selection prevents activation. It performs no startup/polling download. The
operator needs sufficient disk for raw chunks, staging and the disposable index.
Acquisition is bounded to 512 MiB compressed/8 GiB decoded, 1,000 regular JSON
members, 10 million CPEs, 512 MiB/member and 1 MiB/record. JSON duplicate keys,
nonfinite/malformed tokens, excessive depth/key memory and parser progress stalls
fail closed. Archive links, traversal, gaps/overlaps, duplicate identities,
incomplete counts and hidden trailing content fail before atomic activation.

Exact original compressed chunks and META bytes are immutable content-addressed
objects. Every decoded TAR byte, including padding, must match META size/SHA-256;
chunk pagination must cover the declared total using a consistent zero/one-based
index. Assurance is **META_consistent_complete_archive**, not independent publisher
authentication or completeness of NVD's knowledge. No catalog bytes are copied into
whole product state manifests; project policy, reviewed mappings and approvals are
unchanged. Existing generations remain inspectable with `--generation SHA`.

SQLite/FTS5 is a rebuildable local search projection, with no extra database service.
Its receipt pins the generation, index algorithm and exact SQLite byte SHA/size.
Queries hash the index once per filesystem identity and reject subsequent content/
metadata changes; matching row counts or SQLite structural integrity alone are
insufficient. The first query in a process can therefore incur a full index read.
`rebuild` reconstructs it exclusively from verified original chunks/META. Back up
`objects` and `CURRENT` along with the installation; indexes can be regenerated.
Catalog retention/cleanup is explicit operator work; no destructive catalog GC runs.

Project readers use `GET /api/v1/projects/{id}/cpe/catalog`, `/search?q=...` and
`/export?q=...` with optional pinned `generation`, bounded paging and explicit
`include_deprecated`. Search remains on the captured generation across pages.
The collapsed **Local catalog (optional)** panel exposes source/deprecation pins and
SHA-verified candidate downloads. Export contains only the requested page (maximum
200 records/2 MiB), plus source receipt and omitted-field disclosure. Uploading it
through existing curated source preview/publication is a separate explicit action;
search/export never adopts identities or changes mappings/approvals.

For an entirely offline interactive example, use a **new** catalog root:

```bash
uv run python scripts/cpe_catalog.py --root /tmp/dtvp-demo/artifacts/cpe-catalog demo
```

Use that installation's actual artifact directory to expose it in its UI. Demo
refuses an existing selected generation and retains synthetic markers in archive,
META, manifest, API/UI and exported candidate attribution. Its invented records
are never presented as official NVD provenance. Query `demo`; include deprecated
names to see all three synthetic versions.

Synthetic complete-archive tests cover capture, >2,000 records, integrity/semantic
index tampering, reconstruction, exact export, missing/unsafe inputs and fixed-origin
META races without live downloads. Official META and the first compressed TAR block
were inspected to verify the contract; a complete current national archive has not
been downloaded or qualified here. Production resource/latency qualification remains
an operator acceptance task.

### Optional unattended known-ID advisory refresh

`GET/PUT /api/v1/projects/{project}/advisory-schedule` configures a journal-backed,
CAS-pinned opt-in policy. PUT requires `request_id`, `expected_policy` and up to
four distinct `providers`: each has an enabled provider ID, 1–20 explicit version
labels, `interval_seconds` (3,600–2,592,000; default 86,400) and `batch_size` (1–20;
default 20). An empty list stops new scheduling. Generic authenticated
`knowledge request GET/PUT` CLI calls use the same contract.

The existing SQL worker rotates across at most 100 configured products per pass.
It selects only supported exact advisory IDs already reported in configured
versions; each native job pins the complete current product-head register and
product-wide evidence head. Each interval selects one bounded batch, rotating
known IDs across cycles. This is not a promise to refresh every ID per interval.
Selected logical input is bounded to 100,000 records / 64 MiB. Oversized or stale
policies do not block other configured products. Missing configured versions wait.
Provider disablement and the policy author's current credential, management and
evidence permissions are checked before enqueue; native collection rechecks its
credential/permissions/provider and stops fresh GETs after a policy change.

Queued/running/pending-publication native jobs for the same project/provider
coalesce manual and scheduled work. Missed intermediate cycles are coalesced;
terminal failures permit another policy-authorized cycle after the interval.
Frozen unresolved publication requires explicit existing job resolution rather
than silently repinning. Original captures/receipts remain inspectable through
the existing advisory jobs APIs. Changed policies do not rewrite earlier captures.
Use a scoped machine credential for unattended operation; expired session/API
credentials require explicit policy reauthorization. Provider catalogs remain
product-scoped, not version-local discovery or human approvals.

Native manual/scheduled advisory GETs and scoped CPE acquisition share durable
per-provider SQL pacing:
NVD at least six seconds, CIRCL/EUVD/MyJVN at least one second between dispatches.
HTTP 429 Retry-After delta/date values persist a shared cooldown; invalid/missing
values use 60 seconds. There is no automatic HTTP retry. Local waiting is bounded
to 30 seconds; a longer cooldown fails before any outbound request and retains the
job for explicit retry or a later scheduled cycle. Cancellation and current
permission are rechecked after waits. Provider limits can still impose stricter
quotas; this does not guarantee remote availability.

Implicit schema upgrade `0006` adds the small operational provider-throttle table;
normal pre-upgrade backup and startup migration behavior applies. SQL backup keeps
these dispatch/cooldown timestamps; the journal cannot reconstruct operational
rate limits/jobs. Offline cleanup hashes this table without treating timestamps
as object roots and retains each scheduled job's policy checkpoint.

Verification: 32 scheduler/native-job/migration checks and 67 affected HTTP,
maintenance, installation-recovery and upgrade-helper checks passed (33 optional
PostgreSQL cases skipped without a disposable database). Provider fixtures and
fake-clock pacing checks perform no live advisory queries or human approvals.

Nine additional focused HTTP checks verify shared NVD advisory/CPE cooldown,
post-wait CPE management authorization and provider-disabled handling.

The advisory intelligence panel now includes a lazy, collapsed **Optional automatic
refresh schedule** editor. Provider choices come from the current server plan;
managers explicitly configure version labels, interval seconds and bounded batch
sizes. A local review captures the complete CAS replacement before confirmation.
Empty replacements stop new scheduling. Readers see configured scope without
editing actions. Policy/source refreshes never repin captured publication requests.

Failed or uncertain PUTs retain the exact request UUID/body; committed projection
lag keeps its exact receipt refresh. Drafts and pending publication block competing
manual advisory/OSV actions and ordinary navigation. The actor/project-keyed host
tears down old requests on session changes; late responses cannot restore them.
Five scheduling browser checks and six existing manual-advisory checks passed;
frontend typecheck/build passed. No network collection or human approval is
simulated by these UI fixtures.

### Current external specialist contracts and offline mocks

The default sibling checkouts were inspected again: VScorer `b016cf7` is now the
minimal REST-first edition, while Agentyzer is `8ff8372`. The previous isolated
VScorer DTVP-binding branch describes the older product and must not be treated
as the current default service contract. No sibling checkout was modified.

Source-derived JSON Schema snapshots under `tests/fixtures/specialist_contracts`
record full sibling commits and exact relevant source-file hashes. Offline HTTP
mocks validate current request/response shapes while exercising DTVP-issued bytes,
explicit proposal intake and the real native Agentyzer job worker. They perform
no network/provider calls, cloning, LLM analysis or human review. To detect source
drift deliberately against local sibling directories:

```bash
DTVP_SPECIALIST_SOURCE_ROOT=/path/to/src uv run pytest -q tests/test_current_specialist_contracts.py
```

Without that opt-in directory the source-drift check skips; the committed mock
contracts still run in CI. These tests establish the exercised mocked transport
and evidence behavior, not deployed service authentication or analysis quality.

Current minimal VScorer accepts the existing issued `sbom.json` and `cves.json`
unchanged. Its canonical mapping format is semicolon-delimited
`component_ref;threat_model_element_id`. It accepts a separately supplied TM7,
optional items.csv/prior VEX and explicit effective settings. It does not accept
`dtvp-source.json` or `pipeline-context.json` as artifact kinds and does not echo
DTVP receipts in returned finding facts. Its production API currently uses local
sessions, CSRF, exact Origin and idempotency keys; a bearer-token or OIDC service
account must not be assumed. The old qualified DTVP-extension path remains a
separate compatibility contract.

`POST /api/v1/projects/{id}/versions/{version}/proposals/vscorer-minimal`
provides an explicit operator-bound adapter. Inputs are `request_id`, `expected`,
`issued_input_receipt_sha256`, `input_artifacts` (`sbom`/`cves`, each with actual
external `artifact_id` and exact `sha256`), `assessment_id`, exact UTF-8
`finding_json`, its `finding_sha256`, meaningful `binding_reason`, and explicit
`mapping_mode` (`not_declared` or `issued_items_csv`). Optional `source_label`
defaults to `VScorer minimal`. The operator declares which issued upload/result
exchange belongs together; the adapter never manufactures an echoed receipt.
It checks issued input hashes, finding/assessment/revision links, exact selected
CVE/component name/version/PURL/Base facts, native scope/conflict flags and the
recalculated contextual vector. Missing preview or incomplete/conflicting scope
retains a blocked proposal. Exact result bytes, operator declaration, input
receipt and source target fingerprint remain retained; idempotent retries never
publish twice. Changed target material invalidates eligibility through the
existing proposal workflow. No human assessment, approval or score is published.

`POST /api/v1/projects/{id}/vscorer-minimal-mapping` is read-only. It requires
`issued_input_receipt_sha256`, `model_id`, `model_revision` and `model_sha256`,
selecting one exact issued context/model. It returns canonical `items_csv`, its
`items_csv_sha256`, model/context/configuration/parent-receipt pins and a report
digest. Missing mappings, ambiguous/multiple context rows or changed model pins
fail closed. Existing issued serializers and file bytes are untouched. Uploading
this CSV and selecting its effective VScorer mapping settings are separate
explicit actions; no TM7 or placement is invented.

For `mapping_mode: issued_items_csv`, proposal intake additionally requires
`mapping_selection` with that exact selector, plus `input_artifacts.items_csv`
and `input_artifacts.threat_model` upload IDs/hashes. CSV and model-byte digests
must match the declared issued conversion. In `not_declared` mode no CSV/model
mapping proof is implied. TM7 association remains operator-declared; effective
VScorer configuration contents, model authenticity and mapping approval remain
unverified. Reports label provenance `operator_bound_minimal_rest_exchange` and
`DTVP operator; not echoed by VScorer`, visibly distinct from the old extension.

Current default Agentyzer ignores an unknown `source_commit` request field and
its declared response model supplies no `source_input` checkout binding. DTVP
still retains the exact attempted request, completed job/result and raw report,
but explicitly diagnoses `provider_source_commit_binding_unavailable`; those
reports cannot become eligible contextual application or rescoring proposals.
The existing qualified extension path continues to require its full commit and
artifact consistency checks. A useful unqualified report is evidence for review,
never proof of the requested checkout or delivered binary/container contents.

Catalog parsing requires an actual `products` array; dotted literal JSON keys
cannot impersonate array records. Regression checks cover both malformed shapes.
The combined PostgreSQL catalog/scheduler/migration/cleanup/recovery/issued-export
matrix passed 213 checks with one optional skip; the final catalog guard suite
passed 37 checks. These use synthetic fixtures, without live provider acquisition.

### CyBeats read captures with explicit supplied exports

Optional CyBeats integration follows the vendor's public
[request/signing code](https://github.com/cybeats/sbom-studio-action/tree/main/service),
[import lookup](https://github.com/cybeats/sbom-studio-action/blob/main/service/import.service.js)
and [software vulnerability query](https://github.com/cybeats/sbom-studio-action/blob/main/service/dependency.vulnerabilities.service.js).
These document two signed **POST read queries**, not a complete SBOM download API.
DTVP does not invent an export endpoint or upload/scan/writeback operation.
Composition comes from a separately supplied CycloneDX/SPDX export whose association
with the source import ID is an explicit operator declaration. Returned reports
remain opaque attributed artifacts; aggregate vulnerability IDs, scores and counts
are never converted into component findings, approvals or applicability decisions.

Enable `cybeats` in `DTVP_PROVIDERS_ENABLED` and configure `DTVP_CYBEATS_URL` as an
HTTPS origin plus `DTVP_CYBEATS_ACCESS_KEY`/`DTVP_CYBEATS_SECRET_ACCESS_KEY`.
Credentials stay server-side. Managers bind each version through
`PUT /api/v1/projects/{id}/versions/{version}/connectors/cybeats`, supplying
`import_id` and exact `expected_import_id` (explicit null initially).
`POST .../sources/cybeats/capture` with `expected_import_id` performs only the two
SDK queries. Request bodies are signed using timestamp plus the exact transmitted
JSON bytes; redirects/retries are disabled. Every query rechecks the current
credential, project management permission, source binding and provider enablement;
completion rechecks them before returning captured bytes. Responses are bounded
at 4 MiB each and retain their exact decoded HTTP bodies, hashes and source path.

`POST .../sources/cybeats/import` accepts multipart `file` (original SBOM),
`capture_file` (exact capture JSON) and `metadata` (JSON). Metadata uses the native
inventory import fields, `source: "cybeats"`, `expected_import_id`, exact
`capture_sha256`, and `acknowledge_project_reader_disclosure: true`.
The capture is at most 12 MiB; the supplied SBOM at most 16 MiB, also subject to
installation upload limits. Current manager/write permission is required; new
publications recheck the configured origin/import binding and normal inventory
CAS/build/source-role rules. Acknowledgement explicitly allows project readers to
retrieve the retained raw capture, decoded reports and original SBOM.

Uploaded captures are **caller-supplied unverified claims**. Hash/readiness checks
prove internal consistency, not provider authenticity or that the supplied SBOM
was exported from that source. Known configured source credentials echoed literally
in capture/report JSON are rejected before return or publication; this is not a
promise to discover every secret or sanitize arbitrary metadata. Operators must
review the disclosure they authorize. Request headers are not retained. Exact
successful retries recover their original receipt after provider/binding changes,
under current manager/write authorization; new requests use current bindings and
configuration. Failures do not silently rebind, refetch or approve anything.

Mocked SDK-signing and HTTP tests cover raw-byte retention, malformed captures,
known credential echoes, per-query revocation, source CAS and exact receipt replay.
No live customer CyBeats deployment or full remote-export contract has been
qualified. Such acceptance requires the deployment's actual API/schema and a
representative supplied SBOM; the public action SDK alone does not establish it.

The reviewed public action SDK is pinned to commit `f55fb85ef1d0533f5554a436f8a61b0435353aaf`
in `tests/fixtures/cybeats-sdk-contract.json`, with SHA-256/size for its five reviewed
signing/query/entry-point files and a frozen synthetic signing vector. The pin
records this reviewed contract; deployment compatibility remains an acceptance gate.

Generator qualification remains branch-specific. Current default `3357ac7` accepts
Dependency-Track/CycloneDX plus curated configuration; native DTVP knowledge input
exists on the unmerged `feat/dtvp-snapshot-integrity` branch (`da3cba0`). Its source
pins and the default-at-review boundary are recorded in
`tests/fixtures/specialist_contracts/generator-qualified-source.json`.

An optional test executes that isolated adapter's actual `KnowledgeSource` parser
against real locally issued DTVP bytes through a mocked transport, checking exact
file capture and rejection of changed bytes or project scope:

```bash
DTVP_GENERATOR_CONTRACT_ROOT=/path/to/qualified-generator-checkout DTVP_GENERATOR_CONTRACT_PYTHON=/path/to/existing-generator-venv/bin/python uv run pytest -q tests/test_generator_qualified_contract.py
```

The interpreter override is optional; the test otherwise uses the selected
checkout's `.venv/bin/python`. Missing source/environment/dependencies leave the
optional checks skipped; no installation is attempted. Relevant source-file
hashes must match the recorded reviewed adapter. The child process receives no
inherited credentials, disables bytecode writes, uses a private temporary working
directory and blocks live requests. No Generator checkout is changed and no
rendering, publishing, PDF generation or controlled-document parity is inferred.
The configured source/environment passed all four focused checks locally.

Generator acceptance attestations in the consolidated acceptance runner still
remain external `not_run` gates. The adapter must be reconciled with subsequent
default VSBOM/template changes before cutover; these mocked parser checks do not
claim that current default Generator already supports native DTVP input.

Final rewrite verification checkpoint (2026-10-16): the complete backend regression
run passed 1,949 tests with 37 optional environment-dependent skips. Separate
PostgreSQL catalog/scheduler/migration/recovery/root/export checks passed 213 tests
with one skip; SQLite/PostgreSQL CyBeats checks passed 58. Final focused catalog
and CyBeats guard/signing checks passed 37 and 40 respectively. Current specialist
source-pinned mocks and the actual isolated Generator parser checks passed as
described above. These overlapping suites are not additive coverage totals.
Frontend typecheck/build and all three unit tests passed; feature-specific browser
checks are recorded with their implementation sections. Ruff and diff checks pass.

Recorded verification counts in this reference describe individual historical
implementation checks, not a current complete-suite result.

The [rewrite boundaries](rewrite-plan.md#agreed-ground-up-design)
and [consumer contracts](consumers.md#current-dtvp-contract) distinguish
implemented behavior from human approval and deployment acceptance. Generator's
native adapter remains on its isolated branch; current Agentyzer lacks checkout
proof. Representative migration/document parity, production identity, capacity and
engine-upgrade qualification remain operator acceptance tasks. Mocked results
never grant these gates or silently extend assessment approval.

## Non-US advisory adapters

Native journal-backed advisory refresh supports `nvd`, `circl`, `euvd` and `jvn`
when explicitly enabled in `DTVP_PROVIDERS_ENABLED`. EUVD uses ENISA's fixed
`https://euvdservices.enisa.europa.eu/api/enisaid?id=...` endpoint for an exact
baseline CVE or EUVD ID; requested CVEs must appear exactly in the returned aliases.
Multi-CVE/contradictory EUVD aggregates fail closed for a single CVE request, avoiding
transfer of a group score to one CVE. Exact baseline EUVD requests retain their own
record scope. MyJVN uses the supported HND `getVulnDetailInfo` XML endpoint at
`https://jvndb.jvn.jp/myjvn`, for exact baseline `JVNDB-YYYY-NNNNNN` IDs only.
CVE keyword search is deliberately unsupported: it is fuzzy, and JVN's aggregate
CVSS can describe another CVE in a multi-CVE record. Related CVEs remain aliases,
never automatic new findings or coverage.

`GET .../advisory-refresh?provider=euvd|jvn` pages only identifiers supported by the
selected provider, reports `unsupported_total`, and exposes `identifier_formats`
for every provider. The UI resets selected IDs on provider changes, explains IDs
not looked up and preserves frozen pending requests across uncertain outcomes.
CLI/API refresh requests retain existing exact-head/evidence pins and worker leases.
All responses retain byte-exact decoded HTTP bodies and validated normalized facts
in immutable captures; publication independently rechecks normalization against the
retained bytes. Requests disable redirects, bound jobs to 20 IDs, responses to
4 MiB and captures to 32 MiB. XML rejects DTD/entities, unexpected namespace/status,
wrong IDs, incomplete counts, excessive depth and nonfinite scores. EUVD's actual
204/no-body and MyJVN's successful zero-record responses mean provider not-found,
never remediation. Source severity remains an attributed assertion, not a DTVP
approval; no matching, inferred applicability or source independence is claimed.
HTTP errors including rate limiting fail the job; retry remains explicit and uses
existing frozen captures once collection completed. Deployment quotas/availability
and unattended feed scheduling remain separate operational requirements.

Provider contract references: [official EUVD API documentation](https://euvd.enisa.europa.eu/apidoc),
[official MyJVN detail API](https://jvndb.jvn.jp/apis/getVulnDetailInfo_api_hnd.html),
[JVN aggregate-score FAQ](https://jvndb.jvn.jp/apis/myjvnapi_faq.html),
and [HND/OKA support announcement](https://jvndb.jvn.jp/nav/sys_announce.html).
Public success/not-found response shapes were checked against live official
endpoints; automated tests use synthetic response fixtures without external calls.

## Worker and scoring rules

The native worker executes only journal-backed analysis, Dependency-Track intake,
known-ID advisory enrichment, OSV matching and synchronization proposal jobs.
Retained SQL jobs from the previous runtime remain historical records: workers do
not claim or execute them. Legacy enqueue/retry, SQL findings, approval, analysis
and snapshot-generation runtime paths have been removed. Explicit migration of
retained historical snapshot bundles remains supported with current source/target
authorization; imported historical claims never confer native approval.

Project scoring rules are journal-owned immutable policies. Managers configure
`GET/PUT /api/v1/projects/{id}/scoring-policy`; dedicated security coordinators use
`POST /api/v1/projects/{id}/scoring/rules/preview` and `/publish`. Rule applicability
comes exclusively from currently approved contextual assessments, with the usual
all-team gate. False-positive rules require an explicit choice and approved
not-affected applicability. Publication preserves original Base vectors, complete
rule configuration, policy and approved-assessment pins. Policy CAS and branch
publication are atomic; exact request replay retains its original receipt after
policy changes. Policy edits never rewrite prior scores or release tags. Manual
scoring and external scoring proposals remain available separately.

## Editable scenarios and CLI

### Editable local scenarios

Playground startup creates synthetic identities and workspaces only. Load optional
versioned scenario files explicitly:

```sh
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator demo load --file playground/scenarios/workflow.json
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator demo load --file playground/scenarios/specialists.json
```

Both files use `dtvp.demo-scenario/1`: editable complete SBOMs, source/build metadata,
version baselines, team ownership roots/rules, assessment/reviewer personas, release
tags and later imports. Specialist data adds license judgments and explicitly
operator-bound mock VScorer output plus unqualified Agentyzer evidence. Mock output
establishes neither external-service execution nor human approval. The loader uses
ordinary domain workflows in a fixed phase order; JSON never supplies executable
commands. There are no UI seed buttons or production scenario routes.

Reloading the same normalized file preserves existing assessments and current
branch heads. A changed file with the same fixture ID is rejected: choose a new
`fixture_id` **and** `project_name` for an independent scenario. Loading never
resets unrelated projects. Complete normalized input and synthetic actor/provenance
markers are retained in the knowledge journal. All fixture decisions are simulated
by named synthetic playground personas; they are not real review approvals.

The playground-only loader requires an explicit synthetic session (CLI `--persona`),
CSRF protection and real team permissions. The backend validates bounded structured
input; project creation occurs only after the complete scenario builds successfully.

Coordinator CLI commands keep policy and scoring decisions in the backend:

```sh
uv run dtvp knowledge score policy --project PROJECT_ID
uv run dtvp knowledge score policy --project PROJECT_ID --file policy-request.json
uv run dtvp knowledge score preview --project PROJECT_ID --rules --file score-request.json
uv run dtvp knowledge score publish --project PROJECT_ID --rules --file publication-request.json
```

Omit `--rules` for explicitly supplied CVSS scoring. Files contain the exact typed
API request: current expected version/policy pins, scope, vectors and rationale;
publication additionally requires the preview digest. Preview never publishes,
and publication remains subject to current reviews and coordinator authorization.
The CLI prints the server response without selecting scores or fabricating pins.

## Native UI workflow

The UI has one native **Review** workspace. Product/version/team/search and status filters, scope statistics, queue and assessment/review/coordinator detail appear first. Source and published scores remain side by side. Three collapsed tool menus retain composition/team configuration, evidence/integrations, and reports/licensing/history; disclosure drafts remain mounted. Old Products/Statistics/legacy Review components are removed; old page query parameters open native Review. Activity lists native jobs read-only; request actions remain in their scoped native tools. Access and system/light/dark themes remain available. Playground persona switching is compact; demo data is loaded through the file-based CLI, not UI seed buttons.

Coordinator scoring offers readable CVSS 2/3/4 contextual metric groups with fixed source Base metrics and optional advanced vector input. Manual/provided proposals and project rules from approved applicability/false-positive decisions share the server-gated preview and explicit publication workflow. Project scoring rules are journal-backed; the optional JSON policy editor uses CAS, retained request IDs and exact retry after uncertain writes. Rule previews retain policy and approved-assessment provenance. No rule or proposal approves an assessment automatically.

The frontend API clients and retained download URLs derive their prefix from the canonical API_VERSION in dtvp/api_contract.py at build time.

Optional SSVC prioritization is authored alongside the scoped applicability assessment, using pinned local model/version/hash, explicit answers, rationale and evidence references. Outcomes and completeness are calculated by the server. Reviewers can inspect current and approved records separately; filters include SSVC status and action. Scoring selectors use server-normalized original Base vectors while retaining raw source ratings as evidence.

## SSVC prioritization

### Native SSVC and rescoring

Native assessments optionally include SSVC decisions. The authenticated
`GET {API_PREFIX}/ssvc/models` returns the bundled Deployer Patch Application
Priority model, exact version/hash, decision points and source attribution.
The optional assessment `ssvc` object contains `model`, `version`,
`model_sha256`, explicit `answers`, `rationale`, and optional operator-supplied
`evidence` references/descriptions. DTVP evaluates the pinned table itself and
stores its result inside the same immutable assessment revision; clients cannot
supply an outcome. Incomplete answers can be drafted, never submitted. Independent
team review approves the exact assessment/SSVC revision and its explicit consuming
contexts/versions. SSVC does not automatically publish CVSS scores.

Workspace responses expose `ssvc.current`, `ssvc.approved`, `ssvc.pending` and
status (`missing`, `draft`, `submitted`, `approved`, `pending`, `stale`). New pending
answers retain the previously approved priority until reviewed; changed material
invalidates current approval. Imported legacy SSVC documentation remains attributed
source evidence, never native approval. Cross-context correspondence drafts do not
automatically copy a deployment-specific SSVC decision.

UI and CLI support `ssvc_status` and `ssvc_action` filters (CLI
`--ssvc-status`/`--ssvc-action`). Actions: `DEFER`, `SCHEDULED`, `OUT_OF_CYCLE`,
`IMMEDIATE`; action filtering uses current approved SSVC where available, otherwise
an active draft/submitted decision. Combine status/action to distinguish reviewed
from provisional prioritization. Filtered statistics use the same scope.

The retained model/license comes from the v1 resource, sourced from
[CERT/CC SSVC deployer model](https://github.com/CERTCC/SSVC/blob/2026.7.0/data/json/decision_tables/ssvc/deployer_patch_application_priority_1_0_0.json).
Evidence references are operator declarations, not automatically verified KEV or
Vulnrichment enrichment; DTVP does not infer missing SSVC answers. This model's
human-impact decision point preserves the selected SSVC model; DTVP makes no
safety-analysis claim.

Rescoring's source Base selector uses backend-validated `original_base_vectors`;
all original raw ratings remain visible as attributed evidence. Manual and
rule-derived contextual scoring support CVSS 2.0/3.0/3.1/4.0, preserve source Base
metrics, require current reviews and explicit coordinator preview/publication.

Analyst/reviewer CLI file wrappers:

```sh
uv run dtvp knowledge assessment draft --project PROJECT_ID --id ASSESSMENT_ID --file assessment.json
uv run dtvp knowledge assessment submit --project PROJECT_ID --id ASSESSMENT_ID --file assessment.json
uv run dtvp knowledge review --project PROJECT_ID --file review.json
```

Assessment files use the same exact native `AssessmentInput` contract, including
optional SSVC. Review files use `ReviewInput`: explicit approve/request_changes,
assessment revision, targets, current expected version heads and rationale. No CLI
command guesses pins, fills SSVC answers or creates automatic human approval.
