# Separate consumers

## Native journal-backed v3

Native knowledge bundles use content-addressed state hashes and project IDs.
They are distinct from v2 UUID snapshots. Authorize every fetch under current
project permissions; retained source names and imported author labels do not grant
roles. Hashes establish consistency, not publisher identity or human approval.

- `GET /api/v3/projects/{id}/states/{state}/bundle` and `/manifest` provide complete
  pinned native evidence, exact graph/consuming contexts, approved pins and retained
  history. Archive original bytes and configuration with generated outputs.
- Generator's isolated `feat/dtvp-snapshot-integrity` branch now includes issued-input integrity (`791b186`), resource/constructor fixture isolation (`60e63c9`), offline document comparison (`20a7e93`) and pinned authored support reporting (`0ac78ed`). Native CLI/API/UI inputs use exact DTVP project/state selections and issued bundle/receipt/manifest bytes, preserve context/approval/CVSS distinctions and disable mutable enrichment. Existing renderers/templates remain in use. Authored support status, support-until and end-of-life dates retain their separate meanings, provenance and applicability; they never become an inferred support classification. Stale annotations remain historical. The isolated full suite passed 743 tests with one optional-template skip. These changes are not merged into `../generator` or deployed.

  An actual HTTP run against isolated DTVP issued serializer `dtvp.knowledge-bundle-serializer/2` for a synthetic annotated state and produced Markdown/HTML/CSV/JSON support outputs. All four output hashes and the exact archived bundle were independently verified; external transport was blocked except for that DTVP endpoint. Generator retained template revision `41ea5cce0d8736078101570463f6f5dc5e79a18f`. Its consistency report raised three errors and twelve warnings (missing license/composition evidence and other missing inputs); the run does not satisfy controlled-document acceptance. PDF, customer configurations, prior-release/contextual vulnerability outputs and human approval remain unqualified. Source receipts and successful rendering establish neither supplier support verification nor regulatory acceptance.
- `POST .../states/{state}/vscorer-input` derives schema-validated CycloneDX and
  focused strict CVE files after explicit source Base selection. Its receipt pins
  state, consuming context, component, file hashes and original Base assertions.
  Sibling VScorer `feat/dtvp-context-binding`, commit `3994254`, accepts/returns
  this optional binding after independent Python/architecture review. It makes no
  claim to authenticate DTVP remotely. No merge into `../vscorer` was performed.
- Return one native VScorer finding and the assessment's `source_binding` to
  `POST .../versions/{version}/proposals/vscorer`. DTVP reproduces pins and local
  CVSS calculations; stale/withheld/invalid reports stay attributed and ineligible.
  UI and CLI compare proposals; adoption requires coordinator rationale, preview,
  current independent team reviews and explicit publication.
- Internal CPE catalog/alias/rule proposals use `/projects/{id}/cpe` and pinned
  `/states/{state}/cpe`; no name-based identity adoption or applicability inference.
- `/states/{state}/license-worklist` exposes source declarations, concluded claims,
  missing information and provenance, separately from organization license
  dispositions. Dedicated license analysts submit usage/distribution conclusions;
  independent license reviewers approve exact revisions. Material composition and
  metadata changes require revalidation. These are organization decisions, not
  inferred legal clearance.

- `POST .../states/{state}/agentyzer-input` derives an exact producer-qualified
  repository/commit request and contextual receipt. Return the receipt plus a
  completed native job/report envelope to `.../versions/{version}/proposals/agentyzer`.
  DTVP retains raw reports and checks structured request/package/CVE/commit
  consistency. Missing bindings remain ineligible evidence. UI/CLI compare
  analysis and optional validated scoring proposals; imports never approve them.

Native Agentyzer jobs now persist submission/poll/report checkpoints in operational
SQL and publish bound evidence through the journal. Unknown POST outcomes never
automatically repeat; lost in-memory remote jobs still require explicit reconciliation.
Exact parent/report-bound native follow-ups are implemented with the optional
authenticated Agentyzer extension and never fall back to legacy unbound follow-ups.
Bounded offline dictionaries and historical CSV claim import now ship; full national
dictionary refresh and reviewed mapping-history reconstruction remain outside that
contract. Automatic semantic identity reconciliation, legal qualification and architecture acceptance remain
separate scoped work.
Production acceptance also requires machine authorization, archived reproducible
inputs, failure/retry handling and controlled consumer fixture qualification.
Newly issued input receipts resolve retained bytes instead of rerunning current
serializers. Explicit `POST .../states/{state}/exports/bundle` creates a frozen
bundle issuance; authorized file URLs preserve bytes across upgrades. Specialist
preparation returns optional issuance metadata while native receipts remain unchanged.
Older unissued receipts retain reproduction compatibility limits. Generator’s
isolated adapter now explicitly issues native inputs, validates the source receipt,
scope and frozen file digests, and archives issuance/receipt/bundle/manifest bytes.
It constructs same-origin file paths and never falls back to direct native reads.
Actual current DTVP issuance to Generator passed with byte-exact archived files.
Controlled output qualification remains cutover work. Source receipts establish
consistency, not provider authenticity or human approval.

Native Dependency-Track intake uses per-version bindings and durable GET-only
collection jobs. Frozen captures retain original export/finding/analysis responses,
including tagged/plain legacy documentation. Export claims and finding claims
remain independent; nontransactional remote reads never establish snapshot
consistency. This is source intake, with no implicit writeback.

Native advisory feed documents provide exact known-ID enrichment through the
product evidence lifecycle. They retain provider facts independently, without
package/version matching, applicability adoption or new findings. Unknown IDs
remain unresolved. Durable NVD/CIRCL known-ID refresh and optional exact-PURL OSV
matching now ship. OSV claims remain independent of human applicability decisions;
unsupported coordinates retain unknown coverage.

## V2 compatibility contracts

The following UUID snapshot contracts describe the existing v2 runtime and prior
consumer branches. They are not silently reused for native v3 state hashes.

Create a release snapshot through DTVP UI/API. The manifest binds inventory,
source revisions, curated metadata, component occurrences, findings, decisions,
approvals, coverage and checksums. `/bundle` is the complete sealed JSON payload.
Authorization is checked again for every resource, including old snapshots.

### Generator

The isolated branch `feat/dtvp-snapshot-consumer` in
`/tmp/dtvp-generator-consumer` adds a source on Generator's existing CLI/API path.
It does not touch the current `../generator` working tree, which has unrelated edits.

Configure Generator's server `DTVP_URL` and `DTVP_TOKEN` with an expiring scoped
read credential. Supply `--dtvp-snapshot-id UUID` to `uv run architecture-gen`,
or send `input_mode="dtvp"` and `dtvp_snapshot_id` to the generation API. The
requested name/version must match the pinned snapshot. The product-picker route
reads DTVP when configured. Credentials remain server-owned and masked.

The source verifies SHA-256 and supplies all components/graphs, metadata and
occurrence-specific histories. Findings with the same CVE retain separate report
keys; the displayed advisory ID stays unchanged. Current approved DTVP decisions determine reviewed applicability. Existing
non-pending legacy DT assessments retain their source applicability with an
explicit legacy label; pending/conflicting or state-free records stay in triage.
Both tagged and metadata-free rationale/history remain available without
fabricating approval or identities. DT access is explicitly disabled
throughout a DTVP run. Generator retains its own mappings, jobs, templates and outputs.

### VScorer

Download `/snapshots/{id}/sbom` and
`/snapshots/{id}/exports/vscorer/worklist`; upload through VScorer's existing
artifact intake. The combined export endpoint includes a sidecar manifest and
finding mapping. Non-CVE findings, absent/ambiguous refs and competing Base
vectors remain listed as unresolved coverage. Original Base vectors and scores
are never replaced by effective scores. VScorer's specialized review and
NVD/KEV preparation still run inside VScorer.

Return `dtvp.evidence/1` with `source="vscorer"`, `snapshot_id`, a unique result
ID and `assertion` containing `kind="contextual-assessment"`, `assessment_id`,
the exact exported `base_vector` and `component_refs`. DTVP validates the frozen
scope and retains the proposal; analysts explicitly submit a DTVP decision.
Reimports are idempotent. New contextual evidence invalidates older approval.

Exports have been validated with VScorer's actual CVE/CycloneDX parsers. Direct
in-application snapshot selection and an automatic VScorer assessment round trip
were limitations of this earlier v2 integration. The isolated native v3 change
is recorded above.
See [inspected contract](vscorer-consumer-contract.md).

### Agentyzer

Agentyzer is an external service in `../agentyzer`, with independent code, tests,
dependencies, images and releases. DTVP can retain its results through generic
`dtvp.evidence/1` ingestion with `source="agentyzer"`; assessments remain proposals
for an explicit human decision. Preserve repository/commit, component occurrence,
advisory identity, analysis coverage and the complete original response. Missing
code references or partial source coverage cannot establish non-applicability.
V2 supports native `/assess` submission, durable local jobs, remote polling and
follow-ups with qualified repository/commit binding. Journal-backed v3 orchestration
and exact-parent follow-ups now ship with explicit authenticated sibling contracts;
deployed compatibility and operational retention still require acceptance.
The DTVP image and playground do not build or start Agentyzer.
