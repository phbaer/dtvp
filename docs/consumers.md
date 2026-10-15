# Separate consumers

## Native journal-backed v3

Native knowledge bundles use content-addressed state hashes and project IDs.
They are distinct from v2 UUID snapshots. Authorize every fetch under current
project permissions; retained source names and imported author labels do not grant
roles. Hashes establish consistency, not publisher identity or human approval.

- `GET /api/v3/projects/{id}/states/{state}/bundle` and `/manifest` provide complete
  pinned native evidence, exact graph/consuming contexts, approved pins and retained
  history. Archive original bytes and configuration with generated outputs.
- Generator's isolated `feat/dtvp-snapshot-integrity` branch, commit `354d644`,
  adds `--dtvp-project-id ID --dtvp-state SHA` on the existing generation path.
  API mode is `dtvp_knowledge`. It retains renderer/templates, validates exact
  contexts, independent approval pins and published CVSS, archives complete inputs
  and disables mutable enrichment during native runs. External proposals remain
  evidence. Assembly forests retain actual roots without invented software edges;
  omitted/missing parts and coherence limits remain visible in outputs. The native
  UI selects project/version and explicitly pins the state; credentials remain
  server-owned and redacted. Independent review: 96 backend tests, 14 frontend
  tests and production build passed. This is not merged into `../generator`.
  Richer metadata presentation and controlled-document parity remain cutover gates.
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
Native follow-ups, complete CPE migration/refresh and semantic identity
reconciliation, full legal qualification and architecture approval remain planned.
Production acceptance also requires machine authorization, archived reproducible
inputs, failure/retry handling and controlled consumer fixture qualification.
The optional source receipt is a consistency contract; versioned serializer
compatibility across future upgrades remains a pre-cutover requirement.

Native Dependency-Track intake uses per-version bindings and durable GET-only
collection jobs. Frozen captures retain original export/finding/analysis responses,
including tagged/plain legacy documentation. Export claims and finding claims
remain independent; nontransactional remote reads never establish snapshot
consistency. This is source intake, with no implicit writeback.

Native advisory feed documents provide exact known-ID enrichment through the
product evidence lifecycle. They retain provider facts independently, without
package/version matching, applicability adoption or new findings. Unknown IDs
remain unresolved; live native provider refresh remains separate connector work.

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
remains connector work. The DTVP image and playground do not build or start Agentyzer.
