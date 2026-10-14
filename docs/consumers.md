# Separate consumers

Create a release snapshot through DTVP UI/API. The manifest binds inventory,
source revisions, curated metadata, component occurrences, findings, decisions,
approvals, coverage and checksums. `/bundle` is the complete sealed JSON payload.
Authorization is checked again for every resource, including old snapshots.

## Generator

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

## VScorer

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
require a coordinated VScorer change; that repository was not modified here.
See [inspected contract](vscorer-consumer-contract.md).

## Agentyzer

Agentyzer is an external service in `../agentyzer`, with independent code, tests,
dependencies, images and releases. DTVP can retain its results through generic
`dtvp.evidence/1` ingestion with `source="agentyzer"`; assessments remain proposals
for an explicit human decision. Preserve repository/commit, component occurrence,
advisory identity, analysis coverage and the complete original response. Missing
code references or partial source coverage cannot establish non-applicability.
Native `/assess` submission, remote job polling and follow-ups remain connector
work. The DTVP image and playground do not build or start Agentyzer.
