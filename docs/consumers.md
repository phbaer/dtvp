# Separate consumers

## Current DTVP contract

All DTVP endpoints use `API_PREFIX`, currently `/api/v1`, configured once in
`dtvp/api_contract.py`. Native product/version states are content-addressed
journal revisions, with explicit consuming contexts, assessment revisions,
independent approval pins and immutable release tags. Retired SQL release/UUID
snapshot endpoints are unavailable. An imported label, hash or source conclusion
never grants permissions or human approval. Authorization is checked on every
fetch, including retained historical evidence.

- `GET /projects/{id}/states/{state}/bundle` and `/manifest` read pinned native
  evidence, inventory/graph, contexts, annotations, source facts, approvals and history.
- `POST /projects/{id}/states/{state}/exports/bundle` issues frozen consumer bytes.
  Its receipt/file URLs resolve retained original bytes across serializer upgrades.
- `POST .../states/{state}/vscorer-input` derives focused CycloneDX/CVE artifacts
  after explicit occurrence/context and source Base selection.
- `POST .../states/{state}/agentyzer-input` derives a contextual repository/commit
  request and receipt. Derived receipts bind exact inputs; they are not signatures.
- `GET .../states/{state}/license-worklist` separates attributed declarations and
  missing data from scoped organization license decisions and independent review.
- `GET .../states/{state}/pipeline-context?configuration=HASH` exposes the pinned
  component/context/model/entity register. Configuration edits do not repin issued
  artifacts or grant scoring/architecture approval.

Archive exact issued bundle, manifest, receipt and file bytes with consumer outputs.
Consumers must handle all required artifact pins or reject the receipt. Frozen
serializer `/1`, `/2`, `/3` identifiers are **data-format versions**, not HTTP API
versions. Existing issued payload bytes are never rewritten to rename API versions.
Older unissued receipts retain reproduction limits; prefer explicit issuance.

## Current VScorer: minimal REST edition

Source-pinned mocks cover inspected default `b016cf7`; see
[current external contracts](native-reference.md#current-external-specialist-contracts-and-offline-mocks).
Its real artifact/assessment/finding API does not echo a DTVP receipt. Use
`POST /projects/{id}/versions/{version}/proposals/vscorer-minimal` for explicit
**operator-bound** result intake, rather than fabricating an echoed binding.

The request pins current `expected` state, `issued_input_receipt_sha256`, uploaded
SBOM/CVE artifact IDs and exact hashes, assessment ID, original `finding_json`
bytes/hash and a meaningful `binding_reason`. DTVP checks actual component/CVE/
assessment links, source Base/vector/score and retained issued scope. The operator's
exchange declaration remains distinct from provider facts and cryptographic proof.
An eligible proposal still requires current independent team reviews and explicit
coordinator preview/publication. Unknown or inconsistent scope stays diagnostic.

Optional model mappings are CI/operator declarations. Read-only
`POST /projects/{id}/vscorer-minimal-mapping` derives canonical `items.csv` from
one exact issued pipeline-context/model selection, binding parent issuance,
model ID/revision/digest and CSV hash. `mapping_mode=issued_items_csv` result intake
pins the CSV and actual supplied threat-model artifact IDs/hashes. With
`mapping_mode=not_declared`, no CSV/threat-model mapping is claimed. DTVP neither
uploads these artifacts automatically nor invents TM7 files, verified settings or
model approval. Ambiguous/unavailable mappings fail closed.

An earlier isolated VScorer `feat/dtvp-context-binding` branch (including `3994254`
and metadata extension `9fd670b`) accepts/returns a qualified optional binding.
That separate contract uses `.../proposals/vscorer`, retains strict hash/context/
Base checks and can verify uploaded TM7/entity consistency. It is not the current
minimal default and was not merged, pushed or deployed. Historical branch HTTP
namespaces do not establish compatibility with the current DTVP namespace; a real
consumer cutover must be qualified explicitly. See
[inspected earlier contract](vscorer-consumer-contract.md).

## Generator

Generator remains a separate application. Its inspected default still reads
Dependency-Track/CycloneDX directly; it has **not** completed native DTVP cutover.
The default sibling contains unrelated user work and is never silently rewritten.

The isolated `feat/dtvp-snapshot-integrity` adapter, culminating in `da3cba0`, uses
explicit DTVP project/state selection, frozen bundle issuance, exact receipt/
manifest/file hashes and existing renderers/templates. It disables mutable source
enrichment during native runs and archives exact inputs. Authored support status,
support-until and end-of-life retain separate meaning/provenance; missing metadata
stays diagnostic. The pinned model-placement register produces separate
Markdown/HTML/CSV/JSON supplements; it does not invent model GUIDs or topology.

Historical validation included 757 tests with one optional skip and a real synthetic
HTTP issuance/render run producing four support formats with byte-exact archived
inputs. The run reported three errors and twelve warnings for missing inputs; it
was not controlled-document acceptance. Current source-pinned optional parser tests
exercise that isolated adapter against DTVP-issued bytes without modifying siblings.
The adapter's historical HTTP namespace has not been retargeted/qualified against
this native-only API release. Successful parsing of immutable bytes is not a claim
that the unmerged adapter or default Generator deploys unchanged against current
DTVP. Preserve existing audit-document output quality through explicit adapter
cutover and customer fixture qualification; PDF, full model/contextual outputs and
human approval remain separate acceptance gates.

## Agentyzer

Agentyzer is external, separately deployed and versioned. Native DTVP supports
contextual derived inputs, durable submission/poll/report checkpoints, retained
raw reports and explicit proposal intake. The inspected default `8ff8372` lacks
qualified checkout-commit proof: its reports remain evidence and are ineligible
for applicability application or contextual scoring. No binding is fabricated.
Optional authenticated reconciliation/follow-up extensions require a separately
qualified compatible service; uncertain POSTs are never automatically repeated.

Qualified results must match exact issued request, repository/commit, package/
version/CVE and coverage. Exclusion requires explicit adequate coverage. Selecting
an eligible proposal never submits a human assessment or publishes a score.
See [native Agentyzer contract](agentyzer.md) for routes, failure handling and
extension requirements. Mocks prove transport/contract behavior, not deployed
authentication, source/binary authenticity or analysis quality.

## Source intake and supporting evidence

Dependency-Track is a GET-only source via per-version bindings and durable collection
jobs. Original SBOM/finding/analysis responses, tagged DTVP documentation and plain
legacy text are retained independently. Nontransactional remote reads do not prove
snapshot consistency. CyBeats and file inputs follow explicit source authority and
provenance rules. Writeback is never implicit.

CPE discovery is internal, using pinned catalogs/aliases/rules and reviewed mappings;
name similarity does not establish identity or applicability. Known-ID NVD/CIRCL
refresh and explicit exact-PURL OSV matching retain separate source facts. Missing
coordinates/unsupported ranges stay unknown, and external conclusions never replace
organization decisions. National catalog completeness and legal/architecture
qualification require their own measured acceptance evidence.

Pipeline configurations may pin many-to-many component/context/model/entity mappings.
Released states preserve their own configuration and approved decisions while parallel
product versions receive independent nightly imports. Source correctness/completeness
remains the producer interface requirement. Controlled consumer acceptance additionally
requires scoped machine authorization, archived reproducible inputs, retry/failure
qualification and explicit human approvals; rendering success alone is insufficient.
