# Native API contract

[README](../README.md) is canonical; [native reference](native-reference.md) retains
expanded workflows, bounds and integration limitations. `/openapi.json` is the
executable request schema. All application routes use `API_PREFIX`, derived from
`API_VERSION` in `dtvp/api_contract.py` (currently `/api/v1`). Frontend builds read
the same Python constant. Historical data-format names do not mount old runtimes.

## Authentication and concurrency

Machine requests use `Authorization: Bearer TOKEN`. Browser sessions use an
HTTP-only session cookie; mutations require `X-CSRF-Token` and, when supplied,
a matching browser Origin. Credentials expire and can be revoked. Current
membership, project sharing and credential scope are checked on reads, mutations,
artifact downloads and worker requests. Inaccessible resources normally return 404.
Administrator, analyst, reviewer and coordinator capabilities are distinct.

Native mutations carry explicit request IDs and expected immutable version/policy
heads. Stale pins return 409. Preserve the exact request after uncertain responses:
replay returns the original receipt instead of silently replacing scope or pins.
Publication can succeed while projection remains pending; responses report that
condition explicitly. Preview operations never publish decisions.
Inventory imports also accept `expected: "current"` (the default when omitted):
the server captures the current head and still checks it at publication. Receipt
replay occurs first, so retries never silently retarget an already committed import.

All paths below are relative to `API_PREFIX` unless stated otherwise.

## Main resources

| Resource | Contract |
| :--- | :--- |
| `/me`, `/workspaces`, `/workspaces/{id}/members` | Current identity and explicit issuer/subject/role mappings |
| `/projects`, `/catalog/projects`, `/projects/{id}/sharing` | Searchable authorized products and capability grants |
| `POST /projects/resolve` | Resolve an exact product ID/name, creating a missing name in an authorized owner workspace |
| `/projects/{id}/versions`, `/versions/{version}/workspace` | Independent version heads, contextual work queue and scoped statistics |
| `/projects/{id}/states/{state}/dependency-tree` | Pinned, bounded dependency traversal; `root_ref`, `max_depth`, `offset`, `limit`, explicit cycle/shared/missing markers |
| `/projects/{id}/versions/{version}/workspace/{context}/{vulnerability}` | Scoped detail plus shared `contributions`: vulnerability sources, analyses and CPE declarations/mappings/candidates; `expected` guards the selected head |
| `/projects/{id}/versions/{version}/imports`, `/files` | Complete scoped JSON or exact-byte multipart SBOM intake |
| `/projects/{id}/versions/{version}/parts/{part}/imports`, `/files` | Independently ordered constituent-source intake |
| `/projects/{id}/versions/{version}/assembly` | Explicit immutable part selection into a product baseline |
| `/projects/{id}/ownership` | Versioned recursive team selectors and consuming roots |
| `/projects/{id}/assessments/{assessment}/draft`, `/submit` | Context/version-pinned applicability and optional SSVC |
| `/projects/{id}/reviews` | Independent approval or change request on the exact assessment revision |
| `/projects/{id}/scoring/preview`, `/publish` | Explicit coordinator contextual CVSS proposal/publication |
| `/projects/{id}/scoring-policy` | Journal-backed project scoring rules; manager CAS configuration |
| `/projects/{id}/scoring/rules/preview`, `/publish` | Pinned rules evaluated against approved applicability |
| `/ssvc/models`, `/cvss/metrics/{version}` | Authenticated local model and metric metadata |
| `/projects/{id}/states/{state}/bundle`, `/manifest` | Immutable consumer representation under current access |
| `/projects/{id}/states/{state}/source`, `/artifacts/{sha}` | Exact original files explicitly retained by the selected state |
| `/projects/{id}/compare`, `/tags` | Pinned state comparison and immutable released-state references |
| `/credentials`, `/jobs`, `/projects/{id}/audit` | Scoped credentials, native job inspection and operational audit |

Some displayed paths continue a project-scoped prefix: use the exact full path
from OpenAPI when constructing a client. Native evidence, licenses, documentary
review, issued exports, synchronization, CPE discovery and source-specific jobs
have their own typed resources in that schema.

## Inventory intake

Submit JSON to `/projects/{id}/versions/{version}/imports`:

```json
{
  "request_id": "build-123-sbom",
  "expected": null,
  "source": "pipeline/main",
  "build_number": 123,
  "occurred_at": "2026-10-19T00:00:00Z",
  "completeness": "complete",
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": []
  }
}
```

Omitted `expected`, or `expected: "current"`, creates a missing version or updates
its current baseline. Explicit `expected: null` is create-only; an explicit SHA
requires that exact state. Receipt identity retains the selector while publication
uses the captured actual head. `source` authority and monotonic build ordering prevent an unrelated
pipeline or older build from silently replacing the baseline. Optional
`predecessor` branches a new version from an existing product state.
Optional collection context records source revision, target/platform, subject
bindings, producer methods, limitations and separately declared coverage.
Missing coverage remains unknown; `complete` means replacement within that scope,
not independent verification that the producer discovered the entire product.

For byte-exact intake, send multipart `file` and JSON `metadata` to `/files`;
metadata contains the import fields without `sbom`. Supported semantic formats
include CycloneDX JSON/XML and SPDX 2.3 JSON. Parser losses and relationship kinds
remain visible; containment does not silently become a dependency edge.
Constituent intake does not advance the product until explicit assembly.

`POST /projects/resolve` accepts `{"project": "ID or exact name", "workspace_id": "optional owner ID"}`.
Existing IDs take precedence; ambiguous names require an ID or owner workspace.
Missing names are created in the specified writable workspace, or the sole writable
workspace if unambiguous. Project-restricted credentials cannot create products.
The response includes `id`, `name`, `workspace_id` and `created`. The CLI resolves
before uploading, then uses the returned ID. Resolution is a separate committed
operation: rejected uploads may leave an empty product but publish no invalid version.

## Assessment, review and scoring

An assessment names explicit targets (`version`, `context_id`, `vulnerability_id`),
current `expected_versions`, its prior `expected_revision` or null, applicability,
rationale and evidence. `not_affected` requires an explicit `justification`;
other states omit it. Submitted revisions remain immutable.

Optional `ssvc` supplies the exact model/version/hash, explicit answers, rationale
and optional declared evidence. The backend evaluates the pinned model itself;
clients cannot choose an outcome. Incomplete answers are draft-only. Approval
references the exact assessment revision and requires an independent authorized
reviewer for the owning team/context.

Manual scoring supplies exact targets/heads, an original `base_vector`, contextual
`vector` and rationale. Publication additionally supplies its preview digest.
Every original Base metric remains unchanged. All required contexts for the
vulnerability must currently be independently approved before publication.

Rule requests additionally pin `expected_policy` and choose `rule_basis`
(`applicability` or explicit `false_positive`). Applicability comes exclusively
from approved assessments; selected targets must agree. False-positive rules
require approved not-affected status. Rule publication atomically checks the
policy and version heads and retains complete configuration/assessment provenance.
Policy edits do not rewrite prior scores or tags. SSVC, imported proposals and
source severity never create automatic approvals or contextual score publication.

## Providers and retained documentation

Sources produce attributed facts, not DTVP approval. Native jobs implement bound
DT intake, Agentyzer analysis, OSV matching, known-ID advisory enrichment and
synchronization proposals. API/worker configuration must enable the provider.
Retries and cancellation use their explicit scoped resource; generic legacy job
enqueue/retry endpoints are absent. Retained old jobs are never executed.

Known-ID providers include NVD, CIRCL, EUVD and JVN with different supported
identifiers. JVN CVE keyword matching is unsupported; unsupported coverage is
reported rather than silently counted as checked. Empty match/not-found results
do not establish absence, remediation or not-affected status.

DT imports preserve prior DTVP team/state/author/reviewer/date documentation,
contextual scoring and SSVC claims with original text. Plain documentation without
metadata is accepted; absent applicability/identity remains unknown. Source claims
never overwrite a native decision or manufacture reviewers/approval.

Explicit migration resources under `/migration/v2` and `/migration/v1-archive`
read retained historical snapshots or reviewed sanitized single-version exports.
Their names identify source formats. No old finding/release/snapshot runtime is
available, and imported historical approvals remain evidence only.

## Scope and assurance

Inputs and responses are bounded per resource; use the schema and native reference
for exact limits. Original raw files/responses and normalized facts retain separate
provenance. All downloads require current project access and a retained-state pin.
Mirrors are not independent corroboration; signature/META consistency does not
establish producer completeness. Human review remains explicit and attributable.
