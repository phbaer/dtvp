# Native statistics and contextual decisions

All paths below use the release's `API_PREFIX`, currently `/api/v1`, configured
once in `dtvp/api_contract.py`. The retired SQL-finding/Review runtime and its
statistics, review-team and rescoring endpoints are unavailable.

## Reviewer workspace and statistics

`GET /projects/{id}/versions/{version}/workspace` returns contextual findings,
attributed source facts, descriptions, dependency/ownership evidence, current
assessment and independently approved pins, SSVC, external proposals and published
contextual scores. A dependency used by distinct consuming roots has distinct
review targets. Recursive ownership stops at another team's owned component;
namespace and case-sensitive v1 selectors remain supported. Ownership policy and
source imports are versioned; current reassignment does not rewrite past reviews.

`GET /projects/{id}/portfolio` compares selected current version heads, grouped by
version and responsible team. `GET /portfolio` provides an authorized organization
view. Counts distinguish unique vulnerability IDs, logical assessments/revisions,
recorded targets, reviewed coverage and remaining contextual review workload.
One shared assessment can cover several explicit targets without reducing their
required review count. Overlapping team counts are labeled; source findings
without usable context and retained absent assessments remain diagnostics.

Workspace/portfolio filtering occurs before counting and pagination. Filters
include source/published severity, applicability, scoring status, team assessment,
provider, CVSS version, dependency relation, source discrepancy, component,
criticality, exposure, support/annotation status and specialist evidence. SSVC
status/action filters distinguish provisional from approved priorities. Project
portfolio responses pin selected heads with `heads_digest`; pass `expected_heads`
to detect changed selections. Counts represent recorded evidence and decisions,
not proof that producer SBOMs or vulnerability discovery are complete.

## Assessment and independent review

- `POST /projects/{id}/assessments/{assessment_id}/draft` saves a scoped draft.
- `POST /projects/{id}/assessments/{assessment_id}/submit` submits exact targets,
  applicability, justification, rationale, conditions and evidence.
- `POST /projects/{id}/reviews` approves or requests changes against an exact
  assessment revision and current expected version heads.

Native `AssessmentInput` and `ReviewInput` reject unknown fields. Team permissions,
matching scope/material and independent author/reviewer identity are checked on
the server. Not-affected submission requires an explicit justification. New drafts
retain approved history; material changes require revalidation. Analysts assess
applicability; they do not publish contextual CVSS scores.

Optional SSVC is evaluated from the pinned local model returned by
`GET /ssvc/models`. The assessment supplies model/version/hash, explicit answers,
rationale and optional evidence references/descriptions. DTVP derives the outcome;
clients cannot supply it. Incomplete SSVC can be drafted, never submitted. The same
independent team review approves the exact SSVC assessment revision. Workspace
`ssvc.current`, `approved`, `pending` and `status` expose changes without replacing
a retained approved priority. Imported legacy SSVC remains source evidence.
SSVC does not publish a CVSS score, and references do not establish independent
verification of external exploitation evidence.

## Coordinator scoring

The `coordinator` role grants `rescore`; ordinary analyst/reviewer/admin roles do
not. Cross-team coordinators require explicit project sharing, and machine tokens
remain limited by current membership and token scope.

- `GET /cvss/metrics/{version}` returns specification labels/values for the metric
  editor. CVSS 2.0, 3.0, 3.1 and 4.0 are supported.
- `GET|PUT /projects/{id}/scoring-policy` reads/replaces the pinned project rules;
  replacement requires manage permission, request ID and `expected_policy`.
- `POST /projects/{id}/scoring/preview` calculates a supplied contextual vector.
- `POST /projects/{id}/scoring/publish` explicitly publishes its preview digest.
- `POST /projects/{id}/scoring/rules/preview|publish` derives the vector from
  approved applicability and the exact pinned project policy.

Scoring requests include targets, exact expected version heads, original Base
vector, contextual/input vector and rationale. Rule requests additionally pin
`expected_policy` and declare `rule_basis`. Publication requires the exact preview
hash. The server rechecks current independent reviews for **every required context
of that vulnerability** in each selected version, including unresolved ownership.
It preserves every original Base metric/version and rejects malformed/duplicate
metrics, Base changes and inconsistent source scores. Workspace
`original_base_vectors` contains validated choices; raw source ratings remain
visible separately. A lower score does not establish non-applicability.

`rule_basis=false_positive` is an explicit coordinator interpretation under approved
not-affected applicability; it is not an independently approved false-positive
classification. Immutable publications retain the actual policy configuration,
input vector, triggering applicability and approved assessment provenance. Policy
edits do not rewrite existing publications. Changed review/material coverage makes
previous contextual publication outdated; source facts remain intact.

External VScorer/Agentyzer proposals remain attributed evidence with explicit
eligibility and stale/withheld diagnostics. Selecting a proposal fills coordinator
inputs; it never approves an assessment or publishes automatically. Current default
Agentyzer lacks qualified checkout proof and remains ineligible for contextual
application/scoring. See [consumer contracts](consumers.md).

## UI, CLI and local scenarios

The native queue shows source and published severity together. Detail tabs guide
evidence, assessment, independent review and coordinator scoring. Metric controls
hide advanced vectors by default; power-user provenance remains available. CLI
`knowledge workspace` and `portfolio` use the same filters/read models; `score
policy|preview|publish`, `assessment draft|submit` and `review` forward exact JSON
requests. Pins and answers are never guessed locally.

Playground startup creates identities/workspaces only. Load editable synthetic data
explicitly using `knowledge --persona administrator demo load --file
playground/scenarios/workflow.json` (or `specialists.json`). Repeating the same
fixture preserves interactive work. Simulated reviews are labeled synthetic and
never qualify real deployments or human approval.
