# Statistics and contextual scores

`GET /api/v2/statistics` accepts the Review scope: `project_id`, `release_id`,
`workspace_id`, `owner`, `owner_match=contains|exact`, `q` and `lifecycle`. Counts cover every active finding
matching the authorized scope; pagination affects only `project_page`.
`project_cursor`/`project_limit` paginate its alphabetically sorted project rows.
Owning teams are project workspaces. Component owners are separate responsibility
metadata; `owner=Unassigned` selects missing/empty owner values. Shared grants
never multiply counts. Unknown severity and legacy decisions remain separate.

The response includes occurrence and unique-ID totals, lifecycle/applicability,
original/effective severity, per-team and per-owner states, consistency of unique
IDs, changed evidence and coverage diagnostics. Different occurrences of one ID
can be incomplete or inconsistent. Unique IDs do not imply resolved advisory
alias equivalence. PostgreSQL authorization and aggregation run under one
repeatable-read, read-only transaction. Score sorting and statistics derive
current review facts from DTVP storage; no DT request or source cache is used.

## Coordinator scoring API

Only workspace role `coordinator` grants `rescore`; analyst, reviewer and admin
roles do not. Cross-team coordinators need explicit project `rescore` sharing;
machine credentials remain restricted by current membership and token scope.

Required review teams default to the project's owning workspace. Administrators
can `GET /findings/{id}/review-teams` for eligible teams and `PUT` with
`expected_version` and a nonempty `workspace_ids` list. Additional teams require
read, assess and approve grants. Changing assignments reopens evidence review.
Revoked review access blocks completion and invalidates existing scores.
Decision submission accepts optional `workspace_id`; approvals require a reviewer
in that decision's team, a current latest team assessment and a different author.
Finding details include `review_coverage`, each team's current status and decision,
`review_workspace_id`, `review_lifecycle`, and the actor's `latest_decision`.
`GET /findings/{id}?workspace_id=...` selects an authorized review team.
Aggregate lifecycle is approved only when every required team has approved.

- `GET /cvss/metrics/{version}` supplies specification metric labels and values.
- `GET /projects/{id}/rescore-policy` supplies current project rules, version,
  digest and v1 defaults. Version zero denotes the shipped default template.
- `PUT /projects/{id}/rescore-policy` requires manage permission and
  `expected_version`. It validates the rule structure, metric values and Base
  invariants. Changed policies invalidate rule scores and previews; team approvals remain valid.
- `GET /findings/{id}/rescoring/proposals` returns current provider proposals,
  original vectors and the policy digest. Ineligible results include reasons.
- `POST /findings/{id}/rescoring/preview` accepts `expected_version`, applicability
  optional `state` and `rescoring`. All current team approvals and `rescore` permission
  are required. If supplied, state must equal consolidated team applicability. Its response includes the calculated proposal and
  `preview_digest` bound to the occurrence, state version, applicability and
  scoring proposal.
- `POST /findings/{id}/rescoring` publishes the previewed score with `expected_version`
  and `rescoring.preview_digest`. The server rechecks every team approval under
  the release lock. Any relevant change requires a fresh preview. Analyst decisions
  reject both `rescoring` and the generic `details.rescoring` extension.

A rescoring request includes `kind=manual|rule|evidence` and a rationale. Manual
requests supply `base_vector` and contextual `vector`; rules supply the Base and
current `policy_digest`; evidence requests supply an occurrence-bound
`evidence_id`. The false-positive rule basis remains available under
`not_affected` applicability using `rule_basis=false_positive`. Rule transforms
retain optional input metrics not explicitly overridden by the rule and freeze
the actual rule configuration in the immutable scoring record for audit and snapshot export.

The calculator validates CVSS 2.0, 3.0, 3.1 and 4.0. It preserves every Base
metric and version, rejects malformed/duplicate metrics, and calculates scores
on the server. Custom rules cannot redefine specification Base metrics. A lower
contextual score never establishes non-applicability. Source facts remain intact.

VScorer proposals require a matching source snapshot, exact Base assertion,
Environmental vector and consistent numeric score. Native Agentyzer proposals
also require explicit eligibility, verified package/version and an exact link
between the owned job, evidence and immutable report. Earlier evidence without
revision bindings remains readable but requires a new assessment for adoption.
Missing vectors, Base changes, mismatched scores and stale results are ineligible.

Only an explicitly published coordinator score bound to all current required
team approvals exposes `adopted_rescoring` and changes `effective_score`/`effective_vector`. Unpublished or stale proposals keep
original severity effective. Those fields appear in detail, list and immutable
consumer snapshots. `sort=original_score|effective_score` orders the full scoped
queue highest-first, with stable ID ties and filter-bound cursors. Score ordering
uses bounded batch reads followed by server-side ordering; it is intentionally
not limited to the first cursor batch. Future measured scale work can add a
relational projection without changing this API.

## Review and playground

The default workspace shows evidence and applicability side by side. Reviewers
check their team's rationale and justification. Teams & scoring shows required
team progress, admin assignment controls, coordinator calculation/publication and
immutable scoring history. Scoring never writes back to imported providers.

The offline playground includes Security coordinator and Operations reviewer.
**Load large inventory** adds 100 projects with 20 findings each. Tests retain
all CVSS versions, Base preservation, preview changes, stale sources, policy
edits, frozen exports and severity ordering, plus coordinator permissions,
independent team approvals and the per-vulnerability completion gate.
