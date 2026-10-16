# API and adapter contract

The executable schema is `/openapi.json`. Native journal workflows use `/api/v3`;
the [README](../README.md#ground-up-redesign) is the current native API guide.
The resource table and ingestion examples below describe `/api/v2` compatibility
contracts. With `DTVP_LEGACY_REVIEW_ENABLED=false`, compatibility review routes
are unavailable; shared identity/catalog/job services retain their existing paths.
Machine access uses `Authorization: Bearer TOKEN`. Cookie mutations require
`X-CSRF-Token` and a matching browser Origin. Credentials are hashed, expiring,
revocable and scoped; membership/sharing is rechecked for every read/write/job.
Unauthorized resource IDs return 404. Administrative rights alone cannot approve.

## Main resources

| Resource | Behavior |
| :--- | :--- |
| `/workspaces`, `/workspaces/{id}/members` | Explicit issuer/subject/role mappings |
| `/projects`, `/projects/{id}/sharing` | Owner workspace and explicit capability grants |
| `/projects/{id}/releases` | Product release identity |
| `/releases/{id}/components`, `/components/{id}/metadata` | Complete scoped inventory and optimistic curated metadata |
| `/releases/{id}/dependencies`, `/revisions/{id}/artifact` | Exact source graphs and verified original files |
| `/releases/{id}/metadata`, `/attachments` | Owned deployment context and opaque TM7/evidence/attestation files |
| `/releases/{id}/ingestions`, `/uploads` | Shared pipeline JSON-envelope and file import |
| `/findings`, `/findings/{id}` | Cursor summary pages and full evidence/history |
| `/findings/{id}/decisions`, `/approvals` | Version-checked submission, independent approval or change request |
| `/approvals/preview`, `/approvals/apply` | Revision-bound atomic bulk approval |
| `/statistics` | Full authorized state, severity, owning-team, component-owner and project counts |
| `/findings/{id}/rescoring/preview`, `/rescoring/proposals` | Revision-bound CVSS previews and eligible provider proposals |
| `/projects/{id}/rescore-policy`, `/cvss/metrics/{version}` | Versioned rules and calculator metadata |
| `/findings/{id}/evidence` | Immutable attributed advisory/match/context evidence |
| `/snapshots` and snapshot subresources | Immutable consumer bundle, SBOM, worklist, reviewed VEX and coverage |
| `/providers`, `/jobs` | Configured read-only matching/enrichment/import operations; explicit retry/cancel |
| `/credentials`, `/projects/{id}/audit` | Scoped machine access and append-only action history |

## Pipeline envelope

```json
{
  "schema_version": "dtvp.ingestion/1",
  "source": "pipeline:my-ci",
  "event_id": "job-123:sbom",
  "occurred_at": "2026-10-14T00:00:00Z",
  "completeness": "complete",
  "context": {"provider": "my-ci", "run_id": "123", "commit": "abc", "branch": "main"},
  "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
}
```

Submit to `/releases/{id}/ingestions`. Same source/event/content is idempotent;
reuse with different content returns 409. Older events remain history and cannot
overwrite newer source results. Partial snapshots preserve prior coverage.
Format/parser revisions and provider fields remain in the immutable source document.

Administrators bind each DTVP product to its DT project through
`PUT /projects/{id}/connectors/dependency-track`. Import jobs cannot use the
shared source credential to fetch an arbitrary unbound project.

## Provider boundaries

`Matcher.query(purl)` returns matching assertions and checked/unsupported coverage.
`AdvisoryProvider.get(identifier)` returns attributed advisory records, never a
component affectedness decision. Register implementations separately in
`dtvp/providers.py` and enable outbound providers through deployment configuration.
Transport is bounded, timed and rejects redirects. Durable leases are renewed
between requests; publication is atomic and rejects changed release inventory.

OSV cannot supply trustworthy variant matching for qualified PURLs in this adapter;
those remain unsupported. NVD/CIRCL records preserve upstream content. Use
`dtvp.evidence/1` to import other official/vendor advisory evidence while a native
feed adapter is being verified. Native `/api/v3` known-ID enrichment now includes
EUVD (exact CVE/EUVD) and MyJVN (exact JVNDB); unsupported IDs remain explicit.
These adapters do not establish package matching or automatic assessment approval.
Optional journal-pinned known-ID schedules use the native advisory-schedule API;
manual and scheduled jobs share durable provider pacing. See the README for bounds.

Job failures retain unknown coverage and require explicit retry. A successful
empty match response never records `not_affected`. No import, job or approval
writes to the source. Consumer exports are explicit local downloads.

## Bounds and concurrency

Requests/uploads default to 32 MiB, metadata/evidence to 64 KiB. Summary/component
pages are bounded; lifecycle filtering uses a bounded scan and may return an empty
page with a continuation cursor. Bulk approvals allow 100 items. All inventory and
decision mutations lock their release; stale revisions return 409. Source observations
and decisions are retained. Snapshot reads are immutable but current access is required.

## Previous DT documentation

Imports decode DTVP `[Team:]`, `[State:]`, `[Assessed By:]`, `[Reviewed By:]`,
`[Date:]`, `[Assigned:]`, `[Historical:]`, `[Copied From:]`, contextual rescoring
and SSVC records. General precedence and latest dated case-insensitive duplicate
teams are retained. SSVC JSON is isolated from tag scanning. Plain text with
no metadata is valid: explicit DT applicability is retained; prose without an
applicability stays documented with unknown state. Missing authors/reviewers
are never invented.

The finding detail/snapshot exposes `imported_assessments`; list rows distinguish
legacy assessed, pending, conflicting and documented states. Original analysis
and comments remain intact. DT polling retrieves the full occurrence analysis,
not only the abbreviated finding status. New DTVP decisions take precedence;
source imports cannot overwrite them or create new DTVP approvals.

### Searchable catalogs and review queues

`GET /catalog/projects?q=&workspace_id=&cursor=&limit=` returns bounded
`items` with team name, release count and active-finding count.
`GET /catalog/projects/{id}/releases?q=&cursor=&limit=` searches release versions, newest first.
`GET /projects/{id}` resolves a selected product without loading every product.
Original array endpoints remain available for existing consumers.

`GET /findings` additionally accepts `project_id`, `workspace_id`, `owner` and
`sort=id|identifier|component|project`. Text search includes project, release,
component, PURL and vulnerability ID. Non-ID sort cursors are tied to the current
filters; changing filters requires restarting pagination. Lifecycle filtering
retains bounded scans: an empty batch may still have a next cursor.
Component pages accept `q` for name/version/PURL search. Finding rows include
`latest_decision` for independent bulk-approval selection. Duplicate findings in
a selection are rejected. Authorization is applied
before catalog pagination and counts; saved browser views never grant access.

Agentyzer analysis submission/history/report endpoints and their eligibility and
restart semantics are documented in [external analysis integration](agentyzer.md).

Statistics scopes, score ordering, preview/adoption and policy contracts are detailed
in [statistics and rescoring](statistics-rescoring.md). Component-owner filters support
`owner_match=contains|exact`; finding ordering supports `original_score` and
`effective_score`, highest first.

New `not_affected` decisions require the top-level `justification` field: a
CycloneDX justification code or `other` (with the explanation in `rationale`).
Other states must omit it. The server stores it in immutable decision details;
`details.justification` cannot bypass validation. Reviewed VEX uses CycloneDX
analysis states and includes standard justification codes; `other` remains in the
snapshot and its explanation is exported as analysis detail.
