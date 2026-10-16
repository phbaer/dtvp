# External Agentyzer integration

Agentyzer stays in `../agentyzer`, with separate deployment, dependencies and
releases. DTVP uses its existing HTTP contract: `POST /assess`,
`GET /jobs/{id}`, `GET /jobs/{id}/result`, and
`POST /jobs/{id}/follow-up`. No analyzer source is bundled.

Configure API and worker with `DTVP_AGENTYZER_ENABLED=true`,
`DTVP_AGENTYZER_URL` and, optionally, `DTVP_AGENTYZER_TOKEN` for your gateway.
The URL is deployment-controlled; users cannot submit arbitrary destinations.
The optional bearer credential assumes gateway authentication; it does not add
authentication to Agentyzer itself. Observation timeout defaults to one hour.

A product administrator sets `PUT /api/v2/projects/{id}/connectors/agentyzer`
with `{"component_name":"logical-repository-name"}`. This name resolves through
Agentyzer's repository configuration. Analysts cannot select another product's
repository mapping. Deployment endpoint/token configuration remains server-side.

For external proposal eligibility, SBOM import `context.analysis_source` must
contain `repository_name` matching that connector and a full 40-hex `source_commit`.
All current occurrence observations must agree. Generic product commit metadata
does not identify an analyzer repository. DTVP sends the qualified commit and
requires returned `source_input.binding: verified_git_commit` with matching
requested/resolved commits. Changing this import context invalidates earlier
evidence. Missing or conflicting bindings remain visible, ineligible evidence.
These checks establish consistency with the service-reported checkout; they do not independently verify source authenticity, delivered binaries, submodules or LFS.

`POST /api/v2/findings/{id}/analyses` accepts `expected_version`, optional
`guidance`, and optional `parent_job_id` plus `question` for a follow-up.
DTVP sends the vulnerability ID, bound repository name, project/release hints,
and guidance using repository scope. Pending identical requests are deduplicated.
Completed parent runs must still match current evidence and repository binding.

`GET /api/v2/findings/{id}/analyses` returns newest-first cursor pages.
`GET /api/v2/analyses/{job_id}/report` retrieves the immutable full report with
current authorization. Collection can be cancelled using the existing job API;
this prevents publication, but does not terminate or delete an external run.
Generic job retry is intentionally unavailable for analyses: reload the finding
and explicitly submit against current evidence.

Worker polling checkpoints the remote ID. An expired lease resumes polling;
if a crash leaves submission outcome uncertain, DTVP fails the observation
without sending another POST. No implicit remote retry or deletion occurs.
Agentyzer currently keeps its jobs in memory: a service restart can invalidate
remote IDs, including follow-up parents. Already imported DTVP reports survive.

DTVP preserves complete reports plus a compact evidence summary, exact occurrence
coordinates and input evidence revision. Proposal eligibility requires a literal
`application_eligible=true`, verified qualified source binding, an exact package
name and detected-version match,
and consistent affectedness/analysis state. `not_affected` also requires literal
`code_coverage.permits_exclusion=true`. Missing fields, mismatches and incomplete
coverage remain evidence without an applicable proposal. Current proposals only
fill the user's draft on explicit action. Submission and independent approval
remain separate. Original scores and manual decisions are never overwritten.
Adjusted scores remain in the report. Eligible native runs may supply a contextual
score proposal through the rescoring API. DTVP correlates the immutable report,
job and occurrence, validates the vector against original Base facts, and requires
an explicit preview, submission and independent approval. No automatic copying
occurs.

The playground explicitly labels its source binding synthetic and unverified;
its eligible scenarios are an offline workflow exception. It runs deterministic
eligible, inconclusive and failed scenarios
through the same durable workflow without external calls. Contract tests cover
submission, restart/poll recovery, follow-ups, cancellation during completion,
revoked credentials, stale evidence, scope isolation and strict proposal gates.
Live model execution is deployment-specific and is not part of offline tests.

## Native unknown-submission reconciliation

Opted-in new native jobs privately bind the actual submitted request to their exact issued
DTVP input using a unique 256-bit nonce and canonical SHA-256 digests. The private
field is transmitted only to Agentyzer and retained in operational SQL; it is never
a public job DTO, report, log or exported artifact. Existing unknown jobs without
the original private binding remain unreconcilable; no proof is invented later.

Deploy the additive Agentyzer `GET /jobs/{id}/dtvp-binding` contract and configure
its `AGENTYZER_RECONCILIATION_TOKEN` to the same random secret as DTVP's server-owned
`DTVP_AGENTYZER_TOKEN` (at least 32 printable ASCII non-space characters). Its
independent Bearer check protects that endpoint only; legacy API access still
needs the deployment gateway. Empty/invalid tokens cannot enable reconciliation.

The original requesting actor explicitly posts `request_id` and `remote_id` to
`POST /api/v3/projects/{id}/analysis-jobs/{job}/reconcile`. Current read/snapshot/
evidence permissions, current credential, configured endpoint/repository, material
source pins and a SQL lease are checked before authenticated GET and again before
attachment. Only completed jobs with exact request, issued-input/private binding
and service-reported requested/resolved Git commit equality are accepted. Unknown
commits, other repositories/CVEs/versions/scopes, legacy proof, cancellation, changed
credentials, stale source or lost leases leave the local submission unresolved.

The exact authenticated public request/report is checkpointed before import and
reused by the existing native evidence importer. Public polling cannot substitute
a different report after verification. There is no analysis POST, automatic search,
new assessment, approval or score publication. GET failures can be retried explicitly
with the same frozen ID/body; up to 100 distinct request identities per local job
are retained to prevent rebinding an older request ID to another remote ID.

The private proof itself is not archived because it contains the nonce. DTVP
retains a sanitized transport-observation summary and proof/response hashes inside
the public report envelope, explicitly labeled configured-service request
association and receipt consistency. This is not provider/source/binary authenticity
or an archived cryptographic attestation. Unexpected private fields or the known
nonce in public data are rejected before storage; remote errors are returned
generically. Full operational SQL backup is necessary to recover local nonces.
Agentyzer restart may still lose the remote job and proof.

The native jobs panel exposes explicit completed-remote-ID verification only when
backend capabilities permit it. Failed/uncertain verification retains the exact
remote ID and request UUID; discard is explicit. Local cancellation can stop an
unknown job but does not assert remote cancellation or authorize another POST.

Reconciliation is explicitly opt-in: set
`DTVP_AGENTYZER_RECONCILIATION_ENABLED=true` only with the extended Agentyzer
contract. Default false preserves the previous POST body, even when an existing
service token is long enough. Only newly enqueued opted-in jobs get a private
binding; enabling the feature never upgrades an existing unknown job. Disabling
it blocks reconciliation without rewriting already captured request identities.

## Native bound follow-ups

With the private reconciliation extension enabled, a completed native analysis
can start a separate child through
`POST /api/v3/projects/{id}/versions/{version}/analysis-jobs/{parent}/follow-up`.
Supply a new `request_id`, current `expected` state, exact retained
`parent_report_sha256`, meaningful `question` and optional `user_guidance`.
Current read/snapshot/evidence authorization applies to the child actor; the
parent author is preserved and grants no authorization. Repository, vulnerability,
versions, context and qualified Git commit cannot be overridden.

The configured service must support authenticated `dtvp-follow-up-parent` and
`dtvp-follow-up-binding` GET endpoints. Exact parent report/request/scope/private
association hashes are checked before SQL enqueue, again before POST, and
atomically by Agentyzer when creating the child. Unsupported services enqueue
nothing. The child retains its parent's original issued input receipt and gets
its own private correlation. The analyst's exact wire question and the service's
compiled effective request remain distinct and are both verified. Private proofs
and nonces stay out of public views and the journal.

A durable marker precedes POST. An uncertain POST is never repeated automatically;
explicit authenticated reconciliation can attach its exact completed child.
Completed evidence can survive later source changes as stale evidence, without
human assessment, approval or score publication. Parent job age does not expire
retained evidence; child credentials and timeout are checked independently.
Agentyzer's in-memory parent must still exist: this does not repair lost remote
jobs or make source identity equivalent to analysis completeness.

The generic authenticated CLI submits the identical API body (no separate
follow-up policy). Create `follow-up.json` containing `request_id`, `expected`,
`parent_report_sha256`, `question` and optional `user_guidance`, then run:

```bash
uv run dtvp knowledge request POST \
  /api/v3/projects/PRODUCT/versions/7.1.1/analysis-jobs/PARENT_JOB/follow-up \
  --body follow-up.json
```

Use the returned child ID with the existing analysis-jobs API. Repeating the
same request ID and exact body returns the same child; changing its body requires
a new explicit request identity.
