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
