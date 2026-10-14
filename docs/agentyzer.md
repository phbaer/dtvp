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
`application_eligible=true`, an exact package name and detected-version match,
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

The playground runs deterministic eligible, inconclusive and failed scenarios
through the same durable workflow without external calls. Contract tests cover
submission, restart/poll recovery, follow-ups, cancellation during completion,
revoked credentials, stale evidence, scope isolation and strict proposal gates.
Live model execution is deployment-specific and is not part of offline tests.
