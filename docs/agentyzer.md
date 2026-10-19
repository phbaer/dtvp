# External Agentyzer integration

Agentyzer is a separately deployed service in `../agentyzer`; no analyzer source,
dependencies or runtime are bundled. All DTVP paths below use `API_PREFIX`, currently
`/api/v1`, from `dtvp/api_contract.py`. Upstream Agentyzer routes are its own
contract, not DTVP API versions.

Configure API/worker with `DTVP_AGENTYZER_ENABLED=true`, deployment-controlled
`DTVP_AGENTYZER_URL` and optional `DTVP_AGENTYZER_TOKEN` for the gateway. The bearer
credential does not itself add authentication to Agentyzer. Users cannot select
arbitrary destinations. Observation timeout defaults to one hour.

A product manager sets `PUT /api/v1/projects/{id}/connectors/agentyzer` with
`{"component_name":"logical-repository-name"}`. This resolves through the service's
repository configuration. Source import `context.analysis_source` must separately
identify that repository and a full 40-hex `source_commit`. All relevant current
observations must agree; a generic product commit is insufficient.

## Native inputs, jobs and retained results

- `POST /api/v1/projects/{id}/states/{state}/agentyzer-input` prepares a contextual
  request/receipt pinned to component, vulnerability, repository and source commit.
- `POST /api/v1/projects/{id}/versions/{version}/analysis-jobs` submits an explicit
  request with `request_id`, current `expected` state, `context_id`,
  `vulnerability_id` and optional `user_guidance`.
- `GET .../versions/{version}/analysis-jobs` lists bounded local jobs;
  `GET .../analysis-jobs/{job}` returns one authorized operational status.
- Explicit `/cancel` stops local collection/publication, not the external run.
  `/retry` is capability/status dependent and never blindly repeats an unknown POST.
- `POST .../versions/{version}/proposals/agentyzer` retains an external result with
  its exact DTVP input receipt. `GET .../states/{state}/proposals/agentyzer/{result}/report`
  retrieves the retained full report under current project authorization.

Workers checkpoint remote IDs and exact requests/results in operational SQL;
knowledge evidence is retained in the journal. Expired leases resume safe polling.
An uncertain POST becomes `submission_unknown` and is never automatically repeated.
Upstream jobs may be memory-only: restart can lose remote IDs, while already
retained DTVP reports survive. Full operational backup remains necessary for job
credentials/private correlation; journal recovery alone restores knowledge evidence.

The inspected default Agentyzer `8ff8372` supports `/assess`, `/jobs/{id}`,
`/jobs/{id}/result` and `/jobs/{id}/follow-up`, but lacks the required qualified
checkout-commit proof. Source-pinned offline mocks retain these reports with explicit
diagnostics; they do **not** establish deployable compatibility with every extended
workflow. Missing bindings are never fabricated. An unqualified result remains
readable and cannot establish contextual applicability, an exclusion or a lower score.

Qualified results require consistent issued input, exact repository/requested/resolved
commit, component/version/CVE and analysis coverage. Not-affected proposals require
explicit exclusion-permitting coverage. These checks establish reported input/result
consistency, not source/binary authenticity or analysis completeness. Optional scoring
vectors must preserve the occurrence's validated source Base and reproduce its score.
Proposal selection, scoped human assessment, independent review and coordinator
preview/publication remain separate. Imported results never approve themselves.

The optional extensions below require a compatible qualified deployment; they are
not silently enabled for the current default. The playground retains explicit mock
reports and simulated personas, with no exception granting unqualified results
real approval or lowering eligibility.

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
`POST /api/v1/projects/{id}/analysis-jobs/{job}/reconcile`. Current read/snapshot/
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
`POST /api/v1/projects/{id}/versions/{version}/analysis-jobs/{parent}/follow-up`.
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
  /api/v1/projects/PRODUCT/versions/7.1.1/analysis-jobs/PARENT_JOB/follow-up \
  --body follow-up.json
```

Use the returned child ID with the existing analysis-jobs API. Repeating the
same request ID and exact body returns the same child; changing its body requires
a new explicit request identity.
