# DTVP

DTVP owns SBOM inventory, component metadata, security evidence, assessments and
approvals. Dependency-Track, CyBeats exports and pipeline files are sources.
Generator and VScorer remain separate applications consuming immutable snapshots.
Agentyzer lives in the separate `../agentyzer` repository. DTVP owns imported
analysis evidence; Agentyzer owns its source, dependencies, tests and deployment.

FastAPI + Vue · PostgreSQL/JSONB · local immutable artifacts · no S3 or broker.

## Try it locally

Requirements: Docker Compose and `uv`. One command builds the real application,
starts PostgreSQL, applies migrations and loads synthetic data:

```bash
uv run python scripts/playground.py up
```

Open **http://127.0.0.1:8900** in WSL or Windows; WSL forwards localhost ports
automatically. The playground binds to loopback and contains synthetic data.
If Windows has reserved that port, choose a free `DTVP_PLAYGROUND_PORT` when
starting the playground and open that port instead. Windows reservations are
listed by `netsh interface ipv4 show excludedportrange protocol=tcp`.

Select Platform analyst, submit an assessment, then
switch to Platform reviewer to approve. Operations has a separate private product.
Products accepts CycloneDX/SPDX uploads and creates Generator/VScorer snapshots.
Replay changed evidence, conflicting sources and partial scans from the banner.
The offline demo matcher and simulated failure run through the durable worker.
System, light and dark themes and expandable technical evidence are available.
The review workspace places readable evidence beside the assessment and approval
controls. Analysis and full history have separate tabs; technical vectors stay
collapsed by default. Review dialogs retain keyboard focus, close with Escape
and return to the selected finding.
Searchable product/release selectors fetch bounded pages; releases show newest first. Browse products by name
and team, with release and active-finding counts. Review filters cover product,
team, component owner, status and text; sorting is stable across cursor pages.
Filter URLs are shareable; saved views are browser-local and scoped to the user.
Next/previous finding navigation and submit/approve-and-next actions retain queue
context and assessment drafts, including when completion removes an item from
the active status filter.
Reviewers can select up to 100 ready decisions, inspect their scope/rationale in
a bulk preview and explicitly approve the selection. Self-authored or changed
decisions are excluded; concurrent changes block the entire approval batch.
Administrators can replay **Load large inventory**: 100 projects × 20 findings.
It adds synthetic data without replacing existing projects; reset removes it.

```bash
uv run python scripts/playground.py down   # retains data
uv run python scripts/playground.py reset  # resets only playground volumes
uv run python scripts/playground.py logs
```

Set `DTVP_PLAYGROUND_PORT` to change the port. After the initial image build,
`up --skip-build` works offline. Production `.env` is not read by Compose here.
Uploads/edits remain interactive; test fixtures live in `playground/fixtures/`.

If your build network requires a private CA, keep TLS verification enabled:

```bash
docker build --secret id=build_ca,src=/path/to/trusted-ca.pem -t dtvp:rewrite .
uv run python scripts/playground.py up --skip-build
```

## Review and ownership

- Source revisions and original files are immutable. Reimports preserve curated metadata and decisions.
- Package coordinates, qualifiers, hashes and source refs establish identity; names alone do not.
- Each component occurrence has its own finding and decision history. Partial/failed scans cannot imply a clean result.
- Previous DTVP tags and plain DT documentation without metadata are imported, including team history, pending review, suppression, SSVC and contextual rescoring. Original text is retained; missing authors stay unknown.
- Decisions and independent approvals bind to the current evidence revision. Changed evidence requires revalidation.
- Team membership and explicit project sharing control access. Ownership metadata describes responsibility.
- Viewer, analyst, reviewer and administrator permissions are explicit; administration does not imply approval.
- No source receives automatic writes. SBOM, reviewed VEX and consumer exports are explicit downloads.

## API and consumers

The API is `/api/v2`; schema: `/openapi.json`; readiness: `/readyz`.
Browser access uses server-side sessions and request tokens. OIDC maps verified
issuer/subject identities to memberships. Administrators issue expiring, revocable,
workspace/project-scoped machine credentials; tokens are returned only once.

`POST /snapshots` freezes a release. Its manifest, bundle, paginated findings,
SBOM and VScorer worklist retain the same revision and hashes. Consumer reads
always recheck current authorization, including after sharing is revoked.

The separate Generator integration is on `feat/dtvp-snapshot-consumer`, initially
in `/tmp/dtvp-generator-consumer`; the existing `../generator` checkout is untouched.
It adds a native DTVP source to the existing CLI/API generation path, verifies
snapshot integrity and preserves occurrence-specific approved decisions without
DT fallback. See [consumer integration](docs/consumers.md).

VScorer accepts the exported SBOM/worklist through its existing intake. Returned
contextual evidence must identify the snapshot, finding, exact refs and original
Base vector. DTVP approval remains separate; lower severity never proves unaffectedness.

## Sources and matching

CycloneDX 1.5/1.6 JSON/XML and SPDX 2.3 JSON use one versioned ingestion path.
The envelope preserves source/event IDs, timestamps, pipeline context and raw
provider data. CyBeats uses standard SBOM exports; its proprietary API requires
a verified deployment contract before adding a native connector.

The DT connector is read-only. OSV supplies optional package/version matching;
NVD and Luxembourg's CIRCL supply optional advisory enrichment. Provider requests
are disabled unless configured. Mirrors retain upstream publisher data.
Qualified PURLs unsupported by a matcher remain unknown. Successful no-match
checks are coverage observations, not applicability decisions.

ENISA EUVD, Japan's JVN and other providers can use the advisory/evidence ports;
their native feed adapters are not yet shipped. See [API and adapters](docs/api.md).
Agentyzer submission, durable polling, follow-ups and immutable report retrieval
are available from each finding. Set `DTVP_AGENTYZER_ENABLED=true` and
`DTVP_AGENTYZER_URL` on the API and worker; optionally set a gateway bearer token.
A product administrator binds its Agentyzer repository name in Products.
The playground uses the same workflow with clearly marked offline results,
incomplete coverage and simulated failures; no Agentyzer service is bundled.

Eligible, current results can be copied explicitly into an assessment draft.
DTVP requires matching package/version evidence and explicit application
eligibility; exclusion proposals also require exclusion coverage. Analysis never
submits or approves a human decision or changes the original CVSS score.
Full reports persist in local immutable artifacts; normalized evidence lives in
PostgreSQL. A changed finding, revoked credential or changed binding blocks
publication. Polling survives worker restarts. An ambiguous submission is failed
rather than replayed; start a new analysis explicitly. Cancel stops DTVP result
collection; the separate service may continue its run. See [analysis integration](docs/agentyzer.md).

## Statistics and contextual rescoring

Statistics counts the full authorized active inventory, not just the loaded
queue page. It distinguishes component/release findings from unique vulnerability
IDs, review lifecycle from applicability, and owning team workspaces from curated
component-owner labels. Shared projects are counted once. Team and state counts
open matching review queues; project rows are paginated. Statistics inherits the
review filters; Reset scope returns to all accessible data. PostgreSQL statistics
use a consistent read snapshot. Original and effective severity distributions,
legacy consistency, stale evidence and revalidation remain visible.

CVSS 2.0, 3.0, 3.1 and 4.0 contextual calculations and v1's version-aware rules
are available. Select a validated original Base vector, adjust optional metrics
or enter a vector, explain the context, and preview. Base metrics and the CVSS
version cannot change. Administrators edit project rules in Products; concurrent
policy edits are rejected and changed rules reopen dependent decisions.

Current VScorer vectors and eligible native Agentyzer results can supply explicit
rescoring proposals. Scores without a valid vector, mismatched Base assertions,
old snapshots and unverified results cannot be adopted. A contextual proposal
belongs to an occurrence and current evidence revision. It becomes effective
only with independent approval of the assessment. Changing evidence removes the
adoption until revalidation; original source scores and archived snapshots stay
unchanged. Original/effective severity sorting is available in Review. Frozen
consumer findings include the proposed/adopted score, vector, rationale and rule
configuration; VScorer worklists keep original Base inputs. See
[statistics and rescoring API](docs/statistics-rescoring.md).

## Production deployment

```bash
cp .env.example .env
# Set unique secrets, database password/URL, public URL and OIDC configuration.
docker compose up -d --build
docker compose exec api uv run --no-sync python -m dtvp.cli bootstrap \
  --issuer https://your-identity-provider.example --subject YOUR_SUBJECT --name YOUR_NAME
```

Sign in with that identity, create workspaces, and assign explicit memberships.
The supplied deployment binds to loopback; terminate HTTPS through your reverse
proxy. PostgreSQL data and local artifacts use independent persistent volumes.
An optional managed PostgreSQL service uses the same database URL contract.

Schema updates run automatically under a database lock before readiness. Existing
schema upgrades first save a sealed logical data backup. A dedicated migration
database URL is supported. PostgreSQL major upgrades use a separate dump/restore
helper creating a new cluster and retaining the old volume. See
[deployment and recovery](docs/deployment.md).

## Development and verification

Use `uv` from the repository root, `npm` from `frontend/`. Python 3.14+, Node
24.15+ and Docker are supported.

```bash
uv sync --locked --dev
uv run pytest
uv run ruff check dtvp tests scripts
cd frontend
npm ci --include=optional
npm run build
npm run test:unit
npm run test:ui                 # real playground must be running
```

`DTVP_TEST_DATABASE_URL` enables destructive integration checks against an
explicitly disposable PostgreSQL database whose name ends in `_test`.
Fast tests use SQLite only as an isolated test adapter. Browser tests use the
actual PostgreSQL/auth/API stack, without mocked application requests.
`uv run python scripts/playground.py test` runs backend/build/unit/browser checks.
CI runs the same API, PostgreSQL and browser gates on pushes and pull requests.

For separate processes, set the configuration in [development](docs/development.md),
run `uv run python -m dtvp.cli serve` and `uv run python -m dtvp.cli worker`, then
`npm run dev` in `frontend/`. Theme and technical-detail preferences persist locally;
assessment drafts are retained per user/finding in the browser session.

## Repository

| Path | Purpose |
| :--- | :--- |
| `dtvp/` | Domain, permissions, API, parsers, providers, snapshots and durable jobs |
| `dtvp/migrations/` | Frozen Alembic schema revisions |
| `frontend/` | Streamlined Vue review workspace and browser tests |
| `playground/` | Isolated Compose stack and shared public synthetic fixtures |
| `tests/` | Invariants, authorization, adapters, recovery and PostgreSQL checks |
| `scripts/` | Playground and PostgreSQL upgrade helpers |
| `docs/` | API, consumers, deployment, development and retained rewrite design |
| `skills/` | Agent routing back to this README |

The pre-rewrite runtime is preserved at Git commit
`bdc7ba41a40697b0a3f5aa1b619518216e5087f8`; planning checkpoint: `9697b53`.
Legacy DT cache/outbox code, obsolete pre-split analyzer copies, mocks, generated reports,
screenshots and obsolete configuration are removed from the new version.
Existing local legacy data is preserved and ignored; it is never interpreted
automatically as new memberships or approvals.

[Rewrite design and implementation status](docs/rewrite-plan.md) ·
[VScorer contract](docs/vscorer-consumer-contract.md) · [MIT License](LICENSE)

This README is the canonical project/agent overview. Update it alongside meaningful
behavior, API, integration, workflow or structure changes. Trust source and tests
if they disagree with prose. Agent instructions and skills remain routing hints.
