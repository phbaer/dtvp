# DTVP

DTVP coordinates software-composition evidence, contextual cybersecurity assessment,
license review and architecture-documentation inputs across DevSecOps pipelines.
It owns imported knowledge and human decisions. Dependency-Track, CyBeats, SBOM
files and advisory services are sources; imports do not write decisions back.
UI and CLI are presentation layers over the same authenticated backend workflows.

This README is the canonical project overview. See the
[native contract reference](docs/native-reference.md), [API guide](docs/api.md),
[design decisions](docs/rewrite-plan.md) and
[DevSecOps concept and critical review](docs/devsecops-evidence-concept.md).
The design document retains historical decisions; implemented behavior and
`/openapi.json` take precedence over older planning notes.

## Architecture

DTVP runs as an API/UI process, a worker and PostgreSQL, with local persistent
artifact storage. Optional managed PostgreSQL uses the same connection contract.
There is no required object-storage service or separate search service.

- A local knowledge journal owns immutable logical state revisions, original
  artifacts, atomic reference updates, exact request receipts and release tags.
- PostgreSQL stores rebuildable knowledge projections plus operational identity,
  permissions, credentials and jobs. Those operational records also require backup;
  the journal alone cannot reconstruct an entire installation's access configuration.
- Product versions are independent branches within one product line. Nightly imports
  replace the selected source baseline rather than accumulating removed inventory.
  Tags retain released states. Comparisons select immutable states explicitly.
- Original imports and previous assessments remain historical evidence after
  component removal, corrected imports or branch updates. Explicit retention
  maintenance previews reachability before any offline cleanup.

A project belongs to a workspace; explicit sharing grants control access across
teams in one organization. Component responsibility is separate from access.
Teams own selected components and dependencies recursively; a more specific
team-owned subtree delegates responsibility to that team. Shared dependencies used
under distinct consuming roots retain separate assessment contexts.
Selectors support namespace/name separation, case sensitivity, PURLs and optional
product-version limits. Identity reconciliation preserves provenance and exposes
ambiguous matches rather than silently merging distinct usage contexts.

## Native workflow

The application has one native **Review** workspace. Searchable product/version
selectors, team and status filters, scope statistics and a compact work queue lead
to contextual assessment, independent review and coordinator scoring. Source and
published severity remain visible together. Expandable evidence and advanced tools
support detailed analysis without filling the ordinary review view.
System, light and dark themes are available.

1. A pipeline imports complete source snapshots or separately identified delivery
   parts, with explicit source/build ordering, scope and collection limitations.
2. An integrator explicitly assembles selected parts into a product version.
   Overlapping observations use a separate reconciliation workflow.
3. Team analysts assess applicability, rationale, not-affected justification and
   supporting evidence within their consuming contexts and version coverage.
4. Independent team reviewers approve the exact assessment revision or request
   changes. Material input changes require revalidation; historical decisions remain.
5. A dedicated security coordinator previews and publishes contextual scores after
   every required team has approved the vulnerability's current contexts.
6. Consumers retrieve pinned bundles, original files, worklists and issued exports;
   documentation and license judgments have their own explicit review workflows.

Manual contextual CVSS and project rules support CVSS 2.0/3.0/3.1/4.0 while preserving
original Base metrics. Rules derive applicability from approved assessments;
false-positive rules require an explicit choice and approved not-affected status.
Policy configuration, assessment pins and scoring provenance remain immutable.
External proposals never approve an assessment or publish a score automatically.
Optional SSVC answers use a pinned local model and backend-calculated outcomes;
incomplete answers can be drafted but cannot be submitted.

All current application APIs share `/api/v1`. `API_VERSION` in
[dtvp/api_contract.py](dtvp/api_contract.py) defines the namespace; the frontend
build reads that same Python constant. There are no old runtime API aliases.
Retired SQL Review, finding, release-ingestion, snapshot-writing and generic job
retry paths have been deleted. Historical SQL records and migration readers remain.

## Inputs and integrations

| Input or consumer | Current boundary |
| :--- | :--- |
| CycloneDX / SPDX | Exact-byte file intake; supported semantic subsets and parser losses retained |
| Multiple SBOMs | Explicit pinned part assembly; missing parts and coherence remain visible |
| Dependency-Track | Bound native intake, including prior DTVP documentation and plain metadata-free analyses |
| VDR / VEX | Attributed evidence, named validation subsets and explicit scoped application; no imported approval |
| NVD / CIRCL / EUVD / JVN | Known-ID enrichment; provider-specific identifier support and unknown coverage |
| OSV | Optional explicit exact-package matching; no-match does not establish remediation |
| CPE discovery | Curated sources, reviewed proposals, scoped NVD refresh and optional local full-catalog captures |
| VScorer | Separate consumer of issued SBOM/vulnerability inputs; explicitly bound returned scoring proposals |
| Agentyzer | Separate analysis service; retained evidence with qualification limits on source/commit binding |
| CyBeats | Public-SDK-derived read captures plus explicit supplied SBOMs; no invented export endpoint |
| Generator | Separate architecture-document consumer; native adapters exist, production cutover/parity still require acceptance |

Provider access is disabled unless configured. Jobs recheck current permissions
and source bindings, retain bounded raw responses and require explicit scoped
retry after failure. Only native job kinds execute; retained old jobs are history.
Optional advisory schedules are explicit opt-in policies, not automatic approval.

CPE catalog generations stay outside product manifests. Their raw captures are
immutable; a local SQLite search index is disposable and generation-bound.
Catalog consistency checks do not authenticate the publisher or establish that
upstream knowledge is complete. Searching or exporting candidates never adopts
component identities or transfers approval.

Current sibling service contracts, mocked qualification and unsupported features
are documented in the [native reference](docs/native-reference.md).
See the focused [consumer](docs/consumers.md), [Agentyzer](docs/agentyzer.md) and
[statistics and rescoring](docs/statistics-rescoring.md) guides for operation.
The current minimal VScorer does not echo DTVP receipts; operator-bound exchanges
are labeled accordingly. Current default Agentyzer reports do not prove the requested
source commit and cannot qualify as verified contextual application proposals.

## Local playground

Requirements: Python 3.15+, `uv`, Docker/Compose and a supported Node release
when building/testing the frontend locally (see `frontend/package.json`).

```sh
uv sync --locked --dev
uv run python scripts/playground.py up
```

Open **http://127.0.0.1:8900/**. Startup creates synthetic identities and workspaces
only. Load an editable dataset explicitly:

```sh
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator demo load --file playground/scenarios/workflow.json
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator demo load --file playground/scenarios/specialists.json
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator --timeout 300 demo load --file playground/scenarios/scale-5000.json
```

The workflow file includes parallel versions, dependency ownership, contrasting
assessment states, independent synthetic reviewers, imports and a historical tag.
The specialist file adds license review and mock VScorer/Agentyzer evidence.
These simulated fixture decisions are marked synthetic; they are not actual
human approvals or evidence of external-service execution.

**Scale 5000 Vulnerabilities**, version `7.2.0`, contains 5,000 distinct synthetic
vulnerability IDs, 402 components plus the product root, branching/shared
dependencies and delegated team ownership. Shared usage creates 6,000 contextual
review targets, all unassessed. The first load can take over a minute; `--timeout`
sets the CLI's HTTP wait. Repeating the exact file preserves existing work.
Regenerate its editable JSON offline with
`uv run python scripts/generate_scale_scenario.py`.

Edit complete SBOMs and phase data in `playground/scenarios/*.json`.
Reloading an unchanged file preserves interactive changes. To load a changed copy,
choose a new `fixture_id` **and** `project_name`; existing work is never reset.
The loader is playground-only, validates structured data and team permissions,
and publishes a completed staged scenario atomically. JSON cannot execute scripts.
There are no UI seed buttons or runtime reset endpoints.

```sh
uv run python scripts/playground.py logs
uv run python scripts/playground.py down
```

`down` retains local playground data. `DTVP_PLAYGROUND_PORT` selects another port;
`up --skip-build` reuses an existing image. Production `.env` is not read by this
isolated Compose stack. In WSL, use the URL from WSL/VS Code or its forwarded port;
forwarding a port still requires the API process to be running and listening there.
For corporate build trust, use `up --ca-cert /path/to/trusted-ca.pem` or
`DTVP_BUILD_CA`; runtime provider/OIDC trust remains deployment configuration.

For separate development processes, configure `DTVP_PLAYGROUND=true`, a development
PostgreSQL URL and `DTVP_PUBLIC_URL` matching the browser origin. Run
`uv run dtvp serve`, `uv run dtvp worker`, and `npm run dev` from `frontend/`.
Vite proxies backend requests to port 8000.

## CLI and API

`uv run dtvp knowledge --help` lists native presentation commands.
Use an explicit playground `--persona` for local demo sessions, or
`DTVP_API_TOKEN` for scoped machine access. Request files retain exact IDs,
version/policy pins, targets and rationale; the CLI does not infer approval.

```sh
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona coordinator score policy --project PROJECT_ID
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona coordinator score preview --project PROJECT_ID --rules --file score-request.json
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona coordinator score publish --project PROJECT_ID --rules --file publication-request.json
```

Omit `--rules` for manual CVSS input. Analysts/reviewers use `assessment draft`,
`assessment submit` and `review` with the same typed backend request files.
Publication requires a current preview. Preserve an uncertain request unchanged;
exact replay returns its original committed receipt rather than repinning it.
See [API contracts](docs/api.md) for scope, authentication and example intake.

Print dependencies using the same pinned backend read model as the UI:

```sh
uv run dtvp knowledge --persona analyst tree --project PROJECT_ID --version 7.2.0 --depth 4
```

Use `--state HASH` for retained history, `--root COMPONENT_REF` to inspect a subtree,
and `--json` for structured output. Depth is bounded at 20; pages contain at most
200 rows (`--limit`/`--offset`), with an explicit 10,000-row traversal cap. The CLI
prints continuation offsets and state pins. Counts are distinct imported IDs on
each component, not descendant totals or approvals.

In **Review**, expand **Dependency tree** above the queue. It loads lazily for the
selected immutable state, independently of queue filters; collapse branches,
change depth, browse subtrees or page through entries. Shared dependencies, cycles,
missing component metadata and unavailable graph declarations remain explicit.
API: `GET /api/v1/projects/{id}/states/{state}/dependency-tree`.

## Deployment, recovery and migration

```sh
cp .env.example .env
# Configure unique secrets, database credentials, public URL and OIDC.
docker compose up -d --build
docker compose exec api uv run --no-sync python -m dtvp.cli bootstrap \
  --issuer https://identity.example --subject YOUR_SUBJECT --name YOUR_NAME
```

Production requires PostgreSQL and a session secret of at least 32 characters.
OIDC supplies identity; explicit memberships and grants supply access. Bootstrap
registers an organization administrator, not an automatic assessment/review role.
The supplied deployment binds loopback; deploy HTTPS through your reverse proxy.
API and worker share the artifact directory and operational configuration.

Schema migrations run implicitly under a database lock before readiness. Existing
schema upgrades first retain a sealed logical backup. `DTVP_MIGRATION_DATABASE_URL`
can separate migration privileges from runtime access. PostgreSQL major upgrades
use the stopped-writer dump/restore helper into a fresh cluster; they are separate
from schema upgrades and do not automatically switch deployment connections.

Back up PostgreSQL and the artifact/journal directory consistently. Verify the
journal with `dtvp verify-knowledge --directory PATH`; rebuild knowledge projections
with `dtvp rebuild-knowledge`. Restoring projections does not restore lost operational
credentials, grants or jobs. Complete CPE catalog originals need backup; search
indexes can be rebuilt. See [deployment and recovery](docs/deployment.md).

Explicit readers import retained local `dtvp.snapshot/1` bundles and reviewed,
sanitized single-version v1 archives. Preview/apply require current source/target
permissions and original-byte proof. Historical documentation, scores and approvals
remain attributed claims; they never become native approval implicitly. Retained
SQL history is not dropped by removal of its former runtime.

## Verification and acceptance

```sh
uv run pytest
uv run ruff check dtvp tests scripts
cd frontend
npm ci --include=optional
npm run build
npm run test:unit
npm run test:ui
npm run test:integration
```

Browser commands require `DTVP_UI_URL` pointing to an explicitly disposable
playground. Backend fast tests use SQLite as a test adapter. Set
`DTVP_TEST_DATABASE_URL` to a disposable PostgreSQL database ending in `_test` for
native migration, concurrency, restart and permission checks; tests replace its
public schema. `uv run python scripts/playground.py test` creates isolated test
resources and runs backend/frontend/browser verification.

Synthetic tests and offline sibling mocks establish the exercised contracts.
Production acceptance still needs representative producer inputs, deployed service
round trips, recovery/performance qualification and Generator document parity.
SBOM correctness is the producer's responsibility; DTVP reports supplied coverage
and limitations. It does not infer complete discovery, license clearance or
regulatory compliance from an SBOM. Scope is cybersecurity, license compliance
and architecture documentation; DTVP does not establish safety-analysis claims.

## Repository map

| Path | Purpose |
| :--- | :--- |
| `dtvp/knowledge/` | Journal, contextual domain workflows, projections and consumer contracts |
| `dtvp/api_*.py` | Authenticated native presentation adapters |
| `dtvp/providers.py`, provider modules | Bounded source capture and normalization |
| `frontend/` | Native Review UI, themes and browser verification |
| `playground/scenarios/` | Editable explicit synthetic datasets |
| `tests/`, `scripts/` | Automated verification, operator tooling and rehearsals |
| `dtvp/migrations/` | Implicit schema migrations and retained historical tables |
| `docs/native-reference.md` | Detailed native API/domain/integration contracts |
