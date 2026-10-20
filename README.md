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
The [UI review and proposed structure](docs/ui-review.md) and
[interactive wireframe](docs/ui-proposal.html) describe a proposed navigation and
workflow redesign, including automatic My teams work scope and a focused
[assessment preview](docs/ui-proposal.html#assessment) with v1-style CVSS vector
comparison. The assessment workspace and vector comparison are integrated into
Review; the broader navigation and automatic My teams scope remain proposals.
Prototype record links also work when the prototype is already open.
The [screenshot-based usability review](docs/ui-review.md#screenshot-review-hierarchy-before-additional-panels)
and [revised vulnerability mockup](docs/vulnerability-proposal.html) explain the
implemented hierarchy: a stable, wider record pane, compact CVSS display and semantic
accent colours.
The [next UI refactoring plan](docs/ui-review.md#next-refactoring-stable-vulnerability-workspace)
describes the stable vulnerability pane and clearer Overview now implemented. It
also proposes one shared assessment across applicable product versions as the
default, with explicit ranges and version-specific exceptions; durable scope intent
and its UI/CLI support remain planned. Current runtime scope behavior is below.
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

Workspace and portfolio reads support server-filtered responsibility views:
`all`, `my_teams`, `unassigned` and `conflicts`. My teams derives from current
assessment/review memberships and credential restrictions, before statistics and
pagination. CLI workspace/portfolio commands accept `--work-scope`. Sharing grants
remain separate from responsibility. Authorized product readers can inspect the
owner and current sharing grants; only managers can change them.

## Native workflow

The application has one native **Review** workspace. Searchable product/version
selectors, team and status filters, scope statistics and a compact work queue lead
to contextual assessment, independent review and coordinator scoring. Source and
published severity remain visible together. Expandable evidence and advanced tools
support detailed analysis without filling the ordinary review view.
System, light and dark themes are available. Dark mode uses warm charcoal surfaces,
cream text and Catppuccin-inspired mauve accents; System follows the same palette
when the operating system prefers dark mode.

All finding tabs retain the same wider pane and compact results rail on desktop.
The rail distinguishes component, consuming root, team/status and labelled
source/published scores and scrolls independently; closing the finding restores
the full table. Narrow screens
show the selected finding directly, with **Back to results** restoring the queue
and keyboard focus. Tab changes never change pane width or filter visibility.
The shared header separates source severity/provider, contextual publication/currentness
and team assessment, with a role-appropriate action. Overview starts with description
and usage beside advisory/analysis evidence when pane width permits. **Assessment**,
**Independent review** and **Coordinator scoring** retain evidence beside decisions
on sufficiently wide panes and stack on narrower panes. Assessment actions stay in
form flow. Teal identifies sources, peach analyses, rose critical source severity,
amber revalidation and green actual approval; labels carry the same meaning.

The v1-style **CVSS vectors** comparison aligns source ratings, external proposals,
publication and the coordinator's server preview. Added and changed metrics are
explicitly labelled. All metrics, exact vectors and comparison baseline are
selectable; single or identical vectors show their supplied metrics rather than an
empty difference table. CVSS methods stay separate. Metric descriptions come from
the backend; comparison never calculates or adopts a score. Analysts compare read-only.

Analysts record applicability, not-affected justification, reasoning and explicitly
selected evidence citations. Existing unrecognized citations remain retained.
Submitted assessments are read-only; **Start new assessment** creates a separate
proposal. Text, citations and optional SSVC answers survive returning to the queue
within the same workspace session, bound to the input state and assessment revision.
Drafts from earlier input states or other contexts remain inspectable in the
unsaved-drafts disclosure; they are never silently applied to a changed baseline.
They are not browser-persistent: use **Save draft** before leaving. Reload warns
about unsaved drafts. Additional version coverage requires an explicit preview.
Leaving Assessment for another workflow tab or utility task clears that additional
selection. Captured pending submissions retain their exact scope, payload and retry
identity across navigation.
Final rescoring remains a separate coordinator task, gated per vulnerability on
current independent approvals of all required contexts.

The vulnerability pane compares **Vulnerability sources** (imported SBOM/DT facts,
NVD and other advisory/VEX inputs) with **Vulnerability analyses** (VScorer,
Agentyzer and historical analysis claims). Each entry identifies received content,
current/inactive/withheld status and recorded assessment citations. Expand an entry
for claims, vectors, report references and provenance. Matching scores alone never
prove that an analysis was used in a published decision.
CPE details distinguish source declarations, configured mappings and candidates;
none becomes an approved identity implicitly.
The Overview tab opens with description/consuming context, vulnerability sources
and analysis results visible, followed by the compact vector comparison. Dependency
paths remain directly accessible in context. **Analysis tools** opens VScorer input
files, Agentyzer repository input and jobs; **Component & CPE details** opens identity
evidence, candidate discovery and annotation editing; **Technical provenance** holds
raw records, supplementary evidence and imported DT assessment history. These named
task views share the record frame and remain mounted across workflow tabs. Opening
them does not prepare inputs or submit jobs. Pending follow-ups and annotation edits
keep navigation locked with their exact captured inputs reachable.

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
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator --timeout 300 demo load --file playground/scenarios/review-rich.json
uv run dtvp knowledge --url http://127.0.0.1:8900 --persona administrator --timeout 300 demo load --file playground/scenarios/scale-5000.json
```

The workflow file includes parallel versions, dependency ownership, contrasting
assessment states, independent synthetic reviewers, imports and a historical tag.
The specialist file adds license review and mock VScorer/Agentyzer evidence.
These simulated fixture decisions are marked synthetic; they are not actual
human approvals or evidence of external-service execution.

**Rich Review Playground** (`review-rich.json`) exercises feature variety rather
than volume. Open version `7.1.2`; compare it with `7.1.1` or the parallel `7.2.0`.

| Example | What to exercise |
| :--- | :--- |
| `CVE-2099-31001` | Separate team contexts, approved/submitted assessments, two VScorer vectors (0 and 6.5), unqualified Agentyzer evidence, blocked coordinator gate |
| `CVE-2099-31002` | Changed source evidence requiring reassessment |
| `CVE-2099-32001` | Long description/name, two dependency paths, conflicting 9.8/8.1 source vectors, investigation draft, authored exposure/criticality/support/mitigation context and analysis limitations |
| `CVE-2099-32002` | Binary inventory with declared CPE and mixed CVSS 2/4 ratings; these methods are not direct vector conflicts |
| `CVE-2099-32003` | Missing PURL/CPE, unknown package version and absent severity; no invented zero score |
| `CVE-2099-32004` | Removed component and retained historical assessment, visible in earlier states/tag |
| `CVE-2099-32005` | Both team contexts independently approved; explicitly published contextual score 0 beside original 9.8 |
| `CVE-2099-32006` | New component/vulnerability in the parallel `7.2.0` composition |

The file also contains submitted license review, mixed/unknown license claims and
a pre-update release tag. Optional `metadata` and `scores` phases use ordinary
permission, exact-input and review-gate checks. Assessments marked `after_updates`
run after import changes and annotations, so final scoring uses fresh approvals.
Publications are synthetic fixture
operations, not real security approvals. Empty optional phases preserve earlier
scenario hashes; the existing files and loaded projects remain compatible.

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

`uv run dtvp knowledge --help` lists everyday commands: discovery, findings,
assessment/review, scoring, imports, dependency trees and comparisons.
`uv run dtvp knowledge advanced --help` lists integration, configuration,
synchronization, migration and diagnostic tools, including raw `request` access.
Previous direct spellings of advanced commands remain supported for existing scripts.
Connection/authentication options go before the command (including `advanced`).

Discover IDs and versions without constructing API requests:

```sh
uv run dtvp knowledge --persona administrator projects
uv run dtvp knowledge --persona administrator projects --q Product --limit 25
uv run dtvp knowledge --persona administrator versions --project PROJECT_ID
uv run dtvp knowledge --persona administrator teams
uv run dtvp knowledge --persona administrator advanced request GET /api/v1/me
```

Projects support server-side name search, workspace filtering and cursor pagination.
Versions list current branches and immutable release tags with their exact state IDs;
use `--offset`/`--limit` to page them. Discovery commands support `--json` for scripts.
Teams list accessible workspaces/team IDs; component ownership remains separately
configured. Results follow the authenticated user's permissions.

SBOM uploads accept a product ID or exact name. Missing products and versions are
created implicitly; later uploads replace that version's source baseline, preserving
historical imports and assessments:

```sh
uv run dtvp knowledge --persona analyst import-file \
  --project "Device Platform" --version 7.2.0 --file bom.json --metadata import.json
```

For example, `import.json`:

```json
{
  "request_id": "nightly-42",
  "source": "pipeline:device",
  "build_number": 42,
  "occurred_at": "2026-10-20T01:00:00Z",
  "completeness": "complete"
}
```

Omitting `expected` selects the current head on the server. An explicit state SHA
requires that exact head; explicit `null` remains create-only. A new build needs a
new request ID and increasing build number. Retry uncertain uploads with unchanged
metadata and bytes; even after later imports, retries return the original receipt.
Use `--workspace WORKSPACE_ID` to select the owner when creating among multiple
writable teams or disambiguating duplicate names. IDs always select that exact
product. Resolution and import enforce workspace, sharing and credential permissions.

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

The dependency tree and finding-location paths start collapsed and load on demand.
Opening the tree shows collapsed roots. Expand individual branches; **Collapse all**
returns to roots. Compact rows show component/version, direct dependency counts and
vulnerability counts. Select a component to reveal **Show paths**, subtree navigation
and identifiers, without repeating those controls on every row. **Back** restores the
previous subtree. Expanding a node fetches only its immediate children. **Load more
children** appends siblings within that branch; **Load more roots** appends roots.
There is no whole-tree next/previous pagination or global display-depth control.
Expanded descendants, selection and cached branches survive sibling loading and
collapse/re-expansion. **Refresh tree** releases the loaded branches. The UI retains
at most 10,000 loaded occurrences and 100 dependency levels; focus a subtree to
continue. Shared components expand independently per usage path; cycles terminate.
The pinned `GET /api/v1/projects/{project}/states/{state}/dependency-children` endpoint
accepts optional `root_ref`, `parent_ref`, repeated `path` ancestors, and sibling
`offset`/`limit` (default 100, maximum 200). The backend validates declared ancestor
edges and returns context-specific paths, counts and cycle/shared markers.
The UI's expandable dependency hierarchy includes **Show paths** for the selected component.
This switches to a compact path-only view; **Back to dependency tree** restores the
hierarchy without losing its loaded branches or expansion. Finding evidence also shows the
path from that finding's consuming root to the affected component. Named components
and versions replace raw reference chains; alternative shortest paths are selectable.
The authorized, pinned `GET /api/v1/projects/{project}/states/{state}/dependency-paths`
endpoint takes `component_ref`, optional `root_ref` and `limit` (default 20, maximum
50). Reverse graph search avoids unfolding shared dependencies and cycles, with
explicit 10,000-node/100-edge-depth limits. Only shortest declared routes are shown;
longer routes and runtime reachability are not inferred. Missing paths and truncated
searches remain explicit. Path lookup reads inventory only, independent of tree
pages, display depth and the size of the vulnerability worklist.

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
expand nodes, browse subtrees or load additional siblings in place. Shared dependencies, cycles,
missing component metadata and unavailable graph declarations remain explicit.
API: `GET /api/v1/projects/{id}/states/{state}/dependency-tree`.

Inspect the same classified vulnerability detail in the CLI:

```sh
uv run dtvp knowledge --persona analyst workspace --project PROJECT_ID --version 7.2.0 --q CVE-2099-50000 --show-context
uv run dtvp knowledge --persona analyst vulnerability --project PROJECT_ID --version 7.2.0 --context CONTEXT_ID --id CVE-2099-50000
```

The first command exposes context IDs; the second prints compact source, analysis
and CPE contributions. Add `--expected STATE_HASH` to reject a changed version head,
or `--json` for full returned fields and hashes. Classification is computed by
the backend for the selected vulnerability detail, not duplicated in either client
or added to every row of the large review queue.

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
