# Development and testability

[README](../README.md) is canonical. `uv` manages backend dependencies and `npm`
manages `frontend/`. Real local testing defaults to the isolated PostgreSQL
playground; fast invariant/API tests use an in-memory SQLite adapter.

## Separate processes

Configure a development database and:

```bash
export DTVP_PLAYGROUND=true
export DTVP_PUBLIC_URL=http://127.0.0.1:5173
export DTVP_DATABASE_URL=postgresql+psycopg://dtvp:YOUR_PASSWORD@127.0.0.1:5432/dtvp_dev
uv run python -m dtvp.cli serve
uv run python -m dtvp.cli worker
```

Run `npm run dev` from `frontend/`. The Vite proxy targets port 8000; public URL
must match the browser origin for request protection. Production never enables
playground persona login or scenario-loading routes.

## Automatic tests

`uv run pytest` covers import identity/idempotence, partial/out-of-order input,
metadata preservation, approval/revalidation, immutable snapshots, scoped
credentials/sharing, artifact integrity, provider pagination, failure/cancel/lease
recovery, release context and previous-schema backups.

Set `DTVP_TEST_DATABASE_URL` to an isolated database ending in `_test` to check
PostgreSQL schema migrations, concurrent startup and restart persistence. The
test resets that database's public schema and refuses an unmarked database.

`npm run test:unit` covers API request/error handling. Set `DTVP_UI_URL` to an
explicit disposable playground before browser commands; there is no default URL.
`npm run test:ui` checks native workspace transport, assessment/review, scoring,
theme, isolation and compact layouts. Existing historical SQL review screens are removed.

`npm run test:integration` uses the separate `frontend/integration/` configuration
and real native HTTP/storage without mocked responses. It creates a unique synthetic
project, imports byte-exact parallel-version SBOMs, configures ownership, submits
an analyst decision, independently approves it and explicitly publishes a coordinator
score. Assertions retain original Base severity/bytes, per-vulnerability review
gates and independent version scope. Playground mode is required before resource
writes; existing projects are not reset. It has passed on SQLite and PostgreSQL.

The one-command `uv run python scripts/playground.py test` uses a disposable
PostgreSQL stack. Keep browser versions aligned with the npm lockfile.

## Shared scenarios

Load editable `playground/scenarios/workflow.json` or `specialists.json` with
`uv run dtvp knowledge --persona administrator demo load --file PATH`.
Startup creates identities/workspaces only. Loading a scenario explicitly publishes
synthetic inventory and retained provenance through the native journal.

Fixtures in `playground/fixtures/` are public, synthetic and offline. Use
`CVE-2099-*` to avoid real-advisory collisions. Baseline has two private teams;
replay scenarios add changed evidence, conflicting scores and partial coverage.
Offline matching/failure providers execute through the same worker as live
adapters. Tagged and metadata-free legacy DT examples exercise the same imported history
UI and retain Original Base scores. The consumer snapshot fixture covers two components with different
approved decisions for the same CVE.

The playground allows ordinary uploads, metadata edits and analysis beyond
scripted scenarios. Reset affects only its named database/artifact volumes.
Never point playground/test configuration at production storage. Optional
Generator/VScorer remain external applications rather than bundled services.
