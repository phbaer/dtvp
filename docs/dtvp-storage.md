# DTVP-owned catalog and source imports

[Project overview](../README.md) · [API reference](api.md)

## Current boundary

DTVP now provisions its own PostgreSQL database in Compose, applies versioned
migrations before serving requests, and stores immutable normalized snapshots
and original source captures in the content-addressed artifact directory
(`data/dtvp_artifacts` by default). Local development without database settings
uses a file-backed SQLite database.

The storage format is source-neutral: a connector returns a
`dtvp.inventory-snapshot/v1` document with product/version metadata, component
occurrences, dependency relationships, findings, advisory observations, and
provenance. Provider-specific fields and exact source responses remain inside
the retained `source_artifacts` section. Provider identifiers are mapped using
`external_references`; they do not define DTVP product/version keys.

Dependency-Track is the first connector. This is an inbound import and repeatable
full-scope sync; it does not publish DTVP decisions back to Dependency-Track.
The first adapter groups Dependency-Track project versions by exact project name;
ambiguous duplicate name/version mappings fail visibly instead of overwriting a
different version.
Existing project/finding UI APIs and assessment writes still use the legacy
Dependency-Track path until their migration batches are completed.

## Import and sync

Authenticated reviewers can import or refresh one Dependency-Track project
version:

```http
POST /api/catalog/sources/dependency-track/import
Content-Type: application/json

{
  "request_id": "nightly-2026-10-27-01",
  "project_id": "<dependency-track-project-uuid>"
}
```

`POST /api/catalog/sources/dependency-track/sync` accepts the same request and
performs the same complete source refresh. Both operations capture the project,
CycloneDX BOM, findings/analysis, and project vulnerability list. A run is
published only after all source reads and normalization succeed; failed imports
leave the current DTVP snapshot unchanged. Use a new `request_id` for a retry
after a failed run. Replaying the same `(source connection, request_id)` returns
the original durable run rather than fetching again.
Reusing a request ID for a different project scope returns HTTP `409`.

Each run records status, scope, counts, timestamps, and the resulting snapshot
revision/hash. Identical normalized state does not create a new DTVP revision,
but the new run's exact provider response is still retained as a content-addressed
artifact. Changed normalized state creates the next immutable revision. Artifacts
are SHA-256 checked on write and read.

## Reading DTVP state

All endpoints below require DTVP authentication.

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/catalog/products?name=...` | Search DTVP products |
| `GET /api/catalog/products/{product_id}/versions` | List DTVP product versions and current snapshot IDs |
| `GET /api/catalog/versions/{version_id}/snapshot` | Read the latest snapshot |
| `GET /api/catalog/versions/{version_id}/snapshot?revision=N` | Read a pinned revision |
| `GET /api/catalog/versions/{version_id}/snapshots/{snapshot_id}` | Read a specific snapshot ID |
| `GET /api/catalog/import-runs/{run_id}` | Inspect run status and captured cursors/counts |
| `GET /api/catalog/import-runs/{run_id}/artifact` | Retrieve the exact retained source capture for that run |

## Adding another source

Implement `SourceConnector.fetch_snapshot(client, scope)` and return the same
snapshot schema. Call the shared `import_source_scope` service with the provider
client and source type. The service creates a source connection record, durable
idempotent run, retained artifact, external identity mappings, and immutable
snapshot revision. It does not require new provider-specific tables. A future
adapter still needs explicit completeness, deletion, identity-matching, and
incremental-cursor rules before scheduled synchronization is enabled.
