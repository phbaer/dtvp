# VScorer Consumer Contract

[Rewrite plan](rewrite-plan.md) · [Shipped DTVP API](api.md)

DTVP export/evidence contract for the active minimal edition in `../vscorer`.
VScorer consumes DTVP-owned vulnerability/SBOM snapshots and owns its specialized
Environmental assessment workflow. DTVP imports returned evidence/proposals and
owns adoption into its operational decisions. Each application keeps its own
database, artifacts, authorization, and deployment.

## Inspected VScorer Interface

The repository root is the active REST-first rewrite; `experimental/` is the
archived product. The legacy session/inventory adapter was removed from the rewrite.
DTVP exports native SBOM/worklist inputs for the active artifact/assessment API.
The active root currently accepts uploaded files; a direct DTVP source adapter
is a coordinated addition to the two rewrites.
[VScorer overview](../../vscorer/README.md),
[REST contract](../../vscorer/docs/rest_api.md),
[request schemas](../../vscorer/cvss_rescorer/api/schemas.py).

Existing product paths below are relative to `/api/v1`; health/OpenAPI paths
are service routes as noted below the table.

| Step | Contract |
| :--- | :--- |
| Capabilities/readiness | `GET /system/bootstrap`, `/healthz`, `/readyz`; OpenAPI at `/openapi.json` |
| Upload and validate | `POST /artifacts` with multipart `kind` and `file`; kinds: `threat_model`, `sbom`, `items_csv`, `cves`, `prior_vex`; artifact and combined intake validation routes |
| Prepare source facts | `POST /intelligence/assessment-preparations` with the exact CVE `keys`; durable refresh-job status/cancel/resume |
| Create assessment | `POST /assessments` with product-version/configuration IDs, artifact IDs, and explicit deployment-profile selection or `mode=none` |
| Review and resume | Assessment/finding reads, paginated finding summaries, draft/preview/decision/resume routes; optimistic versions |
| Generate/read output | Explicit VEX/report generation; `GET /assessments/{id}/vex`, `/report`, and immutable report revision downloads |

Service health/OpenAPI routes are outside `/api/v1`. Workflow mutations use
`Idempotency-Key`; strict requests reject unknown fields and stale updates return
`409`. Production authentication is local server-side sessions with CSRF/Origin
checks; OIDC and a general inbound machine-token API are not currently provided.
The current installation is scoped to one team.

## Vulnerability Input

VScorer accepts CycloneDX 1.5/1.6 JSON, a TM7 model, optional component placement
mapping, a JSON/semicolon-CSV CVE worklist or embedded vulnerabilities, and
optional prior VEX. Generated VEX is CycloneDX 1.6. The canonical worklist is:

```json
{
  "cves": [
    {
      "cve_id": "CVE-2099-20002",
      "component_refs": ["comp-utility"],
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "base_score": 9.8,
      "description": "Synthetic example",
      "cwe_ids": ["CWE-20"],
      "cpe": "",
      "references": ["https://example.invalid/advisory"]
    }
  ]
}
```

The envelope contains exactly `cves`; entries accept only these fields and CVE
IDs must be unique. `component_refs` are exact `bom-ref` values in the supplied
SBOM, including when a ref happens to look like a PURL. `description` and `cpe`
are required strings but may be empty. A supplied score must be numeric and
match its Base-only vector. Supported Base versions are 3.0, 3.1, and 4.0.
An unlinked CVE remains visible without eligibility for score reduction.
[Input contract](../../vscorer/docs/configuration.md),
[CVE parser](../../vscorer/cvss_rescorer/adapters/parsers/cve.py),
[CVSS validation](../../vscorer/cvss_rescorer/domain/cvss.py).

DTVP export rules:

- Freeze one product release/SBOM revision and the selected findings together.
  Export all graph context needed for assessment; declare partial authorization
  or missing graph coverage. Multiple releases get separate scoped bundles.
- Resolve advisory aliases to CVEs and merge each CVE's exact affected-component
  refs. Preserve DTVP finding/occurrence identities and alias/source facts in the
  snapshot manifest. Non-CVE findings remain in DTVP and appear in export coverage.
- Supply an explicitly selected original Base assertion. Preserve all competing
  assertions in DTVP; flag unresolved conflicts and unsupported vectors. DTVP's
  effective/rescored vector cannot become the new Base input.
- Produce a validated CycloneDX 1.6 representation with consistent refs and
  placement properties. Record conversion losses; reject conversions that lose
  required dependency/assessment context. A CVE-level CPE stays empty if there
  is no unambiguous assertion; component CPEs remain in the SBOM.
- Keep snapshot ID, provenance, schema version, hashes, source-to-ref mappings,
  and coverage in a separate manifest. Add an explicit VScorer source/provenance
  port; do not inject extra fields into its current strict worklist/intake JSON.

## DTVP Consumer API

Use generic immutable snapshots for Generator and VScorer. These are implemented
DTVP `/api/v2` resources, separate from VScorer's existing routes above:

| Resource | Purpose |
| :--- | :--- |
| `POST /snapshots` | Freeze one authorized product release, SBOM, selected findings, metadata, decisions, and source revisions |
| `GET /snapshots/{id}` | Manifest, integrity hashes, scope, completeness, and immutable revision identities |
| `GET /snapshots/{id}/vulnerabilities` | Canonical vulnerability list with occurrence links, aliases, original/effective scores, source provenance, and decision coverage |
| `GET /snapshots/{id}/sbom` | Declared-format SBOM from exactly the same snapshot |
| `GET /snapshots/{id}/exports/vscorer` | Versioned consumer manifest plus downloadable worklist/SBOM artifacts conforming to the inspected parser contract |

Snapshot pagination/exports retain the same revision. Selection filters and
suppressed/assessed findings are explicit and recorded. A VScorer source selector
fetches these resources using DTVP-issued scoped read credentials, validates the
bundle, and uses VScorer's own intake/preparation workflow. Initial file export
is also available for manual exploration. VScorer owns TM7/configuration and
deployment-profile review; DTVP may supply linked artifacts without assuming
that team ownership establishes a threat-model placement.

## Admission and Returned Results

VScorer requires NVD/KEV preparation for the frozen CVE set before creating an
assessment. DTVP facts do not bypass that gate. Current admission includes at
most 1,000 unique merged CVEs, 256 MiB aggregate inputs, and 16 MiB prior VEX,
with additional parsed-context limits. Read backend limits and preflight exports;
oversized work requires explicit partitions with complete per-CVE scope, never
silent truncation. Offline mode needs eligible saved reference observations.
[Capacity/admission contract](../../vscorer/docs/rest_api.md#capacity-contract).

Return results through a scoped DTVP evidence-ingestion adapter or an explicit
VEX/report import. Bind assessment/finding IDs, artifact hashes, selected source
snapshot, Base assertion, configuration/profile and analysis-contract revisions,
reviewer/decision state, Environmental vector/score, and evidence to the original
occurrences. Preserve source approval identity separately from DTVP adoption.
Reject or revalidate applicability when the current DTVP scope has changed.

Lower Environmental severity never proves `NOT_AFFECTED`; Base metrics remain
immutable, KEV stays separate, and unconfirmed/ambiguous/stale evidence cannot
justify a downgrade. VScorer's automatic VEX `not_affected` generation is disabled.
Experimental attack-chain, what-if, and generalized prioritization features are
outside this integration. VScorer's human review/report workflow remains in its
own application; DTVP displays concise status, proposals, and a contextual link.

## Naming and Verification

Use only `vscorer` for rewrite integration names: UI/docs, routes, settings
(`DTVP_VSCORER_*`), modules/types, mocks/PM2 tasks, fixture labels, OpenAPI assets,
and stored provider identities. Migration translates legacy configuration and
saved proposals while retaining original artifacts and audit history. Legacy runtime modules/configuration names were removed from this branch; historical
implementation remains available in Git.

Contract tests must parse DTVP-produced worklists/SBOMs with VScorer's actual
parsers and verify ref agreement, original scores, alias merges, unresolved
facts, export limits, permissions, and repeat import. Exercise one real synthetic
assessment through validation/preparation/review/output and import it into DTVP.
The current playground exports files for the separately running VScorer service.
An optional VScorer Compose profile is future integration work; it is not bundled
by `scripts/playground.py`. Default DTVP scenarios are synthetic/offline. Preserve VScorer's
installation-owned reference/prompt caches across ordinary database resets,
using separate local volumes. Follow its existing review gates when implementing
changes in that repository.
