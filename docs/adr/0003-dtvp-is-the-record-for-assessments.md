# ADR 0003: DTVP is the record for assessments

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-18, repository owner) |
| Implementation status | Partly implemented (2026-11-18); see [Implementation progress](#implementation-progress) |
| Supersedes | The assessment merge and conflict handling of [ADR 0002](0002-local-first-database-with-import-and-export.md). Its database, export queue, history, and ports remain. |
| Related | [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md) |

## Context

ADR 0002 made the local database the working copy but still treated
Dependency-Track as a second writer: an import compared both sides with a
three-way merge, adopted changes made in Dependency-Track, and held changes
made on both sides as conflicts for a person to resolve.

In practice nobody assesses in Dependency-Track. It is the datastore behind
DTVP, and its analysis record (a state, a justification, a response, one
free text) cannot hold what DTVP records, so DTVP writes markup into the text.
Two things followed from the merge model:

- Assessments that Dependency-Track lost, or that existed only there, were
  not protected: only findings edited in DTVP had a local record.
- Conflict handling existed for a second writer that does not exist, and a
  value Dependency-Track reported differently could replace reviewed work.

Other tools need the assessments as well. The security documentation
generator reads them from Dependency-Track's CycloneDX exports and parses
DTVP's markup out of the text, which is lossy.

## Drivers

- Reviewed assessments must not be changed or lost by the source.
- One place holds the assessment; everything else is rendered from it.
- Consumers get atomic, standard fields instead of markup in free text.
- Own vulnerability detection may follow later; identities stay
  Dependency-Track's for now.

## Decision

1. **DTVP's database is the record for assessments.** Dependency-Track
   supplies projects, findings, and vulnerability data. It never changes an
   assessment in DTVP.
2. **One-time adoption.** An assessment Dependency-Track holds for a finding
   DTVP has no record of becomes the local record (revision 0, origin
   `import`). What counts is the DTVP content in its text: assessments were
   never made in Dependency-Track itself, so its separate justification and
   response fields carry nothing of DTVP's and are not part of the record.
   After adoption the record is DTVP's.
3. **Dependency-Track is a rendering target.** Where it holds a different
   value, or none, DTVP's value is exported again. There are no conflicts and
   no resolution step. A value Dependency-Track repeatedly does not keep is
   reported as a failing export and retried with growing delay.
4. **Assessments are stored as structured fields** (state, justification,
   response, suppression, rescoring, per-team assessments, reviewer, SSVC,
   tickets). The Dependency-Track text is generated from them on export.
   Existing text is parsed once; text that does not parse is kept as raw
   text.
5. **DTVP serves CycloneDX per project version**: the inventory, and a VDR
   that carries the assessments in standard fields (analysis, an own rating
   with vector and justification, one annotation per team, properties). It
   contains every finding, including those in triage and not set. The
   generator reads these instead of Dependency-Track's exports.
6. **A finding that a new project version adds to an assessed vulnerability
   is marked as new**, not assessed automatically.

## Alternatives

- **Keep the three-way merge**: protects against a writer that does not
  exist, and keeps reviewed work replaceable by the source.
- **Stop exporting to Dependency-Track**: simplest, but Dependency-Track's
  own views and policy evaluation would show every finding as unassessed.
- **Carry assessments to new project versions automatically**: the same
  component can be used differently in a new version; a copied "not
  affected" would be an unreviewed claim.

## Consequences

- An assessment changed directly in Dependency-Track is overwritten by the
  next export. Analysis permissions there should be limited to DTVP's key.
- Every assessed finding now has a local record, not only those edited in
  DTVP. The database grows accordingly, and the records are held in memory.
- The conflict dialog, the `SOURCE_CONFLICT` reason, the `diverged` status,
  `POST /api/assessments/conflicts/resolve`, and `DTVP_EXPORT_VERIFY_SOURCE`
  are removed. Findings in conflict at upgrade time keep the DTVP value,
  which is exported.
- Dependency-Track's own justification and response fields, and its comment
  trail, are not adopted and not written. DTVP's justification is part of
  each team's assessment.
- The fields are read from the text when a value is adopted or saved, and
  the text is still what is exported. Until saving writes fields directly,
  a field can only hold what the text parser recognises; anything else stays
  in the assessment's free text.
- The database is the system of record for reviewed assessments: backup,
  restore, and retention are operational requirements, not conveniences.

## Confirmation

- `tests/test_assessment_outbox_services.py` and `tests/test_dt_cache.py`:
  adoption, the source never changing a local value, re-export of lost
  values, bounded retries, the upgrade of former conflicts, and the atomic
  fields of adopted, changed, and existing assessments.
- A CycloneDX VDR from DTVP that the generator reads without its text
  parser: checked by hand on 2026-11-18 with the generator's reader; not an
  automated test.

## Implementation progress

| Decision | Status |
| :--- | :--- |
| 1–3 Record, adoption, rendering target | Implemented 2026-11-18 |
| 4 Structured fields | Partly implemented 2026-11-18: fields are stored on adoption and on every change, and served by `GET /api/assessments/fields`. Open: saving writes fields and the Dependency-Track text is generated from them |
| 5 CycloneDX inventory and VDR | Implemented 2026-11-18 in DTVP; see [CycloneDX inventory and VDR](../cyclonedx-export.md). Open: the generator reads from DTVP instead of Dependency-Track |
| 6 New-finding mark | Implemented 2026-11-18 (separate change) |
