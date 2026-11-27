# ADR 0017: Standalone assessments with supporting evidence in DTVP

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted by the repository owner (2026-11-26) |
| Implementation status | Implemented on `feat/evidence-assessment-attachments`; not deployed |
| Amends | Decision 3 and the export consequences of [ADR 0006](0006-agent-code-evidence-is-applied-by-a-person.md) |
| Related | [Assessment model](../assessment-model.md), [AI access](../ai-access.md#code-evidence), [Analysis integrations](../analysis-integrations.md#agent-code-evidence) |
| Verification | Current behavior checked on 2026-11-26 against `CodeAnalysisPanel.vue`, `VulnGroupCard.vue`, `codeEvidence.ts`, `assessment_use_cases.py`, and the evidence backup record schemas; implementation adds the behavior below; validation evidence is recorded in the branch tests |

## Context and drivers

A reviewer must be able to evaluate a printed or exported assessment without
DTVP, a local filesystem, or access to supporting evidence. Before this change,
**Use in assessment draft** inserted a line containing an opaque evidence ID
and title. A save retained only associations whose reference line remained in
the text. Neither that ID nor paths such as `/mnt/d/ProdSec/` explain why a
severity or exploitability decision is justified.

The evidence itself can contain detailed observations, source excerpts and
reports that should be available to an authorized DTVP consumer without
copying all supporting material into every assessment.

## Decision

### Standalone team and global assessments

Each saved team assessment, and any global assessment, must contain an
editable textual rationale sufficient to understand:

- the conclusion and its consumer, release, artifact and configuration scope;
- the code path, artifact checks, observations and their provenance;
- input control, access requirements, demonstrated impact and uncertainty;
- why those facts support the exploitability decision and any severity change;
- remediation or conditions supporting an exclusion, plus closure criteria.

Use ordinary prose, not a mandatory heading template. Distinguish package
presence, code reachability, observed impact and inferred impact. Record
unverified claims as such. A severity change needs its scoring rationale and
applicable vector, preserving the original source score; evidence must not
silently change scoring. Existing author, date and review provenance remain
available in the rendered assessment.

A human-authored global rationale synthesizes team conclusions while
preserving material consumer and release differences. A derived global state
is not automatically a reviewed global rationale; show its team rationales
and label the state as derived until a reviewer records a synthesis. The
existing General block and assessment endpoint store the synthesis; no
parallel synthesis record or endpoint is needed. A manual decision identifies
who set the state, while the saved prose and review metadata show its rationale
and approval separately.

### Evidence associations stay outside the prose

**Use in assessment draft** offers an explicit assessment summary, editable
before saving, and separately selects that evidence as supporting material.
Do not copy an entire evidence body, fabricate a summary from a title, or
insert an opaque ID into the assessment. If no summary exists, let the person
write one in the reader before applying. The Apply action requires nonempty
rationale; it never copies a title or the full report as a substitute.

Keep the summary optional on evidence creation so existing evidence and MCP
clients remain compatible. Validate it through the canonical assessment text
rules before inserting or saving it. Suggested states remain an explicit
human choice; applying evidence never approves an assessment.

Keep selected evidence visible as a separate draft control, removable without
editing prose. Save the associations explicitly through `code_evidence_by_team` in the
browser, or `code_evidence_ids` for the target team in MCP preview/save;
do not infer selection from text or lose it when rationale wording changes.
MCP may propose supporting links on its team's pending draft, with the same
scope checks as the browser; it cannot write General, another team's links,
or reviewer approval. This extends decision 3 of ADR 0006 beyond the browser
application path without changing human approval requirements.
Persist attribution to the relevant team/global block, finding and assessment
revision so later edits do not rewrite the history of a decision. Validate
scope, availability and withdrawal before durable assessment writes; preserve
existing concurrency and review rules. Extend the existing application records
and save workflow rather than create a parallel assessment store.

### Downloadable supporting material

Add attachments owned by an evidence record: sanitized reports, logs and
source excerpts, with filename, media type, size, description, SHA-256,
uploader and upload time. Upload creates an immutable version; replacement
preserves earlier bytes and provenance. Evidence remains readable without
opening attachments, and attachments inherit the evidence access controls.

Store attachment bytes within managed DTVP storage, never as references to an
uploader's local paths. Use generated storage identifiers, bounded uploads,
filename/path validation, safe downloads and atomic publication of complete
content. Preserve existing withdrawal history and analyzer cleanup boundaries.
Define the concrete limits and upload protocol in implementation; do not add
attachment bytes to the existing Markdown field.

Downloads must support individual attachments and an evidence package with
reports, attachment versions, provenance and a hash manifest. A per-evidence
appendix in Markdown and static, escaped, printable HTML includes rationale,
scope, source report, readable provenance and use history; both files are
checksummed. A combined vulnerability-wide print layout is outside this
change. Include bytes, metadata and associations in instance backup/restore and project archives;
missing bytes must be reported, not silently treated as a complete export.

### Print, export and existing records

The normal printed/exported assessment contains the substantive rationale,
assessor and review provenance. It must not depend on evidence IDs, DTVP URLs
or local paths. Keep evidence associations within DTVP; consumers may request
an optional evidence appendix/package with readable titles and provenance.
Retain existing Dependency-Track/CycloneDX assessment mappings for rationale;
do not export attachment bytes or opaque internal links as assessment prose.

Preserve historical assessments and evidence unchanged. Do not strip IDs or
local paths from existing regulatory records automatically. New saves use
explicit associations; legacy references remain readable, with an explicit
human edit required to replace them with adequate rationale. Do not infer
missing team/revision attribution for historical associations.

## Alternatives and consequences

- **Keep ID reference lines:** rejected; portable text cannot explain the decision.
- **Copy all evidence into every assessment:** rejected; creates duplication and
  mixes detailed observations with the decision rationale.
- **Use links or attachments instead of rationale:** rejected; an exported
  assessment must remain understandable without fetching supporting files.
- **Standalone rationale plus internal associations and optional evidence
  downloads:** chosen; adds attachment lifecycle and historical association
  work, but preserves a concise decision and accessible supporting material.

## Implementation and confirmation

1. Add optional assessment summaries, explicit draft evidence selection and
   team/global revision associations. Stop parsing reference lines on new saves.
2. Add managed attachment upload/download, immutable versions and evidence
   packages, then extend backup/restore and project archive contracts together.
3. Update print/export and human/agent guidance. Backfill rationale only through
   reviewed edits; do not rewrite existing evidence as part of migration.

Acceptance checks:

- EST-like findings produce useful printed rationale explaining authenticated
  exposure, observed memory growth, recovery and the isolated-crash limitation,
  without requiring an evidence ID or filesystem path.
- Editing rationale preserves selected evidence; explicit deselection removes
  only the intended association. Team/global and release scopes stay distinct.
- Missing summaries require author input; stale, withdrawn or foreign evidence,
  concurrent edits and failed saves cannot create misleading associations.
- Evidence ingestion alone changes no assessment, score, approval or export queue.
- Attachment access, upload bounds, path handling, incomplete uploads and version
  integrity are checked. Downloaded packages verify against their hash manifest.
- Backup/restore and archive round trips preserve files, versions, associations
  and withdrawals; missing or corrupt content produces an explicit failure.
- Existing clients, evidence and assessments remain readable; migration does not
  fabricate provenance or automatically rewrite historical rationale.


## Implementation notes

Attachment versions and their bytes are appended atomically to the evidence
record's `attachments_json` in the existing database. Ordinary evidence list
queries strip base64 bytes in SQLite before returning rows. Per-file, per-record
and project archive bounds are documented in the integration reference.
Team/revision selections extend the application table and retain legacy
unknown attribution. Application tracking remains a post-commit provenance
write, like analyzer tracking: a failure is logged and does not undo the
assessment. Project archive v2 preserves source application revisions when
destination finding identities change; it does not fabricate a new review.


## Verification (2026-11-26)

- Frontend: all 1,024 unit tests pass; production build and TypeScript checks pass.
- Browser: nine evidence scenarios pass across Chromium, Firefox and WebKit,
  covering scoped display, standalone rationale, explicit links, save, upload
  and download with mocked APIs. WebKit does not expose Blob request bytes to
  Playwright; server integration tests verify the received bytes.
- Backend: affected evidence, MCP, permissions, assessment, migration coverage,
  backup/restore, newer-dump compatibility and archive tests pass, including
  legacy records, integrity failures, file versioning and cross-instance IDs.
- Full backend run: 2,232 passed; two obsolete future-minor fixture failures
  were corrected and verified separately. Two same-issue tests fail only in
  the full run and pass in isolation. Both failures reproduce in the unchanged
  parent branch's full run (2,223 passed, two failed); they are outside this change.
- No deployment, production upload or additional product assessment was performed.

### Integration with main (2026-11-26)

Merged main `7d9ced5d`, retaining the reorganized assessment form and saved
views. Post-merge checks: all 1,291 frontend unit tests, the production
build/TypeScript checks, nine Chromium/Firefox/WebKit scenarios and 364
backend evidence/assessment/MCP/permission/backup/archive checks pass.
The full backend suite was not repeated after this integration; the earlier
full-run results above refer to the original parent branch. The feature diff
against current main passes whitespace checks; upstream-only trailing blank
lines were left unchanged.

### Acceptance-gap corrections (2026-11-27)

The bug report mixed deployment state with code gaps. A read-only check of the
live `/api/version` returned build `39f637de`, predating the justification and
attachment changes; its MCP schema lacked both. Deployment remains outstanding.
The justification read side already exists and is covered by HTTP round-trip
tests; no production assessment was modified to diagnose it.

Corrections add strict unknown-argument rejection, target-team evidence
selection in MCP preview/save, required rationale before applying agent
evidence, and readable/printable evidence appendices. Tests cover foreign and
withdrawn evidence, explicit deselection, missing archived bytes, and HTML
escaping. Global synthesis reuses the existing reviewer General block,
team-rationale overview, derived-state label and normal save/approval paths.

Verification of these corrections: 642 affected backend tests passed, including
MCP HTTP reads/writes, scope and failure checks, reviewer rationale,
attachments, backups, schemas and archives. The exhaustive backup
`test_crash_at_every_rename_then_resume_or_abort` was excluded; the full backend
suite was not run. All 1,304 frontend unit tests and the production build passed;
the attachment layout was rebuilt and its three unit tests rechecked after the
final copy/layout adjustment. Nine evidence browser scenarios passed across
Chromium, Firefox and WebKit, including missing/whitespace-only rationale and
an author-entered rationale saved with explicit evidence selection. Changed
Markdown file links and `git diff --check` passed. These are local/mock checks,
not production rollout verification.
