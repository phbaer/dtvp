# Import, Local State, And Export

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0002](adr/0002-local-first-database-with-import-and-export.md) for the database and export queue, [ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md) for assessments |
| Verified | 2026-11-20: [Findings that disappear](#findings-that-disappear) against `tests/test_dt_cache.py`, `tests/test_finding_lifecycle_services.py`, and `tests/test_assessment_outbox_services.py` with a simulated Dependency-Track (synthetic findings and project times); not against a running Dependency-Track. 2026-11-18 against `tests/test_assessment_outbox_services.py`, `tests/test_dt_cache.py`, and `tests/test_export.py`. The run against the mock Dependency-Track dates from 2026-11-17, before assessments became DTVP's record. The response (2026-11-19) is checked against `tests/test_dt_cache.py`, `tests/test_dt_client.py`, and `tests/test_project_archive_services.py` only; how a running Dependency-Track treats `analysisResponse` was not checked |

DTVP keeps its own copy of everything it works on. It **imports** projects,
findings, and vulnerability data from Dependency-Track, you **work** on the
local copy, and DTVP **exports** assessments back.

For assessments the local database is the record. Dependency-Track never
changes an assessment in DTVP: work is not lost because Dependency-Track is
unreachable, and not replaced because Dependency-Track reports something
else.

- [What Is Stored Locally](#what-is-stored-locally)
- [Import](#import)
- [Export](#export)
- [When Dependency-Track Holds Something Else](#when-dependency-track-holds-something-else)
- [Clearing An Assessment](#clearing-an-assessment)
- [Cleaning Up An Inconsistent Assessment](#cleaning-up-an-inconsistent-assessment)
- [Findings That Disappear](#findings-that-disappear)
- [History](#history)
- [Sync Status Values](#sync-status-values)

## What Is Stored Locally

One SQLite database (`DTVP_DATABASE_PATH`, by default
`<DTVP_DT_CACHE_PATH>/dtvp.sqlite3`) holds the imported source data, every
assessment with its atomic fields and history, the export queue, and access
tokens. Back it up; it is not a cache. See
[Runtime and capacity](runtime.md#runtime-behavior) for the storage details
and [Deployment](deployment.md) for backup notes.

## Import

When importing happens (implemented, checked against `dtvp/dt_cache.py` and
`dtvp/source_sync.py` on 2026-11-21):

- A version is imported from Dependency-Track the first time it is opened, and
  the view waits for it. Afterwards it is served from the database: opening it
  again does not read Dependency-Track.
- The sync scheduler re-reads the project list every
  `DTVP_DT_CACHE_REFRESH_SECONDS` (60), the findings of watched products
  every two minutes, and imports every other active version in the
  background, then re-reads it on Dependency-Track's change signals or every
  12 hours ([Sync scheduler](runtime.md#sync-scheduler)).
- The dashboard is served the stored project list; only a list never read is
  fetched when it is asked for.
- The automatic code-analysis sweep imports versions nobody opened.

Source facts (projects, findings, vulnerability details, BOMs) replace the
stored copy.

Planned: [ADR 0004](adr/0004-background-sync-and-event-stream.md) moves all
reads from Dependency-Track to a background scheduler that keeps every active
version current, and readers serve only the database.

Assessments are **not** replaced by an import. Per finding:

| DTVP's record | Dependency-Track | Result |
| :--- | :--- | :--- |
| None yet | holds an assessment | It is adopted once as DTVP's record (revision 0, origin `import`) |
| None yet | holds an assessment with a [version override](assessment-model.md#version-override) marker | Adopted as revision 0 (origin `import`); revision 1 (origin `import-review`) marks it pending review and is exported |
| None yet | holds nothing | Nothing happens |
| Exists | holds the same value | Nothing happens; a waiting export is dropped |
| Exists, synchronized | holds something else, or nothing | DTVP's value is exported again |
| Exists, waiting for export | holds something else | Stays queued; the export overwrites it |
| Export discarded, previous value unknown (`cancelled`) | any | Dependency-Track's value replaces the local one |

"Same value" compares the analysis state, the details text (ignoring
surrounding whitespace), and the suppression flag. Dependency-Track's findings
list carries the text of findings with a state only; for a finding that DTVP
records with a text and no state, the analysis is read on its own, so that
its text is compared too. A local change made while
an import was already running is never touched by that import, and an
assessed finding whose details could not be read from Dependency-Track is
skipped rather than treated as emptied.

What is adopted is the DTVP content: the state, the suppression flag, and
the text with DTVP's markup. Assessments were never made in Dependency-Track
itself, so its separate justification and response fields and its comment
trail are not part of the record, and are not restored if Dependency-Track
loses an assessment.

The [response](assessment-model.md#response) is adopted only as the tag
`[Response: …]` in the text. A response that exists only in
Dependency-Track's own `analysisResponse` field is not read: the finding has
no response in DTVP, and the first export of that finding sets
Dependency-Track's field to `NOT_SET`. A finding that DTVP adopted and never
changed is not exported, so its field stays as it is.

On adoption, and on every later change, the text is read into atomic fields
that are stored in the database:

- per finding: state, suppression, pending review, the rescored score and
  vector, the [response](assessment-model.md#response), and `free_text`:
  everything written outside the team blocks, kept as written;
- per team (including General): state, justification, assessor, reviewer,
  date, rescoring, SSVC decision, assignees, ticket reference, the evidence
  and version-coverage confirmations, whether the block is historical, and
  the team's text.

An assessment without team blocks (plain or legacy text) is all free text.
Nothing is dropped: the text as it was saved also stays in the record and in
its history. `GET /api/assessments/fields` with `project_uuid`,
`component_uuid`, and `vulnerability_uuid` returns the fields; it answers 404
for a finding without a record. Assessments recorded before this version get
their fields at the first start.

The web form saves an assessment as these fields (`fields` in
`POST /api/assessment`), and the server writes the text from them, always in
the same form. A save that leaves `free_text` out keeps the free text each
finding has; an empty string removes it. Other writers (MCP tools, bulk
workflows) still work on text, which is read into the same fields. Every
text is stored in the same layout, whoever wrote it.

Adoption happens as projects are imported, so after an upgrade the records
appear project by project. Until a project has been imported once with this
version, assessments that exist only in Dependency-Track are not protected.

## Export

`DTVP_EXPORT_MODE` selects how assessments leave DTVP:

- `auto` (default): each saved assessment is exported in the background,
  usually within a second.
- `manual`: assessments stay local until a reviewer exports them under
  **Settings → Export**.

An export overwrites whatever Dependency-Track holds for the finding.

Besides the state, the text, and the suppression flag, every export writes
the [response](assessment-model.md#response) to Dependency-Track's
`analysisResponse`: the value of the exported text, or `NOT_SET` when it has
none, so a response removed in DTVP is removed there. Restoring a project
archive writes it the same way, from the archived text. The justification is
part of each team's assessment and is not written by an export of a saved
assessment; only bulk workflows and archive restores pass one on.

Whether Dependency-Track holds the exported value is judged by the state,
the text, and the suppression flag. A response changed only in
Dependency-Track's own field is therefore not noticed and not corrected
until the finding is exported again.

**Settings → Export** (reviewers) lists everything that has not reached
Dependency-Track: the finding, who changed it, the state change, and on
request the text to be exported next to the text it replaces (loaded when an
entry is opened; `GET /api/export/texts?update_id=…`). Export one entry
or all. Failed exports show their last error; in `auto` mode they are retried
with increasing delay (up to a minute for the first ten attempts, then up to
15 minutes), in `manual` mode on the next export. An export whose project or
finding no longer exists in Dependency-Track is removed from the queue and
its assessment kept as inactive; the finding is marked gone with reason
`missing_at_export`.

### When exports fail

A failing export is shown in three places:

- Reviewers get a warning in the header on every page, for example
  **Export: 10 failing**. It opens the Export tab.
- The cache status panel of a project lists **Failing** next to **Pending**.
- The Export tab shows, per entry, how long it has been waiting, the number
  of attempts, and the error from Dependency-Track. An entry is marked
  **Stuck** after ten failed attempts or when its project is no longer in
  Dependency-Track's project list, with a hint what to do.

Entries keep their product and version when the project has been deleted in
Dependency-Track, together with the time it was last listed. DTVP remembers
every project it has imported; for a project that vanished before that
record existed, name and version come from the root component of its stored
BOM. Only a project of which neither is stored shows as unknown.

**Discard** removes an entry from the queue so it is never sent; **Discard
failing** does so for all failing entries. Where the value last agreed with
Dependency-Track is known, the assessment in DTVP goes back to it, as a new
revision with origin `export-discarded`, so both sides match again. For
changes queued before that value was recorded, the text is kept and marked
`cancelled`. The discarded version stays in the history. Discarding requires
the reviewer role and a browser session.

`POST /api/export/discard` takes `update_ids`. `GET /api/cache-status`
reports `failed_exports` and `oldest_pending_at`.

`GET /api/export` returns the same list; `POST /api/export` exports all due
entries or those named in `update_ids` and reports how many were `exported`,
how many were `dropped` because the finding no longer exists, and which
failed. Exporting requires the reviewer role
and a browser session.

Lines for `.env` (and `.env.dist` as the documented template):

```dotenv
# auto: export assessments to Dependency-Track as they are saved (default).
# manual: keep them in DTVP until a reviewer exports them in Settings.
DTVP_EXPORT_MODE=auto
# The local database. Persistent data: back it up, do not clear it.
# DTVP_DATABASE_PATH=data/dt_cache/dtvp.sqlite3
```

## When Dependency-Track Holds Something Else

Dependency-Track is where DTVP stores a rendering of its assessments; it is
not a second place to edit them. If an import finds a different value there,
or none (as happens when Dependency-Track recreates a finding), DTVP exports
its value again. In `manual` mode the entry appears under
**Settings → Export** instead.

While such an export is waiting, the vulnerability's detail view notes
**Saved locally — Dependency-Track is out of date**, and the Export tab shows
the text Dependency-Track last held next to the one to be exported.

If Dependency-Track is found without the exported value again and again, the
export is not repeated at every import. It is reported as failing, with
"Dependency-Track did not keep the exported assessment" as the error, and
retried with the same growing delay as other failing exports. It ends by
itself as soon as an import finds DTVP's value in Dependency-Track.

An assessment changed directly in Dependency-Track is therefore overwritten.
Earlier versions compared both sides and held such findings as conflicts;
findings in conflict at the time of the upgrade keep the DTVP value, which is
exported.

## Clearing An Assessment

Clearing is an explicit operation, so that it can be told apart from
Dependency-Track merely reporting nothing (which DTVP repairs by exporting the
assessment again). Use the clear button in **Decision & rationale** to
clear the open assessment, or **More** → **Clear assessment…** to choose the
scope. The confirmation names the affected findings, components and versions:

- **Only the open team's assessment** (or the General assessment, on the
  General tab). The other teams' text, and the team's own historical
  assessments, are kept exactly as they were; only when historical
  assessments are all the team has are they deleted. Clearing the
  General (Global) assessment also removes the SSVC decision and response.
  The effective state is derived from any remaining team verdicts.
- **The whole assessment**: every team, the General assessment, rescoring,
  SSVC, and suppression. The vulnerability is open again.

A clear applies to all findings of the vulnerability and is a new revision
(origin `assessment-deletion`, shown as "Cleared" in the history) without a
decision or text for what was cleared: clearing everything leaves the state
Not set and the text empty. It is exported like any change, so the assessment
is cleared in Dependency-Track as well. The previous assessment stays in the
history; there is no separate undo.

Any user can clear a team's assessment; what remains of the assessment is
marked pending review when an analyst did it. Clearing the General assessment
or the whole assessment requires the reviewer role. Access tokens and MCP
agents cannot clear.

`POST /api/assessment/delete` takes `instances` and `team` (a team name,
`"General"`, or `null` for everything). It answers 422 when there is nothing
to clear and 409 when a finding changed in the meantime.

## Cleaning Up An Inconsistent Assessment

When the findings of a vulnerability carry different assessments, **Clean
up…** (on the inconsistency banner, and in **More** of the action bar) lists
the versions of the assessment, compared as the lifecycle compares them, each
with its findings (project version, component), state, teams and the fields
in which it differs from the others, the SSVC record included. Who assessed
when is not listed; it does not make two versions different.

The user keeps one version and chooses the findings to change (by default
those that do not carry it) and what to clean up: the whole assessment, the
Global assessment, or one team's. For the selected findings it then either
**uses the kept version** for that scope, or **clears** it. Clearing one
team's assessment from all findings removes the block of a team that no
longer exists; the scope list marks teams the team mapping does not name, or
names only as an alias.

**Preview** shows per finding what would change (state, and the fields or
team assessments added or removed); nothing is saved before. **Save** writes
what was previewed: each finding a new revision (origin
`assessment-cleanup`), exported to Dependency-Track like any change. A
finding that changed after the preview, or the kept one, makes the save fail
with a conflict; preview again. Using the kept version keeps each finding's
own historical blocks and version override. With the whole assessment it
takes the kept finding's state, rescoring, response, SSVC record, review
status and suppression; with the Global assessment its General block (with
the SSVC record) and response; with a team, that team's block, and the
result of an analyst goes to review.

Reviewers can clean up every scope. Analysts clean up team assessments only.

`POST /api/assessment/cleanup` takes `instances` (the findings to change),
`action` (`apply` or `clear`), `team` (a team name, `"General"`, or `null`
for the whole assessment), `source` (the finding whose stored assessment is
kept, for `apply`), `revisions` (`"project|component|vulnerability"` to the
revision previewed) and `dry_run`. A dry run returns, per finding, `before`,
`after` (`null` when unchanged), `changed`, `revision` and the kept finding's
`source_revision`. The texts are built from the stored ones only. It answers
403 for an analyst's Global or whole cleanup, 422 for an invalid request or
when nothing would change, and 409 on a conflict.

## Reading A Dependency-Track Export Back

Dependency-Track keeps the text DTVP last exported. A CycloneDX VDR that
Dependency-Track exported can therefore be read back to restore team
assessments DTVP lost: see
[Restore team assessments from an export](review-workflows.md#restore-team-assessments-from-an-export).
Nothing else is imported from such a file.

## Findings That Disappear

DTVP follows the source's findings on every read. Dependency-Track
re-analyses a project asynchronously after a BOM upload, so a read in between
can miss findings that return on recreated components a moment later. DTVP
does not wait for that: what such a read misses is marked gone, and the next
read heals it. A finding that returns is active again (step 5); a finding
that returns on a recreated component takes its assessment over (step 4), and
the earlier gone mark becomes `replaced`. Only a read whose findings could not
be read at all is not acted on.

1. **Every read counts.** There is no waiting for the source's analysis and
   no Dependency-Track-specific signal in this logic; any source that reports
   findings works the same way.
2. **Keep the finding, mark it gone.** A finding a read no longer
   has stays in DTVP as *gone*, with the read that first missed it
   (`gone_at`), the last read that had it (`last_seen_at`), and a
   reason:

   | Reason | Meaning |
   | :--- | :--- |
   | `replaced` | The vulnerability is now reported on another component with the same identity (package URL without version, else name), and the BOM no longer has the old component. The successor is recorded |
   | `no_longer_matched` | The component, or one of the same identity, is still there; the vulnerability is no longer reported on it (an analyser or mirror change, or a changed CPE: then the finding records "CPE changed from … to …") |

   Every assessment record is followed, an inactive one too: a record whose
   finding went before DTVP tracked findings gets a gone row, once at the
   first start of this version for all records and at each read for the
   version read, marked as predating tracking (first seen unknown, not
   counted as gone at that read nor in "followed since"). A row without a
   component name takes it from the BOM stored before the read, before its
   reason is told; a gone row still without one takes it from local sources
   inside the read: the stored BOM, the version's stored findings (its
   component may still have other findings), then project archives, newest first,
   each parsed once per process for every project and only until every row
   is named; a read parses at most three new archives and the next read
   goes on. With the
   identity known, a row whose vulnerability is reported on the same
   component under a new ID is `replaced` and counts as recreated, not as
   gone. A row predating tracking whose reason no read has told yet is
   exported apart (`export_findings_gone_predating`). A component missing
   from the BOM is `component_removed` only when its identity is known:
   without it the row is `undetermined` (Dependency-Track recreated
   components nightly before tracking, so a missing UUID proves no
   removal). Rows stored as `component_removed` without an identity are
   repaired to `undetermined` once at startup (idempotent); a read then tells
   them by identity where the lookup finds it. Each read logs how many rows
   it looked up, where it found them (stored BOM, stored findings, archived
   BOMs) and how many stay undetermined. An earlier `component_removed`
   whose row got its identity in this read becomes `no_longer_matched` once a
   component of the same identity and version is in the BOM (the component
   was only recreated). A removal told
   with the identity known stays, also when a later version of the package
   appears. A carry-over by identity, and a recreation that needs no new
   review, need the package URL, unless the component was named by the
   findings themselves (a finding DTVP saw reported): then name and version
   suffice, and a recreation also needs the only finding of the
   vulnerability with that name and version. A component whose name was
   taken from a BOM for an old record is carried by vulnerability and name,
   with that rule's safeguards (exactly one candidate, the same name),
   pending review. A replaced finding whose assessment has a value and that
   no rule carries is never dropped: it is left undetermined, for a person.
   A row made for an old record knows only the vulnerability's UUID; at each
   read, and when gone findings are shown, it is named from the stored
   findings and vulnerability records, so its aliases are found. The startup backfill skips
   versions whose findings DTVP never read, and a row predating tracking
   whose finding is reported is not counted as returned.
   | `component_removed` | The project's BOM has neither the component nor one of its identity; told only with the component's identity known |
   | `undetermined` | The findings do not tell, or suggest a replacement, and the BOM could not be read; or the component's identity is unknown, so a removal cannot be told from a recreation |
   | `missing_at_export` | An export was rejected and Dependency-Track confirmed the finding no longer exists |

   The BOM is read when the findings alone do not decide, and to confirm a
   replacement: a component still in the BOM was not replaced, even when it
   has no finding left and another version of it has the vulnerability. A
   later read looks at earlier reasons again: a successor found
   later makes a finding `replaced` (again only once the BOM confirms it),
   and an `undetermined` reason is replaced once it can be told. Otherwise
   the first reason stays.
3. **The record follows.** The assessment record of a gone finding becomes
   `inactive` with its value kept, whether it was synchronised, waiting for
   export, or failing; a queued export is dropped and logged with the
   reason. A change saved after the read started is left alone. An export
   that was discarded (`cancelled`) stays discarded.
4. **Carry over from the record.** On every read, a reported finding
   without a record and without an assessment in Dependency-Track takes over
   the assessment of a gone finding of the same vulnerability (same UUID or
   identifier) that was `replaced`: its component had the same identity and
   the BOM no longer has it. A finding that is `no_longer_matched` keeps its
   record, inactive. Records count when inactive, waiting, failing, or
   synchronised. One such record, or several
   that agree apart from the pending-review marker, is saved as a new
   revision with origin `carried-over`, marked `[Status: Pending Review]`,
   and queued for export like any other change; the old records become
   `superseded`. When every old record's component had the new one's name,
   version and package URL (Dependency-Track recreated the same component,
   typically a BOM uploaded again), the value is carried unchanged, without
   the marker, with origin `carried-over-recreated`. If the records
   disagree, nothing is carried over and the gone findings say so
   ("assessments differ"). If the new finding already has an assessment,
   nothing is carried over ("successor has its own assessment"); once that
   assessment is approved (a record without the pending-review marker), the
   old record becomes `superseded`, so it is no candidate when the component
   is recreated again.

   A gone finding whose component DTVP never knew (a record from before
   DTVP tracked findings, on a component Dependency-Track has since
   recreated) is never carried on a read: nothing says which package it was
   on. Three things offer it to a person instead, none automatic:
   - the gone findings panel proposes the reported finding of the same
     vulnerability in the version ("same vulnerability, the gone finding's
     component is unknown"); with several candidates it lists all of them,
     and the reviewer applies to one or explicitly to all;
   - the **Unknown component** stage of Repair Assessments applies such
     records in bulk where that is unambiguous (see
     [Review workflows](review-workflows.md));
   - a finding without an assessment shows **Earlier assessments** in its
     assessment form: what DTVP still holds for gone findings of the same
     vulnerability (and its aliases) in the version, each with **Use this**
     to fill the form (`GET /api/project/{uuid}/earlier-assessments`).

   Carries of builds before the recreated rule (2.0.0rc1 and earlier) put
   the marker on a recreated component's assessment too, and components
   recreated every night carried that marker on to the next generation,
   with the old rule and unchanged with the new one. Every read takes it
   back where the record still holds the carried value (its latest revision
   is a carry-over, `carried-over` or `carried-over-recreated`: nobody saved
   since), and, followed back through the records it was carried from, the
   value leads to the same value without the marker, every step a recreation
   (same name, version and package URL; package URLs compared with only
   the qualifiers that name another artifact: `arch`, `classifier`,
   `distro`, `repository_url`, `type`) and every record in between a carry
   nobody saved since. "Nobody saved since" means every revision after the
   last carry is a carry or an automatic write (origin `bulk-workflow`, for
   example Restore adding historical blocks) that changed nothing but
   historical blocks; a person's save anywhere after the carry, or a bulk
   write that changed the assessment (Synchronize copying another text),
   keeps the marker. The marker, matched in any case on a line of its own,
   is then removed where it stands and the historical blocks stay. Each read logs, at INFO, why the markers
   it kept stayed (`saved_since`, `value_differs`, `component_differs`,
   `step_saved_since`, `no_carry_found`; reported findings only), and
   `GET /api/sync/status` lists those counts per project version under
   `review_markers_kept`. A value that was pending review where the chain
   starts, or a step to another version, keeps the marker. A new revision
   with origin `carried-over-recreated` restores the value without the
   marker and is queued for export. It runs once per record; anything saved
   since is left alone.

   The plan is made from the records as they were after the gone findings
   were retired, and saved in one transaction that checks them again. A
   replacing finding assessed in the meantime keeps its assessment, and a
   gone finding's record saved again in the meantime is not superseded:
   that carry-over is left out and logged, and the next read decides.

   Records of findings that went before DTVP recorded findings (before this
   behaviour existed) have no identity. They are carried over by
   vulnerability, with origin `carried-over-by-vulnerability`, when exactly
   one reported finding of that vulnerability has no record, the BOM no
   longer has the record's component, and that component had the same name
   (case-insensitive) as the reported finding's. The name comes from the
   BOM DTVP stored before the read, the only place that may still list the
   component; it is kept with the gone finding. When the name cannot be
   told, nothing is carried over and the gone finding says so ("component
   unknown"): assess the new finding by hand. A component of another name is
   a different package and takes nothing.
5. **A returning finding comes back.** Reported again under the same
   identifiers, the finding is active again (`returned_at`; when and why it
   went stays on the finding), and so is its assessment: `synced` if
   Dependency-Track still holds it, otherwise `pending` and exported. Its
   value did not change, so no revision is written; the history of an
   assessment only lists changes of its value. A finding that returns under
   new identifiers is a replacement (step 4); it has an assessment and so is
   not marked new.

**Gone findings** of a project are listed in the project view; see
[Gone findings](review-workflows.md#gone-findings). `GET
/api/project/{project_uuid}/gone-findings` returns them for one version, and
`GET /api/gone-findings?name=<project name>` for every version of a project:
the last read (time, how many went by reason, returned,
carried over, not carried, and `mass_disappearance` when many went no longer
matched), the current counts by reason, and per finding the
component, vulnerability, reason, dates, carry-over, successor, the
assessment record's status and tickets, whether the component was recreated
(same name and version), whether it needs attention, who acknowledged it
when, `cause` (a CPE change, where the stored BOMs tell) and `alias` (the
same vulnerability under another id still reported on the component, its
state, whether it disagrees, and what applying would do). Each
version also has `summary` (counts by reason and carry-over outcome, needing
attention, acknowledged, `mass_disappearance`), `trend` (how many went per
day, by reason) and `alias_disagreements` (reported ids of one vulnerability
on one component whose states differ). Aliases come from the stored findings
and vulnerability records of the version.
`POST /api/gone-findings/acknowledge` acknowledges gone findings for every
user, or withdraws it. `POST /api/gone-findings/apply-to-alias` (reviewers)
applies a gone finding's assessment to its alias as described in
[Gone findings](review-workflows.md#gone-findings). Acknowledgements and
causes are part of the instance dump (optional `acknowledged_by`,
`acknowledged_at` and `gone_cause` of `finding_presence`).
The VDR states the counts in
`<prefix>:export_findings_gone`; see
[CycloneDX inventory and VDR](cyclonedx-export.md).

A finding that appears for the first time in a **new project version** has no
assessment. DTVP marks it as new instead of copying one; see
[New findings](review-workflows.md#new-findings).

## History

Every value a finding's assessment has had in DTVP is kept with its time,
origin, and author. This is DTVP's own history, not Dependency-Track's audit
trail. **Assessment → History** in a vulnerability's detail view shows it:
who changed the assessment, when, and how, with the text of each version on
request. A change that covered several findings at once is one entry. For
vulnerabilities with more than 30 findings only the first 30 are loaded.

 Origins are `before-history`, `individual-assessment` (a save in the UI),
`mcp-assessment` (an agent), `bulk-workflow`, `assessment-deletion`,
`export-discarded`, `import` (adopted from Dependency-Track), `import-review`
(an adopted value with a version override marker, marked pending review),
`carried-over`, `carried-over-recreated` (taken over unchanged from the same
component recreated under a new ID, or such a carry's review marker taken
back) and `carried-over-by-vulnerability` (taken over from a replaced finding; see
[Findings that disappear](#findings-that-disappear)), and
`conflict-resolution` (only in history written before conflicts were removed). A bulk
workflow records the reviewer who applied it as author; imports record no author. `GET /api/assessments/history` with `project_uuid`,
`component_uuid`, and `vulnerability_uuid` returns it, newest first.

History starts with the version that introduced it: an assessment edited in
DTVP before has a single `before-history` entry, and one adopted from
Dependency-Track starts with an `import` entry at revision 0.

## Sync Status Values

Findings with a record in DTVP carry a status (`dtvpSyncStatus` on an analysis,
`sync_status` on a grouped finding):

| Value | Meaning |
| :--- | :--- |
| `synced` | Dependency-Track holds the local value |
| `pending` | Waiting for export |
| `error` | The last export failed, or Dependency-Track did not keep it; it is retried |
| `inactive` | Dependency-Track no longer reports the finding; the value is kept |
| `superseded` | The value was carried over to the finding that replaced this one; kept as history. Active again if the finding returns |
| `cancelled` | A queued export was discarded and the previous value was not known; the next import replaces the value |
