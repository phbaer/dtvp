# Import, Local State, And Export

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0002](adr/0002-local-first-database-with-import-and-export.md) for the database and export queue, [ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md) for assessments |
| Verified | 2026-11-18 against `tests/test_assessment_outbox_services.py`, `tests/test_dt_cache.py`, and `tests/test_export.py`. The run against the mock Dependency-Track dates from 2026-11-17, before assessments became DTVP's record. The response (2026-11-19) is checked against `tests/test_dt_cache.py`, `tests/test_dt_client.py`, and `tests/test_project_archive_services.py` only; how a running Dependency-Track treats `analysisResponse` was not checked |

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
- [Deleting An Assessment](#deleting-an-assessment)
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

Importing happens when a project is opened or refreshed and in the background
for recently used projects. Source facts (projects, findings, vulnerability
details, BOMs) replace the stored copy.

Assessments are **not** replaced by an import. Per finding:

| DTVP's record | Dependency-Track | Result |
| :--- | :--- | :--- |
| None yet | holds an assessment | It is adopted once as DTVP's record (revision 0, origin `import`) |
| None yet | holds nothing | Nothing happens |
| Exists | holds the same value | Nothing happens; a waiting export is dropped |
| Exists, synchronized | holds something else, or nothing | DTVP's value is exported again |
| Exists, waiting for export | holds something else | Stays queued; the export overwrites it |
| Export discarded, previous value unknown (`cancelled`) | any | Dependency-Track's value replaces the local one |

"Same value" compares the analysis state, the details text (ignoring
surrounding whitespace), and the suppression flag. A local change made while
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
its assessment kept as inactive.

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

## Deleting An Assessment

Deleting is an explicit operation, so that it can be told apart from
Dependency-Track merely reporting nothing (which DTVP repairs by exporting the
assessment again). In the **Assessment** tab of a vulnerability, the delete
button next to Save offers:

- **Only the open team's assessment** (or the General assessment, on the
  General tab). The other teams' text is kept exactly as it was. Deleting the
  General assessment also removes the SSVC decision and the response stored
  with it.
- **The whole assessment**: every team, the General assessment, rescoring,
  SSVC, and suppression. The vulnerability is open again.

A deletion applies to all findings of the vulnerability, is a new revision
with origin `assessment-deletion`, and is exported like any change, so the
assessment is removed from Dependency-Track as well. The deleted text stays in
the history.

Any user can delete a team's assessment; what remains is marked pending
review when an analyst did it. Deleting the General assessment or the whole
assessment requires the reviewer role. Access tokens and MCP agents cannot
delete.

`POST /api/assessment/delete` takes `instances` and `team` (a team name,
`"General"`, or `null` for everything). It answers 422 when there is nothing
to delete and 409 when a finding changed in the meantime.

## Findings That Disappear

When Dependency-Track stops reporting a finding, its assessment is kept and
marked inactive. If the finding is reported again under the same identifiers,
the assessment is active again, and it is exported again if Dependency-Track
no longer has it. A change that was still waiting for export when the finding
vanished is treated as a waiting change when it returns and is exported.

A finding that returns under **new** identifiers is matched by component and
vulnerability identity against the previous import only, as before, and its
restored assessment is marked for review.

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
`export-discarded`, `import` (adopted from Dependency-Track), and
`conflict-resolution` (only in history written before conflicts were removed). Bulk workflows and imports
record no author. `GET /api/assessments/history` with `project_uuid`,
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
| `inactive` | Dependency-Track no longer reports the finding |
| `cancelled` | A queued export was discarded and the previous value was not known; the next import replaces the value |
