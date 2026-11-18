# Import, Local State, And Export

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0002](adr/0002-local-first-database-with-import-and-export.md) |
| Verified | 2026-11-17 against `tests/test_assessment_outbox_services.py`, `tests/test_dt_cache.py`, `tests/test_assessment_conflicts.py`, `tests/test_export.py`, and a run against the mock Dependency-Track |

DTVP keeps its own copy of everything it works on. It **imports** projects,
findings, and assessments from Dependency-Track, you **work** on the local
copy, and DTVP **exports** assessments back. The local database is the record:
work is never lost because Dependency-Track is unreachable, and neither side
overwrites the other unnoticed.

- [What Is Stored Locally](#what-is-stored-locally)
- [Import](#import)
- [Export](#export)
- [Conflicts](#conflicts)
- [Deleting An Assessment](#deleting-an-assessment)
- [Findings That Disappear](#findings-that-disappear)
- [History](#history)
- [Sync Status Values](#sync-status-values)

## What Is Stored Locally

One SQLite database (`DTVP_DATABASE_PATH`, by default
`<DTVP_DT_CACHE_PATH>/dtvp.sqlite3`) holds the imported source data, every
assessment made in DTVP with its history, the export queue, and access
tokens. Back it up; it is not a cache. See
[Runtime and capacity](runtime.md#runtime-behavior) for the storage details
and [Deployment](deployment.md) for backup notes.

## Import

Importing happens when a project is opened or refreshed and in the background
for recently used projects. Source facts (projects, findings, vulnerability
details, BOMs) replace the stored copy.

Assessments are **merged**, per finding:

| Local assessment | Dependency-Track | Result |
| :--- | :--- | :--- |
| Never assessed in DTVP | any | Dependency-Track's value is shown |
| Unchanged since the last sync | unchanged | Nothing happens |
| Unchanged since the last sync | changed | Dependency-Track's value becomes a new local revision |
| Changed, not exported yet | unchanged | Stays queued for export |
| Changed, not exported yet | changed to the same value | The export is dropped; nothing to do |
| Changed, not exported yet | changed to something else | **Conflict**; see below |
| Synchronized | reports nothing at all (no state, no text, not suppressed) | The local assessment is exported again |
| Changed, not exported yet | reports nothing at all | Stays queued; the export overwrites nothing |

"Changed" compares the analysis state, the details text (ignoring surrounding
whitespace), and the suppression flag with the value both sides last agreed
on. For a finding's first edit in DTVP that value is what the editor was
looking at: the UI sends the assessment shown in the open view with every
save. Other clients that send nothing are compared with the last imported
value. A pending-review marker that DTVP itself added to its copy is not
counted as a difference. A
local change made while an import was already running is never touched by
that import, and an assessed finding whose details could not be read from
Dependency-Track is skipped rather than treated as emptied.

Before this model, a finding assessed once in DTVP showed the DTVP value from
then on, and later changes made in Dependency-Track were never seen.

## Export

`DTVP_EXPORT_MODE` selects how assessments leave DTVP:

- `auto` (default): each saved assessment is exported in the background,
  usually within a second.
- `manual`: assessments stay local until a reviewer exports them under
  **Settings → Export**.

Either way, DTVP reads the finding's current assessment from Dependency-Track
immediately before writing. If it changed since the last sync, the export is
held as a conflict instead of overwriting it. Set
`DTVP_EXPORT_VERIFY_SOURCE=false` to skip that read; a conflict is then only
noticed if an import happens to run between the two changes. If
Dependency-Track cannot be read, the export proceeds.

**Settings → Export** (reviewers) lists everything that has not reached
Dependency-Track: the finding, who changed it, the state change, and on
request the text to be exported next to the text it replaces. Export one entry
or all. Failed exports show their last error; in `auto` mode they are retried
with increasing delay (up to a minute for the first ten attempts, then up to
15 minutes), in `manual` mode on the next export. An export whose project or
finding no longer exists in Dependency-Track is removed from the queue and
its assessment kept as inactive.

### When exports fail

A failing export is shown in three places:

- Reviewers get a warning in the header on every page, for example
  **Export: 10 failing, 1 in conflict**. It opens the Export tab.
- The cache status panel of a project lists **Failing** and **Conflicts**
  next to **Pending**.
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
reports `failed_exports`, `diverged_assessments`, and `oldest_pending_at`.

`GET /api/export` returns the same list; `POST /api/export` exports all due
entries or those named in `update_ids` and reports how many were `exported`,
how many were `dropped` because the finding no longer exists, and which
failed or conflict. Exporting requires the reviewer role
and a browser session.

Lines for `.env` (and `.env.dist` as the documented template):

```dotenv
# auto: export assessments to Dependency-Track as they are saved (default).
# manual: keep them in DTVP until a reviewer exports them in Settings.
DTVP_EXPORT_MODE=auto
# Read a finding from Dependency-Track right before exporting to it, so a
# change made there is not overwritten unseen. One extra read per export.
# DTVP_EXPORT_VERIFY_SOURCE=true
# The local database. Persistent data: back it up, do not clear it.
# DTVP_DATABASE_PATH=data/dt_cache/dtvp.sqlite3
```

## Conflicts

A conflict means the assessment of a finding was changed in DTVP and,
independently, in Dependency-Track. DTVP then:

- keeps both values and exports nothing for that finding;
- lists the vulnerability as **Conflicting**, with the inconsistency reason
  **Conflict with Dependency-Track** (`SOURCE_CONFLICT`), which is also a
  filter;
- shows a banner in the vulnerability's detail view.

The banner opens a dialog with both versions per finding. Choose one:

- **Use the Dependency-Track version**: it becomes the local assessment. The
  DTVP version stays in the history.
- **Keep the DTVP version and export it**: it overwrites Dependency-Track's
  value on the next export.

Any signed-in user can resolve a conflict; the choice is recorded with their
name. Access tokens cannot. A conflict also ends by itself when the two sides
come to hold the same value, or when Dependency-Track returns to the value
both sides last agreed on.

A vulnerability can remain Conflicting after a resolution for another reason,
for example when its findings now have different states.

`POST /api/assessments/conflicts/resolve` takes `instances` (each with
`project_uuid`, `component_uuid`, `vulnerability_uuid`) and `resolution`
(`local` or `remote`). It answers 409 if a finding has no open conflict.

## Deleting An Assessment

Deleting is an explicit operation, so that it can be told apart from
Dependency-Track merely reporting nothing (which DTVP repairs by exporting the
assessment again). In the **Assessment** tab of a vulnerability, the delete
button next to Save offers:

- **Only the open team's assessment** (or the General assessment, on the
  General tab). The other teams' text is kept exactly as it was. Deleting the
  General assessment also removes the SSVC decision stored with it.
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
vanished is treated as a waiting change when it returns: exported if
Dependency-Track is unchanged, otherwise a conflict.

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
`conflict-resolution`. Bulk workflows and imports
record no author. `GET /api/assessments/history` with `project_uuid`,
`component_uuid`, and `vulnerability_uuid` returns it, newest first.

History starts with this version: an assessment made earlier has a single
`before-history` entry holding its value at the time of the upgrade.

## Sync Status Values

Findings assessed in DTVP carry a status (`dtvpSyncStatus` on an analysis,
`sync_status` on a grouped finding):

| Value | Meaning |
| :--- | :--- |
| `synced` | Dependency-Track holds the local value |
| `pending` | Waiting for export |
| `error` | The last export failed; it is retried |
| `diverged` | Conflict; the export is held |
| `inactive` | Dependency-Track no longer reports the finding |
| `cancelled` | A queued export was discarded and the previous value was not known; the next import replaces the value |
