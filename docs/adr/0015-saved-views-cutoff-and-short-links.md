# ADR 0015: A cutoff on the published or first-attributed date, and saved views with short links

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-26, repository owner) |
| Implementation status | Implemented on branch `feat/saved-views-cutoff` (PR #360), not merged |
| Related | [Cutoff](../review-workflows.md#cutoff), [Cutoff and the FDA guidance](../review-workflows.md#cutoff-and-the-fda-guidance), [Saved views](../review-workflows.md#saved-views-and-short-links), [AI access](../ai-access.md#mcp-tools), [Backup](../backup-and-restore.md); builds on the filters of PR #351 |

## Context

Teams preparing a release or a submission want a list that stops growing:
what was known by a date. After release, monitoring keeps finding
vulnerabilities, and what it found after a date starts the postmarket
clocks. Filter states have grown large (PR #351 put all of them in the URL)
and every user rebuilds the same lists by hand.

The dates DTVP has (checked against the code, 2026-11-25):

- **Published**: Dependency-Track's `published` of a vulnerability record,
  taken from its source (NVD for CVEs, GitHub for GHSAs, OSV); internal
  records may have none. The record inside a finding may lack it; the full
  record of `/api/v1/vulnerability/project/{uuid}`, which DTVP already
  reads for vectors and aliases, carries it.
- **Attributed**: Dependency-Track's `attributedOn` per finding, set when
  its analysis first attributes the vulnerability to a component. A new
  version, a version deleted and uploaded again (7.1.1), or a component
  recreated under a new UUID gets a new date, although the issue was known.
  A finding that goes and comes back through a recreated component also
  gets a new date.
- DTVP's own `finding_presence.first_seen_at` is a read time, empty or late
  for findings older than tracking, and per version.

The two dates serve different purposes and are both needed at the same
time:

- FDA, "Cybersecurity in Medical Devices: Quality Management System
  Considerations and Content of Premarket Submissions", issued February 3,
  2026 (supersedes the June 27, 2025 version), section V.A.4: "As part of
  the premarket submission, manufacturers should also identify all known
  vulnerabilities associated with the device and the software components,
  including those identified in CISA's Known Exploited Vulnerabilities
  Catalog." It defines no "known as of" date; unresolved anomalies are
  listed "at the time of submission" (section V.A.5).
  ([guidance](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket),
  [PDF](https://www.fda.gov/media/119933/download))
- FDA, "Postmarket Management of Cybersecurity in Medical Devices", issued
  December 28, 2016, section VI.B: "As soon as possible but no later than 30
  days after learning of the vulnerability, the manufacturer communicates
  with its customers …" and "… no later than 60 days after learning of the
  vulnerability, the manufacturer fixes the vulnerability …".
  ([guidance](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/postmarket-management-cybersecurity-medical-devices),
  [PDF](https://www.fda.gov/media/95862/download))

DTVP supports these processes; it is not regulatory advice.

## Decision

1. **One cutoff filter on two dates**, chosen in the filter (`cutoff_basis`):
   - `published` (default), "Published (premarket)": when the source
     published the vulnerability, the earliest `published` among the records
     of the vulnerability and its aliases that the group holds (the findings
     of the CVE, its GHSA and other aliases in the project). An alias that no
     finding in the project carries is not looked up. The same date for
     every finding of the vulnerability. It answers "what was publicly known
     by the date" (premarket scope).
   - `attributed`, "First attributed (postmarket)": the earliest
     `attributedOn` of the same vulnerability on the same component (package
     URL without version, else group and name) in any version of the
     project. New and re-uploaded versions keep the earlier date; a
     component new to the project brings its own; a gone and returned
     finding whose only date is the new attribution takes the new date (no
     DTVP fallback). It answers "since when does our monitoring know of it",
     which starts the postmarket 30/60-day clocks; it is only as good as the
     monitoring cadence.
2. **Parameters**: `cutoff` is `YYYY-MM-DD` (UTC, the whole day included)
   or rolling `<N>d`; `cutoff_mode` is `before` (on or before, default) or
   `after`. A vulnerability is listed when a finding in scope (the selected
   versions, else all) matches. It replaces the attribution-age filter: old
   `attributed_before_days=N&attribution_mode=older|younger` is read as
   `cutoff=Nd&cutoff_mode=before|after&cutoff_basis=attributed`.
3. **Unknown dates are listed and counted per basis**
   (`counts.filtered.cutoff_unknown`, MCP `date_unknown`).
4. **The cutoff selects vulnerabilities, not findings**: the detail marks
   findings dated after the cutoff ("After cutoff"); saves and Bulk Changes
   act on whole vulnerabilities, as with the version filter.
5. **A cutoff is a planning aid, not a compliance boundary.** Every
   vulnerability known at submission must be assessed, so before a
   submission the list is reviewed with the cutoff at the submission date,
   or without a cutoff. The control says so, and which date serves which
   purpose according to the FDA guidance.
6. **Server-side**: the list, facets, Bulk Changes "Current list" and the
   MCP `search_vulnerabilities` tool (`cutoff`, `cutoff_mode`,
   `cutoff_basis`) use one implementation (`dtvp/first_seen.py`). Responses
   name the basis (`cutoff_basis`).
7. **Saved views**: a named filter state (canonical query string), for one
   project or any, `personal` or `global` (reviewers). Unknown parameters
   are rejected. A view with a cutoff stores its basis, so it shows the same
   later. Limits: 100 personal views per user, 200 global views.
8. **Short links only for saved views**: every view's code is its short
   link `/v/<code>` (8 random characters from
   `23456789abcdefghjkmnpqrstuvwxyz`). Unsaved filters are shared as the
   full URL. Any signed-in user can open any code; codes do not expire.
9. **Defaults**: my default per project or for all projects; reviewers set
   role defaults. Order: URL, my default for the project, for all projects,
   the role default for the project, for all projects, the built-in role
   default. Reset returns to the effective default.
10. **Storage**: migration namespace `saved_views` in the main database
    (`saved_views`, `saved_view_defaults`), served by `/api/views`; both are
    records of the instance dump (`dtvp.dump/1`, minor version 1).
11. **Configuration**: `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` is renamed
    `DTVP_CUTOFF_PRESET_DAYS`, without an alias.

## Alternatives

- **An instance-wide setting for the date.** Rejected: premarket and
  postmarket work need both dates at the same time.
- **A per-version attribution date.** Rejected: a re-uploaded version would
  look new; the project-wide attribution answers the monitoring question.
- **DTVP's own first-seen record as a fallback.** Rejected: a read time,
  empty or late before tracking; near a release the documented source date
  is preferred.
- **Unnamed short links for any filter state** (deduplicated, rate limited).
  Rejected: the full URL already shares unsaved filters; codes for named
  views are enough and need no dedupe or rate limit.
- **localStorage only**, **compressed URLs.** Rejected: no shared views,
  defaults or short codes; long opaque links.
- **Hiding findings after the cutoff inside a vulnerability.** Rejected, see
  decision 4.

## Consequences

- A database migration adds two tables; a dump with saved views is format
  minor version 1. An older release refuses it unless `--allow-unknown`
  drops the views. Rollback: the previous release ignores the tables.
- Deployments that set `DTVP_ATTRIBUTION_AGE_FILTER_DAYS` must rename it;
  the old name is ignored (breaking configuration change, in the release
  notes).
- The attribution-age facet key is now `cutoff`; group summaries carry the
  dates of both bases (`cutoff_dates`), so the summary cache and query index
  are rebuilt once.
- Records without a `published` date (internal advisories, some sources)
  are listed as unknown under the default basis.

## Confirmation

- `tests/test_first_seen_cutoff.py`: both bases, aliases, unknown dates,
  re-created versions, facets, Bulk Changes, retired parameters, the API;
  `tests/test_mcp_server.py`: the MCP parameters.
- `tests/test_saved_views.py`: CRUD, permissions, validation, the stored
  basis, defaults and precedence; `tests/test_backup_*`: dump round trip.
- `frontend/e2e/saved-views.spec.ts` (Chromium, Firefox, WebKit, mocked API,
  no 4xx/5xx): both bases with their FDA labels and help, saving, default,
  Reset, full link and short link.
- After deployment: the premarket list of a release keeps its count while
  versions are uploaded, and its "date unknown" count stays small.
