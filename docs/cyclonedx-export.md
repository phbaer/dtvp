# CycloneDX Inventory And VDR

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md), decision 5 |
| Verified | 2026-11-19: the consumer read a second export of a real project version after the first fixes and found the eight gaps closed; historical team assessments, the date fallback and the prefix property were added after that reading and are checked against `tests/test_cyclonedx_export.py` only. 2026-11-18 against `tests/test_cyclonedx_export.py` and `tests/test_export.py`, a run against the mock Dependency-Track in Chromium, and by reading a generated VDR with the security documentation generator's CycloneDX reader (`from_cyclonedx` and `read_cyclonedx_fields` at its commit `6646bb8`). The inventory and the VDR are validated against the official CycloneDX 1.5 JSON schema (strict) in `tests/test_cyclonedx_export.py`. `analysis.response` was added on 2026-11-19 and is checked against that test file and schema only; no consumer has read it yet. 2026-11-20: undated annotations, `annotation_dated_by_assessment` and `unassigned_state` (keyed by the assessor) checked against `tests/test_cyclonedx_export.py` and the CycloneDX 1.5 and 1.6 schemas only; no consumer has read them yet. |

River serves two CycloneDX documents for each project version:

- **Inventory**: the BOM as imported from Dependency-Track.
- **VDR** (vulnerability disclosure report): the BOM plus every finding with
  River's assessment in standard CycloneDX fields. A consumer does not have to
  parse River's markup out of an analysis text.

The documents come from River's own records. An assessment that has not been
exported to Dependency-Track yet is already in the VDR.

- [Getting The Documents](#getting-the-documents)
- [Two Documents And How They Belong Together](#two-documents-and-how-they-belong-together)
- [What The VDR Contains](#what-the-vdr-contains)
- [Naming The Rating Source And Properties](#naming-the-rating-source-and-properties)
- [Limits](#limits)
- [Recommendation](#recommendation)

## Getting The Documents

**In the UI:** the **CycloneDX** button in a project's toolbar lists the
project's versions, each with an **Inventory** and a **VDR** download.

**Through the API**, with a browser session or a
[personal access token](ai-access.md) with the read scope. The token is sent
as `Authorization: Bearer <token>` or as `X-Api-Key: <token>`:

| Request | Result |
| :--- | :--- |
| `GET /api/project/{project_uuid}/cyclonedx?variant=vdr` | By project version UUID |
| `GET /api/cyclonedx?name=<product>&version=<version>&variant=vdr` | By product name and version |

Parameters of both:

| Parameter | Values | Default |
| :--- | :--- | :--- |
| `variant` | `inventory`, `vdr` | `vdr` |
| `assessment_source` | Name of River's own rating source | `DTVP_CYCLONEDX_ASSESSMENT_SOURCE`, else `DTVP` |
| `property_prefix` | Namespace of the properties; letters, digits, `.`, `_`, `-` | `DTVP_CYCLONEDX_PROPERTY_PREFIX`, else `dtvp` |
| `ticket_prefixes` | Comma-separated project keys of ticket references to recognise in assessment texts (`EXP` for `EXP-123`); each a letter, then letters, digits, `_` | `DTVP_CYCLONEDX_TICKET_PREFIXES`, else none |
| `download` | `true` adds a file name (`<name>-<version>.<variant>.cdx.json`) | `false` |

The response is `application/vnd.cyclonedx+json`. It answers 404 when the
project version is unknown or has no BOM, 422 for an invalid property or
ticket prefix, and 503
when the project is not stored locally and Dependency-Track cannot be read.

```bash
curl -H "Authorization: Bearer $DTVP_TOKEN" \
  "https://dtvp.example/api/cyclonedx?name=App&version=1.4.0&variant=vdr" \
  -o App-1.4.0.vdr.cdx.json
```

## Two Documents And How They Belong Together

The inventory describes a release and changes only when its components do.
The VDR changes with every new advisory and every revised assessment. They are
two documents so that a new assessment does not make the inventory another
file.

- **The inventory has a stable serial number.** It is derived from what the
  inventory lists (the described component, the components, services,
  dependencies and compositions), so the same content has the same
  `serialNumber` in every export, in any order and under any property prefix.
  `version` is always 1: a changed inventory is a new BOM with a new serial
  number. Dependency-Track's own serial number, which is new with every one of
  its exports, is not kept. The timestamp is not part of the identity.
- **The VDR is a new document with every export** and names the inventory it
  describes as a [BOM-Link](https://cyclonedx.org/capabilities/bomlink/):
  `externalReferences` has an entry of type `bom` with the URL
  `urn:cdx:<inventory serial number>/1`, and `metadata.properties` repeats it
  as `<prefix>:export_inventory`.
- **To check that two files belong together**, compare that link with the
  inventory's `serialNumber` and `version`. An inventory exported later
  matches as long as the components did not change.

The VDR still lists the components itself, so that every `affects` reference
resolves inside it; a reader needs the inventory file only as the release
artefact.

## What The VDR Contains

Every finding of the project version is listed, also those in triage and
those without an assessment. Findings of one vulnerability that share the same
assessment are one `vulnerabilities` entry with several `affects`; findings
with differing assessments are separate entries (the second has the
`bom-ref` `<uuid>#2`; which one is second follows the identity of the
affected components (package URL, else name and version) and then the
assessment without its review state, so a split keeps its `bom-ref`s from
export to export, also when Dependency-Track recreates a component under a
new ID or one of the entries is approved). Findings that differ only in the response are
separate entries as well.

| River | CycloneDX |
| :--- | :--- |
| Vulnerability ID, source, aliases, description, CWEs | `id`, `source.name`, `references`, `description`, `cwes`. `references` lists every alias River knows: those the vulnerability's own record names and those of the other findings' records (a CVE whose record names no GitHub advisory still lists the advisory whose record names the CVE). Each reference has `id` and `source.name` (`NVD` for CVE ids, `GITHUB` for GHSA ids, else the alias's source in Dependency-Track) |
| Recommendation: Dependency-Track's, else derived from the fixed version of the range that contains the component's version | `recommendation`, see [Recommendation](#recommendation) |
| Publication and last change of the advisory | `published`, `updated`, as date-times in UTC (`2026-04-24T19:17:14+00:00`) |
| Advisory scores and vectors | One `ratings` entry per CVSS version the advisory has (4.0, 3.x, 2.0, in this order), with the advisory's `source.name`, `method`, `vector`, `score`, and the `severity` of that score. A version with a vector and no score gets the score its vector states. An advisory without CVSS data has one rating with its severity only |
| Affected component | `affects[].ref`, the component's `bom-ref` in the BOM |
| State | `analysis.state` (`in_triage`, `not_affected`, `exploitable`, `false_positive`, `resolved`). Not set: no `analysis` |
| Justification | `analysis.justification`, for not-affected findings with a CycloneDX justification |
| [Response](assessment-model.md#response) | `analysis.response`, a list with the one value in lower case (`update`, `rollback`, `workaround_available`, `will_not_fix`, `can_not_fix`). Not set: no `response` |
| Rationale (the General assessment, else the free text) | `analysis.detail`, without former team notes and without `[Assessed by: …]` and `[Reviewed by: …]` tags |
| Date of the assessment | `analysis.lastUpdated`: the date of the General assessment, or, when it has none, the latest date of the live team assessments. A reviewer's approval keeps the date, so it is when the assessment was last written. River does not record when it was first made: no `analysis.firstIssued` |
| Rescoring | A `ratings` entry whose `source.name` is the assessment source, with `score`, `severity`, `method`, `vector`, and the rationale as `justification`. A rescoring that has a score and no CVSS vector has the `method` `other` and no `vector` |
| One team's assessment | An entry in the BOM's `annotations`: `subjects` is the vulnerability's `bom-ref`, `annotator.organization.name` the team, `annotator.organization.contact[0].name` the assessor, `text` the team's text. `timestamp` is the team's date; without one, the date of the assessment (the source of `analysis.lastUpdated`, also when the state is not set) and `<prefix>:annotation_dated_by_assessment`; without either, the export time and `<prefix>:undated_annotation`. A team whose text only says "See global assessment." has no annotation |
| An annotation dated by its assessment (the team recorded no date) | One property `<prefix>:annotation_dated_by_assessment` per such annotation, in annotation order. The value is the annotator's name: the team, or the assessor of an assessment without a team. The date is when the assessment was last written, not the team's own, see [Limits](#limits) |
| An annotation without any recorded date | One property `<prefix>:undated_annotation` per such annotation, in annotation order. The value is the annotator's name: the team, or the assessor of an assessment without a team |
| Assessor, reviewer | Properties `<prefix>:assessed_by`, `<prefix>:reviewed_by`, from the assessments' fields and from `[Assessed by: …]`, `[Reviewed by: …]` tags inside their texts |
| Same issue, confirmed | Property `<prefix>:same_issue_as`, comma-separated ids: on the entry of a finding a reviewer confirmed to be the same issue as another one that no source names as its alias, proposed by the same description (see [Gone findings](review-workflows.md)). River's record, not a source's: never in `references`, and absent for an unconfirmed guess |
| Ticket references | Property `<prefix>:spr`, comma-separated: the tickets recorded with the live and the historical team assessments, then the keys the texts mention (live ones, former team notes and historical ones), if ticket prefixes are configured. A ticket is about the vulnerability in the product, not about who owned the component |
| Pending review, suppressed | Properties `<prefix>:pending_review`, `<prefix>:suppressed` (`true`; absent otherwise) |
| Version override ([ADR 0010](adr/0010-version-overrides.md)) | When this project version has its own assessment of the vulnerability: `<prefix>:assessment_scope` `version_override`, `<prefix>:version_override` (the label), `<prefix>:version_override_reason` (when the findings agree on one) and `<prefix>:version_override_status` (`pending` until a reviewer approves the override, then `approved`), on every entry of the vulnerability in this version, inherited unassessed findings included. `assessment_scope` `ambiguous` alone when the version's findings carry two labels. No property means the base assessment. The status is the override's; `pending_review` stays the entry's own. A recommendation next to a NOT_AFFECTED override is intended: it is about the package, not the decision |
| State per team | One property `<prefix>:team_state` per team, as `<team>=<STATE>` |
| State of an assessment without a team | One property `<prefix>:unassigned_state` per such assessment, as `<assessor>=<STATE>` (`-` without an assessor), see [Assessments Without A Team](#assessments-without-a-team) |
| SSVC decision | Property `<prefix>:ssvc` |
| Free text beside a General assessment | Property `<prefix>:free_text` |
| Assessments of teams that no longer own the component, as earlier repairs noted them in the General assessment | One property `<prefix>:former_assessment` per note, as written ("Former team assessment (…)…"). The repair now keeps such assessments as historical blocks (next row); notes come only from earlier repairs |
| Where the recommendation comes from | Property `<prefix>:recommendation_source` (`advisory`, `fixed_version`), and for a derived one `<prefix>:recommendation_fixed_by` per mirror, see [Recommendation](#recommendation) |
| Team assessments marked historical (the team no longer owns the component, a save left the block out, or the repair kept it) | One property `<prefix>:historical_assessment` per assessment. The value is a JSON object with `team`, `state`, and where recorded `justification`, `assessed_by`, `reviewed_by`, `date`, `ticket`, `text`. Not a `team_state` and not an annotation |

The document's `metadata.properties` name the variant, the assessment source,
the property prefix, and the River version (`<prefix>:export`,
`<prefix>:export_assessment_source`, `<prefix>:export_property_prefix`,
`<prefix>:export_tool`), and what a reader should know about the document:

| Property | Meaning |
| :--- | :--- |
| `<prefix>:export_findings_read_at` | When the findings were last read from Dependency-Track, as a date-time in UTC. The document lists the findings of that import: what Dependency-Track has reported or assessed since is not in it. Open or refresh the project in River before an export that has to be current |
| `<prefix>:export_ticket_prefixes` | The ticket prefixes the texts were searched for. Absent: no text was searched |
| `<prefix>:export_text_only_tickets` | Number of entries with a ticket key that only a text mentions; their records lack the ticket field |
| `<prefix>:export_historical_assessments` | Number of historical team assessments in the document. Absent: none |
| `<prefix>:export_findings_gone` | Findings of this project version Dependency-Track no longer reports and River still follows, one property per reason with `<reason>=<count>`, sorted by reason: `replaced` (another version of the component has the vulnerability), `component_removed` (only with the component's identity known), `no_longer_matched`, `undetermined`, `missing_at_export`. Counts every such finding gone now, not only at the last read, so two exports in a row agree. A finding on a component Dependency-Track recreated (same name and version under a new ID, typically a BOM uploaded again) is not counted: it stands for an earlier generation of a component that is reported again, see the next row. Those findings are not listed. Absent: none. See [Findings that disappear](import-export.md#findings-that-disappear). Until 2.0.0rc2 this counted recreated components as `replaced` |
| `<prefix>:export_findings_gone_predating` | Gone findings followed from assessment records older than finding tracking whose reason no read has told yet, by reason (`undetermined=4942`). Not counted in `export_findings_gone`: most stand for earlier generations of findings still reported, and once their component is known they are classified like any gone finding. Absent: none |
| `<prefix>:export_findings_recreated` | Number of findings that only stand for an earlier generation of a recreated component; their assessments followed the component. Not counted in `export_findings_gone`. Absent: none |
| `<prefix>:export_findings_gone_last_read_at`, `<prefix>:export_findings_gone_last_read` | The last read of the findings from Dependency-Track, as a date-time in UTC: when River asked Dependency-Track for them. `export_findings_read_at` is when the same read was stored, after its response arrived, so on a large project it is seconds later; the two differ only by how long the read took, and the findings that went at it, one property per reason with `<reason>=<count>`, `recreated` apart from `replaced`. The time is there whenever a finding is gone; the counts are absent when nothing went at the last read. Absent altogether: nothing gone, or no read recorded |
| `<prefix>:export_findings_followed_since` | When River started following this version's findings, as a date-time in UTC: counts start there. Absent: nothing gone |
| `<prefix>:export_findings_gone_attention` | Number of gone findings that need a person and nobody acknowledged: their assessment did not carry over, or was exploitable, in triage or ticketed (see [Gone findings](review-workflows.md#gone-findings)). Findings followed from assessment records older than finding tracking (first seen unknown) count here, but do not move `export_findings_followed_since`. Absent: none needs attention (an acknowledged finding does not count), or nothing gone |
| `<prefix>:export_advisory_records` | `unavailable`: the vulnerability records could not be read, see [Limits](#limits) |
| `<prefix>:export_incomplete_findings` | Number of assessed findings whose text could not be read, see [Limits](#limits) |
| `<prefix>:export_derived_recommendations`, `<prefix>:export_fixed_versions_unread`, `<prefix>:export_fixed_versions_read_at` | Derived recommendations, see [Recommendation](#recommendation) |

### Assessments Without A Team

The team mapping names a fallback team (the team owning `*`, for example `Unknown`) for
components no team owns. An assessment under that name is not a team's:

- its state is the property `<prefix>:unassigned_state`, as
  `<assessor>=<STATE>` (for example `rita=EXPLOITABLE`), or `-=<STATE>` when
  it names no assessor; it has no `<prefix>:team_state`. Several such
  assessments are listed in block order;
- its text is an annotation by the assessor, as `annotator.individual.name`:
  the state with the same assessor belongs to it;
- without an assessor the text is the property
  `<prefix>:unassigned_assessment`, and the state is the one keyed `-`.

Several assessments without a team pair by the assessor. Those with the same
assessor, or several without one, pair in block order only when each has a
text; see [Limits](#limits).

The name is that of the team mapping at the time of the export. A team of the
same name that the mapping assigns components to is not distinguished from it.

## Naming The Rating Source And Properties

A consumer finds River's rescoring by the rating's `source.name` and the
properties by their prefix. The security documentation generator configures
both per product (`assessment_source` and `sbom_property_prefix` in its
`product.yaml`) and passes them as request parameters. Lines for `.env` (and
`.env.dist` as the documented template) to change the defaults:

```dotenv
# Name of River's own rating source in CycloneDX VDR exports.
# DTVP_CYCLONEDX_ASSESSMENT_SOURCE=DTVP
# Namespace of the properties River writes into CycloneDX VDR exports.
# DTVP_CYCLONEDX_PROPERTY_PREFIX=dtvp
# Project keys of ticket references to recognise in assessment texts.
# DTVP_CYCLONEDX_TICKET_PREFIXES=EXP,SEC
```

## Limits

- **Annotator.** CycloneDX allows one annotator per annotation, so the team
  is the annotating organization and the assessor its contact. A reader that
  expects the assessor in `annotator.individual` finds none.
- **Undated annotations.** A CycloneDX 1.5–1.7 annotation requires a
  `timestamp` and allows no properties. An annotation without any date
  therefore carries the export time and is named on the vulnerability by
  `<prefix>:undated_annotation`.
- **An annotation dated by its assessment** carries when the assessment as a
  whole was last written: the General assessment's date, else the latest date
  of another team. It is not the team's own date, which River did not record,
  and it can be earlier than when the team wrote its text (for example a text
  edited in Dependency-Track and imported later). The vulnerability names
  such an annotation by `<prefix>:annotation_dated_by_assessment`.
- **Several assessments without a team** pair state and text by the assessor
  (`unassigned_state` is keyed by it). An assessment whose text only refers
  to the General one has a state and no text, so several of them with the
  same assessor, or without any, cannot be told apart beyond block order.
- **Tickets.** River has no list of ticket systems. A key in a text is
  recognised only for the prefixes given with the request or configured, as
  `<prefix>-<number>`; without them only the ticket fields are exported.
  Former and historical assessments are searched too.
- **Advisory data** beyond a finding's summary (every CVSS version, `updated`,
  `recommendation`, `patchedVersions`) comes from Dependency-Track's vulnerability records of
  the project. If they are neither stored nor readable, the document has the
  finding's values only and says so with `<prefix>:export_advisory_records`.
  A CVSS vector that cannot be read is exported without a score.
- **Former team notes** are recognised by the line earlier repairs wrote
  ("Former team assessment (…)"); the repair now keeps a former team's block
  as a historical assessment instead. Nothing marks where such a note ends:
  everything from the first note to the end of the General assessment is
  exported as former assessments, also text that was added below a note
  later.
- **People in a text** are read from `[Assessed by: …]` and
  `[Reviewed by: …]` tags only. A name in prose is not recognised.
- **Assessed findings whose text could not be read** from Dependency-Track
  are counted in `metadata.properties` as
  `<prefix>:export_incomplete_findings` and listed with their state only.
- A component that a finding names but the BOM does not list is added to
  both documents with the name, version, and package URL the finding has,
  and the property `<prefix>:added_from_finding`. Every `affects` reference
  therefore resolves in the inventory as well.
- What Dependency-Track holds in its own justification, response, and
  comment fields is not read. The justification and the response in the VDR
  are those of River's record.

## Recommendation

| | |
| :--- | :--- |
| Status | Implemented; checked against `tests/test_fixed_versions.py`, `tests/test_cyclonedx_export.py` and `tests/test_dt_cache.py` only. No consumer has read a derived recommendation yet |
| Decision | [ADR 0007](adr/0007-recommendation-from-dependency-track-ranges.md) |
| Source read | 2026-11-20: Dependency-Track 4.13.x and 4.14.x sources (`VulnerabilityResource`, `AffectedComponent`, `ComponentVersion`, `AbstractVulnerableSoftwareAnalysisTask`, `OsvAdvisoryParser`); the deployed 4.14.2 was not queried |

Dependency-Track fills a vulnerability's `recommendation` only for
vulnerabilities maintained by hand; its NVD, GitHub advisory and OSV mirrors
do not set it. They do store, per vulnerability, the affected packages with
version ranges. River derives the recommendation from those ranges.

**Where the ranges come from.** `GET /api/v1/vulnerability/source/{source}/vuln/{vulnId}`
(permission `VIEW_PORTFOLIO`, which River's API key already needs) returns
them as `affectedComponents`: an identity (package URL or CPE), either an
exact `version` or the bounds `versionStartIncluding`,
`versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`, and
`affectedVersionAttributions` naming the mirrors that reported the range.
Only these fields are kept, with the distinct mirror names. The answer also
lists the components of every project the vulnerability affects; they are
dropped in the client before anything is stored.

**When they are read.** In the background only, as the last step of a
project refresh (see [Runtime](runtime.md)):

- for the vulnerabilities of the project's records whose `recommendation` is
  empty;
- when the database has no ranges for the vulnerability yet, the record's
  `updated` differs from the one stored with the ranges, or the ranges are
  older than `DTVP_FIXED_VERSIONS_REFRESH_DAYS` (default 7). An answer of 404
  is stored as not found and asked again after the same time. A failed read
  keeps the ranges read before and is retried after a delay that doubles
  with each failure in a row: one minute, two, four, up to one day. A good
  read or a 404 resets it;
- at most `DTVP_FIXED_VERSIONS_READS_PER_CYCLE` (default 200) reads per
  refresh cycle, four at a time. Vulnerabilities never read come first, then
  changed or stale ones, then failed ones whose delay has passed, the
  longest waiting first, so reads that keep failing cannot use up the cycle.
  The rest follows in later cycles;
- once per vulnerability for all projects: the ranges are stored per
  (source, vulnerability ID), and one read of a vulnerability is in flight
  at a time.

An export reads the stored ranges and never asks Dependency-Track for them.
The table `source_vulnerability_ranges` holds rebuildable source data and is
not part of a project archive.

**Which range applies.** Per affected component of an entry:

1. The candidates are the ranges whose identity is the component's: a
   package URL with the same type, namespace and name (case-insensitive
   except for Maven; PyPI names normalised); if both name a `distro`
   qualifier it must be the same, other qualifiers are ignored. Or a CPE
   (2.3 or 2.2) with the same vendor and product, and no other attribute
   (part, update, edition, language, software edition, target software,
   target hardware, other) that both name with different values; a `*` on
   either side matches, as in Dependency-Track's CPE matching. A component
   with neither identity gets no recommendation.
2. The ranges among them that contain the component's version, compared as
   Dependency-Track compares versions (a port of its `ComponentVersion`).
   This holds for a single range too: that the finding was reported does
   not say which range applies, since OSS Index, Trivy and Snyk report
   findings as well, and a range under a package URL without a `distro`
   qualifier may be another release's. A component without a version that
   can be compared (none, `*`, `-`) gets no fix.
3. If every containing range ends with the same `versionEndExcluding`, and
   that version is above the component's, it is the fixed version. An end
   that is included, an open end, ends that differ, exact versions only, or
   no containing range: no fix.
4. If another range of the component contains the fixed version, the fixed
   version moves to that range's end, as often as needed; if that range has
   an included or open end, or an exact version of the component is the
   fixed version, there is no fix.

**The text.**

| Case | `recommendation` |
| :--- | :--- |
| A fixed version | `Upgrade <name> <installed versions> to <version> or later.` One sentence per fixed version: every package with that fix is named, with its installed versions in version order (`Upgrade @angular/animations 20.1.3, 20.1.4; @angular/common 20.3.1 to 20.3.15 or later.`). Sentences in order of the fixed version |
| Another range or an exact version of the package starts at or above the fixed version | `… Later versions are affected too: >=3.0.0 <3.0.2, 3.1.4.` (each range or version, in version order, comma-separated) |
| No fix for one package, a fix for another of the same entry | `No fixed version is known for <name> <installed versions>.`, one sentence for all such packages, so every affected package is named |
| No fix for any package | No `recommendation` |

The record's `patchedVersions` is never the recommendation. Trivy sets it
once, from the package and distribution of whichever project created the
record, and Dependency-Track does not update it, so it says nothing about
another component. It is exported as the property
`<prefix>:patched_versions`, unchecked.

`<name>` is `group:name` for Maven, `group/name` for other packages with a
group or namespace (`@scope/name`), else the name; the package URL's name
and namespace come first, as they name the installed package (`sqlite3`
where the component is called `sqlite`). Sentences are sorted by name. An entry that affects
several components has one sentence per component, distinct, sorted by name
and joined with a space. Dependency-Track's own recommendation is always
kept as it is.

**Provenance.**

| Property | Where | Meaning |
| :--- | :--- | :--- |
| `<prefix>:recommendation_source` | Entry | `advisory`: Dependency-Track's text. `fixed_version`: derived here |
| `<prefix>:recommendation_fixed_by` | Entry, derived only | One per mirror that reported a range the fixed version comes from (`GITHUB`, `OSV`, `NVD`, …) |
| `<prefix>:patched_versions` | Entry without Dependency-Track's own text | The record's `patchedVersions` as it is: a hint, not checked against the component's version, package or distribution |
| `<prefix>:export_derived_recommendations` | Metadata, always | Number of entries with a derived text, possibly `0` |
| `<prefix>:export_fixed_versions_unread` | Metadata | Number of entries without a recommendation whose ranges have not been read yet (no read, or only failed ones). Absent when `0` |
| `<prefix>:export_fixed_versions_read_at` | Metadata | The oldest read of the ranges the document used |

The inventory does not change: its serial number is the same with and
without derived recommendations.

**Limits.**

- OSV's `limit` event is stored by Dependency-Track as
  `versionEndExcluding`, like `fixed`. A range that ends at a limit reads as
  fixed there.
- Findings that only OSS Index reports have no ranges in Dependency-Track:
  no derived recommendation.
- Ranges of different mirrors that disagree about the fix give none; nothing
  is guessed.
- Dependency-Track does not compare the Ubuntu suffix of a deb version
  (`3.0.2-0ubuntu1.10` equals `3.0.2-0ubuntu1.12`). A fix within the same
  upstream version of an Ubuntu package is therefore not found.
- A failed read is asked again after its delay, up to once a day, for as
  long as it fails.
- No fix means no field. A reviewer cannot overwrite the derived text per
  finding.
- The first export of a project after the feature, or of a vulnerability
  that is new, may come before the background read: the entry has no
  derived text yet, and `export_fixed_versions_unread` counts it.
