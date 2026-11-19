# CycloneDX Inventory And VDR

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md), decision 5 |
| Verified | 2026-11-19: the consumer read a second export of a real project version after the first fixes and found the eight gaps closed; historical team assessments, the date fallback and the prefix property were added after that reading and are checked against `tests/test_cyclonedx_export.py` only. 2026-11-18 against `tests/test_cyclonedx_export.py` and `tests/test_export.py`, a run against the mock Dependency-Track in Chromium, and by reading a generated VDR with the security documentation generator's CycloneDX reader (`from_cyclonedx` and `read_cyclonedx_fields` at its commit `6646bb8`). The inventory and the VDR are validated against the official CycloneDX 1.5 JSON schema (strict) in `tests/test_cyclonedx_export.py`. |

DTVP serves two CycloneDX documents for each project version:

- **Inventory**: the BOM as imported from Dependency-Track.
- **VDR** (vulnerability disclosure report): the BOM plus every finding with
  DTVP's assessment in standard CycloneDX fields. A consumer does not have to
  parse DTVP's markup out of an analysis text.

The documents come from DTVP's own records. An assessment that has not been
exported to Dependency-Track yet is already in the VDR.

- [Getting The Documents](#getting-the-documents)
- [What The VDR Contains](#what-the-vdr-contains)
- [Naming The Rating Source And Properties](#naming-the-rating-source-and-properties)
- [Limits](#limits)
- [Planned](#planned)

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
| `assessment_source` | Name of DTVP's own rating source | `DTVP_CYCLONEDX_ASSESSMENT_SOURCE`, else `DTVP` |
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

## What The VDR Contains

Every finding of the project version is listed, also those in triage and
those without an assessment. Findings of one vulnerability that share the same
assessment are one `vulnerabilities` entry with several `affects`; findings
with differing assessments are separate entries (the second has the
`bom-ref` `<uuid>#2`).

| DTVP | CycloneDX |
| :--- | :--- |
| Vulnerability ID, source, aliases, description, recommendation, CWEs | `id`, `source.name`, `references`, `description`, `recommendation`, `cwes` |
| Publication and last change of the advisory | `published`, `updated`, as date-times in UTC (`2026-04-24T19:17:14+00:00`) |
| Advisory scores and vectors | One `ratings` entry per CVSS version the advisory has (4.0, 3.x, 2.0, in this order), with the advisory's `source.name`, `method`, `vector`, `score`, and the `severity` of that score. A version with a vector and no score gets the score its vector states. An advisory without CVSS data has one rating with its severity only |
| Affected component | `affects[].ref`, the component's `bom-ref` in the BOM |
| State | `analysis.state` (`in_triage`, `not_affected`, `exploitable`, `false_positive`, `resolved`). Not set: no `analysis` |
| Justification | `analysis.justification`, for not-affected findings with a CycloneDX justification |
| Rationale (the General assessment, else the free text) | `analysis.detail`, without former team assessments and without `[Assessed by: …]` and `[Reviewed by: …]` tags |
| Date of the assessment | `analysis.lastUpdated`: the date of the General assessment, or, when it has none, the latest date of the live team assessments. A reviewer's approval keeps the date, so it is when the assessment was last written. DTVP does not record when it was first made: no `analysis.firstIssued` |
| Rescoring | A `ratings` entry whose `source.name` is the assessment source, with `score`, `severity`, `method`, `vector`, and the rationale as `justification`. A rescoring that has a score and no CVSS vector has the `method` `other` and no `vector` |
| One team's assessment | An entry in the BOM's `annotations`: `subjects` is the vulnerability's `bom-ref`, `annotator.organization.name` the team, `annotator.organization.contact[0].name` the assessor, `timestamp` the assessment date, `text` the team's text. A team whose text only says "See global assessment." has no annotation |
| Assessor, reviewer | Properties `<prefix>:assessed_by`, `<prefix>:reviewed_by`, from the assessments' fields and from `[Assessed by: …]`, `[Reviewed by: …]` tags inside their texts |
| Ticket references | Property `<prefix>:spr`, comma-separated: the tickets recorded with the live and the historical team assessments, then the keys the texts mention (live, former and historical ones), if ticket prefixes are configured. A ticket is about the vulnerability in the product, not about who owned the component |
| Pending review, suppressed | Properties `<prefix>:pending_review`, `<prefix>:suppressed` (`true`; absent otherwise) |
| State per team | One property `<prefix>:team_state` per team, as `<team>=<STATE>` |
| SSVC decision | Property `<prefix>:ssvc` |
| Free text beside a General assessment | Property `<prefix>:free_text` |
| Assessments of teams that no longer own the component, as the repair noted them in the General assessment | One property `<prefix>:former_assessment` per note, as written ("Former team assessment (…)…") |
| Team assessments marked historical (the team no longer owns the component) | One property `<prefix>:historical_assessment` per assessment. The value is a JSON object with `team`, `state`, and where recorded `justification`, `assessed_by`, `reviewed_by`, `date`, `ticket`, `text`. Not a `team_state` and not an annotation |

The document's `metadata.properties` name the variant, the assessment source,
the property prefix, and the DTVP version (`<prefix>:export`,
`<prefix>:export_assessment_source`, `<prefix>:export_property_prefix`,
`<prefix>:export_tool`), and what a reader should know about the document:

| Property | Meaning |
| :--- | :--- |
| `<prefix>:export_findings_read_at` | When the findings were last read from Dependency-Track, as a date-time in UTC. The document lists the findings of that import: what Dependency-Track has reported or assessed since is not in it. Open or refresh the project in DTVP before an export that has to be current |
| `<prefix>:export_ticket_prefixes` | The ticket prefixes the texts were searched for. Absent: no text was searched |
| `<prefix>:export_text_only_tickets` | Number of entries with a ticket key that only a text mentions; their records lack the ticket field |
| `<prefix>:export_historical_assessments` | Number of historical team assessments in the document. Absent: none |
| `<prefix>:export_advisory_records` | `unavailable`: the vulnerability records could not be read, see [Limits](#limits) |
| `<prefix>:export_incomplete_findings` | Number of assessed findings whose text could not be read, see [Limits](#limits) |

### Assessments Without A Team

The team mapping names a fallback team (key `*`, for example `Unknown`) for
components no team owns. An assessment under that name is not a team's:

- it has no `<prefix>:team_state`;
- its text is an annotation by the assessor, as `annotator.individual.name`;
- without an assessor the text is the property
  `<prefix>:unassigned_assessment`.

The name is that of the team mapping at the time of the export. A team of the
same name that the mapping assigns components to is not distinguished from it.

## Naming The Rating Source And Properties

A consumer finds DTVP's rescoring by the rating's `source.name` and the
properties by their prefix. The security documentation generator configures
both per product (`assessment_source` and `sbom_property_prefix` in its
`product.yaml`) and passes them as request parameters. Lines for `.env` (and
`.env.dist` as the documented template) to change the defaults:

```dotenv
# Name of DTVP's own rating source in CycloneDX VDR exports.
# DTVP_CYCLONEDX_ASSESSMENT_SOURCE=DTVP
# Namespace of the properties DTVP writes into CycloneDX VDR exports.
# DTVP_CYCLONEDX_PROPERTY_PREFIX=dtvp
# Project keys of ticket references to recognise in assessment texts.
# DTVP_CYCLONEDX_TICKET_PREFIXES=EXP,SEC
```

## Limits

- **Annotator.** CycloneDX allows one annotator per annotation, so the team
  is the annotating organization and the assessor its contact. A reader that
  expects the assessor in `annotator.individual` finds none.
- **Undated team assessments** carry the export time as `timestamp`, because
  CycloneDX requires one.
- **Tickets.** DTVP has no list of ticket systems. A key in a text is
  recognised only for the prefixes given with the request or configured, as
  `<prefix>-<number>`; without them only the ticket fields are exported.
  Former and historical assessments are searched too.
- **Advisory data** beyond a finding's summary (every CVSS version, `updated`,
  `recommendation`) comes from Dependency-Track's vulnerability records of
  the project. If they are neither stored nor readable, the document has the
  finding's values only and says so with `<prefix>:export_advisory_records`.
  A CVSS vector that cannot be read is exported without a score.
- **Former team assessments** are recognised by the line the repair writes
  ("Former team assessment (…)"). Nothing marks where such a note ends:
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
- Dependency-Track's own justification, response, and comment fields are not
  part of DTVP's record and are not exported.

## Planned

| | |
| :--- | :--- |
| Status | Proposed; not implemented |
| Recorded | 2026-11-19 |

### A Recommendation From Published Fixed Versions

**Why.** `recommendation` is exported when Dependency-Track's vulnerability
record has one. Dependency-Track fills it only for manually maintained
vulnerabilities: its importers for NVD, GitHub advisories and OSV do not set
it (read in the 4.13.x sources on 2026-11-19; the deployed 4.14.2 was not read
separately). A real project version therefore has none.

**What.** Derive it from the fixed versions that GitHub advisories and OSV
publish per package and version range, for example "Upgrade lib-a to 1.2.3 or
later". A recommendation Dependency-Track has stays as it is.

**To decide.**

- Which source is asked, and how results are cached and refreshed. It is a
  new outbound data source.
- With several fix lines, which one applies to the component version in the
  product.
- Without a fix: say so, or leave the field out.
- Whether a reviewer can overwrite the derived text per finding.
- How the document states where the recommendation comes from.

**Done when** a vulnerability with a published fixed version has
`recommendation` in the VDR, the export says which entries have a derived one,
and this page describes the mapping.
