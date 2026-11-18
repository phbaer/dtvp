# CycloneDX Inventory And VDR

[Project overview](../README.md) · [Documentation index](../README.md#documentation)

| | |
| :--- | :--- |
| Status | Implemented |
| Decision | [ADR 0003](adr/0003-dtvp-is-the-record-for-assessments.md), decision 5 |
| Verified | 2026-11-18 against `tests/test_cyclonedx_export.py` and `tests/test_export.py`, a run against the mock Dependency-Track in Chromium, and by reading a generated VDR with the security documentation generator's CycloneDX reader (`from_cyclonedx` and `read_cyclonedx_fields` at its commit `6646bb8`). Not validated against the CycloneDX JSON schema. |

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
| `download` | `true` adds a file name (`<name>-<version>.<variant>.cdx.json`) | `false` |

The response is `application/vnd.cyclonedx+json`. It answers 404 when the
project version is unknown or has no BOM, 422 for an invalid prefix, and 503
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
| Advisory score and vector | A `ratings` entry with the advisory's `source.name` |
| Affected component | `affects[].ref`, the component's `bom-ref` in the BOM |
| State | `analysis.state` (`in_triage`, `not_affected`, `exploitable`, `false_positive`, `resolved`). Not set: no `analysis` |
| Justification | `analysis.justification`, for not-affected findings with a CycloneDX justification |
| Rationale (the General assessment, else the free text) | `analysis.detail` |
| Rescoring | A `ratings` entry whose `source.name` is the assessment source, with `score`, `severity`, `method`, `vector`, and the rationale as `justification` |
| One team's assessment | An entry in the BOM's `annotations`: `subjects` is the vulnerability's `bom-ref`, `annotator.organization.name` the team, `annotator.organization.contact[0].name` the assessor, `timestamp` the assessment date, `text` the team's text |
| Assessor, reviewer | Properties `<prefix>:assessed_by`, `<prefix>:reviewed_by` |
| Ticket references of the teams' assessments | Property `<prefix>:spr`, comma-separated |
| Pending review, suppressed | Properties `<prefix>:pending_review`, `<prefix>:suppressed` (`true`; absent otherwise) |
| State per team | One property `<prefix>:team_state` per team, as `<team>=<STATE>` |
| SSVC decision | Property `<prefix>:ssvc` |
| Free text beside a General assessment | Property `<prefix>:free_text` |

Historical team blocks are not exported. The document's
`metadata.properties` name the variant, the assessment source, and the DTVP
version (`<prefix>:export`, `<prefix>:export_assessment_source`,
`<prefix>:export_tool`).

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
```

## Limits

- **Annotator.** CycloneDX allows one annotator per annotation, so the team
  is the annotating organization and the assessor its contact. A reader that
  expects the assessor in `annotator.individual` finds none.
- **Undated team assessments** carry the export time as `timestamp`, because
  CycloneDX requires one.
- **Tickets** are the ticket references recorded with a team's assessment.
  A key that is only mentioned in the text is not extracted.
- **Assessed findings whose text could not be read** from Dependency-Track
  are counted in `metadata.properties` as
  `<prefix>:export_incomplete_findings` and listed with their state only.
- A component that a finding names but the BOM does not list is added to
  both documents with the name, version, and package URL the finding has,
  and the property `<prefix>:added_from_finding`. Every `affects` reference
  therefore resolves in the inventory as well.
- Dependency-Track's own justification, response, and comment fields are not
  part of DTVP's record and are not exported.
