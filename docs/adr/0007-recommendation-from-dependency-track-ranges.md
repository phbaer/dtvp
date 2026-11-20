# ADR 0007: The VDR recommendation comes from the ranges Dependency-Track holds

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Proposed (2026-11-20); becomes Accepted when the repository owner merges it |
| Implementation status | Implemented (2026-11-20) on branch `feat/vdr-recommendation`; verified against the tests named in [Confirmation](#confirmation) only |
| Related | [ADR 0002](0002-local-first-database-with-import-and-export.md) (ports, local database), [ADR 0003](0003-dtvp-is-the-record-for-assessments.md) decision 5 (CycloneDX export) |
| Reference | [CycloneDX export: Recommendation](../cyclonedx-export.md#recommendation) |

## Context

A VDR's `recommendation` tells a reader what to do about a vulnerability.
DTVP exported only what Dependency-Track's vulnerability record has there,
and Dependency-Track fills it only for vulnerabilities maintained by hand;
its NVD, GitHub advisory and OSV mirrors do not set it. A real project
version therefore had none.

The mirrors do store, per vulnerability, the affected packages with version
ranges (`VulnerableSoftware`), and Dependency-Track matches components
against them. The end of the range that contains a component's version is the
first fixed version. Read in the 4.13.x and 4.14.x sources on 2026-11-20:

- `GET /api/v1/vulnerability/source/{source}/vuln/{vuln}` returns them as
  `affectedComponents` with identity, exact version or four bounds, and the
  mirrors that reported them (`affectedVersionAttributions`), with
  permission `VIEW_PORTFOLIO`.
- The project endpoint `GET /api/v1/vulnerability/project/{uuid}`, which
  DTVP already reads, does not: `vulnerableSoftware` is not serialised.
  Its records do carry `patchedVersions`, which Trivy fills once, from the
  package and distribution that created the record; it is not updated.
- OSV's `fixed` and `limit` both become `versionEndExcluding`.

## Drivers

- No new outside service: DTVP sends nothing about the deployment anywhere
  but Dependency-Track.
- An export stays a local read: no Dependency-Track call per request.
- What is stored must not hold portfolio-wide data of other projects.
- No guessed fix: a wrong recommendation is worse than none.
- A reader can tell a derived text from Dependency-Track's.

## Decision

1. The fixed version is derived from the ranges Dependency-Track holds,
   read with the endpoint above.
2. They are read in the background, as the last step of a project refresh,
   for vulnerabilities without a recommendation that are missing or stale
   in the local database; bounded per cycle, four at a time, one read per
   vulnerability across projects. A failed read backs off per failure in a
   row and comes after never-read and stale ones. Only the slim `affectedComponents` are
   stored, in the rebuildable table `source_vulnerability_ranges`.
3. The range that applies is the one that names the component (package URL,
   or CPE without a conflicting attribute) and contains its version as
   Dependency-Track compares versions, also when it is the only range: a
   reported finding may come from another analyzer. Only when all containing
   ranges end at the same excluded version above the component's is there a
   fix; a fixed version another range contains moves to that range's end,
   and one an exact entry names gives none. Otherwise the field is left out.
4. The text is `Upgrade <name> to <version> or later.`, with later affected
   ranges and exact versions named. Trivy's vulnerability-wide
   `patchedVersions` is never the text; it is exported as an unchecked
   property. Dependency-Track's own recommendation always wins.
5. Each entry states its provenance (`recommendation_source`,
   `recommendation_fixed_by`), and the document counts derived and not yet
   read entries.

## Alternatives

- **Ask GitHub advisories or OSV directly.** Complete and current, but a new
  outbound data source that learns which vulnerabilities the deployment
  has. Rejected: the same data is already mirrored in Dependency-Track.
- **Read the ranges during the export.** Always current, but one request per
  vulnerability on a request path, and an export would fail with
  Dependency-Track. Rejected.
- **Use `patchedVersions` when the ranges give no fix.** Rejected: the value
  belongs to whichever package and distribution created the record, so it
  named an Alpine fix for a Debian package, also where the component's own
  range is open (unfixed).
- **Take a single range as containing the version.** Rejected: OSS Index,
  Trivy and Snyk report findings without Dependency-Track's ranges, so the
  one range may be another branch's or release's and recommend a version at
  or below the installed one.
- **Say "no fix known" instead of leaving the field out.** A reader cannot
  tell "no fix exists" from "the ranges do not say"; the absent field and
  the counts say what is known.
- **Let a reviewer overwrite the text per finding.** Not needed yet; the
  assessment's response and rationale already carry a reviewer's view.

## Consequences

- A VDR has a recommendation for most findings of GitHub, OSV and NVD
  ranges, without a new outside service.
- The first export after a new vulnerability may come before the read; the
  document says so with `export_fixed_versions_unread`.
- A range that ends at an OSV `limit` reads as fixed there; findings only
  OSS Index reports get no derived text.
- The backup design classifies `source_vulnerability_ranges` as rebuildable.
- Another source than Dependency-Track can offer the same port
  (`AffectedVersionSource`); without it the step is skipped.

## Confirmation

- `tests/test_fixed_versions.py`: the comparator, range choice, identities,
  display names and texts.
- `tests/test_cyclonedx_export.py`: the field, the properties and counts, and
  validation against the strict CycloneDX 1.5 schema; the inventory serial
  number is unchanged.
- `tests/test_dt_cache.py`: only missing or stale vulnerabilities are read,
  the cap, failures and their back-off and order, one read across projects,
  and no read during an export.
- `tests/test_dt_client.py`: the response is slimmed, 404 is None, and the
  path is URL-encoded.
- Still open: a reading of a VDR of a real project version by a consumer.
