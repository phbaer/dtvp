# ADR 0013: The product is called River

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-25, repository owner) |
| Implementation status | In progress: the visible name and the logo are changed; identifiers are not |
| Related | [Brand](../brand.md) (name, mark, wording) |

## Context

The product was called DTVP. The abbreviation is used elsewhere, so it does not identify
this product, and four consonants are hard to say and to remember.

## Drivers

- A name people can say, spell and remember.
- A link to science fiction, fantasy or space.
- No collision with a product in the same field.
- Existing data stays usable: backups restore, and operators are told what to change.

## Decision

1. The product is named **River**, expanded as the recursive acronym "River Inspects
   Vulnerabilities and Evaluates Risks". The name refers to River Song of *Doctor Who*.
   The tagline is "Read the ripples before they reach the shore."
2. The logo is the triple tilde alone: three waves, no ring and no dot. As a character
   it is **≋** (U+224B). It replaces the radar icon.
3. Established names may change: environment variables, context path, image name, and
   the identifiers stored in data or sent to other systems. The rename happens in steps,
   and what users see changes first. A name that existing data depends on changes
   together with a migration or a reader for the old form.
4. The Python distribution is not published as `river`, and the import package is not
   renamed to `river`: that name belongs to an established library on PyPI.
5. Earlier decision records keep their text, including "DTVP" in the titles of ADR 0003
   and ADR 0009.

## Steps

| Step | Scope | Status |
| :--- | :--- | :--- |
| 1 | Product name in the UI, messages, documentation and package description; logo and wordmark | Implemented |
| 2 | Names operators configure: `DTVP_*` and `VITE_DTVP_*` variables, the default context path `/dtvp`, the container image, the repository, SBOM file names | Not started |
| 3 | The import package `dtvp` and its logger names | Not started |
| 4 | Names stored in data: see below | Not started |

Names stored in data, sent to other systems or held by clients, which step 1 leaves
unchanged:

| Name | What a rename needs |
| :--- | :--- |
| Access token prefix `dtvp_pat_` | Accept both prefixes, or new tokens |
| Dump format `dtvp.dump/1`, schema ids `urn:dtvp:dump:1:*`, manifest key `dtvp`, file extension `.dtvp-dump.zip`, default label `dtvp` | A new format version whose reader still accepts the old one |
| Database file `dtvp.sqlite3` | Renaming the file on startup |
| Record fields `dtvpRevision`, `dtvpSyncStatus`, `dtvpRemote`, `dtvpSourceMarks` | A migration of stored records |
| CycloneDX rating source `DTVP` (default of `DTVP_CYCLONEDX_ASSESSMENT_SOURCE`), the `export_tool` value and the property prefix `dtvp` | A decision whether consumers of earlier exports rely on them |
| tmrescore properties `dtvp:*` | The same change in tmrescore if it reads them |
| MCP server id `dtvp`, resource `dtvp://assessment-rules` | Reconfigured agent clients |
| Session token type `dtvp-session`, browser storage keys `dtvp_*` and `dtvp:*` | Nothing; sessions and "What's new" reset once |

## Alternatives

| Name | Why not |
| :--- | :--- |
| Ripley, Tycho, Dave, Carl, Vera | Taken on PyPI; Vera++ is a code checker |
| Dradis, Heimdall | Established security tools |
| Opossum | OpossumUI, an open-source compliance review tool, in the neighbouring field |
| Tribble | Tribble, Inc. sells security-questionnaire software and filed for the wordmark in software classes |
| Laika, Petra, Numbat | A compliance vendor's former name; Petra Security; an agent-security tool |
| Pond | A pending US application for POND in software classes |
| Belka, Morla, Yapok | No clash found; set aside by preference |
| Keep DTVP | Does not solve the problem |

## Name checks

Checked on 2026-11-23 to 2026-11-25, by web search and PyPI lookups only.

| Check | Result |
| :--- | :--- |
| PyPI `river` | Taken: an online machine learning library |
| PyPI `river-review` | Free |
| Security tools named River | None found |
| Nearest neighbour | River Security, a European penetration-testing and attack-surface firm; its product has another name |
| Other software | River, a Wayland compositor; others exist, the word is common |
| Wordmark | No live RIVER wordmark for software found on third-party sites |

Not checked: the USPTO, EUIPO and DPMA registers directly, npm, Docker Hub, domains.
This is not a legal clearance.

## Consequences

- Searching for "River" alone will not find the product. Documents pair it with a
  descriptor, see [Brand](../brand.md#name).
- Until steps 2 to 4 are done, the product is River while its variables, paths, package
  and stored identifiers say `dtvp`. The README says so.
- The analysis log classifies messages that start with "River" or "DTVP" as the product's
  own, so messages stored before the rename still show correctly.
- Documentation screenshots are captured from the River UI with the redesigned
  vulnerability cards and assessment workspace.

## Confirmation

- A search for the standalone word "DTVP" finds only earlier decision records, the
  generated threat-model results, the stored values listed above, and the notes about the
  former name.
- The frontend and backend test suites pass.
- The register checks listed under "Not checked" are done and recorded here.
