# ADR 0012: The team mapping is organised by team

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-24, repository owner) |
| Implementation status | Implemented (PR #349) |
| Related | [Team mapping](../assessment-model.md#team-mapping-and-analyzer-guidance) (the reference); [Settings → Team Mapping](../screens.md#settings-team-mapping) (the editor) |

## Context

Ownership decides which teams must assess a finding. Until now the mapping
file was a list of selectors, each naming a team: `{"vp-stats-app": "Core",
"*": "Unknown"}`. A finding belongs to the nearest mapped component above it in
the BOM; without one it falls to the catch-all `*`.

On production (2026-11-23, read-only, about 90 active versions, about 343
entries) 21,826 findings fell to "Unknown". Three causes:

- **Components named unlike their package.** The BOM calls the root of the
  standalone stats-app project `stats-app`; its purl names `vp-stats-app`,
  which is mapped. Matching the package name a purl names when nothing
  matches the own name (the purl fallback, also in PR #349) fixes 8,798 of
  them.
- **Standalone projects whose BOM root has no purl, and flat BOMs without a
  dependency graph.** Every chain ends at a root no selector can name
  reliably, or there is no chain at all: eventserver (1,202), stats-app
  (993), Service Tools Ext (611), Service Tools (412), ivmclient (317),
  dicom-tag-store-srv (307), systeminfo (229), stats-srv (148), DataStudio
  (137). Their owner is known per project, not per component.
- **Generic root-level components.** Below ViewPoint_Product sit third-party
  packages (`libtiff`, `ffmpeg`, `OpenSSL`, `Qt`) and internal components
  with generic names and no purl (`extlib`, `core`, `auth`, `stats-app`),
  6,556 findings in total. A plain name such as `core` would also match
  unrelated components elsewhere.

The list of 343 selectors was also hard to maintain: it answers "who owns
this selector", while the people maintaining it think "what does my team
own". Aliases (former team names) repeated in every entry of a team, and
nothing showed which entries were stale, shadowed or contradicting.

## Drivers

- Ownership must be expressible for projects as a whole and for components
  inside one project.
- One matching engine for the server, the browser and every reader of the
  mapping (team groups, auto-analysis guidance, MCP, exports).
- Existing files and backups keep working without a migration step.
- The editor must show the effect of a change before it is saved.

## Decision

1. **The file maps teams to what they own.** Keys are team names. A value is
   an object with optional `aliases`, `projects` (Dependency-Track project
   names) and `components` (the selector syntax), or a string or list of
   strings as shorthand for `components`:

   ```json
   {
     "Core": {
       "aliases": ["DE-Core"],
       "projects": ["stats-srv", "estservice"],
       "components": ["vp-stats-app", "project:ViewPoint_Product::core"]
     },
     "3P": {"aliases": ["3rd Party"], "components": ["libtiff", "purl::pkg:generic/ffmpeg"]},
     "Unknown": "*"
   }
   ```

2. **The catch-all is the selector `*`**, owned by at most one team.
3. **Two project selectors** join the selector syntax:
   `project:<project>::<selector>` applies a component selector only inside
   that project; `project::<project>` owns the project's findings no
   component selector owns. A team's `projects: [X]` is `project::X`.
4. **Resolution order:** component selectors (project-scoped first, then
   purl, group, no-group, name), then the package name a purl names, then
   project ownership, then `*`. Ownership still follows the BOM: the nearest
   mapped component above a finding wins.
5. **One engine.** The team document is turned into the selector mapping the
   engine has always read (`dtvp/team_config.py`, mirrored in
   `frontend/src/lib/team-config.ts`); every existing reader gets that.
6. **Validation on save** rejects: a selector or project listed under two
   teams, `*` owned twice, an alias equal to another team or to another
   team's alias, team names differing only by case, unknown or
   contradicting modifiers, and malformed values.
7. **The old format still loads.** A file of selector keys is read as it
   is; the editor converts it in memory (each key under its primary team,
   aliases merged, a clashing alias kept with the first team and reported as
   a warning) and a save writes the team format. A file is in the team
   format when a value is an object or a team owns `*`.
8. **A report** computed in the background from the stored BOMs and
   findings of the active versions shows coverage per project, findings per
   entry, what falls to `*` and under which roots and top-level components,
   and near-duplicate entries that disagree (`VPStatsApp` → Phoenix,
   `vp-stats-app` → Core). The Settings editor is built on it: an overview
   of the key numbers, the unowned findings, a coverage browser over the BOM
   trees (also as a draft would own them), team cards, and the checks with
   their fixes.

## Alternatives

- **Keep selector → team, add `project::` keys.** Smallest change, and the
  engine is the same. Rejected as the file format: it keeps the
  maintenance problem (aliases repeated per entry, no view per team) and
  puts project ownership next to hundreds of component keys.
- **Projects only.** Owning whole projects is easy and covers the
  standalone projects. It cannot split a product such as ViewPoint_Product,
  where most findings belong to component teams.
- **Dependency-Track project tags as the ownership source.** Teams could tag
  their projects in Dependency-Track. Not now: it puts ownership in a system
  DTVP reads only in the background, it needs write access or a process in
  another tool, and it covers projects only. A possible later addition: tags
  could fill a team's `projects`.

## Consequences

- The production file converts without loss; alias clashes show up as
  warnings when it is first opened and must be resolved before the next save
  if they are real conflicts.
- Saving through the API writes the team format, also when the request sends
  the old one (the inline mapping edit of older clients, uploads).
- Shorthand-only files without a `*` owner cannot be told from the old
  format and are read as selector keys; DTVP itself always writes objects.
- A team without any selector or project (only aliases) has no selector in
  the derived mapping; team groups read the team document and still know it.
- The report holds a slim copy of every active version's BOM (refs, names,
  groups, purls, dependencies) and its findings in memory, read again only
  when the stored BOM or findings change.

## Confirmation

- Shared fixtures run on the server and in the browser:
  `tests/fixtures/team_mapping_cases.json` (parsing and precedence) and
  `tests/fixtures/team_config_cases.json` (validation and the derived
  mapping).
- `tests/test_team_config.py` covers conversion, the settings API and a
  backup round trip with both formats; `tests/test_team_mapping_report.py`
  the report, the tree and the preview.
- `frontend/e2e/team-mapping-editor.spec.ts` covers the tree, "Assign to a
  team" with the team combobox, the checks with their fixes, the save bar
  with review and discard, keyboard use and the guard when leaving with
  unsaved changes (Chromium, Firefox, WebKit; mocked API).
- After deployment: the number of findings on "Unknown" in the report falls
  as the standalone projects are assigned, and the report lists no
  near-duplicate disagreements that nobody decided.
