# Version overrides: design

[Project overview](../README.md) · [ADR 0010](adr/0010-version-overrides.md) · [Assessment model](assessment-model.md)

| | |
| :--- | :--- |
| Status | Steps 0 to 6 of the [plan](#19-plan) implemented (step 4: the marker as a read-only field; step 5: scopes and the lifecycle per scope, without per-scope SSVC summaries and `max_rescored_cvss`; step 6: the override in the VDR, with the status from the findings of the exported version) |
| Decision | [ADR 0010: Version overrides of an assessment](adr/0010-version-overrides.md), accepted 2026-11-20 |
| Checked | Against the code at origin/main fc999882 on 2026-11-20, by reading it, not by running it. File and line references are those of that commit; the code wins where it has moved since |
| Changes marked **(v2)** | Resolutions of the second design review |

A vulnerability's findings can be assessed differently per product version on purpose: one base assessment plus marked exceptions. This page is the implementation design; the decision and its reasons are in the ADR.

## 1. Model in one paragraph

A vulnerability group keeps one **base** assessment. A reviewer can put a project version into an **override scope** with a label and a reason. All versions that carry the same label share one scope and one assessment text. Membership is a tag in each finding's own text. Scopes are derived, never stored as a separate table, and the existing lifecycle rules run inside each scope. An override counts as intended only after a reviewer approves it with the explicit approve operation. Until then its scope is NEEDS_APPROVAL, never ASSESSED. A difference between versions without the tag stays Conflicting, as it is today. Creating overrides, and adding a version to a label, is behind a flag that is off by default. Reading, scoped lifecycle, the cross-scope guard, approval, export and Return to base are always on.

## 2. Text tag and fields

- Two preamble tags, rendered next to `[Response: …]` after the leading rescoring tags and before any team block:
  - `[Version Override: <label>]`
  - `[Override Reason: <reason>]`

  They belong to the finding, not to a team block. `[Version Coverage: …]` is unrelated: it is a team-block tag and keeps its meaning.
- Label: 1-40 characters from `[A-Za-z0-9 ._+-]`, trimmed. It is compared after casefolding and collapsing whitespace, but stored as written. `base` and `ambiguous` (any case) are reserved. Reason: 1-200 characters, one line, with no `[`, `]` or `---`. A tag with an invalid value is not a field and stays in free text, like `RESPONSE_TAG_PATTERN`.
- `dtvp/assessment_model.py`:
  - `_VERSION_OVERRIDE` and `_OVERRIDE_REASON` patterns.
  - `parse_assessment` returns `version_override: {label, reason} | None`.
  - `_render_clean` writes the field.
  - `_clean_fields` / `free_text` exclude both tags, in the same way as `_RESPONSE`.
  - Helpers `version_override(details)`, `with_version_override(details, value | None)` (changes nothing else in the text, like `with_response`) and `preserve_version_override(details, existing)`.
  - Add `Version Override` and `Override Reason` to `RESERVED_DETAIL_PATTERN`, so agent free text and copied text can never inject a marker.
- Frontend `frontend/src/lib/assessment-helpers.ts`: the same parse, render and preserve functions. Parity cases go into `frontend/src/lib/__tests__/fixtures/assessment_parser_cases.json` (the existing shared fixture), and both test suites assert them.
- Merge-back note: `FORMER_OVERRIDE_NOTE = "Former version override"`, the first body line of a block turned historical by Return to base (`Former version override <label>: <reason>`). No new tag.

## 3. Migration and stored fields

- `dtvp/migrations/assessment_outbox/0009_version_override.sql`:
  - `ALTER TABLE assessment_fields ADD COLUMN version_override TEXT;`
  - `ALTER TABLE assessment_fields ADD COLUMN version_override_reason TEXT;`
  - `CREATE INDEX assessment_fields_version_override_idx ON assessment_fields (project_uuid, vulnerability_uuid) WHERE version_override IS NOT NULL;`
  - `DELETE FROM assessment_team_fields; DELETE FROM assessment_fields;`, so the fields are re-read at the next start, as 0008 does.
- Fields are filled in `assessment_outbox_services` (fields write at :593-606).
- `dtvp/backup/migration_effects.py`: `("assessment_outbox", 9): NoRecordEffect("derived fields tables only")`. Without it, `tests/test_backup_coverage.py` fails.
- Dump format: dump/1 stays as it is, with no new entity and no schema change. The tag is part of `value.details`, and the fields tables are DERIVED. Instance restore (#290) reproduces the instance's own reviewed records unchanged. Whichever of #290 and this step merges later adds the 0009 entry to the effects registry.
- **(v2)** One new revision origin, `import-review` (section 9). It is a value of the existing `origin` column, so no schema change and no dump change; the dump schema types `origin` as a non-empty string (dtvp/resources/dump-schemas/1/revision.schema.json:21-23), and the step's backup round-trip test covers it.

## 4. assessment_scopes (domain, `dtvp/assessment_scopes.py`)

`assessment_scopes(group, team_mapping) -> ScopeView`. It is pure, works on a group's `affected_versions` (keyed by `project_uuid`), and the backend lifecycle, saves, guard, bulk workflows, carry-over, MCP and export all use it. A TS port in `frontend/src/lib/assessmentScopes.ts` is tested against the same fixtures.

Version identity is `project_uuid` now. After ADR 0009 M3 it becomes the River project version id. The version label string is never used.

**(v2)** Shared predicate `is_untouched(finding)`: NOT_SET, no team blocks and no text other than tags this spec ignores. It is the one definition used by rule 3 below, `override_gaps`, and `refresh_new_finding_flags` (grouped_vuln_services.py:476-483, which today inlines the same test). When ADR 0009's matcher lands and still sets a system `IN_TRIAGE` state on medium-band findings (section 9), only this predicate changes.

Per version V, only the active findings count; inactive records are not in the group:

1. `labels(V)` = normalised labels of findings in V whose text carries a valid `[Version Override]`, in any state, including tag-only NOT_SET texts.
2. `labels(V)` is empty: V maps to `base`.
3. `labels(V) = {L}`: V maps to `L`. Every finding in V belongs to L, including untagged untouched and new findings (inheritance). An untagged finding in V that is not untouched raises `VERSION_OVERRIDE_PARTIAL`.
4. `labels(V)` has more than one label: V maps to `ambiguous` and raises `VERSION_OVERRIDE_LABEL_MISMATCH`. Its findings are compared in no scope, and ordinary saves cannot target it (section 6).

A scope is `{name: "base" | L, label, reason, versions[], findings[], required_teams[], pending, lifecycle, reasons[]}`.

- `reason` is the reason the scope's tagged findings agree on, else `null`. Differing reasons within one label raise `ASSESSMENT_DETAILS_MISMATCH` inside that scope.
- `pending` is true if any finding in the scope carries `[Status: Pending Review]`. Inherited untouched findings have no text and never carry it; the scope's flag is what counts for them (sections 6, 11).
- `required_teams` comes from team ownership of the scope's findings, minus Unassigned. This means moving `_team_tags_by_version` from `task_group_query_services` into a domain helper `team_tags_by_version(group, team_mapping)` that both use.
- The **primary scope** is `base` if it has findings. Otherwise it is the scope with the most findings, with ties broken by label order.
- **(v2)** `resolved_marker(scope)`: `None` for base; `{label, reason}` for an override scope whose reason is agreed; undefined (an error for writers) for `ambiguous` or a scope without an agreed reason.
- **(v2)** `version_scope(group, version, extra_records=())`: the scope a version maps to when `extra_records` (records not active in the group, with their markers) are counted next to its active findings. Used by carry-over and by a finding's return (section 9).

## 5. Lifecycle, reasons and aggregates

- `_derive_group_inconsistency_reasons` and `_derive_group_lifecycle` run unchanged per scope, on a per-scope summary.
- New inconsistency reasons:
  - `VERSION_OVERRIDE_PARTIAL`: an untagged finding that is not untouched in an overridden version.
  - `VERSION_OVERRIDE_LABEL_MISMATCH`: two labels in one version.

  Both are Conflicting. An untagged untouched finding in an overridden version is missing coverage inside its scope. The existing `has_missing_component` rule then gives INCOMPLETE, and the summary sets `override_gaps: [finding keys]` so the card can offer "Apply <L> override". A save in that scope fills the gap (section 6); it never turns it PARTIAL.
- Group lifecycle = combine(scope lifecycles), in order:
  1. Any INCONSISTENT (or an ambiguous version): INCONSISTENT.
  2. Any INCOMPLETE, or a mix of OPEN with non-OPEN scopes: INCOMPLETE.
  3. Any NEEDS_APPROVAL: NEEDS_APPROVAL.
  4. All OPEN: OPEN.
  5. Any ASSESSED_LEGACY: ASSESSED_LEGACY.
  6. Otherwise: ASSESSED.

  A pending override is therefore never ASSESSED, and is never Conflicting only because it differs from base.
- The comparison within a scope (backend `normalize_details`, grouped_vuln_services.py:327-345; frontend assessment-helpers.ts:1089-1101) also strips, on both sides:
  - historical blocks
  - `[Version Coverage: …]` (product owner decision P5)
  - `[Version Override: …]` and `[Override Reason: …]`; the reason is compared separately as above.

  This applies to groups without overrides too. It ships in step 3 and changes the lifecycle of existing data, but only towards fewer false conflicts. **(v2)** Because groups that differ only in historical blocks or Version Coverage can then become INCOMPLETE and so eligible for Synchronize, the same step changes Synchronize so it never moves, drops or spreads historical blocks (section 8).
- Remove the dead per-version block in `_derive_group_lifecycle` (:423-447). Within a scope, mixed states are already caught by `ANALYSIS_STATE_MISMATCH`. Make `technical_state` deterministic: the primary scope's agreed General state, else the first General state by finding key order.
- `calculate_statistics` (logic.py:1244): count each group once, by its combined lifecycle. An approved override is never INCONSISTENT. Add `groups_with_overrides`.
- `ssvc_services.summarize_group`: returns `scopes: {name: summary}` next to the existing top-level summary, which becomes the primary scope's summary. The card prefills from `summary.scopes[editingScope].record`.
- Rescoring and severity:
  - `rescored_cvss`, `rescored_vector` and severity are the primary scope's.
  - New `max_rescored_cvss` is the maximum over scopes, used by "sort by worst".
  - When a view is filtered to one version, the group holds only that version, so the primary scope is that version's scope with no extra rule.
  - Update `_refresh_group_rescoring_metadata` (general_api_routes.py:477) and the grouping code in logic.py (:1050-1060).
- Frontend mirrors these: `getGroupLifecycleFromSummary` (missingTeams per scope), `group-classifier.ts`, `inconsistency.ts` (labels for the two new reasons), `StatsSidebar` and the list summary index. Backend and frontend share JSON fixtures in `frontend/src/lib/__tests__/fixtures/assessment_scope_cases.json`, read by pytest from that path. Required fixtures:
  - base only
  - an approved override
  - a pending override
  - two versions sharing a label
  - one label with two reasons
  - partial (untagged assessed finding)
  - an untagged NOT_SET finding in an overridden version
  - a new component in an overridden version
  - a new version (base)
  - carry-over into an overridden version
  - **(v2)** carry-over that replaced every tagged finding of an overridden version (the version stays in L)
  - an ambiguous version
  - a team owning no component in the override versions (gap 5)
  - historical-only and Version Coverage-only differences (not Conflicting)
  - **(v2)** a scoped save that filled an inherited gap finding (ASSESSED or NEEDS_APPROVAL, not PARTIAL)
  - **(v2, added with the matcher)** an untagged finding whose only content is a system-set IN_TRIAGE, in an overridden version (a gap, not PARTIAL)

## 6. Saves, deletes and the cross-scope guard (domain layer)

- `AssessmentRequest` gains:
  - `assessment_scope: Optional[str]` (`base` or a label)
  - `operation: Literal["save", "approve", "split", "apply_override", "apply_base", "return_to_base"] = "save"` **(v2: `approve`)**
  - `version_override: Optional[{label, reason}]` (only for split and apply_override)

### 6.1 Scope resolution

- The use case gets a `ScopeResolver` dependency.
  - Primary path: resolve the request's group from the grouped-vulnerability cache, as MCP `_find_group` does, then `assessment_scopes`.
  - Fallback: query the fields index over `(project_uuid, vulnerability_uuid)` of the request's instances. **(v2)** It counts only active findings, so it agrees with the active-only rule of section 4: the query joins `assessment_state` and excludes `sync_status IN ('inactive', 'superseded')`, and it is restricted to the request's instance keys plus the keys the finding-presence store reports active for the same (project, vulnerability). `cancelled` is not excluded: it is an active finding whose export was discarded (assessment_outbox_services.py:99, :1403), and excluding it would drop a live finding from its version's scope.
- It returns each finding's scope and its `resolved_marker`, keyed by `finding_key` (River's own key; after #296 `finding_uuid` equals it).
- **(v2) One read.** `save_assessment` reads each instance's stored text **and revision** once, through `get_cached_assessments` (dt_cache.py:2431), and uses that read for the stored text it preserves, the stored markers, and the revision guard (6.4). It replaces today's separate `get_cached_assessment_details` call (assessment_use_cases.py:584-596).
- **(v2) Cross-check.** If an instance's stored marker, from that read, is set and does not equal the label of the scope the resolver gives (for example a split committed after the grouped cache was built), the request fails with 409 `assessment_scope_mismatch`. A stale cache can therefore never lead the save to strip a marker.

### 6.2 Guard

In `save_assessment` and `delete_assessment` in `assessment_use_cases.py` (not only the HTTP route), for `operation in ("save", "approve")`:

- All instances must map to one scope, and that scope is not `ambiguous`.
- If `assessment_scope` is given, it must equal that scope.
- Otherwise the request fails with HTTP 409 `{"error": "assessment_scope_mismatch", "scopes": [...current scopes...]}`, so a stale client (for example after a split in another tab) reloads.

Exempt, because they are explicit operations whose payloads may span versions:

- split, apply_override, apply_base and return_to_base
- restore team assessments from an export (#292), which writes historical blocks only and keeps the preamble byte for byte
- instance restore (#290)
- adoption and carry-over in dt_cache

### 6.3 Markers on ordinary saves (v2, replaces "each finding keeps its stored marker")

- For `operation in ("save", "approve")`, after rendering and next to `with_response`, each target finding's marker is set to its scope's `resolved_marker`: `with_version_override(payload, resolved_marker(scope))`. For base that is none; for an override scope it is `{label, reason}`.
  - A tagged finding gets the marker it already has, so nothing changes for it.
  - An inherited untagged gap finding gains the scope's marker, so a team save or a General save that covers it fills the gap and leaves the scope ASSESSED or NEEDS_APPROVAL, never PARTIAL.
- If the target scope has no agreed reason (one label, two reasons), the save fails with 409 `override_reason_mismatch` when it contains an untagged finding; a reviewer first unifies the reason with apply_override (section 7). A save with only tagged findings keeps each finding's stored marker in that case.
- A marker the client sent in the text (rendered preamble) is ignored and replaced by the resolved one; when it differs from the resolved marker, `_validate_version_override_change` rejects the save (6.5).
- `keep_team_records` and the writers that rebuild text from blocks apply the same rule (section 8).
- `fields.free_text` can never carry the tags (they are reserved).

### 6.4 Pending review and approval (v2)

- **Server-side pending for every non-reviewer save**, both paths: when `role != REVIEWER`, the use case sets `fields.pending_review = True` before `render_assessment` (fields path, assessment_use_cases.py:574-583) and appends `[Status: Pending Review]` after rendering on the text path if it is missing. Today the fields path writes `pending_review` as the client sent it (assessment_model.py:368), and only the text path adds it through `process_assessment_details` (logic.py:1974-1975). This applies to every group, with or without overrides (plan step 2).
- **Pending of an override scope is removed only by `approve`.** For findings whose scope is a pending override:
  - a reviewer's `save` keeps `[Status: Pending Review]` on every target finding;
  - a reviewer's team or General delete re-adds it after `remove_assessment_blocks` (today only non-reviewers get it back, assessment_use_cases.py:718-720);
  - every bulk writer (Synchronize, assessment_repair, automatic assessments) keeps it (section 8).
- A reviewer's `split`, `apply_override` or `apply_base` may be saved without pending: the operation itself is the reviewer's explicit act. Only plain saves, deletes and bulk writers are bound by the rule above.
- `operation = "approve"`: reviewer only (403 otherwise), scoped like a save, always writes every finding of the scope (including inherited gap findings, which gain the marker per 6.3), removes `[Status: Pending Review]` and records Reviewed By. The card's Approve button sends it for an override scope; for base scope the existing approve behaviour (a reviewer save without pending) is unchanged.
- The base scope follows the same rule (decided, section 17): a reviewer's plain save, Synchronize and deletes keep pending; only approve removes it. That part is plan step 2 and independent of overrides.

### 6.5 Revision guard for forced saves (v2)

- `expected_assessment_revisions(req)` returns `{}` when `req.force` or `original_analysis` is empty (assessment_use_cases.py:188-191). From this change, the use case then passes the revisions of its own read (6.1) for every instance as `expected_revisions`. `force` overrides only the check against the client's view, never a concurrent write.
- A revision conflict on that path maps to the existing `AssessmentConflictError` (409); when the conflicting new value carries a different marker, the error is 409 `assessment_scope_mismatch` so the client reloads scopes.
- The stored markers, the preserved SSVC record and response all come from that same read.
- `delete_assessment` already guards with the revisions it reads itself (:705-713); no change.

### 6.6 Validation

`_validate_version_override_change(req, role, resolved)`, modelled on `_validate_response_change`:

- For `save` and `approve`, a finding's marker may only stay as it is or gain exactly its scope's resolved marker (6.3). Any other add, remove, relabel or change of reason requires an override operation.
- `split` and `apply_override` by a non-reviewer are saved as pending review (6.4 makes this the general rule); the use case rejects `force` for them.
- `return_to_base` and `approve` are reviewer only.
- **(v2, flag wording, one rule used in sections 7, 10, 13):** with the flag off, every operation that **changes a version's scope to a label** returns 403 `version_overrides_disabled`. That is:
  - `split` (always changes the target versions' scope to the label, whether new or existing), and
  - `apply_override` whose target versions are not already mapped to that label (joining a base or new version to an existing label).

  Always allowed, flag on or off: `apply_override` to gap findings of a version already mapped to that label, `apply_base`, `return_to_base`, `approve`.

### 6.7 Delete

- `remove_assessment_blocks` (logic.py:1482-1511): the team and General paths are unchanged. Tests prove the tags survive them, and that a reviewer's delete in a pending override keeps pending (6.4).
- A whole delete (`team=None`) returns only the two override tags, so the finding stays in its scope as NOT_SET.
- Only `return_to_base` passes `keep_scope=False`.
- `suppressed_by_finding`, `original_analysis`, `expected_revisions` and code evidence applications stay keyed by finding key. They are already filtered to the request's scope instances.

## 7. Override operations (`dtvp/version_override_services.py`, route `POST /api/assessment/version-override`)

- **split** `{versions: [project_uuid], label, reason}`:
  - For each finding in those versions, write its own current text plus the tags. This copies; it does not replace, so base blocks stay as they are.
  - NOT_SET findings get the tags only.
  - If the label already exists on other versions, the call is a join. It is rejected unless every finding in the target versions is NOT_SET or already equal to the scope's text after normalisation. Otherwise the client must use apply_override.
  - Flag-gated (6.6). Pending unless a reviewer saves without pending.
- **apply_override** `{findings or versions, label, reason?}`: write the scope's agreed text (the merged text that Synchronize would build for that scope, section 8) with the scope's marker to the targets. Used for gap findings in an overridden version (always allowed), and for a new or base version joining the label (flag-gated, 6.6). A reviewer may pass `reason` to unify a scope whose findings disagree on the reason; all findings of the label then get it. Pending for non-reviewers.
- **apply_base** `{findings or versions}`: write the base scope's agreed text to findings of a version that maps to base, which is the new-version case. Pending for non-reviewers.
- **Assess separately…** for a new version is split with tags only (nothing is copied).
- **return_to_base** `{label, versions?}` (reviewer only):
  1. Turn every current override block, General included, into a historical block whose body starts with `Former version override <label>: <reason>`.
  2. Apply the base agreed text, keeping those historical blocks.
  3. Remove the tags.

  Nothing is dropped silently (rule from #291). If the override text equals the base after normalisation, the UI offers one click.
- **approve**: the `approve` operation of section 6.4, limited to the scope's instances.
- All operations persist through `persist_assessment_updates` in one call, per finding with the expected revisions of the operation's own read (6.5). They emit the existing key-based assessment events, and an `assessment_override` audit entry carries the operation, label, versions and user.
- **(v2, decision on inactive records)** Inactive (gone) records are not rewritten by split, apply_override or return_to_base. They are history, are not exported, and stay in the dump unchanged. **By design**, a finding that was gone while its version's scope changed comes back with its old value and is marked pending review because its marker disagrees with the version's scope (section 9); the card shows it as PARTIAL or LABEL_MISMATCH and offers "Apply <L> override" or "Apply base". The alternative, rewriting inactive records in the same persist call, was rejected: inactive records have no export path, and a value change on them would break the flap invariant (finding_lifecycle_services.py:8-12) for every later flap. This is documented in import-export.md and assessment-model.md.

## 8. Writers per scope

- **New findings (independent of the flag, plan step 1).** **(v2)**
  - `incomplete_sync`: the preview and the payloads call `refresh_new_finding_flags` on the group first and, by default, skip findings with `is_new_finding`, counted as skipped `new_finding`. The preview lists those findings per group, and the user can include them explicitly per group ("Also apply to N new findings", never preselected). That is the explicit "apply the existing assessment with a bulk workflow" path that docs/review-workflows.md:55-57 names, so the doc stays true and gains one sentence on the opt-in.
  - `automatic_assessments`: a new finding is skipped, counted as `new_finding`, only when **none** of the applied runs covers its project version: its version name is not in `_covered_product_versions` of any applied run's version entries (automatic_assessments.py:484-516, casefold match as there). After ADR 0009 M3 the match is on the River project version id. A run that covered the version is evidence about it, not a copy, so its verdict is applied as for any finding.
- **Synchronize (incomplete_sync), historical blocks (v2, plan step 3, independent of overrides):**
  - `_parse_blocks` results with `Historical: yes` are not used to build `blocks_by_team`; the merge works on current blocks only.
  - Each finding's payload is built from the merged current blocks plus **that finding's own** historical blocks and its own preamble (SSVC record and response as today through `_keep_finding_values`, plus its rescoring tags and, from step 7, its resolved marker and kept pending). Implemented as an explicit merge in `build_incomplete_sync_payloads`, not `keep_team_records(saved_team=None)`, because that function would also retire blocks the merge intentionally replaces.
  - A historical block never becomes a team's current block, and it is never copied to another finding.
  - The Synchronize stage of `assessment_repair` gets the same audit and fix; tests cover both.
- **Synchronize (incomplete_sync), scopes:** one merged text per scope, never across scopes. A base text is never written onto a finding whose version maps to an override. Ambiguous versions and scopes without an agreed reason are skipped and counted as `override_conflict`. **(v2)** Each finding gets its scope's resolved marker (6.3), so filling an inherited gap leaves the scope ASSESSED or NEEDS_APPROVAL, not PARTIAL. On findings whose scope is a pending override, `[Status: Pending Review]` is kept (6.4); `_parse_blocks` stripping pending from block content (incomplete_sync.py:54) must not decide the finding's pending state.
- **Automatic assessments:** an assessment arriving for a finding in an override scope is counted as `kept_override` and not written. Payloads are built per scope; base findings get no marker.
- **Combine conflicts / assessment_repair:** works per scope, with the resolved marker and kept pending as above. A new stage, "Keep differences per version" (plan step 9, reviewer only, never preselected, flag-gated), proposes a split for a conflict whose differences fall along version lines, and shows the diff per version.
- **Team restore from export (#292):** no change. A test proves a restore into an overridden version keeps the tags and lands its blocks in that scope, and (v2) that a later Synchronize keeps those restored historical blocks only on that version.

## 9. Adoption, gone findings, carry-over, new versions and the matcher

One shared rule: `reconcile_override_marker(text, version_scope) -> (text, needs_review)`.

- **First adoption from the source (origin `import`) and archive import (v2, amends ADR 0003 decision 2):**
  - The source value is adopted **unchanged** as revision 0, origin `import`, exactly as today (assessment_outbox_services.py:1195-1222). ADR 0003 decision 2 holds for that revision.
  - If the value carries a marker, the same transaction appends revision 1, origin `import-review`, author none, which adds `[Status: Pending Review]` and changes nothing else. The record is then pending export, and the next export pass sends revision 1 to Dependency-Track (ADR 0003 decision 3).
  - The disagreement, if any, shows as PARTIAL or LABEL_MISMATCH until a reviewer decides.
  - The same rule applies when a `cancelled` record adopts the source value (:1403-1410).
  - import-export.md's adoption table gets a row: "None yet | holds an assessment with a version override marker | adopted as revision 0 (origin `import`), then revision 1 (origin `import-review`) marks it pending review; revision 1 is exported".
- **Return of a gone finding (v2)** (finding_lifecycle_services):
  - The version's scope is computed **after** the read, over every finding of that version that is active once the read is applied, including all findings returning in the same read, with their markers (`version_scope` over the post-read set).
  - If the returning record's marker agrees with that scope (same label, or none for base, or an untagged untouched record in an override), it is reactivated with the same value and revision, as today (`plan_reported` only flips the status, :585-588). This keeps the flap invariant (:8-12).
  - Only if it disagrees is it marked pending review (a new revision through the reconcile rule). The scoped lifecycle then shows PARTIAL or LABEL_MISMATCH.
- **Carry-over (v2)** (plan_carry_over, same project version only; the carried value is already pending):
  - The target version's scope is `version_scope(group, V, extra_records=carried-from records)`: its active findings plus the markers of the records being carried from. Carry-over is limited to the same project version (ADR 0003, :816-820), so those markers are exactly that version's previous scope.
  - The carried marker is replaced (or, for base, removed) only when **other active findings of that version** carry a different label. If no active finding of V carries a label, the carried marker is kept, and V stays in its override scope.
  - `choose_carry_over` keeps treating differing markers as a carry conflict. The GoneFindingsPanel reason says "differs in version override".
- **New version:** maps to base (rule 2). Nothing is copied by Synchronize unless the user opts in (section 8). The card offers "Apply base to <v>", "Assess <v> separately…" (flag) and "Apply <L> override" (flag, it joins a label) for each existing label.
- **ADR 0009 Mode B:** re-created components keep their key and text, so no carry-over is needed. When two groups merge (ADR 0009 decision 7), scopes merge by label, and differing texts under one label become Conflicting in that scope, covered by the merge's review flag.
- **ADR 0009 medium-band findings (v2):** ADR 0009 decision 2 sends medium-band matches to triage as `in_triage`. ADR 0010 asks the matcher implementation to record "needs match review" as a **finding attribute**, not an assessment state. If it does set a system `IN_TRIAGE` state, `is_untouched` (section 4) treats an untagged finding whose only content is that system-set state, with no team blocks and no text, as untouched: a gap in an overridden version (not PARTIAL) and new for `refresh_new_finding_flags`. The shared fixture is added in the matcher's change.

## 10. MCP (`dtvp/mcp_server.py`)

- The parameter is named `assessment_scope`, because `scope` already means token scopes.
- `get_vulnerability` returns `assessment_scopes: [{name, label, reason, versions: [{project_uuid, version}], finding_uuids, pending, lifecycle, required_teams}]`.
- `preview_assessment` and `save_assessment` take `assessment_scope`, which is required when the vulnerability has more than one scope (error lists the scopes). `_plan_assessment` targets only that scope's findings, and `expected_revisions` covers only those. Saves go through the same use case, so the resolved marker (6.3) and forced pending (6.4) apply.
- New tool `propose_version_override(project, vulnerability_id, versions, label, reason)`: flag-gated as in 6.6, write token, always pending (AGENT_ROLE = ANALYST). Agents can never approve and never return to base.
- The `assessment_rules` resource and the `add_code_evidence` description say: target finding_uuids of one scope when the evidence is version-specific.

## 11. VDR export (`dtvp/cyclonedx_export.py` `_properties`)

- Export is per project version. It calls `assessment_scopes` (section 4) on the per-version group it already builds; there is no second implementation of the scope rule.
- For findings whose version maps to an override, including inherited NOT_SET ones, it adds:
  - `<prefix>:assessment_scope = version_override`
  - `<prefix>:version_override = <label>`
  - `<prefix>:version_override_reason = <reason>`
  - **(v2)** `<prefix>:version_override_status = pending | approved`, from the scope's `pending` flag, on every finding of the overridden version, inherited ones included. The finding-level `pending_review` property (cyclonedx_export.py:515-516) stays as it is and reflects only the finding's own text.
- No property means base.
- Validated against the CycloneDX 1.5 JSON schema in tests (memory rule: never a known limit): a pending override, an approved override, an inherited finding in each, and base.
- The recommendation (#282) is independent of these properties. docs/cyclonedx-export.md states that a recommendation next to a NOT_AFFECTED override is intended.
- Gone findings stay counts only.

## 12. Frontend

- **Scope state lives in the card** (`VulnGroupCard` composable `useAssessmentScope`), not in `VulnDetailInspector`, so the workspace (#280) reuses it.
  - The switcher sits above the form, for example "Base: 1.0, 1.1, 3.0 | 2.x (pending): 2.0, 2.1".
  - Switching with unsaved edits asks, as Close does.
  - A view filtered to one version opens on that version's scope.
  - When an event for the open group arrives (#287), the card re-derives scopes. If the editing scope no longer exists, it shows a notice and switches. A 409 `assessment_scope_mismatch` or `override_reason_mismatch` reloads the group and shows the same notice.
- `useVulnDependencyInfo` exposes `scopeInstances(name)`. Save, delete, approve, the sync draft, Apply/Adopt and the matrix variant button work only on the selected scope's instances. "Use for all findings" becomes "Use for this scope" and is offered only for variants whose findings all belong to the selected scope.
- **(v2) Approve** in an override scope sends `operation: "approve"` (VulnGroupCard.vue:1422 today calls `handleUpdate(true, true)`); a reviewer's plain save in a pending override leaves it pending and the card says so.
- **Matrix** (`FindingMatrix.vue`, `findingMatrix.ts`):
  - Versions are columns, so the version column header (`<th>` at :115) gets a menu with "Assess this version separately…" (flag), "Apply base" (new or base versions), "Apply <L> override" (gap versions always; joining a version: flag) and "Return to base…" (reviewer).
  - Column labels show the scope badge.
  - Variants and "N of M differ" are computed per scope.
  - Override columns use a neutral style, not red.
- **Split dialog:** label (existing labels offered), reason, and every finding of that version across components, including NOT_SET and new ones. Analysts see "Proposed, needs reviewer approval".
- **Return to base:** a diff of base against the override, a list of what becomes historical, and one-click when the texts are identical.
- **Card badges:** "Version overrides" plus "pending" or "partial". There is a "Base vs override" comparison.
- **Code evidence reader (#281):** when the editing scope is an override, evidence whose targets lie only in other scopes is marked "about other versions", and "Also use the suggested decision" is hidden for it.
- **DeleteAssessmentModal:** tests that team, General and whole deletes in an override keep the tags.
- **Synchronize preview (v2, step 1):** per group, the count of new findings skipped, and the "Also apply to N new findings" opt-in.
- **Flag:** `/api/me` returns `features.version_overrides`. Actions that change a version's scope to a label (6.6) are hidden when it is false. Badges, the switcher, the guard, approve, gap filling and Return to base are always shown.

## 13. Feature flag

`DTVP_VERSION_OVERRIDES_ENABLED`, read with the same parsing as the other boolean variables (`true`, `1`, `yes`); default off. **(v2)** It gates exactly the operations that change a version's scope to a label (section 6.6: split, and apply_override into a version not already mapped to that label), `propose_version_override` and the repair stage. Nothing else is gated.

## 14. Event stream and audit

There is no new event type. Override operations, approve and the `import-review` revision emit the existing assessment events per key, and the audit log records `assessment_override` entries for the override operations and approve.

## 15. Documentation (in the same change as each step)

- ADR 0010 (status proposed), plus a row in docs/adr/README.md.
- **(v2)** ADR 0003: an "Amended by" note in its Related line linking ADR 0010, naming decisions 2 and 6 as amended (once ADR 0010 is accepted; while it is proposed the note says "proposed amendment").
- assessment-model.md: scopes, the tags, that ASSESSED needs coverage within each scope, approval only through approve, and the gone-during-split behaviour.
- review-workflows.md: scoped Synchronize, new findings skipped by default with the explicit opt-in, automatic assessments applying runs that covered the version, historical blocks kept per finding, override workflow and approval.
- screens.md: switcher, column menu, dialogs, Synchronize opt-in.
- cyclonedx-export.md: the properties including `version_override_status`, and the recommendation note.
- ai-access.md: `assessment_scope`, `propose_version_override`, forced pending.
- import-export.md: the adoption table row with `import-review`, return (flap invariant kept when the marker agrees) and carry-over of markers.
- backup-and-restore.md: migration 0009 is NoRecordEffect, the dump is unchanged, the `import-review` origin.
- configuration.md: the flag and exactly what it gates.
- README: feature summary and links.

## 16. Tests (summary; details per step)

- Shared parser fixtures and shared scope fixtures, asserted by both pytest and vitest.
- Domain unit tests: assessment_scopes, `is_untouched`, the combined lifecycle, the validation matrix (role × operation × flag, including join with the flag on and off), the 409 guard on the use case and on the route, the cross-check against a stale cache, and the delete variants.
- **(v2)** Gap filling: a team save in L that includes an inherited NOT_SET finding leaves the scope ASSESSED or NEEDS_APPROVAL; per-scope Synchronize of an INCOMPLETE override scope likewise.
- **(v2)** Pending: an analyst fields save with `pending_review=false` stores pending; a reviewer Synchronize of a pending override, a reviewer team delete and a reviewer plain save in it leave it NEEDS_APPROVAL; only `approve` makes it ASSESSED.
- **(v2)** Forced saves: a split persisted between the guard and the persist of a forced approve fails the approve with 409, and the split's tags survive.
- **(v2)** Fallback resolver: a version with a gone tagged record resolves to the same scope on the cache path and on the fallback path.
- **(v2)** Synchronize keeps each finding's historical blocks, keeps every current block, never makes a historical block current; same for assessment_repair's Synchronize stage.
- Bulk workflow counters: `new_finding`, `kept_override`, `override_conflict`; automatic assessments covered vs uncovered new findings; Synchronize opt-in.
- Reconcile rule: adoption (revision 0 `import` unchanged, revision 1 `import-review` pending, exported), return (whole-version flap keeps value and revision; disagreeing marker becomes pending), carry-over (single replaced component keeps the marker; other active label wins).
- MCP: scope required, revisions only for the scope, propose is always pending.
- VDR schema validation with pending and approved overrides and inherited findings.
- Backup coverage: 0009 is registered, the round trip keeps the tags and the `import-review` revision.
- Frontend: component tests for the switcher (dirty-switch prompt, event re-derive), the column menu, approve sending the operation, the split and return dialogs, the Synchronize opt-in and DeleteAssessmentModal.

## 17. Points decided by the repository owner

All decided on 2026-11-20; see [ADR 0010, Decisions](adr/0010-version-overrides.md#decisions).

- **Synchronize and new findings (step 1).** New findings are left unassessed by default; the preview lists them as new, not synchronized; a reviewer can include them per vulnerability.
- **Pending in the base scope (step 2).** Only an explicit Approve removes `[Status: Pending Review]`, in the base scope too. A reviewer's plain save, Synchronize and deletes keep it.
- **A reviewer's plain save in a pending override** stays pending until Approve.
- **A finding gone while its version's scope changed** returns pending and PARTIAL; inactive records are not rewritten.
- **Adoption with a marker:** revision 0 unchanged (`import`) plus revision 1 (`import-review`) adding pending.
- **Disagreeing reasons in one scope:** a save that would fill a gap is rejected (409 `override_reason_mismatch`) until a reviewer unifies the reason.
- **Analyzer or agent assessments** apply to a new finding when the analysis covered that version (amends ADR 0003 decision 6). Agentyzer is to be replaced by agents through MCP; the rule is the same for both.
- **Return to base** is reviewer-only. The security documentation generator reads the VDR only.

## 18. Gap and issue resolution map

| Gap or issue | Resolved in |
| :--- | :--- |
| Gap 1 | Sections 4, 6, 8 and 9 |
| Gap 2 | Section 6.7 |
| Gap 3 | Sections 2, 3 and 6 |
| Gap 4 | Section 9 |
| Gap 5 | Sections 4 and 5 |
| Gap 6 | Section 5 |
| Gap 7 | Section 12 |
| Gap 8 | Section 15 and ADR 0010 |
| C1 gap filling on save and Synchronize | Sections 4 (`resolved_marker`), 6.3, 6.6, 8 |
| C2 carry-over dissolving an override | Sections 4 (`version_scope`), 9 |
| C3 Synchronize and historical blocks | Sections 5, 8; plan step 3 |
| C4 implicit approval | Sections 6.4, 7 (approve), 8, 12 |
| C5 forced saves without revision guard | Sections 6.1 (one read, cross-check), 6.5 |
| C6 fallback counting inactive records | Section 6.1 |
| C7 flap invariant on return; gone during split | Sections 7 (decision), 9 |
| C8 automatic assessments and new findings | Section 8; plan step 1 |
| C9 adoption vs ADR 0003 decision 2 | Sections 3, 9, 15; ADR 0010 amendments |
| C10 ADR 0009 in_triage | Sections 4 (`is_untouched`), 9; ADR 0010 |
| C11 flag wording for joins | Sections 6.6, 7, 12, 13 |
| C12 pending signal in the VDR | Section 11 |
| C13 export depends on scopes | Section 11; plan step 6 depends on step 5 |
| Gone findings | Sections 7 and 9 |
| Carry-over | Section 9 |
| Historical blocks | Sections 5, 7 and 8 |
| Team restore (#292) | Sections 6 and 8 |
| Backup (#289/#290) | Section 3 |
| Workspace (#280) | Section 12 |
| Code evidence (#281) | Section 12 |
| MCP | Section 10 |
| Finding keys / Mode B / matcher | Sections 4, 6 and 9 |
| VDR | Section 11 |
| New findings | Section 8 |
| Event stream (#287) | Sections 12 and 14 |

## 19. Plan

Each step is one pull request with its tests and documentation. Step 2's server-side pending for saves that are not a reviewer's is already merged (#297).

| Step | Scope | Tests |
| :--- | :--- | :--- |
| 0. docs(adr): ADR 0010 version overrides (proposed), with the proposed amendments of ADR 0003 decisions 2 and 6 | Add docs/adr/0010-version-overrides.md (status proposed, implementation not started), including the 'Amendments to ADR 0003' section, and a row in docs/adr/README.md. In ADR 0003's Related line, add 'Proposed amendment of decisions 2 and 6 by ADR 0010'. No code. | Markdown link check over docs/; ADR index lists 0010; ADR 0003 links 0010. |
| 1. fix(bulk): new findings are not filled by Synchronize unless chosen; automatic assessments skip only uncovered new findings | dtvp/bulk_workflows/incomplete_sync.py: preview and payloads call refresh_new_finding_flags, skip is_new_finding findings by default (skipped 'new_finding'), list them per group in the preview, and accept an explicit per-group opt-in (never preselected) that includes them. dtvp/bulk_workflows/automatic_assessments.py: skip a new finding (skipped 'new_finding') only when no applied run's _covered_product_versions contains its version name (casefold, as in :484-516); apply covered ones as today. Frontend: the new-findings count and the opt-in in the Synchronize preview, the counter in the result. Docs: review-workflows.md (:55-57 stays true and names the opt-in and the covered-run rule), screens.md, README. Independent of the flag and of overrides. | pytest: Synchronize leaves a new 2.0 finding untouched by default with the counter right, fills it with the opt-in, and still synchronizes a finding that is merely unassessed but not new; automatic assessments apply to a new finding whose version a run covered and skip one whose version no run covered. vitest/component: preview count, opt-in unchecked by default, result counter. |
| 2. fix(assessments): pending review enforced server-side for non-reviewer saves; forced saves guarded by the use case's own revisions | assessment_use_cases.save_assessment: when role != REVIEWER set fields.pending_review=True before render_assessment (fields path) and append [Status: Pending Review] on the text path if missing. Read stored text and revision once via get_cached_assessments (replacing get_cached_assessment_details) and, when req.force or original_analysis is empty, pass those revisions as expected_revisions for every instance; a conflict maps to the existing AssessmentConflictError. MCP save inherits both. Docs: assessment-model.md (pending is set by the server), ai-access.md, README. Independent of overrides. | An analyst fields save with pending_review=false stores pending; an agent (MCP) save stores pending; a reviewer save without pending is unpending as today. A forced save racing a concurrent persist (injected between read and persist) fails with 409 and leaves the concurrent value; a forced save without a race succeeds. Existing approve flow test still passes. |
| 3. fix(lifecycle): compare texts without historical blocks and Version Coverage; Synchronize keeps each finding's historical blocks; deterministic technical_state | grouped_vuln_services.normalize_details and frontend assessment-helpers (:1089-1101) strip historical blocks and [Version Coverage: …] on both sides. In the same change, incomplete_sync._sync_group builds blocks_by_team from current blocks only (skips Historical: yes), and build_incomplete_sync_payloads renders each finding's payload as merged current blocks + that finding's own historical blocks + its own preamble (SSVC, response, rescoring), by an explicit merge. Audit and fix assessment_repair's Synchronize stage the same way. Remove the unreachable per-version block in _derive_group_lifecycle; make technical_state deterministic. Add the shared fixture file frontend/src/lib/__tests__/fixtures/assessment_scope_cases.json (no-override cases only). Docs: assessment-model.md, review-workflows.md (historical blocks stay per finding). | Shared fixtures in pytest and vitest: historical-only and Version Coverage-only differences are not Conflicting; a real state or text difference still is. Synchronize after a #292 restore into one version keeps the restored historical blocks only on that version, keeps every current block, and never makes a historical block current; same for assessment_repair's Synchronize stage. Regression: a #292 restore into one version does not make the group Conflicting. |
| 4. feat(assessments): version override tags as fields, preserved by every writer (read-only); adoption with a marker is reviewed | assessment_model parse/render/with_/preserve_ helpers and RESERVED_DETAIL_PATTERN (labels 'base' and 'ambiguous' reserved); frontend assessment-helpers parity. Outbox migration 0009_version_override.sql (two columns, partial index, re-read of the fields tables) and the fields write in assessment_outbox_services. backup/migration_effects: ('assessment_outbox', 9) NoRecordEffect. Until scopes exist, save_assessment keeps each finding's stored marker (with_version_override from the step-2 read); keep_team_records and the bulk writers (including the step-3 per-finding Synchronize merge) use preserve_version_override. Whole delete keeps the tags only (keep_scope). _validate_version_override_change rejects every marker change. Adoption (dt_cache first adoption, cancelled re-adoption, archive import): a value with a marker is stored unchanged as revision 0 origin 'import' and followed in the same transaction by revision 1 origin 'import-review' adding pending, which is exported. Docs: assessment-model.md, import-export.md (adoption table row), backup-and-restore.md (0009, import-review origin), README. | Shared parser fixtures (round trip, invalid label stays free text, reason excluded from free_text, reserved labels). Migration test: columns exist and fields are re-read. test_backup_coverage passes; a dump round trip keeps the tags and the import-review revision and validates against the dump schema. Team, General and whole delete keep the tags. Agent text containing '[Version Override' is rejected. Adoption with a marker: revision 0 import equals the source value, revision 1 import-review adds pending, the record is pending export. #292 restore into a tagged version keeps the tags byte for byte. |
| 5. feat(lifecycle): assessment_scopes and per-scope lifecycle, required teams and aggregates | New dtvp/assessment_scopes.py (domain): assessment_scopes, is_untouched (also used by refresh_new_finding_flags), resolved_marker, version_scope(extra_records); team_tags_by_version moved out of task_group_query_services. grouped_vuln_services uses per-scope summaries, VERSION_OVERRIDE_PARTIAL, VERSION_OVERRIDE_LABEL_MISMATCH, the combined lifecycle and override_gaps. logic.calculate_statistics; ssvc_services.summarize_group (scopes); rescored_cvss from the primary scope plus max_rescored_cvss, with _refresh_group_rescoring_metadata and worst-first sorting. Frontend: assessmentScopes.ts, getGroupLifecycleFromSummary, group-classifier, inconsistency labels, StatsSidebar, read-only scope badges in the card and on matrix column headers. Docs: assessment-model.md, screens.md. Interim note: until step 7, a save into a version with an imported marker keeps stored markers only, so an inherited gap it fills shows PARTIAL (correct signal; only imported markers exist before step 8). | The full shared scope fixture set in pytest and vitest (including carry-over replacing every tagged finding via version_scope, and is_untouched). refresh_new_finding_flags unchanged for existing fixtures. Statistics count a group with an approved override as ASSESSED once. SSVC per-scope summaries. Sorting by max_rescored_cvss. Component tests for badges and neutral override columns. |
| 6. feat(export): version override properties in the CycloneDX VDR | cyclonedx_export calls assessment_scopes on the per-version group it already builds and adds assessment_scope, version_override, version_override_reason and version_override_status (pending\|approved, from the scope's pending flag) to every finding of an overridden version, inherited NOT_SET findings included. Docs: cyclonedx-export.md (properties, absence means base, status vs the finding-level pending_review, recommendation next to a NOT_AFFECTED override is intended). | Export tests for a pending override, an approved override, an inherited NOT_SET finding in each (status present, finding-level pending_review absent), and base (no properties); every generated document validates against the CycloneDX 1.5 schema; the recommendation is unchanged. |
| 7. feat(assessments): scoped saves and approve, 409 cross-scope guard, scope markers on save, pending kept in override scopes, scoped bulk workflows, MCP scopes, reconcile on return and carry-over | Backend: AssessmentRequest.assessment_scope and operation (save, approve); ScopeResolver (grouped cache first; fallback over the fields index joined with assessment_state excluding inactive/superseded and restricted to the request keys plus finding-presence active keys); cross-check of stored markers from the step-2 read against the resolved scope (409); the guard in save_assessment and delete_assessment with the documented exemptions; save/approve set each finding's marker to resolved_marker (409 override_reason_mismatch for gap fills in a scope without an agreed reason); _validate_version_override_change allows gaining exactly the resolved marker; pending kept on findings of a pending override for reviewer saves, reviewer team/General deletes and bulk writers; approve operation (reviewer only, scope-wide, removes pending, records Reviewed By, audit entry). incomplete_sync per scope (resolved marker, kept pending, override_conflict); automatic assessments kept_override; assessment_repair per scope. Carry-over: target scope via version_scope with the carried-from records; keep the carried marker unless other active findings of the version carry a different label; GoneFindingsPanel reason. Return of gone findings: scope over every finding active after the read; agreeing marker reactivates with the same value and revision, disagreeing becomes pending. MCP: get_vulnerability assessment_scopes; assessment_scope on preview and save; expected_revisions per scope. Frontend in the same release: useAssessmentScope (card and workspace), switcher, dirty-switch prompt, re-derive on events and on 409, scope-limited save/delete/approve/sync draft/Apply/Adopt, Approve sending operation 'approve', 'Use for this scope', filtered view opening on its version's scope, evidence 'about other versions'. Docs: review-workflows.md, ai-access.md, import-export.md (return, flap invariant, carry-over), assessment-model.md (approval, gone-during-split), screens.md, README. | Use-case: 409 on spanning saves and deletes, on a stale assessment_scope, and on a stale cache (stored marker disagrees); exemptions for restore, adoption and carry-over. A team save in L including an inherited NOT_SET finding leaves the scope ASSESSED or NEEDS_APPROVAL, not PARTIAL; per-scope Synchronize of an INCOMPLETE override scope likewise. A reviewer Synchronize, a reviewer team delete and a reviewer plain save keep a pending override NEEDS_APPROVAL; approve makes it ASSESSED; an analyst cannot approve. A forced approve racing a split fails and the split's tags survive. Fallback and cache paths resolve a version with a gone tagged record to the same scope. Bulk counters; base Synchronize never writes into an override. Return: whole-version flap keeps value and revision; a disagreeing marker becomes pending and PARTIAL. Carry-over: replacing the single component of an overridden version keeps [Version Override] (pending) and the version stays in L; another active label wins. MCP: multi-scope save without assessment_scope fails; revisions only for that scope. vitest/component: switcher, prompt, event and 409 re-derive, Approve operation, variant button limited to the scope, workspace and card sharing state. |
| 8. feat(overrides): split, apply override/base and return to base, behind DTVP_VERSION_OVERRIDES_ENABLED | dtvp/version_override_services.py and POST /api/assessment/version-override (split/join, apply_override with optional reason unification, apply_base, return_to_base converting blocks to historical), persisted in one call with the operation's own read revisions. Validation: analyst pending, return reviewer-only, flag 403 for every operation that changes a version's scope to a label (split; apply_override into a version not already mapped to it); always allowed: apply_override to gaps of a version in that label, apply_base, return_to_base, approve. Inactive records are not rewritten (gone-during-split returns pending by design). Audit entry. The flag in configuration and /api/me features. MCP propose_version_override (always pending, flag-gated as above). Frontend: version column header menu in FindingMatrix, split dialog listing every finding of the version, new-version actions (Apply base / Apply <L> / Assess separately), Return to base diff with one-click when identical. Docs: configuration.md (exactly what the flag gates), review-workflows.md, screens.md, ai-access.md, import-export.md (gone during split), README. | Role x operation x flag matrix, including join (apply_override into a base or new version) with the flag on and off per role, and gap apply_override always allowed. Split copies without replacing, NOT_SET findings get the tags only; joining an existing label; apply_override fills gap findings and unifies a reason; return_to_base leaves a historical block per override block and no tag, and the lifecycle is back to base. A finding gone during a split returns pending and PARTIAL. Agent proposal is pending and an agent cannot approve. Events emitted through persist_assessment_updates. Component tests: menu hidden with the flag off except gap apply and Return to base for reviewers, both dialogs, the analyst 'proposed' notice. |
| 9. feat(repair): 'Keep differences per version' repair stage | assessment_repair: a reviewer-only, flag-gated stage, never preselected, that offers a split (with a diff per version) for Conflicting groups whose differences fall along version lines, using version_override_services. Docs: review-workflows.md. | The stage appears only for reviewers with the flag on, never preselected; a group with differences along version lines is offered; a group with differences inside one version is not; applying it produces an approved override, since a reviewer's split is an explicit operation saved without pending (spec 6.4). |
