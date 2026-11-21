# ADR 0010: Version overrides of an assessment

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-20, repository owner; see [Decisions](#decisions)) |
| Implementation status | In progress (2026-11-21): steps 0 to 5 of the [plan](../version-overrides-design.md#19-plan); the marker is a read-only field every writer keeps, and the lifecycle runs per scope ([Version override](../assessment-model.md#version-override)). Not yet in step 5: per-scope SSVC summaries and `max_rescored_cvss` |
| Related | [ADR 0003](0003-dtvp-is-the-record-for-assessments.md): **amends decisions 2 and 6** (see [Amendments to ADR 0003](#amendments-to-adr-0003)). [ADR 0009](0009-native-vulnerability-matcher.md): decision 7, override scopes are keyed by the DTVP project version id after M3; decision 2, medium-band findings (see decision 12). [ADR 0005](0005-logical-dump-format.md): no change to the dump format. [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md): agents propose and never approve. |

## Context

DTVP groups a vulnerability's findings across all project versions and expects one assessment for all of them:

- The card saves to every finding of every version (`useVulnDependencyInfo.allInstances`).
- Any two differing states make the vulnerability Conflicting (`ANALYSIS_STATE_MISMATCH`, checked before every other lifecycle rule).

Products do differ between versions, for example when 2.x uses a patched fork. Today a reviewer has two ways to record that, and both are wrong. One is to leave the vulnerability Conflicting for good. The other is to write one text that blurs the versions. A per-version difference made through the API is collapsed again by the next save from the card.

The code was checked at origin/main fc999882; fix #296 (DTVP's own finding key as `finding_uuid`) has landed since. Further problems turned up:

- Synchronize and automatic assessments ignore `is_new_finding`, so Synchronize copies an older version's assessment onto findings that a new version added without anyone choosing that.
- `[Version Coverage: …]` and historical blocks are part of the text comparison, so ticking a box in one version, or a historical block restored into one version, makes the vulnerability Conflicting. Synchronize also merges historical blocks as if they were current and copies one text to every finding.
- Approval is only the absence of `[Status: Pending Review]`. An analyst's save through the fields path could store an unpending text (fixed since, #297), Synchronize strips the marker, and a reviewer's plain save or delete drops it. Forced saves (approve, force-overwrite) carry no revision guard.

## Drivers

- A difference between versions is intended only when someone said so, and a reviewer approved it with an explicit act. Nothing is guessed from the data.
- Unmarked differences stay Conflicting, as today.
- A new version gets no assessment copied without someone choosing it (ADR 0003 decision 6).
- No team block, no historical record and no override disappears without a record (rule from #291).
- Business rules live in the domain layer and are enforced for the card, the API, MCP and the bulk workflows alike.
- Identity is never a version label string. Scopes follow DTVP's finding and version keys (ADR 0009 decision 7).
- No change to the dump format, and no new table to back up and verify.
- Small, separately shippable steps. Teams that do not want the feature see no change except fixes.

## Alternatives

- **Scoped blocks (a version list in each team block).** Rejected. It needs the same plumbing, but every finding stores a full version list with several validity rules, and adding a version rewrites every member. It has no base for new versions to fall back to.
- **Split groups (one group per scope, with a second record keyed by a group id).** Rejected. Group ids are not stable. It would change the cache, the archive and the dump, and statistics would count a vulnerability once per scope.
- **Infer intended differences from analyzer facts.** Rejected as a rule; at most a suggestion a person applies. A "not affected" that nobody stated would be an unreviewed claim.
- **Store scopes in a separate table.** Rejected. It would be a second record next to the assessment text, need a dump entity, COLUMN_MAP entries and verify coverage, and could disagree with the text.
- **Approval stored as a field of the override (the reviewer on the tag) instead of the absence of pending.** Not chosen for now: it adds a third tag and a second notion of approval next to the existing pending marker. The pending marker is kept, and only the approve operation may remove it from an override scope (decision 6).
- **Rewrite inactive records when a version's scope changes.** Rejected. Inactive records are not exported, and changing their value would break the flap invariant of the finding lifecycle. A finding that was gone during the change is reconciled when it returns (decision 8).
- **Leave the feature out and keep the vulnerability Conflicting.** Rejected. It keeps a permanent false signal and pushes reviewers to blur the texts.

## Decision

1. **Base plus marked exceptions.** Each vulnerability group has one base assessment. A finding whose text carries `[Version Override: <label>]` and `[Override Reason: <reason>]` belongs to the override scope `<label>`. All versions with the same label share one scope.
2. **Scope is a property of the project version, derived, never stored separately.**
   - A version maps to the one label its active findings carry, else to base.
   - Every finding of the version belongs to that scope, including untouched (NOT_SET, no content) and new findings.
   - Two labels in one version, or an assessed finding without the label in an overridden version, are Conflicting.
   - The version key is `project_uuid` now, and the DTVP project version id after ADR 0009 M3.
3. **The lifecycle runs per scope.** The existing rules apply inside each scope, with required teams computed from the scope's own findings. The vulnerability's lifecycle combines the scope lifecycles, worst first: Conflicting, Incomplete, Ready for approval, Assessed. A proposed override is Ready for approval, never Assessed.
4. **Text comparison ignores records and tags that are not the assessment:** historical blocks, `[Version Coverage]` and the override tags (whose reason is compared on its own). This also applies to vulnerabilities without overrides. Synchronize correspondingly merges only current blocks and keeps each finding's own historical blocks on that finding.
5. **Every writer works inside one scope, and writes the scope's marker.**
   - A save or delete whose findings span scopes, or whose stored markers disagree with the resolved scope, is rejected with 409, in the domain layer.
   - Explicit operations may span scopes: split, apply override, apply base and Return to base, plus restores, adoption and carry-over.
   - Ordinary saves and per-scope bulk writers set every target finding's marker to its scope's marker (none for base). A finding that inherits the scope therefore joins it when it is assessed; any other change of a marker needs an override operation. A whole delete keeps the marker, so the finding stays in its scope.
   - Every save, forced ones included, is guarded by the revisions the use case read itself; `force` only overrides the check against the client's view.
6. **Propose, then approve.**
   - Every save by a non-reviewer is stored as pending review, enforced server-side for text and fields alike. Analysts and agents may propose a split, or apply an existing override, only as pending review.
   - Pending is removed only by the reviewer's approve operation, in the base scope and in override scopes alike (a reviewer's own split or apply is saved approved, since it is itself the explicit act). A reviewer's plain save, a reviewer's delete and every bulk writer keep it.
   - Return to base is reviewer-only. It turns the override's current blocks into historical blocks noted "Former version override <label>: <reason>" before applying the base.
7. **Nothing is copied to new findings without a choice.** Synchronize skips findings marked new, unless the user includes them explicitly for that vulnerability. Automatic assessments skip a new finding only when none of the applied analysis runs covered its project version; a run that covered the version is evidence about it, not a copy. "Automatic assessment" means an assessment an analyzer or an agent produced: the Agentyzer integration is to be replaced by agents working through MCP (ADR 0001, ADR 0006), and the rule is the same for both. A new version maps to base and stays unassessed until someone applies the base, applies an override, or assesses it separately.
8. **Markers from outside are reviewed.**
   - A value adopted from the source or an archive that carries a marker is kept unchanged as revision 0 (origin `import`); a second revision (origin `import-review`) marks it pending review and is exported.
   - A returning gone finding keeps its value and revision when its marker agrees with its version's scope computed over every finding active after the read; otherwise it is marked pending review. A finding that was gone while its version's scope changed therefore returns pending, by design.
   - A carried-over value keeps its marker unless other active findings of the same version carry a different label; then it takes that label (or none, for base).
9. **Stored in the text and the fields only.** The fields tables get `version_override` and `version_override_reason` (outbox migration 0009, derived, with no record effect). The dump format stays dump/1; `import-review` is a new value of the existing revision origin.
10. **Export and MCP.**
    - The per-version VDR marks every finding of an overridden version, inherited ones included, with `<prefix>:assessment_scope`, `<prefix>:version_override`, `<prefix>:version_override_reason` and `<prefix>:version_override_status` (`pending` or `approved`), computed by the same scope function, and validated against the CycloneDX schema.
    - MCP returns scopes. It requires `assessment_scope` on preview and save when there is more than one scope, and offers `propose_version_override` (always pending).
11. **Feature flag.** `DTVP_VERSION_OVERRIDES_ENABLED`, off by default, gates every operation that changes a version's scope to a label: split, and applying an override to a version not already mapped to that label (joining), plus the agent proposal and the repair stage. Always on: reading, the scoped lifecycle, the guard, approve, applying an override to gap findings of a version already in it, apply base, Return to base and export, so existing or imported markers can always be handled.
12. **ADR 0009 medium-band findings.** The matcher should record "needs match review" as a finding attribute, not as an assessment state. If it sets a system `IN_TRIAGE` state instead, an untagged finding whose only content is that state counts as untouched: a gap in an overridden version, not partial, and new for the new-findings flag. One shared predicate decides "untouched" for all of these.

## Amendments to ADR 0003

Both take effect with the acceptance of this ADR (2026-11-20). ADR 0003 notes them at the decisions they amend.

- **Decision 2 (one-time adoption), amended.** Adoption still stores the Dependency-Track value unchanged as revision 0, origin `import`, and after adoption the record is DTVP's. New: when the adopted value carries a version override marker, DTVP appends revision 1, origin `import-review`, which adds `[Status: Pending Review]` and nothing else, and exports it under decision 3. Reason: a marker from outside is a scope claim nobody in this instance reviewed.
- **Decision 6 (new findings are marked new, not assessed automatically), amended.** It holds for copying: no writer copies another version's assessment onto a new finding unless a person chooses it (Apply base, Apply override, or the explicit Synchronize opt-in). New: an automatic-assessment run whose analysis covered the new finding's project version may assess it like any other finding, since that verdict is about this version. The rejected alternative of ADR 0003 ("carry assessments to new project versions automatically") stays rejected.

## Consequences

- A vulnerability can be fully assessed when its versions really differ, and the VDR of each version carries that version's assessment, says it is an override, and says whether it is approved.
- Some existing vulnerabilities become less Conflicting: those whose texts differed only in historical blocks or Version Coverage. No stored record is rewritten. Synchronize no longer moves historical blocks between findings.
- Synchronize no longer fills new findings unless asked. Reviewers see them as new and decide. This is a visible behaviour change, documented in review-workflows.md.
- Analysts can no longer store an unpending text through the fields path, and forced saves fail on a concurrent write. Both are fixes for every group.
- Approving an override is an explicit act; a reviewer's edit of a pending override leaves it pending.
- Saves from older clients that span scopes get 409 once a vulnerability has overrides. Without overrides, nothing changes.
- The text sent to Dependency-Track carries two more tags. Consumers that parse DTVP markup from Dependency-Track text must ignore or read them. DTVP's own consumers read the VDR.
- Inactive records of gone findings keep the marker they had. A finding that returns with an agreeing marker is reactivated unchanged; one that was gone while its version's scope changed comes back pending review.
- The scope logic exists twice, in Python and TypeScript, and is kept equal by shared fixtures.

## Confirmation

- Shared backend and frontend fixtures pass for every scope case: base only, an approved override, a pending override, two versions sharing a label, one label with two reasons, a partial version, an ambiguous version, an untagged NOT_SET finding in an override, a new component in an override, a new version, carry-over into an override, carry-over replacing every tagged finding of an override, a team without components in the override versions, a filled gap, and historical-only or Version Coverage-only differences.
- With the feature flag off, every existing test passes except those changed by decisions 4, 6 (server-side pending), 5 (forced-save revision guard) and 7, and those changes are listed in the release notes.
- A save or delete spanning scopes, or against a stale cache, returns 409 from the use case. MCP save without `assessment_scope` on a multi-scope vulnerability fails. An analyst or agent save or split is always pending.
- A scoped save or Synchronize that covers an inherited gap finding leaves the scope Assessed or Ready for approval, not Conflicting.
- A pending override stays Ready for approval after an analyst fields save, a reviewer Synchronize, a reviewer team delete and a reviewer plain save; only approve makes it Assessed.
- A forced approve that races a split fails, and the split's tags survive.
- Team, General and whole deletes inside an override keep the marker. Return to base leaves a historical block for every override block.
- Synchronize keeps each finding's own historical blocks and never makes one current.
- Synchronize and automatic assessments report `new_finding` and `kept_override` counts; automatic assessments apply covered runs to new findings and skip uncovered ones.
- A whole-version flap reactivates findings with the same value and revision. Adoption with a marker stores revision 0 `import` unchanged and revision 1 `import-review` pending.
- A VDR with pending and approved overrides validates against the CycloneDX 1.5 schema.
- Backup coverage tests pass with migration 0009 registered as having no record effect. A dump round trip keeps the markers and the `import-review` revisions.

## Decisions

Recorded on 2026-11-20 by the repository owner.

| # | Decision |
|---|---|
| P1 | Versions with the same override label share one scope |
| P2 | Analysts and agents propose (pending review); an override counts as intended only after a reviewer approves it |
| P3 | New versions: nothing is copied; the card offers Apply base, Apply override and Assess separately |
| P4 | Off by default in the first release: the setting gates creating overrides; reading, guarding and exporting are always on |
| P5 | `[Version Coverage]` is ignored when comparing assessment texts |
| P6 | Return to base is reviewer-only |
| P7 | Synchronize leaves a new version's findings unassessed by default; the preview lists them as new, not synchronized; a reviewer can include them per vulnerability |
| P8 | Only an explicit Approve removes pending review, everywhere, the base scope included; a reviewer's plain save keeps it |
| P9 | An analyzer's or agent's assessment whose analysis covered the new version itself may assess that version's findings (amends ADR 0003 decision 6) |
| P10 | A finding that was gone while its version's scope changed returns pending review and flagged; inactive records are not rewritten |
| P11 | A save that would fill a gap in a scope whose findings disagree on the reason is refused until a reviewer aligns the reasons |
| P12 | The security documentation generator reads the VDR only; it does not need the new tags in Dependency-Track's text |

Taken as designed, without a separate decision: adoption of a value with a marker is stored as revision 0 unchanged (`import`) plus revision 1 (`import-review`) that adds pending review.
