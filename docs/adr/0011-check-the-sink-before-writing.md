# ADR 0011: Check the sink before writing; edits made there go to an inbox

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Proposed (2026-11-23) |
| Implementation status | Not started; planned for 2.1.0 |
| Related | [ADR 0003](0003-dtvp-is-the-record-for-assessments.md): **amends decision 3** ("Dependency-Track is a rendering target") and the overwrite described in [When Dependency-Track Holds Something Else](../import-export.md#when-dependency-track-holds-something-else). [ADR 0004](0004-background-sync-and-event-stream.md): the background sync reads conservatively (no polling, idle without users, amendment of 2026-11-23); this record makes correctness independent of how often it reads. |

## Context

DTVP is the record for assessments (ADR 0003). Dependency-Track receives a
rendering of them. When an import finds a different value there, DTVP exports
its own value again, so an assessment changed directly in Dependency-Track is
overwritten. Earlier versions held such findings as conflicts; that handling
was removed with ADR 0003.

Two things changed since:

- The background sync no longer polls. Since 2026-11-23 it reads a version
  only on a change hint, a request, a first import, missing data or a stale
  open, and nothing while nobody uses DTVP (ADR 0004 amendment). A hand edit
  in Dependency-Track does not move the change hints, so DTVP may export over
  it before any read has seen it.
- The sink port already reads the value a write would replace
  (`AssessmentSink.get_analysis` in `dtvp/ports.py`), and DTVP keeps the value
  it last exported or adopted per finding, the base its echo classification
  uses (ADR 0004, decision 5).

Overwriting silently loses a person's decision. Reading Dependency-Track often
enough to catch every hand edit costs requests DTVP has just learned to avoid.

## Drivers

- No silent loss of a decision made in either place.
- Correctness must not depend on how often the background sync reads.
- Cheap: at most one extra request per exported finding.
- Source neutrality: the core uses the sink port, not Dependency-Track
  specifics (`tests/test_source_neutrality.py`).
- A person decides; DTVP does not guess which value is right.
- Sources and sinks stay black boxes: DTVP tracks what it did itself and reads
  only the sink's current value, not its history, users or internals.

## Decision

1. **Every exported field counts.** The comparison covers everything DTVP
   writes: state, justification, response, suppression and the text, exactly
   (whitespace included). Any difference means the sink is out of sync with
   DTVP.
2. **Check before writing.** Right before the export writes a finding, it
   reads the sink's current value through `AssessmentSink.get_analysis` and
   compares it with DTVP's value and with the base (the value DTVP last
   exported or adopted for that finding):
   - sink already equals DTVP's value: nothing to write; record it as exported;
   - sink equals the base: write, as today;
   - sink differs from both: decision 3.

   A finding without a base follows ADR 0003's adoption rule (decision 2),
   unchanged.
3. **DTVP tracks only what it did; the sink is a black box.** DTVP does not
   ask the sink who changed a value or why. It knows what it wrote last (the
   base) and what the sink holds now:
   - the sink holds no value for the finding (lost, recreated, reset to not
     set): **re-export**, as today. A value the sink keeps refusing ends as the
     existing failing export ("Dependency-Track did not keep the exported
     assessment"), so this cannot loop;
   - the sink holds a value that is neither the base nor DTVP's value: **hold**
     the export and create an inbox item. DTVP cannot tell a person's edit from
     anything else, so it does not overwrite a value it did not write.
4. **Reads raise the same item.** When a read (change hint, request, safety
   re-read) finds such a value, it creates the same inbox item instead of
   queueing an overwrite. A missing value is re-exported.
5. **The inbox.** One list of items that need a person, per project version
   and across the portfolio. An item for a changed sink value shows the
   finding, DTVP's value, the sink's value, the base, and when DTVP noticed the
   difference. Reviewers decide:
   - **Keep DTVP's value**: the held export is written (overwrite);
   - **Adopt the sink's value**: it becomes a new DTVP revision (origin
     `sink-adopted`, with who decided), parsed into fields like an import;
   - **Edit**: open the assessment form with both values to merge, then save.

   Analysts see the items and can propose an edit, which stays pending review.
   Agents (MCP) can list items but not resolve them (ADR 0001).
6. **Held, not failing.** A held export does not count as failing, is not
   retried, and does not block other findings. The export indicator shows
   held items separately. `DTVP_EXPORT_MODE=manual` keeps working; its export
   list shows held items with a link to the inbox.
7. **Events.** New and resolved items are events on the event stream
   (`inbox.changed`), so open views update.
8. **An item closes itself** when the sink agrees again before a reviewer
   decided: the sink returns to the base (the held export is
   then written, as in decision 2) or already holds DTVP's value (the held
   export is dropped). The item records how it closed.
9. **Other events may join the inbox later** (gone findings to acknowledge, a
   sync that keeps failing, agent proposals). Each joins by its own change;
   this record covers changed sink values.

## Alternatives

- **Keep overwriting** (today). Simple, but a hand edit in Dependency-Track is
  lost without anyone seeing it.
- **Poll Dependency-Track often enough to see hand edits.** Costs requests
  across the whole portfolio and still races the export.
- **Adopt the sink's value automatically when it is newer.** Removes the person
  from a decision about an assessment; contradicts ADR 0003 decision 1.
- **Bring back the old conflict state on the finding.** Blocked the finding's
  whole workflow; the inbox holds only the export and lists the decision in
  one place.

## Consequences

- One extra read per exported finding. Exports become slower per item but
  remain within the shared request budget; they are far fewer than the
  per-finding analysis reads removed in 2.0.
- A hand edit in Dependency-Track survives until a reviewer decides.
- New storage: inbox items with their values and resolution (a local store
  migration; dump format entities with a version bump, ADR 0005).
- A new reviewer workflow and screen; documentation in
  `docs/import-export.md`, `docs/review-workflows.md`, `docs/screens.md`.
- ADR 0003 decision 3 changes from "always overwrite" to "re-export a missing
  value; a value DTVP did not write waits for a reviewer".
- A change the sink makes on its own to a stored value (if a sink ever
  rewrites values) also lands in the inbox; a reviewer keeps DTVP's value once
  and the item does not return while the sink keeps it.

## Confirmation

- Tests: an export over an unchanged sink value writes; an export where the
  sink already holds DTVP's value writes nothing; an export where the sink
  holds another value (a whitespace difference included) writes nothing and
  creates exactly one item, while a sink without a value is re-exported;
  an item closes itself when the sink agrees again; each of the
  three resolutions has the stated effect and history; a read that sees a hand
  edit creates the item; a held export is not retried and not counted as
  failing; a dump round trip keeps items.
- Against a running Dependency-Track 4.14: change an analysis field in its UI,
  save the finding in DTVP, and see the item instead of an overwrite; undo the
  change in Dependency-Track and see the item close.

## Open questions

None at the time of writing.
