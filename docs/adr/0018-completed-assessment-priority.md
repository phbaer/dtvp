# ADR 0018: False positive is the least concerning completed assessment

Status: accepted, 2026-11-27. Owner: DTVP maintainers.
Amends the ordering in [ADR 0014](0014-lifecycle-decision-table.md).

## Context and decision

The previous shared order made False positive override Not affected and
Resolved when deriving a decision from teams. The user approved placing
False positive below both: an incorrect finding needs less attention than
a real vulnerability assessed as inapplicable or resolved.

Use the [canonical assessment order](../assessment-model.md#the-global-decision)
for both server and client. Keeping a separate display order was rejected:
the displayed decision would disagree with exports and repair. Not assessed
remains unresolved; its sentinel rank does not make it a safe decision.

## Consequences and confirmation

Mixed completed team assessments can derive a different Global decision.
Explicit reviewer decisions, stored assessment text, audit history and
original advisory severity are preserved. Export and repair use the new
order when next invoked; this change does not automatically rewrite remote
Dependency-Track records.

Confirm with shared lifecycle/order fixtures, pairwise aggregation and
export-state tests, plus frontend unit and browser checks. Implementation
and verification results are recorded in the associated pull request.
