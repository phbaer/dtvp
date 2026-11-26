# ADR 0016: Changes requested for a team assessment

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Proposed (2026-11-26) |
| Implementation status | Implemented |
| Related | [ADR 0003](0003-dtvp-is-the-record-for-assessments.md), [ADR 0010](0010-version-overrides.md), [ADR 0014](0014-lifecycle-decision-table.md) |

## Context and drivers

Reviewers need to send a submitted team assessment back with a rationale.
The team must see what to address. Approval must wait for a new submission,
while the existing technical decision remains available for review and audit.

## Alternatives

- Setting the technical state to **In triage** would replace the team's
  conclusion and could change the product's effective decision and export.
- An ordinary comment would preserve the feedback but leave approval and the
  analyst's work list unchanged.
- A team-level review flag lets the team and reviewer act on the feedback
  while preserving the original verdict, scoring and rationale.

## Decision

Store an outstanding **Changes requested** review decision for the selected
team with a reviewer, timestamp and required rationale. A reviewer applies it
to a current submitted team assessment. Approval checks the outstanding
decision against the stored assessment. An explicit resubmission resolves the
request for that team, with the previous request available in history. A
reviewer can withdraw an obsolete request without clearing the team's
assessment.

Use the existing **Incomplete** lifecycle for an assessment that requires
team action. Preserve the technical verdict and surface the outstanding
request alongside it. The request continues to block approval when a Global
assessment covers the team's ordinary missing assessment.

Feedback follows the same export and audit visibility as assessment details
in Dependency-Track. The assessment history retains it after resubmission or
withdrawal.

## Consequences and confirmation

This reuses the existing work lists and status filters. A team request must
remain visible to its team independently of Global coverage. Verify that a
stale save, repair or the approval action cannot erase outstanding feedback.
Verify two teams can receive requests independently and that a team
resubmission retains the other team's request. Confirm that reviewers can
read the rationale from the assessment and history.

See [assessment review rules](../assessment-model.md#changes-requested) and
the [review workflow](../review-workflows.md#requesting-changes).
