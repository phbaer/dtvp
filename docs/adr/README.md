# Architecture Decision Records

[Project overview](../../README.md) · [Documentation index](../../README.md#documentation)

Decision status and implementation status are tracked separately in each record.

| ADR | Decision | Implementation |
| :--- | :--- | :--- |
| [0001: AI access through MCP and personal access tokens](0001-ai-access-through-mcp-and-access-tokens.md) | Accepted | Implemented |
| [0002: Local-first database with import and export](0002-local-first-database-with-import-and-export.md) | Accepted; merge and conflict handling superseded by 0003 | Implemented, with listed limits |
| [0003: DTVP is the record for assessments](0003-dtvp-is-the-record-for-assessments.md) | Accepted | Partly implemented |
| [0004: Backend I/O runs in the background; clients follow an event stream](0004-background-sync-and-event-stream.md) | Accepted | In progress |
| [0005: Logical dump format for backup, restore and migration](0005-logical-dump-format.md) | Accepted | Implemented |
| [0006: Agent code evidence is applied by a person](0006-agent-code-evidence-is-applied-by-a-person.md) | Proposed | Implemented |
| [0007: The VDR recommendation comes from the ranges Dependency-Track holds](0007-recommendation-from-dependency-track-ranges.md) | Proposed | Implemented |
| [0008: Expiring, revocable session tokens](0008-expiring-revocable-session-tokens.md) | Accepted | Implemented |
| [0009: DTVP matches vulnerabilities itself from mirrored advisories](0009-native-vulnerability-matcher.md) | Accepted | Not started |
| [0010: Version overrides of an assessment](0010-version-overrides.md) | Accepted; amends decisions 2 and 6 of 0003 | In progress (steps 0-6) |
| [0011: Check the sink before writing; edits made there go to an inbox](0011-check-the-sink-before-writing.md) | Accepted; amends decision 3 of 0003 | Not started (planned for 2.1.0) |
| [0012: The team mapping is organised by team](0012-team-centric-mapping.md) | Accepted | Implemented |
| [0014: One lifecycle decision table; a pending Global decision is ready for approval](0014-lifecycle-decision-table.md) | Accepted | Implemented |
| [0015: A cutoff on the published or first-attributed date, and saved views with short links](0015-saved-views-cutoff-and-short-links.md) | Accepted | Implemented ([PR #360](https://git.baer.one/phbaer/dtvp/pulls/360)) |
| [0016: Changes requested for a team assessment](0016-team-assessment-changes-requested.md) | Proposed | Implemented |
