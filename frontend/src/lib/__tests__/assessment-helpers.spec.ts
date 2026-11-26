
import { describe, it, expect } from 'vitest';
import parserCasesJson from './fixtures/assessment_parser_cases.json'
import { parseAssessmentBlocks, constructAssessmentDetails, mergeTeamAssessment, buildBulkSyncDetails, getGroupLifecycle, getGroupInconsistencyReasons, getAssessmentSyncDraft, getAssessedTeams, hasOpenTeamAssessment, normalizeTags, assessmentTextToFields, assessmentTextKey, sanitizeAssessmentDetails, withoutHistoricalBlocks, markAssessmentBlocksHistorical, parseVersionOverride } from '../assessment-helpers';
import { renderAssessmentFields } from './assessmentFieldsText';

// Kept inside the frontend tree: the Docker image builds the frontend
// without the repository's tests/ folder.
const parserCases = parserCasesJson as Array<{ name: string; text: string; blocks: any[]; version_override?: any }>

describe('Assessment Helpers', () => {
    describe('getGroupLifecycle', () => {
        it('ignores historical team blocks in current lifecycle and state', () => {
            const details = [
                '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] [Historical: yes] ---',
                'Former owner',
                '--- [Team: TeamB] [State: RESOLVED] [Assessed By: bob] [Copied From: TeamA] ---',
                'Current owner',
            ].join('\n')
            const group: any = {
                id: 'CVE-TRANSFERRED',
                tags: ['TeamB'],
                affected_versions: [{ components: [{ analysis_state: 'RESOLVED', analysis_details: details }] }],
            }
            expect(getGroupLifecycle(group, group.tags, {})).toBe('ASSESSED')
            expect(getAssessedTeams(group)).toEqual(new Set(['TeamB']))
            expect(parseAssessmentBlocks(details)[0]?.historical).toBe(true)
            expect(parseAssessmentBlocks(details)[1]?.copiedFrom).toBe('TeamA')
        })

        it('should return OPEN when no component has a technical assessment', () => {
            const group: any = {
                id: 'CVE-OPEN',
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            { analysis_state: 'NOT_SET', analysis_details: '' }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('OPEN');
        });

        it('should normalize alias tags to their primary team', () => {
            const mapping = {
                'libA': ['PrimaryTeam', 'OldAlias', 'LegacyAlias']
            };
            const tags = normalizeTags(['OldAlias', 'PrimaryTeam'], mapping);
            expect(tags).toEqual(['PrimaryTeam']);
        });

        it('should return ASSESSED_LEGACY when technical state exists but the format is legacy', () => {
            const group: any = {
                id: 'CVE-LEGACY',
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            { analysis_state: 'FALSE_POSITIVE', analysis_details: '' }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('ASSESSED_LEGACY');
        });

        it('should return INCOMPLETE when required team assessments are missing despite structured blocks', () => {
            const group: any = {
                id: 'CVE-INCOMPLETE',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'FALSE_POSITIVE',
                                analysis_details: '--- [Team: team-a] [State: FALSE_POSITIVE] ---'
                            }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');
        });

        it.each([
            '--- [Team: General] [State: NOT_AFFECTED] ---',
            '--- [Team: General] [State: NOT_AFFECTED] ---\n--- [Team: team-a] [State: NOT_AFFECTED] ---',
            'Legacy analyst assessment',
            '',
        ])('should stay INCOMPLETE while a version has no assessment (%j)', (details) => {
            const assessedVersions = ['b', 'c', 'd'].map(version => ({
                project_version: version,
                components: [{ analysis_state: 'NOT_AFFECTED', analysis_details: details }],
            }));
            const group: any = {
                id: 'CVE-MISSING-VERSION',
                tags: ['team-a'],
                affected_versions: [
                    { project_version: 'a', components: [{ analysis_state: 'NOT_SET', analysis_details: '' }] },
                    ...assessedVersions,
                ],
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');
        });

        it('should treat an approved General assessment as terminal', () => {
            const group: any = {
                id: 'CVE-GLOBAL-BEFORE-TEAMS',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'FALSE_POSITIVE',
                                analysis_details: [
                                    '--- [Team: General] [State: FALSE_POSITIVE] ---',
                                    '--- [Team: team-a] [State: FALSE_POSITIVE] ---',
                                ].join('\n'),
                            },
                        ],
                    },
                ],
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('ASSESSED');

            group.affected_versions[0].components[0].analysis_details +=
                '\n[Status: Pending Review]';
            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');

            group.affected_versions[0].components[0].analysis_details +=
                '\n--- [Team: team-b] [State: FALSE_POSITIVE] ---';
            expect(getGroupLifecycle(group, group.tags, {})).toBe('NEEDS_APPROVAL');

            group.affected_versions[0].components[0].analysis_details =
                '--- [Team: team-a] [State: FALSE_POSITIVE] ---';
            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');
        });

        it('should not classify pending legacy assessments as assessed', () => {
            const group: any = {
                id: 'CVE-PENDING-LEGACY',
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'FALSE_POSITIVE',
                                analysis_details: 'Legacy analyst assessment\n[Status: Pending Review]',
                            },
                        ],
                    },
                ],
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');
        });

        it('should return INCONSISTENT when multiple distinct component states exist but no assessment blocks', () => {
            const group: any = {
                id: 'CVE-INCONSISTENT',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            { analysis_state: 'EXPLOITABLE', analysis_details: '' },
                            { analysis_state: 'NOT_AFFECTED', analysis_details: '' }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCONSISTENT');
            expect(getGroupInconsistencyReasons(group)).toContain('ANALYSIS_STATE_MISMATCH');
        });

        it('should return INCONSISTENT when same state but different analysis details across instances', () => {
            const group: any = {
                id: 'CVE-DIFF-DETAILS',
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            { analysis_state: 'NOT_AFFECTED', analysis_details: '--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] [Date: 1000] ---\nFirst analysis' },
                            { analysis_state: 'NOT_AFFECTED', analysis_details: '--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: bob] [Date: 2000] ---\nDifferent analysis' }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCONSISTENT');
            expect(getGroupInconsistencyReasons(group)).toEqual(expect.arrayContaining([
                'TEAM_ASSESSMENT_MISMATCH',
                'ASSESSMENT_DETAILS_MISMATCH',
            ]));
        });

        it('should return INCONSISTENT when same state but different analysis details across versions', () => {
            const group: any = {
                id: 'CVE-DIFF-DETAILS-VERSIONS',
                tags: ['team-a'],
                affected_versions: [
                    {
                        components: [
                            { analysis_state: 'NOT_AFFECTED', analysis_details: '--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] [Date: 1000] ---\nAnalysis for v1' },
                        ]
                    },
                    {
                        components: [
                            { analysis_state: 'NOT_AFFECTED', analysis_details: '--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] [Date: 2000] ---\nAnalysis for v2' },
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCONSISTENT');
        });

        it('should judge one finding with two teams as several findings with the same blocks: ASSESSED', () => {
            const group: any = {
                id: 'CVE-MULTI-BLOCK',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'NOT_AFFECTED',
                                analysis_details: `--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] ---\nFirst analysis\n--- [Team: team-b] [State: NOT_AFFECTED] [Assessed By: bob] ---\nSecond analysis`
                            }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('ASSESSED');
        });

        it('should return INCONSISTENT when one team has two differing blocks within one finding', () => {
            const group: any = {
                id: 'CVE-SAME-TEAM-TWICE',
                tags: ['team-a'],
                affected_versions: [{ components: [{
                    analysis_state: 'NOT_AFFECTED',
                    analysis_details: `--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] ---\nFirst analysis\n--- [Team: Team-A] [State: EXPLOITABLE] [Assessed By: bob] ---\nSecond analysis`,
                }] }],
            };

            expect(getGroupInconsistencyReasons(group)).toContain('TEAM_ASSESSMENT_MISMATCH');
            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCONSISTENT');
        });

        it('should return ASSESSED when every version repeats complete multi-team assessments without General', () => {
            // The teams agree on the state, each with its own rationale.
            const sharedDetails = `--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: alice] ---\nApproved by team A\n--- [Team: team-b] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNot used by team B`;
            const group: any = {
                id: 'CVE-MULTI-BLOCK-REPEATED',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'IN_TRIAGE',
                                analysis_details: sharedDetails
                            }
                        ]
                    },
                    {
                        components: [
                            {
                                analysis_state: 'IN_TRIAGE',
                                analysis_details: sharedDetails
                            }
                        ]
                    }
                ]
            };

            expect(getGroupLifecycle(group, group.tags, {})).toBe('ASSESSED');

            for (const version of group.affected_versions) {
                version.components[0].analysis_details += '\n[Status: Pending Review]';
            }
            expect(getGroupLifecycle(group, group.tags, {})).toBe('NEEDS_APPROVAL');

            group.affected_versions.push({ components: [{ analysis_state: 'NOT_SET', analysis_details: '' }] });
            expect(getGroupLifecycle(group, group.tags, {})).toBe('INCOMPLETE');
        });

        it('should use the same team assessment check for open team assessment and chip state', () => {
            const group: any = {
                id: 'CVE-OPEN-TEAM',
                tags: ['team-a', 'team-b'],
                affected_versions: [
                    {
                        components: [
                            {
                                analysis_state: 'EMPTY',
                                analysis_details: '--- [Team: team-a] [State: NOT_AFFECTED] ---'
                            },
                            {
                                analysis_state: 'NOT_SET',
                                analysis_details: ''
                            }
                        ]
                    }
                ]
            };

            const assessed = getAssessedTeams(group);
            expect(assessed.has('team-a')).toBe(true);
            expect(assessed.has('team-b')).toBe(false);

            const open = hasOpenTeamAssessment(group, group.tags, {});
            expect(open).toBe(true);
        });
    });

    describe('parseAssessmentBlocks', () => {
        it('should parse legacy text as General block', () => {
            const text = 'Legacy analysis text.';
            const blocks = parseAssessmentBlocks(text);
            const general = blocks.find(b => b.team === 'General');
            expect(general).toBeDefined();
            expect(general!.details).toBe('Legacy analysis text.');
            expect(general!.justification).toBe('NOT_SET');
        });

        it('should parse structured blocks', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] [Justification: CODE_NOT_PRESENT] ---
Details A
--- [Team: TeamB] [State: FALSE_POSITIVE] [Assessed By: UserB] ---
Details B`;
            const blocks = parseAssessmentBlocks(text);
            const teamA = blocks.find(b => b.team === 'TeamA');
            const teamB = blocks.find(b => b.team === 'TeamB');
            expect(teamA).toBeDefined();
            expect(teamA?.state).toBe('IN_TRIAGE');
            expect(teamA?.details).toBe('Details A');
            expect(teamA?.justification).toBe('CODE_NOT_PRESENT');
            expect(teamB).toBeDefined();
            expect(teamB?.state).toBe('FALSE_POSITIVE');
            expect(teamB?.justification).toBe('NOT_SET');

            // Check order
            expect(blocks[0]!.team).toBe('TeamA');
            expect(blocks[1]!.team).toBe('TeamB');
        });

        it('should handle General + structured blocks', () => {
            const text = `General Text
--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] ---
Details A`;
            const blocks = parseAssessmentBlocks(text);
            const general = blocks.find(b => b.team === 'General');
            expect(general).toBeDefined();
            expect(general!.details).toBe('General Text');
            expect(general!.justification).toBe('NOT_SET');
            expect(blocks.find(b => b.team === 'TeamA')).toBeDefined();
        });

        it('should clean leaked metadata from details', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: user1] ---\nDetails A [Team: TeamB] [Status: Pending Review] [Rescored: 5.0]`;
            const blocks = parseAssessmentBlocks(text);
            const teamA = blocks.find(b => b.team === 'TeamA');
            expect(teamA?.details).toBe('Details A');
        });

        it('should use justification from another NOT_AFFECTED block when DT state has no justification', () => {
            const blocks = [
                { team: 'TeamA', state: 'NOT_AFFECTED', user: 'UserA', details: 'x', justification: 'NOT_SET' },
                { team: 'TeamB', state: 'NOT_AFFECTED', user: 'UserB', details: 'y', justification: 'CODE_NOT_PRESENT' }
            ];

            const result = getAssessmentSyncDraft(blocks, ['NOT_AFFECTED'], undefined);
            expect(result.state).toBe('NOT_AFFECTED');
            expect(result.justification).toBe('CODE_NOT_PRESENT');
        });

        it('should clean redundant metadata from details', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] ---
[Team: TeamA] My actual rationale -- UserA`;
            const blocks = parseAssessmentBlocks(text);
            const teamA = blocks.find(b => b.team === 'TeamA');
            expect(teamA).toBeDefined();
            expect(teamA?.details).toBe('My actual rationale');
        });

        it.each(parserCases)('reads "$name" as the server does', ({ text, blocks, version_override }) => {
            // fixtures/assessment_parser_cases.json is also read by
            // test_logic.py. Text before the first header is the client's
            // legacy General block; the server keeps it apart. Tags that are
            // fields of their own (response, version override) make none.
            let read = parseAssessmentBlocks(text)
            const legacy = read[0]
            if (!text.trimStart().startsWith('---') && legacy?.team === 'General' && legacy.user === 'Unknown') {
                read = read.slice(1)
            }
            if (version_override !== undefined) expect(parseVersionOverride(text)).toEqual(version_override)
            expect(read.map(block => ({
                team: block.team,
                state: block.state,
                justification: block.justification || 'NOT_SET',
                historical: Boolean(block.historical),
                ticket: block.ticket || '',
                details: block.details,
            }))).toEqual(blocks)
        });

        it('keeps evidence and coverage values other than yes through a save', () => {
            const stored = [
                '--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: b] [Justification: CODE_NOT_REACHABLE] [Evidence Reviewed: partial] [Version Coverage: 6.x only] ---',
                'Second.',
                '',
                '--- [Team: TeamT] [State: EXPLOITABLE] [Assessed By: t] [Date: 1] [Evidence Reviewed: partial] [Historical: yes] ---',
                'Old.',
            ].join('\n')
            const { text } = mergeTeamAssessment(stored, 'TeamA', 'NOT_AFFECTED', 'Not shipped.', 'alice')

            expect(text).toContain('[Team: TeamB] [State: NOT_AFFECTED] [Assessed By: b]')
            expect(text).toContain('[Evidence Reviewed: partial] [Version Coverage: 6.x only]')
            expect(text.match(/\[Evidence Reviewed: partial\]/g)).toHaveLength(2)
            const fields = assessmentTextToFields(text)
            const teamB = fields.teams.find(team => team.team === 'TeamB')
            expect([teamB?.evidence_reviewed, teamB?.version_coverage]).toEqual(['partial', '6.x only'])
        });

        it('reads [Historical: yes ] as historical everywhere', () => {
            const record = '--- [Team: TeamT] [State: EXPLOITABLE] [Assessed By: t] [Date: 1] [Evidence Reviewed: partial] [Historical: yes ] ---\nOld.';
            expect(parseAssessmentBlocks(record)[0]?.historical).toBe(true);
            expect(withoutHistoricalBlocks(record)).toBe('');
            expect(markAssessmentBlocksHistorical(record, ['TeamT'])).toBe(record);
        });

        it('should parse review context metadata from block headers', () => {
            const text = `--- [Team: Platform] [State: IN_TRIAGE] [Assessed By: alice] [Evidence Reviewed: yes] [Version Coverage: checked] [Ticket: SEC-42] ---
Checked direct usage and release branches.`;
            const blocks = parseAssessmentBlocks(text);
            expect(blocks).toHaveLength(1);
            expect(blocks[0].evidenceReviewed).toBe(true);
            expect(blocks[0].versionCoverageChecked).toBe(true);
            expect(blocks[0].ticket).toBe('SEC-42');
            expect(blocks[0].details).toBe('Checked direct usage and release branches.');
        });
    });

    describe('constructAssessmentDetails', () => {
        it('should format blocks correctly', () => {
            const blocks = [
                { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'Details A', justification: 'CODE_NOT_PRESENT' }
            ];
            const result = constructAssessmentDetails(blocks);
            expect(result.text).toContain('--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] [Justification: CODE_NOT_PRESENT] ---');
            expect(result.text).toContain('Details A');
            expect(result.text).toContain('[Status: Pending Review]');
            expect(result.aggregatedState).toBe('IN_TRIAGE');
        });

        it('should calculate aggregated state (Critical wins)', () => {
            const blocks = [
                { team: 'TeamA', state: 'NOT_AFFECTED', user: 'UserA', details: '', justification: 'CODE_NOT_PRESENT' },
                { team: 'TeamB', state: 'EXPLOITABLE', user: 'UserB', details: '', justification: 'NOT_SET' }
            ];
            const result = constructAssessmentDetails(blocks);
            expect(result.aggregatedState).toBe('EXPLOITABLE');
        });

        it('should conditionally include or exclude the Pending Review flag', () => {
            const blocks = [
                { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'D', justification: 'NOT_SET' }
            ];
            const pending = constructAssessmentDetails(blocks, [], true);
            expect(pending.text).toContain('[Status: Pending Review]');

            const approved = constructAssessmentDetails(blocks, [], false);
            expect(approved.text).not.toContain('[Status: Pending Review]');
        });

        it('should emit review context metadata in block headers', () => {
            const blocks = [{
                team: 'Platform',
                state: 'IN_TRIAGE',
                user: 'bob',
                details: 'Reviewed.',
                justification: 'NOT_SET',
                evidenceReviewed: true,
                versionCoverageChecked: true,
                ticket: 'SEC-42\n[ignored]',
            }];
            const { text } = constructAssessmentDetails(blocks, [], false);
            expect(text).toContain('[Evidence Reviewed: yes]');
            expect(text).toContain('[Version Coverage: yes]');
            expect(text).toContain('[Ticket: SEC-42 ignored]');
            expect(text).toContain('Reviewed.');
        });

        it('should emit only one block per team regardless of casing', () => {
            const blocks = [
                { team: 'General', state: 'NOT_SET', user: 'old', details: 'Old', justification: 'NOT_SET' },
                { team: 'general', state: 'NOT_AFFECTED', user: 'new', details: 'Newer details', justification: 'CODE_NOT_PRESENT' },
                { team: 'API', state: 'IN_TRIAGE', user: 'one', details: 'First', justification: 'NOT_SET' },
                { team: 'api', state: 'NOT_AFFECTED', user: 'two', details: 'Second and longer', justification: 'CODE_NOT_PRESENT' },
            ];

            const { text, aggregatedState } = constructAssessmentDetails(blocks, [], false);

            expect(text.match(/\[Team: General\]/g)).toHaveLength(1);
            expect(text.toLocaleLowerCase().match(/\[team: api\]/g)).toHaveLength(1);
            expect(text).toContain('Newer details');
            expect(text).toContain('Second and longer');
            expect(aggregatedState).toBe('NOT_AFFECTED');
        });
    });

    describe('mergeTeamAssessment', () => {
        it('should preserve NOT_SET General block and use team state for aggregation', () => {
            const initial = `--- [Team: General] [State: NOT_SET] [Assessed By: Reviewer] [Justification: NOT_SET] ---
Global Policy`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'IN_TRIAGE', 'Fixing soon', 'UserA', 'CODE_NOT_PRESENT');

            expect(result.text).toContain('Global Policy');
            expect(result.text).toMatch(/---\s*\[Team:\s*TeamA\]\s*\[State:\s*IN_TRIAGE\]\s*\[Assessed By:\s*UserA\]\s*\[Date:\s*\d+\]\s*\[Justification:\s*CODE_NOT_PRESENT\]\s*---/);
            expect(result.aggregatedState).toBe('IN_TRIAGE'); // Fallback to TeamA
        });

        it('should choose General state over other teams (Global Precedence)', () => {
            const initial = `--- [Team: General] [State: NOT_AFFECTED] [Assessed By: Reviewer] [Justification: CODE_NOT_PRESENT] ---
Baseline`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'EXPLOITABLE', 'Exploit found', 'UserA');

            // Aggregated state should be NOT_AFFECTED because General (Global Policy) wins
            expect(result.aggregatedState).toBe('NOT_AFFECTED');
            expect(result.text).toContain('--- [Team: TeamA] [State: EXPLOITABLE]');
        });

        it('should choose FALSE_POSITIVE over global NOT_SET', () => {
            const initial = `--- [Team: General] [State: NOT_SET] [Assessed By: Reviewer] [Justification: NOT_SET] ---
Global Policy`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'FALSE_POSITIVE', 'Notes', 'UserA');

            // Aggregated state should be FALSE_POSITIVE because it has higher priority than NOT_SET (priority 5)
            expect(result.aggregatedState).toBe('FALSE_POSITIVE');
        });

        it('should update existing team block', () => {
            const initial = `--- [Team: TeamA] [State: NOT_SET] [Assessed By: UserA] [Justification: NOT_SET] ---
Old Details`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'RESOLVED', 'New Details', 'UserA', 'NOT_SET');

            expect(result.text).not.toContain('Old Details');
            expect(result.text).toContain('New Details');
            expect(result.aggregatedState).not.toBe('NOT_SET');
        });

        it('keeps a team\'s historical block beside its new assessment', () => {
            const record = '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: olga] [Date: 1700000000000] [Justification: CODE_NOT_REACHABLE] [Ticket: T-1] [Historical: yes] ---\nOld reason.';
            const { text, aggregatedState } = mergeTeamAssessment(record, 'TeamA', 'EXPLOITABLE', 'New reason.', 'bob', 'NOT_SET');

            const blocks = parseAssessmentBlocks(text).filter(block => block.team === 'TeamA');
            expect(blocks[0]).toMatchObject({ historical: true, timestamp: 1700000000000, ticket: 'T-1', justification: 'CODE_NOT_REACHABLE', details: 'Old reason.' });
            expect(blocks.map(block => [block.historical, block.state, block.user])).toEqual([
                [true, 'NOT_AFFECTED', 'olga'],
                [false, 'EXPLOITABLE', 'bob'],
            ]);
            // The new assessment takes no ticket from the record.
            expect(blocks[1].ticket || '').toBe('');
            expect(aggregatedState).toBe('EXPLOITABLE');
        });

        it('keeps every distinct historical block of one team', () => {
            const first = '--- [Team: Old] [State: EXPLOITABLE] [Assessed By: o1] [Date: 1600000000000] [Justification: NOT_SET] [Ticket: T-1] [Historical: yes] ---\nFirst.';
            const second = '--- [Team: Old] [State: NOT_AFFECTED] [Assessed By: o2] [Date: 1650000000000] [Justification: CODE_NOT_REACHABLE] [Ticket: T-2] [Historical: yes] ---\nSecond.';
            const { text } = mergeTeamAssessment(`${first}\n\n${second}\n\n${second}`, 'TeamA', 'NOT_AFFECTED', 'Alpha.', 'bob', 'CODE_NOT_REACHABLE');

            const old = parseAssessmentBlocks(text).filter(block => block.team === 'Old');
            expect(old.map(block => [block.historical, block.user, block.ticket, block.details])).toEqual([
                [true, 'o1', 'T-1', 'First.'],
                [true, 'o2', 'T-2', 'Second.'],
            ]);
        });

        it('never takes a historical General block as the global decision', () => {
            const text = '--- [Team: General] [State: EXPLOITABLE] [Assessed By: gina] [Justification: NOT_SET] [Historical: yes] ---\nOld global.';
            const result = mergeTeamAssessment(text, 'TeamA', 'NOT_AFFECTED', 'Alpha.', 'bob', 'CODE_NOT_REACHABLE');
            expect(result.aggregatedState).toBe('NOT_AFFECTED');
            expect(result.text).toContain('Old global.');
        });

        it('should preserve rescored tags across merges', () => {
            const initial = `[Rescored: 8.5]
--- [Team: General] [State: NOT_SET] [Assessed By: Reviewer] [Justification: NOT_SET] ---
Text`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'NOT_SET', 'TextA', 'UserA');
            expect(result.text).toContain('[Rescored: 8.5]');
        });

        it('should preserve review context metadata through team edits', () => {
            const initial = `--- [Team: Dev] [State: IN_TRIAGE] [Assessed By: alice] [Evidence Reviewed: yes] [Version Coverage: yes] [Ticket: SEC-77] ---
Old details.`;
            const { text } = mergeTeamAssessment(initial, 'Dev', 'EXPLOITABLE', 'New details.', 'bob', 'NOT_SET');
            expect(text).toContain('[Evidence Reviewed: yes]');
            expect(text).toContain('[Version Coverage: yes]');
            expect(text).toContain('[Ticket: SEC-77]');
            expect(text).toContain('New details.');
        });

        describe('attribution', () => {
            const stored = `--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] [Reviewed By: rita] [Date: 1790000000000] [Justification: CODE_NOT_REACHABLE] [Assigned: alice] [Ticket: EXP-1] ---
Not reachable.`;
            const merge = (overrides: {
                state?: string, details?: string, justification?: string,
                assigned?: string[], metadata?: Record<string, unknown>, pending?: boolean,
            }) => {
                const { text } = mergeTeamAssessment(
                    stored, 'TeamA',
                    overrides.state ?? 'NOT_AFFECTED',
                    overrides.details ?? 'Not reachable.',
                    'bob',
                    overrides.justification ?? 'CODE_NOT_REACHABLE',
                    undefined,
                    overrides.pending ?? true,
                    overrides.assigned ?? ['alice'],
                    { ticket: 'EXP-1', evidenceReviewed: false, versionCoverageChecked: false, ...overrides.metadata },
                );
                return parseAssessmentBlocks(text).find(block => block.team === 'TeamA')!;
            };
            const kept = { user: 'alice', timestamp: 1790000000000, reviewer: 'rita' };

            it.each([
                ['ticket', { metadata: { ticket: 'EXP-1, EXP-2' } }],
                ['evidence', { metadata: { evidenceReviewed: true } }],
                ['coverage', { metadata: { versionCoverageChecked: true } }],
                ['assignees', { assigned: ['alice', 'bob'] }],
            ])('keeps assessor, date and reviewer when only the %s changes', (_name, overrides) => {
                expect(merge(overrides)).toMatchObject(kept);
            });

            it('reads date and justification of a reviewed block', () => {
                expect(parseAssessmentBlocks(stored)[0]).toMatchObject({
                    ...kept, justification: 'CODE_NOT_REACHABLE',
                });
            });

            it.each([
                ['state', { state: 'EXPLOITABLE', metadata: { ticket: 'EXP-2' } }],
                ['text', { details: 'Reachable after all.', metadata: { ticket: 'EXP-2' } }],
                ['justification', { justification: 'CODE_NOT_PRESENT', metadata: { ticket: 'EXP-2' } }],
            ])('re-stamps when the %s changes', (_name, overrides) => {
                const block = merge(overrides);
                expect(block.user).toBe('bob');
                expect(block.timestamp).toBeGreaterThan(1790000000000);
                expect(block.reviewer).toBeUndefined();
            });

            it('re-stamps an approval that changes only the ticket', () => {
                const block = merge({ metadata: { ticket: 'EXP-2' }, pending: false });
                expect(block.user).toBe('bob');
                expect(block.timestamp).toBeGreaterThan(1790000000000);
            });
        });
    });

    describe('buildBulkSyncDetails', () => {
        it('should preserve team assessments without creating a duplicate General assessment', () => {
            const blocks = [
                { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'Investigating now', justification: 'NOT_SET' },
                { team: 'TeamB', state: 'FALSE_POSITIVE', user: 'UserB', details: 'Not relevant', justification: 'NOT_SET' },
            ]
            const { text, aggregatedState } = buildBulkSyncDetails(blocks)

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')
            expect(general).toBeUndefined()

            // Team blocks should still be present
            expect(parsed.find(b => b.team === 'TeamA')).toBeDefined()
            expect(parsed.find(b => b.team === 'TeamB')).toBeDefined()

            // Aggregated state should be worst (IN_TRIAGE < FALSE_POSITIVE)
            expect(aggregatedState).toBe('IN_TRIAGE')
        })

        it('should preserve existing user comment in General block', () => {
            const existingText = `--- [Team: General] [State: NOT_SET] [Assessed By: Reviewer] [Justification: NOT_SET] ---
My Policy Comment: track this carefully`
            const blocks = [
                { team: 'TeamA', state: 'NOT_AFFECTED', user: 'UserA', details: 'Safe path checked', justification: 'CODE_NOT_PRESENT' },
            ]
            const { text } = buildBulkSyncDetails(blocks, existingText)

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')
            expect(general).toBeDefined()
            // User comment must be preserved
            expect(general!.details).toContain('My Policy Comment: track this carefully')
            expect(general!.details).not.toContain('[TeamA] NOT_AFFECTED')
        })

        it('should not copy raw team details into an existing General block', () => {
            const blocks = [
                { team: 'General', state: 'NOT_SET', user: 'Reviewer', details: 'Global policy.', justification: 'NOT_SET' },
                { team: 'TeamA', state: 'EXPLOITABLE', user: 'UserA', details: 'Active attack vector confirmed', justification: 'NOT_SET' },
            ]
            const { text } = buildBulkSyncDetails(blocks)

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')!
            // Raw details of TeamA must NOT appear in the General block
            expect(general.details).not.toContain('Active attack vector confirmed')
        })

        it('should preserve explicit General state (Global Precedence)', () => {
            const blocks = [
                { team: 'General', state: 'NOT_AFFECTED', user: 'Reviewer', details: 'Mitigated globally', justification: 'CODE_NOT_PRESENT' },
                { team: 'TeamA', state: 'EXPLOITABLE', user: 'UserA', details: 'Exploit found', justification: 'NOT_SET' },
            ]
            const { text, aggregatedState } = buildBulkSyncDetails(blocks)

            // General state was explicitly set, so it must win
            expect(aggregatedState).toBe('NOT_AFFECTED')

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')!
            expect(general.state).toBe('NOT_AFFECTED')
        })

        it('should strip a legacy generated team summary from General details', () => {
            const blocks = [
                { team: 'General', state: 'NOT_SET', user: 'Reviewer', details: 'Policy note.\n\nTeam assessments:\n[TeamB] RESOLVED', justification: 'NOT_SET' },
                { team: 'TeamB', state: 'RESOLVED', user: 'UserB', details: 'Fixed', justification: 'NOT_SET' },
            ]
            const { text } = buildBulkSyncDetails(blocks)

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')!
            expect(general.details).toBe('Policy note.')
        })

        it('should not be marked as pending (bulk sync is a reviewer action)', () => {
            const blocks = [
                { team: 'TeamA', state: 'RESOLVED', user: 'UserA', details: 'Done', justification: 'NOT_SET' },
            ]
            const { text } = buildBulkSyncDetails(blocks)
            expect(text).not.toContain('[Status: Pending Review]')
        })
    });

    describe('Assigned Users', () => {
        it('should parse [Assigned: ...] from block headers', () => {
            const text = '--- [Team: Security] [State: IN_TRIAGE] [Assessed By: alice] [Assigned: jane.doe, john.smith] ---\nDetails here.'
            const blocks = parseAssessmentBlocks(text)
            expect(blocks).toHaveLength(1)
            expect(blocks[0].assigned).toEqual(['jane.doe', 'john.smith'])
        })

        it('should return empty array when no [Assigned] tag is present', () => {
            const text = '--- [Team: Security] [State: IN_TRIAGE] [Assessed By: alice] ---\nDetails here.'
            const blocks = parseAssessmentBlocks(text)
            expect(blocks).toHaveLength(1)
            expect(blocks[0].assigned).toEqual([])
        })

        it('should emit [Assigned: ...] tag in constructAssessmentDetails', () => {
            const blocks = [{
                team: 'Platform',
                state: 'EXPLOITABLE',
                user: 'bob',
                details: 'Bad.',
                justification: 'NOT_SET',
                assigned: ['user1', 'user2']
            }]
            const { text } = constructAssessmentDetails(blocks, [], false)
            expect(text).toContain('[Assigned: user1, user2]')
        })

        it('should not emit [Assigned] tag when assigned is empty', () => {
            const blocks = [{
                team: 'Platform',
                state: 'EXPLOITABLE',
                user: 'bob',
                details: 'Bad.',
                justification: 'NOT_SET',
                assigned: []
            }]
            const { text } = constructAssessmentDetails(blocks, [], false)
            expect(text).not.toContain('[Assigned')
        })

        it('should preserve assigned through mergeTeamAssessment when not explicitly provided', () => {
            const existing = '--- [Team: Dev] [State: IN_TRIAGE] [Assessed By: alice] [Assigned: keeper] ---\nOld details.'
            const { text } = mergeTeamAssessment(existing, 'Dev', 'EXPLOITABLE', 'New details.', 'bob', 'NOT_SET', undefined, true)
            expect(text).toContain('[Assigned: keeper]')
        })

        it('should replace assigned when explicitly provided in mergeTeamAssessment', () => {
            const existing = '--- [Team: Dev] [State: IN_TRIAGE] [Assessed By: alice] [Assigned: old.user] ---\nOld.'
            const { text } = mergeTeamAssessment(existing, 'Dev', 'EXPLOITABLE', 'New.', 'bob', 'NOT_SET', undefined, true, ['new.user1', 'new.user2'])
            expect(text).toContain('[Assigned: new.user1, new.user2]')
            expect(text).not.toContain('old.user')
        })

        it('should round-trip assigned through parse → construct', () => {
            const original = '--- [Team: Ops] [State: NOT_AFFECTED] [Assessed By: carol] [Justification: CODE_NOT_PRESENT] [Assigned: user.a, user.b] ---\nSafe.'
            const blocks = parseAssessmentBlocks(original)
            const { text } = constructAssessmentDetails(blocks, [], false)
            const reparsed = parseAssessmentBlocks(text)
            expect(reparsed[0].assigned).toEqual(['user.a', 'user.b'])
        })

        it('should not leak [Assigned: ...] into content', () => {
            const text = '--- [Team: X] [State: IN_TRIAGE] [Assessed By: z] [Assigned: a, b] ---\nDetails.'
            const blocks = parseAssessmentBlocks(text)
            expect(blocks[0].details).not.toContain('[Assigned')
            expect(blocks[0].details).toBe('Details.')
        })
    });

    describe('assessmentTextToFields', () => {
        const VECTOR = 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N';
        const text = [
            `[Rescored: 2.5] [Rescored Vector: ${VECTOR}]`,
            '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_REACHABLE] ---',
            'Not reachable.',
            '--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] [Date: 1794561289026] [Justification: CODE_NOT_REACHABLE] [Assigned: carol, dave] [Evidence Reviewed: yes] [Version Coverage: yes] [Ticket: EXP-1001] [Historical: yes] [Copied From: Old Team] ---',
            'See General.',
            '\n[Status: Pending Review]',
        ].join('\n\n');

        it('reads every field the form writes', () => {
            expect(assessmentTextToFields(text)).toEqual({
                free_text: null, // not edited in the form: the server keeps it
                pending_review: true,
                rescored_score: 2.5,
                rescored_vector: VECTOR,
                response: null,
                teams: [
                    {
                        team: 'General', state: 'NOT_AFFECTED', justification: 'CODE_NOT_REACHABLE',
                        assessed_by: 'alice', reviewed_by: null, assessed_at_ms: null,
                        rescored_score: null, rescored_vector: null, ssvc: null, ssvc_details: null,
                        assigned: [], ticket: null, evidence_reviewed: null, version_coverage: null,
                        historical: false, copied_from: null, details: 'Not reachable.',
                    },
                    {
                        team: 'Core', state: 'NOT_AFFECTED', justification: 'CODE_NOT_REACHABLE',
                        assessed_by: 'bob', reviewed_by: null, assessed_at_ms: 1794561289026,
                        rescored_score: null, rescored_vector: null, ssvc: null, ssvc_details: null,
                        assigned: ['carol', 'dave'], ticket: 'EXP-1001', evidence_reviewed: 'yes',
                        version_coverage: 'yes', historical: true, copied_from: 'Old Team',
                        details: 'See General.',
                    },
                ],
            });
        });

        it('keeps tags of a header that the form does not edit', () => {
            const fields = assessmentTextToFields(
                `--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] [Reviewed By: rita] [Justification: NOT_SET] [Rescored: 1.5] [Rescored Vector: ${VECTOR}] ---\nok`,
            );
            expect(fields.teams[0]).toEqual(expect.objectContaining({
                reviewed_by: 'rita', rescored_score: 1.5, rescored_vector: VECTOR, justification: null,
            }));
            // A rescoring inside a block is that team's, not the finding's.
            expect(fields.rescored_score).toBeNull();
        });

        it('reads the version override as a field, never as text or a General block', () => {
            const text = [
                '[Response: UPDATE] [Version Override: LTS 2.x] [Override Reason: Backported fix]',
                '',
                '--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: NOT_SET] ---',
                'Checked.',
            ].join('\n')
            const fields = assessmentTextToFields(text)
            expect(fields.version_override).toEqual({ label: 'LTS 2.x', reason: 'Backported fix' })
            expect(fields.free_text).toBeNull()
            expect(parseAssessmentBlocks(text).map(block => block.team)).toEqual(['Core'])
            expect(renderAssessmentFields(fields)).toBe(text)
            expect(assessmentTextToFields('Plain.').version_override).toBeUndefined()
        })

        it('treats text without team blocks as free text, not as a General assessment', () => {
            expect(assessmentTextToFields('Legacy note.\n[Status: Pending Review]')).toEqual({
                free_text: 'Legacy note.', pending_review: true,
                rescored_score: null, rescored_vector: null, response: null, teams: [],
            });
            expect(assessmentTextToFields('')).toEqual({
                free_text: '', pending_review: false, rescored_score: null, rescored_vector: null, response: null, teams: [],
            });
        });

        it('keeps text ahead of the blocks as free text beside a General assessment', () => {
            const fields = assessmentTextToFields(
                'Agreed with the supplier.\n\n--- [Team: General] [State: IN_TRIAGE] [Assessed By: alice] ---\nLooking.',
            );
            expect(fields.free_text).toBe('Agreed with the supplier.');
            expect(fields.teams.map(team => [team.team, team.details])).toEqual([['General', 'Looking.']]);
        });

        it('sends one assessment per team and no unknown assessor', () => {
            const fields = assessmentTextToFields([
                '--- [Team: Core] [State: IN_TRIAGE] [Assessed By: bob] [Date: 1] ---\nOlder.',
                '--- [Team: core] [State: NOT_AFFECTED] [Assessed By: bob] [Date: 2] ---\nNewer.',
                '--- [Team: general] [State: NOT_SET] ---\nNo assessor named.',
            ].join('\n\n'));
            expect(fields.teams.map(team => [team.team, team.details, team.assessed_by])).toEqual([
                ['core', 'Newer.', 'bob'],
                ['General', 'No assessor named.', null],
            ]);
        });

        it('says the same after the server has rendered it', () => {
            const sent = assessmentTextToFields(text);
            const rendered = renderAssessmentFields(sent);
            expect(rendered).not.toBe(text);
            expect(assessmentTextToFields(rendered)).toEqual(sent);
            expect(parseAssessmentBlocks(rendered)).toEqual(parseAssessmentBlocks(text));
        });
    });

    describe('assessmentTextKey', () => {
        it('ignores whitespace-only differences between writers', () => {
            const fromUi = '--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] ---\n\nReachable.\n\n\n[Status: Pending Review]';
            const fromWorkflow = '--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] ---\nReachable.\n\n[Status: Pending Review]';
            expect(assessmentTextKey(fromUi)).toBe(assessmentTextKey(fromWorkflow));
            expect(assessmentTextKey(fromUi)).not.toBe(assessmentTextKey(fromUi.replace('Reachable', 'Unreachable')));
            expect(assessmentTextKey(undefined)).toBe('');
        });
    });

    describe('restored historical blocks', () => {
        const restored = [
            '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] [Justification: CODE_NOT_PRESENT] ---',
            'Approved globally.',
            '',
            '--- [Team: TeamT] [State: EXPLOITABLE] [Assessed By: tom] [Date: 1600000000000] [Justification: NOT_SET] [Ticket: SYN-1] [Rescored: 9.8] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H] [Historical: yes] ---',
            'Restored old text.',
        ].join('\n')

        it('keeps a historical block when its team saves', () => {
            const saved = mergeTeamAssessment(restored, 'TeamT', 'NOT_AFFECTED', 'New decision.', 'tess', 'CODE_NOT_REACHABLE')
            const final = sanitizeAssessmentDetails(saved.text)
            const teamT = final.blocks.filter(block => block.team === 'TeamT')
            expect(teamT.map(block => [block.historical, block.details])).toEqual([
                [true, 'Restored old text.'],
                [false, 'New decision.'],
            ])
            expect(teamT[0]?.ticket).toBe('SYN-1')
            expect(teamT[1]?.ticket).toBe('')
            expect(final.aggregatedState).toBe('NOT_AFFECTED')
        })

        it('does not take the rescoring of a historical block for the finding', () => {
            expect(withoutHistoricalBlocks(restored)).not.toContain('Rescored')
            const saved = mergeTeamAssessment(restored, 'TeamU', 'NOT_AFFECTED', 'Not shipped.', 'ulla', 'CODE_NOT_PRESENT')
            const final = sanitizeAssessmentDetails(saved.text)
            const fields = assessmentTextToFields(final.text)
            expect(fields.rescored_score ?? null).toBeNull()
            expect(fields.rescored_vector ?? null).toBeNull()
            // The historical block keeps the rescoring it was recorded with.
            const historical = fields.teams.find(team => team.historical)
            expect(historical?.rescored_score).toBe(9.8)
            expect(historical?.rescored_vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        })
    })
});
