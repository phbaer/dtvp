
import { describe, it, expect } from 'vitest';
import { parseAssessmentBlocks, constructAssessmentDetails, mergeTeamAssessment, buildBulkSyncDetails, getGroupLifecycle, getConsensusAssessment, getAssessedTeams, hasOpenTeamAssessment, normalizeTags } from '../assessment-helpers';

describe('Assessment Helpers', () => {
    describe('getGroupLifecycle', () => {
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

            const result = getConsensusAssessment(blocks, 'INCOMPLETE', ['NOT_AFFECTED'], undefined);
            expect(result.state).toBe('NOT_AFFECTED');
            expect(result.justification).toBe('CODE_NOT_PRESENT');
        });

        it('should clean redundant metadata from details', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] ---
[Comment] [Team: TeamA] My actual rationale -- UserA`;
            const blocks = parseAssessmentBlocks(text);
            const teamA = blocks.find(b => b.team === 'TeamA');
            expect(teamA).toBeDefined();
            expect(teamA?.details).toBe('My actual rationale');
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

        it('should preserve rescored tags across merges', () => {
            const initial = `[Rescored: 8.5]
--- [Team: General] [State: NOT_SET] [Assessed By: Reviewer] [Justification: NOT_SET] ---
Text`;
            const result = mergeTeamAssessment(initial, 'TeamA', 'NOT_SET', 'TextA', 'UserA');
            expect(result.text).toContain('[Rescored: 8.5]');
        });
    });

    describe('buildBulkSyncDetails', () => {
        it('should create a General block with team state summary when none exists', () => {
            const blocks = [
                { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'Investigating now', justification: 'NOT_SET' },
                { team: 'TeamB', state: 'FALSE_POSITIVE', user: 'UserB', details: 'Not relevant', justification: 'NOT_SET' },
            ]
            const { text, aggregatedState } = buildBulkSyncDetails(blocks)

            // General block should exist
            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')
            expect(general).toBeDefined()

            // Summary of team states should be in General block
            expect(general!.details).toContain('[TeamA] IN_TRIAGE')
            expect(general!.details).toContain('[TeamB] FALSE_POSITIVE')

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
            // Team summary should also be appended
            expect(general!.details).toContain('[TeamA] NOT_AFFECTED')
        })

        it('should NOT duplicate raw team details inside the General block', () => {
            const blocks = [
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

        it('should skip NOT_SET teams from the summary', () => {
            const blocks = [
                { team: 'TeamA', state: 'NOT_SET', user: 'UserA', details: '', justification: 'NOT_SET' },
                { team: 'TeamB', state: 'RESOLVED', user: 'UserB', details: 'Fixed', justification: 'NOT_SET' },
            ]
            const { text } = buildBulkSyncDetails(blocks)

            const parsed = parseAssessmentBlocks(text)
            const general = parsed.find(b => b.team === 'General')!
            // TeamA (NOT_SET) should not appear in summary
            expect(general.details).not.toContain('[TeamA]')
            expect(general.details).toContain('[TeamB] RESOLVED')
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
});
