
import { describe, it, expect } from 'vitest';
import { parseAssessmentBlocks, constructAssessmentDetails, mergeTeamAssessment } from '../assessment-helpers';

describe('Assessment Helpers', () => {
    describe('parseAssessmentBlocks', () => {
        it('should parse legacy text as General block', () => {
            const text = 'Legacy analysis text.';
            const blocks = parseAssessmentBlocks(text);
            expect(blocks['General']).toBeDefined();
            expect(blocks['General']?.details).toBe('Legacy analysis text.');
            expect(blocks['General']?.justification).toBe('NOT_SET');
        });

        it('should parse structured blocks', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] [Justification: CODE_NOT_PRESENT] ---
Details A
--- [Team: TeamB] [State: FALSE_POSITIVE] [Assessed By: UserB] ---
Details B`;
            const blocks = parseAssessmentBlocks(text);
            expect(blocks['TeamA']).toBeDefined();
            expect(blocks['TeamA']?.state).toBe('IN_TRIAGE');
            expect(blocks['TeamA']?.details).toBe('Details A');
            expect(blocks['TeamA']?.justification).toBe('CODE_NOT_PRESENT');
            expect(blocks['TeamB']).toBeDefined();
            expect(blocks['TeamB']?.state).toBe('FALSE_POSITIVE');
            expect(blocks['TeamB']?.justification).toBe('NOT_SET');
        });

        it('should handle General + structured blocks', () => {
            const text = `General Text
--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] ---
Details A`;
            const blocks = parseAssessmentBlocks(text);
            expect(blocks['General']).toBeDefined();
            expect(blocks['General']?.details).toBe('General Text');
            expect(blocks['General']?.justification).toBe('NOT_SET');
            expect(blocks['TeamA']).toBeDefined();
        });

        it('should clean redundant metadata from details', () => {
            const text = `--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] ---
[Comment] [Team: TeamA] My actual rationale -- UserA`;
            const blocks = parseAssessmentBlocks(text);
            expect(blocks['TeamA']).toBeDefined();
            expect(blocks['TeamA']?.details).toBe('My actual rationale');
        });
    });

    describe('constructAssessmentDetails', () => {
        it('should format blocks correctly', () => {
            const blocks = {
                'TeamA': { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'Details A', justification: 'CODE_NOT_PRESENT' }
            };
            const result = constructAssessmentDetails(blocks);
            expect(result.text).toContain('--- [Team: TeamA] [State: IN_TRIAGE] [Assessed By: UserA] [Justification: CODE_NOT_PRESENT] ---');
            expect(result.text).toContain('Details A');
            expect(result.text).toContain('[Status: Pending Review]');
            expect(result.aggregatedState).toBe('IN_TRIAGE');
        });

        it('should calculate aggregated state (Critical wins)', () => {
            const blocks = {
                'TeamA': { team: 'TeamA', state: 'NOT_AFFECTED', user: 'UserA', details: '', justification: 'CODE_NOT_PRESENT' },
                'TeamB': { team: 'TeamB', state: 'EXPLOITABLE', user: 'UserB', details: '', justification: 'NOT_SET' }
            };
            const result = constructAssessmentDetails(blocks);
            expect(result.aggregatedState).toBe('EXPLOITABLE');
        });

        it('should conditionally include or exclude the Pending Review flag', () => {
            const blocks = {
                'TeamA': { team: 'TeamA', state: 'IN_TRIAGE', user: 'UserA', details: 'D', justification: 'NOT_SET' }
            };
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
});
