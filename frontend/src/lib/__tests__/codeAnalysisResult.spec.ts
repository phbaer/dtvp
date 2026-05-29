import { describe, expect, it } from 'vitest'
import { buildCodeAnalysisDetails, prepareCodeAnalysisResult } from '../codeAnalysisResult'
import type { CodeAnalysisAssessResponse } from '../api'

describe('codeAnalysisResult', () => {
    const createResponse = (): CodeAnalysisAssessResponse => ({
        assessment: {
            affected: false,
            verdict: 'not affected',
            confidence: 'high',
            exposure: 'none',
            advisory_sources: ['GHSA', 'NVD'],
            cwe_ids: ['CWE-79', 'CWE-94'],
            cwe_descriptions: {
                'CWE-79': 'Improper Neutralization of Input During Web Page Generation',
                'CWE-94': 'Improper Control of Generation of Code',
            },
            summary: 'The vulnerable path is not reachable.',
            reasoning: 'Static analysis found no invocation path into the sink.',
            adjusted_cvss: {
                original_score: 8.1,
                adjusted_score: 3.2,
                adjusted_vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N',
                reasons: ['Attack complexity increased', 'User interaction required'],
                summary: 'Exploitability is reduced by runtime constraints.',
                version_affected: true,
            },
        },
        versions_checked: ['2.0.0', '2.1.0', '3.0.0-beta.1'],
        steps: [
            {
                step: 'reachability',
                title: 'Reachability analysis',
                status: 'pass',
                findings: {},
                evidence: ['No call chain reaches the vulnerable method'],
            },
        ],
    })

    it('formats the code analysis details block with justification, cvss, and steps', () => {
        const details = buildCodeAnalysisDetails(createResponse(), 'CODE_NOT_PRESENT')

        expect(details).toContain('[Code Analysis]')
        expect(details).toContain('Verdict: not affected (high confidence)')
        expect(details).toContain('Advisory Sources: GHSA, NVD')
        expect(details).toContain('Justification: CODE_NOT_PRESENT')
        expect(details).toContain('Versions Checked:')
        expect(details).toContain('  - 2.0.0')
        expect(details).toContain('  - 2.1.0')
        expect(details).toContain('CWEs:')
        expect(details).toContain('  - CWE-79: Improper Neutralization of Input During Web Page Generation')
        expect(details).toContain('CVSS: 8.1 → 3.2')
        expect(details).toContain('[Rescored: 3.2]')
        expect(details).toContain('Adjusted Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N')
        expect(details).toContain('[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N]')
        expect(details).not.toContain('Pipeline Steps:')
        expect(details).not.toContain('Reachability analysis')
    })

    it('formats merged results with compact per-component sections', () => {
        const response = createResponse()
        response.assessment.summary = 'Combined analysis for 2 components. lib-a: not affected; lib-b: affected'
        response.assessment.reasoning = 'Global result merged from the latest completed analysis for each selected component.'
        response.component_results = [
            {
                component: 'lib-a',
                assessment: {
                    ...createResponse().assessment,
                    summary: 'No vulnerable path is reachable.',
                    reasoning: 'No invocation reaches the sink.',
                },
                versions_checked: ['2.0.0'],
            },
            {
                component: 'lib-b',
                assessment: {
                    ...createResponse().assessment,
                    affected: true,
                    verdict: 'affected',
                    exposure: 'high',
                    summary: 'A vulnerable path is reachable.',
                    reasoning: 'Execution reaches the vulnerable method.',
                },
                versions_checked: ['3.0.0'],
            },
        ]

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('Components:')
        expect(details).toContain('[Component: lib-a]')
        expect(details).toContain('Summary: No vulnerable path is reachable.')
        expect(details).toContain('Advisory Sources: GHSA, NVD')
        expect(details).toContain('Versions: 2.0.0')
        expect(details).toContain('[Component: lib-b]')
        expect(details).toContain('Verdict: affected (high confidence)')
        expect(details).toContain('Reasoning: Execution reaches the vulnerable method.')
        expect(details).not.toContain('Pipeline Steps:')
    })

    it('prepares team drafts from matching components and falls back to the first tagged team', () => {
        const response = createResponse()
        const prepared = prepareCodeAnalysisResult(
            response,
            ['unknown-component'],
            [
                { name: 'log4j-core', tag: 'TEAM-PLATFORM' },
                { name: 'shared-lib', tag: 'TEAM-APP' },
            ],
            ['alice', 'bob'],
        )

        expect(prepared.targetState).toBe('NOT_AFFECTED')
        expect(prepared.targetJustification).toBe('CODE_NOT_PRESENT')
        expect(prepared.firstTeam).toBe('TEAM-PLATFORM')
        expect(prepared.teamDrafts).toEqual([
            {
                team: 'TEAM-PLATFORM',
                state: 'NOT_AFFECTED',
                details: prepared.detailsText,
                justification: 'CODE_NOT_PRESENT',
                assigned: ['alice', 'bob'],
            },
        ])
        expect(prepared.adjustedVector).toBe('CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N')
        expect(prepared.adjustedScore).toBe(3.2)
    })

    it('uses team-specific details when only one team is involved', () => {
        const response = createResponse()
        response.component_results = [
            {
                component: 'shared-lib',
                assessment: {
                    ...response.assessment,
                    summary: 'Only the shared-lib path was analyzed.',
                    reasoning: 'The shared-lib sink is unreachable.',
                },
                versions_checked: ['2.0.0'],
            },
            {
                component: 'other-lib',
                assessment: {
                    ...response.assessment,
                    summary: 'This should not appear in the single-team details.',
                    reasoning: 'Filtered out for the selected team.',
                },
                versions_checked: ['3.0.0'],
            },
        ]

        const prepared = prepareCodeAnalysisResult(
            response,
            ['shared-lib'],
            [
                { name: 'shared-lib', tag: 'TEAM-APP' },
                { name: 'other-lib', tag: 'TEAM-PLATFORM' },
            ],
            ['alice'],
        )

        expect(prepared.firstTeam).toBe('TEAM-APP')
        expect(prepared.detailsText).toContain('[Component: shared-lib]')
        expect(prepared.detailsText).not.toContain('[Component: other-lib]')
        expect(prepared.teamDrafts[0]?.details).toContain('[Component: shared-lib]')
        expect(prepared.teamDrafts[0]?.details).not.toContain('[Component: other-lib]')
    })

    it('keeps per-team drafts scoped to each team component slice', () => {
        const response = createResponse()
        response.component_results = [
            {
                component: 'lib-a',
                assessment: {
                    ...response.assessment,
                    summary: 'Analysis for lib-a.',
                    reasoning: 'Reasoning for lib-a.',
                },
                versions_checked: ['1.0.0'],
            },
            {
                component: 'lib-b',
                assessment: {
                    ...response.assessment,
                    summary: 'Analysis for lib-b.',
                    reasoning: 'Reasoning for lib-b.',
                },
                versions_checked: ['2.0.0'],
            },
        ]

        const prepared = prepareCodeAnalysisResult(
            response,
            ['lib-a', 'lib-b'],
            [
                { name: 'lib-a', tag: 'TEAM-A' },
                { name: 'lib-b', tag: 'TEAM-B' },
            ],
            ['alice'],
        )

        expect(prepared.detailsText).toContain('[Component: lib-a]')
        expect(prepared.detailsText).toContain('[Component: lib-b]')
        expect(prepared.teamDrafts).toEqual([
            expect.objectContaining({
                team: 'TEAM-A',
                details: expect.stringContaining('[Component: lib-a]'),
            }),
            expect.objectContaining({
                team: 'TEAM-B',
                details: expect.stringContaining('[Component: lib-b]'),
            }),
        ])
        expect(prepared.teamDrafts[0]?.details).not.toContain('[Component: lib-b]')
        expect(prepared.teamDrafts[1]?.details).not.toContain('[Component: lib-a]')
    })
})