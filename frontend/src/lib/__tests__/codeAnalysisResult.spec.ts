import { describe, expect, it } from 'vitest'
import { buildCodeAnalysisDetails, buildCodeAnalysisGlobalReferenceDraft, prepareCodeAnalysisResult, prepareCodeAnalysisResults } from '../codeAnalysisResult'
import type { CodeAnalysisComponentRun } from '../codeAnalysisResult'
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
        expect(details).toContain('Adjusted Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N')
        expect(details).not.toContain('[Rescored:')
        expect(details).not.toContain('[Rescored Vector:')
        expect(details).not.toContain('Pipeline Steps:')
        expect(details).not.toContain('Reachability analysis')
    })

    it('formats zero adjusted scores with one decimal place', () => {
        const response = createResponse()
        response.assessment.adjusted_cvss!.adjusted_score = 0

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('CVSS: 8.1 → 0.0')
    })

    it('formats important analyzer evidence as a compact human-readable assessment', () => {
        const response = createResponse()
        Object.assign(response.assessment, {
            analysis: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            response: 'WILL_NOT_FIX',
            details: 'The package is present in the SBOM but absent from source.',
            dependency_presence: { sbom_attributed: true, repo_found: false },
            advisory_relevance: { applies_to_detected_version: false },
            version_analysis: { detected_version: '2.1.0' },
            researcher_view: { conclusion: 'No vulnerable path.' },
            remediation_view: { recommendations: ['Keep monitoring.'] },
            audit_view: { conclusion: 'Evidence is sufficient.' },
            ticket_text: 'No remediation ticket required.',
        })

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('Analyzer state: NOT_AFFECTED')
        expect(details).toContain('Suggested response: WILL_NOT_FIX')
        expect(details).toContain('Additional analysis:\nThe package is present in the SBOM but absent from source.')
        expect(details).toContain('Dependency evidence:\nPresent via SBOM attribution; not rediscovered in repository manifests or lock files.')
        expect(details).toContain('Advisory relevance:\nApplies to detected version: no')
        expect(details).toContain('Version evidence:\nDetected version: 2.1.0')
        expect(details).toContain('No vulnerable path.')
        expect(details).toContain('Keep monitoring.')
        expect(details).toContain('Evidence is sufficient.')
        expect(details).not.toContain('sbom_attributed')
        expect(details).not.toContain('Ticket Draft')
    })

    it('uses structured conclusions instead of copying the generated raw report', () => {
        const response = createResponse()
        response.assessment.details = [
            'VULNERABILITY ASSESSMENT REPORT',
            'Repository inventory and raw version table',
            'x'.repeat(5000),
        ].join('\n')
        response.assessment.researcher_view = { conclusion: 'No reachable path was found.' }
        response.assessment.remediation_view = { recommendations: ['Monitor the next release.'] }

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('Research conclusion:\nNo reachable path was found.')
        expect(details).toContain('Remediation:\n  - Monitor the next release.')
        expect(details).not.toContain('VULNERABILITY ASSESSMENT REPORT')
        expect(details).not.toContain('x'.repeat(5000))
    })

    it('keeps the generated report as a fallback when no semantic narrative exists', () => {
        const response = createResponse()
        response.assessment.summary = ''
        response.assessment.reasoning = ''
        response.assessment.details = 'VULNERABILITY ASSESSMENT REPORT\nOnly available analysis.'

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('Additional analysis:\nVULNERABILITY ASSESSMENT REPORT')
        expect(details).toContain('Only available analysis.')
    })

    it('does not truncate summaries, rationales, or decision-relevant result collections', () => {
        const response = createResponse()
        response.assessment.summary = `Generated summary ${'s'.repeat(700)} SUMMARY_END`
        response.assessment.reasoning = `Generated rationale ${'r'.repeat(700)} RATIONALE_END`
        response.assessment.details = `Detailed report ${'d'.repeat(700)} DETAILS_END`
        response.assessment.dependency_presence = {
            presence_basis: 'direct',
            declared_in: Array.from({ length: 10 }, (_, index) => `manifest-${index + 1}.xml`),
        }
        response.assessment.version_analysis = {
            note: `Version analysis ${'v'.repeat(700)} VERSION_NOTE_END`,
            affected_product_versions: Array.from({ length: 14 }, (_, index) => `release-${index + 1}`),
        }
        response.assessment.remediation_view = {
            recommendations: Array.from(
                { length: 10 },
                (_, index) => `Recommendation ${index + 1}${index === 9 ? ' REMEDIATION_END' : ''}`,
            ),
        }
        response.assessment.cwe_ids = Array.from({ length: 10 }, (_, index) => `CWE-${index + 1}`)
        response.assessment.cwe_descriptions = Object.fromEntries(
            response.assessment.cwe_ids.map(cweId => [cweId, `Description for ${cweId}`]),
        )
        response.assessment.adjusted_cvss!.summary = `CVSS rationale ${'c'.repeat(400)} CVSS_SUMMARY_END`
        response.assessment.adjusted_cvss!.reasons = Array.from(
            { length: 10 },
            (_, index) => `CVSS reason ${index + 1}${index === 9 ? ' CVSS_REASON_END' : ''}`,
        )
        response.versions_checked = Array.from({ length: 14 }, (_, index) => `version-${index + 1}`)
        response.component_results = Array.from({ length: 10 }, (_, index) => ({
            component: `component-${index + 1}`,
            assessment: {
                ...createResponse().assessment,
                summary: `Component ${index + 1} summary${index === 9 ? ' COMPONENT_SUMMARY_END' : ''}`,
                reasoning: `Component ${index + 1} rationale${index === 9 ? ' COMPONENT_RATIONALE_END' : ''}`,
            },
            versions_checked: [`component-version-${index + 1}`],
        }))

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('SUMMARY_END')
        expect(details).toContain('RATIONALE_END')
        expect(details).toContain('DETAILS_END')
        expect(details).toContain('Declared in: manifest-10.xml')
        expect(details).toContain('VERSION_NOTE_END')
        expect(details).toContain('release-14')
        expect(details).toContain('REMEDIATION_END')
        expect(details).toContain('  - CWE-10: Description for CWE-10')
        expect(details).toContain('CVSS_SUMMARY_END')
        expect(details).toContain('CVSS_REASON_END')
        expect(details).toContain('  - version-14')
        expect(details).toContain('[Component: component-10]')
        expect(details).toContain('COMPONENT_SUMMARY_END')
        expect(details).toContain('COMPONENT_RATIONALE_END')
    })

    it.each([
        { verdict: 'Affected', affected: true, expectedState: 'EXPLOITABLE' },
        { verdict: 'Probably Affected', affected: true, expectedState: 'IN_TRIAGE' },
        { verdict: 'Uncertain', affected: false, expectedState: 'IN_TRIAGE' },
        { verdict: 'Not Affected', affected: false, expectedState: 'NOT_AFFECTED' },
    ])('maps the overall $verdict verdict to $expectedState', ({ verdict, affected, expectedState }) => {
        const response = createResponse()
        response.assessment.verdict = verdict
        response.assessment.affected = affected

        const prepared = prepareCodeAnalysisResult(response, [], [], [])

        expect(prepared.targetState).toBe(expectedState)
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
        expect(details).toContain('Summary:\nNo vulnerable path is reachable.')
        expect(details).toContain('Advisory Sources: GHSA, NVD')
        expect(details).toContain('Versions: 2.0.0')
        expect(details).toContain('[Component: lib-b]')
        expect(details).toContain('Verdict: affected (high confidence)')
        expect(details).toContain('Rationale:\nExecution reaches the vulnerable method.')
        expect(details).not.toContain('Pipeline Steps:')
    })

    it('omits raw version inventories and process prompts from assessment rationale', () => {
        const response = createResponse()
        Object.assign(response.assessment, {
            summary: 'The workspace is not affected, but tracked releases require remediation.',
            reasoning: 'The dependency is SBOM-attributed and the checked workspace has no affected version.',
            dependency_presence: {
                found: true,
                repo_found: false,
                sbom_attributed: true,
                presence_basis: 'sbom_attributed',
                direct: false,
                transitive: false,
            },
            version_analysis: {
                affected: false,
                current_workspace_affected: false,
                note: 'No lock files were found; version exposure remains conservative.',
                affected_product_versions: ['6.15.5', '7.1.1'],
                affected_ranges_summary: ['range-one', 'range-two'],
                affected_product_version_refs: { '6.15.5': '6.15.5' },
                checked_versions: [{ ref: 'WORKTREE', notes: 'not found' }, { ref: 'master', notes: 'not found' }],
            },
            researcher_view: {
                objective: 'Find the weakness and determine exposure.',
                target_outcome: 'Prefer a low-info outcome.',
                findings: ['Dependency presence: present via SBOM attribution'],
                conclusion: 'Upgrade the upstream runtime and verify its resolved Netty version.',
            },
        })

        const details = buildCodeAnalysisDetails(response, 'CODE_NOT_PRESENT')

        expect(details).toContain('Summary:\nThe workspace is not affected')
        expect(details).toContain('Rationale:\nThe dependency is SBOM-attributed')
        expect(details).toContain('Current workspace affected: no')
        expect(details).toContain('Affected product versions: 6.15.5, 7.1.1')
        expect(details).toContain('Upgrade the upstream runtime')
        expect(details).not.toContain('Checked Versions')
        expect(details).not.toContain('Affected Product Version Refs')
        expect(details).not.toContain('range-one')
        expect(details).not.toContain('Find the weakness')
        expect(details).not.toContain('Prefer a low-info outcome')
    })

    it('does not assign an unmatched component to an unrelated team', () => {
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
        expect(prepared.firstTeam).toBeNull()
        expect(prepared.teamDrafts).toEqual([])
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
                    reasoning: `The shared-lib sink is unreachable. ${'r'.repeat(700)} TEAM_RATIONALE_END`,
                    researcher_view: { conclusion: 'TEAM_RESEARCH_CONCLUSION' },
                    audit_view: { conclusion: 'TEAM_AUDIT_CONCLUSION' },
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
        expect(prepared.detailsText).toContain('TEAM_RATIONALE_END')
        expect(prepared.detailsText).toContain('TEAM_RESEARCH_CONCLUSION')
        expect(prepared.detailsText).toContain('TEAM_AUDIT_CONCLUSION')
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
        expect(prepared.detailsText).not.toContain('[Component: lib-b]')
        expect(prepared.detailsText).toContain('CVSS: 8.1 → 3.2')
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

    it('deduplicates team and component scopes case-insensitively', () => {
        const response = createResponse()
        response.component_results = [
            { component: 'lib-a', assessment: response.assessment, versions_checked: ['1.0.0'] },
            { component: 'lib-b', assessment: response.assessment, versions_checked: ['2.0.0'] },
        ]

        const prepared = prepareCodeAnalysisResult(
            response,
            ['lib-a', 'LIB-A', 'lib-b'],
            [
                { name: 'lib-a', tag: 'API' },
                { name: 'lib-b', tag: 'api' },
            ],
            [],
        )

        expect(prepared.teamDrafts).toHaveLength(1)
        expect(prepared.teamDrafts[0]?.team).toBe('API')
        expect(prepared.teamDrafts[0]?.details.match(/\[Component: lib-a\]/g)).toHaveLength(1)
        expect(prepared.teamDrafts[0]?.details.match(/\[Component: lib-b\]/g)).toHaveLength(1)
    })

    describe('buildCodeAnalysisGlobalReferenceDraft', () => {
        const teamDraft = (team: string, state: string, details: string, justification = 'NOT_SET') => ({
            team,
            state,
            details,
            justification,
            assigned: [],
        })

        it('creates one worst-wins global reference without copying team evidence', () => {
            const global = buildCodeAnalysisGlobalReferenceDraft([
                teamDraft('TEAM-A', 'NOT_AFFECTED', 'Evidence unique to team A.', 'CODE_NOT_PRESENT'),
                teamDraft('TEAM-B', 'EXPLOITABLE', 'Evidence unique to team B.'),
                teamDraft('team-a', 'IN_TRIAGE', 'Latest decision for team A.'),
            ])

            expect(global).toEqual(expect.objectContaining({
                team: 'General',
                state: 'EXPLOITABLE',
                justification: 'NOT_SET',
            }))
            expect(global?.details).toContain('Global state follows the owning-team assessments.')
            expect(global?.details).toContain('Assessed Teams: team-a, TEAM-B')
            expect(global?.details).not.toContain('Evidence unique to team A.')
            expect(global?.details).not.toContain('Evidence unique to team B.')
        })

        it('preserves an independently authored global assessment', () => {
            const global = buildCodeAnalysisGlobalReferenceDraft(
                [teamDraft('TEAM-A', 'EXPLOITABLE', 'Team evidence.')],
                teamDraft('General', 'NOT_AFFECTED', 'Reviewer-owned global policy.', 'CODE_NOT_PRESENT'),
            )

            expect(global).toBeNull()
        })

        it('keeps notes from an incomplete global block when linking it to team assessments', () => {
            const global = buildCodeAnalysisGlobalReferenceDraft(
                [teamDraft('TEAM-A', 'NOT_AFFECTED', 'Team evidence.', 'CODE_NOT_PRESENT')],
                teamDraft('General', 'NOT_SET', 'Keep this reviewer note.'),
            )

            expect(global?.state).toBe('NOT_AFFECTED')
            expect(global?.details).toContain('Assessed Teams: TEAM-A')
            expect(global?.details).toContain('Keep this reviewer note.')
        })

        it('updates an existing generated reference instead of creating another global assessment', () => {
            const generated = buildCodeAnalysisGlobalReferenceDraft([
                teamDraft('TEAM-A', 'NOT_AFFECTED', 'Old team evidence.', 'CODE_NOT_PRESENT'),
            ])!
            const updated = buildCodeAnalysisGlobalReferenceDraft([
                teamDraft('TEAM-A', 'NOT_AFFECTED', 'New team evidence.', 'CODE_NOT_PRESENT'),
                teamDraft('TEAM-B', 'IN_TRIAGE', 'New team evidence.'),
            ], generated)

            expect(updated?.state).toBe('IN_TRIAGE')
            expect(updated?.details).toContain('Assessed Teams: TEAM-A, TEAM-B')
            expect(updated?.details.match(/Global state follows/g)).toHaveLength(1)
        })
    })

    describe('prepareCodeAnalysisResults', () => {
        const createRun = (
            component: string,
            verdict: string,
            adjustedScore?: number,
            adjustedVector?: string,
        ): CodeAnalysisComponentRun => {
            const response = createResponse()
            response.assessment.verdict = verdict
            response.assessment.affected = verdict.toLowerCase() === 'affected'
            response.assessment.summary = `Summary for ${component}.`
            response.assessment.reasoning = `Reasoning for ${component}.`
            if (adjustedScore == null) {
                delete response.assessment.adjusted_cvss
            } else {
                response.assessment.adjusted_cvss = {
                    original_score: 8.1,
                    adjusted_score: adjustedScore,
                    adjusted_vector: adjustedVector,
                    reasons: [],
                    summary: '',
                    version_affected: true,
                }
            }
            return { component, result: response, runId: `run-${component}` }
        }

        it('applies every run to its own team and takes the worst assessment to global', () => {
            const prepared = prepareCodeAnalysisResults(
                [
                    createRun('lib-a', 'not affected', 3.2, 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N'),
                    createRun('lib-b', 'affected', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
                    createRun('lib-c', 'probably affected', 6.0, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L'),
                ],
                [
                    { name: 'lib-a', tag: 'TEAM-A' },
                    { name: 'lib-b', tag: 'TEAM-B' },
                    { name: 'lib-c', tag: 'TEAM-C' },
                ],
                ['alice'],
            )

            expect(prepared.teamDrafts).toEqual([
                expect.objectContaining({ team: 'TEAM-A', state: 'NOT_AFFECTED', justification: 'CODE_NOT_PRESENT', assigned: ['alice'] }),
                expect.objectContaining({ team: 'TEAM-B', state: 'EXPLOITABLE' }),
                expect.objectContaining({ team: 'TEAM-C', state: 'IN_TRIAGE' }),
            ])
            expect(prepared.teamDrafts[0]?.details).toContain('Summary for lib-a.')
            expect(prepared.teamDrafts[0]?.details).not.toContain('Summary for lib-b.')
            expect(prepared.globalState).toBe('EXPLOITABLE')
            expect(prepared.globalJustification).toBe('NOT_SET')
            expect(prepared.adjustedScore).toBe(9.1)
            expect(prepared.adjustedVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
            expect(prepared.runIds).toEqual(['run-lib-a', 'run-lib-b', 'run-lib-c'])
            expect(prepared.unmappedComponents).toEqual([])
        })

        it('combines several components of one team into a single worst-wins draft', () => {
            const prepared = prepareCodeAnalysisResults(
                [
                    createRun('lib-a', 'not affected', 3.2),
                    createRun('lib-b', 'probably affected', 6.0),
                ],
                [
                    { name: 'lib-a', tag: 'TEAM-A' },
                    { name: 'lib-b', tag: 'team-a' },
                ],
                [],
            )

            expect(prepared.teamDrafts).toHaveLength(1)
            expect(prepared.teamDrafts[0]?.team).toBe('TEAM-A')
            expect(prepared.teamDrafts[0]?.state).toBe('IN_TRIAGE')
            expect(prepared.teamDrafts[0]?.details).toContain('Summary for lib-a.')
            expect(prepared.teamDrafts[0]?.details).toContain('Summary for lib-b.')
            expect(prepared.globalState).toBe('IN_TRIAGE')
            expect(prepared.adjustedScore).toBe(6.0)
        })

        it('breaks a state tie with the higher analyzer score', () => {
            const prepared = prepareCodeAnalysisResults(
                [
                    createRun('lib-a', 'affected', 7.5, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'),
                    createRun('lib-b', 'affected', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
                ],
                [
                    { name: 'lib-a', tag: 'TEAM-A' },
                    { name: 'lib-b', tag: 'TEAM-B' },
                ],
                [],
            )

            expect(prepared.globalState).toBe('EXPLOITABLE')
            expect(prepared.adjustedScore).toBe(9.8)
            expect(prepared.adjustedVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
        })

        it('reports components without a team but still counts them for the global worst', () => {
            const prepared = prepareCodeAnalysisResults(
                [
                    createRun('lib-a', 'not affected', 3.2),
                    createRun('orphan-lib', 'affected', 9.1),
                ],
                [{ name: 'lib-a', tag: 'TEAM-A' }],
                [],
            )

            expect(prepared.teamDrafts).toHaveLength(1)
            expect(prepared.teamDrafts[0]?.team).toBe('TEAM-A')
            expect(prepared.unmappedComponents).toEqual(['orphan-lib'])
            expect(prepared.globalState).toBe('EXPLOITABLE')
        })

        it('ignores duplicate components and leaves the analyzer CVSS unset when the worst run has none', () => {
            const prepared = prepareCodeAnalysisResults(
                [
                    createRun('lib-a', 'affected'),
                    createRun('LIB-A', 'not affected', 3.2),
                ],
                [{ name: 'lib-a', tag: 'TEAM-A' }],
                [],
            )

            expect(prepared.teamDrafts).toHaveLength(1)
            expect(prepared.teamDrafts[0]?.state).toBe('EXPLOITABLE')
            expect(prepared.globalState).toBe('EXPLOITABLE')
            expect(prepared.adjustedVector).toBeUndefined()
            expect(prepared.adjustedScore).toBeUndefined()
        })

        it('returns an empty preparation without runs', () => {
            const prepared = prepareCodeAnalysisResults([], [{ name: 'lib-a', tag: 'TEAM-A' }], [])

            expect(prepared.teamDrafts).toEqual([])
            expect(prepared.globalState).toBe('NOT_SET')
            expect(prepared.globalJustification).toBe('NOT_SET')
            expect(prepared.runIds).toEqual([])
        })
    })
})
