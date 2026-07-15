import { describe, expect, it } from 'vitest'
import type { GroupedVuln } from '../../types'
import { getGroupAssessmentSyncIssues } from '../assessmentSyncIssues'

const instance = (overrides: Record<string, any> = {}) => ({
    project_name: 'Example',
    project_version: '1.0.0',
    project_uuid: 'project-1',
    component_name: 'library-a',
    component_version: '1.0.0',
    component_uuid: 'component-1',
    vulnerability_uuid: 'vulnerability-1',
    finding_uuid: 'finding-1',
    analysis_state: 'NOT_SET',
    analysis_details: '',
    is_suppressed: false,
    ...overrides,
})

describe('assessmentSyncIssues', () => {
    it('explains every missing part of an incomplete assessment', () => {
        const group: GroupedVuln = {
            id: 'CVE-INCOMPLETE',
            tags: ['Team A', 'Team B'],
            affected_versions: [{
                project_name: 'Example',
                project_version: '1.0.0',
                project_uuid: 'project-1',
                components: [
                    instance({
                        analysis_state: 'EXPLOITABLE',
                        analysis_details: '--- [Team: Team A] [State: EXPLOITABLE] ---',
                    }),
                    instance({
                        finding_uuid: 'finding-2',
                        component_name: 'library-b',
                    }),
                ],
            }],
        }

        const issues = getGroupAssessmentSyncIssues(group, { lifecycle: 'INCOMPLETE' })

        expect(issues).toEqual(expect.arrayContaining([
            expect.objectContaining({
                code: 'MISSING_TEAM_ASSESSMENTS',
                detail: 'No completed assessment for Team B.',
            }),
            expect.objectContaining({
                code: 'UNASSESSED_FINDINGS',
                detail: expect.stringContaining('1 of 2 finding instances'),
            }),
            expect.objectContaining({ code: 'MISSING_GLOBAL_ASSESSMENT' }),
        ]))
    })

    it('shows the concrete conflicting states for an inconsistent assessment', () => {
        const group: GroupedVuln = {
            id: 'CVE-INCONSISTENT',
            list_metadata: {
                lifecycle: 'INCONSISTENT',
                inconsistency_reasons: ['ANALYSIS_STATE_MISMATCH'],
            },
            affected_versions: [{
                project_name: 'Example',
                project_version: '1.0.0',
                project_uuid: 'project-1',
                components: [
                    instance({ analysis_state: 'EXPLOITABLE' }),
                    instance({ finding_uuid: 'finding-2', analysis_state: 'NOT_AFFECTED' }),
                ],
            }],
        }

        expect(getGroupAssessmentSyncIssues(group)).toEqual([
            expect.objectContaining({
                code: 'ANALYSIS_STATE_MISMATCH',
                label: 'Analysis states differ',
                detail: 'Current analysis states: Exploitable, Not Affected.',
            }),
        ])
    })

    it('uses the indexed descriptions for non-state inconsistencies', () => {
        const group: GroupedVuln = {
            id: 'CVE-INCONSISTENT',
            list_metadata: {
                lifecycle: 'INCONSISTENT',
                inconsistency_reasons: [
                    'TEAM_ASSESSMENT_MISMATCH',
                    'ASSESSMENT_DETAILS_MISMATCH',
                ],
            },
            affected_versions: [],
        }

        const issues = getGroupAssessmentSyncIssues(group)

        expect(issues.map(issue => issue.label)).toEqual([
            'Team assessments differ',
            'Assessment details differ',
        ])
        expect(issues.every(issue => issue.detail.length > 20)).toBe(true)
    })
})
