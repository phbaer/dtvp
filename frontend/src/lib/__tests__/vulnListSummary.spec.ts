import { describe, expect, it } from 'vitest'
import type { GroupedVuln } from '../../types'
import { summarizeGroupForList } from '../vulnListSummary'

const makeFullGroup = (overrides: Partial<GroupedVuln> = {}): GroupedVuln => ({
    id: 'CVE-2026-0001',
    title: 'Example vulnerability',
    description: 'Long description',
    severity: 'HIGH',
    cvss_score: 8.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    tags: ['Team Alias'],
    aliases: ['GHSA-abcd'],
    assignees: ['alice'],
    affected_versions: [
        {
            project_name: 'Project',
            project_uuid: 'project-uuid',
            project_version: '1.0.0',
            components: [
                {
                    project_name: 'Project',
                    project_version: '1.0.0',
                    project_uuid: 'project-uuid',
                    component_name: 'library-a',
                    component_version: '2.0.0',
                    component_uuid: 'component-uuid',
                    vulnerability_uuid: 'vuln-uuid',
                    finding_uuid: 'finding-uuid',
                    attributed_on: 1782748800000,
                    analysis_state: 'IN_TRIAGE',
                    analysis_details: '--- [Team: Team Alias] [State: IN_TRIAGE] [Assessed By: analyst] ---\nDetailed notes',
                    analysis_comments: [{ comment: 'large comment history', timestamp: 1 }],
                    dependency_chains: ['library-a -> app'],
                    is_suppressed: false,
                    is_direct_dependency: true,
                    justification: 'CODE_NOT_REACHABLE',
                    tags: ['Team Alias'],
                },
            ],
        },
    ],
    ...overrides,
})

describe('vulnListSummary', () => {
    it('summarizes a full group into a lightweight list payload', () => {
        const summary = summarizeGroupForList(makeFullGroup(), {
            'library-a': ['Team Primary', 'Team Alias'],
        })
        const component = summary.affected_versions[0].components[0]

        expect(summary.list_metadata).toMatchObject({
            lifecycle: 'INCOMPLETE',
            is_pending: false,
            is_open: false,
            technical_state: 'IN_TRIAGE',
            assessed_teams: ['Team Primary'],
        })
        expect(component.analysis_state).toBe('IN_TRIAGE')
        expect(component.justification).toBe('CODE_NOT_REACHABLE')
        expect(component.is_direct_dependency).toBe(true)
        expect(component).not.toHaveProperty('analysis_details')
        expect(component).not.toHaveProperty('analysis_comments')
        expect(component).not.toHaveProperty('dependency_chains')
    })

    it('refreshes metadata from updated assessment details', () => {
        const summary = summarizeGroupForList(makeFullGroup({
            tags: ['General'],
            affected_versions: [
                {
                    project_name: 'Project',
                    project_uuid: 'project-uuid',
                    project_version: '1.0.0',
                    components: [
                        {
                            project_name: 'Project',
                            project_version: '1.0.0',
                            project_uuid: 'project-uuid',
                            component_name: 'library-a',
                            component_version: '2.0.0',
                            component_uuid: 'component-uuid',
                            vulnerability_uuid: 'vuln-uuid',
                            finding_uuid: 'finding-uuid',
                            analysis_state: 'FALSE_POSITIVE',
                            analysis_details: '--- [Team: General] [State: FALSE_POSITIVE] [Assessed By: reviewer] ---\nReviewed',
                            is_suppressed: false,
                        },
                    ],
                },
            ],
        }), {})

        expect(summary.list_metadata?.lifecycle).toBe('ASSESSED')
        expect(summary.list_metadata?.is_assessed).toBe(true)
        expect(summary.list_metadata?.technical_state).toBe('FALSE_POSITIVE')
    })
})
