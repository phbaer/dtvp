import { describe, expect, it } from 'vitest'
import { buildMergedAssessmentData } from '../mergedAssessmentData'
import type { Instance } from '../../types'

describe('mergedAssessmentData', () => {
    it('keeps the latest block per team and marks pending review status', () => {
        const instances: Instance[] = [
            {
                project_name: 'Example',
                project_version: '1.0.0',
                project_uuid: 'project-1',
                component_name: 'lib-a',
                component_version: '1.0.0',
                component_uuid: 'component-1',
                vulnerability_uuid: 'vuln-1',
                finding_uuid: 'finding-1',
                analysis_state: 'EXPLOITABLE',
                analysis_details: '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: user1] [Date: 10] ---\nOlder details',
                is_suppressed: false,
            },
            {
                project_name: 'Example',
                project_version: '1.0.0',
                project_uuid: 'project-1',
                component_name: 'lib-a',
                component_version: '1.0.1',
                component_uuid: 'component-2',
                vulnerability_uuid: 'vuln-1',
                finding_uuid: 'finding-2',
                analysis_state: 'EXPLOITABLE',
                analysis_details: '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: user2] [Date: 11] ---\nNewer details\n[Status: Pending Review]',
                is_suppressed: false,
            },
        ]

        const merged = buildMergedAssessmentData(instances)

        expect(merged.blocks).toHaveLength(1)
        expect(merged.blocks[0]?.details).toBe('Newer details')
        expect(merged.isPending).toBe(true)
        expect(merged.fullText).toContain('[Status: Pending Review]')
    })

    it('includes shared rescored tags in the reconstructed full text', () => {
        const instances: Instance[] = [
            {
                project_name: 'Example',
                project_version: '1.0.0',
                project_uuid: 'project-1',
                component_name: 'lib-a',
                component_version: '1.0.0',
                component_uuid: 'component-1',
                vulnerability_uuid: 'vuln-1',
                finding_uuid: 'finding-1',
                analysis_state: 'NOT_AFFECTED',
                analysis_details: '[Rescored: 5.4]\n--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\nSafe path',
                is_suppressed: false,
            },
        ]

        const merged = buildMergedAssessmentData(instances)

        expect(merged.fullText).toContain('[Rescored: 5.4]')
        expect(merged.fullText).toContain('--- [Team: General] [State: NOT_AFFECTED]')
    })
})