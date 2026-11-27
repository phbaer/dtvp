import { describe, expect, it } from 'vitest'
import { hasGlobalAssessmentData } from '../assessmentCleanup'

const team = '--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: analyst] ---\nEvidence.'

describe('Global cleanup availability', () => {
    it.each(['[Status: Pending Review]', '[Rescored: 0.0]', '[Response: UPDATE]', 'Global rationale.'])(
        'recognizes a shared field without a General block: %s', shared => {
            expect(hasGlobalAssessmentData([{ analysis_details: `${shared}\n\n${team}` }])).toBe(true)
        },
    )
    it('keeps team-only decisions distinct from Global fields', () => {
        expect(hasGlobalAssessmentData([{ analysis_details: team }])).toBe(false)
        expect(hasGlobalAssessmentData([{ analysis_details: '[Version Override: 7.x exception]\n\n' + team }])).toBe(false)
        expect(hasGlobalAssessmentData([{ analysis_details: team, is_suppressed: true }])).toBe(true)
    })
})
