import { describe, expect, it } from 'vitest'
import { buildSavedAssessmentResultState, buildSavedOriginalAnalysis, prepareAssessmentSubmission } from '../assessmentSubmission'
import type { Instance } from '../../types'

describe('assessmentSubmission', () => {
    const instances: Instance[] = [
        {
            project_name: 'Example',
            project_version: '1.0.0',
            project_uuid: 'project-1',
            component_name: 'lib-a',
            component_version: '2.0.0',
            component_uuid: 'component-1',
            vulnerability_uuid: 'vuln-1',
            finding_uuid: 'finding-1',
            analysis_state: 'NOT_SET',
            analysis_details: '--- [Team: General] [State: NOT_SET] [Assessed By: system] ---\nBaseline details',
            is_suppressed: false,
        },
    ]

    it('merges the active draft into the payload and preserves unsaved team drafts', () => {
        const prepared = prepareAssessmentSubmission({
            allInstances: instances,
            originalAnalysis: {},
            selectedTeam: 'TeamA',
            state: 'EXPLOITABLE',
            details: 'Current team details',
            justification: 'NOT_SET',
            currentAssigned: ['alice'],
            evidenceReviewed: true,
            versionCoverageChecked: true,
            ticket: 'SEC-1234',
            teamDrafts: new Map([
                ['TeamB', {
                    state: 'NOT_AFFECTED',
                    details: 'Other team details',
                    justification: 'CODE_NOT_PRESENT',
                    assigned: ['bob'],
                    evidenceReviewed: false,
                    versionCoverageChecked: true,
                    ticket: 'APP-9',
                }],
            ]),
            isReviewer: true,
            pendingVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            pendingScore: 9.8,
            initialVector: '',
            initialScore: null,
            originalVector: '',
            originalScore: null,
            currentUser: 'reviewer',
            isApprove: false,
            showRawEdit: false,
            rawDetailsTouched: false,
            rawDetails: '',
            mergedAssessmentFullText: '',
            suppressed: false,
            force: false,
        })

        expect(prepared.targetTeam).toBe('TeamA')
        expect(prepared.nextDrafts.get('TeamA')).toEqual({
            state: 'EXPLOITABLE',
            details: 'Current team details',
            justification: 'NOT_SET',
            assigned: ['alice'],
            evidenceReviewed: true,
            versionCoverageChecked: true,
            ticket: 'SEC-1234',
        })
        expect(prepared.reviewText).toContain('--- [Team: TeamA] [State: EXPLOITABLE]')
        expect(prepared.reviewText).toContain('[Evidence Reviewed: yes]')
        expect(prepared.reviewText).toContain('[Version Coverage: yes]')
        expect(prepared.reviewText).toContain('[Ticket: SEC-1234]')
        expect(prepared.reviewText).toContain('[Rescored: 9.8]')
        expect(prepared.reviewText).toContain('[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]')
        expect(prepared.payload.team).toBe('TeamA')
        expect(prepared.payload).not.toHaveProperty('comment')
        expect(prepared.payload.original_analysis).toEqual({})
    })

    it('uses sanitized raw text and clears original analysis on force overwrite', () => {
        const prepared = prepareAssessmentSubmission({
            allInstances: instances,
            originalAnalysis: {
                'finding-1': { analysisDetails: 'stale text' },
            },
            selectedTeam: '',
            state: 'NOT_AFFECTED',
            details: 'Ignored form details',
            justification: 'CODE_NOT_PRESENT',
            currentAssigned: [],
            evidenceReviewed: false,
            versionCoverageChecked: false,
            ticket: '',
            teamDrafts: new Map(),
            isReviewer: false,
            pendingVector: '',
            pendingScore: null,
            initialVector: '',
            initialScore: null,
            originalVector: '',
            originalScore: null,
            currentUser: 'reviewer',
            isApprove: true,
            showRawEdit: true,
            rawDetailsTouched: true,
            rawDetails: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer] [Justification: CODE_NOT_PRESENT] ---\nRaw details',
            mergedAssessmentFullText: 'previous text',
            suppressed: true,
            force: true,
        })

        expect(prepared.reviewText).toContain('--- [Team: General] [State: NOT_AFFECTED]')
        expect(prepared.finalState).toBe('NOT_AFFECTED')
        expect(prepared.payload.justification).toBe('CODE_NOT_PRESENT')
        expect(prepared.payload.force).toBe(true)
        expect(prepared.payload.original_analysis).toEqual({})
        expect(prepared.payload.suppressed).toBe(true)
        expect(prepared.payload.team).toBeUndefined()
    })

    it('builds emitted assessment data and next local score state after a successful save', () => {
        const result = buildSavedAssessmentResultState({
            success: {
                new_state: 'NOT_AFFECTED',
                new_details: 'Saved details\n[Rescored: 5.4]\n[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N]',
            },
            isReviewer: true,
            pendingVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            pendingScore: 5.4,
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            existingRescoredVector: null,
            existingRescoredCvss: null,
            suppressed: true,
            currentAssigned: ['alice'],
        })

        expect(result.emittedAssessment).toEqual({
            rescored_cvss: 5.4,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Saved details\n[Rescored: 5.4]\n[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N]',
            is_suppressed: true,
            assignees: ['alice'],
        })
        expect(result.nextPendingVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')
        expect(result.nextInitialScore).toBe(5.4)
        expect(result.nextLastRescoredScore).toBe(5.4)
    })

    it('preserves score-only rescored state from saved details when no vector is present', () => {
        const result = buildSavedAssessmentResultState({
            success: {
                new_state: 'NOT_AFFECTED',
                new_details: 'Saved details\n[Rescored: 3.2]',
            },
            isReviewer: false,
            pendingVector: '',
            pendingScore: 3.2,
            baseVector: '',
            existingRescoredVector: null,
            existingRescoredCvss: null,
            suppressed: false,
            currentAssigned: ['alice'],
        })

        expect(result.emittedAssessment).toEqual({
            rescored_cvss: 3.2,
            rescored_vector: null,
            analysis_state: 'NOT_AFFECTED',
            analysis_details: 'Saved details\n[Rescored: 3.2]',
            is_suppressed: false,
            assignees: ['alice'],
        })
        expect(result.nextPendingVector).toBe('')
        expect(result.nextInitialScore).toBe(3.2)
        expect(result.nextLastRescoredScore).toBe(3.2)
    })

    it('builds refreshed original-analysis entries for all findings after save', () => {
        expect(buildSavedOriginalAnalysis({
            allInstances: instances,
            finalState: 'EXPLOITABLE',
            finalText: 'Merged final text',
            suppressed: false,
        })).toEqual({
            'finding-1': {
                analysisState: 'EXPLOITABLE',
                analysisDetails: 'Merged final text',
                isSuppressed: false,
            },
        })
    })
})
