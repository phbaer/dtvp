import { describe, expect, it } from 'vitest'
import { cleanStructuredAssessmentDetails, resolveAssessmentFormValues, resolveDependencyTrackConsensusInput, stripPendingReviewStatus } from '../assessmentFormState'
import type { AssessmentBlock } from '../assessment-helpers'

describe('assessmentFormState', () => {
    it('strips the pending review marker from textarea details', () => {
        expect(stripPendingReviewStatus('Summary\n\n[Status: Pending Review]')).toBe('Summary')
        expect(stripPendingReviewStatus('Summary [Status: Pending Review]')).toBe('Summary ')
    })

    it('removes structured assessment metadata when plain textarea content is needed', () => {
        expect(cleanStructuredAssessmentDetails(
            '--- [Team: General] [State: EXPLOITABLE] [Assessed By: Reviewer] [Justification: NOT_SET] ---\nSummary\n[Rescored: 4.2]\n[Rescored Vector: CVSS:3.1/AV:N]\n[Status: Pending Review]',
        )).toBe('Summary')
    })

    it('returns the selected team block when a team is active', () => {
        const blocks: AssessmentBlock[] = [
            {
                team: 'TEAM-A',
                state: 'EXPLOITABLE',
                user: 'Reviewer',
                details: 'Team summary\n\n[Status: Pending Review]',
                justification: 'NOT_SET',
                assigned: [],
            },
        ]

        expect(resolveAssessmentFormValues({
            selectedTeam: 'TEAM-A',
            isReviewer: true,
            teamBlocks: blocks,
            instances: [],
        })).toEqual({
            state: 'EXPLOITABLE',
            details: 'Team summary',
            justification: 'NOT_SET',
        })
    })

    it('falls back to the worst DT general block for reviewers when no general assessment exists', () => {
        expect(resolveAssessmentFormValues({
            selectedTeam: '',
            isReviewer: true,
            teamBlocks: [],
            instances: [
                {
                    analysis_state: 'NOT_AFFECTED',
                    analysis_details: '--- [Team: General] [State: NOT_AFFECTED] [Assessed By: Reviewer] [Justification: CODE_NOT_PRESENT] ---\nGeneral finding [Status: Pending Review]',
                },
                {
                    analysis_state: 'EXPLOITABLE',
                    analysis_details: '--- [Team: General] [State: EXPLOITABLE] [Assessed By: Reviewer] [Justification: NOT_SET] ---\nGeneral exploit path\n\n[Status: Pending Review]',
                },
            ],
        })).toEqual({
            state: 'EXPLOITABLE',
            details: 'General exploit path',
            justification: 'NOT_SET',
        })
    })

    it('returns empty defaults for non-reviewers without a selected team', () => {
        expect(resolveAssessmentFormValues({
            selectedTeam: '',
            isReviewer: false,
            teamBlocks: [],
            instances: [
                {
                    analysis_state: 'EXPLOITABLE',
                    analysis_details: 'ignored',
                },
            ],
        })).toEqual({
            state: 'NOT_SET',
            details: '',
            justification: 'NOT_SET',
        })
    })

    it('resolves dependency-track consensus input from structured or plain-text justification sources', () => {
        expect(resolveDependencyTrackConsensusInput([
            {
                analysis_state: 'EXPLOITABLE',
                analysis_details: '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: user1] [Justification: CODE_NOT_PRESENT] ---\nBlock says NOT_AFFECTED',
            },
            {
                analysis_state: 'NOT_AFFECTED',
                analysis_details: 'Plain DT text. Justification: CODE_NOT_REACHABLE',
            },
        ])).toEqual({
            dtStates: ['EXPLOITABLE', 'NOT_AFFECTED'],
            dtJustification: 'CODE_NOT_PRESENT',
        })
    })

    it('falls back to another same-state DT candidate when the worst candidate has no explicit justification', () => {
        expect(resolveDependencyTrackConsensusInput([
            {
                analysis_state: 'NOT_AFFECTED',
                analysis_details: '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: user1] ---\nAssessment block without justification',
            },
            {
                analysis_state: 'NOT_AFFECTED',
                analysis_details: 'Plain DT text. Justification: CODE_NOT_PRESENT',
            },
        ])).toEqual({
            dtStates: ['NOT_AFFECTED', 'NOT_AFFECTED'],
            dtJustification: 'CODE_NOT_PRESENT',
        })
    })
})