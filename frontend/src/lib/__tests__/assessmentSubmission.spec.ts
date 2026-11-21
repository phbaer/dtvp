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

    it('leaves the assessments of other teams alone when their drafts say nothing new', () => {
        const stored = [
            '--- [Team: Phoenix] [State: NOT_AFFECTED] [Assessed By: paul] [Date: 1791500000000] [Justification: CODE_NOT_PRESENT] ---',
            'Not shipped.',
            '',
            '--- [Team: R-Web] [State: EXPLOITABLE] [Assessed By: rosa] [Date: 1786600000000] [Justification: NOT_SET] [Ticket: VP-66089] ---',
            'Reachable from the web tier.',
        ].join('\n')
        const draft = (state: string, details: string, justification: string, ticket: string) => ({
            state, details, justification, ticket,
            assigned: [], evidenceReviewed: false, versionCoverageChecked: false,
        })
        const prepared = prepareAssessmentSubmission({
            allInstances: [{ ...instances[0]!, analysis_state: 'EXPLOITABLE', analysis_details: stored }],
            originalAnalysis: {},
            selectedTeam: '',
            state: 'NOT_AFFECTED',
            details: 'Decided.',
            justification: 'CODE_NOT_PRESENT',
            currentAssigned: [],
            evidenceReviewed: false,
            versionCoverageChecked: false,
            ticket: '',
            teamDrafts: new Map([
                // The tab was opened and left as it was.
                ['Phoenix', draft('NOT_AFFECTED', 'Not shipped.', 'CODE_NOT_PRESENT', '')],
                // A form that never showed the team's assessment.
                ['R-Web', draft('NOT_SET', '', 'NOT_SET', '')],
            ]),
            isReviewer: true,
            pendingVector: '',
            pendingScore: null,
            initialVector: '',
            initialScore: null,
            originalVector: '',
            originalScore: null,
            currentUser: 'reviewer',
            isApprove: true,
            showRawEdit: false,
            rawDetailsTouched: false,
            rawDetails: '',
            mergedAssessmentFullText: stored,
            suppressed: false,
            force: false,
        })

        // A reviewer's approval is sent as such.
        expect(prepared.payload.approve).toBe(true)
        const teams = Object.fromEntries(prepared.payload.fields!.teams.map(team => [team.team, team]))
        expect(Object.keys(teams).sort()).toEqual(['General', 'Phoenix', 'R-Web'])
        expect(teams.General).toMatchObject({ state: 'NOT_AFFECTED', assessed_by: 'reviewer' })
        // Not written again under the saving user's name and time.
        expect(teams.Phoenix).toMatchObject({ assessed_by: 'paul', assessed_at_ms: 1791500000000 })
        // Not removed, and its ticket is still there.
        expect(teams['R-Web']).toMatchObject({
            state: 'EXPLOITABLE', assessed_by: 'rosa', ticket: 'VP-66089',
            details: 'Reachable from the web tier.',
        })
    })

    it('keeps assessor and date when the team changes only its ticket', () => {
        const stored = [
            '--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] [Date: 1790000000000] [Justification: CODE_NOT_REACHABLE] [Ticket: EXP-1] ---',
            'Not reachable.',
            '',
            '[Status: Pending Review]',
        ].join('\n')
        const prepared = prepareAssessmentSubmission({
            allInstances: [{ ...instances[0]!, analysis_state: 'NOT_AFFECTED', analysis_details: stored }],
            originalAnalysis: {},
            selectedTeam: 'TeamA',
            state: 'NOT_AFFECTED',
            details: 'Not reachable.',
            justification: 'CODE_NOT_REACHABLE',
            currentAssigned: [],
            evidenceReviewed: false,
            versionCoverageChecked: false,
            ticket: 'EXP-1, EXP-2',
            teamDrafts: new Map(),
            isReviewer: false,
            pendingVector: '',
            pendingScore: null,
            initialVector: '',
            initialScore: null,
            originalVector: '',
            originalScore: null,
            currentUser: 'bob',
            isApprove: false,
            showRawEdit: false,
            rawDetailsTouched: false,
            rawDetails: '',
            mergedAssessmentFullText: stored,
            suppressed: false,
            force: false,
        })

        const [team] = prepared.payload.fields!.teams
        expect(team).toMatchObject({
            team: 'TeamA', ticket: 'EXP-1, EXP-2',
            assessed_by: 'alice', assessed_at_ms: 1790000000000,
        })
    })

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
        // The assessment is sent as fields; no composed text leaves the browser.
        expect(prepared.payload).not.toHaveProperty('details')
        expect(prepared.payload).not.toHaveProperty('comparison_mode')
        expect(prepared.payload.fields).toEqual(expect.objectContaining({
            free_text: null, // not edited in the form: the server keeps it
            pending_review: true,
            rescored_score: 9.8,
            rescored_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        }))
        expect(prepared.payload.fields?.teams.map(team => team.team)).toEqual(['General', 'TeamA', 'TeamB'])
        expect(prepared.payload.fields?.teams.find(team => team.team === 'TeamA')).toEqual(expect.objectContaining({
            state: 'EXPLOITABLE',
            justification: null,
            assessed_by: 'reviewer',
            assessed_at_ms: expect.any(Number),
            assigned: ['alice'],
            ticket: 'SEC-1234',
            evidence_reviewed: 'yes',
            version_coverage: 'yes',
            details: 'Current team details',
        }))
        expect(prepared.payload.fields?.teams.find(team => team.team === 'TeamB')).toEqual(expect.objectContaining({
            state: 'NOT_AFFECTED',
            justification: 'CODE_NOT_PRESENT',
            ticket: 'APP-9',
            evidence_reviewed: null,
            version_coverage: 'yes',
            details: 'Other team details',
        }))
        // No reload happened: the value shown in the view is what the edit
        // was based on, and the server checks it against Dependency-Track.
        expect(prepared.payload.original_analysis).toEqual({
            'finding-1': {
                analysisState: 'NOT_SET',
                analysisDetails: '--- [Team: General] [State: NOT_SET] [Assessed By: system] ---\nBaseline details',
                isSuppressed: false,
            },
        })
    })

    it('copies a previous team into a pending target draft and retires the source', () => {
        const previous = '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] [Justification: NOT_SET] ---\nEarlier rationale'
        const prepared = prepareAssessmentSubmission({
            allInstances: [{ ...instances[0]!, analysis_state: 'EXPLOITABLE', analysis_details: previous }],
            originalAnalysis: {},
            selectedTeam: 'TeamB',
            state: 'RESOLVED',
            details: 'Reviewed earlier rationale',
            justification: 'NOT_SET',
            currentAssigned: [],
            evidenceReviewed: false,
            versionCoverageChecked: false,
            ticket: '',
            teamDrafts: new Map(),
            takeoverSources: new Map([['TeamB', 'TeamA']]),
            isReviewer: false,
            pendingVector: '',
            pendingScore: null,
            initialVector: '',
            initialScore: null,
            currentUser: 'bob',
            isApprove: false,
            showRawEdit: false,
            rawDetailsTouched: false,
            rawDetails: '',
            mergedAssessmentFullText: previous,
            suppressed: false,
            force: false,
        })
        expect(prepared.finalText).toContain('[Team: TeamA] [State: EXPLOITABLE]')
        expect(prepared.finalText).toContain('[Historical: yes]')
        expect(prepared.finalText).toContain('[Team: TeamB] [State: RESOLVED]')
        expect(prepared.finalText).toContain('[Copied From: TeamA]')
        expect(prepared.finalState).toBe('RESOLVED')
        expect(prepared.finalText).toContain('[Status: Pending Review]')
        // A save is not an approval.
        expect(prepared.payload).not.toHaveProperty('approve')
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
        expect(prepared.payload.fields).toEqual(expect.objectContaining({
            pending_review: false,
            teams: [expect.objectContaining({
                team: 'General', state: 'NOT_AFFECTED', assessed_by: 'reviewer',
                justification: 'CODE_NOT_PRESENT', details: 'Raw details',
            })],
        }))
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

    it('does not take a historical record\'s rescoring as the finding\'s after a save', () => {
        const record = '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] [Justification: NOT_SET] '
            + '[Rescored: 9.8] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H] [Historical: yes] ---\nOld record.'
        const result = buildSavedAssessmentResultState({
            success: {
                new_state: 'NOT_AFFECTED',
                new_details: `--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_PRESENT] ---\nNot shipped.\n\n${record}`,
            },
            isReviewer: false,
            pendingVector: '',
            pendingScore: null,
            baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            existingRescoredVector: null,
            existingRescoredCvss: null,
            suppressed: false,
            currentAssigned: [],
        })

        expect(result.emittedAssessment.rescored_cvss ?? null).toBeNull()
        expect(result.emittedAssessment.rescored_vector ?? null).toBeNull()
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
            results: [{
                uuid: 'finding-1',
                new_state: 'EXPLOITABLE',
                new_details: 'Merged final text',
                queued: true,
                sync_status: 'pending',
                update_id: 'update-1',
                revision: 3,
            }],
        })).toEqual({
            'finding-1': {
                analysisState: 'EXPLOITABLE',
                analysisDetails: 'Merged final text',
                isSuppressed: false,
                dtvpRevision: 3,
                dtvpSyncStatus: 'pending',
                dtvpUpdateId: 'update-1',
            },
        })
    })

    const teamSave = (allInstances: Instance[]) => prepareAssessmentSubmission({
        allInstances,
        originalAnalysis: {},
        selectedTeam: 'TeamB',
        state: 'NOT_AFFECTED',
        details: 'Not shipped.',
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
        currentUser: 'bob',
        isApprove: false,
        showRawEdit: false,
        rawDetailsTouched: false,
        rawDetails: '',
        mergedAssessmentFullText: '',
        suppressed: false,
        force: false,
    })
    const finding = (id: string, details: string): Instance => ({
        ...instances[0]!, finding_uuid: id, component_uuid: `component-${id}`, analysis_details: details,
    })

    it('does not take the rescoring of a historical block as the finding\'s', () => {
        const prepared = teamSave([finding('f1', [
            '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: a] [Date: 1700000000000] [Justification: NOT_SET] [Rescored: 9.1] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H] [Historical: yes] ---',
            'Old record.',
        ].join('\n'))])

        expect(prepared.finalText.startsWith('---')).toBe(true)
        expect(prepared.payload.fields!.rescored_score).toBeNull()
        expect(prepared.payload.fields!.rescored_vector).toBeNull()
        const record = prepared.payload.fields!.teams.find(team => team.team === 'TeamA')
        expect(record).toMatchObject({ historical: true, rescored_score: 9.1 })
    })

    it('keeps a team\'s current block next to a newer historical one of the same team', () => {
        const live = '--- [Team: TeamX] [State: NOT_AFFECTED] [Assessed By: xa] [Date: 1600000000000] [Justification: CODE_NOT_PRESENT] ---\nCurrent.'
        const undated = '--- [Team: TeamX] [State: NOT_AFFECTED] [Assessed By: xa] [Justification: CODE_NOT_PRESENT] ---\nCurrent.'
        const record = '--- [Team: TeamX] [State: EXPLOITABLE] [Assessed By: xo] [Date: 1650000000000] [Justification: NOT_SET] [Historical: yes] ---\nOld.'
        const older = '--- [Team: TeamX] [State: IN_TRIAGE] [Assessed By: xp] [Date: 1550000000000] [Justification: NOT_SET] [Historical: yes] ---\nOlder.'
        for (const allInstances of [
            [finding('f1', `${live}\n\n${record}`)],
            [finding('f1', `${undated}\n\n${record}`)],
            // Across the findings of a group.
            [finding('f1', live), finding('f2', `${record}\n\n${older}`)],
        ]) {
            const teams = teamSave(allInstances).payload.fields!.teams
                .filter(team => team.team === 'TeamX')
                .map(team => [team.state, team.historical])
            expect(teams).toHaveLength(allInstances.length === 2 ? 3 : 2)
            expect(teams).toContainEqual(['NOT_AFFECTED', false])
            expect(teams).toContainEqual(['EXPLOITABLE', true])
        }
    })

    it('sends a historical block\'s text back as written', () => {
        const stored = '--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: a] [Date: 1700000000000] [Justification: NOT_SET] [Historical: yes] ---\n[Comment] Fixed upstream, see [Ticket: ABC-1] for details.'
        const record = teamSave([finding('f1', stored)]).payload.fields!.teams.find(team => team.team === 'TeamA')
        expect(record).toMatchObject({
            historical: true,
            details: '[Comment] Fixed upstream, see [Ticket: ABC-1] for details.',
            ticket: null,
        })
    })
})
