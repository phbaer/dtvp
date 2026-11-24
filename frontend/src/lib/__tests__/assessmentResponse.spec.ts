import { describe, expect, it } from 'vitest'
import {
    ANALYSIS_RESPONSE_OPTIONS,
    analysisResponseLabel,
    assessmentTextToFields,
    buildBulkSyncDetails,
    mergeTeamAssessment,
    normalizeAssessmentResponse,
    parseAssessmentBlocks,
    parseAssessmentResponse,
    sanitizeAssessmentDetails,
    setAssessmentResponse,
    stripAssessmentResponseTags,
} from '../assessment-helpers'
import { cleanStructuredAssessmentDetails } from '../assessmentFormState'
import { buildMergedAssessmentData } from '../mergedAssessmentData'
import { prepareAssessmentSubmission } from '../assessmentSubmission'
import { renderAssessmentFields } from './assessmentFieldsText'
import type { Instance } from '../../types'

const VECTOR = 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'
const GENERAL = '--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] [Justification: NOT_SET] ---\nReachable.'
const CORE = '--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] [Justification: NOT_SET] ---\nConfirmed.'

describe('the analysis response in assessment text', () => {
    it('offers the responses of Dependency-Track in the order of the form', () => {
        expect(ANALYSIS_RESPONSE_OPTIONS.map(option => [option.value, option.label])).toEqual([
            ['NOT_SET', 'Not set'],
            ['UPDATE', 'Update'],
            ['ROLLBACK', 'Rollback'],
            ['WORKAROUND_AVAILABLE', 'Workaround available'],
            ['WILL_NOT_FIX', 'Will not fix'],
            ['CAN_NOT_FIX', 'Can not fix'],
        ])
        expect(analysisResponseLabel('WILL_NOT_FIX')).toBe('Will not fix')
        expect(analysisResponseLabel('NOT_SET')).toBe('')
        expect(analysisResponseLabel(null)).toBe('')
    })

    it('normalises the spelling and drops unknown values', () => {
        expect(normalizeAssessmentResponse('will_not_fix')).toBe('WILL_NOT_FIX')
        expect(normalizeAssessmentResponse('NOT_SET')).toBeNull()
        expect(normalizeAssessmentResponse('MAYBE_LATER')).toBeNull()
        expect(normalizeAssessmentResponse(undefined)).toBeNull()
    })

    it('reads the tag beside the team blocks as a field', () => {
        const text = `[Rescored: 2.5] [Rescored Vector: ${VECTOR}] [Response: UPDATE]\n\n${GENERAL}\n\n${CORE}`
        expect(parseAssessmentResponse(text)).toBe('UPDATE')
        const fields = assessmentTextToFields(text)
        expect(fields.response).toBe('UPDATE')
        expect(fields.rescored_score).toBe(2.5)
        // Nothing but the blocks: the form did not edit the free text.
        expect(fields.free_text).toBeNull()
        expect(fields.teams.map(team => team.details)).toEqual(['Reachable.', 'Confirmed.'])
        // What the server renders from the fields is the same text.
        expect(renderAssessmentFields(fields)).toBe(text)
    })

    it('has no response without a tag, and none for a tag that is not of the list', () => {
        expect(assessmentTextToFields(GENERAL).response).toBeNull()
        expect(parseAssessmentResponse('')).toBeNull()
        expect(parseAssessmentResponse(undefined)).toBeNull()
        const unknown = assessmentTextToFields('[Response: ask the supplier]')
        expect(unknown.response).toBeNull()
        expect(unknown.free_text).toBe('[Response: ask the supplier]')
    })

    it('never shows a response tag inside rationale text', () => {
        // Ahead of the blocks it is not the text of a General assessment.
        expect(parseAssessmentBlocks(`[Response: ROLLBACK]\n\n${CORE}`).map(block => block.team)).toEqual(['Core'])
        expect(parseAssessmentBlocks('[Response: ROLLBACK]')).toEqual([])
        expect(parseAssessmentBlocks('[Response: ROLLBACK]\n\nAn older note.')[0]?.details).toBe('An older note.')
        // Inside a team's text it is neither the field nor shown.
        const inside = `${CORE} [Response: UPDATE]`
        expect(parseAssessmentBlocks(inside)[0]?.details).toBe('Confirmed.')
        expect(parseAssessmentResponse(inside)).toBeNull()
        expect(stripAssessmentResponseTags('We [Response: update] soon.')).toBe('We  soon.')
        expect(cleanStructuredAssessmentDetails(`[Response: UPDATE]\n\n${GENERAL}`)).toBe('Reachable.')
    })

    it('sets, changes and removes the response of a text', () => {
        const rescored = `[Rescored: 4.0]\n\n${GENERAL}`
        const withResponse = setAssessmentResponse(rescored, 'UPDATE')
        expect(withResponse).toBe(`[Rescored: 4.0] [Response: UPDATE]\n\n${GENERAL}`)
        expect(setAssessmentResponse(withResponse, 'ROLLBACK')).toBe(`[Rescored: 4.0] [Response: ROLLBACK]\n\n${GENERAL}`)
        expect(setAssessmentResponse(withResponse, 'NOT_SET')).toBe(rescored)
        expect(setAssessmentResponse(withResponse, null)).toBe(rescored)
        expect(setAssessmentResponse(GENERAL, 'CAN_NOT_FIX')).toBe(`[Response: CAN_NOT_FIX]\n\n${GENERAL}`)
        expect(setAssessmentResponse('', 'UPDATE')).toBe('[Response: UPDATE]')
        expect(setAssessmentResponse(GENERAL, 'NOT_SET')).toBe(GENERAL)
    })

    it('keeps the response when a team assessment is merged or the text is tidied', () => {
        const text = `[Response: WORKAROUND_AVAILABLE]\n\n${GENERAL}\n\n${CORE}`
        const merged = mergeTeamAssessment(text, 'Core', 'EXPLOITABLE', 'Still confirmed.', 'bob')
        expect(parseAssessmentResponse(merged.text)).toBe('WORKAROUND_AVAILABLE')
        // Also when the save brings new rescoring tags, or removes them.
        for (const tags of [['[Rescored: 1.0]'], []]) {
            const rescored = mergeTeamAssessment(text, 'General', 'EXPLOITABLE', 'Reachable.', 'rita', 'NOT_SET', tags)
            expect(parseAssessmentResponse(rescored.text)).toBe('WORKAROUND_AVAILABLE')
            expect(rescored.text.match(/\[Response:/g)).toHaveLength(1)
        }
        const sanitized = sanitizeAssessmentDetails(`${text}\n\n${CORE}`)
        expect(parseAssessmentResponse(sanitized.text)).toBe('WORKAROUND_AVAILABLE')
        expect(sanitized.blocks.every(block => !block.details.includes('Response'))).toBe(true)
        const synced = buildBulkSyncDetails(parseAssessmentBlocks(text), text)
        expect(parseAssessmentResponse(synced.text)).toBe('WORKAROUND_AVAILABLE')
    })

    it('shows the first response of the findings in the merged view', () => {
        const instance = (finding: string, details: string) => ({
            finding_uuid: finding, analysis_state: 'EXPLOITABLE', analysis_details: details,
        }) as unknown as Instance
        const merged = buildMergedAssessmentData([
            instance('f1', GENERAL),
            instance('f2', `[Response: ROLLBACK]\n\n${GENERAL}`),
        ])
        expect(merged.response).toBe('ROLLBACK')
        expect(merged.fullText.startsWith('[Response: ROLLBACK]\n\n--- [Team: General]')).toBe(true)
        expect(merged.blocks.map(block => block.details)).toEqual(['Reachable.'])
        expect(buildMergedAssessmentData([instance('f1', GENERAL)]).response).toBeNull()
    })
})

describe('the analysis response in a save', () => {
    const instances = [{
        project_name: 'Example', project_version: '1.0.0', project_uuid: 'project-1',
        component_name: 'lib-a', component_version: '2.0.0', component_uuid: 'component-1',
        vulnerability_uuid: 'vuln-1', finding_uuid: 'finding-1',
        analysis_state: 'EXPLOITABLE',
        analysis_details: `[Response: UPDATE]\n\n${GENERAL}\n\n${CORE}`,
        is_suppressed: false,
    }] as Instance[]

    const prepare = (overrides: Record<string, unknown>) => prepareAssessmentSubmission({
        allInstances: instances,
        originalAnalysis: {},
        selectedTeam: '',
        state: 'EXPLOITABLE',
        details: 'Reachable.',
        justification: 'NOT_SET',
        currentAssigned: [],
        evidenceReviewed: false,
        versionCoverageChecked: false,
        ticket: '',
        teamDrafts: new Map(),
        isReviewer: true,
        pendingVector: '',
        pendingScore: null,
        initialVector: '',
        initialScore: null,
        originalVector: '',
        originalScore: null,
        currentUser: 'rita',
        isApprove: true,
        suppressed: false,
        force: false,
        ...overrides,
    } as Parameters<typeof prepareAssessmentSubmission>[0])

    it('sends the response chosen on the Global form in the fields', () => {
        const changed = prepare({ response: 'WILL_NOT_FIX' })
        expect(changed.payload.fields?.response).toBe('WILL_NOT_FIX')
        // The review dialog shows it as the server will store it.
        expect(changed.finalText.startsWith('[Response: WILL_NOT_FIX]\n\n--- [Team: General]')).toBe(true)
        expect(changed.payload.fields?.teams.map(team => team.team)).toEqual(['General', 'Core'])

        const kept = prepare({ response: 'UPDATE' })
        expect(kept.payload.fields?.response).toBe('UPDATE')
    })

    it('removes the response when the form says not set', () => {
        const cleared = prepare({ response: 'NOT_SET' })
        expect(cleared.payload.fields).toHaveProperty('response', null)
        expect(cleared.finalText).not.toContain('Response')
    })

    it('leaves the response out of a team save and of an analyst\'s save', () => {
        const team = prepare({ selectedTeam: 'Core', details: 'Confirmed.', response: undefined })
        expect(team.payload.fields).not.toHaveProperty('response')
        // The dialog still shows the stored one, which the server keeps.
        expect(parseAssessmentResponse(team.finalText)).toBe('UPDATE')

        const analyst = prepare({ isReviewer: false, selectedTeam: 'Core', details: 'Confirmed.', response: 'ROLLBACK', isApprove: false })
        expect(analyst.payload.fields).not.toHaveProperty('response')
        expect(parseAssessmentResponse(analyst.finalText)).toBe('UPDATE')
    })
})
