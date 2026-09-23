import { describe, expect, it } from 'vitest'
import model from '../../../../dtvp/resources/ssvc/deployer-1.0.0.json'
import { evaluateSsvc, readSsvcRecord, summarizeSsvc, ssvcReviewSummary, ssvcReviewText, stripSsvcDocumentation } from '../ssvc'
import { parseAssessmentBlocks } from '../assessment-helpers'
import { mergeTeamAssessment, sanitizeAssessmentDetails } from '../assessment-helpers'

const record = {
    model: 'ssvc:DT_DP', version: '1.0.0', rationale: 'Context ] —\n---',
    answers: { 'ssvc:E:1.1.0': 'A', 'ssvc:EXP:1.0.1': 'O', 'ssvc:A:2.0.0': 'Y', 'ssvc:HI:2.0.2': 'VH' },
    outcome: 'I', assessor: 'reviewer', assessed_at: '2026-09-21T12:00:00Z',
}
const details = (value = record) => `--- [Team: General] [State: NOT_SET] [Assessed By: reviewer] [SSVC: ${encodeURIComponent(JSON.stringify(value)).replaceAll('-', '%2D')}] ---`
const structured = (value = record, outcome = 'IMMEDIATE') => `--- [Team: General] [State: NOT_SET] [Assessed By: reviewer] [SSVC: ${outcome}] ---\n\n[SSVC Details]\n${JSON.stringify(value, null, 2)}\n[/SSVC Details]`

describe('resource-driven SSVC', () => {
    it('includes the priority and inputs in the review, replacing managed documentation', () => {
        expect(ssvcReviewSummary(record)).toContain('SSVC priority: Immediate')
        expect(ssvcReviewSummary(record)).toContain('Exploitation: Active')
        expect(ssvcReviewSummary({ ...record, answers: {} })).toContain('SSVC priority: Incomplete')
        expect(ssvcReviewSummary(null)).toBe('SSVC: cleared')
        expect(stripSsvcDocumentation('Notes\n\n[SSVC Summary]\nSSVC priority: Defer\n[/SSVC Summary]\nOther')).toBe('Notes\nOther')
        const text = details() + '\n\n[SSVC Summary]\nSSVC priority: Defer\n[/SSVC Summary]\n\nReviewer notes\n\n--- [Team: Security] [State: IN_TRIAGE] ---\n\nTeam notes'
        const blocks = parseAssessmentBlocks(ssvcReviewText(text, record))
        expect(blocks.find(block => block.team === 'General')!.details).toContain('SSVC priority: Immediate')
        expect(blocks.find(block => block.team === 'Security')!.details).toBe('Team notes')
        expect(ssvcReviewText(text, record)).not.toContain('SSVC priority: Defer')
    })
    it('evaluates every official decision without assuming unanswered values', () => {
        expect(model.mapping).toHaveLength(72)
        for (const row of model.mapping) {
            const answers = Object.fromEntries(Object.entries(row).filter(([key]) => key !== model.outcome))
            expect(evaluateSsvc(model, answers)).toBe(row['ssvc:DSOI:1.0.0'])
        }
        expect(evaluateSsvc(model, {})).toBeNull()
        expect(evaluateSsvc(model, { 'ssvc:E:1.1.0': 'A' })).toBeNull()
        expect(evaluateSsvc(model, { ...record.answers, forged: 'Y' })).toBeNull()
    })

    it.each([details, structured])('preserves legacy and JSON metadata through sanitization and team edits', (format) => {
        const text = format()
        expect(readSsvcRecord(text)).toEqual(record)
        expect(readSsvcRecord(sanitizeAssessmentDetails(text).text)).toEqual(record)
        const edited = mergeTeamAssessment(text, 'Team A', 'IN_TRIAGE', 'Team notes', 'analyst')
        expect(readSsvcRecord(edited.text)).toEqual(record)
        const emptyGeneral = mergeTeamAssessment(text, 'General', 'NOT_SET', '', 'reviewer')
        expect(readSsvcRecord(emptyGeneral.text)).toEqual(record)
    })

    it('keeps raw JSON separate from editable prose and cannot mistake it for team headers', () => {
        const value = { ...record, rationale: 'Café 50% ] \\ path\n--- [Team: Fake] [State: EXPLOITABLE] ---\n[/SSVC Details]\n[Status: Pending Review]\n[Rescored: 0.0]' }
        const text = structured(value) + '\n\nReviewer notes'
        const blocks = parseAssessmentBlocks(text)
        expect(blocks).toHaveLength(1)
        expect(blocks[0]!.details).toBe('Reviewer notes')
        expect(blocks[0]!.ssvcDetails).toContain('"outcome": "I"')
        expect(readSsvcRecord(sanitizeAssessmentDetails(text).text)).toEqual(value)
        expect(sanitizeAssessmentDetails(text).text.startsWith('[Rescored:')).toBe(false)
        expect(sanitizeAssessmentDetails(text).text.endsWith('[Status: Pending Review]')).toBe(false)
        expect(stripSsvcDocumentation(text)).not.toContain('"answers"')
    })

    it('rejects missing, malformed, duplicate, mismatched, and wrong-team JSON', () => {
        const text = structured()
        const block = text.slice(text.indexOf('\n\n[SSVC Details]'))
        const invalid = [
            text.replace('[SSVC: IMMEDIATE]', '[SSVC: DEFER]'),
            text.replace('[SSVC: IMMEDIATE]', ''),
            text.replace(block, ''),
            text + block,
            text.replace('"model":', 'invalid:'),
            text.replace(block, '') + '\n\n--- [Team: Security] [State: NOT_SET] ---' + block,
        ]
        for (const entry of invalid) {
            expect(() => readSsvcRecord(entry)).toThrow()
            expect(summarizeSsvc([entry]).status).toBe('INVALID')
        }
        expect(readSsvcRecord(structured({ ...record, answers: {} as typeof record.answers, outcome: null as any }, 'INCOMPLETE'))?.outcome).toBeNull()
    })

    it('summarizes coverage and disagreement without picking the first decision', () => {
        expect(summarizeSsvc(['', '']).status).toBe('UNASSESSED')
        expect(summarizeSsvc([details(), details()]).status).toBe('IMMEDIATE')
        expect(summarizeSsvc([details(), '']).status).toBe('INCOMPLETE')
        expect(summarizeSsvc([details(), details({ ...record, rationale: 'Different' })]).status).toBe('MIXED')
        expect(summarizeSsvc([details({ ...record, version: 'unknown' })]).status).toBe('INVALID')
        expect(summarizeSsvc([details({ ...record, outcome: 'D' })]).status).toBe('INVALID')
        expect(summarizeSsvc(['--- [Team: General] [SSVC: %invalid] ---']).status).toBe('INVALID')
    })
})
