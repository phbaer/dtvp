import { describe, expect, it } from 'vitest'
import { buildRescoredVectorForState, normalizeCvssVectorInstance } from '../cvssRescore'
import { Cvss3P1 } from 'ae-cvss-calculator'

describe('cvssRescore', () => {
    it('returns null when no transition matches the target state', () => {
        expect(buildRescoredVectorForState({
            rules: [],
            targetState: 'NOT_AFFECTED',
            currentVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            fallbackVersion: '3.1',
        })).toBeNull()
    })

    it('applies matching 3.1 rescore actions for the target state', () => {
        const result = buildRescoredVectorForState({
            rules: [{
                trigger: { state: 'NOT_AFFECTED' },
                actions: {
                    '3.1': { MC: 'N', MI: 'N', MA: 'N' },
                },
            }],
            targetState: 'NOT_AFFECTED',
            currentVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            fallbackVersion: '3.1',
        })

        expect(result?.version).toBe('3.1')
        expect(result?.vector).toContain('MC:N')
        expect(result?.vector).toContain('MI:N')
        expect(result?.vector).toContain('MA:N')
    })

    it('does not add modified metrics when they already match the base metric', () => {
        const result = buildRescoredVectorForState({
            rules: [{
                trigger: { state: 'NOT_AFFECTED' },
                actions: {
                    '3.1': { MC: 'N' },
                },
            }],
            targetState: 'NOT_AFFECTED',
            currentVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
            fallbackVersion: '3.1',
        })

        expect(result?.vector).not.toContain('MC:N')
    })

    it('removes modified and requirement metrics when they collapse to base values', () => {
        const instance = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/IR:H/MI:H')

        const cleanedVector = normalizeCvssVectorInstance(instance)

        expect(cleanedVector).not.toContain('MI:H')
        expect(cleanedVector).not.toContain('IR:H')
    })
})