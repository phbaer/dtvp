import { describe, expect, it } from 'vitest'
import { buildRescoredVectorForState, normalizeCvssVectorInstance } from '../cvssRescore'
import { Cvss2, Cvss3P1 } from 'ae-cvss-calculator'
import defaultRescoreRules from '../../../../data/rescore_rules.json'

const allVersionRules = [{
    trigger: { state: 'NOT_AFFECTED' },
    actions: {
        '4.0': { CR: 'L', IR: 'L', AR: 'L', MVC: 'N', MVI: 'N', MVA: 'N' },
        '3.1': { CR: 'L', IR: 'L', AR: 'L', MC: 'N', MI: 'N', MA: 'N' },
        '3.0': { CR: 'L', IR: 'L', AR: 'L', MC: 'N', MI: 'N', MA: 'N' },
        '2.0': { CR: 'L', IR: 'L', AR: 'L', CDP: 'N', TD: 'N' },
    },
}]

describe('cvssRescore', () => {
    it('ships complete default actions and paired impact requirements for every supported version', () => {
        const versions = ['2.0', '3.0', '3.1', '4.0']
        const requirementPairs: Record<string, Record<string, string>> = {
            '3.0': { MC: 'CR', MI: 'IR', MA: 'AR' },
            '3.1': { MC: 'CR', MI: 'IR', MA: 'AR' },
            '4.0': { MVC: 'CR', MVI: 'IR', MVA: 'AR' },
        }

        for (const transition of defaultRescoreRules.transitions as Array<Record<string, any>>) {
            expect(Object.keys(transition.actions).sort()).toEqual(versions)
            for (const version of versions) {
                const actions = transition.actions[version]
                expect(Object.keys(actions).length).toBeGreaterThan(0)
                if (version === '2.0') {
                    expect(actions).toMatchObject({ CR: expect.any(String), IR: expect.any(String), AR: expect.any(String) })
                    continue
                }
                for (const [modifiedMetric, requirementMetric] of Object.entries(requirementPairs[version] || {})) {
                    if (modifiedMetric in actions) {
                        expect(actions).toHaveProperty(requirementMetric)
                    }
                }
            }
        }
    })

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

    it.each([
        {
            version: '4.0' as const,
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
            modifiedMetrics: ['MVC:N', 'MVI:N', 'MVA:N'],
        },
        {
            version: '3.1' as const,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            modifiedMetrics: ['MC:N', 'MI:N', 'MA:N'],
        },
        {
            version: '3.0' as const,
            vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            modifiedMetrics: ['MC:N', 'MI:N', 'MA:N'],
        },
        {
            version: '2.0' as const,
            vector: 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
            modifiedMetrics: ['CDP:N', 'TD:N'],
        },
    ])('applies complete $version rules and requirement fields', ({ version, vector, modifiedMetrics }) => {
        const result = buildRescoredVectorForState({
            rules: allVersionRules,
            targetState: 'NOT_AFFECTED',
            currentVector: vector,
            fallbackVersion: version,
        })

        expect(result?.version).toBe(version)
        if (version !== '2.0') expect(result?.vector.startsWith(`CVSS:${version}/`)).toBe(true)
        for (const metric of [...modifiedMetrics, 'CR:L', 'IR:L', 'AR:L']) {
            expect(result?.vector).toContain(metric)
        }
    })

    it('repairs missing requirements on an already-rescored vector', () => {
        const result = buildRescoredVectorForState({
            rules: allVersionRules,
            targetState: 'NOT_AFFECTED',
            currentVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N',
            fallbackVersion: '3.1',
        })

        expect(result?.vector).toContain('CR:L/IR:L/AR:L')
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

    it('clears stale modified and requirement values when the rule target matches the base metric', () => {
        const result = buildRescoredVectorForState({
            rules: allVersionRules,
            targetState: 'NOT_AFFECTED',
            currentVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H/CR:H/MC:H',
            fallbackVersion: '3.1',
        })

        expect(result?.vector).not.toContain('MC:')
        expect(result?.vector).not.toContain('CR:')
        expect(result?.vector).toContain('MI:N')
        expect(result?.vector).toContain('IR:L')
    })

    it('removes modified and requirement metrics when they collapse to base values', () => {
        const instance = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/IR:H/MI:H')

        const cleanedVector = normalizeCvssVectorInstance(instance)

        expect(cleanedVector).not.toContain('MI:H')
        expect(cleanedVector).not.toContain('IR:H')
    })

    it('preserves a requirement when its corresponding modified metric is effective', () => {
        const instance = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/MC:L')

        const cleanedVector = normalizeCvssVectorInstance(instance)

        expect(cleanedVector).toContain('MC:L')
        expect(cleanedVector).toContain('CR:H')
    })

    it('preserves CVSS 2.0 requirements because they apply directly to base CIA metrics', () => {
        const instance = new Cvss2('AV:N/AC:L/Au:N/C:C/I:P/A:P/CR:L/IR:M/AR:H')

        const cleanedVector = normalizeCvssVectorInstance(instance)

        expect(cleanedVector).toContain('CR:L')
        expect(cleanedVector).toContain('IR:M')
        expect(cleanedVector).toContain('AR:H')
    })
})
